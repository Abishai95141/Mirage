"""Gate 0: a scripted SSH session appears as a normalised session in ClickHouse and on Grafana."""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime

import httpx
import paramiko
import pytest

pytestmark = pytest.mark.integration

COMMANDS = ["uname -a", "whoami", "cat /etc/passwd", "cd /tmp", "mirage-not-a-command-{tag}"]


def root_password() -> str:
    from .conftest import ROOT

    userdb = (ROOT / "build/profile/cowrie/userdb.txt").read_text().splitlines()
    return next(line.split(":", 2)[2] for line in userdb if line.startswith("root:"))


def _ssh_session(tag: str, port: int) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # The rendered profile accepts only its own root passwords (phase 1, spec 1.3).
    client.connect(
        "127.0.0.1",
        port,
        username="root",
        password=root_password(),
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
        banner_timeout=15,
    )
    chan = client.invoke_shell()
    chan.settimeout(10)
    out = b""
    for cmd in COMMANDS:
        chan.send((cmd.format(tag=tag) + "\n").encode())
        time.sleep(0.6)
        while chan.recv_ready():
            out += chan.recv(65536)
    chan.send(b"exit\n")
    time.sleep(0.5)
    client.close()
    return out.decode(errors="replace")


@pytest.fixture(scope="module")
def session(clickhouse, env):
    tag = uuid.uuid4().hex[:8]
    t0 = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    transcript = _ssh_session(tag, int(env.get("SSH_PORT", "2222")))
    marker = f"mirage-not-a-command-{tag}"
    deadline = time.time() + 60
    while time.time() < deadline:
        rows = clickhouse(
            "SELECT session_id FROM mirage.events FINAL "
            f"WHERE ts >= '{t0}' AND source = 'cowrie' "
            f"AND JSONExtractString(payload, 'command') = '{marker}'"
        )
        if rows:
            return {"id": rows[0]["session_id"], "transcript": transcript, "marker": marker}
        time.sleep(2)
    pytest.fail("session did not reach ClickHouse within 60 s")


def test_shell_answered(session):
    assert "Linux" in session["transcript"]  # uname -a
    assert "command not found" in session["transcript"]


def test_session_row(session, clickhouse):
    (row,) = clickhouse(f"SELECT * FROM mirage.sessions WHERE session_id = '{session['id']}'")
    assert row["logged_in"] == 1
    assert row["username"] == "root"
    assert row["commands"] >= 4
    assert row["unknown_commands"] == 1
    assert row["client_version"].startswith("SSH-2.0-paramiko")
    assert row["hassh"]
    assert row["command_list"][:3] == ["uname -a", "whoami", "cat /etc/passwd"]


def test_src_ip_is_client_not_edge(session, clickhouse):
    """The PROXY v2 header from the edge must reach Cowrie."""
    from .conftest import container_ip

    (row,) = clickhouse(f"SELECT src_ip FROM mirage.sessions WHERE session_id = '{session['id']}'")
    assert row["src_ip"]
    assert row["src_ip"] != container_ip("edge", "mirage_decoy")


def test_event_classes_present(session, clickhouse):
    rows = clickhouse(
        f"SELECT DISTINCT class, action FROM mirage.events FINAL WHERE session_id = '{session['id']}'"
    )
    seen = {(r["class"], r["action"]) for r in rows}
    for expected in [
        ("ssh_activity", "connect"),
        ("ssh_activity", "client_version"),
        ("ssh_activity", "client_kex"),
        ("authentication", "login"),
        ("process_activity", "command"),
    ]:
        assert expected in seen, f"missing {expected}; saw {sorted(seen)}"


def test_no_dead_letters_or_unmapped(session, clickhouse, env):
    rows = clickhouse(
        f"SELECT action FROM mirage.events FINAL WHERE session_id = '{session['id']}' AND class = 'unknown'"
    )
    assert rows == [], f"unmapped Cowrie events: {rows}"
    nats_mon = f"http://127.0.0.1:{env.get('NATS_MONITOR_PORT', '8222')}/jsz"
    js = httpx.get(nats_mon, params={"streams": "true"}, timeout=5).json()
    streams = {s["name"]: s for acct in js["account_details"] for s in acct["stream_detail"]}
    assert {"RAW", "EVENTS", "SIM"} <= streams.keys()


def test_grafana_shows_session(session, env):
    auth = ("admin", env["GRAFANA_ADMIN_PASSWORD"])
    base = f"http://127.0.0.1:{env.get('GRAFANA_PORT', '3300')}"
    assert (
        httpx.get(f"{base}/api/dashboards/uid/mirage-sessions", auth=auth, timeout=10).status_code
        == 200
    )
    dash = httpx.get(f"{base}/api/dashboards/uid/mirage-sessions", auth=auth, timeout=10).json()
    panel = next(p for p in dash["dashboard"]["panels"] if p["title"] == "Recent sessions")
    target = panel["targets"][0] | {"datasource": {"uid": "clickhouse"}}
    resp = httpx.post(
        f"{base}/api/ds/query",
        auth=auth,
        timeout=20,
        json={"from": "now-1h", "to": "now", "queries": [target]},
    )
    resp.raise_for_status()
    frame = resp.json()["results"]["A"]["frames"][0]
    names = [f["name"] for f in frame["schema"]["fields"]]
    ids = frame["data"]["values"][names.index("session_id")]
    assert session["id"] in ids
