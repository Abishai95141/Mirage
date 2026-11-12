"""Phase 2 lab (docs/05-phase-2-spec.md): the runner's isolation, a run end to end, and the
label join's health. Needs `make up` and `make lab-up`.

Gate 2 tests 1 (runner safety) and 2 (join health) start here; both grow with the catalogue.
"""

from __future__ import annotations

import json
import time

import pytest

from .conftest import ROOT, docker

pytestmark = pytest.mark.integration

COMPOSE = [
    "compose", "--env-file", str(ROOT / ".env"), "-f", str(ROOT / "compose/docker-compose.yml"),
    "--profile", "lab",
]  # fmt: skip
WAIT_S = 150


def lab_running() -> bool:
    out = docker("ps", "--format", "{{.Names}}").stdout.split()
    return {"mirage-lab-edge-1", "mirage-sim-join-1"} <= set(out)


@pytest.fixture(scope="module", autouse=True)
def lab():
    if not lab_running():
        pytest.skip("the lab is not running; run make lab-up")


def runner(*args: str, timeout: int = 300, check: bool = True):
    return docker(*COMPOSE, "run", "--rm", "-T", "runner", *args, timeout=timeout, check=check)


def poll(query, sql: str, ok, wait: float = WAIT_S) -> list[dict]:
    deadline = time.time() + wait
    rows: list[dict] = []
    while time.time() < deadline:
        rows = query(sql)
        if ok(rows):
            return rows
        time.sleep(2)
    pytest.fail(f"timed out after {wait:.0f} s waiting for: {sql}\nlast rows: {rows[:5]}")


# ------------------------------------------------------------------ Gate 2 test 1: safety


def test_runner_passes_its_isolation_check_only_inside_the_lab():
    assert "inside the lab network" in runner("check").stdout
    # The same image on an ordinary network has a default route and no lab edge: it refuses.
    out = docker(
        "run", "--rm", "--entrypoint", "mirage-lab", "mirage/lab:dev", "check", check=False
    )
    assert out.returncode != 0
    assert "refusing to run" in out.stderr and "default route" in out.stderr
    # ... and "run" makes the same check before it opens anything.
    out = docker(
        "run", "--rm", "-v", f"{ROOT}/lab/catalogue:/lab/catalogue:ro",
        "-v", f"{ROOT}/lab/scenarios:/lab/scenarios:ro", "-e", "LAB_CATALOGUE=/lab/catalogue",
        "--entrypoint", "mirage-lab", "mirage/lab:dev", "run", "/lab/scenarios/smoke",
        check=False,
    )  # fmt: skip
    assert out.returncode != 0 and "refusing to run" in out.stderr


PROBE = r"""
import json, socket
out = {}
for name, port in [("cowrie", 2222), ("http-decoy", 8080), ("redis-decoy", 6379),
                   ("mysql-decoy", 3306), ("policy", 8000), ("clickhouse", 8123),
                   ("nats", 4222), ("edge", 2222), ("1.1.1.1", 443), ("lab-edge", 2222)]:
    try:
        socket.create_connection((name, port), timeout=3).close()
        out[name] = "open"
    except OSError as e:
        out[name] = type(e).__name__
print(json.dumps(out))
"""


def test_runner_reaches_the_lab_edge_and_nothing_else():
    out = docker(
        *COMPOSE, "run", "--rm", "-T", "--entrypoint", "python", "runner", "-c", PROBE, timeout=120
    ).stdout
    reach = json.loads(out.strip().splitlines()[-1])
    assert reach.pop("lab-edge") == "open"
    assert all(v != "open" for v in reach.values()), reach


def test_lab_services_exist_only_under_the_lab_profile():
    plain = docker(
        "compose", "--env-file", str(ROOT / ".env"), "-f", str(ROOT / "compose/docker-compose.yml"),
        "config", "--services",
    ).stdout.split()  # fmt: skip
    assert not {"lab-edge", "runner", "sim-join"} & set(plain)
    with_lab = docker(*COMPOSE, "config", "--services").stdout.split()
    assert {"lab-edge", "runner", "sim-join"} <= set(with_lab)
    # The real edge never accepts a client's PROXY header; only the lab's does.
    assert "accept-proxy" not in (ROOT / "compose/edge/haproxy.cfg").read_text()
    assert "accept-proxy" in (ROOT / "compose/lab/haproxy.cfg").read_text()


# ------------------------------------------------------------------ Gate 2 test 2: join health


@pytest.fixture(scope="module")
def smoke_run(clickhouse):
    out = runner(
        "run", "/lab/scenarios/smoke", "--seed", str(int(time.time())), "--repeat", "2",
        "--time-scale", "0.05",
    )  # fmt: skip
    summary = json.loads(out.stdout.strip().splitlines()[-1])
    assert summary["errors"] == []
    (row,) = poll(
        clickhouse,
        f"SELECT * FROM mirage.sim_runs FINAL WHERE run_id = '{summary['run_id']}' AND final = 1",
        lambda rows: len(rows) == 1,
    )
    return summary, row


def test_every_step_that_ran_is_matched_exactly(smoke_run):
    summary, row = smoke_run
    assert row["no_event"] == 0 and row["mismatch"] == 0, row["problems"]
    assert row["connections_unmatched"] == 0, row["problems"]
    assert row["matched"] == summary["steps"]["ran"]
    assert row["not_run"] == summary["steps"].get("skipped", 0)
    assert row["sessions"] == summary["sessions"] == 6  # three scenarios, twice


def test_labels_sit_on_the_inputs_that_were_sent(smoke_run, clickhouse):
    run_id = smoke_run[0]["run_id"]
    rows = clickhouse(
        "SELECT sim_session_ref, sim_step, procedure_id, technique_id, sim_role, class, action, "
        f"payload FROM mirage.events_labelled WHERE sim_run_id = '{run_id}' ORDER BY ts"
    )
    catalogue_text = {
        "sysinfo-uname-all": "uname -a", "owner-id": "id", "owner-w": "w",
        "accounts-passwd": "cat /etc/passwd",
    }  # fmt: skip
    inputs = [r for r in rows if r["sim_role"] == "input" and r["action"] == "command"]
    assert inputs
    for r in inputs:
        want = catalogue_text.get(r["procedure_id"])
        if want is not None:
            assert json.loads(r["payload"])["command"] == want, r
    # the human-paced session typed with corrections, and the captured lines are still exact
    human = [r for r in inputs if "smoke-human-look" in r["sim_session_ref"]]
    assert {r["sim_step"] for r in human} == {"s1", "s2", "s3", "s4"}
    # an explicit negative keeps its empty technique; the guessed logins carry the auth label
    assert any(r["procedure_id"] == "change-dir" and r["technique_id"] == "" for r in rows)
    auth = [r for r in rows if r["procedure_id"] == "ssh-password-guessing"]
    assert auth and all(r["class"] == "authentication" for r in auth)
    # each line's gate decisions carry the line's label
    assert any(r["sim_role"] == "decision" and r["class"] == "policy_decision" for r in rows)
    uploads = [r for r in rows if r["procedure_id"] == "transfer-sftp-put"]
    assert uploads and all(r["action"] == "upload" for r in uploads)


def test_each_simulated_actor_is_its_own_source_and_actor(smoke_run, clickhouse):
    run_id = smoke_run[0]["run_id"]
    sessions = clickhouse(
        "SELECT session_id, actor_ref, actor_class, timing_profile, src_ip "
        f"FROM mirage.sim_sessions FINAL WHERE run_id = '{run_id}'"
    )
    by_actor: dict[str, set[str]] = {}
    for s in sessions:
        by_actor.setdefault(s["actor_ref"], set()).add(s["src_ip"])
        assert s["src_ip"].startswith("198.18.")  # the capture range
    assert len(by_actor) == 6 and all(len(ips) == 1 for ips in by_actor.values())
    assert len({next(iter(ips)) for ips in by_actor.values()}) == 6
    assert {s["actor_class"] for s in sessions} == {"scripted_bot", "human"}
    assert any(s["timing_profile"] == "human@0.05" for s in sessions)
    # The sessioniser must see what the lab built: one actor per simulated actor, never merged.
    ids = [s["session_id"] for s in sessions]
    id_list = ",".join(f"'{i}'" for i in ids)
    summaries = poll(
        clickhouse,
        "SELECT session_id, actor_id FROM mirage.session_summary FINAL "
        f"WHERE session_id IN ({id_list})",
        lambda rows: len(rows) == len(ids) and all(r["actor_id"] for r in rows),
    )
    actor_of = {r["session_id"]: r["actor_id"] for r in summaries}
    pipeline_actors: dict[str, set[str]] = {}
    for s in sessions:
        pipeline_actors.setdefault(s["actor_ref"], set()).add(actor_of[s["session_id"]])
    assert all(len(a) == 1 for a in pipeline_actors.values()), pipeline_actors
    assert len({next(iter(a)) for a in pipeline_actors.values()}) == 6, pipeline_actors


# ------------------------------------------------------------------ protocol coverage


@pytest.fixture(scope="module")
def proto_run(clickhouse):
    out = runner("run", "/lab/scenarios/smoke-proto", "--seed", str(int(time.time())))
    summary = json.loads(out.stdout.strip().splitlines()[-1])
    assert summary["errors"] == []
    (row,) = poll(
        clickhouse,
        f"SELECT * FROM mirage.sim_runs FINAL WHERE run_id = '{summary['run_id']}' AND final = 1",
        lambda rows: len(rows) == 1,
    )
    return summary, row


def test_http_redis_mysql_sessions_all_join_cleanly(proto_run, clickhouse):
    summary, row = proto_run
    assert row["no_event"] == 0 and row["mismatch"] == 0, row["problems"]
    assert row["connections_unmatched"] == 0, row["problems"]
    assert row["matched"] == summary["steps"]["ran"]
    rows = clickhouse(
        "SELECT protocol, sim_role, technique_id, class, action FROM mirage.events_labelled "
        f"WHERE sim_run_id = '{summary['run_id']}'"
    )
    by_proto: dict[str, set[str]] = {}
    for r in rows:
        by_proto.setdefault(r["protocol"], set()).add(r["sim_role"])
    assert set(by_proto) == {"http", "redis", "mysql"}
    # every protocol has both the content event and its gate decision labelled
    assert all(roles >= {"input", "decision"} for roles in by_proto.values()), by_proto
    # the input labels sit on the right event classes per protocol
    inputs = {(r["protocol"], r["class"]) for r in rows if r["sim_role"] == "input"}
    assert ("http", "http_activity") in inputs
    assert ("redis", "datastore_activity") in inputs
    assert ("mysql", "datastore_activity") in inputs
    assert ("mysql", "authentication") in inputs  # the login step
    assert {r["technique_id"] for r in rows if r["technique_id"]} >= {"T1082", "T1083", "T1005"}


# ------------------------------------------------------------------ Gate 2 tests 3 and 4: demos

TA = {
    "recon": "TA0043", "cred": "TA0006", "discovery": "TA0007", "exec": "TA0002",
    "persist": "TA0003", "c2": "TA0011", "impact": "TA0040", "initial": "TA0001",
    "collection": "TA0009",
}  # fmt: skip


def run_one(clickhouse, path: str) -> tuple[dict, dict]:
    out = runner("run", path, "--seed", str(int(time.time())), "--time-scale", "0.1")
    summary = json.loads(out.stdout.strip().splitlines()[-1])
    assert summary["errors"] == [], summary
    (row,) = poll(
        clickhouse,
        f"SELECT * FROM mirage.sim_runs FINAL WHERE run_id = '{summary['run_id']}' AND final = 1",
        lambda rows: len(rows) == 1,
    )
    assert row["no_event"] == 0 and row["mismatch"] == 0, row["problems"]
    assert row["connections_unmatched"] == 0, row["problems"]
    return summary, row


def tactics_of(clickhouse, run_id: str, where: str = "") -> set[str]:
    rows = clickhouse(
        f"SELECT DISTINCT tactic FROM mirage.sim_steps FINAL WHERE run_id = '{run_id}' "
        f"AND tactic != '' {where}"
    )
    return {r["tactic"] for r in rows}


def test_demo_1_ssh_brute_to_miner(clickhouse):
    summary, _ = run_one(clickhouse, "/lab/scenarios/demo/demo-1-ssh-brute-miner.yaml")
    run_id = summary["run_id"]
    # the session's label union is exactly the six tactics the demo promises
    assert tactics_of(clickhouse, run_id) == {
        TA["cred"],
        TA["discovery"],
        TA["c2"],
        TA["exec"],
        TA["persist"],
        TA["impact"],
    }
    # brute-force login opens several connections, so there are several session rows; all bot
    sess = clickhouse(
        f"SELECT session_id, actor_class FROM mirage.sim_sessions FINAL WHERE run_id = '{run_id}'"
    )
    assert sess and all(s["actor_class"] == "scripted_bot" for s in sess)
    # the miner upload is a distinct step, and its bytes are an indexed artifact
    up = clickhouse(
        f"SELECT session_id FROM mirage.sim_steps FINAL WHERE run_id = '{run_id}' "
        "AND evidence = 'upload' AND state = 'matched'"
    )
    assert up, "demo 1 must have a matched upload step"
    art = poll(
        clickhouse,
        f"SELECT sha256 FROM mirage.artifacts WHERE has(sessions, '{up[0]['session_id']}')",
        lambda rows: bool(rows),
    )
    assert art


def test_demo_2_web_cred_theft_reused_on_mysql(clickhouse):
    summary, _ = run_one(clickhouse, "/lab/scenarios/demo/demo-2-web-cred-mysql.yaml")
    run_id = summary["run_id"]
    sessions = clickhouse(
        "SELECT session_id, session_ref, actor_class, protocol, logical_session_id "
        f"FROM mirage.sim_sessions FINAL WHERE run_id = '{run_id}' ORDER BY session_ref"
    )
    scanner = [s for s in sessions if s["actor_class"] == "scanner"]
    bot = [s for s in sessions if s["actor_class"] == "scripted_bot"]
    assert scanner and bot, sessions
    # the scanner sweeps and reads the planted file; the bot reuses the credential on MySQL
    ref = scanner[0]["session_ref"]
    assert tactics_of(clickhouse, run_id, f"AND session_ref = '{ref}'") >= {TA["recon"], TA["cred"]}
    bref = bot[0]["session_ref"]
    assert tactics_of(clickhouse, run_id, f"AND session_ref = '{bref}'") >= {
        TA["initial"],
        TA["collection"],
    }
    # the honeytoken fires on the second session, and the pipeline ties both to one actor
    mysql_logical = bot[0]["logical_session_id"]
    poll(
        clickhouse,
        "SELECT session_id FROM mirage.events FINAL WHERE action = 'token_triggered' "
        f"AND JSONExtractString(payload, 'session') = '{mysql_logical}'",
        lambda rows: bool(rows),
    )
    ids = [s["logical_session_id"] for s in sessions]
    id_list = ",".join(f"'{i}'" for i in ids)
    actors = poll(
        clickhouse,
        f"SELECT actor_id FROM mirage.session_summary FINAL WHERE session_id IN ({id_list})",
        lambda rows: len(rows) >= 2 and len({r["actor_id"] for r in rows}) == 1,
    )
    assert actors[0]["actor_id"].startswith("actor-")
