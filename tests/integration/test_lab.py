"""Phase 2 lab (docs/05-phase-2-spec.md): the runner's isolation, a run end to end, the label
join's health and the two demos. Needs `make up`, `make lab-up`, the classifier worker with a
model and the learned tagger (`make models`, then `make tagger-model` or
`make tagger-model-host`).

Gate 2 tests 1 (runner safety), 2 (join health), 3 and 4 (the demos).

**What the demos assert.** A tactic, a class or an alert is read from what the system itself
produced: `mirage.labels` (the tagger), `mirage.actor_class` (the classifier) and
`mirage.actor_alerts` (the alert worker). The `sim_*` tables hold the scenario's own answers;
here they only say which sessions belong to the demo and what the right answer is. Stop the
tagger or the classifier worker and these tests fail.
"""

from __future__ import annotations

import contextlib
import json
import random
import socket
import struct
import time

import pytest

from .conftest import ROOT, container_ips, docker, unavailable

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
        unavailable("the lab is not running; run make lab-up")


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


# A port each service listens on. The probe is by address: by name it would fail at DNS, which
# says nothing about whether a packet could get there.
PORTS = {
    "cowrie": 2222, "http-decoy": 8080, "redis-decoy": 6379, "mysql-decoy": 3306, "policy": 8000,
    "clickhouse": 8123, "nats": 4222, "edge": 2222, "grafana": 3000,
}  # fmt: skip
INTERNET = "192.0.2.1:443"  # a documentation address: routed like any public one


def test_runner_reaches_the_lab_edge_and_nothing_else():
    lab_edge = container_ips("lab-edge")
    targets = [f"{lab_edge['mirage_lab']}:2222", INTERNET]
    targets += [f"{ip}:2222" for net, ip in lab_edge.items() if net != "mirage_lab"]
    for service, port in PORTS.items():
        targets += [f"{ip}:{port}" for ip in container_ips(service).values()]
    args = [x for t in targets for x in ("--probe", t)]
    reach = json.loads(runner("check", *args, timeout=180).stdout.strip().splitlines()[-1])
    assert set(reach) == set(targets)
    assert reach.pop(targets[0])["state"] == "open"  # the one way in
    assert all(v["state"] != "open" for v in reach.values()), reach
    # No route at all, which is what an internal network with one member means. A refusal
    # would mean a packet got there and back.
    assert reach[INTERNET]["state"] == "no_route", reach[INTERNET]
    assert all(v["state"] in ("no_route", "host_unreachable") for v in reach.values()), reach


def test_the_lab_network_is_internal_and_holds_only_the_lab_edge():
    net = json.loads(docker("network", "inspect", "mirage_lab").stdout)[0]
    assert net["Internal"] is True
    members = {c["Name"] for c in net["Containers"].values()}
    # The runner joins only for the length of a run. The one other member there can be is the
    # showcase's console, while a showcase is up on a lab host (docs/08-showcase.md): it
    # reaches the decoys the way the runner does, through the lab edge.
    standing = {m for m in members if not m.startswith("mirage-runner-run-")}
    assert "mirage-lab-edge-1" in standing
    assert standing <= {"mirage-lab-edge-1", "mirage-showcase-console-1"}


def _proxy_v1(src: str) -> bytes:
    return f"PROXY TCP4 {src} 10.0.0.9 40000 6379\r\n".encode()


def _proxy_v2(src: str) -> bytes:
    body = socket.inet_aton(src) + socket.inet_aton("10.0.0.9") + struct.pack("!HH", 40000, 6379)
    return b"\r\n\r\n\x00\r\nQUIT\n" + bytes([0x21, 0x11]) + struct.pack("!H", len(body)) + body


def test_the_real_edge_does_not_believe_a_clients_proxy_header(env, clickhouse):
    # Only the lab edge may accept a PROXY header, because only the runner can reach it. Sent
    # through the real edge, the same header must be treated as the client's own bytes: the
    # event carries the address the connection really came from, never the one it claimed.
    claimed = f"198.51.100.{random.randint(2, 250)}"  # documentation range: nobody's address
    started = clickhouse("SELECT toString(now64(6)) AS t")[0]["t"]
    redis_port = int(env.get("REDIS_PORT", "6380"))
    for header in (_proxy_v1(claimed), _proxy_v2(claimed)):
        with socket.create_connection(("127.0.0.1", redis_port), timeout=10) as sock:
            sock.sendall(header + b"PING\r\n")
            sock.settimeout(3)
            # the decoy may answer the stray bytes or close; either is fine
            with contextlib.suppress(OSError):
                sock.recv(4096)
    # The connections were recorded (so their absence below is not silence) ...
    poll(
        clickhouse,
        "SELECT event_id FROM mirage.events WHERE protocol = 'redis' "
        f"AND ingest_ts >= parseDateTime64BestEffort('{started}', 6, 'UTC') LIMIT 1",
        lambda rows: bool(rows),
        wait=60,
    )
    # ... and none of them, nor anything else, came from the claimed address.
    spoofed = clickhouse(f"SELECT count() AS n FROM mirage.events WHERE src_ip = '{claimed}'")
    assert int(spoofed[0]["n"]) == 0


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
    # a step that was skipped, or tried on a connection that broke, reached no decoy
    not_sent = summary["steps"].get("skipped", 0) + summary["steps"].get("failed", 0)
    assert row["not_run"] == not_sent
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


def in_list(ids) -> str:
    return ", ".join(f"'{i}'" for i in sorted(set(ids)))


def demo_sessions(clickhouse, run_id: str) -> list[dict]:
    """Which decoy sessions the demo made, and what the scenario says each one is. Ground
    truth: used to find the sessions and as the expected answer, never as the answer."""
    return clickhouse(
        "SELECT session_id, session_ref, actor_class, protocol, logical_session_id, src_ip "
        f"FROM mirage.sim_sessions FINAL WHERE run_id = '{run_id}' ORDER BY session_ref"
    )


def expected_tactics(clickhouse, run_id: str, where: str = "") -> set[str]:
    """The tactics of the steps that reached a decoy and were matched. A step that was
    skipped or never arrived is not something the tagger could have labelled."""
    rows = clickhouse(
        f"SELECT DISTINCT tactic FROM mirage.sim_steps FINAL WHERE run_id = '{run_id}' "
        f"AND tactic != '' AND state = 'matched' {where}"
    )
    return {r["tactic"] for r in rows}


def tagged_tactics(clickhouse, sessions: list[dict], want: set[str]) -> set[str]:
    """What the tagger wrote for these sessions (`mirage.labels`): input labels from the
    learned layer and session labels from the session rules. Waits for `want` to appear."""
    ids = {s["session_id"] for s in sessions} | {s["logical_session_id"] for s in sessions}
    sql = (
        "SELECT DISTINCT tactic FROM mirage.labels FINAL "
        f"WHERE session_id IN ({in_list(ids)}) AND technique != '' AND tactic != ''"
    )
    rows = poll(clickhouse, sql, lambda rows: want <= {r["tactic"] for r in rows})
    return {r["tactic"] for r in rows}


def predicted_classes(clickhouse, sessions: list[dict]) -> dict[str, str]:
    """The classifier's prediction per logical session (`mirage.actor_class`)."""
    ids = {s["logical_session_id"] for s in sessions}
    rows = poll(
        clickhouse,
        "SELECT session_id, actor_class, decided_by FROM mirage.actor_class FINAL "
        f"WHERE session_id IN ({in_list(ids)})",
        lambda rows: {r["session_id"] for r in rows} == ids,
    )
    return {r["session_id"]: r["actor_class"] for r in rows}


def actor_of(clickhouse, sessions: list[dict]) -> str:
    ids = {s["logical_session_id"] for s in sessions}
    rows = poll(
        clickhouse,
        f"SELECT actor_id FROM mirage.session_summary FINAL WHERE session_id IN ({in_list(ids)})",
        lambda rows: len(rows) == len(ids) and len({r["actor_id"] for r in rows}) == 1,
    )
    assert rows[0]["actor_id"].startswith("actor-")
    return rows[0]["actor_id"]


def actor_alert(clickhouse, actor_id: str, ok) -> dict:
    """The actor's one live alert (`mirage.actor_alerts`), once `ok` holds for it. The alert
    worker's sweep fills it in, so this waits a few sweeps."""
    rows = poll(
        clickhouse,
        "SELECT * FROM mirage.actor_alerts FINAL "
        f"WHERE actor_id = '{actor_id}' AND notEmpty(reasons)",
        lambda rows: len(rows) == 1 and ok(rows[0]),
    )
    return rows[0]


def test_demo_1_ssh_brute_to_miner(clickhouse):
    summary, _ = run_one(clickhouse, "/lab/scenarios/demo/demo-1-ssh-brute-miner.yaml")
    run_id = summary["run_id"]
    sessions = demo_sessions(clickhouse, run_id)
    promised = {TA["cred"], TA["discovery"], TA["c2"], TA["exec"], TA["persist"], TA["impact"]}
    # the demo ran as written ...
    assert expected_tactics(clickhouse, run_id) == promised
    # ... and the tagger, which never sees that, labelled the sessions with exactly those
    assert tagged_tactics(clickhouse, sessions, promised) == promised

    # Each failed guess is a connection that never held access: scanner behaviour, by the
    # rule. The connection that got in and ran the steps is the model's call.
    stepped = clickhouse(
        f"SELECT DISTINCT session_id FROM mirage.sim_steps FINAL WHERE run_id = '{run_id}' "
        "AND state = 'matched' AND evidence != 'auth'"
    )
    working = {
        s["logical_session_id"] for s in sessions
        if s["session_id"] in {r["session_id"] for r in stepped}
    }  # fmt: skip
    assert working
    classes = predicted_classes(clickhouse, sessions)
    assert {classes[i] for i in working} == {"scripted_bot"}
    assert set(classes.values()) <= {"scripted_bot", "scanner"}

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
    # One alert for the actor, raised for what the tagger and the artifact index found. The
    # predicted class reaches the alert one sweep after the classifier writes it, so it is
    # part of what is waited for: asserting it on whichever version had the reasons first
    # failed about one run in two.
    alert = actor_alert(
        clickhouse,
        actor_of(clickhouse, sessions),
        lambda a: (
            {"artifact", "persistence", "impact"} <= set(a["reasons"])
            and "scripted_bot" in a["actor_classes"]
        ),
    )
    assert art[0]["sha256"] in alert["artifacts"]
    assert working <= set(alert["session_ids"])


def test_demo_2_web_cred_theft_reused_on_mysql(clickhouse):
    summary, _ = run_one(clickhouse, "/lab/scenarios/demo/demo-2-web-cred-mysql.yaml")
    run_id = summary["run_id"]
    sessions = demo_sessions(clickhouse, run_id)
    web = [s for s in sessions if s["protocol"] == "http"]
    db = [s for s in sessions if s["protocol"] == "mysql"]
    assert web and db, sessions
    assert {s["actor_class"] for s in web} == {"scanner"}  # what the scenario says they are
    assert {s["actor_class"] for s in db} == {"scripted_bot"}

    # The classifier's answer: the sweep never logged in, so the rule calls it a scanner; the
    # MySQL session held access, and the model calls it a bot.
    classes = predicted_classes(clickhouse, sessions)
    assert {classes[s["logical_session_id"]] for s in web} == {"scanner"}
    assert {classes[s["logical_session_id"]] for s in db} == {"scripted_bot"}

    # The tagger's answer, per session, against the steps that ran in it.
    for group, promised in (
        (web, {TA["recon"], TA["cred"]}),
        (db, {TA["initial"], TA["collection"]}),
    ):
        refs = in_list({s["session_ref"] for s in group})
        assert promised <= expected_tactics(clickhouse, run_id, f"AND session_ref IN ({refs})")
        assert promised <= tagged_tactics(clickhouse, group, promised)

    # the honeytoken fires on the second session, and the pipeline ties both to one actor
    poll(
        clickhouse,
        "SELECT session_id FROM mirage.events FINAL WHERE action = 'token_triggered' "
        f"AND JSONExtractString(payload, 'session') = '{db[0]['logical_session_id']}'",
        lambda rows: bool(rows),
    )
    actor = actor_of(clickhouse, sessions)
    # One alert naming both sessions and both addresses (spec 2.8).
    logical = {s["logical_session_id"] for s in sessions}
    addresses = {s["src_ip"] for s in sessions}
    assert len(logical) == 2 and len(addresses) == 2
    alert = actor_alert(
        clickhouse,
        actor,
        lambda a: (
            logical <= set(a["session_ids"])
            and {"scanner", "scripted_bot"} <= set(a["actor_classes"])
        ),
    )
    assert "honeytoken" in alert["reasons"] and alert["tokens"]
    # Both of this run's sessions and both of its addresses are in that one alert. It may name
    # more: the planted credential is the same on every run of a deployment, so on a store
    # with history the sessioniser links earlier readers and users of it to the same actor.
    assert logical <= set(alert["session_ids"]) and addresses <= set(alert["src_ips"])
    assert {"http", "mysql"} <= set(alert["protocols"])
    others = clickhouse(
        "SELECT actor_id FROM mirage.actor_alerts FINAL WHERE notEmpty(reasons) "
        f"AND hasAny(session_ids, [{in_list(logical)}]) AND actor_id != '{actor}'"
    )
    assert others == [], "the demo's sessions must be named by one alert only"
