"""Label join: exact on the connection, then on the window, then on the hash of the input."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from mirage_pipeline.simjoin import Event, match, truth_row
from mirage_schema.groundtruth import GroundTruth, RunRecord, SessionTruth, input_hash

T0 = datetime(2026, 11, 12, 10, 0, 0, tzinfo=UTC)
IP = "198.18.0.5"


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


_n = iter(range(10_000))


def ev(t, cls, action, payload=None, *, sid="S1", port=40001, source="cowrie", outcome="unknown",
       dst=2222, ip=IP) -> Event:  # fmt: skip
    return Event(
        f"e{next(_n)}", at(t), source, cls, action, outcome, sid, ip, port, dst, payload or {}
    )


def line(t, text, **kw) -> Event:
    return ev(t, "process_activity", "command", {"command": text}, **kw)


def decision(t, text, **kw) -> Event:
    return ev(t, "policy_decision", "decide", {"command": text, "input": text}, **kw)


def step(step_id, t0, t1, text=None, *, port=40001, status="ran", evidence="input", sha=None,
         technique="T1082", ref="a/0") -> GroundTruth:  # fmt: skip
    return GroundTruth(
        run_id="r1", scenario_id="sc", session_ref=ref, step_id=step_id, procedure_id=f"p-{step_id}",
        technique_id=technique, tactic="TA0007" if technique else None, attack_version="20.1",
        protocol="ssh", src={"ip": IP, "port": port}, dst={"ip": "172.26.0.2", "port": 2222},
        evidence=evidence,
        input_sha256=sha or (input_hash(text) if text is not None else None),
        start_ts=at(t0), end_ts=at(t1), status=status,
    )  # fmt: skip


def session(ports=(40001,), ref="a/0", protocol="ssh", dst=2222) -> SessionTruth:
    return SessionTruth(
        run_id="r1", scenario_id="sc", session_ref=ref, protocol=protocol, actor_ref="a",
        actor_class="scripted_bot", timing_profile="bot-fast", mode="capture",
        connections=[
            {"src": {"ip": IP, "port": p}, "dst": {"ip": "172.26.0.2", "port": dst}, "opened_ts": T0}
            for p in ports
        ],
        start_ts=T0, end_ts=at(60),
    )  # fmt: skip


def base_events() -> list[Event]:
    return [
        ev(0, "ssh_activity", "connect"),
        ev(
            0.2, "authentication", "login", {"username": "root", "password": "x"}, outcome="failure"
        ),
        ev(
            0.4, "authentication", "login", {"username": "root", "password": "y"}, outcome="success"
        ),
        line(1.0, "uname -a"),
        decision(1.01, "uname -a"),
        line(2.0, "id; echo done"),
        decision(2.01, "id"),
        decision(2.02, "echo done"),
        line(3.0, "ls -la /tmp"),
        decision(3.01, "ls"),
        ev(9, "ssh_activity", "disconnect"),
    ]


def states(result) -> dict[str, str]:
    return {s.step.step_id: s.state for s in result.steps}


def test_every_step_matches_its_own_line_and_decisions():
    steps = [
        step("login", 0.1, 0.5, evidence="auth", technique="T1110.001"),
        step("s1", 0.9, 1.2, "uname -a"),
        step("s2", 1.9, 2.2, "id; echo done"),
        step("s3", 2.9, 3.2, "ls -la /tmp", technique=None),
    ]
    r = match([session()], steps, base_events())
    assert states(r) == {"login": "matched", "s1": "matched", "s2": "matched", "s3": "matched"}
    assert r.counts() == {"matched": 4, "no_event": 0, "mismatch": 0, "not_run": 0}
    assert r.settled() and not r.connections_unmatched
    by_step: dict[str, list[str]] = {}
    for lab in r.labels:
        by_step.setdefault(lab.step.step_id, []).append(lab.role)
    assert sorted(by_step["login"]) == ["input", "input"]  # both authentication attempts
    assert sorted(by_step["s1"]) == ["decision", "input"]
    assert sorted(by_step["s2"]) == ["decision", "decision", "input"]  # a list of two commands
    assert len({lab.event_id for lab in r.labels}) == len(r.labels)  # no event labelled twice
    (row,) = r.sessions
    assert (row.session_id, row.src_port) == ("S1", 40001)


def test_a_different_input_in_the_window_is_a_mismatch_not_a_label():
    r = match([session()], [step("s1", 0.9, 1.2, "uname -r")], base_events())
    (s,) = r.steps
    assert s.state == "mismatch" and "uname -a" in s.detail
    assert r.labels == [] and r.counts()["mismatch"] == 1


def test_nothing_in_the_window_is_no_event():
    r = match([session()], [step("s1", 5.0, 5.2, "uname -a")], base_events())
    assert states(r) == {"s1": "no_event"} and r.labels == []
    assert not r.settled()


def test_steps_that_did_not_run_are_not_matched_to_anything():
    r = match([session()], [step("s1", 0.9, 1.2, "uname -a", status="skipped")], base_events())
    assert states(r) == {"s1": "not_run"} and r.labels == []


def test_identical_lines_close_together_each_take_one_event():
    events = [
        ev(0, "ssh_activity", "connect"),
        line(1.00, "id"), decision(1.01, "id"),
        line(1.10, "id"), decision(1.11, "id"),
        ev(5, "ssh_activity", "disconnect"),
    ]  # fmt: skip
    # the widened windows overlap; order and one-use-per-event keep them apart
    steps = [step("s1", 0.99, 1.05, "id"), step("s2", 1.09, 1.15, "id")]
    r = match([session()], steps, events)
    assert states(r) == {"s1": "matched", "s2": "matched"}
    inputs = {lab.step.step_id: lab.event_id for lab in r.labels if lab.role == "input"}
    assert inputs["s1"] != inputs["s2"]
    assert [lab.role for lab in r.labels if lab.step.step_id == "s1"] == ["input", "decision"]


def test_another_connection_from_the_same_address_is_never_confused():
    events = [
        *base_events(),
        ev(0, "ssh_activity", "connect", sid="S2", port=40002),
        line(1.0, "uname -a", sid="S2", port=40002),
        ev(4, "ssh_activity", "disconnect", sid="S2", port=40002),
    ]
    steps = [step("s1", 0.9, 1.2, "uname -a", port=40002)]
    r = match([session(ports=(40001, 40002))], steps, events)
    (lab,) = [x for x in r.labels if x.role == "input"]
    assert lab.session_id == "S2"
    assert {(s.session_id, s.src_port) for s in r.sessions} == {("S1", 40001), ("S2", 40002)}


def test_unmatched_and_ambiguous_connections_are_reported():
    r = match(
        [session(ports=(40009,))], [step("s1", 0.9, 1.2, "uname -a", port=40009)], base_events()
    )
    assert r.connections_unmatched == [f"{IP}:40009 no connect event"]
    assert states(r) == {"s1": "no_event"} and not r.settled()
    twice = [*base_events(), ev(0.1, "ssh_activity", "connect", sid="S9")]
    r = match([session()], [], twice)
    assert r.connections_unmatched == [f"{IP}:40001 2 connect events"]
    # same address and source port, another service: not this connection
    r = match(
        [session()], [], [ev(0, "network_activity", "connect", dst=8080, source="http-decoy")]
    )
    assert r.connections_unmatched == [f"{IP}:40001 no connect event"]


def test_a_session_still_open_is_not_settled():
    events = [e for e in base_events() if e.action != "disconnect"]
    r = match([session()], [step("s1", 0.9, 1.2, "uname -a")], events)
    assert states(r) == {"s1": "matched"} and r.open_sessions == 1 and not r.settled()


def test_upload_is_matched_by_the_files_hash():
    data_sha = input_hash(b"\x00\x01payload")
    events = [
        ev(0, "ssh_activity", "connect"),
        ev(2.0, "file_activity", "upload", {"sha256": data_sha, "filename": "x.bin"}),
        ev(5, "ssh_activity", "disconnect"),
    ]
    ok = step("up", 1.9, 2.3, evidence="upload", sha=data_sha, technique="T1105")
    r = match([session()], [ok], events)
    assert states(r) == {"up": "matched"} and r.labels[0].role == "input"
    other = step("up", 1.9, 2.3, evidence="upload", sha=input_hash(b"other"), technique="T1105")
    assert states(match([session()], [other], events)) == {"up": "mismatch"}


def test_http_and_database_inputs_match_on_the_decision_and_label_the_content_event():
    kw = {"sid": "H1", "source": "http-decoy", "dst": 8080}
    events = [
        ev(0, "network_activity", "connect", **kw),
        ev(1.0, "policy_decision", "decide", {"input": "GET /.env", "request_id": "q1"}, **kw),
        ev(1.0, "http_activity", "request", {"path": "/.env", "request_id": "q1"}, **kw),
        ev(
            1.5,
            "policy_decision",
            "decide",
            {"input": "GET /favicon.ico", "request_id": "q2"},
            **kw,
        ),
        ev(1.5, "http_activity", "request", {"path": "/favicon.ico", "request_id": "q2"}, **kw),
        ev(2, "network_activity", "disconnect", **kw),
    ]
    s = step("g1", 0.9, 1.2, "GET /.env")
    r = match([session(protocol="http", dst=8080)], [s], events)
    assert states(r) == {"g1": "matched"}
    assert sorted(lab.role for lab in r.labels) == ["decision", "input"]
    labelled = {lab.event_id for lab in r.labels}
    assert all(e.event_id in labelled for e in events if e.payload.get("request_id") == "q1")
    assert not any(e.event_id in labelled for e in events if e.payload.get("request_id") == "q2")


def test_truth_rows_have_one_key_per_record():
    run = RunRecord(
        run_id="r1", mode="capture", started_ts=T0, ended_ts=at(60), seed=1, attack_version="20.1",
        catalogue_sha256="a" * 64, scenarios_sha256="b" * 64, code_version="dev",
        scenarios=["sc"], sessions=1, steps=1,
    )  # fmt: skip
    rows = [truth_row(x) for x in (step("s1", 1, 2, "id"), session(), run)]
    assert [(r["kind"], r["key"]) for r in rows] == [
        ("step", "a/0/s1"),
        ("session", "a/0"),
        ("run", "r1"),
    ]
    assert all(r["run_id"] == "r1" for r in rows)
