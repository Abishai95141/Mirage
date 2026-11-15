"""Label join: exact on the connection, then on the window, then on the hash of the input;
evidence that is counted, and ground truth whose loss shows in the result."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from mirage_pipeline.rows import _ch_ts
from mirage_pipeline.simjoin import (
    Event,
    Joiner,
    Run,
    Truth,
    match,
    read_record,
    truth_health,
    truth_row,
)
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


class CountedStep(GroundTruth):
    """A step record that says how many login attempts the runner made. The schema has no
    such field yet (the lab runner knows the number and does not write it); the join reads
    ``attempts`` by name, so this is the record it will get once the field exists."""

    attempts: int | None = None


def step(step_id, t0, t1, text=None, *, port=40001, status="ran", evidence="input", sha=None,
         technique="T1082", ref="a/0", outcome="unchecked", attempts=None) -> GroundTruth:  # fmt: skip
    fields = dict(
        run_id="r1", scenario_id="sc", session_ref=ref, step_id=step_id, procedure_id=f"p-{step_id}",
        technique_id=technique, tactic="TA0007" if technique else None, attack_version="20.1",
        protocol="ssh", src={"ip": IP, "port": port}, dst={"ip": "172.26.0.2", "port": 2222},
        evidence=evidence,
        input_sha256=sha or (input_hash(text) if text is not None else None),
        start_ts=at(t0), end_ts=at(t1), status=status, outcome=outcome,
    )  # fmt: skip
    if attempts is None:
        return GroundTruth(**fields)
    return CountedStep(**fields, attempts=attempts)


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
        # Changed with R7: the login step now carries what the runner did (two attempts, the
        # second one in), because a login step that says nothing is no longer fully verified.
        step("login", 0.1, 0.5, evidence="auth", technique="T1110.001", attempts=2, outcome="ok"),
        step("s1", 0.9, 1.2, "uname -a"),
        step("s2", 1.9, 2.2, "id; echo done"),
        step("s3", 2.9, 3.2, "ls -la /tmp", technique=None),
    ]
    r = match([session()], steps, base_events())
    assert states(r) == {"login": "matched", "s1": "matched", "s2": "matched", "s3": "matched"}
    assert r.counts() == {"matched": 4, "no_event": 0, "mismatch": 0, "not_run": 0}
    assert r.settled() and not r.connections_unmatched
    assert r.problems() == []  # nothing to report, the uncounted-login line included
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


# ------------------------------------------------------------------ R7: evidence is counted


def login_step(**kw) -> GroundTruth:
    return step("login", 0.1, 0.5, evidence="auth", technique="T1110.001", **kw)


def test_a_login_step_is_matched_only_when_every_attempt_was_captured():
    # base_events holds two login attempts in the window: one failure, then the success.
    r = match([session()], [login_step(attempts=2, outcome="ok")], base_events())
    (s,) = r.steps
    assert (s.state, s.events, s.uncounted) == ("matched", 2, False)

    # The runner made three; one never reached the store. Not a label, and not settled:
    # the third may still be on its way, so the join waits before it calls this final.
    r = match([session()], [login_step(attempts=3, outcome="ok")], base_events())
    (s,) = r.steps
    assert s.state == "mismatch" and s.detail == "the runner made 3 login attempts, 2 were captured"
    assert r.labels == [] and s.waiting and not r.settled()

    # More captured than made cannot be repaired by waiting: final at once.
    r = match([session()], [login_step(attempts=1, outcome="ok")], base_events())
    (s,) = r.steps
    assert s.state == "mismatch" and "1 login attempts, 2 were captured" in s.detail
    assert r.labels == [] and not s.waiting and r.settled()


def test_a_login_step_s_outcome_must_agree_with_the_captured_logins():
    # The runner says this connection never got in, but a successful login was captured.
    r = match([session()], [login_step(attempts=2, outcome="failed")], base_events())
    (s,) = r.steps
    assert s.state == "mismatch" and not s.waiting
    assert s.detail == "the runner failed to log in, 1 successful logins were captured"

    # The runner says it got in; only the failure was captured.
    failures_only = [e for e in base_events() if e.outcome != "success"]
    r = match([session()], [login_step(outcome="ok")], failures_only)
    (s,) = r.steps
    assert s.state == "mismatch" and s.waiting
    assert s.detail == "the runner logged in, 0 successful logins were captured"

    # No login event at all is still no_event, as before.
    quiet = [e for e in base_events() if e.cls != "authentication"]
    assert states(match([session()], [login_step(attempts=2, outcome="ok")], quiet)) == {
        "login": "no_event"
    }


def test_a_login_step_without_a_count_is_matched_and_reported_as_uncounted():
    # What today's runner writes: no attempt count. The step keeps its labels, the run stays
    # healthy, and the run's problems say the evidence was not counted.
    r = match([session()], [login_step(outcome="ok")], base_events())
    (s,) = r.steps
    assert s.state == "matched" and s.uncounted and r.settled()
    assert r.problems() == ["1 login steps carry no attempt count; their evidence was not counted"]


def gated(kind="http") -> tuple[dict, list[Event]]:
    """One gated input and its content event on a non-SSH decoy."""
    if kind == "http":
        kw = {"sid": "H1", "source": "http-decoy", "dst": 8080}
        content = ev(1.0, "http_activity", "request", {"path": "/.env", "request_id": "q1"}, **kw)
        text = "GET /.env"
    else:
        kw = {"sid": "D1", "source": "db-decoy", "dst": 3306}
        content = ev(1.0, "datastore_activity", "query", {"request_id": "q1"}, **kw)
        text = "SELECT * FROM customers"
    events = [
        ev(0, "network_activity", "connect", **kw),
        ev(1.0, "policy_decision", "decide", {"input": text, "request_id": "q1"}, **kw),
        content,
        ev(2, "network_activity", "disconnect", **kw),
    ]
    return {"text": text, "dst": kw["dst"], "protocol": kind}, events


def test_a_gated_input_needs_its_content_event():
    for kind in ("http", "mysql"):
        about, events = gated(kind)
        truth = [session(protocol=about["protocol"], dst=about["dst"])]
        s1 = step("g1", 0.9, 1.2, about["text"])
        assert states(match(truth, [s1], events)) == {"g1": "matched"}

        # The decision alone used to be "matched", with a label on the decision only. The
        # content event is what the tagger reads, so without it the step is a mismatch.
        decision_only = [e for e in events if not e.is_content()]
        r = match(truth, [s1], decision_only)
        (s,) = r.steps
        assert s.state == "mismatch" and "no content event with its request ID q1" in s.detail
        assert r.labels == [] and s.waiting and not r.settled()

    # A decision with no request ID cannot be linked to anything, now or later.
    about, events = gated("http")
    for e in events:
        e.payload.pop("request_id", None)
    r = match([session(protocol="http", dst=8080)], [step("g1", 0.9, 1.2, about["text"])], events)
    (s,) = r.steps
    assert s.state == "mismatch" and "carries no request ID" in s.detail and not s.waiting


# ------------------------------------------------------------------ R2: lost ground truth


def run_record(sessions=1, steps=1, run_id="r1") -> RunRecord:
    return RunRecord(
        run_id=run_id, mode="capture", started_ts=T0, ended_ts=at(60), seed=1,
        attack_version="20.1", catalogue_sha256="a" * 64, scenarios_sha256="b" * 64,
        code_version="dev", scenarios=["sc"], sessions=sessions, steps=steps,
    )  # fmt: skip


def test_truth_health_reports_records_the_runner_wrote_that_never_arrived():
    truth = Truth(run_record(sessions=3, steps=5), [session()], [step("s1", 0.9, 1.2, "uname -a")])
    result = match(truth.sessions, truth.steps, base_events())
    assert result.settled()  # as far as the records that arrived go
    truth_health(Run.of("r1", truth), truth, result)
    assert (result.truth_sessions_missing, result.truth_steps_missing) == (2, 4)
    assert not result.incomplete and result.truth_invalid == 0
    assert result.problems()[:2] == [
        "2 session records are missing: the runner wrote 3, 1 arrived",
        "4 step records are missing: the runner wrote 5, 1 arrived",
    ]
    assert not result.settled()  # records may still be on their way: wait before calling it final

    # Everything arrived: nothing to say.
    truth = Truth(run_record(1, 1), [session()], [step("s1", 0.9, 1.2, "uname -a")])
    result = match(truth.sessions, truth.steps, base_events())
    truth_health(Run.of("r1", truth), truth, result)
    assert result.problems() == [] and result.settled()

    # More than the runner counted is not a shortfall, but it is said.
    truth = Truth(run_record(0, 1), [session()], [step("s1", 0.9, 1.2, "uname -a")])
    result = match(truth.sessions, truth.steps, base_events())
    truth_health(Run.of("r1", truth), truth, result)
    assert result.truth_sessions_missing == 0
    assert result.problems() == ["1 more session records arrived than the runner counted (0)"]


def test_a_record_that_does_not_validate_is_kept_and_counted_not_dropped():
    good = step("s1", 0.9, 1.2, "uname -a")
    assert read_record(good.model_dump_json().encode()) == good

    # Valid JSON, wrong record: the run ID can still be read, so it counts against its run.
    bad = json.dumps({**json.loads(good.model_dump_json()), "status": "exploded"}).encode()
    row = read_record(bad)
    assert (row["run_id"], row["kind"]) == ("r1", "invalid")
    assert "status" in json.loads(row["record"])["error"]
    assert read_record(bad)["key"] == row["key"]  # a redelivery replaces, it does not add

    # Not an object, and not JSON at all: kept under no run. Neither may stop the service
    # (a JSON array used to raise AttributeError out of the loop).
    for junk in (b"[1, 2]", b'"text"', b"{not json"):
        row = read_record(junk)
        assert (row["run_id"], row["kind"]) == ("", "invalid")


def event_row(e: Event) -> dict:
    return {
        "event_id": e.event_id, "ts_text": _ch_ts(e.ts), "source": e.source, "class": e.cls,
        "action": e.action, "outcome": e.outcome, "session_id": e.session_id, "src_ip": e.src_ip,
        "src_port": e.src_port, "dst_port": e.dst_port, "payload": json.dumps(e.payload),
    }  # fmt: skip


class FakeStore:
    """ClickHouse as the Joiner uses it: ``sim_truth`` and ``sim_runs`` as replacing tables
    read with FINAL, the events, and a clock that stamps ``ingested`` and answers ``now64``."""

    def __init__(self, events=()) -> None:
        self.events = list(events)
        self.tables: dict[str, list[dict]] = {}
        self.now = datetime.now(UTC)

    async def insert(self, rows, table=None):
        for row in rows:
            extra = {"ingested": self.now} if table == "mirage.sim_truth" else {}
            self.tables.setdefault(table, []).append({**row, **extra})

    def truth(self) -> list[dict]:
        latest = {}
        for row in self.tables.get("mirage.sim_truth", []):
            latest[row["run_id"], row["kind"], row["key"]] = row
        return list(latest.values())

    def runs(self) -> dict[str, dict]:
        latest: dict[str, dict] = {}
        for row in self.tables.get("mirage.sim_runs", []):
            if row["run_id"] not in latest or row["version"] >= latest[row["run_id"]]["version"]:
                latest[row["run_id"]] = row
        return latest

    async def select(self, sql, **params):
        if "mirage.session_map" in sql:
            return []
        if "FROM mirage.events" in sql:
            return [event_row(e) for e in self.events if e.src_ip in params["ips"]]
        if "SELECT kind, record" in sql:
            return [r for r in self.truth() if r["run_id"] == params["run"]]
        final = [r for r in self.runs().values() if r["final"] == 1]
        if "GROUP BY run_id" in sql:  # OPEN_RUNS_SQL: runs with records and no closing record
            by_run: dict[str, list[dict]] = {}
            for r in self.truth():
                if r["run_id"]:
                    by_run.setdefault(r["run_id"], []).append(r)
            return [
                {
                    "run_id": run_id,
                    "closing": "0",
                    "last_record": _ch_ts(max(r["ingested"] for r in rows)),
                    "asked": _ch_ts(self.now),
                }
                for run_id, rows in by_run.items()
                if not any(r["kind"] == "run" for r in rows)
            ]
        if "kind = 'run'" in sql:  # pending: closed, and no final join of the closed run
            assert "incomplete = 0" in sql
            done = {r["run_id"] for r in final if not r["incomplete"]}
            return [
                {"run_id": r["run_id"]}
                for r in self.truth()
                if r["kind"] == "run" and r["run_id"] not in done
            ]
        assert "FROM mirage.sim_runs FINAL WHERE final = 1" in sql
        return [{"run_id": r["run_id"], "version": str(r["version"])} for r in final]


async def test_join_writes_the_shortfall_and_the_invalid_count_to_sim_runs():
    store = FakeStore(base_events())
    joiner = Joiner(store)
    s1 = step("s1", 0.9, 1.2, "uname -a")
    invalid = read_record(b'{"run_id": "r1", "kind": "step", "step_id": "s9"}')
    await joiner.store([session(), s1, run_record(sessions=2, steps=3)], [invalid])

    result = await joiner.join("r1")  # the run ended long ago, so this is final
    assert result is not None and result.counts()["matched"] == 1
    (row,) = store.tables["mirage.sim_runs"]
    assert (row["truth_sessions_missing"], row["truth_steps_missing"]) == (1, 2)
    assert (row["truth_invalid"], row["incomplete"], row["final"]) == (1, 0, 1)
    assert row["sessions"] == 2 and row["steps"] == 3  # what the runner says it wrote
    assert row["problems"] == (
        "1 session records are missing: the runner wrote 2, 1 arrived; "
        "2 step records are missing: the runner wrote 3, 1 arrived; "
        "1 ground-truth records did not validate and were not joined"
    )
    assert await joiner.pending() == []


async def test_a_stored_record_that_no_longer_validates_is_counted_not_fatal():
    store = FakeStore(base_events())
    joiner = Joiner(store)
    await joiner.store([session(), run_record(1, 1)])
    old = truth_row(step("s1", 0.9, 1.2, "uname -a"))
    await store.insert([{**old, "record": '{"kind": "step", "run_id": "r1"}'}], "mirage.sim_truth")
    truth = await joiner.load("r1")
    assert (len(truth.sessions), len(truth.steps), truth.invalid) == (1, 0, 1)
    assert (await joiner.join("r1")).truth_invalid == 1


async def test_a_run_without_its_closing_record_is_joined_as_incomplete_after_the_wait():
    store = FakeStore(base_events())
    joiner = Joiner(store, orphan_wait_s=600)
    await joiner.store([session(), step("s1", 0.9, 1.2, "uname -a")])  # no run record

    # Not before the wait: the runner may still be working.
    store.now += timedelta(seconds=599)
    assert await joiner.pending() == [] and await joiner.orphans() == {}
    assert await joiner.join("r1") is None and "mirage.sim_runs" not in store.tables

    store.now += timedelta(seconds=2)
    orphans = await joiner.orphans()
    assert list(orphans) == ["r1"] and 600 <= orphans["r1"] < 602
    result = await joiner.join("r1", silent_s=orphans["r1"])
    assert result is not None and result.incomplete and result.counts()["matched"] == 1
    (row,) = store.tables["mirage.sim_runs"]
    assert (row["final"], row["incomplete"], row["mode"]) == (1, 1, "capture")
    assert (row["sessions"], row["steps"], row["matched"]) == (1, 1, 1)
    assert row["problems"].startswith(
        "the run's closing record never arrived (no record for 601 s)"
    )
    assert len(store.tables["mirage.sim_labels"]) == 2  # what did arrive is joined as usual

    # Joined, so not an orphan again while nothing new arrives ...
    store.now += timedelta(seconds=3600)
    assert await joiner.orphans() == {}
    # ... but a record that arrives after that join makes it stale, once the run is silent again.
    await joiner.store([step("s2", 1.9, 2.2, "id; echo done")])
    assert await joiner.orphans() == {}
    store.now += timedelta(seconds=601)
    assert list(await joiner.orphans()) == ["r1"]


async def test_a_late_closing_record_replaces_the_incomplete_join():
    store = FakeStore(base_events())
    joiner = Joiner(store, orphan_wait_s=600)
    await joiner.store([session(), step("s1", 0.9, 1.2, "uname -a")])
    store.now += timedelta(seconds=700)
    await joiner.join("r1", silent_s=700.0)
    assert store.runs()["r1"]["incomplete"] == 1

    await joiner.store([run_record(1, 1)])
    assert await joiner.pending() == ["r1"]  # an incomplete join is not the run's final word
    await joiner.join("r1")
    row = store.runs()["r1"]
    assert (row["final"], row["incomplete"], row["problems"]) == (1, 0, "")
    assert row["seed"] == 1 and row["catalogue_sha256"] == "a" * 64
    assert await joiner.pending() == [] and await joiner.orphans() == {}


async def test_a_run_of_nothing_but_invalid_records_still_shows_up():
    store = FakeStore()
    joiner = Joiner(store, orphan_wait_s=600)
    await joiner.store([], [read_record(b'{"run_id": "r7", "kind": "run", "seed": "x"}')])
    store.now += timedelta(seconds=601)
    orphans = await joiner.orphans()
    result = await joiner.join("r7", silent_s=orphans["r7"])
    assert result is not None
    (row,) = store.tables["mirage.sim_runs"]
    assert (row["run_id"], row["incomplete"], row["truth_invalid"]) == ("r7", 1, 1)
    assert "1 ground-truth records did not validate" in row["problems"]
    assert await joiner.join("nope", force=True) is None  # a run with no record at all
