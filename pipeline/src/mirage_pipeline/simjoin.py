"""Label join (phase 2 spec, section 3): ground truth from the lab -> labels on captured events.

The runner knows the source address and port of every connection it opened, and the decoys log
both, so the join is exact, not a guess from time:

1. a connection in the ground truth matches exactly one captured connect event, which gives
   the decoy's session;
2. inside that session, a step matches an input in the step's time window;
3. the match is accepted only if what was captured hashes to what the runner sent.

Every step ends in one state: ``matched``, ``no_event`` (it ran, nothing was captured),
``mismatch`` (something was captured in the window, but not what the runner sent) or
``not_run``. ``no_event`` and ``mismatch`` mean the capture or the join is wrong; the dataset
builder refuses a run that has either.

The evidence is counted, not just found. A login step is matched only if the captured
attempts agree with what the runner says it did (how many, where the record says, and whether
one succeeded); an HTTP, Redis or MySQL step only if the decision's content event, linked by
request ID, was captured too. Anything less is a ``mismatch`` that says what was missing.

The service stores every ground-truth record in ``mirage.sim_truth`` and joins a run when its
closing ``run`` record has arrived and its sessions have settled. All state is in ClickHouse,
so a restart, or ``mirage-sim-join --run ID``, repeats the same join.

Lost ground truth is part of the result (``mirage.sim_runs``), not a log line:

* ``truth_sessions_missing`` / ``truth_steps_missing``: the run record counts what the runner
  wrote; fewer records arrived.
* ``truth_invalid``: records of the run that did not validate. They are kept in
  ``mirage.sim_truth`` with kind ``invalid`` and counted, not silently dropped.
* ``incomplete``: the closing record never arrived. After ``ORPHAN_WAIT_S`` without a new
  record the run is joined with what there is, so it shows up; if the closing record turns
  up later the run is joined again and the row replaced.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import signal
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import nats
from nats.js.api import AckPolicy, ConsumerConfig

from mirage_pipeline.normaliser import ClickHouse, Settings, _retry, ensure_streams
from mirage_pipeline.rows import _ch_ts
from mirage_schema.groundtruth import (
    GroundTruth,
    RunRecord,
    SessionTruth,
    input_hash,
    parse_record,
)

log = logging.getLogger("mirage.simjoin")
HEALTH = Path("/tmp/mirage-simjoin.alive")  # noqa: S108 container-private

SLACK = timedelta(milliseconds=250)  # widening of a step's window (spec section 3)
SETTLE_S = 8  # events take a few seconds to reach ClickHouse
GIVE_UP_S = 120  # after this long a run is joined with whatever has arrived
ORPHAN_WAIT_S = 600  # a run silent this long without its closing record is joined incomplete
ORPHAN_CHECK_S = 30  # how often the service looks for such runs


def _ts(value: str) -> datetime:
    """A ClickHouse DateTime64 string as an aware datetime."""
    return datetime.fromisoformat(value.replace(" ", "T")).replace(tzinfo=UTC)


@dataclass
class Event:
    event_id: str
    ts: datetime
    source: str
    cls: str
    action: str
    outcome: str
    session_id: str
    src_ip: str
    src_port: int
    dst_port: int
    payload: dict[str, Any]

    @classmethod
    def from_row(cls, r: dict[str, Any]) -> Event:
        payload = r["payload"]
        return cls(
            r["event_id"],
            _ts(r["ts_text"]),  # not "ts": an alias of that name would shadow the column
            r["source"],
            r["class"],
            r["action"],
            r["outcome"],
            r["session_id"],
            r["src_ip"],
            int(r["src_port"]),
            int(r["dst_port"]),
            json.loads(payload) if isinstance(payload, str) else payload,
        )

    # What kind of evidence this event can be, and the hash it offers.

    def is_connect(self) -> bool:
        return self.action == "connect" and self.source != "policy"

    def is_decision(self) -> bool:
        return self.cls == "policy_decision" and self.source != "policy"

    def is_ssh_line(self) -> bool:
        return (
            self.source == "cowrie"
            and self.cls == "process_activity"
            and self.action == "command"
            and self.outcome == "unknown"
        )

    def is_content(self) -> bool:
        """The event that carries an input's full content (the tagger reads these)."""
        return self.is_ssh_line() or (
            self.cls in ("http_activity", "datastore_activity")
            and self.action in ("request", "query")
        )

    def input_sha(self) -> str | None:
        if self.is_ssh_line():
            return input_hash(str(self.payload.get("command", "")))
        if self.is_decision() and self.source != "cowrie":
            return input_hash(str(self.payload.get("input", "")))
        return None


@dataclass
class Label:
    event_id: str
    session_id: str
    role: str  # "input": the content-bearing event; "decision": a gate decision for it
    step: GroundTruth


@dataclass
class StepState:
    step: GroundTruth
    state: str  # matched | no_event | mismatch | not_run
    session_id: str = ""
    events: int = 0  # events labelled for the step
    detail: str = ""
    # Less was captured than the runner sent, so more may still be on its way: the join is
    # not settled yet. (A mismatch that more events cannot repair is final at once.)
    waiting: bool = False
    # A matched login step whose record says nothing to count the captured attempts against.
    uncounted: bool = False


@dataclass
class SessionRow:
    truth: SessionTruth
    session_id: str
    src_ip: str
    src_port: int


@dataclass
class JoinResult:
    labels: list[Label] = field(default_factory=list)
    steps: list[StepState] = field(default_factory=list)
    sessions: list[SessionRow] = field(default_factory=list)
    connections: int = 0
    connections_unmatched: list[str] = field(default_factory=list)
    open_sessions: int = 0  # matched sessions with no disconnect event yet
    # What the ground truth itself is missing, filled in by Joiner.join (see truth_health).
    truth_sessions_missing: int = 0
    truth_steps_missing: int = 0
    truth_invalid: int = 0
    incomplete: bool = False  # the run's closing record never arrived
    truth_problems: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = {"matched": 0, "no_event": 0, "mismatch": 0, "not_run": 0}
        for s in self.steps:
            out[s.state] += 1
        return out

    def settled(self) -> bool:
        """Nothing more is expected: every record the runner wrote is here, every connection
        found its session and every session has closed, and no step is still waiting for an
        event."""
        c = self.counts()
        return (
            not self.connections_unmatched
            and not self.open_sessions
            and c["no_event"] == 0
            and not any(s.waiting for s in self.steps)
            and not self.truth_sessions_missing
            and not self.truth_steps_missing
        )

    def problems(self) -> list[str]:
        """Everything wrong with the run, worst first, one line each."""
        uncounted = sum(1 for s in self.steps if s.uncounted)
        return (
            self.truth_problems
            + self.connections_unmatched
            + [
                f"{s.step.session_ref}/{s.step.step_id}: {s.state} {s.detail}".strip()
                for s in self.steps
                if s.state in ("no_event", "mismatch")
            ]
            + (
                [f"{uncounted} login steps carry no attempt count; their evidence was not counted"]
                if uncounted
                else []
            )
        )


def match(
    sessions: list[SessionTruth], steps: list[GroundTruth], events: list[Event]
) -> JoinResult:
    """The join itself, as a function of its inputs."""
    result = JoinResult()
    connects: dict[tuple[str, int], list[Event]] = {}
    by_session: dict[str, list[Event]] = {}
    for ev in sorted(events, key=lambda e: e.ts):
        by_session.setdefault(ev.session_id, []).append(ev)
        if ev.is_connect():
            connects.setdefault((ev.src_ip, ev.src_port), []).append(ev)

    # 1. connection -> decoy session, exactly one
    session_of: dict[tuple[str, int], str] = {}
    for truth in sessions:
        for conn in truth.connections:
            result.connections += 1
            key = (str(conn.src.ip), int(conn.src.port or 0))
            found = [e for e in connects.get(key, []) if e.dst_port == conn.dst.port]
            if len(found) != 1:
                what = "no connect event" if not found else f"{len(found)} connect events"
                result.connections_unmatched.append(f"{key[0]}:{key[1]} {what}")
                continue
            sid = found[0].session_id
            session_of[key] = sid
            result.sessions.append(SessionRow(truth, sid, key[0], key[1]))
            if not any(e.action == "disconnect" for e in by_session.get(sid, [])):
                result.open_sessions += 1

    # 2 and 3. step -> events, in time order, each event used once
    used: set[str] = set()
    for step in sorted(steps, key=lambda s: (s.session_ref, s.start_ts)):
        if step.status != "ran":
            result.steps.append(StepState(step, "not_run"))
            continue
        sid = session_of.get((str(step.src.ip), int(step.src.port or 0)), "")
        if not sid:
            result.steps.append(
                StepState(step, "no_event", detail="its connection was not matched")
            )
            continue
        lo, hi = step.start_ts - SLACK, step.end_ts + SLACK
        session_events = by_session.get(sid, [])
        window = [e for e in session_events if lo <= e.ts <= hi and e.event_id not in used]
        state = _match_step(step, sid, window, session_events, used, result)
        result.steps.append(state)
    return result


def _match_step(
    step: GroundTruth,
    sid: str,
    window: list[Event],
    session_events: list[Event],
    used: set[str],
    result: JoinResult,
) -> StepState:
    def take(ev: Event, role: str) -> None:
        used.add(ev.event_id)
        result.labels.append(Label(ev.event_id, sid, role, step))

    if step.evidence == "connect":
        found = [e for e in window if e.is_connect()]
        for ev in found:
            take(ev, "input")
        return StepState(step, "matched" if found else "no_event", sid, len(found))

    if step.evidence == "auth":
        found = [e for e in window if e.cls == "authentication" and e.action == "login"]
        if not found:
            return StepState(step, "no_event", sid)
        problem, waiting = _auth_problem(step, found)
        if problem:
            return StepState(step, "mismatch", sid, detail=problem, waiting=waiting)
        for ev in found:
            take(ev, "input")
        return StepState(step, "matched", sid, len(found), uncounted=_attempts(step) is None)

    if step.evidence == "upload":
        uploads = [e for e in window if e.action == "upload"]
        hit = next((e for e in uploads if e.payload.get("sha256") == step.input_sha256), None)
        if hit is None:
            state = "mismatch" if uploads else "no_event"
            return StepState(step, state, sid, detail="no upload with the file's hash")
        take(hit, "input")
        return StepState(step, "matched", sid, 1)

    # evidence == "input": a typed line (SSH) or one gated input (HTTP, Redis, MySQL)
    candidates = [e for e in window if e.input_sha() is not None]
    hit = next((e for e in candidates if e.input_sha() == step.input_sha256), None)
    if hit is None:
        if not candidates:
            return StepState(step, "no_event", sid)
        seen = str(candidates[0].payload.get("command") or candidates[0].payload.get("input"))
        return StepState(step, "mismatch", sid, detail=f"captured {seen[:120]!r} instead")
    n = 1
    if hit.is_ssh_line():
        take(hit, "input")
        # One line can be several gated commands (a pipeline, a list). Its decisions are the
        # ones between this line and the session's next line.
        later = [e.ts for e in session_events if e.is_ssh_line() and e.ts > hit.ts]
        until = min(later) if later else datetime.max.replace(tzinfo=UTC)
        for ev in session_events:
            if ev.is_decision() and hit.ts <= ev.ts < until and ev.event_id not in used:
                take(ev, "decision")
                n += 1
    else:
        # The decision carries the canonical input; the request or query event carries the
        # content the tagger reads, and the two share a request ID (spec section 3 and 12).
        # A label on the decision alone would be a label on nothing a model is trained on.
        rid = hit.payload.get("request_id")
        content = [
            ev
            for ev in session_events
            if rid
            and ev.is_content()
            and ev.payload.get("request_id") == rid
            and ev.event_id not in used
        ]
        if not content:
            why = (
                f"the decision was captured, but no content event with its request ID {rid}"
                if rid
                else "the decision was captured, but it carries no request ID"
            )
            return StepState(step, "mismatch", sid, detail=why, waiting=bool(rid))
        take(hit, "decision")
        for ev in content:
            take(ev, "input")
            n += 1
    return StepState(step, "matched", sid, n)


def _attempts(step: GroundTruth) -> int | None:
    """How many login attempts the runner says it made in an auth step, if its record says.
    Read by name so that a record written before the field existed still loads."""
    value = getattr(step, "attempts", None)
    return int(value) if value is not None else None


def _auth_problem(step: GroundTruth, found: list[Event]) -> tuple[str, bool]:
    """Why the captured login attempts are not what the runner says it did ("" if they are),
    and whether events still on their way could make up the difference."""
    expected, captured = _attempts(step), len(found)
    if expected is not None and captured != expected:
        return (
            f"the runner made {expected} login attempts, {captured} were captured",
            captured < expected,
        )
    # outcome on a login step is that connection's own result: "ok" ended in a success.
    succeeded = sum(1 for e in found if e.outcome == "success")
    want = {"ok": 1, "failed": 0}.get(step.outcome)
    if want is not None and succeeded != want:
        said = "logged in" if want else "failed to log in"
        return (
            f"the runner {said}, {succeeded} successful logins were captured",
            succeeded < want,
        )
    return "", False


# ---------------------------------------------------------------------------- storage


def truth_row(record: GroundTruth | SessionTruth | RunRecord) -> dict[str, Any]:
    if isinstance(record, GroundTruth):
        key, ts = f"{record.session_ref}/{record.step_id}", record.start_ts
    elif isinstance(record, SessionTruth):
        key, ts = record.session_ref, record.start_ts
    else:
        key, ts = record.run_id, record.ended_ts
    return {
        "run_id": record.run_id,
        "kind": record.kind,
        "key": key,
        "ts": _ch_ts(ts),
        "record": record.model_dump_json(),
    }


def read_record(data: bytes) -> GroundTruth | SessionTruth | RunRecord | dict[str, Any]:
    """One message off ``sim.groundtruth``: the record, or, when it does not validate, the
    ``mirage.sim_truth`` row that keeps it (kind ``invalid``) so that it is counted against its
    run instead of vanishing. The row's key is the hash of the message, so a redelivery does
    not count twice. Its ``run_id`` is empty when even that could not be read."""
    try:
        return parse_record(json.loads(data))
    except (ValueError, TypeError, AttributeError) as exc:  # not JSON, not an object, not valid
        text = data.decode(errors="replace")
        run_id = ""
        try:
            obj = json.loads(text)
        except ValueError:
            obj = None
        if isinstance(obj, dict) and isinstance(obj.get("run_id"), str):
            run_id = obj["run_id"]
        return {
            "run_id": run_id,
            "kind": "invalid",
            "key": hashlib.sha256(data).hexdigest(),
            "ts": _ch_ts(datetime.now(UTC)),
            "record": json.dumps(
                {"error": f"{type(exc).__name__}: {exc}"[:500], "data": text[:10_000]}
            ),
        }


@dataclass
class Truth:
    """What ``mirage.sim_truth`` holds for one run."""

    run: RunRecord | None = None
    sessions: list[SessionTruth] = field(default_factory=list)
    steps: list[GroundTruth] = field(default_factory=list)
    invalid: int = 0  # records that did not validate, on arrival or on reading back

    def empty(self) -> bool:
        return self.run is None and not self.sessions and not self.steps and not self.invalid


@dataclass
class Run:
    """A run as ``mirage.sim_runs`` describes it: the closing record's fields, or, when that
    record never arrived, what the session and step records that did arrive can say."""

    run_id: str
    mode: str
    started_ts: datetime
    ended_ts: datetime
    seed: int = 0
    attack_version: str = ""
    catalogue_sha256: str = ""
    scenarios_sha256: str = ""
    code_version: str = ""
    scenarios: list[str] = field(default_factory=list)
    sessions: int = 0
    steps: int = 0
    closed: bool = True

    @classmethod
    def of(cls, run_id: str, truth: Truth) -> Run:
        rec = truth.run
        if rec is not None:
            return cls(
                rec.run_id, rec.mode, rec.started_ts, rec.ended_ts, rec.seed, rec.attack_version,
                rec.catalogue_sha256, rec.scenarios_sha256, rec.code_version, rec.scenarios,
                rec.sessions, rec.steps,
            )  # fmt: skip
        records = [*truth.sessions, *truth.steps]
        now = datetime.now(UTC)
        return cls(
            run_id,
            # Every session of a run has the run's mode. With no session record it is unknown.
            mode=truth.sessions[0].mode if truth.sessions else "",
            started_ts=min((r.start_ts for r in records), default=now),
            ended_ts=max((r.end_ts for r in records), default=now),
            attack_version=truth.steps[0].attack_version if truth.steps else "",
            scenarios=sorted({r.scenario_id for r in records}),
            # The runner's own counts were in the record that is missing; these are what came.
            sessions=len(truth.sessions),
            steps=len(truth.steps),
            closed=False,
        )


def truth_health(run: Run, truth: Truth, result: JoinResult, silent_s: float | None = None) -> None:
    """Compare the ground truth that arrived with what the runner says it wrote, and put the
    difference on the result: the counts for ``mirage.sim_runs`` and a line each for
    ``problems``."""
    lines = []
    result.incomplete = not run.closed
    result.truth_invalid = truth.invalid
    if not run.closed:
        waited = f" (no record for {silent_s:.0f} s)" if silent_s is not None else ""
        lines.append(
            f"the run's closing record never arrived{waited}; joined as incomplete with the "
            f"{len(truth.sessions)} session and {len(truth.steps)} step records that did, and "
            "how many the runner wrote is unknown"
        )
    else:
        for what, said, got in (
            ("session", run.sessions, len(truth.sessions)),
            ("step", run.steps, len(truth.steps)),
        ):
            if got < said:
                lines.append(
                    f"{said - got} {what} records are missing: "
                    f"the runner wrote {said}, {got} arrived"
                )
            elif got > said:
                lines.append(
                    f"{got - said} more {what} records arrived than the runner counted ({said})"
                )
        result.truth_sessions_missing = max(run.sessions - len(truth.sessions), 0)
        result.truth_steps_missing = max(run.steps - len(truth.steps), 0)
    if truth.invalid:
        lines.append(f"{truth.invalid} ground-truth records did not validate and were not joined")
    result.truth_problems = lines


EVENTS_SQL = """
SELECT event_id, toString(ts) AS ts_text, source, class, action, outcome, session_id, src_ip,
       src_port, dst_port, payload
FROM mirage.events FINAL
WHERE src_ip IN {ips:Array(String)} AND source != 'policy'
  AND ts >= parseDateTime64BestEffort({lo:String}, 6, 'UTC')
  AND ts <= parseDateTime64BestEffort({hi:String}, 6, 'UTC')
"""


# Runs that have records but no closing record, with when the last one arrived (by ClickHouse's
# clock, which also says what time it is now, so the service's clock does not matter).
OPEN_RUNS_SQL = """
SELECT run_id, countIf(kind = 'run') AS closing, toString(max(ingested)) AS last_record,
       toString(now64(6, 'UTC')) AS asked
FROM mirage.sim_truth FINAL
WHERE run_id != ''
GROUP BY run_id
HAVING closing = 0
"""


class Joiner:
    def __init__(self, ch: ClickHouse, orphan_wait_s: float = ORPHAN_WAIT_S) -> None:
        self.ch = ch
        self.orphan_wait_s = orphan_wait_s

    async def store(
        self, records: list[GroundTruth | SessionTruth | RunRecord], invalid: Sequence[dict] = ()
    ) -> None:
        """Keep the records, and the rows that stand for records that did not validate."""
        await self.ch.insert([*(truth_row(r) for r in records), *invalid], "mirage.sim_truth")

    async def pending(self) -> list[str]:
        """Runs whose closing record has arrived and that have no final join yet. A join made
        without the closing record does not count: the record arriving late replaces it."""
        rows = await self.ch.select(
            "SELECT run_id FROM mirage.sim_truth FINAL WHERE kind = 'run' AND run_id NOT IN "
            "(SELECT run_id FROM mirage.sim_runs FINAL WHERE final = 1 AND incomplete = 0)"
        )
        return [r["run_id"] for r in rows]

    async def orphans(self) -> dict[str, float]:
        """Runs with records but no closing record that have been silent for the wait, and
        have not been joined since their last record arrived: run ID -> seconds of silence."""
        rows = await self.ch.select(OPEN_RUNS_SQL)
        if not rows:
            return {}
        joined = {
            r["run_id"]: int(r["version"])
            for r in await self.ch.select(
                "SELECT run_id, version FROM mirage.sim_runs FINAL WHERE final = 1"
            )
        }
        out = {}
        for r in rows:
            last = _ts(r["last_record"])
            silent = (_ts(r["asked"]) - last).total_seconds()
            # sim_runs.version is the join's time in microseconds: an older join missed records.
            current = joined.get(r["run_id"], -1) >= int(last.timestamp() * 1_000_000)
            if silent >= self.orphan_wait_s and not current:
                out[r["run_id"]] = silent
        return out

    async def load(self, run_id: str) -> Truth:
        rows = await self.ch.select(
            "SELECT kind, record FROM mirage.sim_truth FINAL WHERE run_id = {run:String}",
            run=run_id,
        )
        truth = Truth()
        for row in rows:
            if row["kind"] == "invalid":
                truth.invalid += 1
                continue
            try:
                rec = parse_record(json.loads(row["record"]))
            except ValueError:  # stored under an older schema that accepted it
                truth.invalid += 1
                continue
            if isinstance(rec, RunRecord):
                truth.run = rec
            elif isinstance(rec, SessionTruth):
                truth.sessions.append(rec)
            else:
                truth.steps.append(rec)
        return truth

    async def events_for(self, run: Run, sessions: list[SessionTruth]) -> list[Event]:
        ips = sorted({str(c.src.ip) for s in sessions for c in s.connections})
        events: list[Event] = []
        for i in range(0, len(ips), 500):
            rows = await self.ch.select(
                EVENTS_SQL,
                ips=ips[i : i + 500],
                lo=_ch_ts(run.started_ts - timedelta(seconds=5)),
                hi=_ch_ts(run.ended_ts + timedelta(seconds=GIVE_UP_S)),
            )
            events += [Event.from_row(r) for r in rows]
        return events

    async def join(
        self, run_id: str, force: bool = False, silent_s: float | None = None
    ) -> JoinResult | None:
        """Join one run and write the result. Returns None when the run is not ready: its
        closing record is missing, or records or events may still be on their way.

        ``silent_s`` is given for a run from :meth:`orphans`: it has gone that long without a
        record, so it is joined as incomplete although its closing record never arrived.
        ``force`` joins whatever there is, now."""
        truth = await self.load(run_id)
        if truth.empty() or (truth.run is None and silent_s is None and not force):
            return None
        run = Run.of(run_id, truth)
        age = (datetime.now(UTC) - run.ended_ts).total_seconds()
        if run.closed and not force and age < SETTLE_S:
            return None
        result = match(truth.sessions, truth.steps, await self.events_for(run, truth.sessions))
        truth_health(run, truth, result, silent_s)
        final = force or not run.closed or result.settled() or age >= GIVE_UP_S
        if not final:
            return None
        await self.write(run, result)
        return result

    async def logical_sessions(self, conn_ids: list[str]) -> dict[str, str]:
        """HTTP connections belong to a logical session the sessioniser assigns."""
        if not conn_ids:
            return {}
        rows = await self.ch.select(
            "SELECT conn_id, session_id FROM mirage.session_map FINAL "
            "WHERE conn_id IN {ids:Array(String)}",
            ids=conn_ids,
        )
        return {r["conn_id"]: r["session_id"] for r in rows}

    async def write(self, run: Run, result: JoinResult) -> None:
        version = time.time_ns() // 1000
        logical = await self.logical_sessions([s.session_id for s in result.sessions])
        await self.ch.insert(
            [
                {
                    "event_id": lab.event_id,
                    "run_id": run.run_id,
                    "scenario_id": lab.step.scenario_id,
                    "session_ref": lab.step.session_ref,
                    "step_id": lab.step.step_id,
                    "procedure_id": lab.step.procedure_id,
                    "technique_id": lab.step.technique_id or "",
                    "tactic": lab.step.tactic or "",
                    "attack_version": lab.step.attack_version,
                    "role": lab.role,
                    "session_id": lab.session_id,
                    "version": version,
                }
                for lab in result.labels
            ],
            "mirage.sim_labels",
        )
        await self.ch.insert(
            [
                {
                    "run_id": run.run_id,
                    "session_ref": st.step.session_ref,
                    "step_id": st.step.step_id,
                    "scenario_id": st.step.scenario_id,
                    "procedure_id": st.step.procedure_id,
                    "technique_id": st.step.technique_id or "",
                    "tactic": st.step.tactic or "",
                    "protocol": st.step.protocol,
                    "evidence": st.step.evidence,
                    "status": st.step.status,
                    "outcome": st.step.outcome,
                    "state": st.state,
                    "session_id": st.session_id,
                    "events": st.events,
                    "detail": st.detail,
                    "start_ts": _ch_ts(st.step.start_ts),
                    "end_ts": _ch_ts(st.step.end_ts),
                    "version": version,
                }
                for st in result.steps
            ],
            "mirage.sim_steps",
        )
        await self.ch.insert(
            [
                {
                    "session_id": s.session_id,
                    "run_id": run.run_id,
                    "scenario_id": s.truth.scenario_id,
                    "session_ref": s.truth.session_ref,
                    "logical_session_id": logical.get(s.session_id, s.session_id),
                    "protocol": s.truth.protocol,
                    "actor_ref": s.truth.actor_ref,
                    "actor_class": s.truth.actor_class,
                    "timing_profile": s.truth.timing_profile,
                    "real": int(s.truth.real),
                    "mode": s.truth.mode,
                    "src_ip": s.src_ip,
                    "src_port": s.src_port,
                    "version": version,
                }
                for s in result.sessions
            ],
            "mirage.sim_sessions",
        )
        counts = result.counts()
        await self.ch.insert(
            [
                {
                    "run_id": run.run_id,
                    "mode": run.mode,
                    "started_ts": _ch_ts(run.started_ts),
                    "ended_ts": _ch_ts(run.ended_ts),
                    "seed": run.seed,
                    "attack_version": run.attack_version,
                    "catalogue_sha256": run.catalogue_sha256,
                    "scenarios_sha256": run.scenarios_sha256,
                    "code_version": run.code_version,
                    "scenarios": run.scenarios,
                    "sessions": run.sessions,
                    "steps": run.steps,
                    "final": 1,
                    **counts,
                    "connections": result.connections,
                    "connections_unmatched": len(result.connections_unmatched),
                    "truth_sessions_missing": result.truth_sessions_missing,
                    "truth_steps_missing": result.truth_steps_missing,
                    "truth_invalid": result.truth_invalid,
                    "incomplete": int(result.incomplete),
                    "problems": "; ".join(result.problems())[:4000],
                    "version": version,
                }
            ],
            "mirage.sim_runs",
        )
        log.info(
            "joined %s%s: %s, %d of %d connections matched, %d labels",
            run.run_id,
            " (incomplete: no closing record)" if result.incomplete else "",
            counts,
            result.connections - len(result.connections_unmatched),
            result.connections,
            len(result.labels),
        )
        for line in result.truth_problems:
            log.warning("%s: %s", run.run_id, line)


# ---------------------------------------------------------------------------- service


async def run(s: Settings, stop: asyncio.Event) -> None:
    nc = await _retry("NATS", lambda: nats.connect(s.nats_url, max_reconnect_attempts=-1))
    js = nc.jetstream()
    await ensure_streams(js)
    ch = ClickHouse(s)
    await _retry("ClickHouse", ch.ping)
    joiner = Joiner(ch, float(os.environ.get("SIM_ORPHAN_WAIT_S", ORPHAN_WAIT_S)))
    await _retry("ClickHouse tables", joiner.pending)
    sub = await js.pull_subscribe(
        "sim.groundtruth",
        durable="sim-join-v1",
        stream="SIM",
        config=ConsumerConfig(ack_policy=AckPolicy.EXPLICIT, ack_wait=60, max_deliver=-1),
    )
    log.info("label join running")
    looked = float("-inf")  # when the runs without a closing record were last looked for
    while not stop.is_set():
        HEALTH.touch()
        try:
            msgs = await sub.fetch(s.batch_size, timeout=2)
        except TimeoutError:
            msgs = []
        records, invalid = [], []
        for m in msgs:
            out = read_record(m.data)
            (invalid if isinstance(out, dict) else records).append(out)
        if invalid:
            lost = sum(1 for row in invalid if not row["run_id"])
            log.error(
                "%d ground-truth records do not validate; kept as invalid and counted against "
                "their runs (%d name no run and count against none)",
                len(invalid),
                lost,
            )
        try:
            await joiner.store(records, invalid)
        except Exception:
            log.exception("storing ground truth failed; will be redelivered")
            for m in msgs:
                await m.nak(delay=5)
            await asyncio.sleep(5)
            continue
        # Stored, so acknowledged. A join that fails after this is retried from ClickHouse on
        # the next pass; the messages must not be touched again (a nak after an ack raises).
        for m in msgs:
            await m.ack()
        try:
            for run_id in await joiner.pending():
                await joiner.join(run_id)
            if time.monotonic() - looked >= ORPHAN_CHECK_S:
                for run_id, silent_s in (await joiner.orphans()).items():
                    await joiner.join(run_id, silent_s=silent_s)
                looked = time.monotonic()
        except Exception:
            log.exception("label join failed; will retry")
            await asyncio.sleep(5)
    await ch.close()
    await nc.drain()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage-sim-join")
    ap.add_argument("--run", help="join this run again now, and exit")
    args = ap.parse_args(argv)
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.Formatter.converter = time.gmtime
    logging.getLogger("httpx").setLevel(logging.WARNING)
    stop = asyncio.Event()

    async def _once(run_id: str) -> None:
        ch = ClickHouse(Settings.from_env())
        result = await Joiner(ch).join(run_id, force=True)
        print(json.dumps(result.counts() if result else {"error": "no such run"}))
        await ch.close()

    async def _main() -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        await run(Settings.from_env(), stop)

    asyncio.run(_once(args.run) if args.run else _main())


def healthcheck() -> None:
    raise SystemExit(0 if HEALTH.exists() and time.time() - HEALTH.stat().st_mtime < 30 else 1)


if __name__ == "__main__":
    main()
