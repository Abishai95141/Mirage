"""Label join (phase 2 spec, section 3): ground truth from the lab -> labels on captured events.

The runner knows the source address and port of every connection it opened, and the decoys log
both, so the join is exact, not a guess from time:

1. a connection in the ground truth matches exactly one captured connect event, which gives
   the decoy's session;
2. inside that session, a step matches an input in the step's time window;
3. the match is accepted only if what was captured hashes to what the runner sent.

Every step ends in one state: ``matched``, ``no_event`` (it ran, nothing was captured),
``mismatch`` (something was captured in the window, but not that input) or ``not_run``.
``no_event`` and ``mismatch`` mean the capture or the join is wrong; the dataset builder
refuses a run that has either.

The service stores every ground-truth record in ``mirage.sim_truth`` and joins a run when its
closing ``run`` record has arrived and its sessions have settled. All state is in ClickHouse,
so a restart, or ``mirage-sim-join --run ID``, repeats the same join.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import time
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
    events: int = 0
    detail: str = ""


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

    def counts(self) -> dict[str, int]:
        out = {"matched": 0, "no_event": 0, "mismatch": 0, "not_run": 0}
        for s in self.steps:
            out[s.state] += 1
        return out

    def settled(self) -> bool:
        """Nothing more is expected: every connection found its session and every session
        has closed, and no step is still waiting for its event."""
        c = self.counts()
        return not self.connections_unmatched and not self.open_sessions and c["no_event"] == 0


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
        for ev in found:
            take(ev, "input")
        return StepState(step, "matched" if found else "no_event", sid, len(found))

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
        take(hit, "decision")
        rid = hit.payload.get("request_id")
        for ev in session_events:
            same = ev.is_content() and rid and ev.payload.get("request_id") == rid
            if same and ev.event_id not in used:
                take(ev, "input")
                n += 1
    return StepState(step, "matched", sid, n)


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


EVENTS_SQL = """
SELECT event_id, toString(ts) AS ts_text, source, class, action, outcome, session_id, src_ip,
       src_port, dst_port, payload
FROM mirage.events FINAL
WHERE src_ip IN {ips:Array(String)} AND source != 'policy'
  AND ts >= parseDateTime64BestEffort({lo:String}, 6, 'UTC')
  AND ts <= parseDateTime64BestEffort({hi:String}, 6, 'UTC')
"""


class Joiner:
    def __init__(self, ch: ClickHouse) -> None:
        self.ch = ch

    async def store(self, records: list[GroundTruth | SessionTruth | RunRecord]) -> None:
        await self.ch.insert([truth_row(r) for r in records], "mirage.sim_truth")

    async def pending(self) -> list[str]:
        """Runs whose closing record has arrived and that have no final join yet."""
        rows = await self.ch.select(
            "SELECT run_id FROM mirage.sim_truth FINAL WHERE kind = 'run' AND run_id NOT IN "
            "(SELECT run_id FROM mirage.sim_runs FINAL WHERE final = 1)"
        )
        return [r["run_id"] for r in rows]

    async def load(
        self, run_id: str
    ) -> tuple[RunRecord | None, list[SessionTruth], list[GroundTruth]]:
        rows = await self.ch.select(
            "SELECT record FROM mirage.sim_truth FINAL WHERE run_id = {run:String}", run=run_id
        )
        run, sessions, steps = None, [], []
        for row in rows:
            rec = parse_record(json.loads(row["record"]))
            if isinstance(rec, RunRecord):
                run = rec
            elif isinstance(rec, SessionTruth):
                sessions.append(rec)
            else:
                steps.append(rec)
        return run, sessions, steps

    async def events_for(self, run: RunRecord, sessions: list[SessionTruth]) -> list[Event]:
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

    async def join(self, run_id: str, force: bool = False) -> JoinResult | None:
        """Join one run and write the result. Returns None when the run is not ready: its
        closing record is missing, or events may still be on their way."""
        run, sessions, steps = await self.load(run_id)
        if run is None:
            return None
        age = (datetime.now(UTC) - run.ended_ts).total_seconds()
        if not force and age < SETTLE_S:
            return None
        result = match(sessions, steps, await self.events_for(run, sessions))
        final = force or result.settled() or age >= GIVE_UP_S
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

    async def write(self, run: RunRecord, result: JoinResult) -> None:
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
                    "problems": "; ".join(
                        result.connections_unmatched
                        + [
                            f"{s.step.session_ref}/{s.step.step_id}: {s.state} {s.detail}".strip()
                            for s in result.steps
                            if s.state in ("no_event", "mismatch")
                        ]
                    )[:4000],
                    "version": version,
                }
            ],
            "mirage.sim_runs",
        )
        log.info(
            "joined %s: %s, %d of %d connections matched, %d labels",
            run.run_id,
            counts,
            result.connections - len(result.connections_unmatched),
            result.connections,
            len(result.labels),
        )


# ---------------------------------------------------------------------------- service


async def run(s: Settings, stop: asyncio.Event) -> None:
    nc = await _retry("NATS", lambda: nats.connect(s.nats_url, max_reconnect_attempts=-1))
    js = nc.jetstream()
    await ensure_streams(js)
    ch = ClickHouse(s)
    await _retry("ClickHouse", ch.ping)
    joiner = Joiner(ch)
    await _retry("ClickHouse tables", joiner.pending)
    sub = await js.pull_subscribe(
        "sim.groundtruth",
        durable="sim-join-v1",
        stream="SIM",
        config=ConsumerConfig(ack_policy=AckPolicy.EXPLICIT, ack_wait=60, max_deliver=-1),
    )
    log.info("label join running")
    while not stop.is_set():
        HEALTH.touch()
        try:
            msgs = await sub.fetch(s.batch_size, timeout=2)
        except TimeoutError:
            msgs = []
        records, bad = [], 0
        for m in msgs:
            try:
                records.append(parse_record(json.loads(m.data)))
            except ValueError:
                bad += 1
        if bad:
            log.warning("skipped %d ground-truth records that do not validate", bad)
        try:
            await joiner.store(records)
            for m in msgs:
                await m.ack()
            for run_id in await joiner.pending():
                await joiner.join(run_id)
        except Exception:
            log.exception("label join failed; will retry")
            for m in msgs:
                await m.nak(delay=5)
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
