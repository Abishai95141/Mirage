"""Tagger worker (spec 2.4 labelling, 2.7 alerts): ``events.normalised.>`` -> labels and alerts.

For each gated input in a batch it runs the technique rule engine and writes one row to
``mirage.labels``. Then, for every session the batch touched, it recomputes an alert from
ClickHouse -- the session's labelled tactics, plus any honeytoken or captured artifact -- and
writes a row to ``mirage.alerts`` when the session reached a honeytoken, captured an artifact,
or showed Persistence or Impact. Both tables are recomputed, not appended, so a redelivered
batch cannot double-count, and a restart rebuilds from the same tables.

The rule engine lives in ``mirage_schema`` so this worker and the policy service share it
without the intel package's heavy libraries. With only the benign starter rules it labels
discovery; the offensive rules land later, and the worker picks them up with no code change.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import nats
from nats.js.api import AckPolicy, ConsumerConfig

from mirage_pipeline.normaliser import ClickHouse, Settings, _retry, ensure_streams
from mirage_pipeline.rows import _ch_ts
from mirage_schema import MirageEvent
from mirage_schema.techniques import Engine

log = logging.getLogger("mirage.tagger")
HEALTH = Path("/tmp/mirage-tagger.alive")  # noqa: S108 container-private

PERSISTENCE, IMPACT = "TA0003", "TA0040"

# Aggregate a session's honeytokens and artifacts from its events (structural, no labels).
EVIDENCE_SQL = """
SELECT
    session_id,
    anyIf(src_ip, src_ip != '')                               AS src_ip,
    anyIf(protocol, protocol != '')                           AS protocol,
    countIf((source = 'cowrie' AND class = 'process_activity' AND action = 'command'
             AND outcome = 'unknown')
            OR (class = 'http_activity' AND action = 'request')
            OR (class = 'datastore_activity' AND action = 'query'))  AS inputs,
    min(ts)                                                   AS start_ts,
    max(ts)                                                   AS end_ts,
    arraySort(groupUniqArrayIf(JSONExtractString(payload, 'token_id'),
        action = 'token_triggered'))                          AS tokens,
    arraySort(groupUniqArrayIf(JSONExtractString(payload, 'sha256'),
        class = 'file_activity'
        AND action IN ('download', 'upload', 'artifact_stored')
        AND JSONExtractString(payload, 'sha256') != ''))      AS artifacts
FROM mirage.events FINAL
WHERE session_id IN {ids:Array(String)} AND source != 'policy'
GROUP BY session_id
"""

LABELS_SQL = """
SELECT session_id,
       arraySort(groupUniqArray(tactic))    AS tactics,
       arraySort(groupUniqArray(technique)) AS techniques
FROM mirage.labels FINAL
WHERE session_id IN {ids:Array(String)} AND technique != ''
GROUP BY session_id
"""


@dataclass
class Config:
    base: Settings
    rules_dir: Path
    attack_version: str

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            base=Settings.from_env(),
            rules_dir=Path(os.environ.get("TECHNIQUE_RULES", "/rules")),
            attack_version=os.environ.get("ATTACK_VERSION", "20.1"),
        )


def decision_text(ev: MirageEvent) -> str | None:
    """The input a gate decision was made on: the executed command (cowrie) or the canonical
    input (http/redis/mysql). None when this event is not a gate decision."""
    if ev.event_class.value != "policy_decision" or ev.source.value == "policy":
        return None
    payload = ev.payload
    return payload.get("command") or payload.get("input") or ""


def alert_reasons(tactics: list[str], tokens: list[str], artifacts: list[str]) -> list[str]:
    reasons = []
    if tokens:
        reasons.append("honeytoken")
    if artifacts:
        reasons.append("artifact")
    if PERSISTENCE in tactics:
        reasons.append("persistence")
    if IMPACT in tactics:
        reasons.append("impact")
    return reasons


class Tagger:
    def __init__(self, engine: Engine, ch: ClickHouse, attack_version: str) -> None:
        self.engine = engine
        self.ch = ch
        self.attack_version = attack_version

    def labels(self, events: list[MirageEvent], version: int) -> list[dict[str, Any]]:
        rows = []
        for ev in events:
            text = decision_text(ev)
            if text is None:
                continue
            hit = self.engine.best(ev.protocol or "any", text)
            if hit is None:
                continue
            rows.append(
                {
                    "event_id": ev.event_id,
                    "version": version,
                    "session_id": ev.session_id or "",
                    "protocol": ev.protocol or "",
                    "kind": "input",
                    "technique": hit.technique,
                    "tactic": hit.tactic,
                    "confidence": hit.confidence,
                    "rule_id": hit.rule_id,
                    "model_version": self.engine.version,
                    "attack_version": self.attack_version,
                    "ts": _ch_ts(ev.ts),
                }
            )
        return rows

    @staticmethod
    def touched(events: list[MirageEvent]) -> set[str]:
        return {ev.session_id for ev in events if ev.session_id}

    async def write_labels(self, rows: list[dict[str, Any]]) -> None:
        await self.ch.insert(rows, "mirage.labels")

    async def alerts(self, session_ids: set[str], version: int) -> list[dict[str, Any]]:
        if not session_ids:
            return []
        ids = sorted(session_ids)
        evidence = {r["session_id"]: r for r in await self.ch.select(EVIDENCE_SQL, ids=ids)}
        labelled = {r["session_id"]: r for r in await self.ch.select(LABELS_SQL, ids=ids)}
        out = []
        for sid in ids:
            ev = evidence.get(sid)
            if ev is None:
                continue
            lab = labelled.get(sid, {})
            tactics = lab.get("tactics", [])
            reasons = alert_reasons(tactics, ev["tokens"], ev["artifacts"])
            if not reasons:
                continue
            out.append(
                {
                    "session_id": sid,
                    "version": version,
                    "src_ip": ev["src_ip"],
                    "protocol": ev["protocol"],
                    "reasons": reasons,
                    "tactics": tactics,
                    "techniques": lab.get("techniques", []),
                    "tokens": ev["tokens"],
                    "artifacts": ev["artifacts"],
                    "inputs": int(ev["inputs"]),
                    "start_ts": ev["start_ts"],
                    "end_ts": ev["end_ts"],
                }
            )
        return out

    async def process(self, events: list[MirageEvent]) -> tuple[int, int]:
        version = time.time_ns() // 1000
        label_rows = self.labels(events, version)
        await self.write_labels(label_rows)
        alert_rows = await self.alerts(self.touched(events), version)
        await self.ch.insert(alert_rows, "mirage.alerts")
        return len(label_rows), len(alert_rows)


async def run(cfg: Config, stop: asyncio.Event) -> None:
    s = cfg.base
    nc = await _retry("NATS", lambda: nats.connect(s.nats_url, max_reconnect_attempts=-1))
    js = nc.jetstream()
    await ensure_streams(js)
    ch = ClickHouse(s)
    await _retry("ClickHouse", ch.ping)
    engine = Engine.load(cfg.rules_dir) if cfg.rules_dir.is_dir() else Engine([], [])
    tagger = Tagger(engine, ch, cfg.attack_version)
    sub = await js.pull_subscribe(
        "events.normalised.>",
        durable="tagger-v1",
        stream="EVENTS",
        config=ConsumerConfig(ack_policy=AckPolicy.EXPLICIT, ack_wait=60, max_deliver=-1),
    )
    log.info("tagger running with %d rules (%s)", len(engine.rules), engine.version)
    backoff = 1.0
    while not stop.is_set():
        HEALTH.touch()
        try:
            msgs = await sub.fetch(s.batch_size, timeout=s.batch_wait_s)
        except TimeoutError:
            continue
        events = []
        for m in msgs:
            try:
                events.append(MirageEvent.model_validate_json(m.data))
            except ValueError:
                log.warning("skipping an event that does not validate")
        try:
            n_labels, n_alerts = await tagger.process(events)
        except Exception:
            log.exception("batch of %d failed; will be redelivered", len(msgs))
            for m in msgs:
                await m.nak(delay=backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)
            continue
        backoff = 1.0
        for m in msgs:
            await m.ack()
        if n_labels or n_alerts:
            log.info("batch: %d events, %d labels, %d alerts", len(events), n_labels, n_alerts)
    await ch.close()
    await nc.drain()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.Formatter.converter = time.gmtime
    logging.getLogger("httpx").setLevel(logging.WARNING)
    stop = asyncio.Event()

    async def _main() -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        await run(Config.from_env(), stop)

    asyncio.run(_main())


def healthcheck() -> None:
    raise SystemExit(0 if HEALTH.exists() and time.time() - HEALTH.stat().st_mtime < 30 else 1)


if __name__ == "__main__":
    main()
