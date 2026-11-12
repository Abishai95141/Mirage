"""Sessioniser service (spec 1.6 detection and 1.7): ``events.normalised.>`` -> ClickHouse.

For each batch it runs :class:`~mirage_pipeline.analyst.Analyst` over the events, writes what
changed (``token.triggered`` findings into ``mirage.events``, ``mirage.actor_links``,
``mirage.session_map``, ``mirage.token_exposures``), then recomputes the summary of every
touched session from ``mirage.events`` itself and upserts it into ``mirage.session_summary``.
Summaries are recomputed rather than counted, so a redelivered batch cannot double-count, and
a restart rebuilds the in-memory state from the same tables.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import signal
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import nats
from nats.js.api import AckPolicy, ConsumerConfig

from mirage_pipeline.analyst import STRENGTH, Analyst, Changes, Exposure, Use
from mirage_pipeline.normaliser import ClickHouse, Settings, _retry, ensure_streams
from mirage_pipeline.rows import _ch_ts, to_row
from mirage_schema import MirageEvent
from mirage_tokens import Token, load

log = logging.getLogger("mirage.sessioniser")
HEALTH = Path("/tmp/mirage-sessioniser.alive")  # noqa: S108 container-private

INPUT = (
    "(source = 'cowrie' AND class = 'process_activity' AND action = 'command'"
    " AND outcome = 'unknown')"
    " OR (class = 'http_activity' AND action = 'request')"
    " OR (class = 'datastore_activity' AND action = 'query')"
)
DECISION = "class = 'policy_decision' AND source != 'policy'"
# Constants only; values arrive as ClickHouse query parameters.
SUMMARY_SQL = f"""
SELECT
    transform(session_id, {{conns:Array(String)}}, {{sids:Array(String)}}, session_id) AS sid,
    anyIf(source, source != 'pipeline')                       AS source,
    anyIf(protocol, protocol != '')                           AS protocol,
    anyIf(sensor, sensor != '')                               AS sensor,
    anyIf(src_ip, src_ip != '')                               AS src_ip,
    min(ts)                                                   AS start_ts,
    max(ts)                                                   AS end_ts,
    countIf({INPUT})                                          AS inputs,
    countIf({DECISION})                                       AS decisions,
    countIf({DECISION} AND JSONExtractBool(payload, 'fallback')) AS fallbacks,
    countIf(class = 'authentication' AND action = 'login')    AS auth_attempts,
    countIf(class = 'authentication' AND action = 'login' AND outcome = 'success') AS auth_ok,
    arraySort(groupUniqArrayIf(
        (JSONExtractString(payload, 'username'), JSONExtractString(payload, 'password')),
        class = 'authentication' AND action = 'login'))       AS credentials,
    anyIf(JSONExtractString(payload, 'hassh'), action = 'client_kex')              AS hassh,
    anyIf(JSONExtractString(payload, 'client_version'),
        action = 'client_version')                            AS client_version,
    anyIf(JSONExtractString(payload, 'user_agent'), class = 'http_activity')       AS user_agent,
    anyIf(JSONExtractRaw(payload, 'headers'), class = 'http_activity')             AS headers,
    anyIf(payload, action = 'client_attributes')                                   AS client_attrs,
    arraySort(groupUniqArrayIf(JSONExtractString(payload, 'token_id'),
        action = 'token_triggered'))                          AS tokens,
    arraySort(groupUniqArrayIf(JSONExtractString(payload, 'sha256'),
        class = 'file_activity' AND action IN ('download', 'upload', 'artifact_stored')
        AND JSONExtractString(payload, 'sha256') != ''))      AS artifacts,
    arraySort(groupUniqArray(session_id))                     AS connections
FROM mirage.events FINAL
WHERE session_id IN {{ids:Array(String)}} AND source != 'policy'
GROUP BY sid
SETTINGS prefer_column_name_to_alias = 1
"""  # noqa: S608


@dataclass
class Config:
    base: Settings
    tokens_file: Path

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            Settings.from_env(),
            Path(os.environ.get("TOKENS_FILE", "/profile/tokens.json")),
        )


def _dt(v: str) -> datetime:
    return datetime.fromisoformat(v.replace(" ", "T")).replace(tzinfo=UTC)


def fingerprints(row: dict[str, Any]) -> dict[str, Any]:
    """Per-protocol client fingerprints (spec 1.7). No JA4: 1.1 removed it."""
    fp: dict[str, Any] = {}
    if row.get("hassh"):
        fp["hassh"] = row["hassh"]
    if row.get("client_version"):
        fp["client_version"] = row["client_version"]
    if row.get("user_agent"):
        fp["user_agent"] = row["user_agent"]
    if row.get("headers"):
        try:
            names = [h[0].lower() for h in json.loads(row["headers"])]
        except (ValueError, TypeError, IndexError):
            names = []
        fp["header_order"] = hashlib.sha256(",".join(names).encode()).hexdigest()[:16]
    if row.get("client_attrs"):
        try:
            p = json.loads(row["client_attrs"])
            fp["client_attrs"] = p.get("attrs", p)
        except ValueError:
            pass
    return fp


def summary_row(row: dict[str, Any], actor_id: str, version: int) -> dict[str, Any]:
    return {
        "session_id": row["sid"],
        "version": version,
        "protocol": row["protocol"],
        "source": row["source"],
        "sensor": row["sensor"],
        "src_ip": row["src_ip"],
        "start_ts": row["start_ts"],
        "end_ts": row["end_ts"],
        "inputs": int(row["inputs"]),
        "decisions": int(row["decisions"]),
        "fallbacks": int(row["fallbacks"]),
        "auth_attempts": int(row["auth_attempts"]),
        "auth_success": 1 if int(row["auth_ok"]) else 0,
        "credentials": [list(c) for c in row["credentials"]],
        "fingerprints": json.dumps(fingerprints(row), sort_keys=True),
        "tokens": row["tokens"],
        "artifacts": row["artifacts"],
        "connections": row["connections"],
        "actor_id": actor_id,
    }


class Sessioniser:
    def __init__(self, ch: ClickHouse, tokens: list[Token]) -> None:
        self.ch = ch
        self.tokens = tokens
        self.analyst = Analyst(tokens)

    async def publish_tokens(self) -> None:
        now = _ch_ts(datetime.now(UTC))
        await self.ch.insert(
            [{**t.to_row(), "username": t.username or "", "loaded_at": now} for t in self.tokens],
            "mirage.tokens",
        )

    async def restore(self) -> None:
        a = self.analyst
        for r in await self.ch.select("SELECT a, b, reason FROM mirage.actor_links FINAL"):
            a.restore_link(r["a"], r["b"], r["reason"])
        for r in await self.ch.select("SELECT conn_id, session_id FROM mirage.session_map FINAL"):
            a.restore_conn(r["conn_id"], r["session_id"])
        for r in await self.ch.select(
            "SELECT session_id, src_ip, end_ts, protocol,"
            " JSONExtractString(fingerprints, 'user_agent') AS ua"
            " FROM mirage.session_summary FINAL"
        ):
            end = _dt(r["end_ts"])
            a.restore_session(r["session_id"], r["src_ip"], end)
            if r["protocol"] == "http":
                a.restore_http(r["src_ip"], r["ua"], r["session_id"], end)
        for r in await self.ch.select(
            "SELECT token_id, session_id, ts, location, event_id FROM mirage.token_exposures FINAL"
        ):
            a.restore_exposure(
                Exposure(r["token_id"], r["session_id"], _dt(r["ts"]), r["location"], r["event_id"])
            )
        for r in await self.ch.select(
            "SELECT JSONExtractString(payload, 'token_id') AS token_id,"
            " JSONExtractString(payload, 'session') AS session_id, ts,"
            " JSONExtractString(payload, 'trigger_event_id') AS event_id"
            " FROM mirage.events FINAL WHERE action = 'token_triggered'"
        ):
            a.restore_use(Use(r["token_id"], r["session_id"], _dt(r["ts"]), r["event_id"]))
        log.info(
            "restored %d sessions, %d links, %d connection mappings",
            len(a.seen),
            len(a.linked),
            len(a.conn_map),
        )

    def analyse(self, events: list[MirageEvent]) -> Changes:
        out = Changes()
        for ev in sorted(events, key=lambda e: e.ts):
            out.merge(self.analyst.process(ev))
        return out

    async def write(self, ch: Changes) -> int:
        version = time.time_ns()
        await self.ch.insert([to_row(e) for e in ch.findings])
        await self.ch.insert(
            [
                {
                    "a": lk.a,
                    "b": lk.b,
                    "reason": lk.reason,
                    "strength": STRENGTH[lk.reason],
                    "evidence": json.dumps(lk.evidence, sort_keys=True),
                    "ts": _ch_ts(lk.ts),
                    "version": version,
                }
                for lk in ch.links
            ],
            "mirage.actor_links",
        )
        await self.ch.insert(
            [{"conn_id": c, "session_id": s, "version": version} for c, s in ch.conn_map.items()],
            "mirage.session_map",
        )
        await self.ch.insert(
            [
                {
                    "token_id": e.token_id,
                    "session_id": e.session_id,
                    "ts": _ch_ts(e.ts),
                    "location": e.location,
                    "event_id": e.event_id,
                    "version": version,
                }
                for e in ch.exposures
            ],
            "mirage.token_exposures",
        )
        return await self.summarise(ch.touched, version)

    async def summarise(self, sids: set[str], version: int) -> int:
        if not sids:
            return 0
        a = self.analyst
        pairs = [(c, s) for c, s in a.conn_map.items() if s in sids]
        ids = sorted(sids | {c for c, _ in pairs})
        rows = []
        for i in range(0, len(ids), 2000):
            rows += await self.ch.select(
                SUMMARY_SQL,
                conns=[c for c, _ in pairs],
                sids=[s for _, s in pairs],
                ids=ids[i : i + 2000],
            )
        out = [summary_row(r, a.components.actor_id(r["sid"]), version) for r in rows]
        await self.ch.insert(out, "mirage.session_summary")
        return len(out)


async def run(cfg: Config, stop: asyncio.Event) -> None:
    s = cfg.base
    nc = await _retry("NATS", lambda: nats.connect(s.nats_url, max_reconnect_attempts=-1))
    js = nc.jetstream()
    await ensure_streams(js)
    ch = ClickHouse(s)
    await _retry("ClickHouse", ch.ping)
    tokens = load(cfg.tokens_file) if cfg.tokens_file.exists() else []
    if not tokens:
        log.warning("no tokens at %s; honeytoken detection is off", cfg.tokens_file)
    svc = Sessioniser(ch, tokens)
    await _retry("ClickHouse tables", svc.publish_tokens)
    await svc.restore()
    sub = await js.pull_subscribe(
        "events.normalised.>",
        durable="sessioniser-v1",
        stream="EVENTS",
        config=ConsumerConfig(ack_policy=AckPolicy.EXPLICIT, ack_wait=60, max_deliver=-1),
    )
    log.info("sessioniser running with %d tokens", len(tokens))
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
            changes = svc.analyse(events)
            n = await svc.write(changes)
        except Exception:
            log.exception("batch of %d failed; will be redelivered", len(msgs))
            for m in msgs:
                await m.nak(delay=backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)
            # The in-memory state may hold half a batch; rebuild it from what was written.
            svc.analyst = Analyst(tokens)
            await svc.restore()
            continue
        backoff = 1.0
        for m in msgs:
            await m.ack()
        log.info(
            "batch: %d events, %d sessions, %d links, %d findings",
            len(events),
            n,
            len(changes.links),
            len(changes.findings),
        )
    await ch.close()
    await nc.drain()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.Formatter.converter = time.gmtime
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
