"""Normaliser: raw source records on NATS JetStream -> MirageEvent -> ClickHouse.

Delivery is at-least-once. A batch is acknowledged only after ClickHouse accepted it; event IDs
are deterministic and ``mirage.events`` is a ReplacingMergeTree on them, so a redelivered batch
does not double-count. Records that cannot be mapped go to ``events.deadletter`` with the reason
and are acknowledged, so one bad record never blocks the stream.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import nats
from nats.js.api import AckPolicy, ConsumerConfig, StreamConfig
from nats.js.errors import BadRequestError

from mirage_pipeline.rows import to_row
from mirage_schema import MirageEvent
from mirage_schema.mappings import cowrie, cowrie_zenodo

log = logging.getLogger("mirage.normaliser")

Mapper = Callable[[dict[str, Any]], MirageEvent]
MAPPERS: dict[str, Mapper] = {
    "raw.honeypot.cowrie": cowrie.map_record,
    # Replayed public corpus (tools/seed_sample.py); tagged with its dataset in the payload.
    "raw.honeypot.cowrie.zenodo21260400": cowrie_zenodo.map_record,
}

STREAMS = [
    StreamConfig(name="RAW", subjects=["raw.>"], max_age=7 * 86400, max_bytes=2 * 1024**3),
    StreamConfig(name="SIM", subjects=["sim.>"], max_age=30 * 86400, max_bytes=1024**3),
    StreamConfig(name="EVENTS", subjects=["events.>"], max_age=7 * 86400, max_bytes=2 * 1024**3),
]


@dataclass
class Settings:
    nats_url: str = "nats://nats:4222"
    clickhouse_url: str = "http://clickhouse:8123"
    clickhouse_user: str = "mirage"
    clickhouse_password: str = ""
    clickhouse_table: str = "mirage.events"
    batch_size: int = 500
    batch_wait_s: float = 1.0
    health_file: Path = field(default_factory=lambda: Path("/tmp/mirage-normaliser.alive"))  # noqa: S108 container-private

    @classmethod
    def from_env(cls) -> Settings:
        env = os.environ
        return cls(
            nats_url=env.get("NATS_URL", cls.nats_url),
            clickhouse_url=env.get("CLICKHOUSE_URL", cls.clickhouse_url),
            clickhouse_user=env.get("CLICKHOUSE_USER", cls.clickhouse_user),
            clickhouse_password=env.get("CLICKHOUSE_PASSWORD", ""),
            batch_size=int(env.get("BATCH_SIZE", cls.batch_size)),
            batch_wait_s=float(env.get("BATCH_WAIT_S", cls.batch_wait_s)),
        )


@dataclass
class Result:
    events: list[MirageEvent]
    dead: list[dict[str, Any]]


def normalise(subject: str, data: bytes) -> MirageEvent | dict[str, Any]:
    """Map one message. Returns the event, or a dead-letter record explaining the failure."""
    mapper = MAPPERS.get(subject)
    if mapper is None:
        return {
            "subject": subject,
            "reason": "no mapper for subject",
            "data": data.decode(errors="replace"),
        }
    try:
        return mapper(json.loads(data))
    except Exception as exc:  # any malformed record is dead-lettered, never fatal
        return {
            "subject": subject,
            "reason": f"{type(exc).__name__}: {exc}"[:500],
            "data": data.decode(errors="replace")[:10_000],
        }


def normalise_batch(messages: list[tuple[str, bytes]]) -> Result:
    res = Result(events=[], dead=[])
    for subject, data in messages:
        out = normalise(subject, data)
        (res.events if isinstance(out, MirageEvent) else res.dead).append(out)
    return res


class ClickHouse:
    def __init__(self, s: Settings) -> None:
        self._s = s
        self._client = httpx.AsyncClient(
            base_url=s.clickhouse_url,
            headers={
                "X-ClickHouse-User": s.clickhouse_user,
                "X-ClickHouse-Key": s.clickhouse_password,
            },
            timeout=30,
        )

    async def ping(self) -> None:
        (await self._client.get("/ping")).raise_for_status()

    async def insert(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        body = "\n".join(json.dumps(r, separators=(",", ":")) for r in rows)
        resp = await self._client.post(
            "/",
            params={"query": f"INSERT INTO {self._s.clickhouse_table} FORMAT JSONEachRow"},
            content=body.encode(),
        )
        if resp.status_code != 200:
            raise RuntimeError(f"ClickHouse insert failed {resp.status_code}: {resp.text[:300]}")

    async def close(self) -> None:
        await self._client.aclose()


async def _retry(what: str, fn: Callable[[], Any], attempts: int = 60) -> Any:
    for i in range(attempts):
        try:
            return await fn()
        except Exception as exc:
            if i == attempts - 1:
                raise
            log.info("waiting for %s (%s)", what, exc)
            await asyncio.sleep(min(2 + i, 10))


async def ensure_streams(js: Any) -> None:
    for cfg in STREAMS:
        try:
            await js.add_stream(cfg)
        except BadRequestError:
            await js.update_stream(cfg)


async def run(s: Settings, stop: asyncio.Event) -> None:
    nc = await _retry("NATS", lambda: nats.connect(s.nats_url, max_reconnect_attempts=-1))
    js = nc.jetstream()
    await ensure_streams(js)
    ch = ClickHouse(s)
    await _retry("ClickHouse", ch.ping)

    sub = await js.pull_subscribe(
        "raw.honeypot.>",
        durable="normaliser",
        stream="RAW",
        config=ConsumerConfig(ack_policy=AckPolicy.EXPLICIT, ack_wait=60, max_deliver=-1),
    )
    log.info("normaliser running: %s -> %s", s.nats_url, s.clickhouse_url)
    backoff = 1.0
    while not stop.is_set():
        s.health_file.touch()
        try:
            msgs = await sub.fetch(s.batch_size, timeout=s.batch_wait_s)
        except TimeoutError:
            continue
        res = normalise_batch([(m.subject, m.data) for m in msgs])
        try:
            await ch.insert([to_row(e) for e in res.events])
            for e in res.events:
                await js.publish(f"events.normalised.{e.source.value}", e.to_json().encode())
            for d in res.dead:
                await js.publish("events.deadletter", json.dumps(d).encode())
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
        log.info("batch: %d stored, %d dead-lettered", len(res.events), len(res.dead))

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
        await run(Settings.from_env(), stop)

    asyncio.run(_main())


def healthcheck() -> None:
    """Exit 0 if the main loop ran in the last 30 s (used by the container healthcheck)."""
    f = Settings().health_file
    raise SystemExit(0 if f.exists() and time.time() - f.stat().st_mtime < 30 else 1)


if __name__ == "__main__":
    main()
