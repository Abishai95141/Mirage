"""MirageEvent -> flat ClickHouse row for ``mirage.events``."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from mirage_schema import MirageEvent


def _ch_ts(ts: datetime) -> str:
    # ClickHouse DateTime64(6, 'UTC') parses this form without extra settings.
    return ts.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")


def _json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, default=str)


def to_row(ev: MirageEvent) -> dict[str, Any]:
    return {
        "event_id": ev.event_id,
        "ts": _ch_ts(ev.ts),
        "ingest_ts": _ch_ts(ev.ingest_ts),
        "schema_version": ev.schema_version,
        "source": ev.source.value,
        "class": ev.event_class.value,
        "class_uid": ev.class_uid,
        "session_id": ev.session_id or "",
        "actor_id": ev.actor_id or "",
        "sensor": ev.sensor or "",
        "src_ip": str(ev.src.ip) if ev.src.ip else "",
        "src_pseudonym": ev.src.pseudonym or "",
        "src_port": ev.src.port or 0,
        "src_asn": ev.src.asn or 0,
        "src_country": ev.src.country or "",
        "dst_ip": str(ev.dst.ip) if ev.dst.ip else "",
        "dst_pseudonym": ev.dst.pseudonym or "",
        "dst_port": ev.dst.port or 0,
        "protocol": ev.protocol or "",
        "action": ev.action,
        "outcome": ev.outcome.value,
        "payload": _json(ev.payload),
        "policy": _json(ev.policy.model_dump(mode="json")) if ev.policy else "",
        "labels": _json([lb.model_dump(mode="json") for lb in ev.labels]),
        "sim_scenario_id": ev.sim.scenario_id if ev.sim else "",
        "sim_step_id": ev.sim.step_id if ev.sim else "",
        "raw": _json(ev.raw),
    }
