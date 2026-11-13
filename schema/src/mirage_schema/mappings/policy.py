"""Policy service decision log (``policy.decision``) -> MirageEvent.

The decoy's own decision event records what it applied, fallbacks included; this record says
why: the rule, the rule set's version and the service-side latency. Both carry the
``request_id`` they join on (spec 1.2).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from mirage_schema.events import (
    Endpoint,
    EventClass,
    MirageEvent,
    Outcome,
    PolicyRef,
    Source,
    utc_now,
)

_NS = uuid.UUID("6f0d7a4e-2a52-4c1e-9a43-6d6972616765")


def map_record(record: dict[str, Any], *, ingest_ts: datetime | None = None) -> MirageEvent:
    if record.get("eventid") != "policy.decision":
        raise ValueError(f"not a policy decision: {record.get('eventid')!r}")
    req = record["request"]
    src = req.get("src") or {}
    digest = hashlib.sha256(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()
    payload = {
        "request_id": req["request_id"],
        "seq": req.get("seq"),
        "command": record.get("input"),
        "known": req.get("known"),
        "rule_id": record.get("rule_id"),
        "rules_version": record.get("rules_version"),
        "latency_us": record.get("latency_us"),
        # The bandit's enriched record (spec 2.5): what it saw, what it was allowed, and what
        # the acting and shadow policies would do. Present once the exploring policy is wired.
        "context": record.get("context"),
        "allowed": record.get("allowed"),
        "acting": record.get("acting"),
        "shadow": record.get("shadow"),
        "explore": record.get("explore"),
        "request": req,
    }
    return MirageEvent(
        event_id=str(uuid.uuid5(_NS, f"policy:{digest}")),
        ts=datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00")),
        ingest_ts=ingest_ts or utc_now(),
        source=Source.POLICY,
        event_class=EventClass.POLICY_DECISION,
        session_id=req.get("session_id"),
        sensor=req.get("deployment_id"),
        src=Endpoint(ip=src.get("ip") or None, port=src.get("port")),
        protocol=req.get("protocol"),
        action="decide",
        outcome=Outcome.SUCCESS,
        payload=payload,
        policy=PolicyRef(
            decision_id=record["decision_id"],
            action=record["action"],
            propensity=record.get("propensity"),
        ),
        raw=record,
    )
