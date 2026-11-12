"""Records from the decoys MIRAGE writes (HTTP, and Redis/MySQL when they land) -> MirageEvent.

All of them log through ``mirage_decoy_common.session.Session``, so they share one shape:
``eventid`` is ``<protocol>.<event>`` and the envelope fields are the same as Cowrie's.
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
SHARED = {
    "eventid",
    "timestamp",
    "session",
    "sensor",
    "protocol",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
}
SOURCE = {"http": Source.HTTP_DECOY, "redis": Source.DB_DECOY, "mysql": Source.DB_DECOY}

S, F, U = Outcome.SUCCESS, Outcome.FAILURE, Outcome.UNKNOWN
C = EventClass

# event (eventid without the protocol prefix) -> (class, action, outcome); None = from record
TABLE: dict[str, tuple[EventClass | None, str, Outcome | None]] = {
    "session.connect": (C.NETWORK_ACTIVITY, "connect", S),
    "session.closed": (C.NETWORK_ACTIVITY, "disconnect", S),
    "policy.decision": (C.POLICY_DECISION, "decide", None),
    "artifact": (C.FILE_ACTIVITY, "artifact_stored", S),
    "request": (C.HTTP_ACTIVITY, "request", None),
    "login.success": (C.AUTHENTICATION, "login", S),
    "login.failed": (C.AUTHENTICATION, "login", F),
    "client.attrs": (C.NETWORK_ACTIVITY, "client_attributes", U),
    "input": (C.DATASTORE_ACTIVITY, "query", None),
    "state.change": (C.DATASTORE_ACTIVITY, "state_change", S),
}


def _event_id(record: dict[str, Any]) -> str:
    digest = hashlib.sha256(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()
    return str(uuid.uuid5(_NS, f"decoy:{digest}"))


def _endpoint(ip: Any, port: Any) -> Endpoint:
    return Endpoint(ip=ip or None, port=int(port) if port not in (None, "") else None)


def map_record(record: dict[str, Any], *, ingest_ts: datetime | None = None) -> MirageEvent:
    eventid: str = record["eventid"]
    protocol, _, event = eventid.partition(".")
    if protocol not in SOURCE:
        raise ValueError(f"unknown decoy protocol in eventid {eventid!r}")
    cls, action, outcome = TABLE.get(event, (EventClass.UNKNOWN, event, Outcome.UNKNOWN))
    payload = {k: v for k, v in record.items() if k not in SHARED}

    policy = None
    if event == "policy.decision":
        outcome = F if record.get("fallback") else S
        policy = PolicyRef(
            decision_id=record.get("decision_id") or f"fallback:{record.get('request_id')}",
            action=record["action"],
            propensity=record.get("propensity"),
        )
        payload["command"] = record.get("input")
    if outcome is None:
        outcome = {"success": S, "failure": F}.get(record.get("outcome", ""), U)

    return MirageEvent(
        event_id=_event_id(record),
        ts=datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00")),
        ingest_ts=ingest_ts or utc_now(),
        source=SOURCE[protocol],
        event_class=cls,
        session_id=record.get("session"),
        sensor=record.get("sensor"),
        src=_endpoint(record.get("src_ip"), record.get("src_port")),
        dst=_endpoint(record.get("dst_ip"), record.get("dst_port")),
        protocol=protocol,
        action=action,
        outcome=outcome,
        payload=payload,
        policy=policy,
        raw=record,
    )
