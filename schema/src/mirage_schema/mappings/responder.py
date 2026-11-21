"""The responder's record of an answer (``responder.answer``) -> MirageEvent.

One record for each request the SSH decoy made of the responder: which rung answered, what it
cost, how long it took, what stopped it. It never holds a generated line or the input: the
decoy's own events have those, and the two join on ``request_id`` (phase 3 spec, section 3).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from mirage_schema.events import Endpoint, EventClass, MirageEvent, Outcome, Source, utc_now

_NS = uuid.UUID("6f0d7a4e-2a52-4c1e-9a43-6d6972616765")
OUTCOMES = {"end": Outcome.SUCCESS, "abort": Outcome.FAILURE}


def map_record(record: dict[str, Any], *, ingest_ts: datetime | None = None) -> MirageEvent:
    if record.get("eventid") != "responder.answer":
        raise ValueError(f"not a responder record: {record.get('eventid')!r}")
    digest = hashlib.sha256(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()
    envelope = {"eventid", "timestamp", "session_id", "deployment_id", "src_ip"}
    payload = {k: v for k, v in record.items() if k not in envelope}
    # `outcome` is the envelope's; the record's own word (end, abort, resync, cancelled) is
    # kept under another name.
    payload["answer_outcome"] = payload.pop("outcome", None)
    return MirageEvent(
        event_id=str(uuid.uuid5(_NS, f"responder:{digest}")),
        ts=datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00")),
        ingest_ts=ingest_ts or utc_now(),
        source=Source.RESPONDER,
        event_class=EventClass.PROCESS_ACTIVITY,
        session_id=record.get("session_id"),
        sensor=record.get("deployment_id"),
        src=Endpoint(ip=record.get("src_ip") or None),
        protocol="ssh",
        action="answer",
        outcome=OUTCOMES.get(str(record.get("outcome")), Outcome.UNKNOWN),
        payload=payload,
        raw=record,
    )
