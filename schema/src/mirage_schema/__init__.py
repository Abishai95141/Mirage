"""MIRAGE event schema.

One envelope (:class:`MirageEvent`) for every source, aligned to OCSF class names, plus the
ground-truth records (:class:`GroundTruth`, :class:`SessionTruth`, :class:`RunRecord`)
published by the simulation lab.
"""

from mirage_schema.events import (
    OCSF_CLASS_UID,
    SCHEMA_VERSION,
    Endpoint,
    EventClass,
    Label,
    MirageEvent,
    Outcome,
    PolicyRef,
    SimRef,
    Source,
)
from mirage_schema.groundtruth import (
    Connection,
    GroundTruth,
    RunRecord,
    SessionTruth,
    input_hash,
    parse_record,
)

__all__ = [
    "OCSF_CLASS_UID",
    "SCHEMA_VERSION",
    "Connection",
    "Endpoint",
    "EventClass",
    "GroundTruth",
    "Label",
    "MirageEvent",
    "Outcome",
    "PolicyRef",
    "RunRecord",
    "SessionTruth",
    "SimRef",
    "Source",
    "input_hash",
    "parse_record",
]
