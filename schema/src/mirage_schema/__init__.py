"""MIRAGE event schema.

One envelope (:class:`MirageEvent`) for every source, aligned to OCSF class names, plus the
ground-truth record (:class:`GroundTruth`) published by the simulation lab.
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
from mirage_schema.groundtruth import GroundTruth

__all__ = [
    "OCSF_CLASS_UID",
    "SCHEMA_VERSION",
    "Endpoint",
    "EventClass",
    "GroundTruth",
    "Label",
    "MirageEvent",
    "Outcome",
    "PolicyRef",
    "SimRef",
    "Source",
]
