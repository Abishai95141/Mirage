"""The normalised event envelope.

Design rules (see docs/02-architecture.md, section 4):

* Class names follow OCSF 1.9; ``class_uid`` carries the OCSF class UID where one exists.
  The schema is OCSF-*aligned*, not OCSF-conformant: field names are ours.
* Every ATT&CK label (tactic or technique) must carry ``attack_version``. ATT&CK v19 split
  Defense Evasion into Stealth (TA0005) and Defense Impairment (TA0112), so labels from
  different versions are not comparable without it.
* Lab traffic is marked in ``sim``. That field identifies ground truth and must never be used
  as a model input.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    computed_field,
    model_validator,
)

SCHEMA_VERSION = "0.3.0"


class Source(StrEnum):
    COWRIE = "cowrie"
    HTTP_DECOY = "http-decoy"
    DB_DECOY = "db-decoy"
    ZEEK = "zeek"
    SURICATA = "suricata"
    POLICY = "policy"
    # The responder's own record of an answer (phase 3 spec, section 3). The decoy's event
    # for the same command says what the session saw; the two join on request_id.
    RESPONDER = "responder"
    SIM = "sim"
    # Derived by the pipeline itself (the sessioniser's token.triggered findings).
    PIPELINE = "pipeline"


class EventClass(StrEnum):
    NETWORK_ACTIVITY = "network_activity"
    SSH_ACTIVITY = "ssh_activity"
    HTTP_ACTIVITY = "http_activity"
    AUTHENTICATION = "authentication"
    PROCESS_ACTIVITY = "process_activity"
    FILE_ACTIVITY = "file_activity"
    POLICY_DECISION = "policy_decision"
    # Database decoys. Mapped to OCSF's Application Activity category; the class UID is left
    # unset until checked against the OCSF 1.9 schema (spec section 7), so class_uid is 0.
    DATASTORE_ACTIVITY = "datastore_activity"
    # A honeytoken was used (spec 1.6). OCSF Findings category, Detection Finding.
    DETECTION_FINDING = "detection_finding"
    UNKNOWN = "unknown"


# OCSF 1.x class UIDs for the classes that have one. Policy decisions are MIRAGE-specific.
OCSF_CLASS_UID: dict[EventClass, int] = {
    EventClass.FILE_ACTIVITY: 1001,
    EventClass.PROCESS_ACTIVITY: 1007,
    EventClass.AUTHENTICATION: 3002,
    EventClass.NETWORK_ACTIVITY: 4001,
    EventClass.HTTP_ACTIVITY: 4002,
    EventClass.SSH_ACTIVITY: 4007,
    EventClass.DETECTION_FINDING: 2004,
}


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class Endpoint(_Model):
    ip: IPvAnyAddress | None = None
    # A stable stand-in when the address was withheld (a public dataset that hashed its IPs,
    # or data pseudonymised before cross-site sharing). Groups sources without revealing them.
    pseudonym: str | None = Field(default=None, max_length=128)
    port: int | None = Field(default=None, ge=0, le=65535)
    asn: int | None = None
    country: str | None = Field(default=None, min_length=2, max_length=2)


class PolicyRef(_Model):
    decision_id: str
    action: str
    propensity: float | None = Field(default=None, ge=0.0, le=1.0)


class Label(_Model):
    kind: Literal["actor", "tactic", "technique"]
    value: str
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    model_version: str
    attack_version: str | None = None

    @model_validator(mode="after")
    def _attack_labels_are_versioned(self) -> Label:
        if self.kind in ("tactic", "technique") and not self.attack_version:
            raise ValueError(f"{self.kind} label {self.value!r} must carry attack_version")
        return self


class SimRef(_Model):
    scenario_id: str
    step_id: str


class MirageEvent(_Model):
    event_id: str
    ts: AwareDatetime
    ingest_ts: AwareDatetime
    schema_version: str = SCHEMA_VERSION
    source: Source
    event_class: EventClass = Field(alias="class")
    session_id: str | None = None
    actor_id: str | None = None
    sensor: str | None = None
    src: Endpoint = Field(default_factory=Endpoint)
    dst: Endpoint = Field(default_factory=Endpoint)
    protocol: str | None = None
    action: str
    outcome: Outcome = Outcome.UNKNOWN
    payload: dict[str, Any] = Field(default_factory=dict)
    policy: PolicyRef | None = None
    labels: list[Label] = Field(default_factory=list)
    sim: SimRef | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def class_uid(self) -> int:
        return OCSF_CLASS_UID.get(self.event_class, 0)

    @model_validator(mode="before")
    @classmethod
    def _accept_serialised_class_uid(cls, data: Any) -> Any:
        # class_uid is derived from class. Serialised events carry it; accept it on the way
        # back in only if it agrees with class.
        if isinstance(data, dict) and "class_uid" in data:
            data = dict(data)
            uid = data.pop("class_uid")
            cls_name = data.get("class", data.get("event_class"))
            if cls_name is not None and uid != OCSF_CLASS_UID.get(EventClass(cls_name), 0):
                raise ValueError(f"class_uid {uid} does not match class {cls_name!r}")
        return data

    @model_validator(mode="after")
    def _ingest_not_before_event(self) -> MirageEvent:
        # Clock skew between sensors is tolerated up to a minute; beyond that the record is
        # suspect and should be dead-lettered rather than stored with a misleading time.
        if (self.ts - self.ingest_ts).total_seconds() > 60:
            raise ValueError("event ts is more than 60 s after ingest_ts")
        return self

    def to_json(self) -> str:
        return self.model_dump_json(by_alias=True)


def utc_now() -> datetime:
    from datetime import UTC

    return datetime.now(UTC)
