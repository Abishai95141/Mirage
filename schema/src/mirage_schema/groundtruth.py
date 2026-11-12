"""Ground-truth records published by the simulation lab on ``sim.groundtruth``.

Three kinds share the subject (docs/05-phase-2-spec.md, section 3):

* ``step``: one per scenario step. It names the connection that carried the step (source
  address and port, as the decoy logged them) and the hash of what was sent, so the label join
  is exact rather than a guess from time alone.
* ``session``: what is true of a whole simulated session: its connections, and the actor
  behind it.
* ``run``: one per run of the runner, with the hashes of everything that produced it.

``procedure_id`` is the unit for train/test splits, so that a model cannot pass evaluation by
memorising a command template it saw in training. None of these records is ever a model input.
"""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from mirage_schema.events import Endpoint, _Model

TECHNIQUE_ID = r"^T\d{4}(\.\d{3})?$"
TACTIC_ID = r"^TA\d{4}$"
SHA256 = r"^[0-9a-f]{64}$"

ActorClass = Literal["scanner", "scripted_bot", "human", "llm_agent"]
Mode = Literal["capture", "explore"]


def input_hash(text: str | bytes) -> str:
    """The hash a step carries for what it sent. The join computes the same over what the
    decoy captured, so both sides must hash the same bytes: the input as UTF-8."""
    data = text.encode() if isinstance(text, str) else text
    return hashlib.sha256(data).hexdigest()


class GroundTruth(_Model):
    kind: Literal["step"] = "step"
    run_id: str
    scenario_id: str
    session_ref: str
    step_id: str
    procedure_id: str
    # None for both means "this step is no technique": an explicit negative, not a gap.
    technique_id: str | None = Field(default=None, pattern=TECHNIQUE_ID)
    tactic: str | None = Field(default=None, pattern=TACTIC_ID)
    attack_version: str
    protocol: str
    # The connection that carried the step, as the decoy sees it (PROXY v2 source).
    src: Endpoint
    dst: Endpoint
    # What the join looks for in the step's window: a typed input (hash of the text), an
    # uploaded file (hash of its bytes), authentication attempts, or just the connection.
    evidence: Literal["input", "upload", "auth", "connect"] = "input"
    input_sha256: str | None = Field(default=None, pattern=SHA256)
    start_ts: AwareDatetime
    end_ts: AwareDatetime
    status: Literal["ran", "failed", "skipped"]
    # What the scenario's own check concluded about the decoy's answer.
    outcome: Literal["ok", "failed", "unchecked"] = "unchecked"

    @model_validator(mode="after")
    def _consistent(self) -> GroundTruth:
        if self.end_ts < self.start_ts:
            raise ValueError("end_ts is before start_ts")
        if (self.technique_id is None) != (self.tactic is None):
            raise ValueError("technique_id and tactic are given together or not at all")
        if self.evidence in ("input", "upload") and self.status == "ran" and not self.input_sha256:
            raise ValueError(f"a step that ran with {self.evidence} evidence needs input_sha256")
        return self


class Connection(_Model):
    src: Endpoint
    dst: Endpoint
    opened_ts: AwareDatetime
    closed_ts: AwareDatetime | None = None

    @model_validator(mode="after")
    def _addressed(self) -> Connection:
        if self.src.ip is None or self.src.port is None or self.dst.port is None:
            raise ValueError("a connection needs src ip, src port and dst port")
        return self


class SessionTruth(_Model):
    kind: Literal["session"] = "session"
    run_id: str
    scenario_id: str
    session_ref: str
    protocol: str
    actor_ref: str
    actor_class: ActorClass
    timing_profile: str
    real: bool = False  # True for a recorded human, never for a generated profile
    mode: Mode
    connections: list[Connection] = Field(min_length=1)
    start_ts: AwareDatetime
    end_ts: AwareDatetime


class RunRecord(_Model):
    kind: Literal["run"] = "run"
    run_id: str
    mode: Mode
    started_ts: AwareDatetime
    ended_ts: AwareDatetime
    seed: int
    attack_version: str
    catalogue_sha256: str = Field(pattern=SHA256)
    scenarios_sha256: str = Field(pattern=SHA256)
    code_version: str
    scenarios: list[str]
    sessions: int = Field(ge=0)
    steps: int = Field(ge=0)


def parse_record(data: dict) -> GroundTruth | SessionTruth | RunRecord:
    """One record off ``sim.groundtruth``, by its ``kind`` (a record without one is a step)."""
    kind = data.get("kind", "step")
    if kind == "session":
        return SessionTruth.model_validate(data)
    if kind == "run":
        return RunRecord.model_validate(data)
    return GroundTruth.model_validate(data)
