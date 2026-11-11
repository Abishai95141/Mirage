"""Ground-truth record published by the simulation lab on ``sim.groundtruth``.

One record per scenario step. ``procedure_id`` is the unit for train/test splits, so that a
model cannot pass evaluation by memorising a command template it saw in training.
"""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from mirage_schema.events import Endpoint, _Model

TECHNIQUE_ID = r"^T\d{4}(\.\d{3})?$"
TACTIC_ID = r"^TA\d{4}$"


class GroundTruth(_Model):
    scenario_id: str
    step_id: str
    procedure_id: str
    technique_id: str = Field(pattern=TECHNIQUE_ID)
    tactic: str = Field(pattern=TACTIC_ID)
    attack_version: str
    src: Endpoint
    dst: Endpoint
    start_ts: AwareDatetime
    end_ts: AwareDatetime
    status: Literal["ran", "failed", "skipped"]

    @model_validator(mode="after")
    def _ordered(self) -> GroundTruth:
        if self.end_ts < self.start_ts:
            raise ValueError("end_ts is before start_ts")
        return self
