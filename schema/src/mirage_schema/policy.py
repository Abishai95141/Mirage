"""Gate contract v1: what a decoy asks the policy service, and what it gets back.

Spec: docs/04-phase-1-spec.md, section 3. The SSH fields are the ones spike S1 built; v1 adds
the HTTP, Redis and MySQL protocols and the routing fields. Requests are validated leniently
(``extra="ignore"``) so a newer decoy can talk to an older service; responses strictly, because
the decoy must refuse anything outside the action mask.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_OUTPUT_BYTES = 64 * 1024
MAX_DELAY_MS = 10_000
ARG_CAP = 1024  # bytes per Redis argument sent to the gate
SQL_CAP = 4096  # bytes of SQL sent to the gate
BODY_HEAD_CAP = 1024  # bytes of an HTTP body sent to the gate


class Protocol(StrEnum):
    SSH = "ssh"
    HTTP = "http"
    REDIS = "redis"
    MYSQL = "mysql"


class Action(StrEnum):
    ALLOW = "allow"
    DELAY = "delay"
    FAKE_SUCCESS = "fake_success"
    FAKE_ERROR = "fake_error"
    TERMINATE = "terminate"


class Src(BaseModel):
    model_config = ConfigDict(extra="ignore")
    ip: str | None = None
    port: int | None = None


class DecideRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    request_id: str = Field(min_length=1, max_length=64)
    session_id: str | None = Field(default=None, max_length=64)
    deployment_id: str | None = Field(default=None, max_length=64)
    seq: int | None = Field(default=None, ge=0)
    protocol: Protocol
    src: Src = Field(default_factory=Src)
    known: bool = True

    # ssh
    argv: list[str] | None = None  # also redis
    cwd: str | None = None
    user: str | None = None  # also mysql
    interactive: bool | None = None
    # http
    method: str | None = None
    path: str | None = None
    query: str | None = None
    headers: dict[str, str] | None = None
    body_len: int | None = None
    body_sha256: str | None = None
    body_head: str | None = None
    # redis
    db: int | str | None = None  # mysql uses a name
    # mysql
    command: str | None = None
    sql: str | None = None

    def input_text(self) -> str:
        """One string per input unit, used by rule regexes and the decision log."""
        if self.protocol is Protocol.HTTP:
            q = f"?{self.query}" if self.query else ""
            return f"{self.method or ''} {self.path or ''}{q}"
        if self.protocol is Protocol.MYSQL:
            return self.sql if self.sql is not None else (self.command or "")
        return " ".join(self.argv or [])

    def verb(self) -> str | None:
        """argv[0] for shells and Redis (Redis upper-cased), the SQL verb for MySQL."""
        if self.protocol is Protocol.MYSQL:
            words = (self.sql or "").split(None, 1)
            return words[0].upper() if words else self.command
        if self.protocol is Protocol.HTTP:
            return self.method
        if not self.argv:
            return None
        return self.argv[0].upper() if self.protocol is Protocol.REDIS else self.argv[0]


class Decision(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action: Action
    output: str = ""
    exit_code: int | None = None
    delay_ms: int = 0
    decision_id: str
    propensity: float | None = Field(default=None, ge=0.0, le=1.0)
    rule_id: str | None = None
    rules_version: str | None = None

    @field_validator("output")
    @classmethod
    def _cap_output(cls, v: str) -> str:
        b = v.encode()
        return b[:MAX_OUTPUT_BYTES].decode(errors="ignore") if len(b) > MAX_OUTPUT_BYTES else v

    @field_validator("delay_ms")
    @classmethod
    def _cap_delay(cls, v: int) -> int:
        return min(max(v, 0), MAX_DELAY_MS)


def truncate(value: str | bytes | None, cap: int) -> str | None:
    """Cut to ``cap`` bytes of UTF-8 (bytes decoded with replacement)."""
    if value is None:
        return None
    if isinstance(value, bytes):
        return value[:cap].decode(errors="replace")
    b = value.encode()
    return value if len(b) <= cap else b[:cap].decode(errors="ignore")


def as_dict(req: DecideRequest) -> dict[str, Any]:
    return req.model_dump(mode="json", exclude_none=True)
