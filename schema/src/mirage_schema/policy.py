"""The gate contract: what a decoy asks the policy service, and what it gets back.

**v1** (docs/04-phase-1-spec.md, section 3). The SSH fields are the ones spike S1 built; v1
adds the HTTP, Redis and MySQL protocols and the routing fields. Requests are validated
leniently (``extra="ignore"``) so a newer decoy can talk to an older service; responses
strictly, because the decoy must refuse anything outside the action mask.

**v2** (docs/06-phase-3-spec.md, section 3) extends it and changes no v1 field. A decoy that
can carry out a new action says so in ``supports``, and says in ``tier`` what it would answer
with if allowed. The service never returns an action the request did not list, so a decoy
that sends no ``supports`` keeps receiving v1 actions only.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mirage_schema.ops import Op

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
    # v2 (SSH only in phase 3)
    RESPOND = "respond"  # ask the responder to answer this input
    # apply ``ops`` (a file holding a reserve token), then allow
    PLANT_TOKEN = "plant_token"  # noqa: S105 - an action's name, not a secret
    ESCALATE = "escalate"  # move the session to a sandbox


V1_ACTIONS = frozenset(
    {Action.ALLOW, Action.DELAY, Action.FAKE_SUCCESS, Action.FAKE_ERROR, Action.TERMINATE}
)
V2_ACTIONS = frozenset({Action.RESPOND, Action.PLANT_TOKEN, Action.ESCALATE})
MAX_OUTPUT_TOKENS = 400  # a generated answer (spec 3.2b)
MAX_RESPOND_DEADLINE_MS = 10_000


class Tier(StrEnum):
    """What the decoy would answer an input with if allowed."""

    EMULATED = "emulated"  # a command its emulator has
    RENDERED = "rendered"  # an entry of its render library
    NONE = "none"  # a program that is there, which nothing of the decoy's answers for
    # No such program on the host. "command not found" is the true answer and the decoy's
    # shell gives it, so this is not a case for the responder (decided 17 November 2026).
    ABSENT = "absent"


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
    # v2: the new actions this decoy can carry out now, and what it has for this input. A
    # value this service does not know is dropped, not refused: a newer decoy may say more.
    supports: list[Action] = Field(default_factory=list)
    tier: Tier | None = None
    # v2: the output tokens this session's generated answers have really used so far, as the
    # responder told the decoy. With it the policy counts what was spent; without it (an
    # older decoy) it can only count what it granted, which is several times more.
    respond_spent: int | None = Field(default=None, ge=0, le=10_000_000)

    @field_validator("supports", mode="before")
    @classmethod
    def _known_v2(cls, v: Any) -> Any:
        if not isinstance(v, list):
            return []
        names = {a.value for a in V2_ACTIONS}
        return [a for a in dict.fromkeys(v) if isinstance(a, str) and a in names]

    @field_validator("tier", mode="before")
    @classmethod
    def _known_tier(cls, v: Any) -> Any:
        return v if v in {t.value for t in Tier} else None

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


class Budget(BaseModel):
    """What a ``respond`` may spend: output tokens, and time until the whole answer is in."""

    model_config = ConfigDict(extra="ignore")

    max_tokens: int = Field(ge=1, le=MAX_OUTPUT_TOKENS)
    deadline_ms: int = Field(ge=1, le=MAX_RESPOND_DEADLINE_MS)


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
    # v2
    budget: Budget | None = None  # respond
    ops: list[Op] | None = None  # plant_token: validated state operations
    sandbox: str | None = Field(default=None, max_length=128)  # escalate: the broker's session

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
