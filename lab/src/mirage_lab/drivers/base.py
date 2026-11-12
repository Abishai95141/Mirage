"""What every protocol driver gives the runner."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from mirage_lab.net import Conn


@dataclass
class Result:
    """One step, as the driver saw it."""

    sent: bool  # False when nothing reached the decoy (the connection was already gone)
    output: str = ""
    status: int | None = None  # exit status, where the protocol has one
    alive: bool = True  # whether the session can take another step
    conn: Conn | None = None  # the connection that carried the step
    started: datetime | None = None
    ended: datetime | None = None
    sha256: str | None = None  # of the input text, or of the uploaded bytes


@dataclass
class AuthPhase:
    """The login attempts made on one connection."""

    conn: Conn
    started: datetime
    ended: datetime
    attempts: int
    success: bool


@dataclass
class LoginResult:
    ok: bool
    phases: list[AuthPhase] = field(default_factory=list)
