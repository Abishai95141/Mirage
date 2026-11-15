"""What every protocol driver gives the runner."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from mirage_lab.net import Conn


def failure(exc: BaseException) -> str:
    """An exception as one short line for a ground-truth record: its type and what it said."""
    text = " ".join(str(exc).split())
    return f"{type(exc).__name__}: {text}"[:200] if text else type(exc).__name__


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
    # What broke, when the connection failed under the step. ``sent`` still says whether the
    # input reached the decoy, which is what decides if the join should look for it.
    error: str | None = None


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
    error: str | None = None  # why a connection could not be opened, if one could not
