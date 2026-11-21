"""State operations (docs/06-phase-3-spec.md, 3.1): the only ways anything but the emulator
itself may change a session.

A model never changes state. It *proposes* operations from this vocabulary; the responder's
state manager validates them against the session; the decoy validates them again against its
own filesystem and applies them through the mutators an emulated command uses, all of an
answer's operations or none. The policy's ``plant_token`` carries operations of the same
kind.

What is checked here is what can be checked without a session: the shape of each operation
and the caps. Whether the parent exists, whether the user may write there and whether the
path holds a planted token are the session's to say.
"""

from __future__ import annotations

import posixpath
import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

MAX_OPS = 8  # operations in one answer
MAX_WRITE_BYTES = 4096  # content of one write
MAX_PATH_BYTES = 1024
MAX_VALUE_BYTES = 4096  # an environment value, a process's command line
# Directories the kernel fills. Nothing a model proposes may touch them.
PROTECTED = ("/proc", "/sys", "/dev")
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


class OpKind(StrEnum):
    MKDIR = "mkdir"
    WRITE = "write"
    REMOVE = "remove"
    RENAME = "rename"
    CHMOD = "chmod"
    CHOWN = "chown"
    CD = "cd"
    SETENV = "setenv"
    UNSETENV = "unsetenv"
    PROC_START = "proc_start"
    PROC_END = "proc_end"


FILESYSTEM = frozenset(
    {OpKind.MKDIR, OpKind.WRITE, OpKind.REMOVE, OpKind.RENAME, OpKind.CHMOD, OpKind.CHOWN}
)
# The fields each kind needs, and may have. Anything else on an operation is an error.
_NEEDS: dict[OpKind, tuple[str, ...]] = {
    OpKind.MKDIR: ("path",),
    OpKind.WRITE: ("path", "content"),
    OpKind.REMOVE: ("path",),
    OpKind.RENAME: ("path", "to"),
    OpKind.CHMOD: ("path", "mode"),
    OpKind.CHOWN: ("path",),
    OpKind.CD: ("path",),
    OpKind.SETENV: ("name", "value"),
    OpKind.UNSETENV: ("name",),
    OpKind.PROC_START: ("args",),
    OpKind.PROC_END: ("pid",),
}
_MAY: dict[OpKind, tuple[str, ...]] = {
    OpKind.MKDIR: ("mode",),
    OpKind.WRITE: ("mode",),
    OpKind.CHOWN: ("uid", "gid"),
}


def protected(path: str) -> bool:
    """Whether ``path`` is one of the kernel's directories or under one."""
    return any(path == p or path.startswith(p + "/") for p in PROTECTED)


def well_formed(path: str) -> str | None:
    """What is wrong with a path as a path, or None: it must be absolute and already in its
    simplest form, so that what is validated is what is applied."""
    if not path.startswith("/"):
        return "not absolute"
    if "\0" in path or len(path.encode()) > MAX_PATH_BYTES:
        return "not a usable path"
    if posixpath.normpath(path) != path:
        return "not normalised"
    return None


class Op(BaseModel):
    model_config = ConfigDict(extra="forbid")

    op: OpKind
    path: str | None = None
    to: str | None = None  # rename: the new path
    content: str | None = None  # write
    mode: int | None = Field(default=None, ge=0, le=0o7777, strict=True)
    uid: int | None = Field(default=None, ge=0, le=65535, strict=True)
    gid: int | None = Field(default=None, ge=0, le=65535, strict=True)
    name: str | None = None  # setenv, unsetenv
    value: str | None = None  # setenv
    args: str | None = None  # proc_start: the command line the process shows
    pid: int | None = Field(default=None, ge=2, le=4194304, strict=True)  # proc_end

    @model_validator(mode="after")
    def _shape(self) -> Op:
        given = {k for k, v in self.model_dump(exclude={"op"}).items() if v is not None}
        needs, may = set(_NEEDS[self.op]), set(_MAY.get(self.op, ()))
        if needs - given:
            raise ValueError(f"{self.op.value} needs {sorted(needs - given)}")
        if given - needs - may:
            raise ValueError(f"{self.op.value} does not take {sorted(given - needs - may)}")
        if self.op is OpKind.CHOWN and self.uid is None and self.gid is None:
            raise ValueError("chown needs a uid or a gid")
        for field in ("path", "to"):
            value = getattr(self, field)
            if value is None:
                continue
            wrong = well_formed(value)
            if wrong:
                raise ValueError(f"{self.op.value}: {field} is {wrong}")
            if self.op in FILESYSTEM and protected(value):
                raise ValueError(f"{self.op.value}: {field} is under a directory the kernel fills")
        if self.op in FILESYSTEM and self.path == "/":
            raise ValueError(f"{self.op.value}: not the root")
        if self.content is not None and len(self.content.encode()) > MAX_WRITE_BYTES:
            raise ValueError(f"write: content over {MAX_WRITE_BYTES} bytes")
        if self.name is not None and not _NAME.match(self.name):
            raise ValueError(f"{self.op.value}: not a variable name")
        for field in ("value", "args"):
            value = getattr(self, field)
            if value is not None and (len(value.encode()) > MAX_VALUE_BYTES or "\0" in value):
                raise ValueError(f"{self.op.value}: {field} is too long or holds a NUL")
        return self


def parse_ops(raw: Any) -> list[Op]:
    """The operations of one answer, or ``ValueError`` naming the first thing wrong. One bad
    operation refuses them all: an answer's operations apply together or not at all."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("ops is not a list")
    if len(raw) > MAX_OPS:
        raise ValueError(f"{len(raw)} operations; at most {MAX_OPS} in one answer")
    out = []
    for index, item in enumerate(raw):
        try:
            out.append(item if isinstance(item, Op) else Op.model_validate(item))
        except ValidationError as exc:
            first = exc.errors()[0]
            message = str(first["msg"]).removeprefix("Value error, ")
            where = ".".join(str(part) for part in first["loc"])
            raise ValueError(
                f"operation {index + 1}: {message}" + (f" ({where})" if where else "")
            ) from exc
    return out
