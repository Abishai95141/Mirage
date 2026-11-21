"""The responder API (docs/06-phase-3-spec.md, section 3): what the SSH decoy sends when the
policy answers ``respond``, and what comes back.

``POST /v1/respond`` with a bearer token. The request is one JSON object. The reply is
newline-delimited JSON, one record a line:

    {"type": "out", "line": "..."}       one complete line of stdout, as soon as it is safe
    {"type": "end", ...}                  the rest of the answer; nothing follows it
    {"type": "abort", "reason": "..."}    no answer, or no more of one; nothing follows it
    {"type": "resync", "have": N}         the journal sent does not join what is held

An answer reaches the decoy in one of two ways, by what its command may do. A command that
only reads is *streamed*: its lines come as ``out`` records while the model is still writing,
and its ``end`` carries no operations. Any other command is *held*: no ``out`` record is sent,
and ``end`` carries the whole of stdout with the operations, so that the decoy can apply the
operations first and show nothing at all if it refuses them. An ``end`` with operations after
``out`` records is a breach of this, and the decoy applies nothing.

The decoy owns the session's filesystem and working directory. It tells the responder what
changed since last time (the *journal*, numbered from 1), and shows it the part of the
filesystem the command names (the *slice*). The responder never changes anything: an answer
may carry operations (:mod:`mirage_schema.ops`), which the decoy validates again and applies.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from mirage_schema.ops import Op
from mirage_schema.policy import Budget, Src

MAX_INPUT_BYTES = 1024  # the input line (spec 3.2b)
MAX_JOURNAL = 4096  # entries in one request
MAX_SLICE = 256  # filesystem entries in one request
HEAD_BYTES = 1024  # of a small text file shown in the slice
MAX_CHILDREN = 200  # names of a directory shown in the slice


class JournalEntry(BaseModel):
    """One change the session made, as the decoy recorded it. ``op`` is the decoy's own word
    for it: what ``cowrie.fs.change`` calls a filesystem change, and ``cd``, ``setenv``,
    ``unsetenv``, ``proc_start`` and ``proc_end`` for what is not one."""

    model_config = ConfigDict(extra="ignore")

    seq: int = Field(ge=1)
    op: str = Field(max_length=16)
    path: str | None = None
    new_path: str | None = None  # rename
    mode: int | None = None
    size: int | None = None
    uid: int | None = None
    gid: int | None = None
    name: str | None = None  # setenv, unsetenv
    value: str | None = None
    pid: int | None = None  # proc_start, proc_end
    args: str | None = None  # proc_start


class FsEntry(BaseModel):
    """A path as the decoy has it now. ``type`` is ``missing`` for a path that is not there:
    saying so is as much a fact as showing a file."""

    model_config = ConfigDict(extra="ignore")

    path: str
    type: Literal["file", "dir", "link", "other", "missing"]
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    size: int | None = None
    target: str | None = None  # a link's
    head: str | None = None  # the first bytes of a small text file the user may read
    children: list[str] | None = None  # a directory's names, as far as they are shown


class RespondRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    request_id: str = Field(min_length=1, max_length=64)
    session_id: str = Field(min_length=1, max_length=64)
    deployment_id: str = Field(min_length=1, max_length=64)
    seq: int | None = Field(default=None, ge=0)
    src: Src = Field(default_factory=Src)
    user: str = Field(min_length=1, max_length=64)
    uid: int = Field(ge=0, le=65535)
    gid: int = Field(default=0, ge=0, le=65535)
    cwd: str
    argv: list[str] = Field(min_length=1, max_length=256)
    input: str  # the command as it was typed, after expansion
    interactive: bool = True
    env: dict[str, str] = Field(default_factory=dict)  # what the session changed
    # The journal: entries ``journal_from`` to ``journal_to``. 1 means from the beginning.
    journal_from: int = Field(default=1, ge=1)
    journal_to: int = Field(default=0, ge=0)
    journal: list[JournalEntry] = Field(default_factory=list, max_length=MAX_JOURNAL)
    slice: list[FsEntry] = Field(default_factory=list, max_length=MAX_SLICE)
    budget: Budget


class Out(BaseModel):
    type: Literal["out"] = "out"
    line: str  # without its newline; every line but an answer's last ends in one
    newline: bool = True


class End(BaseModel):
    type: Literal["end"] = "end"
    stdout: str = ""  # a held answer's whole stdout; empty for a streamed one
    stderr: str = ""
    exit_code: int = Field(default=0, ge=0, le=255)
    ops: list[Op] = Field(default_factory=list)
    rung: Literal["cache", "model", "replay"]
    prompt_tokens: int = 0
    output_tokens: int = 0
    first_ms: float | None = None  # until the first line could be sent
    total_ms: float = 0.0


class Abort(BaseModel):
    type: Literal["abort"] = "abort"
    reason: str = Field(max_length=120)


class Resync(BaseModel):
    type: Literal["resync"] = "resync"
    have: int = Field(ge=0)  # the last journal entry the responder holds for the session


Reply = Annotated[Out | End | Abort | Resync, Field(discriminator="type")]
_reply = TypeAdapter(Reply)


def parse_reply(line: str | bytes) -> Out | End | Abort | Resync:
    """One line of a reply. Raises ``pydantic.ValidationError`` for anything else."""
    return _reply.validate_json(line)


def dump(record: BaseModel) -> bytes:
    """A record as one line of the stream."""
    return record.model_dump_json(exclude_none=True).encode() + b"\n"


def as_dict(record: BaseModel) -> dict[str, Any]:
    return record.model_dump(mode="json", exclude_none=True)
