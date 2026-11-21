"""The state manager (docs/06-phase-3-spec.md, 3.1, decision R7).

The decoy owns a session's filesystem and working directory. This holds a *mirror* of what
the session changed, built from the decoy's change journal, and the things the decoy has no
place for: the processes the session started and the facts earlier answers asserted. All of
it is in memory, bounded, and may be lost at any time: the next request is answered with
``resync`` and the decoy sends its journal again from the beginning.

A model never changes state. It proposes operations; :meth:`Session.validate` checks them
against what is known of the session; the decoy checks them again against its own filesystem
and applies them. Nothing here is changed by an answer: a change becomes part of the mirror
only when the decoy's journal reports it.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from mirage_schema.ops import FILESYSTEM, Op, OpKind
from mirage_schema.respond import FsEntry, JournalEntry, RespondRequest

SESSION_TTL_S = 3600  # dropped an hour after the last request
MAX_SESSIONS = 512
MAX_FACTS = 32  # facts earlier answers asserted, most recent kept
MAX_MIRROR = 4096  # paths remembered for one session
# What the answers of one session may ask the decoy to do, in all.
SESSION_WRITE_BYTES = 64 * 1024
SESSION_FILES = 64
SESSION_PROCESSES = 16
# Environment a command's answer can depend on, for the state fingerprint.
RELEVANT_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "USER")


class Rejected(ValueError):
    """An answer's operations cannot be applied. The whole answer is refused."""


@dataclass
class Node:
    """What is known of one path: from the decoy's slice of its filesystem, or from the
    session's own changes."""

    type: str  # file, dir, link, other, missing
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    size: int | None = None

    @classmethod
    def of(cls, entry: FsEntry) -> Node:
        return cls(entry.type, entry.mode, entry.uid, entry.gid, entry.size)


@dataclass
class Process:
    pid: int
    args: str
    started: float


@dataclass
class Session:
    profile_id: str
    user: str = "root"
    uid: int = 0
    gid: int = 0
    cwd: str = "/"
    env: dict[str, str] = field(default_factory=dict)
    journal_seq: int = 0  # the last journal entry folded in
    mirror: dict[str, Node] = field(default_factory=dict)
    processes: dict[int, Process] = field(default_factory=dict)
    facts: list[str] = field(default_factory=list)
    tokens_spent: int = 0
    bytes_written: int = 0  # by operations of this session's answers, as the journal reports
    # What this session was told, by command and by the state it was told in: asked the same
    # thing again in the same state, it is told the same (see Responder._answer).
    said: OrderedDict[tuple[str, str], tuple[str, str, int]] = field(default_factory=OrderedDict)
    files_made: int = 0
    last_seen: float = 0.0

    # ---------------------------------------------------------------- the journal

    def joins(self, journal_from: int) -> bool:
        """Whether a journal starting at ``journal_from`` continues what is held."""
        return journal_from == 1 or journal_from <= self.journal_seq + 1

    def fold(self, journal_from: int, entries: Iterable[JournalEntry]) -> None:
        """Fold journal entries into the mirror. A journal from 1 replaces everything."""
        if journal_from == 1:
            self.journal_seq = 0
            self.mirror.clear()
            self.processes.clear()
            self.env.clear()
            self.bytes_written = self.files_made = 0
        for entry in sorted(entries, key=lambda e: e.seq):
            if entry.seq <= self.journal_seq:
                continue  # already held
            self._apply(entry)
            self.journal_seq = entry.seq

    def _apply(self, e: JournalEntry) -> None:
        if e.op in ("create", "write"):
            if e.path:
                known = self.mirror.get(e.path)
                if known is None or known.type != "file":
                    self.files_made += 1
                # A write to a file already known says only its new size: the rest is kept.
                was = known if known is not None and known.type == "file" else Node("file")
                self._put(
                    e.path,
                    Node(
                        "file",
                        e.mode if e.mode is not None else was.mode,
                        e.uid if e.uid is not None else was.uid,
                        e.gid if e.gid is not None else was.gid,
                        e.size if e.size is not None else was.size,
                    ),
                )
                self.bytes_written += int(e.size or 0)
        elif e.op == "mkdir":
            if e.path:
                self._put(e.path, Node("dir", e.mode, e.uid, e.gid, 4096))
        elif e.op in ("remove", "rmdir"):
            if e.path:
                self._gone(e.path)
        elif e.op == "rename":
            if e.path and e.new_path:
                moved = self.mirror.get(e.path) or Node("file")
                under = e.path.rstrip("/") + "/"
                for path in [p for p in self.mirror if p.startswith(under)]:
                    self._put(e.new_path.rstrip("/") + "/" + path[len(under) :], self.mirror[path])
                self._gone(e.path)
                self._put(e.new_path, moved)
        elif e.op == "chmod":
            if e.path and e.mode is not None:
                self.mirror.setdefault(e.path, Node("file")).mode = e.mode
        elif e.op == "chown":
            if e.path:
                node = self.mirror.setdefault(e.path, Node("file"))
                node.uid = e.uid if e.uid is not None and e.uid >= 0 else node.uid
                node.gid = e.gid if e.gid is not None and e.gid >= 0 else node.gid
        elif e.op == "cd":
            if e.path:
                self.cwd = e.path
        elif e.op == "setenv":
            if e.name:
                self.env[e.name] = e.value or ""
        elif e.op == "unsetenv":
            if e.name:
                self.env.pop(e.name, None)
        elif e.op == "proc_start":
            if e.pid and len(self.processes) < SESSION_PROCESSES * 4:
                self.processes[e.pid] = Process(e.pid, e.args or "", time.time())
        elif e.op == "proc_end" and e.pid:
            self.processes.pop(e.pid, None)

    def _put(self, path: str, node: Node) -> None:
        self.mirror.pop(path, None)
        self.mirror[path] = node
        while len(self.mirror) > MAX_MIRROR:
            self.mirror.pop(next(iter(self.mirror)))

    def _gone(self, path: str) -> None:
        under = path.rstrip("/") + "/"
        for known in [p for p in self.mirror if p.startswith(under)]:
            del self.mirror[known]
        self._put(path, Node("missing"))

    # ---------------------------------------------------------------- facts

    def assert_fact(self, fact: str) -> None:
        fact = fact.strip()[:200]
        if fact and fact not in self.facts:
            self.facts.append(fact)
            del self.facts[:-MAX_FACTS]

    # ---------------------------------------------------------------- validation

    def view(self, slice_: Iterable[FsEntry]) -> dict[str, Node]:
        """What is known of the filesystem for this request: the mirror, then the decoy's own
        slice over it, which is the newer of the two for every path it names."""
        known = dict(self.mirror)
        for entry in slice_:
            known[entry.path] = Node.of(entry)
        known.setdefault("/", Node("dir", 0o755, 0, 0, 4096))
        return known

    def validate(
        self, ops: list[Op], slice_: Iterable[FsEntry], protected: Callable[[str], bool]
    ) -> list[Op]:
        """The operations, if every one of them can be applied in order; else ``Rejected``
        with the first reason. ``protected`` says whether a path holds a planted token.

        Checked here: the parent exists and is a directory; the session's user may make the
        change; no planted token is touched; the session stays inside its caps. A path nothing
        is known about is not assumed to exist: the decoy shows the paths a command names, and
        an operation on any other path is refused.
        """
        known = self.view(slice_)
        written, made, running = self.bytes_written, self.files_made, len(self.processes)
        for index, op in enumerate(ops, 1):
            try:
                if op.op in FILESYSTEM:
                    for path in (op.path, op.to):
                        if path and protected(path):
                            raise Rejected("the path holds a planted token")
                    add_bytes, add_files = self._filesystem(op, known)
                    written, made = written + add_bytes, made + add_files
                    if written > SESSION_WRITE_BYTES:
                        raise Rejected("the session's answers have written their limit")
                    if made > SESSION_FILES:
                        raise Rejected("the session's answers have made their limit of files")
                elif op.op is OpKind.CD:
                    node = known.get(op.path or "")
                    if node is None or node.type != "dir":
                        raise Rejected("not a directory the session can be shown to have")
                elif op.op is OpKind.PROC_START:
                    running += 1
                    if running > SESSION_PROCESSES:
                        raise Rejected("the session's answers have started their limit")
                elif op.op is OpKind.PROC_END and op.pid not in self.processes:
                    raise Rejected("not a process this session started")
            except Rejected as exc:
                raise Rejected(f"operation {index} ({op.op.value}): {exc}") from None
        return ops

    def _may_write(self, node: Node) -> bool:
        """Whether the session's user may change the entries of a directory, or a file's
        contents: root may; an owner with the write bit may; anyone may with the other-write
        bit. A group's bits are not used: the session's groups are not known here, and
        refusing is the safe mistake."""
        if self.uid == 0:
            return True
        mode = node.mode if node.mode is not None else 0
        if node.uid == self.uid:
            return bool(mode & 0o200)
        return bool(mode & 0o002)

    def _filesystem(self, op: Op, known: dict[str, Node]) -> tuple[int, int]:
        """Check one filesystem operation and fold it into ``known``, so that the operations
        after it see it. Returns the bytes and the files it adds to the session's totals."""
        path = op.path or ""
        parent = known.get(posixpath.dirname(path))
        if parent is None:
            raise Rejected("nothing is known of the parent directory")
        if parent.type != "dir":
            raise Rejected("the parent is not a directory")
        node = known.get(path)
        exists = node is not None and node.type != "missing"
        if op.op is OpKind.MKDIR:
            if exists:
                raise Rejected("the path exists")
            if not self._may_write(parent):
                raise Rejected("the user may not write there")
            known[path] = Node("dir", op.mode if op.mode is not None else 0o755, self.uid, self.gid)
            return 0, 0
        if op.op is OpKind.WRITE:
            if exists and node.type != "file":
                raise Rejected("the path is not a file")
            if exists and not self._may_write(node):
                raise Rejected("the user may not write the file")
            if not exists and not self._may_write(parent):
                raise Rejected("the user may not write there")
            size = len((op.content or "").encode())
            known[path] = Node(
                "file", op.mode if op.mode is not None else 0o644, self.uid, self.gid, size
            )
            return size, 0 if exists else 1
        if node is None:
            raise Rejected("nothing is known of the path")
        if not exists:
            raise Rejected("the path does not exist")
        if op.op is OpKind.REMOVE:
            if not self._may_write(parent):
                raise Rejected("the user may not write there")
            if node.type == "dir" and any(
                p.startswith(path + "/") and n.type != "missing" for p, n in known.items()
            ):
                raise Rejected("the directory is not empty")
            known[path] = Node("missing")
            return 0, 0
        if op.op is OpKind.RENAME:
            to = op.to or ""
            target_parent = known.get(posixpath.dirname(to))
            if target_parent is None or target_parent.type != "dir":
                raise Rejected("the new path's parent is not a known directory")
            if not self._may_write(parent) or not self._may_write(target_parent):
                raise Rejected("the user may not write there")
            target = known.get(to)
            if target is not None and target.type == "dir":
                raise Rejected("the new path is a directory")
            known[to], known[path] = node, Node("missing")
            return 0, 0
        if op.op is OpKind.CHMOD:
            if self.uid not in (0, node.uid):
                raise Rejected("only the owner may change the mode")
            node.mode = op.mode
            return 0, 0
        # chown
        if self.uid != 0:
            raise Rejected("only root may change the owner")
        return 0, 0

    # ---------------------------------------------------------------- the cache key

    def fingerprint(self, paths: Iterable[str], slice_: Iterable[FsEntry]) -> str:
        """The state a state-reading command's answer can depend on: where the session is,
        the environment that matters, and what is at the paths the command names."""
        known = self.view(slice_)
        shown = {}
        for path in sorted(set(paths)):
            node = known.get(path)
            shown[path] = None if node is None else [node.type, node.mode, node.uid, node.size]
            for other, child in sorted(known.items()):
                if other.startswith(path.rstrip("/") + "/"):
                    shown[other] = [child.type, child.mode, child.uid, child.size]
        heads = {e.path: e.head for e in slice_ if e.head is not None}
        body = {
            "cwd": self.cwd,
            "user": self.user,
            "env": {k: self.env[k] for k in RELEVANT_ENV if k in self.env},
            "paths": shown,
            "heads": heads,
        }
        text = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(text.encode()).hexdigest()[:24]


class Sessions:
    """Every session held, least recently used first."""

    def __init__(
        self,
        max_sessions: int = MAX_SESSIONS,
        ttl_s: float = SESSION_TTL_S,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        self._held: OrderedDict[str, Session] = OrderedDict()
        self._max, self._ttl, self._now = max_sessions, ttl_s, now

    def __len__(self) -> int:
        return len(self._held)

    def get(self, session_id: str) -> Session | None:
        session = self._held.get(session_id)
        if session is not None and self._now() - session.last_seen > self._ttl:
            del self._held[session_id]
            return None
        return session

    def open(self, req: RespondRequest) -> Session:
        """The session of this request, made if it is not held, with what the request says of
        who and where it is. The journal is folded in by the caller."""
        session = self.get(req.session_id)
        if session is None:
            session = Session(profile_id=req.deployment_id)
            self._held[req.session_id] = session
        self._held.move_to_end(req.session_id)
        while len(self._held) > self._max:
            self._held.popitem(last=False)
        session.user, session.uid, session.gid, session.cwd = req.user, req.uid, req.gid, req.cwd
        session.last_seen = self._now()
        return session

    def drop(self, session_id: str) -> None:
        self._held.pop(session_id, None)

    def summary(self) -> dict[str, Any]:
        return {"sessions": len(self._held)}
