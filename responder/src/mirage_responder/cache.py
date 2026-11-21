"""The answer cache (docs/06-phase-3-spec.md, 3.2b): rung 3 of the ladder.

A generated answer that completed and passed the filter is kept, so that the same command on
the same deployment in the same state gets the same answer at once: a host that answers one
question two ways is a bigger tell than one that is slightly wrong both times. Only answers
that change nothing are kept (stateless and state-reading commands). An entry made by another
model or another prompt is not an answer of this one, and is dropped when it is met.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS answers (
    profile_id     TEXT NOT NULL,
    command        TEXT NOT NULL,
    fingerprint    TEXT NOT NULL,
    model_version  TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    stdout         TEXT NOT NULL,
    stderr         TEXT NOT NULL,
    exit_code      INTEGER NOT NULL,
    output_tokens  INTEGER NOT NULL,
    created        REAL NOT NULL,
    hits           INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (profile_id, command, fingerprint)
)
"""
# Where a program stands on a deployment: the first thing a session was told about it. A
# program the decoy once said it could not run must not run for the next login, and the
# emulator's fallback says exactly that ("cannot execute binary file"). Found by the
# consistency probes on 18 November 2026: an answer that missed its deadline for one login
# and arrived for the next showed the same program broken and working within a minute.
STANDINGS = """
CREATE TABLE IF NOT EXISTS standings (
    profile_id TEXT NOT NULL,
    verb       TEXT NOT NULL,
    state      TEXT NOT NULL,
    reason     TEXT NOT NULL,
    at         REAL NOT NULL,
    PRIMARY KEY (profile_id, verb)
)
"""
WORKS, REFUSED = "works", "refused"
MAX_ENTRIES = 50_000


@dataclass(frozen=True)
class Answer:
    stdout: str
    stderr: str
    exit_code: int
    output_tokens: int = 0


class Cache:
    def __init__(
        self, path: Path | str, model_version: str, prompt_version: str, refusal_s: float = 0.0
    ) -> None:
        self.refusal_s = refusal_s  # how long a refusal holds; 0: standings are not kept
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(SCHEMA)
        self._db.execute(STANDINGS)
        self._lock = threading.Lock()
        self.model_version, self.prompt_version = model_version, prompt_version
        self.hits = self.misses = 0

    def get(self, profile_id: str, command: str, fingerprint: str) -> Answer | None:
        key = (profile_id, command, fingerprint)
        with self._lock:
            row = self._db.execute(
                "SELECT model_version, prompt_version, stdout, stderr, exit_code, output_tokens "
                "FROM answers WHERE profile_id = ? AND command = ? AND fingerprint = ?",
                key,
            ).fetchone()
            if row is not None and (row[0], row[1]) != (self.model_version, self.prompt_version):
                self._db.execute(
                    "DELETE FROM answers WHERE profile_id = ? AND command = ? AND fingerprint = ?",
                    key,
                )
                row = None
            if row is None:
                self.misses += 1
                return None
            self._db.execute(
                "UPDATE answers SET hits = hits + 1 "
                "WHERE profile_id = ? AND command = ? AND fingerprint = ?",
                key,
            )
            self.hits += 1
        return Answer(row[2], row[3], int(row[4]), int(row[5]))

    def put(self, profile_id: str, command: str, fingerprint: str, answer: Answer) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO answers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
                (
                    profile_id,
                    command,
                    fingerprint,
                    self.model_version,
                    self.prompt_version,
                    answer.stdout,
                    answer.stderr,
                    answer.exit_code,
                    answer.output_tokens,
                    time.time(),
                ),
            )
            (count,) = self._db.execute("SELECT COUNT(*) FROM answers").fetchone()
            if count > MAX_ENTRIES:  # the oldest tenth goes
                self._db.execute(
                    "DELETE FROM answers WHERE rowid IN "
                    "(SELECT rowid FROM answers ORDER BY created LIMIT ?)",
                    (count // 10,),
                )

    def evict(self, profile_id: str, command: str, fingerprint: str) -> bool:
        """Drop one entry (an answer the offline fidelity check has refused)."""
        with self._lock:
            done = self._db.execute(
                "DELETE FROM answers WHERE profile_id = ? AND command = ? AND fingerprint = ?",
                (profile_id, command, fingerprint),
            )
        return done.rowcount > 0

    def standing(self, profile_id: str, verb: str, now: float | None = None) -> str | None:
        """``works``, ``refused`` or None for a program nothing has been said about. A refusal
        lapses after ``refusal_s``: a host whose broken program runs again a week later has
        been repaired, one whose program runs again a minute later is no host."""
        if self.refusal_s <= 0:
            return None
        with self._lock:
            row = self._db.execute(
                "SELECT state, at FROM standings WHERE profile_id = ? AND verb = ?",
                (profile_id, verb),
            ).fetchone()
            if row is None:
                return None
            if row[0] == REFUSED and (now or time.time()) - float(row[1]) > self.refusal_s:
                self._db.execute(
                    "DELETE FROM standings WHERE profile_id = ? AND verb = ?", (profile_id, verb)
                )
                return None
        return str(row[0])

    def stand(self, profile_id: str, verb: str, state: str, reason: str = "") -> bool:
        """Note where a program stands, if nothing is noted yet: the first answer decides.
        Returns whether this call decided it."""
        if self.refusal_s <= 0 or self.standing(profile_id, verb) is not None:
            return False
        with self._lock:
            done = self._db.execute(
                "INSERT OR IGNORE INTO standings VALUES (?, ?, ?, ?, ?)",
                (profile_id, verb, state, reason[:80], time.time()),
            )
        return done.rowcount > 0

    def standings(self) -> list[dict[str, object]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT profile_id, verb, state, reason, at FROM standings ORDER BY at"
            ).fetchall()
        return [
            {"profile_id": r[0], "verb": r[1], "state": r[2], "reason": r[3], "at": r[4]}
            for r in rows
        ]

    def forgive(self, verb: str | None = None) -> int:
        """Forget where programs stand (one, or all): after a model or a prompt changes, or
        between tests. Returns how many were forgotten."""
        with self._lock:
            if verb is None:
                done = self._db.execute("DELETE FROM standings")
            else:
                done = self._db.execute("DELETE FROM standings WHERE verb = ?", (verb,))
        return int(done.rowcount)

    def most_answered(self, limit: int = 50) -> list[tuple[str, str, int]]:
        """(profile, command, times served from here): what to promote to the render library."""
        with self._lock:
            rows = self._db.execute(
                "SELECT profile_id, command, SUM(hits) AS n FROM answers "
                "GROUP BY profile_id, command ORDER BY n DESC, command LIMIT ?",
                (limit,),
            ).fetchall()
        return [(r[0], r[1], int(r[2])) for r in rows]

    def __len__(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM answers").fetchone()[0])

    def close(self) -> None:
        self._db.close()
