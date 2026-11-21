"""What the answer cache holds, for the render library's promotion step (phase 3 spec 3.2b).

    python -m mirage_responder.candidates list     the cached answers, as JSON
    python -m mirage_responder.candidates evict    drop the entries listed on standard input
    python -m mirage_responder.candidates standings    which programs are refused, and which work
    python -m mirage_responder.candidates forgive [VERB ...]   forget those standings

Run inside the responder's container (`make render-candidates`, `make llm-evict`). ``list``
prints every cached answer with how often it was served. The profile tool turns the
stateless ones into entries of the render library, once the reference host has answered the
same commands, and names the cached answers that are not the real host's; ``evict`` takes
that list (JSON: objects with ``command`` and ``fingerprint``) and removes them, so that a
wrong answer is not served again.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path


def cache_path() -> Path:
    return Path(os.environ.get("RESPONDER_CACHE", "/var/lib/mirage-responder/cache.db"))


def listed(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        rows = db.execute(
            "SELECT profile_id, command, fingerprint, model_version, prompt_version, stdout, "
            "stderr, exit_code, hits FROM answers ORDER BY hits DESC, command"
        ).fetchall()
    finally:
        db.close()
    keys = (
        "profile_id",
        "command",
        "fingerprint",
        "model_version",
        "prompt_version",
        "stdout",
        "stderr",
        "exit_code",
        "hits",
    )
    return [dict(zip(keys, row, strict=True)) for row in rows]


def evict(path: Path, entries: list[dict[str, object]]) -> int:
    if not path.exists():
        return 0
    db = sqlite3.connect(str(path), isolation_level=None)
    gone = 0
    try:
        for entry in entries:
            done = db.execute(
                "DELETE FROM answers WHERE command = ? AND fingerprint = ?",
                (str(entry["command"]), str(entry.get("fingerprint", ""))),
            )
            gone += done.rowcount
    finally:
        db.close()
    return gone


def standings(path: Path) -> list[dict[str, object]]:
    """Where each program stands on the deployment (cache.STANDINGS): works, or refused."""
    if not path.exists():
        return []
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        rows = db.execute(
            "SELECT profile_id, verb, state, reason, at FROM standings ORDER BY at"
        ).fetchall()
    except sqlite3.OperationalError:  # a cache from before standings were kept
        return []
    finally:
        db.close()
    return [
        dict(zip(("profile_id", "verb", "state", "reason", "at"), r, strict=True)) for r in rows
    ]


def forgive(path: Path, verbs: list[str]) -> int:
    """Forget where the named programs stand, or every program with no name given."""
    if not path.exists():
        return 0
    db = sqlite3.connect(str(path), isolation_level=None)
    try:
        if not verbs:
            return int(db.execute("DELETE FROM standings").rowcount)
        return sum(
            int(db.execute("DELETE FROM standings WHERE verb = ?", (verb,)).rowcount)
            for verb in verbs
        )
    except sqlite3.OperationalError:
        return 0
    finally:
        db.close()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args == ["standings"]:
        json.dump(standings(cache_path()), sys.stdout, indent=1)
        return 0
    if args[:1] == ["forgive"]:
        print(f"{forgive(cache_path(), args[1:])} standings forgotten", file=sys.stderr)
        return 0
    if args == ["list"]:
        json.dump(listed(cache_path()), sys.stdout, indent=1)
        return 0
    if args == ["evict"]:
        entries = json.loads(sys.stdin.read() or "[]")
        print(f"{evict(cache_path(), entries)} cached answers evicted", file=sys.stderr)
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
