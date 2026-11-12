"""Honeytokens: minted when a profile is rendered, detected in the pipeline (spec 1.6, P3).

Decoys never call a token service. The profile generator plants token values in decoy files,
rows and keys and registers each one; the pipeline's :class:`Matcher` scans every captured
input for the values and reports a ``token.triggered`` event when one is used.
"""

from __future__ import annotations

import hashlib
import json
import random
import string
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

TYPES = ("credential", "url", "record", "cloud_key")


@dataclass(frozen=True)
class Token:
    token_id: str
    type: str
    value: str  # the string to look for in captured input
    deployment_id: str
    planted_at: str  # where: "ssh:/var/www/html/.env", "mysql:wordpress.wp_users", ...
    minted_at: str
    username: str | None = None  # credentials: the user the password belongs to
    note: str = ""

    def to_row(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Minter:
    deployment_id: str
    rng: random.Random
    tokens: list[Token] = field(default_factory=list)

    def _id(self, value: str) -> str:
        return "tok-" + hashlib.sha256(f"{self.deployment_id}:{value}".encode()).hexdigest()[:16]

    def _add(self, type_: str, value: str, planted_at: str, **kw: Any) -> Token:
        if type_ not in TYPES:
            raise ValueError(type_)
        t = Token(
            token_id=self._id(value),
            type=type_,
            value=value,
            deployment_id=self.deployment_id,
            planted_at=planted_at,
            minted_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            **kw,
        )
        self.tokens.append(t)
        return t

    def password(self, length: int = 14) -> str:
        """A password that looks hand-made but is unique enough to match without false hits."""
        words = ["Summer", "Winter", "Admin", "Welcome", "Prod", "Db", "Web", "Sql", "Backup"]
        w = self.rng.choice(words)
        digits = "".join(self.rng.choice(string.digits) for _ in range(4))
        tail = "".join(
            self.rng.choice(string.ascii_letters) for _ in range(max(4, length - len(w) - 5))
        )
        return f"{w}{digits}!{tail}"

    def credential(self, username: str, planted_at: str, password: str | None = None) -> Token:
        return self._add("credential", password or self.password(), planted_at, username=username)

    def url(self, planted_at: str, prefix: str = "/") -> Token:
        slug = "".join(self.rng.choice(string.ascii_lowercase + string.digits) for _ in range(10))
        return self._add("url", f"{prefix}{slug}", planted_at)

    def record(self, value: str, planted_at: str) -> Token:
        return self._add("record", value, planted_at)

    def cloud_key(self, planted_at: str) -> Token:
        # AWS-shaped but in a form AWS never issues (the fifth character is a digit run that
        # real keys do not use), so secret scanners and AWS itself never treat it as real.
        body = "".join(self.rng.choice(string.ascii_uppercase + string.digits) for _ in range(12))
        return self._add("cloud_key", f"AKIA0000{body}", planted_at, note="recorded only")

    def write(self, path: Path) -> None:
        path.write_text(json.dumps([t.to_row() for t in self.tokens], indent=1) + "\n")


def load(path: Path) -> list[Token]:
    return [Token(**r) for r in json.loads(path.read_text())]


class Matcher:
    """Find planted token values in captured text. A few dozen tokens per deployment, so a
    plain substring scan is enough; values are long and random, so false hits are negligible."""

    MIN_LEN = 8

    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = [t for t in tokens if len(t.value) >= self.MIN_LEN]

    def find(self, text: str) -> list[Token]:
        if not text:
            return []
        return [t for t in self.tokens if t.value in text]
