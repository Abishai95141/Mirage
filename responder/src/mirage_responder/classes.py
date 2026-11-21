"""Command classes (docs/06-phase-3-spec.md, 3.1): which of six kinds a command is.

The class decides how an answer may be made: whether it is generated at all, whether it may
be shown line by line or must be held back until its operations are checked, and whether it
may be kept and reused.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

TABLE = Path(__file__).with_name("classes.yaml")


class CommandClass(StrEnum):
    STATELESS = "stateless"
    STATE_READING = "state-reading"
    STATE_CHANGING = "state-changing"
    VOLATILE = "volatile"
    INTERACTIVE = "interactive"
    NETWORK = "network"


REFUSED = frozenset({CommandClass.INTERACTIVE, CommandClass.NETWORK})
CACHED = frozenset({CommandClass.STATELESS, CommandClass.STATE_READING})
# Shown line by line as it is made. Anything else is held back until it is whole.
STREAMED = frozenset({CommandClass.STATELESS, CommandClass.STATE_READING, CommandClass.VOLATILE})
# The cautious case, for a command the table does not name: it may change something.
DEFAULT = CommandClass.STATE_CHANGING


@dataclass(frozen=True)
class Classes:
    commands: dict[str, tuple[CommandClass, dict[str, CommandClass]]]
    version: str

    @classmethod
    def load(cls, path: Path = TABLE) -> Classes:
        raw = path.read_bytes()
        doc = yaml.safe_load(raw)
        if not isinstance(doc, dict) or doc.get("version") != 1:
            raise ValueError(f"{path.name}: not a version 1 class table")
        commands = {}
        for name, entry in (doc.get("commands") or {}).items():
            if not isinstance(entry, dict) or set(entry) - {"class", "forms"}:
                raise ValueError(f"{path.name}: {name}: an entry has a class and may have forms")
            forms = {str(k): CommandClass(v) for k, v in (entry.get("forms") or {}).items()}
            commands[str(name)] = (CommandClass(entry["class"]), forms)
        return cls(commands, hashlib.sha256(raw).hexdigest()[:12])

    def of(self, argv: list[str]) -> CommandClass:
        """The class of a command line. A form is recognised by any of its arguments, so that
        `systemctl --now enable x` is state-changing as `systemctl enable x` is."""
        if not argv:
            return DEFAULT
        name = argv[0].rsplit("/", 1)[-1]
        if name not in self.commands:
            return DEFAULT
        base, forms = self.commands[name]
        found = [forms[a] for a in argv[1:] if a in forms]
        if not found:
            return base
        # The most cautious form wins: refused before changing, changing before the rest.
        for kind in (*sorted(REFUSED), CommandClass.STATE_CHANGING, CommandClass.VOLATILE):
            if kind in found:
                return kind
        return found[0]

    def summary(self) -> dict[str, Any]:
        return {"version": self.version, "commands": len(self.commands)}


def normalise(argv: list[str]) -> str:
    """A command as the cache and the sampling seed name it: its words, single-spaced."""
    return " ".join(" ".join(argv).split())


def named_paths(argv: list[str], cwd: str) -> list[str]:
    """The paths a command line names, made absolute: every argument that is not an option.
    More than the command will read, which is the safe side for a fingerprint."""
    import posixpath

    out = []
    for arg in argv[1:]:
        if not arg or "\0" in arg or (arg.startswith("-") and "=" not in arg):
            continue
        # name=value and --option=value name their value.
        value = arg.split("=", 1)[1] if "=" in arg and not arg.startswith("/") else arg
        if not value:
            continue
        path = value if value.startswith("/") else posixpath.join(cwd, value)
        out.append(posixpath.normpath(path))
    return list(dict.fromkeys(out))
