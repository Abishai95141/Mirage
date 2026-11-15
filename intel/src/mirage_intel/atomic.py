"""Atomic Red Team's Linux tests as labelled text for the tagger (phase 2 spec, 2.4 layer 2).

The first tagger experiment (15 November 2026) showed why a tagger fitted only on the lab's own
training procedures cannot go far: about three procedures per technique, and a held-out
procedure is by construction a different command for the same technique. The AI/ML design's
next step is to index a larger labelled corpus. Atomic Red Team (Red Canary, MIT licence) is
that corpus: several hundred Linux shell tests, each labelled with its technique by people
outside this project.

It is read from the project's published index (``atomics/Indexes/linux-index.yaml``, about
4 MB, not in the repository) and used as retrieval entries and as extra training pairs. Two
rules keep it honest:

- a third of the lab's catalogue quotes Atomic tests. Any test a **held-out** procedure quotes
  is excluded by its GUID before anything is fitted, or the tagger would look the answer up;
- the scorer still drops, and counts, any scored input whose normalised text equals an index
  entry (``tagscore``'s leak guard), which catches a copy the GUID did not.

Nothing here prints a command: callers get entries to index, and reports hold counts only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
ARG = re.compile(r"#\{([^}]+)\}")
SPLIT = re.compile(r"\s*(?:\|\||&&|;|\|)\s*")
# Script scaffolding that carries no sign of a technique. Indexing it would teach the tagger
# that `echo` or `cd` belongs to whichever test happened to use it.
SCAFFOLD = re.compile(
    r"^(?:#|echo\b|cd\b|sleep\b|exit\b|fi\b|done\b|then\b|else\b|do\b|true\b|false\b|set\b"
    r"|export\b|unset\b|\{|\}|if\b|for\b|while\b|case\b|esac\b|function\b|return\b|wait\b)"
)
MIN_LENGTH = 4


@dataclass(frozen=True)
class AtomicTest:
    guid: str
    technique: str
    lines: tuple[str, ...]  # the test's command, one script line each, defaults filled in


def _expand(command: str, arguments: dict | None) -> str:
    """Fill ``#{name}`` with the argument's default, as the test would run unmodified."""
    defaults = {k: str((v or {}).get("default", "")) for k, v in (arguments or {}).items()}
    return ARG.sub(lambda m: defaults.get(m.group(1), ""), command)


def load(path: Path) -> list[AtomicTest]:
    """Every Linux test with a shell executor."""
    doc = yaml.safe_load(path.read_text()) or {}
    seen: dict[str, AtomicTest] = {}
    for items in doc.values():
        if not isinstance(items, dict):
            continue
        for technique, body in items.items():
            for test in (body or {}).get("atomic_tests") or []:
                executor = test.get("executor") or {}
                if executor.get("name") not in ("sh", "bash"):
                    continue
                if "linux" not in (test.get("supported_platforms") or []):
                    continue
                guid = str(test.get("auto_generated_guid") or "")
                command = _expand(str(executor.get("command") or ""), test.get("input_arguments"))
                lines = tuple(line.strip() for line in command.splitlines() if line.strip())
                if guid and lines:
                    seen.setdefault(guid, AtomicTest(guid, str(technique), lines))
    return sorted(seen.values(), key=lambda t: t.guid)


def guids_in(refs: list[str | None]) -> set[str]:
    """The Atomic GUIDs a list of catalogue ``ref`` strings names."""
    return {m.group(0) for ref in refs if ref for m in [GUID.search(ref)] if m}


def texts(test: AtomicTest, unit: str) -> list[str]:
    """What to index for one test: its script lines, or the commands each line is made of."""
    out = []
    for line in test.lines:
        parts = [p for p in SPLIT.split(line) if p] if unit == "pieces" else [line]
        for part in parts:
            if len(part) >= MIN_LENGTH and not SCAFFOLD.match(part):
                out.append(part)
    return out


def pairs(
    tests: list[AtomicTest],
    unit: str,
    techniques: set[str],
    exclude: set[str],
    current: dict[str, str] | None = None,
) -> list[tuple[str, str]]:
    """(text, technique) for every usable line of every test that is not excluded. A technique
    ID the pinned ATT&CK version has replaced is translated (``current``); a test whose
    technique is outside ``techniques`` is left out, so the tagger's label space stays the
    catalogue's."""
    current = current or {}
    out: dict[tuple[str, str], None] = {}
    for test in tests:
        if test.guid in exclude:
            continue
        technique = current.get(test.technique, test.technique)
        if technique not in techniques:
            continue
        for text in texts(test, unit):
            out.setdefault((text, technique), None)
    return list(out)
