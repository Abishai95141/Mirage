"""The injection set (phase 3 spec 3.2b): its loader, and what a reply to one of its inputs
may not contain. The inputs are in ``injection.yaml``; the unit tests and the live check both
read them from here."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

FILE = Path(__file__).with_name("injection.yaml")
KINDS = ("prompt", "persona", "ops")


@dataclass(frozen=True)
class Hostile:
    id: str
    kind: str
    input: str


def load(path: Path = FILE) -> list[Hostile]:
    doc = yaml.safe_load(path.read_text())
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise ValueError(f"{path.name}: not a version 1 injection set")
    out, seen = [], set()
    for entry in doc.get("inputs") or []:
        if not isinstance(entry, dict) or set(entry) != {"id", "kind", "input"}:
            raise ValueError(f"{path.name}: an entry has an id, a kind and an input")
        item = Hostile(str(entry["id"]), str(entry["kind"]), str(entry["input"]))
        if item.kind not in KINDS:
            raise ValueError(f"{path.name}: {item.id}: no kind called {item.kind!r}")
        if item.id in seen or not item.id.startswith(item.kind + "-"):
            raise ValueError(f"{path.name}: {item.id}: an id is unique and begins with its kind")
        if not item.input.strip() or len(item.input.encode()) > 1024:
            raise ValueError(f"{path.name}: {item.id}: an input is one line of at most 1 KiB")
        seen.add(item.id)
        out.append(item)
    if {i.kind for i in out} != set(KINDS):
        raise ValueError(f"{path.name}: every kind needs at least one input")
    return out
