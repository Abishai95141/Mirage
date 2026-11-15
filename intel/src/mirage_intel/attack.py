"""MITRE ATT&CK Enterprise, pinned (phase 2 spec, Q14).

Labels are only comparable inside one ATT&CK version: v19 split Defense Evasion in two, for
example. The project labels against v20.1. Until now that was a string beside a pattern check;
nothing compared a technique ID with what v20.1 contains. This reads the official STIX bundle
(``mitre-attack/attack-stix-data``, ``enterprise-attack-20.1.json``, about 50 MB, not in the
repository) and derives two things:

- a small index (ID, name, tactics, deprecated or revoked), written to ``eval/attack-index.json``
  and committed with the bundle's SHA-256, so the lint can validate every technique and tactic
  in the catalogue and the rules without the bundle;
- the technique descriptions, for the retrieval layer's index. These stay out of the
  repository; the layer's artefact is built where the bundle is.

    uv run python -m mirage_intel.attack index data/attack/enterprise-attack-20.1.json
    uv run python -m mirage_intel.attack check
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
INDEX_FILE = ROOT / "eval" / "attack-index.json"
VERSION = "20.1"


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]  # tactic IDs, e.g. TA0007
    retired: bool = False  # deprecated or revoked in this version
    description: str = ""


@dataclass
class Attack:
    version: str
    sha256: str  # of the STIX bundle the index came from
    techniques: dict[str, Technique]
    tactics: dict[str, str]  # tactic ID -> name
    # A revoked technique -> the one this version says replaced it (followed to the end).
    replaced_by: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_stix(cls, path: Path) -> Attack:
        raw = path.read_bytes()
        bundle = json.loads(raw)
        objects = bundle["objects"]
        version = next(
            (o.get("x_mitre_version", "") for o in objects if o["type"] == "x-mitre-collection"),
            "",
        )
        short_to_id, names = {}, {}
        for o in objects:
            if o["type"] == "x-mitre-tactic":
                tid = _external_id(o)
                short_to_id[o["x_mitre_shortname"]] = tid
                names[tid] = o["name"]
        techniques = {}
        for o in objects:
            if o["type"] != "attack-pattern":
                continue
            tid = _external_id(o)
            if not tid:
                continue
            phases = [
                p["phase_name"]
                for p in o.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ]
            techniques[tid] = Technique(
                id=tid,
                name=o["name"],
                tactics=tuple(sorted(short_to_id[p] for p in phases if p in short_to_id)),
                retired=bool(o.get("revoked") or o.get("x_mitre_deprecated")),
                description=o.get("description", ""),
            )
        by_stix_id = {
            o["id"]: _external_id(o)
            for o in objects
            if o["type"] == "attack-pattern" and o.get("id")
        }
        direct = {
            by_stix_id[o["source_ref"]]: by_stix_id[o["target_ref"]]
            for o in objects
            if o["type"] == "relationship"
            and o.get("relationship_type") == "revoked-by"
            and o.get("source_ref") in by_stix_id
            and o.get("target_ref") in by_stix_id
        }
        replaced = {}
        for old in direct:
            new, hops = direct[old], 0
            while new in direct and hops < 10:
                new, hops = direct[new], hops + 1
            if old and new:
                replaced[old] = new
        return cls(version, hashlib.sha256(raw).hexdigest(), techniques, names, replaced)

    @classmethod
    def from_index(cls, path: Path = INDEX_FILE) -> Attack:
        doc = json.loads(path.read_text())
        techniques = {
            tid: Technique(tid, t["name"], tuple(t["tactics"]), bool(t.get("retired")))
            for tid, t in doc["techniques"].items()
        }
        return cls(
            doc["version"], doc["sha256"], techniques, doc["tactics"], doc.get("replaced_by", {})
        )

    def to_index(self) -> dict:
        return {
            "version": self.version,
            "sha256": self.sha256,
            "source": "mitre-attack/attack-stix-data enterprise-attack",
            "tactics": dict(sorted(self.tactics.items())),
            "replaced_by": dict(sorted(self.replaced_by.items())),
            "techniques": {
                tid: {
                    "name": t.name,
                    "tactics": list(t.tactics),
                    **({"retired": True} if t.retired else {}),
                }
                for tid, t in sorted(self.techniques.items())
            },
        }

    def problems(self, technique: str | None, tactic: str | None, where: str) -> list[str]:
        """What is wrong with one (technique, tactic) label under this version."""
        if not technique and not tactic:
            return []
        t = self.techniques.get(technique or "")
        if t is None:
            return [f"{where}: {technique} is not a technique in ATT&CK v{self.version}"]
        out = []
        if t.retired:
            out.append(f"{where}: {technique} is deprecated or revoked in v{self.version}")
        if tactic and tactic not in t.tactics:
            out.append(
                f"{where}: {technique} is not under {tactic} in v{self.version} "
                f"(it is under {', '.join(t.tactics) or 'no tactic'})"
            )
        return out

    def text(self, technique: str, limit: int = 600) -> str:
        """A technique's name and the start of its description, for a retrieval index."""
        t = self.techniques[technique]
        first = t.description.split("\n\n", 1)[0].strip()
        return f"{t.name}. {first}"[:limit]


def _external_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def check_catalogue(attack: Attack) -> list[str]:
    """Every technique and tactic the catalogue and the rules name, against the pinned version."""
    import yaml

    from mirage_lab.models import Catalogue

    catalogue = Catalogue.load(ROOT / "lab" / "catalogue")
    problems = []
    if catalogue.attack_version != attack.version:
        problems.append(
            f"catalogue is labelled against v{catalogue.attack_version}, "
            f"the index is v{attack.version}"
        )
    for pid, proc in sorted(catalogue.procedures.items()):
        problems += attack.problems(proc.technique, proc.tactic, f"procedure {pid}")
    for path in sorted((ROOT / "intel" / "rules").glob("*.yaml")):
        doc = yaml.safe_load(path.read_text()) or {}
        for rule in [*doc.get("rules", []), *doc.get("session_rules", [])]:
            problems += attack.problems(
                rule.get("technique"), rule.get("tactic"), f"rule {rule.get('id')}"
            )
    return problems


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage_intel.attack")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_index = sub.add_parser("index", help="derive eval/attack-index.json from the STIX bundle")
    p_index.add_argument("bundle", type=Path)
    sub.add_parser("check", help="validate the catalogue and the rules against the index")
    args = ap.parse_args(argv)
    if args.cmd == "index":
        attack = Attack.from_stix(args.bundle)
        if attack.version != VERSION:
            sys.exit(
                f"this bundle is ATT&CK v{attack.version}; the project is pinned to v{VERSION}"
            )
        INDEX_FILE.write_text(json.dumps(attack.to_index(), indent=1) + "\n")
        print(f"wrote {INDEX_FILE.relative_to(ROOT)}: {len(attack.techniques)} techniques")
        return
    problems = check_catalogue(Attack.from_index())
    for p in problems:
        print("PROBLEM", p)
    print(f"{len(problems)} problem(s)")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
