"""Freeze the train/dev/test split (phase 2 spec, section 5).

Two rules pull against each other: the split is **by procedure** (a model must not meet a
command template in both training and test), and **no scenario mixes splits** (a session's
steps are all one split, because the classifier is per session). Scenarios that share a
procedure are therefore tied together: this module builds the bipartite graph of scenarios and
the procedures they use, takes its connected components, and assigns whole components to
train, dev or test (about 60/20/20), stratified so that as many techniques as possible appear
in both training and test. A procedure used by no scenario is assigned by its technique.

The content check (section 5, check 3) guards the other leak: two differently named procedures
that are the same command landing on opposite sides of the split. It normalises each template
and reports any cross-split pair that is identical or near-identical -- **by procedure ID and
score only; it never prints a template**, because the templates are the offensive command
content.

``eval/split.yaml`` is the frozen result. It is written once and then read by everything
downstream; rebuilding it is deliberate and rare, because a model's scores only compare across
runs that share a split.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from mirage_lab.models import Catalogue, Scenario

ROOT = Path(__file__).resolve().parents[1]
SPLIT_FILE = ROOT / "eval" / "split.yaml"
SPLITS = ("train", "dev", "test")
RATIO = {"train": 0.60, "dev": 0.20, "test": 0.20}
SIM_THRESHOLD = 0.9

# Normalisation for the content check: slot references and the literals a slot could hold
# become one placeholder, so two templates are compared by their command skeleton.
SLOT_RE = re.compile(r"\{\{[a-z]+\d*\}\}")
HEX_RE = re.compile(r"\b[0-9a-f]{6,}\b")
NUM_RE = re.compile(r"\b\d+\b")
WS_RE = re.compile(r"\s+")
TOKEN_RE = re.compile(r"[a-z0-9_]+|[^\sa-z0-9_]")


def normalise(template: str) -> str:
    t = SLOT_RE.sub("\0", template.lower())
    t = HEX_RE.sub("\0", t)
    t = NUM_RE.sub("\0", t)
    return WS_RE.sub(" ", t).strip()


def tokens(normalised: str) -> frozenset[str]:
    return frozenset(TOKEN_RE.findall(normalised))


def jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


@dataclass
class Split:
    of_procedure: dict[str, str]
    of_scenario: dict[str, str]
    catalogue_sha256: str
    manifest: dict = field(default_factory=dict)

    def write(self, path: Path = SPLIT_FILE) -> None:
        by_split: dict[str, list[str]] = {s: [] for s in SPLITS}
        for pid, split in sorted(self.of_procedure.items()):
            by_split[split].append(pid)
        doc = {
            "# ": "Frozen by `python -m eval.split build`. Edit via that, not by hand.",
            "catalogue_sha256": self.catalogue_sha256,
            "manifest": self.manifest,
            "procedures": by_split,
            "scenarios": dict(sorted(self.of_scenario.items())),
        }
        path.write_text(yaml.safe_dump(doc, sort_keys=False, width=100))

    @classmethod
    def load(cls, path: Path = SPLIT_FILE) -> Split:
        doc = yaml.safe_load(path.read_text())
        of_proc = {pid: s for s, ids in doc["procedures"].items() for pid in ids}
        return cls(
            of_proc, doc.get("scenarios", {}), doc["catalogue_sha256"], doc.get("manifest", {})
        )


def _components(
    catalogue: Catalogue, scenarios: list[Scenario]
) -> tuple[list[set[str]], dict[str, set[str]]]:
    """Connected components of the scenario/procedure graph, and each scenario's procedures."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        parent[find(a)] = find(b)

    scen_procs: dict[str, set[str]] = {}
    for sc in scenarios:
        procs: set[str] = set()
        for session in sc.sessions:
            if session.login.procedure:
                procs.add(session.login.procedure)
            procs.update(step.procedure for step in session.steps)
        scen_procs[sc.id] = procs
        node = f"scn:{sc.id}"
        for p in procs:
            union(node, f"prc:{p}")
    # procedures in no scenario are their own singletons
    for pid in catalogue.procedures:
        find(f"prc:{pid}")
    # Near-identical commands must share a split, so tie them into one component here; the
    # content check then verifies none slipped across (section 5, check 3).
    toks = {
        pid: tokens(normalise(p.template)) for pid, p in catalogue.procedures.items() if p.template
    }
    ids = sorted(toks)
    for i, a in enumerate(ids):
        for b in ids[i + 1 :]:
            if jaccard(toks[a], toks[b]) >= SIM_THRESHOLD:
                union(f"prc:{a}", f"prc:{b}")
    groups: dict[str, set[str]] = defaultdict(set)
    for node in list(parent):
        if node.startswith("prc:"):
            groups[find(node)].add(node[4:])
    return [g for g in groups.values() if g], scen_procs


def _rank(key: str) -> float:
    """A stable number in [0, 1) for deterministic assignment."""
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) / 0x100000000


def build(catalogue: Catalogue, scenarios: list[Scenario]) -> Split:
    components, scen_procs = _components(catalogue, scenarios)
    procs = catalogue.procedures

    def techniques(comp: set[str]) -> set[str]:
        return {procs[p].technique for p in comp if procs[p].technique}

    # Assign components largest first; within the running counts, send each to the split that
    # is furthest below its target share, so small components fill the gaps and every split
    # fills up. Ties and the overall order are broken by a stable hash, so the split is fixed.
    order = sorted(components, key=lambda c: (-len(c), _rank(min(c))))
    counts = dict.fromkeys(SPLITS, 0)
    total = sum(len(c) for c in components)
    of_proc: dict[str, str] = {}
    tech_in: dict[str, set[str]] = {s: set() for s in SPLITS}
    for comp in order:
        want = {s: RATIO[s] * total - counts[s] for s in SPLITS}
        # Prefer a split that still needs this component's techniques in train and test.
        comp_techs = techniques(comp)
        bonus = {}
        for s in SPLITS:
            missing = comp_techs - tech_in[s] if s in ("train", "test") else set()
            bonus[s] = len(missing) * 0.5
        choice = max(SPLITS, key=lambda s: want[s] + bonus[s] + _rank(f"{s}:{min(comp)}") * 0.01)
        for p in comp:
            of_proc[p] = choice
        counts[choice] += len(comp)
        tech_in[choice] |= comp_techs

    of_scenario = {sc_id: of_proc[next(iter(ps))] for sc_id, ps in scen_procs.items() if ps}
    all_techs = {p.technique for p in procs.values() if p.technique}
    covered = sorted(all_techs & tech_in["train"] & tech_in["test"])
    manifest = {
        "procedures": len(of_proc),
        "by_split": {s: sum(1 for v in of_proc.values() if v == s) for s in SPLITS},
        "scenarios_by_split": {s: sum(1 for v in of_scenario.values() if v == s) for s in SPLITS},
        "techniques_total": len(all_techs),
        "techniques_covered": len(covered),
    }
    return Split(of_proc, of_scenario, catalogue.sha256, manifest)


@dataclass
class CheckResult:
    problems: list[str] = field(default_factory=list)
    similar_pairs: list[tuple[str, str, str, str, float]] = field(default_factory=list)
    coverage: int = 0
    techniques_total: int = 0

    @property
    def ok(self) -> bool:
        return not self.problems


def check(split: Split, catalogue: Catalogue, scenarios: list[Scenario]) -> CheckResult:
    r = CheckResult()
    procs = catalogue.procedures
    if split.catalogue_sha256 != catalogue.sha256:
        r.problems.append("split was frozen against a different catalogue; rebuild it")
    # every procedure assigned, to a real split
    for pid in procs:
        s = split.of_procedure.get(pid)
        if s not in SPLITS:
            r.problems.append(f"procedure {pid} is not assigned to a split")
    # no scenario mixes splits (check 2)
    _, scen_procs = _components(catalogue, scenarios)
    for sc_id, ps in scen_procs.items():
        splits = {split.of_procedure.get(p) for p in ps if p in split.of_procedure}
        if len(splits) > 1:
            r.problems.append(f"scenario {sc_id} mixes splits {sorted(splits)}")
    for s in SPLITS:
        if not any(v == s for v in split.of_procedure.values()):
            r.problems.append(f"split {s} is empty")
    # content similarity across splits (check 3): IDs and scores only, never the template
    toks = {
        pid: tokens(normalise(p.template))
        for pid, p in procs.items()
        if p.template and p.id in split.of_procedure
    }
    items = sorted(toks)
    for i, a in enumerate(items):
        for b in items[i + 1 :]:
            sa, sb = split.of_procedure[a], split.of_procedure[b]
            if sa == sb:
                continue
            score = jaccard(toks[a], toks[b])
            if score >= SIM_THRESHOLD:
                r.similar_pairs.append((a, sa, b, sb, round(score, 3)))
    if r.similar_pairs:
        r.problems.append(
            f"{len(r.similar_pairs)} near-identical command(s) span the split; "
            "merge them into one procedure or move one so both sit in the same split"
        )
    all_techs = {p.technique for p in procs.values() if p.technique}
    tech_split: dict[str, set[str]] = {s: set() for s in SPLITS}
    for pid, p in procs.items():
        if p.technique:
            tech_split[split.of_procedure[pid]].add(p.technique)
    covered = all_techs & tech_split["train"] & tech_split["test"]
    r.coverage, r.techniques_total = len(covered), len(all_techs)
    return r


def _load() -> tuple[Catalogue, list[Scenario]]:
    cat = Catalogue.load(ROOT / "lab" / "catalogue")
    scn = [Scenario.load(p) for p in sorted((ROOT / "lab" / "scenarios").rglob("*.yaml"))]
    return cat, scn


def extend(
    split: Split, catalogue: Catalogue, scenarios: list[Scenario]
) -> tuple[Split, list[str]]:
    """Re-derive the scenario assignments from the frozen procedure assignments, leaving every
    procedure where it is. This is how a new scenario joins a frozen split: `build` would run
    the assignment again over a changed scenario graph and could move procedures between
    train and test. Returns the split and the problems that stop it being written."""
    _, scen_procs = _components(catalogue, scenarios)
    problems, of_scenario = [], {}
    for sc_id, procs in sorted(scen_procs.items()):
        unknown = sorted(p for p in procs if p not in split.of_procedure)
        if unknown:
            problems.append(f"scenario {sc_id} uses procedures with no split: {unknown}")
            continue
        splits = {split.of_procedure[p] for p in procs}
        if len(splits) > 1:
            problems.append(f"scenario {sc_id} mixes splits {sorted(splits)}")
        elif splits:
            of_scenario[sc_id] = splits.pop()
    # The catalogue may change under a frozen split in one way only: a procedure's label or
    # text is corrected. Its ID set must stay the same; a new or removed procedure would need
    # an assignment, and that is `build --force`, a new freeze. With the same IDs the split
    # is re-pinned to the catalogue as it is now, and the content check below still has to
    # pass on the corrected text.
    if set(catalogue.procedures) != set(split.of_procedure):
        added = sorted(set(catalogue.procedures) - set(split.of_procedure))
        gone = sorted(set(split.of_procedure) - set(catalogue.procedures))
        problems.append(f"the catalogue's procedures changed (added {added}, removed {gone})")
    techniques = {s: set() for s in SPLITS}
    for pid, where in split.of_procedure.items():
        proc = catalogue.procedures.get(pid)
        if proc is not None and proc.technique:
            techniques[where].add(proc.technique)
    every = set().union(*techniques.values())
    manifest = {
        **split.manifest,
        "scenarios_by_split": {s: sum(1 for v in of_scenario.values() if v == s) for s in SPLITS},
        "techniques_total": len(every),
        "techniques_covered": len(techniques["train"] & techniques["test"]),
    }
    extended = Split(split.of_procedure, of_scenario, catalogue.sha256, manifest)
    if not problems:
        problems += check(extended, catalogue, scenarios).problems
    return extended, problems


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="eval.split")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_build = sub.add_parser(
        "build", help="freeze eval/split.yaml from the catalogue and scenarios"
    )
    p_build.add_argument(
        "--force", action="store_true", help="replace a frozen split (moves procedures)"
    )
    sub.add_parser("extend", help="assign new scenarios without moving any procedure")
    sub.add_parser("check", help="verify the frozen split (IDs and scores only)")
    args = ap.parse_args(argv)
    cat, scn = _load()
    if args.cmd == "extend":
        split, problems = extend(Split.load(), cat, scn)
        for p in problems:
            print("PROBLEM", p)
        if problems:
            sys.exit(1)
        split.write()
        print(f"wrote {SPLIT_FILE.relative_to(ROOT)}")
        print(" ", split.manifest)
        return
    if args.cmd == "build":
        if SPLIT_FILE.exists() and not args.force:
            print(
                f"{SPLIT_FILE.relative_to(ROOT)} is frozen. `extend` adds scenarios without "
                "moving procedures; `build --force` re-runs the assignment and may move them."
            )
            sys.exit(1)
        split = build(cat, scn)
        result = check(split, cat, scn)
        if not result.ok:
            print("refusing to freeze a split with problems:")
            for p in result.problems:
                print(" ", p)
            for a, sa, b, sb, score in result.similar_pairs[:20]:
                print(f"    similar: {a} ({sa}) ~ {b} ({sb})  {score}")
            sys.exit(1)
        split.write()
        print(f"wrote {SPLIT_FILE.relative_to(ROOT)}")
        print(" ", split.manifest)
        return
    split = Split.load()
    result = check(split, cat, scn)
    print("by_split", {s: sum(1 for v in split.of_procedure.values() if v == s) for s in SPLITS})
    print("techniques covered (train & test)", result.coverage, "of", result.techniques_total)
    for p in result.problems:
        print("PROBLEM", p)
    for a, sa, b, sb, score in result.similar_pairs[:20]:
        print(f"  similar: {a} ({sa}) ~ {b} ({sb})  {score}")
    sys.exit(0 if result.ok else 1)


if __name__ == "__main__":
    main()
