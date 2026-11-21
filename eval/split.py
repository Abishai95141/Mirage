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

Phase 3's depth scenarios (phase 3 spec, 3.0 and section 5) are a second, independent split,
``eval/split-depth.yaml``. The phase 2 file is frozen on its set of procedure IDs, so a new
procedure cannot join it; depth procedures live in catalogue files of their own and are dealt
into a dev half and a test half here, by the same component rule. That file is
``provisional`` until every scenario's checks have been confirmed on the reference host, and
``frozen`` after: a provisional split may be rebuilt, a frozen one only with ``--force``.

Demo 3's procedures (phase 3 spec, 3.8) are a third set and are in **no** split: they were
written after both splits were frozen, and their steps are neither training nor evaluation
data. ``check`` reports them: one that a split file names is a problem, and one that is
near-identical to a held-out procedure is listed for a person to look at.
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

from mirage_lab.models import DEMO, DEPTH, PHASE2, Catalogue, Scenario

ROOT = Path(__file__).resolve().parents[1]
SPLIT_FILE = ROOT / "eval" / "split.yaml"
DEPTH_SPLIT_FILE = ROOT / "eval" / "split-depth.yaml"
SPLITS = ("train", "dev", "test")
HALVES = ("dev", "test")  # the depth split has no training part: nothing is fitted on it
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
    status: str | None = None  # the depth split only: provisional or frozen

    def write(self, path: Path = SPLIT_FILE, names: tuple[str, ...] = SPLITS) -> None:
        by_split: dict[str, list[str]] = {s: [] for s in names}
        for pid, split in sorted(self.of_procedure.items()):
            by_split[split].append(pid)
        made_by = "depth-build" if self.status else "build"
        doc: dict = {
            "# ": f"Written by `python -m eval.split {made_by}`. Edit via that, not by hand.",
        }
        if self.status:
            doc["status"] = self.status
        doc |= {
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
            of_proc,
            doc.get("scenarios", {}),
            doc["catalogue_sha256"],
            doc.get("manifest", {}),
            doc.get("status"),
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


def load_sets(root: Path = ROOT) -> dict[str, tuple[Catalogue, list[Scenario]]]:
    """Each catalogue set with the scenarios written from it. A scenario that mixes sets
    belongs to neither and is the lint's to report."""
    full = Catalogue.load(root / "lab" / "catalogue")
    scenarios = [Scenario.load(p) for p in sorted((root / "lab" / "scenarios").rglob("*.yaml"))]
    return {
        which: (full.only(which), [sc for sc in scenarios if full.set_of_scenario(sc) == which])
        for which in full.set_sha256
    }


def _load() -> tuple[Catalogue, list[Scenario]]:
    """What the phase 2 split is made from and checked against: the phase 2 set alone."""
    return load_sets()[PHASE2]


# ---------------------------------------------------------------- the depth split


def depth_build(catalogue: Catalogue, scenarios: list[Scenario]) -> Split:
    """Deal the depth scenarios into a dev half and a test half.

    The unit is the component, as in ``build``: scenarios that share a procedure, or use
    near-identical ones, stay together. Every way of dealing the components into two halves
    is tried, and the one kept has the most even scenario counts, then the most tactics
    present in both halves, then the most techniques present in both. What is still tied is
    settled by a hash of the IDs, so the result does not depend on file order."""
    components, scen_procs = _components(catalogue, scenarios)
    procs = catalogue.procedures
    if len(components) > 20:
        raise ValueError(f"{len(components)} components: too many to deal exhaustively")
    comp_of = {pid: i for i, comp in enumerate(components) for pid in comp}
    n_scen = [0] * len(components)
    for ps in scen_procs.values():
        if ps:
            n_scen[comp_of[next(iter(ps))]] += 1
    tactics = [{procs[p].tactic for p in c if procs[p].tactic} for c in components]
    techniques = [{procs[p].technique for p in c if procs[p].technique} for c in components]

    def both(sets: list[set[str]], test: list[int], dev: list[int]) -> int:
        return len(set().union(*(sets[i] for i in test)) & set().union(*(sets[i] for i in dev)))

    best: tuple | None = None
    for mask in range(1, 2 ** len(components) - 1):
        test = [i for i in range(len(components)) if mask >> i & 1]
        dev = [i for i in range(len(components)) if not mask >> i & 1]
        key = (
            -abs(sum(n_scen[i] for i in test) - sum(n_scen[i] for i in dev)),
            both(tactics, test, dev),
            both(techniques, test, dev),
            _rank("|".join(sorted(p for i in test for p in components[i]))),
        )
        if best is None or key > best[0]:
            best = (key, test)
    if best is None:
        raise ValueError("the depth scenarios form one component: they cannot be divided")
    in_test = set(best[1])
    of_proc = {
        pid: "test" if i in in_test else "dev" for i, comp in enumerate(components) for pid in comp
    }
    of_scenario = {sc_id: of_proc[next(iter(ps))] for sc_id, ps in scen_procs.items() if ps}

    def held(sets: list[set[str]], half: str) -> set[str]:
        want = in_test if half == "test" else set(range(len(components))) - in_test
        return set().union(*(sets[i] for i in want))

    manifest = {
        "procedures": len(of_proc),
        "components": len(components),
        "by_half": {h: sum(1 for v in of_proc.values() if v == h) for h in HALVES},
        "scenarios_by_half": {h: sum(1 for v in of_scenario.values() if v == h) for h in HALVES},
        "tactics_by_half": {h: len(held(tactics, h)) for h in HALVES},
        "tactics_in_both": len(held(tactics, "dev") & held(tactics, "test")),
        "techniques_in_both": len(held(techniques, "dev") & held(techniques, "test")),
    }
    return Split(of_proc, of_scenario, catalogue.sha256, manifest, status="provisional")


def depth_check(
    split: Split,
    catalogue: Catalogue,
    scenarios: list[Scenario],
    phase2: Catalogue | None = None,
    phase2_split: Split | None = None,
) -> CheckResult:
    """The depth split against the depth catalogue and scenarios. ``similar_pairs`` lists
    depth procedures of the test half that are near-identical to a phase 2 training or dev
    procedure, by ID and score only. Those are reported, not refused: an ordinary command
    belongs in both, and what must not happen (an answer prepared from a test scenario) is
    guarded where the answers are made, by their inventory source (phase 3 spec, section 5)."""
    r = CheckResult()
    procs = catalogue.procedures
    if split.status not in ("provisional", "frozen"):
        r.problems.append(f"the depth split's status is {split.status!r}")
    if split.catalogue_sha256 != catalogue.sha256:
        r.problems.append(
            "the depth split was made against a different depth catalogue; "
            + ("rebuild it (depth-build)" if split.status != "frozen" else "it is frozen")
        )
    for pid in procs:
        if split.of_procedure.get(pid) not in HALVES:
            r.problems.append(f"depth procedure {pid} is in no half")
    for pid in sorted(set(split.of_procedure) - set(procs)):
        r.problems.append(f"the depth split names {pid}, which the depth catalogue lacks")
    _, scen_procs = _components(catalogue, scenarios)
    for sc_id, ps in sorted(scen_procs.items()):
        halves = {split.of_procedure.get(p) for p in ps}
        if len(halves) > 1:
            r.problems.append(f"depth scenario {sc_id} mixes halves {sorted(map(str, halves))}")
        elif split.of_scenario.get(sc_id) not in halves:
            r.problems.append(f"depth scenario {sc_id} is not filed under its procedures' half")
    for h in HALVES:
        if not any(v == h for v in split.of_procedure.values()):
            r.problems.append(f"the {h} half is empty")
    toks = {pid: tokens(normalise(p.template)) for pid, p in procs.items() if p.template}
    ids = sorted(pid for pid in toks if pid in split.of_procedure)
    across = 0
    for i, a in enumerate(ids):
        for b in ids[i + 1 :]:
            differ = split.of_procedure[a] != split.of_procedure[b]
            if differ and jaccard(toks[a], toks[b]) >= SIM_THRESHOLD:
                across += 1
    if across:
        r.problems.append(f"{across} near-identical depth command(s) span the two halves")
    if phase2 is not None and phase2_split is not None:
        other = {
            pid: tokens(normalise(p.template)) for pid, p in phase2.procedures.items() if p.template
        }
        for a in ids:
            if split.of_procedure[a] != "test":
                continue
            for b, tb in sorted(other.items()):
                where = phase2_split.of_procedure.get(b)
                if where in ("train", "dev"):
                    score = jaccard(toks[a], tb)
                    if score >= SIM_THRESHOLD:
                        r.similar_pairs.append((a, "depth test", b, where, round(score, 3)))
    techs = {
        h: {procs[p].technique for p, v in split.of_procedure.items() if v == h and p in procs}
        for h in HALVES
    }
    r.coverage = len((techs["dev"] & techs["test"]) - {None})
    r.techniques_total = len((techs["dev"] | techs["test"]) - {None})
    return r


def demo_check(demo: Catalogue, others: list[tuple[str, Catalogue, Split]]) -> CheckResult:
    """Demo 3's procedures against the splits they are kept out of (``others``: a name, that
    set's catalogue and its split). A demo procedure that a split names is a problem.
    ``similar_pairs`` lists the demo procedures that are identical or near-identical to a
    held-out procedure, by ID and score only. Those are reported, not refused, as in
    ``depth_check``: an ordinary command belongs anywhere. A person reads the list, because
    the demo is what the responder's first recordings are made for, and a recording made for
    a command of the test half would be an answer prepared from the test."""
    r = CheckResult()
    toks = {pid: tokens(normalise(p.template)) for pid, p in demo.procedures.items() if p.template}
    for name, catalogue, split in others:
        for pid in sorted(set(demo.procedures) & set(split.of_procedure)):
            r.problems.append(f"demo procedure {pid} is in the {name} split; the demo set has none")
        for b, proc in sorted(catalogue.procedures.items()):
            if not proc.template or split.of_procedure.get(b) != "test":
                continue
            held = tokens(normalise(proc.template))
            for a in sorted(toks):
                score = jaccard(toks[a], held)
                if score >= SIM_THRESHOLD:
                    r.similar_pairs.append((a, "demo", b, f"{name} test", round(score, 3)))
    return r


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
    sub.add_parser("check", help="verify both splits (IDs and scores only)")
    p_depth = sub.add_parser(
        "depth-build", help="deal the depth scenarios into halves (eval/split-depth.yaml)"
    )
    p_depth.add_argument("--force", action="store_true", help="replace a frozen depth split")
    sub.add_parser("depth-freeze", help="mark the depth split frozen, once checked on the host")
    args = ap.parse_args(argv)
    if args.cmd in ("depth-build", "depth-freeze"):
        sys.exit(_depth_command(args))
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
    depth_ok = _depth_report(split)
    demo_ok = _demo_report(split)
    sys.exit(0 if result.ok and depth_ok and demo_ok else 1)


def _depth_report(phase2_split: Split) -> bool:
    """Check the depth split, if the catalogue has depth procedures. True when it is sound."""
    sets = load_sets()
    if DEPTH not in sets:
        return True
    cat, scn = sets[DEPTH]
    if not DEPTH_SPLIT_FILE.exists():
        print(f"PROBLEM {len(cat.procedures)} depth procedures and no depth split: depth-build")
        return False
    split = Split.load(DEPTH_SPLIT_FILE)
    result = depth_check(split, cat, scn, sets[PHASE2][0], phase2_split)
    print(
        f"depth ({split.status})",
        {h: sum(1 for v in split.of_procedure.values() if v == h) for h in HALVES},
        "scenarios",
        {h: sum(1 for v in split.of_scenario.values() if v == h) for h in HALVES},
    )
    print("depth techniques in both halves", result.coverage, "of", result.techniques_total)
    for p in result.problems:
        print("PROBLEM", p)
    if result.similar_pairs:
        print(
            f"  {len(result.similar_pairs)} depth test procedure(s) are near-identical to a "
            "phase 2 train or dev procedure (reported, not refused):"
        )
    for a, _sa, b, sb, score in result.similar_pairs[:20]:
        print(f"    {a} ~ {b} ({sb})  {score}")
    return result.ok


def _demo_report(phase2_split: Split) -> bool:
    """Check demo 3's procedures, if the catalogue has any. True when no split names one."""
    sets = load_sets()
    if DEMO not in sets:
        return True
    cat, scn = sets[DEMO]
    others = [("phase 2", sets[PHASE2][0], phase2_split)]
    if DEPTH in sets and DEPTH_SPLIT_FILE.exists():
        others.append(("depth", sets[DEPTH][0], Split.load(DEPTH_SPLIT_FILE)))
    result = demo_check(cat, others)
    print(f"demo: {len(cat.procedures)} procedure(s) in no split, {len(scn)} scenario(s)")
    for p in result.problems:
        print("PROBLEM", p)
    if result.similar_pairs:
        print(
            f"  {len(result.similar_pairs)} demo procedure(s) are near-identical to a held-out "
            "procedure (reported, not refused; read each pair):"
        )
    for a, _sa, b, sb, score in result.similar_pairs[:20]:
        print(f"    {a} ~ {b} ({sb})  {score}")
    return result.ok


def _depth_command(args: argparse.Namespace) -> int:
    sets = load_sets()
    if DEPTH not in sets:
        print("the catalogue has no depth procedures")
        return 1
    cat, scn = sets[DEPTH]
    existing = Split.load(DEPTH_SPLIT_FILE) if DEPTH_SPLIT_FILE.exists() else None
    if args.cmd == "depth-freeze":
        if existing is None:
            print("there is no depth split to freeze: depth-build")
            return 1
        problems = depth_check(existing, cat, scn).problems
        for p in problems:
            print("PROBLEM", p)
        if problems:
            return 1
        existing.status = "frozen"
        existing.write(DEPTH_SPLIT_FILE, HALVES)
        print(f"froze {DEPTH_SPLIT_FILE.relative_to(ROOT)}")
        return 0
    if existing is not None and existing.status == "frozen" and not args.force:
        print(f"{DEPTH_SPLIT_FILE.relative_to(ROOT)} is frozen; --force replaces it")
        return 1
    split = depth_build(cat, scn)
    problems = depth_check(split, cat, scn).problems
    for p in problems:
        print("PROBLEM", p)
    if problems:
        return 1
    split.write(DEPTH_SPLIT_FILE, HALVES)
    print(f"wrote {DEPTH_SPLIT_FILE.relative_to(ROOT)} (provisional)")
    print(" ", split.manifest)
    return 0


if __name__ == "__main__":
    main()
