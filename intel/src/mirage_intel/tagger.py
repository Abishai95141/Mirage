"""Tagger v0 (phase 2 spec, 2.4): label inputs and sessions with ATT&CK techniques, and score
the labelling against the lab ground truth.

Layer 1 is the rule engine (``techniques.py``). Layers 2 and 3 -- retrieval over ATT&CK and
LogPrecis for SSH tactics -- need model downloads and are added when those are approved; the
engine abstains cleanly where no rule fires, so the pipeline runs without them.

Scoring reads the per-command dataset (``steps.parquet``), compares the rule tagger's technique
against the ground-truth technique, and reports micro/macro F1 and the abstention rate, by
source. It reads command text only inside this process and prints only numbers, never a
command.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq

from mirage_intel.techniques import Engine

ROOT = Path(__file__).resolve().parents[3]
RULES_DIR = ROOT / "intel" / "rules"


@dataclass
class Scored:
    n: int
    predicted: int  # inputs where a rule fired (did not abstain)
    correct: int  # fired and matched the ground-truth technique
    micro_f1: float = 0.0
    macro_f1: float = 0.0
    abstention: float = 0.0
    by_source: dict[str, dict[str, float]] = field(default_factory=dict)


def _f1(tp: int, fp: int, fn: int) -> float:
    if tp == 0:
        return 0.0
    prec, rec = tp / (tp + fp), tp / (tp + fn)
    return 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0


def score(engine: Engine, steps: list[dict[str, Any]]) -> Scored:
    """steps: rows with protocol, input (text), technique_id (ground truth, '' = none), source."""
    n = len(steps)
    fired = 0
    # micro over techniques; macro averages per-technique F1
    per_tech: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    source_tot: dict[str, dict[str, int]] = defaultdict(lambda: {"n": 0, "fired": 0, "correct": 0})
    for s in steps:
        truth = s.get("technique_id") or ""
        hit = engine.best(s["protocol"], s["input"])
        pred = hit.technique if hit else ""
        src = s.get("source", "?")
        source_tot[src]["n"] += 1
        if pred:
            fired += 1
            source_tot[src]["fired"] += 1
        if pred and pred == truth:
            per_tech[truth]["tp"] += 1
            source_tot[src]["correct"] += 1
        else:
            if pred:
                per_tech[pred]["fp"] += 1
            if truth:
                per_tech[truth]["fn"] += 1
    tp = sum(t["tp"] for t in per_tech.values())
    fp = sum(t["fp"] for t in per_tech.values())
    fn = sum(t["fn"] for t in per_tech.values())
    macro = (
        sum(_f1(t["tp"], t["fp"], t["fn"]) for t in per_tech.values()) / len(per_tech)
        if per_tech
        else 0.0
    )
    by_source = {
        src: {
            "n": t["n"],
            "abstention": round(1 - t["fired"] / t["n"], 3) if t["n"] else 0.0,
            "precision": round(t["correct"] / t["fired"], 3) if t["fired"] else 0.0,
        }
        for src, t in sorted(source_tot.items())
    }
    return Scored(
        n=n,
        predicted=fired,
        correct=tp,
        micro_f1=round(_f1(tp, fp, fn), 4),
        macro_f1=round(macro, 4),
        abstention=round(1 - fired / n, 4) if n else 0.0,
        by_source=by_source,
    )


def load_steps(path: Path) -> list[dict[str, Any]]:
    return pq.read_table(path).to_pylist()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage-tagger")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("lint", help="compile the rules and report how many loaded")
    sc = sub.add_parser("score", help="score the rule tagger on the per-command dataset")
    sc.add_argument("--data", type=Path, default=ROOT / "build" / "dataset" / "steps.parquet")
    sc.add_argument("--split", default="test")
    args = ap.parse_args(argv)
    engine = Engine.load(RULES_DIR)
    if args.cmd == "lint":
        print(json.dumps({"rules": len(engine.rules), "session_rules": len(engine.session_rules)}))
        return
    steps = [s for s in load_steps(args.data) if s.get("split") == args.split]
    result = score(engine, steps)
    print(json.dumps(result.__dict__, indent=2, default=lambda o: o.__dict__))


if __name__ == "__main__":
    main()
