"""Evaluation harness (phase 2 spec, 2.6): score the models on the held-out split, write the
baselines, and fail CI when a metric regresses.

It ties the pieces together -- the split integrity check, the actor classifier, the technique
tagger -- against one dataset, records the result as a baseline keyed by the dataset's hash,
and compares a fresh run to the committed baseline. A model is never judged by an absolute
threshold (a guess before any data exists); the gate asks only that a metric not fall below
its committed baseline by more than a tolerance, and that the classifier beat rules-only and
the tagger beat the most-frequent-technique baseline (spec Gate 2 tests 6, 7, 10).

MLflow tracking (spec 2.6) is additive and not required for the gate; the baselines are plain
JSON so the regression check needs nothing but the repository.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mirage_intel import classifier, tagger
from mirage_intel.techniques import Engine

ROOT = Path(__file__).resolve().parents[3]
DATASET_DIR = ROOT / "build" / "dataset"
RULES_DIR = ROOT / "intel" / "rules"
BASELINE_DIR = ROOT / "eval" / "baselines"
# How far a metric may fall below its committed baseline before CI fails.
TOLERANCE = 0.05


@dataclass
class Metrics:
    dataset_sha256: str
    n_sessions: int
    n_steps: int
    classifier: dict[str, Any] = field(default_factory=dict)
    tagger: dict[str, Any] = field(default_factory=dict)
    gates: dict[str, bool] = field(default_factory=dict)

    # Metrics the regression check tracks (name -> path into this object).
    TRACKED = ("classifier.macro_f1", "tagger.micro_f1")

    def get(self, dotted: str) -> float:
        obj: Any = self
        for part in dotted.split("."):
            obj = obj[part] if isinstance(obj, dict) else getattr(obj, part)
        return float(obj)


def evaluate(sessions: list[dict], steps: list[dict], engine: Engine, dataset_sha: str) -> Metrics:
    m = Metrics(dataset_sha256=dataset_sha, n_sessions=len(sessions), n_steps=len(steps))

    train_rows = [r for r in sessions if r["split"] == "train" and not r["real"]]
    test_rows = [r for r in sessions if r["split"] == "test"]
    if train_rows and test_rows:
        model = classifier.train(train_rows)
        report = classifier.evaluate(model, test_rows)
        m.classifier = asdict(report)
        m.gates["classifier_beats_rules"] = report.beats_rules()
        m.gates["classifier_beats_majority"] = report.macro_f1 > report.majority_f1

    test_steps = [s for s in steps if s["split"] == "test"]
    if test_steps:
        scored = tagger.score(engine, test_steps)
        m.tagger = asdict(scored)
        m.gates["tagger_beats_most_frequent"] = scored.micro_f1 > _most_frequent_f1(test_steps)
    return m


def _most_frequent_f1(steps: list[dict]) -> float:
    """The baseline that always predicts the most common technique: its micro-F1."""
    truths = [s["technique_id"] for s in steps if s["technique_id"]]
    if not truths:
        return 0.0
    _top, n_top = Counter(truths).most_common(1)[0]
    tp, fp, fn = n_top, len(steps) - n_top, len(truths) - n_top
    return tagger._f1(tp, fp, fn)


def regress(current: Metrics, baseline: dict, tolerance: float = TOLERANCE) -> list[str]:
    """Reasons CI should fail: a tracked metric fell too far, or a gate flipped to false."""
    problems = []
    if baseline.get("dataset_sha256") != current.dataset_sha256:
        problems.append("the committed baseline is for a different dataset; rebuild it")
    for name in Metrics.TRACKED:
        was = _dig(baseline, name)
        if was is None:
            continue  # the baseline never tracked this metric
        try:
            now = current.get(name)
        except (KeyError, AttributeError, TypeError):
            # The baseline had this metric but this run did not produce it -- the section did
            # not run (e.g. no test rows). That is a regression, not a silent pass.
            problems.append(f"{name} is missing from this run but the baseline has {was:.3f}")
            continue
        if now < was - tolerance:
            problems.append(f"{name} fell from {was:.3f} to {now:.3f} (> {tolerance} drop)")
    # Every gate the baseline asserted true must still be present and true.
    for gate, ok in (baseline.get("gates") or {}).items():
        if ok and not current.gates.get(gate):
            problems.append(f"gate {gate} was met in the baseline but is not now")
    for gate, ok in current.gates.items():
        if not ok:
            problems.append(f"gate {gate} is not met")
    # A run that evaluated nothing must not pass as clean.
    if not current.gates:
        problems.append("no gates were evaluated (empty train/test split?)")
    return problems


def _dig(obj: dict, dotted: str):
    for part in dotted.split("."):
        if not isinstance(obj, dict) or part not in obj:
            return None
        obj = obj[part]
    return obj


def load_dataset(directory: Path) -> tuple[list[dict], list[dict], str]:
    import pyarrow.parquet as pq

    sessions_path = directory / "sessions.parquet"
    manifest = json.loads((directory / "sessions.manifest.json").read_text())
    sessions = pq.read_table(sessions_path).to_pylist()
    steps_path = directory / "steps.parquet"
    steps = pq.read_table(steps_path).to_pylist() if steps_path.exists() else []
    return sessions, steps, manifest.get("rows_sha256", "")


def baseline_path(dataset_dir: Path) -> Path:
    return BASELINE_DIR / f"{dataset_dir.name}.json"


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage-eval")
    ap.add_argument("cmd", choices=["run", "check"])
    ap.add_argument("--data", type=Path, default=DATASET_DIR)
    args = ap.parse_args(argv)
    sessions, steps, dataset_sha = load_dataset(args.data)
    engine = Engine.load(RULES_DIR)
    metrics = evaluate(sessions, steps, engine, dataset_sha)
    path = baseline_path(args.data)
    if args.cmd == "run":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(metrics), indent=2) + "\n")
        print(f"wrote {path.relative_to(ROOT)}")
        print(
            json.dumps(
                {
                    "gates": metrics.gates,
                    "tracked": {
                        k: round(metrics.get(k), 4) for k in Metrics.TRACKED if _has(metrics, k)
                    },
                },
                indent=2,
            )
        )
        return
    if not path.exists():
        raise SystemExit(f"no committed baseline at {path.relative_to(ROOT)}; run `eval run` first")
    problems = regress(metrics, json.loads(path.read_text()))
    for p in problems:
        print("REGRESSION", p)
    print("ok" if not problems else f"{len(problems)} problem(s)")
    raise SystemExit(1 if problems else 0)


def _has(metrics: Metrics, dotted: str) -> bool:
    try:
        metrics.get(dotted)
        return True
    except (KeyError, AttributeError):
        return False


if __name__ == "__main__":
    main()
