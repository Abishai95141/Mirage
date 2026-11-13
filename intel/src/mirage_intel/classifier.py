"""Actor classifier v0 (phase 2 spec, 2.3): rules plus LightGBM over structural features.

Classes: ``scanner`` (no authenticated activity), ``scripted_bot`` (automated activity after
access), ``human`` (interactive). ``llm_agent`` stays in the label space but is not trained or
scored until phase 4 provides lab agents.

A rule handles the obvious case with no model: a session with no successful login and no input
is a scanner. LightGBM decides the rest, over the feature allowlist in ``dataset.FEATURES`` --
timings, counts and outcomes, never an address, an ID, a time or anything from ``sim_*``. The
report compares the rules-plus-model pipeline against two baselines (majority class, rules
only) on the held-out split; a threshold would be a guess before any data exists, so the gate
asks only that the model beat rules-only (spec Gate 2 test 6).
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import lightgbm as lgb
import numpy as np
import pyarrow.parquet as pq
from sklearn.metrics import confusion_matrix, f1_score

from mirage_intel.dataset import FEATURES, FORBIDDEN

ROOT = Path(__file__).resolve().parents[3]
CLASSES = ["scanner", "scripted_bot", "human"]  # llm_agent: phase 4


def rule_label(row: dict[str, Any]) -> str | None:
    """The one case decided without a model: no access and no activity is a scanner."""
    if int(row["auth_success"]) == 0 and int(row["inputs"]) == 0:
        return "scanner"
    return None


def load_rows(path: Path) -> list[dict[str, Any]]:
    return pq.read_table(path).to_pylist()


def _matrix(rows: list[dict[str, Any]]) -> np.ndarray:
    return np.array([[float(r[f]) for f in FEATURES] for r in rows], dtype=np.float64)


@dataclass
class Model:
    booster: lgb.Booster | None
    classes: list[str]
    majority: str = "scanner"  # the most frequent training class, for the majority baseline

    def predict(self, rows: list[dict[str, Any]]) -> list[str]:
        out: list[str | None] = [rule_label(r) for r in rows]
        unresolved = [i for i, label in enumerate(out) if label is None]
        if unresolved and self.booster is not None:
            probs = self.booster.predict(_matrix([rows[i] for i in unresolved]))
            probs = np.atleast_2d(probs)
            for i, p in zip(unresolved, probs, strict=True):
                out[i] = self.classes[int(np.argmax(p))]
        return [label or self.majority for label in out]


def train(rows: list[dict[str, Any]]) -> Model:
    """Train on the rows a rule does not already settle."""
    learn = [r for r in rows if rule_label(r) is None]
    classes = sorted({r["actor_class"] for r in learn}) or CLASSES
    majority = Counter(r["actor_class"] for r in rows).most_common(1)
    majority_class = majority[0][0] if majority else classes[0]
    if len(classes) < 2:
        return Model(None, classes or CLASSES, majority_class)
    index = {c: i for i, c in enumerate(classes)}
    x = _matrix(learn)
    y = np.array([index[r["actor_class"]] for r in learn])
    params = {
        "objective": "multiclass",
        "num_class": len(classes),
        "num_leaves": 15,
        "min_data_in_leaf": 3,
        "learning_rate": 0.1,
        "verbose": -1,
        "deterministic": True,
        "force_row_wise": True,
        "seed": 0,
    }
    booster = lgb.train(params, lgb.Dataset(x, label=y), num_boost_round=60)
    return Model(booster, classes, majority_class)


@dataclass
class Report:
    n_test: int
    macro_f1: float
    rules_only_f1: float
    majority_f1: float
    per_class_f1: dict[str, float]
    confusion: list[list[int]]
    labels: list[str] = field(default_factory=list)

    def beats_rules(self) -> bool:
        return self.macro_f1 > self.rules_only_f1


def evaluate(model: Model, test: list[dict[str, Any]]) -> Report:
    labels = sorted({r["actor_class"] for r in test} | set(model.classes))
    truth = [r["actor_class"] for r in test]
    pred = model.predict(test)
    rules_only = [rule_label(r) or _majority(model) for r in test]
    majority = [_majority(model)] * len(test)

    def macro(p: list[str]) -> float:
        return float(f1_score(truth, p, labels=labels, average="macro", zero_division=0))

    per_class = f1_score(truth, pred, labels=labels, average=None, zero_division=0)
    return Report(
        n_test=len(test),
        macro_f1=macro(pred),
        rules_only_f1=macro(rules_only),
        majority_f1=macro(majority),
        per_class_f1={lab: round(float(v), 3) for lab, v in zip(labels, per_class, strict=True)},
        confusion=confusion_matrix(truth, pred, labels=labels).tolist(),
        labels=labels,
    )


def _majority(model: Model) -> str:
    return model.majority


def check_no_forbidden_features() -> None:
    """A guard the tests call: no feature column is an identity, address, time or ground truth."""
    leaked = sorted(set(FEATURES) & FORBIDDEN)
    if leaked:
        raise AssertionError(f"forbidden columns used as features: {leaked}")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage-classifier")
    ap.add_argument("--data", type=Path, default=ROOT / "build" / "dataset" / "sessions.parquet")
    ap.add_argument("--out", type=Path, default=ROOT / "build" / "models")
    args = ap.parse_args(argv)
    check_no_forbidden_features()
    rows = load_rows(args.data)
    train_rows = [r for r in rows if r["split"] == "train" and not r["real"]]
    test_rows = [r for r in rows if r["split"] == "test"]
    model = train(train_rows)
    report = evaluate(model, test_rows) if test_rows else None
    args.out.mkdir(parents=True, exist_ok=True)
    if model.booster is not None:
        model.booster.save_model(str(args.out / "actor_classifier.txt"))
    result = {
        "classes": model.classes,
        "n_train": len(train_rows),
        "report": None if report is None else report.__dict__,
    }
    (args.out / "actor_classifier.metrics.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
