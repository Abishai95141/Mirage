"""Actor classifier v0 (phase 2 spec, 2.3): rules plus LightGBM over structural features.

Classes: ``scanner`` (no authenticated activity), ``scripted_bot`` (automated activity after
access), ``human`` (interactive). ``llm_agent`` stays in the label space but is not trained or
scored until phase 4 provides lab agents.

A rule handles the obvious case with no model: a session with no successful login and no input
is a scanner. LightGBM decides the rest, over the feature allowlist in ``dataset.FEATURES`` --
timings, counts and outcomes, never an address, an ID, a time or anything from ``sim_*``. The
report compares the rules-plus-model pipeline against two baselines (majority class, rules
only); a threshold would be a guess before any data exists, so the gate asks only that the
model beat both by more than its interval (spec Gate 2 test 6).

It is scored by holding out whole scenarios in rotation (``cross_validate``), not on the frozen
procedure split. That split exists to stop the tagger memorising command text, which this model
never reads, and its test half turned out to hold a single actor class (first live run, 14
November 2026). A scenario and its timing variants are held out together.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
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


def label_of(row: dict[str, Any]) -> str:
    """The session-level class a row is scored against (``label``; older datasets have only
    the actor's class)."""
    return row.get("label") or row["actor_class"]


def group_of(row: dict[str, Any]) -> str:
    """What a row is held out with: its scenario, or the scenario that one is a variant of."""
    return row.get("group") or row["scenario_id"]


def assign_folds(rows: list[dict[str, Any]], k: int, seed: int = 0) -> dict[str, int]:
    """Group -> fold. Whole groups move together, and groups are dealt out class by class so
    every fold holds out some of each class where there are enough groups to go round."""
    by_group: dict[str, Counter] = {}
    for r in rows:
        by_group.setdefault(group_of(r), Counter())[label_of(r)] += 1
    # A group's class is its rarest label overall, so scarce classes are spread first.
    overall = Counter(label_of(r) for r in rows)
    rng = np.random.default_rng(seed)
    order = sorted(by_group)
    rng.shuffle(order)
    by_class: dict[str, list[str]] = {}
    for g in order:
        rarest = min(by_group[g], key=lambda c: (overall[c], c))
        by_class.setdefault(rarest, []).append(g)
    folds: dict[str, int] = {}
    cursor = 0
    for cls in sorted(by_class, key=lambda c: (overall[c], c)):
        for g in by_class[cls]:
            folds[g] = cursor % k
            cursor += 1
    return folds


@dataclass
class CVReport:
    """Every session predicted once, by a model that never saw its group."""

    n_test: int
    n_groups: int
    folds: int
    macro_f1: float
    rules_only_f1: float
    majority_f1: float
    per_class_f1: dict[str, float]
    confusion: list[list[int]]
    labels: list[str]
    support: dict[str, int]
    groups_per_class: dict[str, int]
    # 95% bootstrap intervals over groups, on the difference to each baseline.
    vs_rules_ci: list[float]
    vs_majority_ci: list[float]
    rule_settled: int = 0  # sessions the scanner rule decided, with no model involved
    model_only_macro_f1: float | None = None  # the model alone, on the sessions the rule left

    def beats_rules(self) -> bool:
        return self.vs_rules_ci[0] > 0

    def beats_majority(self) -> bool:
        return self.vs_majority_ci[0] > 0


def _macro(truth: list[str], pred: list[str], labels: list[str]) -> float:
    return float(f1_score(truth, pred, labels=labels, average="macro", zero_division=0))


def cross_validate(
    rows: list[dict[str, Any]], k: int = 5, seed: int = 0, draws: int = 1000
) -> CVReport | None:
    """Hold out whole scenarios in rotation (phase 2 spec, section 5). Returns None when there
    are too few groups to hold any out."""
    rows = [r for r in rows if label_of(r) in CLASSES]
    groups = sorted({group_of(r) for r in rows})
    k = min(k, len(groups))
    if k < 2:
        return None
    fold_of = assign_folds(rows, k, seed)
    truth: list[str] = []
    pred: list[str] = []
    rules_only: list[str] = []
    majority: list[str] = []
    group: list[str] = []
    settled: list[bool] = []
    for fold in range(k):
        held = [r for r in rows if fold_of[group_of(r)] == fold]
        # Real recordings are for testing only (spec Q8): they are predicted, never trained on.
        learn = [r for r in rows if fold_of[group_of(r)] != fold and not r.get("real")]
        if not held or not learn:
            continue
        model = train([{**r, "actor_class": label_of(r)} for r in learn])
        truth += [label_of(r) for r in held]
        pred += model.predict(held)
        rules_only += [rule_label(r) or model.majority for r in held]
        majority += [model.majority] * len(held)
        group += [group_of(r) for r in held]
        settled += [rule_label(r) is not None for r in held]
    labels = sorted(set(truth) | set(CLASSES))
    t, p, ro, mj, g = (np.array(x) for x in (truth, pred, rules_only, majority, group))

    # Sessions of one scenario are not independent, so the interval resamples scenarios.
    rng = np.random.default_rng(seed)
    index = {name: np.flatnonzero(g == name) for name in sorted(set(group))}
    names = list(index)
    d_rules, d_major = [], []
    for _ in range(draws):
        pick = np.concatenate([index[names[i]] for i in rng.integers(0, len(names), len(names))])
        tt, pp = list(t[pick]), list(p[pick])
        base = _macro(tt, pp, labels)
        d_rules.append(base - _macro(tt, list(ro[pick]), labels))
        d_major.append(base - _macro(tt, list(mj[pick]), labels))

    per_class = f1_score(truth, pred, labels=labels, average=None, zero_division=0)
    left = [i for i, s in enumerate(settled) if not s]
    by_class_groups: dict[str, set[str]] = {}
    for lab, grp in zip(truth, group, strict=True):
        by_class_groups.setdefault(lab, set()).add(grp)
    return CVReport(
        n_test=len(truth),
        n_groups=len(names),
        folds=k,
        macro_f1=_macro(truth, pred, labels),
        rules_only_f1=_macro(truth, rules_only, labels),
        majority_f1=_macro(truth, majority, labels),
        per_class_f1={lab: round(float(v), 3) for lab, v in zip(labels, per_class, strict=True)},
        confusion=confusion_matrix(truth, pred, labels=labels).tolist(),
        labels=labels,
        support=dict(sorted(Counter(truth).items())),
        groups_per_class={c: len(v) for c, v in sorted(by_class_groups.items())},
        vs_rules_ci=[round(float(x), 4) for x in np.percentile(d_rules, [2.5, 97.5])],
        vs_majority_ci=[round(float(x), 4) for x in np.percentile(d_major, [2.5, 97.5])],
        rule_settled=sum(settled),
        model_only_macro_f1=(
            _macro([truth[i] for i in left], [pred[i] for i in left], labels) if left else None
        ),
    )


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
    report = cross_validate(rows)
    # The model that is saved is trained on everything that is not a real recording.
    train_rows = [{**r, "actor_class": label_of(r)} for r in rows if not r.get("real")]
    model = train(train_rows)
    args.out.mkdir(parents=True, exist_ok=True)
    if model.booster is not None:
        model.booster.save_model(str(args.out / "actor_classifier.txt"))
    result = {
        "classes": model.classes,
        "n_train": len(train_rows),
        "report": None if report is None else asdict(report),
    }
    (args.out / "actor_classifier.metrics.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
