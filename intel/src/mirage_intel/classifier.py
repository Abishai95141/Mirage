"""Actor classifier (phase 2 spec, 2.3): a rule, then a model over behaviour features.

Classes: ``scanner`` (no authenticated activity), ``scripted_bot`` (automated activity after
access), ``human`` (interactive). ``llm_agent`` stays in the label space but is not trained or
scored until phase 4 provides lab agents.

A rule settles the one case that needs no model: a session that never held access (no login
that succeeded, on a service that asks for one) is a scanner, which is the class's definition.
A model decides the rest, bot or person, over the feature allowlist in ``dataset`` -- counts,
timings, outcomes and keystroke statistics, never an address, an ID, a time or anything from
``sim_*``. Which model family and which feature set is an experiment
(``experiments/classifier_bench.py``), and its result lives in ``eval/choices.yaml``.

It is scored by holding out whole scenarios in rotation, not on the frozen procedure split.
That split exists to stop the tagger memorising command text, which this model never reads,
and its test half turned out to hold a single actor class (first live run, 14 November 2026).
A scenario and its timing variants are held out together.

**What the gate is computed on.** The rule and the session-level label share one definition,
so every rule-settled session is right by construction. Counting them flatters any model. The
gate therefore compares the model with the majority class over the sessions the rule leaves,
and the all-session figure is reported beside it, not instead of it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import lightgbm as lgb
import numpy as np
import pyarrow.parquet as pq
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score
from sklearn.preprocessing import StandardScaler

from mirage_intel.dataset import FEATURES, FEATURES_EVENT, FEATURES_TTY, FORBIDDEN, has_access

ROOT = Path(__file__).resolve().parents[3]
CLASSES = ["scanner", "scripted_bot", "human"]  # llm_agent: phase 4
FEATURE_SETS = {"event": FEATURES_EVENT, "tty": FEATURES_TTY, "both": FEATURES}
FAMILIES = ("logreg", "forest", "gbm")  # simplest first: ties go to the earlier one
MODEL_DIR = ROOT / "build" / "models" / "actor_classifier"


def rule_label(row: dict[str, Any]) -> str | None:
    """The one case decided without a model: a session that never held access is a scanner.
    The rule reads the protocol (some services ask for no login); the model never does."""
    access = has_access(
        str(row.get("protocol") or ""),
        int(row["auth_success"]),
        int(row.get("auth_attempts") or 0),
        int(row["inputs"]),
    )
    return None if access else "scanner"


def label_of(row: dict[str, Any]) -> str:
    """The session-level class a row is scored against (``label``; older datasets have only
    the actor's class)."""
    return row.get("label") or row["actor_class"]


def group_of(row: dict[str, Any]) -> str:
    """What a row is held out with: its scenario, or the scenario that one is a variant of."""
    return row.get("group") or row["scenario_id"]


def load_rows(path: Path) -> list[dict[str, Any]]:
    return pq.read_table(path).to_pylist()


def _matrix(rows: list[dict[str, Any]], features: list[str]) -> np.ndarray:
    return np.array([[float(r.get(f) or 0.0) for f in features] for r in rows], dtype=np.float64)


def _squash(x: np.ndarray) -> np.ndarray:
    """Counts and durations span orders of magnitude; a linear model wants them compressed."""
    return np.log1p(np.maximum(x, 0.0))


@dataclass
class Forest:
    """A random forest as plain arrays: what is trained with scikit-learn is converted to this
    at once, and this is what predicts, in evaluation and when served. So a saved forest is
    numbers in JSON (scikit-learn's own format is a pickle, which is code), and there is no
    second implementation whose answers could differ from the ones that were scored."""

    left: list[np.ndarray]  # per tree: a node's left child, -1 at a leaf
    right: list[np.ndarray]
    feature: list[np.ndarray]
    threshold: list[np.ndarray]
    value: list[np.ndarray]  # per tree: nodes x classes, each row a distribution

    @classmethod
    def from_sklearn(cls, fitted: RandomForestClassifier) -> Forest:
        trees = [e.tree_ for e in fitted.estimators_]
        values = []
        for t in trees:
            v = t.value[:, 0, :].astype(np.float64)
            values.append(v / np.maximum(v.sum(axis=1, keepdims=True), 1e-300))
        return cls(
            [t.children_left.astype(np.int64) for t in trees],
            [t.children_right.astype(np.int64) for t in trees],
            [np.maximum(t.feature, 0).astype(np.int64) for t in trees],
            [t.threshold.astype(np.float64) for t in trees],
            values,
        )

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        # scikit-learn splits on 32-bit inputs; the same cast keeps the same side of a split.
        x = np.asarray(x, dtype=np.float32)
        rows = np.arange(len(x))
        total = np.zeros((len(x), self.value[0].shape[1]))
        for left, right, feature, threshold, value in zip(
            self.left, self.right, self.feature, self.threshold, self.value, strict=True
        ):
            node = np.zeros(len(x), dtype=np.int64)
            while True:
                inner = left[node] != -1
                if not inner.any():
                    break
                go_left = x[rows, feature[node]] <= threshold[node]
                node = np.where(inner, np.where(go_left, left[node], right[node]), node)
            total += value[node]
        return total / len(self.value)

    def to_json(self) -> dict[str, Any]:
        return {
            "left": [a.tolist() for a in self.left],
            "right": [a.tolist() for a in self.right],
            "feature": [a.tolist() for a in self.feature],
            "threshold": [a.tolist() for a in self.threshold],
            "value": [np.round(a, 6).tolist() for a in self.value],
        }

    @classmethod
    def from_json(cls, body: dict[str, Any]) -> Forest:
        ints = [
            [np.array(a, dtype=np.int64) for a in body[k]] for k in ("left", "right", "feature")
        ]
        floats = [[np.array(a, dtype=np.float64) for a in body[k]] for k in ("threshold", "value")]
        n = len(ints[0])
        if n == 0 or any(len(part) != n for part in (*ints, *floats)):
            raise ValueError("a saved forest needs the same number of trees in every part")
        for left, right, feature, threshold, value in zip(*ints, *floats, strict=True):
            size = len(left)
            if size == 0:
                raise ValueError("a saved tree has no nodes")
            if not (len(right) == len(feature) == len(threshold) == len(value) == size):
                raise ValueError("a saved tree's arrays differ in length")
            if (feature < 0).any():
                raise ValueError("a saved tree names a feature before the first")
            # A child index must point forward inside the tree, or prediction could loop.
            for child in (left, right):
                inner = child != -1
                if (child[inner] <= np.flatnonzero(inner)).any() or (child >= size).any():
                    raise ValueError("a saved tree has a child that does not point forward")
            if ((left == -1) != (right == -1)).any():
                raise ValueError("a saved tree has a node with one child")
        return cls(*ints, *floats)


@dataclass
class Model:
    family: str
    features: list[str]
    classes: list[str]
    majority: str = "scanner"  # the most frequent training class
    estimator: Any = None  # None when training had fewer than two classes for the model
    scaler: Any = None

    def proba(self, rows: list[dict[str, Any]]) -> np.ndarray:
        x = _matrix(rows, self.features)
        if self.family == "gbm":
            return np.atleast_2d(self.estimator.predict(x))
        if self.family == "logreg":
            return self.estimator.predict_proba(self.scaler.transform(_squash(x)))
        return self.estimator.predict_proba(x)

    def decide(self, rows: list[dict[str, Any]]) -> list[tuple[str, float, str]]:
        """(class, confidence, who decided) for each row: the rule, the model, or neither."""
        out: list[tuple[str, float, str] | None] = []
        for r in rows:
            settled = rule_label(r)
            out.append((settled, 1.0, "rule") if settled else None)
        todo = [i for i, v in enumerate(out) if v is None]
        if todo and self.estimator is not None:
            probs = self.proba([rows[i] for i in todo])
            for i, p in zip(todo, probs, strict=True):
                j = int(np.argmax(p))
                out[i] = (self.classes[j], float(p[j]), "model")
        return [v if v is not None else (self.majority, 0.0, "majority") for v in out]

    def predict(self, rows: list[dict[str, Any]]) -> list[str]:
        return [c for c, _, _ in self.decide(rows)]

    @property
    def version(self) -> str:
        return f"actor-{self.family}-{_digest(self._payload())}"

    def _payload(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "family": self.family,
            "features": self.features,
            "classes": self.classes,
            "majority": self.majority,
        }
        if self.estimator is None:
            return body
        if self.family == "gbm":
            body["booster"] = self.estimator.model_to_string()
        elif self.family == "logreg":
            body["mean"] = self.scaler.mean_.tolist()
            body["scale"] = self.scaler.scale_.tolist()
            body["coef"] = self.estimator.coef_.tolist()
            body["intercept"] = self.estimator.intercept_.tolist()
        elif self.family == "forest":
            body["forest"] = self.estimator.to_json()
        else:
            raise ValueError(f"unknown model family {self.family!r}")
        return body

    def save(self, directory: Path = MODEL_DIR) -> Path:
        """Write the model as JSON: numbers, or a LightGBM text dump. Nothing executable."""
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "model.json"
        path.write_text(json.dumps({**self._payload(), "version": self.version}) + "\n")
        return path

    @classmethod
    def load(cls, directory: Path = MODEL_DIR) -> Model:
        body = json.loads((directory / "model.json").read_text())
        model = cls(body["family"], body["features"], body["classes"], body["majority"])
        if body["family"] == "gbm" and "booster" in body:
            model.estimator = lgb.Booster(model_str=body["booster"])
        elif body["family"] == "logreg" and "coef" in body:
            model.scaler = StandardScaler()
            model.scaler.mean_ = np.array(body["mean"])
            model.scaler.scale_ = np.array(body["scale"])
            model.scaler.n_features_in_ = len(body["mean"])
            model.estimator = LogisticRegression()
            model.estimator.coef_ = np.array(body["coef"])
            model.estimator.intercept_ = np.array(body["intercept"])
            model.estimator.classes_ = np.arange(len(body["classes"]))
        elif body["family"] == "forest" and "forest" in body:
            model.estimator = Forest.from_json(body["forest"])
            width = max(int(f.max()) for f in model.estimator.feature) + 1
            if width > len(model.features) or model.estimator.value[0].shape[1] != len(
                model.classes
            ):
                raise ValueError("the saved forest does not match its feature or class list")
        return model


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:12]


def train(
    rows: list[dict[str, Any]], features: list[str] | None = None, family: str = "gbm"
) -> Model:
    """Train on the rows the rule does not already settle. Rows are labelled by ``label_of``."""
    features = features or FEATURES
    learn = [r for r in rows if rule_label(r) is None]
    classes = sorted({label_of(r) for r in learn}) or CLASSES
    counts = Counter(label_of(r) for r in rows)
    majority = sorted(counts, key=lambda c: (-counts[c], c))[0] if counts else classes[0]
    model = Model(family, list(features), classes, majority)
    if len(classes) < 2:
        return model
    index = {c: i for i, c in enumerate(classes)}
    x = _matrix(learn, features)
    y = np.array([index[label_of(r)] for r in learn])
    if family == "gbm":
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
        model.estimator = lgb.train(params, lgb.Dataset(x, label=y), num_boost_round=60)
    elif family == "logreg":
        model.scaler = StandardScaler().fit(_squash(x))
        model.estimator = LogisticRegression(C=1.0, max_iter=2000, class_weight="balanced")
        model.estimator.fit(model.scaler.transform(_squash(x)), y)
    elif family == "forest":
        fitted = RandomForestClassifier(
            n_estimators=200, min_samples_leaf=2, class_weight="balanced", random_state=0
        ).fit(x, y)
        model.estimator = Forest.from_sklearn(fitted)
    else:
        raise ValueError(f"unknown model family {family!r}")
    return model


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

    family: str
    features: list[str]
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
    # 95% bootstrap intervals over groups, on the difference to each baseline, all sessions.
    vs_rules_ci: list[float]
    vs_majority_ci: list[float]
    rule_settled: int = 0  # sessions the scanner rule decided, with no model involved
    # The gate's population: the sessions the rule left to the model.
    model_only: dict[str, Any] = field(default_factory=dict)
    model_only_macro_f1: float | None = None

    def beats_rules(self) -> bool:
        return self.vs_rules_ci[0] > 0

    def beats_majority(self) -> bool:
        """On the sessions the rule leaves: the model against always answering the most
        frequent class among them."""
        ci = self.model_only.get("vs_majority_ci")
        return bool(ci) and ci[0] > 0


def _macro(truth: list[str], pred: list[str], labels: list[str]) -> float:
    return float(f1_score(truth, pred, labels=labels, average="macro", zero_division=0))


def macro_f1_codes(truth: np.ndarray, pred: np.ndarray, k: int, over: np.ndarray) -> float:
    """Macro-F1 over the classes ``over`` for labels coded 0..k-1. The same number
    scikit-learn gives with ``zero_division=0``, about a hundred times faster, which is what
    lets every interval here use a thousand resamples of scenarios."""
    m = np.bincount(truth * k + pred, minlength=k * k).reshape(k, k)
    both = m.sum(axis=0) + m.sum(axis=1)  # 2 TP + FP + FN per class
    f1 = np.divide(2.0 * np.diag(m), both, out=np.zeros(k), where=both > 0)
    return float(f1[over].mean())


def encode(labels: list[str], *columns: np.ndarray) -> tuple[int, np.ndarray, list[np.ndarray]]:
    """Code label columns as integers: (number of codes, the codes of ``labels``, columns)."""
    names = sorted(set(labels).union(*(set(c.tolist()) for c in columns)))
    code = {name: i for i, name in enumerate(names)}
    coded = [np.array([code[v] for v in c.tolist()], dtype=np.int64) for c in columns]
    return len(names), np.array([code[v] for v in labels], dtype=np.int64), coded


def _interval(
    group: np.ndarray,
    truth: np.ndarray,
    a: np.ndarray,
    b: np.ndarray | None,
    labels: list[str],
    draws: int,
    seed: int,
) -> list[float]:
    """A 95% interval on macro-F1(a) - macro-F1(b), or on macro-F1(a) alone when ``b`` is
    None, resampling scenarios: sessions of one scenario are not independent."""
    index = {name: np.flatnonzero(group == name) for name in sorted(set(group.tolist()))}
    names = list(index)
    if not names:
        return [0.0, 0.0]
    k, over, (t, pa, pb) = encode(labels, truth, a, b if b is not None else a)
    rng = np.random.default_rng(seed)
    diffs = []
    for _ in range(draws):
        pick = np.concatenate([index[names[i]] for i in rng.integers(0, len(names), len(names))])
        other = macro_f1_codes(t[pick], pb[pick], k, over) if b is not None else 0.0
        diffs.append(macro_f1_codes(t[pick], pa[pick], k, over) - other)
    return [round(float(x), 4) for x in np.percentile(diffs, [2.5, 97.5])]


@dataclass
class Folded:
    """Out-of-fold predictions: every session predicted once, by a model that never saw its
    scenario group. The order depends only on the rows and the fold seed, so two candidates
    run with one seed line up session for session and can be compared as pairs."""

    k: int
    truth: np.ndarray
    pred: np.ndarray
    rules_only: np.ndarray
    majority: np.ndarray
    majority_open: np.ndarray  # the majority class among the sessions the rule leaves
    group: np.ndarray
    scenario: np.ndarray
    is_open: np.ndarray  # True where the rule left the session to the model


def out_of_fold(
    rows: list[dict[str, Any]],
    k: int = 5,
    seed: int = 0,
    features: list[str] | None = None,
    family: str = "gbm",
) -> Folded | None:
    """Hold out whole scenario groups in rotation. None when there are too few to hold out."""
    features = features or FEATURES
    rows = [r for r in rows if label_of(r) in CLASSES]
    k = min(k, len({group_of(r) for r in rows}))
    if k < 2:
        return None
    fold_of = assign_folds(rows, k, seed)
    cols: dict[str, list] = {
        name: []
        for name in ("truth", "pred", "rules", "major", "major_open", "group", "scenario", "open")
    }
    for fold in range(k):
        held = [r for r in rows if fold_of[group_of(r)] == fold]
        # Real recordings are for testing only (spec Q8): they are predicted, never trained on.
        learn = [r for r in rows if fold_of[group_of(r)] != fold and not r.get("real")]
        if not held or not learn:
            continue
        model = train(learn, features, family)
        open_counts = Counter(label_of(r) for r in learn if rule_label(r) is None)
        open_major = (
            sorted(open_counts, key=lambda c: (-open_counts[c], c))[0]
            if open_counts
            else model.majority
        )
        cols["truth"] += [label_of(r) for r in held]
        cols["pred"] += model.predict(held)
        cols["rules"] += [rule_label(r) or model.majority for r in held]
        cols["major"] += [model.majority] * len(held)
        cols["major_open"] += [open_major] * len(held)
        cols["group"] += [group_of(r) for r in held]
        cols["scenario"] += [str(r.get("scenario_id") or "") for r in held]
        cols["open"] += [rule_label(r) is None for r in held]
    return Folded(
        k,
        *(
            np.array(cols[name])
            for name in ("truth", "pred", "rules", "major", "major_open", "group", "scenario")
        ),
        np.array(cols["open"], dtype=bool),
    )


def cross_validate(
    rows: list[dict[str, Any]],
    k: int = 5,
    seed: int = 0,
    draws: int = 1000,
    features: list[str] | None = None,
    family: str = "gbm",
) -> CVReport | None:
    """Hold out whole scenarios in rotation (phase 2 spec, section 5). Returns None when there
    are too few groups to hold any out."""
    features = features or FEATURES
    folded = out_of_fold(rows, k, seed, features, family)
    if folded is None:
        return None
    k = folded.k
    t, p, ro, mj, mo, g = (
        folded.truth, folded.pred, folded.rules_only, folded.majority, folded.majority_open,
        folded.group,
    )  # fmt: skip
    is_open = folded.is_open
    truth, pred, rules_only, majority, group = (list(x.tolist()) for x in (t, p, ro, mj, g))
    labels = sorted(set(truth) | set(CLASSES))

    per_class = f1_score(truth, pred, labels=labels, average=None, zero_division=0)
    by_class_groups: dict[str, set[str]] = {}
    for lab, grp in zip(truth, group, strict=True):
        by_class_groups.setdefault(lab, set()).add(grp)

    open_truth, open_pred, open_major = list(t[is_open]), list(p[is_open]), list(mo[is_open])
    open_labels = sorted(set(open_truth)) or labels
    open_per_class = (
        f1_score(open_truth, open_pred, labels=open_labels, average=None, zero_division=0)
        if open_truth
        else []
    )
    model_only = {
        "n": int(is_open.sum()),
        "groups": len(set(g[is_open].tolist())),
        "macro_f1": round(_macro(open_truth, open_pred, open_labels), 4) if open_truth else 0.0,
        "majority_f1": round(_macro(open_truth, open_major, open_labels), 4) if open_truth else 0.0,
        "per_class_f1": {
            lab: round(float(v), 3) for lab, v in zip(open_labels, open_per_class, strict=True)
        },
        "support": dict(sorted(Counter(open_truth).items())),
        "macro_f1_ci": _interval(g[is_open], t[is_open], p[is_open], None, open_labels, draws, seed)
        if open_truth
        else [0.0, 0.0],
        "vs_majority_ci": _interval(
            g[is_open], t[is_open], p[is_open], mo[is_open], open_labels, draws, seed
        )
        if open_truth
        else [0.0, 0.0],
    }
    return CVReport(
        family=family,
        features=list(features),
        n_test=len(truth),
        n_groups=len(set(group)),
        folds=k,
        macro_f1=_macro(truth, pred, labels),
        rules_only_f1=_macro(truth, rules_only, labels),
        majority_f1=_macro(truth, majority, labels),
        per_class_f1={lab: round(float(v), 3) for lab, v in zip(labels, per_class, strict=True)},
        confusion=confusion_matrix(truth, pred, labels=labels).tolist(),
        labels=labels,
        support=dict(sorted(Counter(truth).items())),
        groups_per_class={c: len(v) for c, v in sorted(by_class_groups.items())},
        vs_rules_ci=_interval(g, t, p, ro, labels, draws, seed),
        vs_majority_ci=_interval(g, t, p, mj, labels, draws, seed),
        rule_settled=int((~is_open).sum()),
        model_only=model_only,
        model_only_macro_f1=model_only["macro_f1"] if open_truth else None,
    )


def check_no_forbidden_features() -> None:
    """A guard the tests call: no feature column is an identity, address, time or ground truth."""
    leaked = sorted(set(FEATURES) & FORBIDDEN)
    if leaked:
        raise AssertionError(f"forbidden columns used as features: {leaked}")


def chosen() -> tuple[str, list[str]]:
    """The model family and feature set the experiment settled on (``eval/choices.yaml``)."""
    import yaml

    path = ROOT / "eval" / "choices.yaml"
    doc = (yaml.safe_load(path.read_text()) or {}) if path.exists() else {}
    choice = doc.get("classifier", {})
    return choice.get("family", "gbm"), FEATURE_SETS[choice.get("features", "both")]


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage-classifier")
    ap.add_argument("--data", type=Path, default=ROOT / "build" / "dataset" / "sessions.parquet")
    ap.add_argument("--out", type=Path, default=MODEL_DIR)
    args = ap.parse_args(argv)
    check_no_forbidden_features()
    family, features = chosen()
    rows = load_rows(args.data)
    report = cross_validate(rows, features=features, family=family)
    # The model that is saved is trained on everything that is not a real recording.
    model = train([r for r in rows if not r.get("real")], features, family)
    path = model.save(args.out)
    result = {
        "model": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
        "version": model.version,
        "classes": model.classes,
        "n_train": sum(1 for r in rows if not r.get("real")),
        "report": None if report is None else asdict(report),
    }
    (args.out / "metrics.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
