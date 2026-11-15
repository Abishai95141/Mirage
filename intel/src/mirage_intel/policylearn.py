"""Learning a response policy from the explore logs, and judging it without running it
(phase 2 spec, 2.5; Gate 2 test 9).

A policy maps a decision's context to a probability for each allowed action. Three kinds:

- ``RulesPolicy``: what the rules would do. The baseline.
- ``TablePolicy``: the empirically best action per context bucket, backing off to coarser
  buckets and finally to the rule where a bucket has too little support. Nothing to tune but
  the support threshold; every choice it makes can be read.
- ``LinearPolicy``: one linear reward model per action over one-hot context features, fitted by
  inverse-propensity-weighted regression; it answers the action with the highest predicted
  reward. Its file is numbers, so the policy service can load it with no new dependency.
- ``VWPolicy``: Vowpal Wabbit's contextual bandit (``--cb_adf``), as the reference learner the
  spec names. Used to check the other two, and only if the library is installed.

Evaluation is off-policy: inverse propensity (IPS), self-normalised (SNIPS) and doubly robust
(DR, with a reward model fitted on the training sessions only). A learned policy is compared
with the rules by the difference of their estimates over the same decisions, with an interval
that resamples sessions. Only decisions whose logged action is the one the decoy applied are
used (``decisions.usable``).

**What a value means here.** Each decision's reward is what followed it in its session under
the *exploring* policy. Scoring a target policy decision by decision treats the problem as a
contextual bandit, as the spec chose to; it does not account for the target also changing
later decisions. It is a screen before a policy is allowed to act in the lab, not a forecast.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import numpy as np

from mirage_schema import bandit

ACTIONS = ("allow", "delay", "fake_success", "fake_error", "terminate")
SMOOTH = bandit.SMOOTH  # the share of exploration a learned policy keeps when it acts


def allowed_of(row: dict[str, Any]) -> list[str]:
    value = row["allowed"]
    return json.loads(value) if isinstance(value, str) else list(value)


def logged_probs(row: dict[str, Any]) -> dict[str, float]:
    value = row["probs"]
    return json.loads(value) if isinstance(value, str) else dict(value)


def context(row: dict[str, Any]) -> dict[str, str]:
    """The categorical view of a decision's context: the shared definition, so the policy
    service buckets a context exactly as training did."""
    return bandit.buckets(row)


class Policy(Protocol):
    name: str

    def choose(self, row: dict[str, Any]) -> str: ...


def target_probs(policy: Policy, row: dict[str, Any], smooth: float = 0.0) -> dict[str, float]:
    """The policy's distribution over the allowed actions: its choice, with ``smooth`` spread
    evenly over everything allowed (0 for a deterministic policy)."""
    allowed = allowed_of(row)
    choice = policy.choose(row)
    if choice not in allowed:
        choice = row["rule_action"] if row["rule_action"] in allowed else allowed[0]
    return {a: smooth / len(allowed) + (1.0 - smooth) * (a == choice) for a in allowed}


class RulesPolicy:
    name = "rules"

    def fit(self, rows: list[dict[str, Any]], reward: str) -> RulesPolicy:
        return self

    def choose(self, row: dict[str, Any]) -> str:
        return row["rule_action"]


class TablePolicy:
    """The best action per bucket by self-normalised IPS, with back-off. The model is held in
    the form it is saved in, and the choice is made by the code the policy service runs."""

    LEVELS = (
        ("protocol", "verb_class", "known", "inputs", "tactic"),
        ("protocol", "known", "inputs"),
        ("protocol", "known"),
        ("protocol",),
    )

    def __init__(self, min_support: float = 30.0, margin: float = 0.0) -> None:
        self.min_support, self.margin = min_support, margin
        self.name = f"table(support>={min_support:g})"
        self.model: dict[str, Any] = self._empty()

    def _empty(self) -> dict[str, Any]:
        return {
            "kind": "table",
            "levels": [list(level) for level in self.LEVELS],
            "min_support": self.min_support,
            "margin": self.margin,
            "cells": [{} for _ in self.LEVELS],
        }

    def fit(self, rows: list[dict[str, Any]], reward: str) -> TablePolicy:
        self.model = self._empty()
        for depth, level in enumerate(self.LEVELS):
            sums: dict[str, dict[str, list[float]]] = defaultdict(
                lambda: defaultdict(lambda: [0.0, 0.0, 0.0])
            )
            for r in rows:
                cats = context(r)
                cell = sums["|".join(cats[k] for k in level)][r["action"]]
                w = 1.0 / r["propensity"]
                cell[0] += w * r[reward]
                cell[1] += w
                cell[2] += w * w
            self.model["cells"][depth] = {
                # (self-normalised mean reward, effective sample size)
                key: {a: [c[0] / c[1], c[1] * c[1] / c[2]] for a, c in acts.items() if c[1] > 0}
                for key, acts in sums.items()
            }
        return self

    def choose(self, row: dict[str, Any]) -> str:
        return bandit.choose(self.model, row, allowed_of(row), row["rule_action"])

    def to_json(self) -> dict[str, Any]:
        return self.model


def _one_hot(rows: list[dict[str, Any]], vocab: dict[str, int] | None = None):
    grow = vocab is None
    vocab = {} if vocab is None else vocab
    keyed = []
    for r in rows:
        keys = [f"{k}={v}" for k, v in context(r).items()]
        if grow:
            for k in keys:
                vocab.setdefault(k, len(vocab))
        keyed.append(keys)
    x = np.zeros((len(rows), len(vocab) + 1))
    x[:, -1] = 1.0  # intercept
    for i, keys in enumerate(keyed):
        for k in keys:
            j = vocab.get(k)
            if j is not None:
                x[i, j] = 1.0
    return x, vocab


class LinearPolicy:
    """Per action, a ridge regression of reward on the context, weighted by 1/propensity so the
    fit describes the population of contexts rather than the ones the logging policy favoured."""

    def __init__(self, ridge: float = 1.0, weighted: bool = True) -> None:
        self.ridge, self.weighted = ridge, weighted
        self.name = f"linear(ridge={ridge:g}{',ipw' if weighted else ''})"
        self.vocab: dict[str, int] = {}
        self.weights: dict[str, np.ndarray] = {}
        self._saved: dict[str, Any] | None = None  # the model as saved, built on first use

    def fit(self, rows: list[dict[str, Any]], reward: str) -> LinearPolicy:
        self._saved = None
        x, self.vocab = _one_hot(rows)
        y = np.array([r[reward] for r in rows], dtype=float)
        w = np.array([1.0 / r["propensity"] for r in rows]) if self.weighted else np.ones(len(rows))
        taken = np.array([r["action"] for r in rows])
        self.weights = {}
        penalty = self.ridge * np.eye(x.shape[1])
        penalty[-1, -1] = 0.0  # the intercept is not shrunk
        for a in ACTIONS:
            m = taken == a
            if m.sum() < 2:
                continue
            xa, ya, wa = x[m], y[m], w[m]
            self.weights[a] = np.linalg.solve(
                (xa * wa[:, None]).T @ xa + penalty, (xa * wa[:, None]).T @ ya
            )
        return self

    def predict(self, rows: list[dict[str, Any]]) -> dict[str, np.ndarray]:
        x, _ = _one_hot(rows, self.vocab)
        return {a: x @ w for a, w in self.weights.items()}

    @property
    def model(self) -> dict[str, Any]:
        names = sorted(self.vocab, key=self.vocab.get)
        return {
            "kind": "linear",
            "features": names,
            "weights": {a: [float(v) for v in w] for a, w in self.weights.items()},
        }

    def choose(self, row: dict[str, Any]) -> str:
        if self._saved is None:
            self._saved = self.model
            self._saved["_index"] = {n: i for i, n in enumerate(self._saved["features"])}
        return bandit.choose(self._saved, row, allowed_of(row), row["rule_action"])

    def to_json(self) -> dict[str, Any]:
        return self.model


class VWPolicy:
    """Vowpal Wabbit ``--cb_adf``. Cost is minus reward. Needs the ``vowpalwabbit`` package."""

    def __init__(self, cb_type: str = "dr", passes: int = 3) -> None:
        self.cb_type, self.passes = cb_type, passes
        self.name = f"vw(cb_adf,{cb_type})"
        self.vw = None

    @staticmethod
    def _lines(row: dict[str, Any], label: bool, reward: str = "") -> list[str]:
        shared = "shared |U " + " ".join(
            f"{k}={v}".replace(":", "_").replace("|", "_") for k, v in context(row).items()
        )
        out = [shared]
        for a in allowed_of(row):
            head = (
                f"0:{-float(row[reward]):.6f}:{row['propensity']:.6f} "
                if label and a == row["action"]
                else ""
            )
            out.append(f"{head}|A action={a}")
        return out

    def fit(self, rows: list[dict[str, Any]], reward: str) -> VWPolicy:
        import vowpalwabbit

        self.vw = vowpalwabbit.Workspace(f"--cb_adf --cb_type {self.cb_type} -q UA --quiet -b 18")
        cb = vowpalwabbit.LabelType.CONTEXTUAL_BANDIT
        for _ in range(self.passes):
            for r in rows:
                example = self.vw.parse(self._lines(r, True, reward), cb)
                self.vw.learn(example)
                self.vw.finish_example(example)
        return self

    def choose(self, row: dict[str, Any]) -> str:
        import vowpalwabbit

        example = self.vw.parse(self._lines(row, False), vowpalwabbit.LabelType.CONTEXTUAL_BANDIT)
        scores = self.vw.predict(example)
        self.vw.finish_example(example)
        allowed = allowed_of(row)
        return allowed[int(np.argmin(scores))]  # the lowest predicted cost


# ---------------------------------------------------------------- off-policy evaluation


@dataclass
class Value:
    ips: float
    snips: float
    dr: float
    ess: float


def _arrays(
    policy: Policy,
    rows: list[dict[str, Any]],
    reward: str,
    model: LinearPolicy | None,
    smooth: float,
):
    r = np.array([row[reward] for row in rows], dtype=float)
    p = np.array([row["propensity"] for row in rows], dtype=float)
    probs = [target_probs(policy, row, smooth) for row in rows]
    pi = np.array([pr.get(row["action"], 0.0) for pr, row in zip(probs, rows, strict=True)])
    w = pi / p
    if model is None or not model.weights:
        return r, w, np.zeros(len(rows)), np.zeros(len(rows))
    q = model.predict(rows)
    zero = np.zeros(len(rows))
    q_logged = np.array([q.get(row["action"], zero)[i] for i, row in enumerate(rows)])
    q_target = np.array([sum(pr[a] * q.get(a, zero)[i] for a in pr) for i, pr in enumerate(probs)])
    return r, w, q_logged, q_target


def terms(
    policy: Policy,
    rows: list[dict[str, Any]],
    reward: str,
    model: LinearPolicy | None = None,
    smooth: float = 0.0,
) -> dict[str, np.ndarray]:
    """One policy's per-decision pieces of the three estimators: the reward, the importance
    weight, and the reward model's prediction for the logged action and under the policy.
    ``compare`` sums them over a set of decisions. An analysis that needs them per session or
    per fold (a cross-fitted comparison) takes them from here, so there is one definition."""
    r, w, q_logged, q_target = _arrays(policy, rows, reward, model, smooth)
    return {"reward": r, "weight": w, "q_logged": q_logged, "q_target": q_target}


def _point(r, w, ql, qt, weight) -> tuple[float, float, float]:
    total = weight.sum()
    ips = float((weight * w * r).sum() / total)
    snips = float((weight * w * r).sum() / max((weight * w).sum(), 1e-12))
    dr = float((weight * (qt + w * (r - ql))).sum() / total)
    return ips, snips, dr


def evaluate(
    policy: Policy,
    rows: list[dict[str, Any]],
    reward: str,
    model: LinearPolicy | None = None,
    smooth: float = 0.0,
    balanced: bool = False,
) -> Value:
    """The policy's estimated value. ``balanced`` gives every session the same total weight,
    so one session that looped a thousand times does not decide the answer."""
    r, w, ql, qt = _arrays(policy, rows, reward, model, smooth)
    weight = (
        np.array([1.0 / row["n_in_session"] for row in rows]) if balanced else np.ones(len(rows))
    )
    ips, snips, dr = _point(r, w, ql, qt, weight)
    return Value(ips, snips, dr, float(w.sum() ** 2 / max((w**2).sum(), 1e-12)))


def compare(
    a: Policy,
    b: Policy,
    rows: list[dict[str, Any]],
    reward: str,
    model: LinearPolicy | None = None,
    smooth_a: float = 0.0,
    smooth_b: float = 0.0,
    balanced: bool = False,
    draws: int = 1000,
    seed: int = 0,
) -> dict[str, Any]:
    """Value(a) - Value(b) under each estimator, with a 95% interval that resamples sessions."""
    ra, wa, qla, qta = _arrays(a, rows, reward, model, smooth_a)
    rb, wb, qlb, qtb = _arrays(b, rows, reward, model, smooth_b)
    weight = (
        np.array([1.0 / row["n_in_session"] for row in rows]) if balanced else np.ones(len(rows))
    )
    sessions = np.array([row["session"] for row in rows])
    order = np.argsort(sessions, kind="stable")
    _, starts = np.unique(sessions[order], return_index=True)
    members = np.split(order, starts[1:])

    def diff(idx: np.ndarray) -> tuple[float, float, float]:
        pa = _point(ra[idx], wa[idx], qla[idx], qta[idx], weight[idx])
        pb = _point(rb[idx], wb[idx], qlb[idx], qtb[idx], weight[idx])
        return tuple(x - y for x, y in zip(pa, pb, strict=True))

    point = diff(np.arange(len(rows)))
    rng = np.random.default_rng(seed)
    samples = np.array(
        [
            diff(np.concatenate([members[i] for i in rng.integers(0, len(members), len(members))]))
            for _ in range(draws)
        ]
    )
    lo, hi = np.percentile(samples, [2.5, 97.5], axis=0)
    names = ("ips", "snips", "dr")
    out = {
        n: {"diff": round(point[i], 4), "ci": [round(float(lo[i]), 4), round(float(hi[i]), 4)]}
        for i, n in enumerate(names)
    }
    out["sessions"] = len(members)
    out["same_sign"] = len({np.sign(round(point[i], 6)) for i in range(3)}) == 1
    out["changed"] = round(float(np.mean([a.choose(r) != b.choose(r) for r in rows])), 4)
    return out


def save(policy: TablePolicy | LinearPolicy, path: Path, meta: dict[str, Any]) -> None:
    """Write a learned policy as plain JSON: numbers and names, nothing executable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({**policy.to_json(), "name": policy.name, **meta}) + "\n")
