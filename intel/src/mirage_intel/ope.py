"""Off-policy evaluation (phase 2 spec, 2.5): what a new policy would have earned, from logs a
different policy produced.

Each logged decision carries the behaviour policy's probability of the action it took, so a
target policy can be scored without acting: inverse propensity scoring (IPS), its
self-normalised form (SNIPS), and the doubly robust estimator (DR) when a reward model is
available. Every estimate comes with a bootstrap confidence interval, because at a few hundred
sessions the variance is large and a point estimate alone would mislead.

These are short enough to own (the maintained libraries have not released since 2023), and the
tests check them against synthetic logs whose true value is known.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

EPS = 1e-12


@dataclass
class Estimate:
    value: float
    ci_low: float
    ci_high: float
    ess: float  # effective sample size of the importance weights (a variance warning)

    def __repr__(self) -> str:
        return (
            f"Estimate({self.value:.4f}, [{self.ci_low:.4f}, {self.ci_high:.4f}], "
            f"ess={self.ess:.1f})"
        )


@dataclass
class Logs:
    """One row per logged decision. All arrays share length n."""

    reward: np.ndarray
    behavior_prob: np.ndarray  # P(logged action | context) under the policy that acted
    target_prob: np.ndarray  # P(logged action | context) under the policy being evaluated
    q_logged: np.ndarray | None = None  # reward model for the logged action (DR)
    q_target: np.ndarray | None = None  # E over the target policy of the reward model (DR)

    def __post_init__(self) -> None:
        n = len(self.reward)
        for name in ("behavior_prob", "target_prob"):
            if len(getattr(self, name)) != n:
                raise ValueError(f"{name} length does not match reward")
        if np.any(self.behavior_prob <= 0):
            raise ValueError("every logged action needs a positive behaviour probability")

    def weights(self) -> np.ndarray:
        return self.target_prob / np.maximum(self.behavior_prob, EPS)


def effective_sample_size(w: np.ndarray) -> float:
    s2 = float(np.sum(w) ** 2)
    return s2 / float(np.sum(w**2) + EPS) if s2 > 0 else 0.0


def _bootstrap(
    point: callable, n: int, rng: np.random.Generator, draws: int
) -> tuple[float, float]:
    vals = []
    for _ in range(draws):
        idx = rng.integers(0, n, n)
        vals.append(point(idx))
    lo, hi = np.percentile(vals, [2.5, 97.5])
    return float(lo), float(hi)


def ips(logs: Logs, draws: int = 1000, seed: int = 0) -> Estimate:
    w, r = logs.weights(), logs.reward
    rng = np.random.default_rng(seed)
    value = float(np.mean(w * r))
    lo, hi = _bootstrap(lambda idx: float(np.mean(w[idx] * r[idx])), len(r), rng, draws)
    return Estimate(value, lo, hi, effective_sample_size(w))


def snips(logs: Logs, draws: int = 1000, seed: int = 0) -> Estimate:
    w, r = logs.weights(), logs.reward
    rng = np.random.default_rng(seed)

    def point(idx: np.ndarray) -> float:
        wi = w[idx]
        return float(np.sum(wi * r[idx]) / (np.sum(wi) + EPS))

    value = point(np.arange(len(r)))
    lo, hi = _bootstrap(point, len(r), rng, draws)
    return Estimate(value, lo, hi, effective_sample_size(w))


def dr(logs: Logs, draws: int = 1000, seed: int = 0) -> Estimate:
    if logs.q_logged is None or logs.q_target is None:
        raise ValueError("doubly robust needs q_logged and q_target")
    w, r = logs.weights(), logs.reward
    q_logged, q_target = logs.q_logged, logs.q_target
    rng = np.random.default_rng(seed)

    def point(idx: np.ndarray) -> float:
        return float(np.mean(q_target[idx] + w[idx] * (r[idx] - q_logged[idx])))

    value = point(np.arange(len(r)))
    lo, hi = _bootstrap(point, len(r), rng, draws)
    return Estimate(value, lo, hi, effective_sample_size(w))


def on_policy_mean(reward: np.ndarray, draws: int = 1000, seed: int = 0) -> Estimate:
    """The behaviour policy's own value: the plain mean reward, for comparison."""
    rng = np.random.default_rng(seed)
    value = float(np.mean(reward))
    lo, hi = _bootstrap(lambda idx: float(np.mean(reward[idx])), len(reward), rng, draws)
    return Estimate(value, lo, hi, float(len(reward)))
