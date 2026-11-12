"""Off-policy estimators and the reward, on synthetic data whose answer is known."""

from __future__ import annotations

import numpy as np
import pytest
from mirage_intel import ope, reward

pytestmark = pytest.mark.ml


def synthetic_logs(n: int, k: int, best: int, seed: int) -> tuple[ope.Logs, float]:
    """A uniform behaviour policy over k actions; the target always picks `best`. Reward
    depends on the action, so the target's true value is the best action's mean reward."""
    rng = np.random.default_rng(seed)
    base = np.linspace(0.2, 0.8, k)
    actions = rng.integers(0, k, n)
    rewards = base[actions] + rng.normal(0, 0.05, n)
    behavior = np.full(n, 1.0 / k)
    target = np.where(actions == best, 1.0, 0.0)
    q = np.tile(base, (n, 1))
    logs = ope.Logs(
        reward=rewards,
        behavior_prob=behavior,
        target_prob=target,
        q_logged=base[actions],
        q_target=q[np.arange(n), best],
    )
    return logs, float(base[best])


def test_ips_and_snips_recover_the_target_value():
    logs, true_value = synthetic_logs(4000, 4, best=3, seed=1)
    for est in (ope.ips(logs), ope.snips(logs)):
        assert est.ci_low <= true_value <= est.ci_high, (est, true_value)
        assert abs(est.value - true_value) < 0.05


def test_doubly_robust_is_tighter_than_ips():
    logs, true_value = synthetic_logs(2000, 4, best=2, seed=2)
    ips_est, dr_est = ope.ips(logs), ope.dr(logs)
    assert dr_est.ci_low <= true_value <= dr_est.ci_high
    assert (dr_est.ci_high - dr_est.ci_low) < (ips_est.ci_high - ips_est.ci_low)


def test_effective_sample_size_falls_as_the_policies_diverge():
    logs, _ = synthetic_logs(1000, 8, best=0, seed=3)  # target rare under behaviour
    assert logs.weights().max() > 1
    assert ope.ips(logs).ess < 1000


def test_logs_reject_a_zero_behaviour_probability():
    with pytest.raises(ValueError, match="positive"):
        ope.Logs(np.array([1.0]), np.array([0.0]), np.array([1.0]))


def test_on_policy_mean_is_the_plain_average():
    r = np.array([0.0, 1.0, 2.0, 3.0])
    assert ope.on_policy_mean(r).value == 1.5


# ------------------------------------------------------------------ reward


def d(seq, action="allow", ended_after=False, **sets) -> reward.Decision:
    return reward.Decision(
        seq=seq,
        action=action,
        ended_after=ended_after,
        **{k: frozenset(v) for k, v in sets.items()},
    )


def test_reward_pays_once_for_each_new_thing():
    decisions = [
        d(1, techniques=["T1082"]),
        d(2, techniques=["T1082", "T1083"]),  # T1082 already seen; only T1083 is new
        d(3, artifacts=["abc"]),
        d(4, tokens=["tok1"]),
    ]
    rewards = {r.seq: r.reward for r in reward.session_rewards(decisions)}
    assert rewards[1] == 1.0  # one new technique
    assert rewards[2] == 1.0  # one new technique (T1083)
    assert rewards[3] == 2.0  # artifact
    assert rewards[4] == 3.0  # token
    assert reward.total(decisions) == 7.0


def test_early_exit_after_a_fake_is_penalised_but_not_after_allow():
    assert reward.total([d(1, action="fake_success", ended_after=True)]) == -2.0
    assert reward.total([d(1, action="allow", ended_after=True)]) == 0.0
    # a fake that keeps the attacker (another input follows) is not penalised
    assert reward.total([d(1, action="fake_error", techniques=["T1059"], ended_after=False)]) == 1.0


def test_reward_is_order_independent_in_total_but_credits_the_first_reacher():
    a = [d(1, techniques=["T1", "T2"]), d(2, techniques=["T2"])]
    rewarded = {r.seq: r.reward for r in reward.session_rewards(a)}
    assert rewarded[1] == 2.0 and rewarded[2] == 0.0
