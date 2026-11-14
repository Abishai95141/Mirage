"""Gate 2 test 8's checks on the bandit's decision log, against synthetic logs."""

from __future__ import annotations

import random

import pytest
from mirage_intel import explore_check as ec

pytestmark = pytest.mark.ml

ACTIONS = ["allow", "delay", "fake_success", "fake_error", "terminate"]
EPS = 0.3


def probs(allowed: list[str], rule_action: str = "allow") -> dict[str, float]:
    p = {a: EPS / len(allowed) for a in allowed}
    p[rule_action] += 1 - EPS
    return {a: round(v, 6) for a, v in p.items()}


def log(sessions: int = 400, per_session: int = 10, seed: int = 0, sampler=None) -> list:
    """A faithful explore log: each action drawn from the distribution that is logged."""
    rng = random.Random(seed)
    out = []
    for s in range(sessions):
        for seq in range(1, per_session + 1):
            allowed = [a for a in ACTIONS if not (a == "terminate" and seq == 1)]
            p = probs(allowed)
            if sampler:
                action = sampler(rng, allowed, p)
            else:
                action = rng.choices(list(p), weights=list(p.values()))[0]
            out.append(
                ec.Decision(
                    session_id=f"s{s}",
                    src_ip=f"198.19.{s // 250}.{s % 250 + 1}",
                    protocol="ssh",
                    explore=True,
                    policy="epsilon-greedy-v0(eps=0.3)",
                    action=action,
                    propensity=p[action],
                    probs=p,
                    allowed=allowed,
                    seq=seq,
                )
            )
    return out


def by_name(checks: list[ec.Check]) -> dict[str, ec.Check]:
    return {c.name: c for c in checks}


def test_a_faithful_log_passes_every_check():
    checks = by_name(ec.run_checks(log()))
    assert all(c.ok for c in checks.values()), {n: c.detail for n, c in checks.items() if not c.ok}
    assert checks["size"].detail["explore_sessions"] == 400
    assert checks["calibration"].detail["buckets_tested"] == 2  # first input, and every later one


def test_a_sampler_that_ignores_the_logged_probabilities_is_caught():
    # The service logs epsilon-greedy probabilities but really draws uniformly.
    uniform = log(sampler=lambda rng, allowed, p: rng.choice(allowed))
    checks = by_name(ec.run_checks(uniform))
    assert not checks["calibration"].ok and checks["calibration"].detail["rejected"]
    assert not checks["weights"].ok  # the uniform target's mean weight is far above 1
    assert checks["mask"].ok and checks["range"].ok  # the other checks are not confused by it


def test_a_masked_action_is_caught():
    decisions = log(sessions=40)
    decisions[0].action = "terminate"  # seq 1: masked, and not in its allowed list
    mask = by_name(ec.run_checks(decisions))["mask"]
    assert not mask.ok
    assert mask.detail["action_outside_allowed"] == 1
    assert mask.detail["terminate_on_first_input"] == 1


def test_exploring_outside_the_lab_range_is_caught():
    decisions = log(sessions=40)
    decisions[5].src_ip = "198.18.0.9"  # the capture range
    decisions[6].src_ip = "203.0.113.7"
    assert by_name(ec.run_checks(decisions))["range"].detail["explored_outside_lab_range"] == 2


def test_only_the_rules_may_act_outside_the_explore_range():
    rules = ec.Decision("r1", "198.18.0.4", "ssh", False, "rules", "allow", 1.0, {}, ACTIONS, 2)
    rogue = ec.Decision("r2", "198.18.0.5", "ssh", False, "bandit", "delay", 0.5, {}, ACTIONS, 2)
    assert by_name(ec.run_checks([*log(sessions=40), rules]))["range"].ok
    assert not by_name(ec.run_checks([*log(sessions=40), rules, rogue]))["range"].ok


def test_propensity_must_be_the_logged_probability_of_the_action():
    decisions = log(sessions=40)
    decisions[3].propensity = 0.5
    detail = by_name(ec.run_checks(decisions))["consistency"].detail
    assert detail["propensity_not_prob_of_action"] == 1


def test_a_small_log_fails_on_size_alone():
    checks = by_name(ec.run_checks(log(sessions=50)))
    assert not checks["size"].ok
    assert checks["mask"].ok and checks["consistency"].ok and checks["range"].ok


def test_decision_from_a_clickhouse_row():
    row = {
        "session_id": "s1",
        "src_ip": "198.19.0.7",
        "protocol": "ssh",
        "explore": 1,
        "acting": '{"name": "epsilon-greedy-v0(eps=0.3)", "action": "delay", "propensity": 0.06,'
        ' "probs": {"allow": 0.76, "delay": 0.06, "fake_success": 0.06, "fake_error": 0.06,'
        ' "terminate": 0.06}}',
        "allowed": '["allow", "delay", "fake_success", "fake_error", "terminate"]',
        "seq": 4,
    }
    d = ec.Decision.from_row(row)
    assert d.explore and d.action == "delay" and d.propensity == 0.06
    assert d.allowed[-1] == "terminate" and d.probs["allow"] == 0.76 and d.seq == 4
    # a rules decision carries no distribution
    rules = ec.Decision.from_row({**row, "explore": 0, "acting": '{"name": "rules"}'})
    assert rules.policy == "rules" and rules.probs == {} and not rules.explore
