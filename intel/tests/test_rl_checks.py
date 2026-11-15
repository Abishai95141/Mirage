"""The four checks of phase 3's 3.3, on synthetic logs whose answer is known."""

from __future__ import annotations

import numpy as np
import pytest
from mirage_intel import policylearn as pl
from mirage_intel.experiments import rl_checks as rc

pytestmark = pytest.mark.ml

ACTIONS = ["allow", "delay", "fake_error"]
PROBS = {"allow": 0.8, "delay": 0.1, "fake_error": 0.1}


def world(
    sessions: int,
    seed: int,
    stay: dict[str, float],
    pay: dict[tuple[str, str], float] | None = None,
    steps: int = 6,
) -> list[dict]:
    """Sessions logged by a policy that picks each action with ``PROBS``. After a decision the
    attacker goes on with probability ``stay[action]``. A decision is paid ``pay[(verb_class,
    action)]``, so a policy can be better than allow in one context only."""
    rng = np.random.default_rng(seed)
    rows = []
    for s in range(sessions):
        members = []
        for pos in range(1, steps + 1):
            action = str(rng.choice(ACTIONS, p=[PROBS[a] for a in ACTIONS]))
            verb_class = "read" if pos % 2 else "write"
            members.append(
                {
                    "session": f"s{s:04d}",
                    "group": f"g{s % 12:02d}",
                    "split": "train",
                    "pos": pos,
                    "protocol": "ssh",
                    "verb": f"cmd{pos}",
                    "verb_class": verb_class,
                    "known": True,
                    "inputs_so_far": pos - 1,
                    "seconds_since_last": 1.0,
                    "last_tactic": "",
                    "seen_before": False,
                    "allowed": list(ACTIONS),
                    "action": action,
                    "applied": action,
                    "usable": True,
                    "propensity": PROBS[action],
                    "probs": dict(PROBS),
                    "rule_action": "allow",
                    "reward_truth": (pay or {}).get((verb_class, action), 0.0)
                    + float(rng.normal(0, 0.05)),
                }
            )
            if rng.random() > stay[action]:
                break
        for m in members:
            m["n_in_session"] = len(members)
        rows += members
    return rows


def test_what_followed_a_decision_is_read_from_the_whole_session():
    rows = [
        {"session": "a", "pos": 1, "verb": "ls", "applied": "allow", "usable": True,
         "split": "train", "reward_truth": 1.0},
        {"session": "a", "pos": 2, "verb": "ls", "applied": "delay", "usable": False,
         "split": "train", "reward_truth": 0.0},
        {"session": "a", "pos": 3, "verb": "id", "applied": "fake_error", "usable": True,
         "split": "train", "reward_truth": -2.0},
        {"session": "b", "pos": 1, "verb": "ls", "applied": "allow", "usable": True,
         "split": "test", "reward_truth": 5.0},
    ]  # fmt: skip
    out = rc.prepare(rows)
    assert [(r["session"], r["pos"]) for r in out] == [("a", 1), ("a", 3)]  # usable, not test
    first, last = out
    # The unusable decision in between is still an input the attacker sent.
    assert first["continues"] == 1.0 and first["remaining"] == 2.0 and first["repeats"] == 1.0
    assert last["continues"] == 0.0 and last["remaining"] == 0.0
    # Only a session's last decision carries the exit penalty, and only if it was not allow.
    assert first["reward_no_exit"] == 1.0 and last["reward_no_exit"] == 0.0


def test_resampling_by_counts_matches_the_data_on_average():
    rng = np.random.default_rng(0)
    sums = rng.normal(5, 1, size=(40, 3))
    totals = rc.resampled_totals(sums, draws=4000, seed=1)
    assert totals.shape == (4000, 3)
    assert np.allclose(totals.mean(axis=0), sums.sum(axis=0), rtol=0.01)


def test_an_answer_that_ends_sessions_is_found_and_one_that_does_not_is_not():
    rows = rc.prepare(world(900, 3, stay={"allow": 0.9, "delay": 0.9, "fake_error": 0.4}))
    ends = rc.action_effect(rows, "fake_error", "continues", draws=400)
    same = rc.action_effect(rows, "delay", "continues", draws=400)
    # A decision at the last scripted step never continues, whatever the answer was, so the
    # measured effect is a little smaller than the 0.5 that was put in.
    assert -0.5 < ends["value"] < -0.3 and rc.excludes_zero(ends)
    assert abs(same["value"]) < 0.08 and not rc.excludes_zero(same)
    assert ends["taken"] > 100 and ends["ci_groups"][0] <= ends["value"] <= ends["ci_groups"][1]


def test_a_scenario_group_is_never_split_between_folds():
    rows = world(120, 4, stay={a: 0.9 for a in ACTIONS})
    fold_of = rc.folds_of(rows)
    assert set(fold_of.values()) == set(range(rc.FOLDS))
    assert set(fold_of) == {r["group"] for r in rows}


def test_the_careful_end_of_each_dial_is_the_rule():
    rows = rc.prepare(world(300, 5, stay={a: 0.9 for a in ACTIONS}, pay={("write", "delay"): 1.0}))
    fold_of = rc.folds_of(rows)
    for _name, make in rc.most_careful():
        parts = rc.cross_fit(rows, make, "reward_truth", fold_of)
        assert parts["changed"].sum() == 0
        # Scored with the same exploration share, a policy that is the rule differs by nothing.
        assert np.abs(parts["d_dr"]).max() < 1e-9


def test_a_cautious_learner_leaves_the_rule_only_where_it_pays():
    rows = rc.prepare(world(500, 6, stay={a: 0.9 for a in ACTIONS}, pay={("write", "delay"): 1.0}))
    learner = rc.CautiousLinear(z=2.0, members=15).fit(rows, "reward_truth")
    by_class = {
        vc: {learner.choose(r) for r in rows if r["verb_class"] == vc} for vc in ("read", "write")
    }
    assert by_class == {"read": {"allow"}, "write": {"delay"}}
    never = rc.CautiousLinear(z=1e6, members=5).fit(rows, "reward_truth")
    assert {never.choose(r) for r in rows} == {"allow"}


def test_the_screen_passes_a_policy_that_is_better_and_not_one_that_is_the_rule():
    rows = rc.prepare(world(700, 7, stay={a: 0.9 for a in ACTIONS}, pay={("write", "delay"): 1.0}))
    fold_of = rc.folds_of(rows)
    good = rc.judge(
        rows,
        rc.cross_fit(rows, lambda: rc.CautiousLinear(3.0, members=10), "reward_truth", fold_of),
        draws=300,
    )
    # Delay on every second decision is worth 1 there: about 0.5 per decision, less the
    # tenth of its choices the policy still spreads over the other actions.
    assert 0.3 < good["dr"]["value"] < 0.6 and good["passes_screen"]
    assert 0.4 < good["changed"] < 0.6
    assert good["ess_sessions"] <= len({r["session"] for r in rows})
    rule = rc.judge(
        rows,
        rc.cross_fit(rows, lambda: pl.TablePolicy(min_support=1e9), "reward_truth", fold_of),
        draws=300,
    )
    assert not rule["passes_screen"] and rule["changed"] == 0.0 and rule["dr"]["value"] == 0.0
    # Scored as phase 2 did, with the share on one side only, the rule "beats" itself here:
    # the share spreads a tenth of its choices over actions, one of which pays.
    as_phase2 = rc.exploration_share_cost(rows, fold_of, draws=300)
    assert as_phase2["value"] > 0 and as_phase2["ci"][0] > 0


def test_the_penalty_is_called_coincidence_when_sessions_end_anyway():
    # Nothing the decoy answers changes whether the attacker goes on.
    rows = rc.prepare(world(900, 8, stay={a: 0.7 for a in ACTIONS}))
    effects = {
        a: {o: rc.action_effect(rows, a, o, draws=200) for o in rc.OUTCOMES}
        for a in ("delay", "fake_error")
    }
    out = rc.loopholes(
        rows, {**effects, "fake_success": effects["delay"], "terminate": effects["delay"]}
    )
    assert out["exit_penalty_fired"] > 0
    assert out["by_action"]["fake_error"]["share_coincidence"] > 0.85


def test_a_stratum_keeps_its_name_beside_its_effect():
    rows = rc.prepare(world(400, 9, stay={a: 0.9 for a in ACTIONS}))
    strata = rc.closed_loop(rows, draws=50)["strata"]
    assert {s["stratum"] for s in strata if s["by"] == "verb_class"} == {"read", "write"}
    assert {s["action"] for s in strata} == {"delay", "fake_error"}  # the two that were allowed
    assert all(isinstance(s["value"], float) for s in strata)
