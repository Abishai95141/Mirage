"""Off-policy estimators and the reward, on synthetic data whose answer is known."""

from __future__ import annotations

import json

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
# The spec's sentence, case by case: "for each decision, over the rest of its session: +1 per
# new distinct technique, +2 per new captured artifact, +3 per honeytoken reached or used, -2 if
# the session ends before the next input after a non-allow action. Nothing is paid for time or
# for input count."

D, Seen = reward.Decision, reward.Observation


def rewards(decisions, observations):
    return {r.seq: r.reward for r in reward.session_rewards(decisions, observations)}


def test_a_decision_is_paid_for_what_first_appears_after_it():
    decisions = [D(1, "allow"), D(2, "allow"), D(3, "allow")]
    seen = [
        Seen("technique", "T1082", 0),  # in decision 1's own input: it came after no decision
        Seen("technique", "T1083", 1),  # in decision 2's input: after decision 1
        Seen("artifact", "abc", 2),  # captured between decisions 2 and 3
        Seen("token", "tok1", 3),  # reached after decision 3
    ]
    got = rewards(decisions, seen)
    assert got[1] == 6.0  # T1083 + artifact + token; not T1082, which its response did not cause
    assert got[2] == 5.0  # artifact + token; T1083 was already in its own input
    assert got[3] == 3.0  # the token


def test_every_earlier_decision_is_credited_not_only_the_first():
    # Two decisions precede the new technique. Either could have ended the session.
    got = rewards([D(1, "allow"), D(2, "delay"), D(3, "allow")], [Seen("technique", "T1053", 2)])
    assert got[1] == 1.0 and got[2] == 1.0 and got[3] == 0.0


def test_something_already_seen_is_not_new():
    seen = [
        Seen("technique", "T1082", 0),
        Seen("technique", "T1082", 2),
        Seen("artifact", "abc", 1),
    ]
    got = rewards([D(1, "allow"), D(2, "allow"), D(3, "allow")], seen)
    assert got[1] == 2.0  # the artifact; the repeat of T1082 is not new
    assert got[2] == 0.0 and got[3] == 0.0


def test_early_exit_after_a_non_allow_action_is_penalised():
    assert rewards([D(1, "fake_success")], []) == {1: -2.0}
    assert rewards([D(1, "terminate")], []) == {1: -2.0}
    assert rewards([D(1, "allow")], []) == {1: 0.0}
    # a faked answer that keeps the attacker (another input follows) is not penalised
    got = rewards([D(1, "fake_error"), D(2, "allow")], [Seen("technique", "T1059", 1)])
    assert got == {1: 1.0, 2: 0.0}


def test_nothing_is_paid_for_time_or_for_input_count():
    assert rewards([D(i, "allow") for i in range(1, 30)], []) == dict.fromkeys(range(1, 30), 0.0)
    assert rewards([D(i, "delay") for i in range(1, 30)], [])[1] == 0.0  # stalling earns nothing


def test_where_a_timestamped_event_sits_on_the_decision_timeline():
    times = [(10.0, 1), (12.0, 2), (15.0, 3)]
    assert reward.after_seq(times, 9.0) == 0  # before every decision
    assert reward.after_seq(times, 12.0) == 2 and reward.after_seq(times, 14.9) == 2
    assert reward.after_seq(times, 99.0) == 3


def test_intervals_resample_sessions_when_told_which_session_each_decision_is_in():
    # Twenty sessions of fifty decisions; reward is a property of the session. Treating the
    # thousand decisions as independent makes the interval far too narrow.
    rng = np.random.default_rng(0)
    session_reward = rng.normal(0.0, 1.0, 20)
    cluster = np.repeat(np.arange(20), 50)
    r = session_reward[cluster]
    naive = ope.on_policy_mean(r, draws=500)
    honest = ope.on_policy_mean(r, draws=500, cluster=cluster)
    assert (honest.ci_high - honest.ci_low) > 4 * (naive.ci_high - naive.ci_low)
    ones = np.ones_like(r)
    logs = ope.Logs(reward=r, behavior_prob=ones, target_prob=ones, cluster=cluster)
    wide = ope.ips(logs, draws=500)
    assert abs((wide.ci_high - wide.ci_low) - (honest.ci_high - honest.ci_low)) < 0.2


# ------------------------------------------------------------------ the decision table


def _policy(session, request, ts, action="allow", propensity=0.76, seq=1, verb="ls"):
    probs = {
        "allow": 0.76,
        "delay": 0.06,
        "fake_success": 0.06,
        "fake_error": 0.06,
        "terminate": 0.06,
    }
    return {
        "session_id": session,
        "ts": ts,
        "protocol": "ssh",
        "request_id": request,
        "explore": 1,
        "acting": json.dumps({"name": "eps", "action": action, "propensity": propensity, "probs": probs}),
        "allowed": json.dumps(list(probs)),
        "context": json.dumps({"verb": verb, "known": True, "inputs_so_far": seq - 1,
                               "seconds_since_last": None if seq == 1 else 0.4,
                               "last_tactic": None, "seen_before": False}),
        "shadow": "null",
    }  # fmt: skip


def _decoy(session, request, applied="allow", fallback=0):
    return {"event_id": f"ev-{request}", "session_id": session, "request_id": request,
            "applied": applied, "fallback": fallback}  # fmt: skip


SIM = [
    {"session_id": "c1", "logical_session_id": "c1", "scenario_id": "bot-a", "run_id": "r1"},
    {"session_id": "h1", "logical_session_id": "web", "scenario_id": "scan-b", "run_id": "r1"},
    {"session_id": "h2", "logical_session_id": "web", "scenario_id": "scan-b", "run_id": "r1"},
]


def test_decisions_carry_both_rewards_and_follow_the_logical_session():
    from mirage_intel import decisions

    policy = [
        _policy("c1", "a", 10.0, seq=1),
        _policy("c1", "b", 11.0, action="delay", propensity=0.06, seq=2),
        _policy("c1", "c", 12.0, seq=3),
        _policy("h2", "y", 21.0),  # the second connection of one web session
        _policy("h1", "x", 20.0),
    ]
    decoy = [_decoy("c1", "a"), _decoy("c1", "b", "delay"), _decoy("c1", "c"),
             _decoy("h1", "x"), _decoy("h2", "y")]  # fmt: skip
    tagged = [{"event_id": "ev-b", "technique": "T1082"}]  # the tagger saw one technique
    truth = [{"event_id": "ev-b", "technique": "T1082"}, {"event_id": "ev-c", "technique": "T1105"}]
    artifacts = [{"session_id": "c1", "ts": 12.5, "value": "abc"}]  # after decision 3
    rows = decisions.build(
        policy, decoy, SIM, tagged, truth, artifacts, [], {"bot-a": "train", "scan-b": "test"}
    )
    ssh = [r for r in rows if r["session"] == "c1"]
    assert [r["pos"] for r in ssh] == [1, 2, 3] and all(r["usable"] for r in ssh)
    # decision 1: T1082 (in decision 2's input) and the artifact follow it
    assert [r["reward_tagged"] for r in ssh] == [3.0, 2.0, 2.0]
    # ground truth also knows decision 3's technique, which followed decisions 1 and 2
    assert [r["reward_truth"] for r in ssh] == [4.0, 3.0, 2.0]
    assert ssh[1]["action"] == "delay" and ssh[1]["rule_action"] == "allow"
    assert ssh[0]["seconds_since_last"] == -1.0 and ssh[1]["seconds_since_last"] == 0.4
    web = [r for r in rows if r["session"] == "web"]
    assert [r["n_in_session"] for r in web] == [2, 2] and web[0]["split"] == "test"
    assert decisions.health(rows)["ok"] and decisions.health(rows)["usable"] == 5


def test_a_fallback_or_an_action_the_decoy_did_not_apply_is_never_usable():
    from mirage_intel import decisions

    policy = [
        _policy("c1", "a", 10.0, action="terminate", propensity=0.06),
        _policy("c1", "b", 11.0, action="fake_error", propensity=0.06, seq=2),
        _policy("c1", "c", 12.0, seq=3),
        _policy("c1", "d", 13.0, seq=4),
    ]
    decoy = [
        _decoy("c1", "a", "allow", fallback=1),  # the decoy could not reach the service
        _decoy("c1", "b", "allow"),  # it applied something other than what was logged
        _decoy("c1", "c"),
    ]  # "d" has no decoy event at all
    rows = decisions.build(policy, decoy, SIM, [], [], [], [], {"bot-a": "train"})
    assert [r["usable"] for r in rows] == [False, False, True, False]
    h = decisions.health(rows)
    assert (
        h["fallbacks"] == 1 and h["applied_differs_from_logged"] == 1 and h["no_decoy_event"] == 1
    )
    assert not h["ok"]
    # a fallback alone is the fail-open design working, not a broken log
    only_fallback = decisions.build(
        policy[:1] + policy[2:3], decoy[:1] + decoy[2:], SIM, [], [], [], [], {}
    )
    assert decisions.health(only_fallback)["ok"]
    # the reward follows what was applied: the fallback allowed the input, so no early exit
    assert rows[0]["applied"] == "allow" and rows[0]["reward_tagged"] == 0.0


# ------------------------------------------------------------------ learning and judging a policy


def explore_log(n_sessions=300, per_session=6, seed=0):
    """Logs from epsilon-greedy over a rule that always allows. The truth: faking success on
    an unknown input is worth 3, allowing anything is worth 1, terminating costs 2."""
    from mirage_intel import policylearn as pl

    rng = np.random.default_rng(seed)
    rows = []
    for s in range(n_sessions):
        for pos in range(1, per_session + 1):
            known = bool(rng.random() < 0.5)
            allowed = [a for a in pl.ACTIONS if not (a == "terminate" and pos == 1)]
            probs = {a: 0.3 / len(allowed) + (0.7 if a == "allow" else 0.0) for a in allowed}
            action = str(rng.choice(allowed, p=[probs[a] for a in allowed]))
            mean = {"allow": 1.0, "terminate": -2.0}.get(action, 0.5)
            if action == "fake_success" and not known:
                mean = 3.0
            rows.append(
                {
                    "session": f"s{s}",
                    "n_in_session": per_session,
                    "pos": pos,
                    "protocol": "ssh",
                    "verb_class": "other",
                    "known": known,
                    "inputs_so_far": pos - 1,
                    "seconds_since_last": -1.0 if pos == 1 else 0.3,
                    "last_tactic": "",
                    "seen_before": False,
                    "allowed": json.dumps(allowed),
                    "action": action,
                    "propensity": probs[action],
                    "probs": json.dumps(probs),
                    "rule_action": "allow",
                    "reward": mean + float(rng.normal(0, 0.3)),
                }
            )
    return rows


class Oracle:
    name = "oracle"

    def choose(self, row):
        return "allow" if row["known"] else "fake_success"


def test_estimators_recover_known_values_on_the_decision_table():
    from mirage_intel import policylearn as pl

    rows = explore_log()
    model = pl.LinearPolicy().fit(rows, "reward")
    rules = pl.evaluate(pl.RulesPolicy(), rows, "reward", model)
    best = pl.evaluate(Oracle(), rows, "reward", model)
    assert abs(rules.ips - 1.0) < 0.1 and abs(rules.snips - 1.0) < 0.1 and abs(rules.dr - 1.0) < 0.1
    assert abs(best.snips - 2.0) < 0.35 and abs(best.dr - 2.0) < 0.2
    assert best.ess < rules.ess  # the further from the logging policy, the less data counts


def test_learners_find_the_better_action_and_the_comparison_shows_it():
    from mirage_intel import policylearn as pl

    train, held = explore_log(seed=1), explore_log(n_sessions=200, seed=2)
    unknown = next(r for r in held if not r["known"] and r["pos"] > 1)
    known = next(r for r in held if r["known"])
    for learner in (pl.TablePolicy(min_support=20), pl.LinearPolicy()):
        policy = learner.fit(train, "reward")
        assert policy.choose(unknown) == "fake_success", policy.name
        assert policy.choose(known) == "allow", policy.name
        json.dumps(policy.to_json())  # a plain-JSON artefact
        model = pl.LinearPolicy().fit(train, "reward")
        got = pl.compare(policy, pl.RulesPolicy(), held, "reward", model, draws=300)
        assert got["dr"]["ci"][0] > 0 and got["same_sign"], policy.name
        assert 0.3 < got["changed"] < 0.7  # it departs from the rule on the unknown half


def test_a_policy_no_better_than_the_rules_is_not_reported_as_better():
    from mirage_intel import policylearn as pl

    held = explore_log(n_sessions=200, seed=3)
    same = pl.compare(pl.RulesPolicy(), pl.RulesPolicy(), held, "reward", draws=200)
    assert same["dr"]["diff"] == 0.0 and same["dr"]["ci"] == [0.0, 0.0] and same["changed"] == 0.0

    class Worse:
        name = "always-terminate"

        def choose(self, row):
            return "terminate"

    worse = pl.compare(Worse(), pl.RulesPolicy(), held, "reward", draws=200)
    assert worse["snips"]["ci"][1] < 0


def test_a_table_backs_off_to_the_rule_where_it_knows_too_little():
    from mirage_intel import policylearn as pl

    few = explore_log(n_sessions=4, seed=4)
    policy = pl.TablePolicy(min_support=500).fit(few, "reward")
    assert all(policy.choose(r) == "allow" for r in few)


def test_a_masked_or_unknown_choice_falls_back_and_smoothing_sums_to_one():
    from mirage_intel import policylearn as pl

    row = explore_log(n_sessions=1)[0]  # the first input: terminate is masked

    class Terminator:
        name = "t"

        def choose(self, row):
            return "terminate"

    probs = pl.target_probs(Terminator(), row, smooth=0.1)
    assert "terminate" not in probs and abs(sum(probs.values()) - 1.0) < 1e-9
    assert max(probs, key=probs.get) == "allow"  # the rule's action stands in


def test_session_balanced_value_is_not_decided_by_one_looping_session():
    from mirage_intel import policylearn as pl

    rows = explore_log(n_sessions=50, seed=5)
    loop = [
        dict(
            rows[0], session="loop", n_in_session=2000, action="allow", propensity=0.76, reward=-5.0
        )
        for _ in range(2000)
    ]
    plain = pl.evaluate(pl.RulesPolicy(), rows + loop, "reward")
    balanced = pl.evaluate(pl.RulesPolicy(), rows + loop, "reward", balanced=True)
    assert plain.snips < -3.0  # the loop's two thousand decisions drown the other fifty sessions
    assert balanced.snips > 0.5  # one session among fifty-one


def test_vowpal_wabbit_agrees_when_it_is_installed():
    pytest.importorskip("vowpalwabbit")
    from mirage_intel import policylearn as pl

    train, held = explore_log(seed=6), explore_log(n_sessions=150, seed=7)
    policy = pl.VWPolicy("dr").fit(train, "reward")
    unknown = next(r for r in held if not r["known"] and r["pos"] > 1)
    assert policy.choose(unknown) == "fake_success"


def test_the_policy_service_would_choose_what_training_chose(tmp_path):
    # Train/serve parity: a learned policy is saved, loaded by the policy service's own loader,
    # and asked about every held-out decision. Its most probable action must be the one the
    # offline code evaluated, or every offline number describes a different policy.
    from mirage_intel import policylearn as pl

    from mirage_policy import shadow_json  # noqa: F401 - registers the .json loader, as app.py does
    from mirage_policy.explore import BanditPolicy
    from mirage_policy.shadow import load_shadow
    from mirage_schema.policy import Action

    train, held = explore_log(seed=8), explore_log(n_sessions=80, seed=9)
    for learner in (pl.TablePolicy(min_support=20), pl.LinearPolicy()):
        policy = learner.fit(train, "reward")
        path = tmp_path / f"{type(policy).__name__}.json"
        pl.save(policy, path, {"reward": "reward"})
        shadow = load_shadow(path, BanditPolicy())
        assert shadow.name.startswith("learned("), shadow.name
        for row in held:
            ctx = {
                "protocol": row["protocol"], "verb_class": row["verb_class"], "known": row["known"],
                "inputs_so_far": row["inputs_so_far"],
                "seconds_since_last": None if row["seconds_since_last"] < 0 else row["seconds_since_last"],
                "last_tactic": row["last_tactic"] or None, "seen_before": row["seen_before"],
                "rule_action": row["rule_action"],
            }  # fmt: skip
            allowed = [Action(a) for a in pl.allowed_of(row)]
            probs = shadow.probabilities(ctx, allowed)
            assert max(probs, key=probs.get).value == policy.choose(row)
            assert pl.target_probs(policy, row, pl.SMOOTH) == {a.value: p for a, p in probs.items()}


def test_the_shadow_is_the_pick_or_else_the_learner_most_worth_watching():
    from mirage_intel.experiments import bandit_bench as bench

    class Saved:
        def to_json(self):
            return {}

    def row(name, rank, low, changed, eligible=False, policy=None):
        return {
            "name": name,
            "rank": rank,
            "eligible": eligible,
            "policy": policy or Saved(),
            "vs_rules": {"dr": {"ci": [low, low + 1]}, "changed": changed},
        }

    same_as_rules = row("table(support>=60)", 0, -0.01, 0.0)  # the best interval, no difference
    table = row("table(support>=15)", 0, -0.31, 0.08)
    linear = row("linear(ridge=1,ipw)", 1, -0.27, 0.67)
    not_a_file = row("vw(cb_adf,dr)", 2, -0.05, 0.6, policy=object())
    rows = [same_as_rules, table, linear, not_a_file]
    assert bench.pick(rows) is None  # nothing is fit to act: the rules stay
    assert bench.shadow(rows)["name"] == "linear(ridge=1,ipw)"
    # an eligible learner is both the pick and the shadow
    winner = row("table(support>=30)", 0, 0.12, 0.2, eligible=True)
    assert bench.pick([*rows, winner]) is winner and bench.shadow([*rows, winner]) is winner
    # with nothing that both differs and can be saved, nothing shadows
    assert bench.shadow([same_as_rules, not_a_file]) is None
