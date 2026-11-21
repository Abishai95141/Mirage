"""The bandit's exploring policy, action mask, context and the enriched decision log (2.5)."""

from __future__ import annotations

import json
import random
from collections import Counter
from pathlib import Path

from fastapi.testclient import TestClient

from mirage_policy.app import RULES_DIR, Settings, create_app
from mirage_policy.explore import (
    ACTIONS,
    BanditPolicy,
    Context,
    TacticRules,
    allowed_actions,
    is_explore,
)
from mirage_schema.policy import Action, DecideRequest

TOKEN = "t" * 32
EXPLORE_IP = "198.19.0.7"
CAPTURE_IP = "198.18.0.7"


def req(seq=1, session="s1", ip=EXPLORE_IP, **over) -> DecideRequest:
    base = {
        "request_id": "r",
        "session_id": session,
        "protocol": "ssh",
        "argv": ["uname", "-a"],
        "known": True,
        "seq": seq,
        "src": {"ip": ip},
    }
    base.update(over)
    return DecideRequest.model_validate(base)


# ------------------------------------------------------------------ mask and range


def test_terminate_is_masked_on_the_first_input():
    assert Action.TERMINATE not in allowed_actions(req(seq=1))
    assert Action.TERMINATE not in allowed_actions(req(seq=None))  # nothing seen yet: first
    assert Action.TERMINATE in allowed_actions(req(seq=2))
    assert set(allowed_actions(req(seq=5))) == set(ACTIONS)


def test_explore_only_in_range_and_when_enabled():
    assert is_explore(req(ip=EXPLORE_IP), enabled=True)
    assert not is_explore(req(ip=EXPLORE_IP), enabled=False)
    assert not is_explore(req(ip=CAPTURE_IP), enabled=True)
    assert not is_explore(req(ip="203.0.113.9"), enabled=True)
    assert not is_explore(req(ip=None), enabled=True)


# ------------------------------------------------------------------ the policy


def test_epsilon_greedy_probabilities_sum_to_one_and_favour_the_rule():
    p = BanditPolicy(epsilon=0.3)
    allowed = allowed_actions(req(seq=5))
    probs = p.probs(allowed, Action.ALLOW)
    assert abs(sum(probs.values()) - 1.0) < 1e-9
    assert probs[Action.ALLOW] > max(v for a, v in probs.items() if a is not Action.ALLOW)
    # 1-eps + eps/n for the rule action
    assert abs(probs[Action.ALLOW] - (0.7 + 0.3 / len(allowed))) < 1e-9


def test_sampling_frequencies_match_the_logged_propensities():
    p = BanditPolicy(epsilon=0.3)
    allowed = allowed_actions(req(seq=5))
    rng = random.Random(0)
    want = {a.value: pr for a, pr in p.probs(allowed, Action.ALLOW).items()}
    counts: Counter = Counter()
    n = 20000
    for _ in range(n):
        counts[p.sample(allowed, Action.ALLOW, rng).action.value] += 1
    for action, prob in want.items():
        assert abs(counts[action] / n - prob) < 0.02, (action, counts[action] / n, prob)


def test_a_masked_action_is_never_sampled_on_the_first_input():
    p = BanditPolicy(epsilon=0.9)
    allowed = allowed_actions(req(seq=1))  # no terminate
    rng = random.Random(1)
    for _ in range(5000):
        assert p.sample(allowed, Action.ALLOW, rng).action is not Action.TERMINATE


# ------------------------------------------------------------------ context


def test_context_counts_inputs_and_remembers_the_tactic():
    clock = {"t": 100.0}
    ctx = Context(now=lambda: clock["t"])
    f1 = ctx.observe(req(session="a"), tactic="TA0007")
    clock["t"] = 103.0
    assert (
        f1["inputs_so_far"] == 0 and f1["seconds_since_last"] is None and f1["last_tactic"] is None
    )
    f2 = ctx.observe(req(session="a", argv=["uname", "-a"]), tactic=None)
    assert f2["inputs_so_far"] == 1 and f2["seconds_since_last"] == 3.0
    assert f2["last_tactic"] == "TA0007"  # carried from the previous input
    assert f2["seen_before"] is True  # same command again


def test_tactic_rules_load_from_the_real_starter_file():
    rules = TacticRules.load(Path(__file__).resolve().parents[2] / "intel" / "rules")
    assert rules.tactic("ssh", "uname -a") == "TA0007"
    assert rules.tactic("ssh", "echo nothing-matches-here") is None


# ------------------------------------------------------------------ the service


def app(tmp_path: Path, explore: bool, monkeypatch) -> tuple[TestClient, Path]:
    monkeypatch.setenv("POLICY_EXPLORE", "lab" if explore else "")
    monkeypatch.setenv(
        "POLICY_TECHNIQUE_RULES", str(Path(__file__).resolve().parents[2] / "intel" / "rules")
    )
    log = tmp_path / "decisions.json"
    settings = Settings(token=TOKEN, log_path=log, rule_files=[RULES_DIR / "default.yaml"])
    return TestClient(create_app(settings, rng=random.Random(7))), log


def post(c: TestClient, seq: int, session: str, ip: str):
    body = {
        "request_id": f"r{seq}",
        "session_id": session,
        "protocol": "ssh",
        "argv": ["uname", "-a"],
        "known": True,
        "seq": seq,
        "src": {"ip": ip},
    }
    return c.post("/v1/decide", json=body, headers={"Authorization": f"Bearer {TOKEN}"})


def records(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text().splitlines()]


def test_rules_decide_outside_the_explore_range_and_the_bandit_shadows(tmp_path, monkeypatch):
    c, log = app(tmp_path, explore=True, monkeypatch=monkeypatch)
    assert post(c, 1, "s1", CAPTURE_IP).json()["action"] == "allow"
    (r,) = records(log)
    assert r["explore"] is False
    assert r["acting"] == {
        "name": "rules",
        "version": r["rules_version"],
        "action": "allow",
        "propensity": 1.0,
    }
    # No trained model is loaded, and the record says so instead of naming one.
    assert r["shadow"]["name"] == "shadow-fallback(epsilon-greedy)"
    assert r["shadow"]["version"].startswith("epsilon-greedy") and r["shadow"]["probs"]["allow"] > 0
    assert r["context"]["last_tactic"] is None  # the stage before this input; nothing yet
    assert "terminate" not in r["allowed"]  # first input


def test_bandit_acts_and_logs_propensities_in_the_explore_range(tmp_path, monkeypatch):
    c, log = app(tmp_path, explore=True, monkeypatch=monkeypatch)
    for i in range(400):
        post(c, seq=1, session=f"sess{i}", ip=EXPLORE_IP)
    rows = records(log)
    assert all(r["explore"] for r in rows)
    # every logged action was allowed, its propensity is the acting policy's prob for it,
    # and no first-input decision terminated
    for r in rows:
        assert r["action"] in r["allowed"]
        assert abs(r["acting"]["propensity"] - r["acting"]["probs"][r["action"]]) < 1e-9
        assert r["acting"]["name"].startswith("epsilon-greedy")
        if r["request"].get("seq") == 1:
            assert r["action"] != "terminate"
    # over many first-input sessions, the action mix matches the logged probabilities
    firsts = [r for r in rows if r["request"]["seq"] == 1]
    counts = Counter(r["action"] for r in firsts)
    allow_share = counts["allow"] / len(firsts)
    assert 0.70 <= allow_share <= 0.90  # ~0.7 + 0.3/4 under epsilon-greedy over 4 allowed
    assert counts["terminate"] == 0


def test_an_explored_fake_error_is_a_valid_decision(tmp_path, monkeypatch):
    c, log = app(tmp_path, explore=True, monkeypatch=monkeypatch)
    seen = set()
    for i in range(300):
        seen.add(post(c, seq=2, session=f"x{i}", ip=EXPLORE_IP).json()["action"])
    assert {"allow", "delay", "fake_success", "fake_error", "terminate"} & seen
    for r in records(log):
        if r["action"] == "fake_error":
            # "uname -a" has no entry of its own, so it gets the shell's default fake error
            assert (r["output"], r["exit_code"]) == ("Segmentation fault\n", 139)
        if r["action"] == "delay":
            assert r["delay_ms"] == 250


def test_tactic_rules_honour_all_of_as_and(tmp_path):
    # Regression guard for the review's #4/#7: the old reader matched all_of like any_of.
    import yaml

    from mirage_policy.explore import TacticRules

    (tmp_path / "r.yaml").write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "id": "web-env",
                        "technique": "T1552.001",
                        "tactic": "TA0006",
                        "protocol": "http",
                        "confidence": 0.95,
                        "all_of": ["GET ", r"\.env"],
                    },
                ]
            }
        )
    )
    rules = TacticRules.load(tmp_path)
    assert rules.tactic("http", "GET /.env") == "TA0006"  # both patterns present
    assert rules.tactic("http", "GET /index.html") is None  # only one present -> no match
    assert rules.tactic("http", "POST /.env") is None  # the other missing -> no match
