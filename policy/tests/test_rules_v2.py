"""Rules v2 and the mask for contract v2's actions (phase 3 spec 3.3, decision R11)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from mirage_policy import explore
from mirage_policy.app import RULES_DIR, Settings, create_app
from mirage_policy.explore import Context, allowed_actions, budget_bucket, v2_allowed
from mirage_policy.rules import RuleSet
from mirage_schema.policy import Action, DecideRequest

TOKEN = "t" * 32
V2 = RULES_DIR / "v2.yaml"


def req(**over) -> DecideRequest:
    body = {
        "request_id": "r",
        "session_id": "s1",
        "protocol": "ssh",
        "argv": ["getent", "passwd"],
        "known": False,
        "tier": "none",
        "supports": ["respond", "plant_token", "escalate"],
        "src": {"ip": "203.0.113.9", "port": 40000},
    }
    return DecideRequest.model_validate(body | over)


def client(tmp_path: Path, rules: Path = V2) -> tuple[TestClient, Path]:
    log = tmp_path / "decisions.json"
    return TestClient(create_app(Settings(token=TOKEN, log_path=log, rule_files=[rules]))), log


def post(c: TestClient, **over) -> dict:
    body = json.loads(req(**over).model_dump_json(exclude_none=True))
    r = c.post("/v1/decide", json=body, headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200, r.text
    return r.json()


def records(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text().splitlines()]


# ------------------------------------------------------------------ the rule files


def write(tmp_path: Path, version: int, rules: list[dict]) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump({"version": version, "rules": rules}))
    return path


ALLOW = {"id": "all", "action": "allow"}


@pytest.mark.parametrize(
    "rule",
    [
        {"id": "x", "action": "respond"},
        {"id": "x", "action": "plant_token"},
        {"id": "x", "action": "escalate"},
        {"id": "x", "action": "allow", "when": {"tier": "none"}},
        {"id": "x", "action": "allow", "when": {"inputs_min": 3}},
        {"id": "x", "action": "allow", "when": {"tactic": "TA0006"}},
        {"id": "x", "action": "allow", "when": {"token_planted": False}},
    ],
)
def test_a_version_1_file_may_use_nothing_of_version_2(tmp_path, rule):
    with pytest.raises(ValueError, match="version 2"):
        RuleSet.load(write(tmp_path, 1, [rule, ALLOW]))
    RuleSet.load(write(tmp_path, 2, [rule, ALLOW]))  # and a version 2 file may


@pytest.mark.parametrize(
    "rules",
    [
        [{"id": "x", "action": "respond"}],  # a v2 action cannot be the rule of last resort
        [{"id": "x", "action": "allow", "max_tokens": 10}, ALLOW],
        [{"id": "x", "action": "respond", "max_tokens": 401}, ALLOW],
        [{"id": "x", "action": "respond", "deadline_ms": 10_001}, ALLOW],
        [{"id": "x", "action": "allow", "when": {"tier": "imagined"}}, ALLOW],
        [{"id": "x", "action": "allow", "when": {"inputs_min": 0}}, ALLOW],
    ],
)
def test_a_bad_version_2_file_is_refused_at_load(tmp_path, rules):
    with pytest.raises(ValueError):
        RuleSet.load(write(tmp_path, 2, rules))


def test_the_shipped_v2_set_loads_and_ends_in_allow():
    rules = RuleSet.load(V2)
    assert [r.action for r in rules.rules] == [Action.PLANT_TOKEN, Action.RESPOND, Action.ALLOW]


# ------------------------------------------------------------------ conditions


def features(**over) -> dict:
    return {"inputs_so_far": 0, "last_tactic": None, "token_planted": False} | over


def test_each_context_condition(tmp_path):
    def matches(when: dict, request: DecideRequest, feats: dict, tactic: str | None = None) -> bool:
        rs = RuleSet.load(write(tmp_path, 2, [{"id": "x", "action": "delay", "when": when}, ALLOW]))
        return rs.decide(request, feats, tactic).id == "x"

    assert matches({"tier": "none"}, req(), features())
    assert not matches({"tier": "none"}, req(tier="emulated"), features())
    assert not matches({"tier": ["emulated", "rendered"]}, req(), features())
    assert not matches({"inputs_min": 3}, req(), features(inputs_so_far=1))
    assert matches({"inputs_min": 3}, req(), features(inputs_so_far=2))  # the third input
    assert matches({"inputs_max": 1}, req(), features()) and not matches(
        {"inputs_max": 1}, req(), features(inputs_so_far=1)
    )
    assert matches({"tactic": "TA0006"}, req(), features(), "TA0006")
    assert not matches({"tactic": "TA0006"}, req(), features(), "TA0007")
    assert matches({"tactic": "unknown"}, req(), features(), None)
    assert matches({"last_tactic": "TA0007"}, req(), features(last_tactic="TA0007"))
    assert not matches({"last_tactic": "TA0007"}, req(), features())
    assert matches({"actor_class": "human"}, req(), features(actor_class="human"))
    assert matches({"actor_class": "unknown"}, req(), features())
    assert not matches({"not_actor_class": "scanner"}, req(), features(actor_class="scanner"))
    assert matches({"not_actor_class": "scanner"}, req(), features())  # not known to be one
    assert matches({"token_planted": False}, req(), features())
    assert not matches({"token_planted": False}, req(), features(token_planted=True))
    # A rule on the context cannot match where there is no context to read.
    rs = RuleSet.load(
        write(tmp_path, 2, [{"id": "x", "action": "delay", "when": {"tier": "none"}}, ALLOW])
    )
    assert rs.decide(req()).id == "all"


def test_a_rule_whose_action_is_masked_is_passed_over():
    rules = RuleSet.load(V2)
    ready = frozenset({Action.RESPOND})
    assert rules.decide(req(), features(), None, ready).action is Action.RESPOND
    assert rules.decide(req(), features(), None, frozenset()).action is Action.ALLOW
    # Credential-seeking, with a token to plant and none planted yet: plant first.
    both = frozenset({Action.RESPOND, Action.PLANT_TOKEN})
    assert rules.decide(req(), features(), "TA0006", both).action is Action.PLANT_TOKEN
    assert (
        rules.decide(req(), features(token_planted=True), "TA0006", both).action is Action.RESPOND
    )


# ------------------------------------------------------------------ the mask


def test_respond_needs_support_an_unknown_command_and_budget():
    context = Context()
    feats = context.observe(req(), None)
    assert v2_allowed(req(), feats, context) == [Action.RESPOND]
    assert v2_allowed(req(supports=[]), feats, context) == []
    assert v2_allowed(req(tier="emulated"), feats, context) == []
    assert v2_allowed(req(tier="rendered"), feats, context) == []
    assert v2_allowed(req(tier=None), feats, context) == []
    assert v2_allowed(req(), feats | {"respond_budget_left": "none"}, context) == []


def test_plant_token_needs_a_reserve_and_happens_once():
    context = Context()
    feats = context.observe(req(), None)
    assert Action.PLANT_TOKEN not in v2_allowed(req(), feats, context)
    assert Action.PLANT_TOKEN in v2_allowed(req(), feats, context, reserve=True)
    planted = feats | {"token_planted": True}
    assert Action.PLANT_TOKEN not in v2_allowed(req(), planted, context, reserve=True)
    assert Action.PLANT_TOKEN not in v2_allowed(
        req(supports=["respond"]), feats, context, reserve=True
    )


def test_escalate_needs_the_host_flag_three_inputs_a_lab_source_and_no_scanner():
    context = Context()
    lab = {"src": {"ip": "198.18.0.7", "port": 1}}
    context.observe(req(**lab), None)
    context.observe(req(**lab), None)
    third = context.observe(req(**lab), None)
    assert Action.ESCALATE in v2_allowed(req(**lab), third, context, host_ready=True)
    assert Action.ESCALATE not in v2_allowed(req(**lab), third, context)  # no flag
    assert Action.ESCALATE not in v2_allowed(
        req(), third, context, host_ready=True
    )  # not a lab source
    early = third | {"inputs_so_far": 1}
    assert Action.ESCALATE not in v2_allowed(req(**lab), early, context, host_ready=True)
    scanner = third | {"actor_class": "scanner"}
    assert Action.ESCALATE not in v2_allowed(req(**lab), scanner, context, host_ready=True)


def test_after_an_escalation_nothing_is_faked_and_nothing_new_is_offered():
    context = Context()
    feats = context.observe(req(), None)
    context.record(req(), Action.ESCALATE)
    assert context.escalated("s1")
    assert v2_allowed(req(), feats, context, reserve=True, host_ready=True) == []
    assert allowed_actions(req(seq=5), 4, escalated=True) == [
        Action.ALLOW,
        Action.DELAY,
        Action.TERMINATE,
    ]


# ------------------------------------------------------------------ budgets


@pytest.mark.parametrize(
    ("left", "bucket"), [(0, "none"), (-5, "none"), (1, "low"), (750, "low"), (751, "part"),
                         (2999, "part"), (3000, "full"), (9000, "full")]
)  # fmt: skip
def test_the_budget_bucket(left, bucket):
    assert budget_bucket(left, 3000) == bucket


def test_a_session_is_granted_no_more_than_its_budget():
    context = Context()
    context.observe(req(), None)
    granted = []
    for _ in range(9):
        got = context.grant(req(), 400)
        context.record(req(), Action.RESPOND, got)
        granted.append(got)
    assert granted == [400] * 7 + [200, 0] and sum(granted) == explore.SESSION_TOKEN_BUDGET
    assert context.observe(req(), None)["respond_budget_left"] == "none"
    # Another session of the same source starts with its own, inside the source's day.
    context.observe(req(session_id="s2"), None)
    assert context.grant(req(session_id="s2"), 400) == 400


def test_a_source_is_granted_no_more_than_its_day_and_starts_again_the_next():
    context = Context()
    day = [20_000.0]
    context._clock = lambda: day[0] * 86400
    total = 0
    for n in range(60):
        session = f"s{n}"
        context.observe(req(session_id=session), None)
        got = context.grant(req(session_id=session), 400)
        context.record(req(session_id=session), Action.RESPOND, got)
        total += got
    assert total == explore.SOURCE_TOKEN_BUDGET
    context.observe(req(session_id="other"), None)
    assert context.grant(req(session_id="other", src={"ip": "203.0.113.10"}), 400) == 400
    day[0] += 1
    assert context.grant(req(session_id="other"), 400) == 400


def test_a_decoy_that_reports_what_was_spent_is_charged_that_and_not_its_grants():
    # As measured: a grant is 400, the median answer uses 50, a cached one nothing. Counting
    # grants cut a session off after seven answers (the test above, still true of a decoy
    # that reports nothing); counting what was spent lets it go on while tokens are left.
    context = Context()
    spent = 0
    for n in range(40):
        ask = req(respond_spent=spent, seq=n + 1)
        context.observe(ask, None)
        assert context.grant(ask, 400) == 400, n
        context.record(ask, Action.RESPOND, 400)
        spent += 50 if n % 2 else 0  # every other answer came from the cache
    assert spent == 1000
    assert context.observe(req(respond_spent=spent), None)["respond_budget_left"] == "part"
    # What is left is the session's budget less what was really used.
    context.observe(req(respond_spent=2900), None)
    assert context.grant(req(), 400) == 100
    assert context.observe(req(respond_spent=3000), None)["respond_budget_left"] == "none"
    assert context.grant(req(), 400) == 0


def test_the_reported_count_only_grows_and_the_source_is_charged_the_difference():
    context = Context()
    context._clock = lambda: 20_000.0 * 86400
    context.observe(req(respond_spent=500), None)
    context.observe(req(respond_spent=200), None)  # a decoy that began again: ignored
    context.observe(req(respond_spent=700), None)
    assert context.source_budget_left("198.18.0.5") == explore.SOURCE_TOKEN_BUDGET
    ip = req().src.ip
    assert context.source_budget_left(ip) == explore.SOURCE_TOKEN_BUDGET - 700
    # Grants to a reporting session are not charged to the source a second time.
    context.record(req(respond_spent=700), Action.RESPOND, 400)
    assert context.source_budget_left(ip) == explore.SOURCE_TOKEN_BUDGET - 700
    # Another session of that source, whose decoy reports nothing, is charged its grants.
    context.observe(req(session_id="old"), None)
    context.record(req(session_id="old"), Action.RESPOND, 400)
    assert context.source_budget_left(ip) == explore.SOURCE_TOKEN_BUDGET - 1100
    # A request with no session has nothing to count against.
    context.observe(req(session_id=None, respond_spent=9999), None)
    assert context.source_budget_left(ip) == explore.SOURCE_TOKEN_BUDGET - 1100


def test_the_service_keeps_answering_respond_while_the_reported_spend_is_inside_the_budget(
    tmp_path,
):
    c, log = client(tmp_path)
    decisions = [post(c, request_id=f"r{n}", seq=n + 1, respond_spent=60 * n) for n in range(30)]
    assert [d["action"] for d in decisions] == ["respond"] * 30
    assert all(d["budget"]["max_tokens"] == 400 for d in decisions)
    assert records(log)[-1]["context"]["respond_budget_left"] == "part"
    # Out of tokens, the rules fall back as before.
    last = post(c, request_id="out", seq=31, respond_spent=3000)
    assert last["action"] == "allow"


# ------------------------------------------------------------------ the service


def test_the_service_answers_an_unknown_command_with_respond_and_a_budget(tmp_path):
    c, log = client(tmp_path)
    d = post(c)
    assert d["action"] == "respond" and d["rule_id"] == "v2.respond-to-the-unknown"
    assert d["budget"] == {"max_tokens": 400, "deadline_ms": 10000}
    (r,) = records(log)
    assert r["eligible_v2"] == ["respond"]
    assert r["context"]["rule_action"] == "allow" and r["context"]["rule_action_v2"] == "respond"
    assert r["request"]["supports"] == ["respond", "plant_token", "escalate"]
    assert r["request"]["tier"] == "none"


def test_it_never_returns_an_action_the_decoy_did_not_list(tmp_path):
    c, _ = client(tmp_path)
    for body in (
        {"supports": []},
        {"supports": ["plant_token"]},
        {"protocol": "http", "argv": None, "method": "GET", "path": "/x", "supports": []},
    ):
        d = post(c, **body)
        assert d["action"] == "allow" and "budget" not in d, body
    # A decoy that says nothing at all (contract v1) is answered as in phase 2.
    plain = {
        "request_id": "r9",
        "session_id": "v1",
        "protocol": "ssh",
        "argv": ["nosuch"],
        "known": False,
    }
    r = c.post("/v1/decide", json=plain, headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.json()["action"] == "allow"


def test_a_command_the_decoy_can_answer_is_left_to_it(tmp_path):
    c, _ = client(tmp_path)
    assert post(c, tier="emulated", known=True)["action"] == "allow"
    assert post(c, tier="rendered", known=True)["action"] == "allow"


def test_the_session_s_budget_runs_out_and_the_rules_fall_back_to_allow(tmp_path):
    c, log = client(tmp_path)
    decisions = [post(c, request_id=f"r{n}", seq=n + 1) for n in range(10)]
    assert [d["action"] for d in decisions] == ["respond"] * 8 + ["allow"] * 2
    assert [d["budget"]["max_tokens"] for d in decisions[:8]] == [400] * 7 + [200]
    last = records(log)[-1]
    assert last["context"]["respond_budget_left"] == "none" and last["eligible_v2"] == []
    assert last["context"]["previous_action"] == "allow"
    assert records(log)[1]["context"]["previous_action"] == "respond"
    assert records(log)[1]["context"]["had_non_allow"] is True


def test_the_allow_all_set_is_unchanged_by_a_decoy_that_supports_more(tmp_path):
    c, _ = client(tmp_path, RULES_DIR / "default.yaml")
    d = post(c)
    assert d["action"] == "allow" and d["rule_id"] == "default-allow"


def test_plant_token_stays_masked_until_a_reserve_exists(tmp_path):
    # A credential-seeking input: the rule is there, and nothing to plant yet (step 6).
    c, log = client(tmp_path)
    d = post(c, argv=["cat", "/etc/shadow"], tier="emulated", known=True)
    assert d["action"] == "allow"
    assert "plant_token" not in records(log)[0]["eligible_v2"]


def test_the_rule_set_is_chosen_by_name(monkeypatch, tmp_path):
    monkeypatch.setenv("POLICY_TOKEN", TOKEN)
    monkeypatch.setenv("POLICY_LOG", str(tmp_path / "d.json"))
    monkeypatch.delenv("POLICY_RULES", raising=False)
    monkeypatch.delenv("POLICY_SELFTEST", raising=False)
    monkeypatch.setenv("POLICY_RULESET", "v2")
    assert Settings.from_env().rule_files == [V2]
    monkeypatch.delenv("POLICY_RULESET")
    assert Settings.from_env().rule_files == [RULES_DIR / "default.yaml"]
    monkeypatch.setenv("POLICY_RULESET", "imagined")
    with pytest.raises(SystemExit, match="no rule set"):
        Settings.from_env()


def test_respond_is_never_eligible_for_a_program_that_is_not_there(tmp_path: Path):
    """The decoy's shell answers "command not found" itself, and that is the true answer."""
    c, log = client(tmp_path)
    body = req(argv=["no-such-program"], tier="absent").model_dump(mode="json")
    answer = c.post("/v1/decide", headers={"Authorization": f"Bearer {TOKEN}"}, json=body)
    assert answer.status_code == 200 and answer.json()["action"] != "respond"
    record = json.loads(log.read_text().splitlines()[-1])
    assert "respond" not in record.get("eligible_v2", [])
