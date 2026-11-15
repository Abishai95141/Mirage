"""A learned policy saved as JSON, loaded as the shadow."""

from __future__ import annotations

import json

import pytest

from mirage_policy import shadow_json
from mirage_policy.explore import BanditPolicy
from mirage_policy.shadow import FALLBACK_NAME, load_shadow
from mirage_schema.policy import Action

ALLOWED = [Action.ALLOW, Action.DELAY, Action.FAKE_SUCCESS, Action.FAKE_ERROR, Action.TERMINATE]
CONTEXT = {
    "protocol": "ssh", "verb": "foo", "verb_class": "other", "known": False, "inputs_so_far": 3,
    "seconds_since_last": 0.4, "last_tactic": None, "seen_before": False,
    "seen_before_in_session": False, "rule_action": "allow",
}  # fmt: skip
TABLE = {
    "kind": "table",
    "name": "table(support>=30)",
    "levels": [["protocol", "known"], ["protocol"]],
    "min_support": 30.0,
    "margin": 0.0,
    "cells": [
        {
            "ssh|unknown": {
                "allow": [1.0, 400.0],
                "fake_success": [3.0, 60.0],
                "delay": [0.5, 10.0],
            },
            "ssh|known": {"allow": [1.0, 400.0], "fake_success": [0.4, 60.0]},
        },
        {"ssh": {"allow": [1.0, 800.0], "fake_success": [1.7, 120.0], "terminate": [-2.0, 90.0]}},
    ],
}
LINEAR = {
    "kind": "linear",
    "name": "linear(ridge=1,ipw)",
    "features": ["known=known", "known=unknown", "protocol=ssh"],
    "weights": {"allow": [0.0, 0.0, 0.0, 1.0], "fake_success": [-0.6, 2.0, 0.0, 1.0]},
}


def write(tmp_path, model, name="shadow.json"):
    path = tmp_path / name
    path.write_text(json.dumps(model))
    return path


@pytest.mark.parametrize("model", [TABLE, LINEAR], ids=["table", "linear"])
def test_a_saved_policy_becomes_the_shadow_and_answers_a_distribution(tmp_path, model):
    shadow = load_shadow(write(tmp_path, model), BanditPolicy())
    assert shadow.name == f"learned({model['name']})" and shadow.name != FALLBACK_NAME
    assert len(shadow.version) == 12
    probs = shadow.probabilities(CONTEXT, ALLOWED)
    assert set(probs) == set(ALLOWED) and abs(sum(probs.values()) - 1.0) < 1e-9
    assert max(probs, key=probs.get) is Action.FAKE_SUCCESS  # unknown input: fake it
    assert abs(probs[Action.FAKE_SUCCESS] - 0.92) < 1e-9 and abs(probs[Action.DELAY] - 0.02) < 1e-9
    known = shadow.probabilities({**CONTEXT, "known": True}, ALLOWED)
    assert max(known, key=known.get) is Action.ALLOW


def test_the_choice_never_leaves_the_allowed_set(tmp_path):
    shadow = load_shadow(write(tmp_path, TABLE), BanditPolicy())
    masked = [Action.ALLOW, Action.DELAY]  # what it would choose is not allowed for this input
    probs = shadow.probabilities(CONTEXT, masked)
    assert set(probs) == set(masked) and max(probs, key=probs.get) is Action.ALLOW


def test_a_table_backs_off_when_the_fine_bucket_knows_too_little(tmp_path):
    thin = json.loads(json.dumps(TABLE))
    thin["cells"][0]["ssh|unknown"]["fake_success"] = [3.0, 5.0]  # too few to trust here
    shadow = load_shadow(write(tmp_path, thin), BanditPolicy())
    probs = shadow.probabilities(CONTEXT, ALLOWED)
    assert max(probs, key=probs.get) is Action.FAKE_SUCCESS  # the coarser bucket still says so


@pytest.mark.parametrize(
    "bad",
    [
        {"kind": "neural"},
        {"kind": "table", "levels": [["protocol"]], "cells": [], "min_support": 1},
        {"kind": "linear", "features": ["a"], "weights": {"allow": [1.0]}},
        ["not", "an", "object"],
    ],
)
def test_a_file_that_is_not_a_policy_falls_back_and_says_so(tmp_path, bad, caplog):
    shadow = load_shadow(write(tmp_path, bad), BanditPolicy())
    assert shadow.name == FALLBACK_NAME


def test_an_oversized_file_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(shadow_json, "MAX_BYTES", 10)
    with pytest.raises(ValueError, match="too large"):
        shadow_json.load(write(tmp_path, TABLE))


def test_a_coarse_bucket_does_not_bring_back_what_a_fine_one_ruled_out(tmp_path):
    # For a known input the fine bucket has plenty of evidence that faking success is worse
    # than allowing (0.4 against 1.0). The coarse bucket, which mixes known and unknown inputs,
    # says it is better on average (1.7). The fine evidence must win.
    shadow = load_shadow(write(tmp_path, TABLE), BanditPolicy())
    known = shadow.probabilities({**CONTEXT, "known": True}, ALLOWED)
    assert max(known, key=known.get) is Action.ALLOW
    # ...while an action the fine bucket never saw can still come from the coarse one
    richer = json.loads(json.dumps(TABLE))
    richer["cells"][1]["ssh"]["delay"] = [2.5, 200.0]
    shadow = load_shadow(write(tmp_path, richer, "richer.json"), BanditPolicy())
    known = shadow.probabilities({**CONTEXT, "known": True}, ALLOWED)
    assert max(known, key=known.get) is Action.DELAY
