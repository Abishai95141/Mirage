"""Actor classifier: the rule, the feature guard, and that the model beats the baselines on
separable synthetic data. Synthetic rows only — no lab content."""

from __future__ import annotations

import random

import pytest
from mirage_intel import classifier
from mirage_intel.dataset import FEATURES

pytestmark = pytest.mark.ml


def row(actor_class: str, split: str, **over) -> dict:
    base = dict.fromkeys(FEATURES, 0.0)
    base.update(
        {
            "session_id": f"s{random.random()}",
            "actor_class": actor_class,
            "protocol": "ssh",
            "scenario_id": "x",
            "real": False,
            "split": split,
        }
    )
    base.update(over)
    return base


def test_rule_labels_a_silent_session_as_scanner():
    assert classifier.rule_label(row("scanner", "test", auth_success=0, inputs=0)) == "scanner"
    assert classifier.rule_label(row("scripted_bot", "test", auth_success=1, inputs=5)) is None


def test_features_are_not_identity_or_ground_truth():
    classifier.check_no_forbidden_features()  # raises if a forbidden column leaked in


def synthetic(n: int, split: str, rng: random.Random) -> list[dict]:
    rows = []
    for _ in range(n):
        # scanner: no login, no input. bot: fast, regular, many inputs. human: slow, irregular.
        rows.append(
            row("scanner", split, auth_success=0, inputs=0, auth_attempts=rng.randint(1, 9))
        )
        rows.append(
            row(
                "scripted_bot",
                split,
                auth_success=1,
                inputs=rng.randint(6, 20),
                gap_mean_s=rng.uniform(0.05, 0.3),
                gap_median_s=rng.uniform(0.05, 0.3),
                duration_s=rng.uniform(1, 5),
                auth_attempts=rng.randint(1, 6),
            )
        )
        rows.append(
            row(
                "human",
                split,
                auth_success=1,
                inputs=rng.randint(3, 10),
                gap_mean_s=rng.uniform(3, 9),
                gap_median_s=rng.uniform(3, 9),
                duration_s=rng.uniform(20, 90),
                auth_attempts=1,
            )
        )
    return rows


def test_model_beats_rules_and_majority_on_separable_data():
    rng = random.Random(0)
    model = classifier.train(synthetic(80, "train", rng))
    report = classifier.evaluate(model, synthetic(25, "test", rng))
    assert report.macro_f1 > report.rules_only_f1
    assert report.macro_f1 > report.majority_f1
    assert report.macro_f1 > 0.8  # the three classes are clearly separable here
    # the silent-scanner rule is right where it fires
    assert report.per_class_f1["scanner"] > 0.9


def test_training_with_one_class_makes_no_model():
    model = classifier.train(
        [row("scripted_bot", "train", inputs=3, auth_success=1) for _ in range(5)]
    )
    assert model.booster is None
    assert model.predict([row("scripted_bot", "test", inputs=3, auth_success=1)]) == [
        "scripted_bot"
    ]
