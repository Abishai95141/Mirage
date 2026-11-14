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


def test_majority_baseline_is_the_most_frequent_class_not_alphabetical():
    # Regression guard for the review's #8: _majority returned classes[0] (alphabetical).
    # 'human' sorts after 'bot-ish' names but is the most frequent here; make it dominate.
    rows = [row("human", "train", auth_success=1, inputs=4) for _ in range(20)]
    rows += [row("scripted_bot", "train", auth_success=1, inputs=8) for _ in range(4)]
    model = classifier.train(rows)
    assert model.majority == "human"
    assert classifier._majority(model) == "human"
    # a one-class model predicts the majority, not classes[0]
    one = classifier.train([row("human", "train", auth_success=1, inputs=4) for _ in range(5)])
    assert one.predict([row("human", "test", auth_success=1, inputs=4)]) == ["human"]


def _scenarios(rng, per_class=6, sessions=8):
    """Separable synthetic sessions, several scenarios per class."""
    rows = []
    for g in range(per_class):
        for _ in range(sessions):
            rows.append(_row("scanner", rng, scenario_id=f"scan-{g}", auth_success=0, inputs=0))
            rows.append(
                _row(
                    "scripted_bot",
                    rng,
                    scenario_id=f"bot-{g}",
                    auth_success=1,
                    inputs=rng.randint(5, 15),
                    gap_mean_s=rng.uniform(0.05, 0.3),
                    duration_s=rng.uniform(1, 4),
                )
            )
            rows.append(
                _row(
                    "human",
                    rng,
                    scenario_id=f"typed-{g}",
                    group=f"bot-{g}",  # a human-paced twin of the bot scenario
                    auth_success=1,
                    inputs=rng.randint(5, 15),
                    gap_mean_s=rng.uniform(3, 8),
                    duration_s=rng.uniform(20, 70),
                )
            )
    return rows


def _row(cls, rng, **over):
    base = dict.fromkeys(FEATURES, 0.0)
    base.update(
        {
            "session_id": f"s{rng.random()}",
            "actor_class": cls,
            "protocol": "ssh",
            "real": False,
            "split": "train",
        }
    )
    base.update(over)
    return base


def test_folds_keep_a_scenario_and_its_variants_together():
    rows = _scenarios(random.Random(1))
    folds = classifier.assign_folds(rows, k=5)
    assert set(folds) == {classifier.group_of(r) for r in rows}
    # the twin is filed under its base scenario, so both are held out in the same fold
    assert all(classifier.group_of(r) == r.get("group", r["scenario_id"]) for r in rows)
    assert "typed-0" not in folds and "bot-0" in folds
    # every fold holds out some of each class
    for fold in range(5):
        held = {r["actor_class"] for r in rows if folds[classifier.group_of(r)] == fold}
        assert held == {"scanner", "scripted_bot", "human"}


def test_cross_validation_scores_every_session_once_and_beats_the_baselines():
    rows = _scenarios(random.Random(2))
    report = classifier.cross_validate(rows, draws=200)
    assert report.n_test == len(rows) and report.folds == 5 and report.n_groups == 12
    assert report.macro_f1 > 0.9
    assert report.beats_rules() and report.beats_majority()
    assert report.vs_rules_ci[0] > 0 and report.vs_majority_ci[0] > 0
    assert report.support == {"human": 48, "scanner": 48, "scripted_bot": 48}
    assert report.rule_settled == 48  # the silent scanners, decided with no model


def test_cross_validation_needs_scenarios_to_hold_out():
    rng = random.Random(3)
    one_group = [_row("scripted_bot", rng, scenario_id="only", inputs=5) for _ in range(10)]
    assert classifier.cross_validate(one_group) is None


def test_a_single_class_cannot_beat_its_baselines():
    rng = random.Random(4)
    rows = [
        _row("scripted_bot", rng, scenario_id=f"bot-{i % 4}", auth_success=1, inputs=5)
        for i in range(24)
    ]
    report = classifier.cross_validate(rows, draws=100)
    assert not report.beats_rules() and not report.beats_majority()


def test_real_recordings_are_scored_but_never_trained_on(monkeypatch):
    rows = _scenarios(random.Random(5))
    for r in rows:
        if r["actor_class"] == "human" and r["scenario_id"] == "typed-0":
            r["real"] = True
    seen = []
    original = classifier.train

    def spy(learn):
        seen.extend(learn)
        return original(learn)

    monkeypatch.setattr(classifier, "train", spy)
    report = classifier.cross_validate(rows, draws=50)
    assert not any(r["real"] for r in seen)
    assert report.n_test == len(rows)  # the recordings are still predicted


def test_the_session_label_is_scored_when_the_dataset_has_one():
    row = {"actor_class": "scripted_bot", "label": "scanner", "scenario_id": "x"}
    assert classifier.label_of(row) == "scanner"
    assert classifier.label_of({"actor_class": "human", "scenario_id": "x"}) == "human"
