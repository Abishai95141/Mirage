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


def test_the_rule_calls_a_session_without_access_a_scanner():
    assert classifier.rule_label(row("scanner", "test", auth_success=0, inputs=0)) == "scanner"
    assert classifier.rule_label(row("scripted_bot", "test", auth_success=1, inputs=5)) is None
    # requests to a web decoy with no login: no access, whatever sent them
    swept = row("scripted_bot", "test", protocol="http", auth_success=0, inputs=4)
    assert classifier.rule_label(swept) == "scanner"
    # commands to a service that asks for no login are activity with access: the model's call
    poked = row("scripted_bot", "test", protocol="redis", auth_success=0, inputs=4)
    assert classifier.rule_label(poked) is None


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


def test_every_family_separates_clearly_different_classes():
    rng = random.Random(0)
    train_rows, test_rows = synthetic(80, "train", rng), synthetic(25, "test", rng)
    for family in classifier.FAMILIES:
        model = classifier.train(train_rows, family=family)
        pred = model.predict(test_rows)
        right = sum(p == r["actor_class"] for p, r in zip(pred, test_rows, strict=True))
        assert right / len(test_rows) > 0.9, family
        # the silent-scanner rule decides its case, the model the rest
        who = {w for _, _, w in model.decide(test_rows)}
        assert who == {"rule", "model"}, family


def test_training_with_one_class_makes_no_model():
    model = classifier.train(
        [row("scripted_bot", "train", inputs=3, auth_success=1) for _ in range(5)]
    )
    assert model.estimator is None
    assert model.predict([row("scripted_bot", "test", inputs=3, auth_success=1)]) == [
        "scripted_bot"
    ]
    assert model.decide([row("scripted_bot", "test", inputs=3, auth_success=1)])[0][2] == "majority"


def test_majority_baseline_is_the_most_frequent_class_not_alphabetical():
    # Regression guard for the review's #8: the baseline returned classes[0] (alphabetical).
    rows = [row("human", "train", auth_success=1, inputs=4) for _ in range(20)]
    rows += [row("scripted_bot", "train", auth_success=1, inputs=8) for _ in range(4)]
    assert classifier.train(rows).majority == "human"
    rows = [row("scripted_bot", "train", auth_success=1, inputs=8) for _ in range(20)]
    rows += [row("human", "train", auth_success=1, inputs=4) for _ in range(4)]
    assert classifier.train(rows).majority == "scripted_bot"


def test_a_saved_model_predicts_the_same_and_is_plain_json(tmp_path):
    rng = random.Random(1)
    train_rows, test_rows = synthetic(60, "train", rng), synthetic(20, "test", rng)
    for family in classifier.FAMILIES:
        model = classifier.train(train_rows, family=family)
        path = model.save(tmp_path / family)
        body = path.read_text()
        assert body.lstrip().startswith("{") and "version" in body
        again = classifier.Model.load(tmp_path / family)
        assert again.predict(test_rows) == model.predict(test_rows), family
        assert again.version == model.version and again.features == model.features


def test_the_plain_forest_answers_as_scikit_learn_does():
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier

    rng = np.random.default_rng(0)
    x = rng.normal(size=(300, 6)) * [1, 10, 100, 1, 1e-3, 1e4]
    y = (x[:, 0] > 0).astype(int) + (x[:, 1] > 5).astype(int)
    fitted = RandomForestClassifier(
        n_estimators=25, min_samples_leaf=2, class_weight="balanced", random_state=0
    ).fit(x, y)
    plain = classifier.Forest.from_sklearn(fitted)
    fresh = rng.normal(size=(200, 6)) * [1, 10, 100, 1, 1e-3, 1e4]
    for data in (x, fresh):
        assert np.allclose(plain.predict_proba(data), fitted.predict_proba(data), atol=1e-9)
    # ... and survives its JSON form (values are rounded to six places when saved)
    again = classifier.Forest.from_json(plain.to_json())
    assert np.allclose(again.predict_proba(fresh), plain.predict_proba(fresh), atol=1e-5)


def test_a_saved_forest_that_could_loop_or_does_not_fit_is_refused(tmp_path):
    import json

    rng = random.Random(4)
    model = classifier.train(synthetic(30, "train", rng), family="forest")
    path = model.save(tmp_path)
    body = json.loads(path.read_text())
    looped = json.loads(json.dumps(body))
    looped["forest"]["left"][0][0] = 0  # the root as its own child
    path.write_text(json.dumps(looped))
    with pytest.raises(ValueError, match="point forward"):
        classifier.Model.load(tmp_path)
    short = json.loads(json.dumps(body))
    short["forest"]["value"] = short["forest"]["value"][:-1]
    path.write_text(json.dumps(short))
    with pytest.raises(ValueError, match="same number of trees"):
        classifier.Model.load(tmp_path)
    narrow = json.loads(json.dumps(body))
    narrow["features"] = narrow["features"][:1]
    path.write_text(json.dumps(narrow))
    with pytest.raises(ValueError, match="does not match"):
        classifier.Model.load(tmp_path)


def test_the_fast_macro_f1_is_scikit_learns():
    import numpy as np
    from sklearn.metrics import f1_score

    rng = np.random.default_rng(3)
    names = np.array(["human", "scanner", "scripted_bot", "llm_agent"])
    for labels in (["human", "scanner", "scripted_bot"], ["human", "scripted_bot"]):
        for _ in range(50):
            n = int(rng.integers(1, 40))
            truth = names[rng.integers(0, 3, n)]
            pred = names[rng.integers(0, 4, n)]  # a prediction may be outside the scored labels
            k, over, (t, p) = classifier.encode(labels, truth, pred)
            want = f1_score(truth, pred, labels=labels, average="macro", zero_division=0)
            assert classifier.macro_f1_codes(t, p, k, over) == pytest.approx(want, abs=1e-12)


def test_two_candidates_under_one_seed_line_up_session_for_session():
    rng = random.Random(5)
    rows = []
    for i in range(12):
        for r in synthetic(3, "train", rng):
            rows.append({**r, "scenario_id": f"sc-{i}", "group": f"sc-{i // 2}"})
    a = classifier.out_of_fold(rows, seed=1, family="logreg")
    b = classifier.out_of_fold(rows, seed=1, family="forest", features=classifier.FEATURES_EVENT)
    assert (a.truth == b.truth).all() and (a.group == b.group).all()
    assert (a.is_open == b.is_open).all() and len(a.truth) == len(rows)
    other = classifier.out_of_fold(rows, seed=2, family="logreg")
    assert sorted(other.group.tolist()) == sorted(a.group.tolist())


def test_the_model_reads_only_the_features_it_was_given():
    rng = random.Random(2)
    rows = synthetic(40, "train", rng)
    event_only = classifier.train(rows, classifier.FEATURE_SETS["event"])
    assert event_only.features == classifier.FEATURE_SETS["event"]
    assert not set(event_only.features) & set(classifier.FEATURE_SETS["tty"])
    # a row with no keystroke columns at all is still scored by the event-level model
    bare = {k: v for k, v in rows[1].items() if not k.startswith("tty_")}
    assert event_only.predict([bare])[0] in classifier.CLASSES


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

    def spy(learn, *args, **kwargs):
        seen.extend(learn)
        return original(learn, *args, **kwargs)

    monkeypatch.setattr(classifier, "train", spy)
    report = classifier.cross_validate(rows, draws=50)
    assert not any(r["real"] for r in seen)
    assert report.n_test == len(rows)  # the recordings are still predicted


def test_the_session_label_is_scored_when_the_dataset_has_one():
    row = {"actor_class": "scripted_bot", "label": "scanner", "scenario_id": "x"}
    assert classifier.label_of(row) == "scanner"
    assert classifier.label_of({"actor_class": "human", "scenario_id": "x"}) == "human"


def test_the_gate_is_computed_on_the_sessions_the_rule_leaves():
    # Rule-settled sessions are right by definition (the rule and the label share a
    # definition), so the gate must not count them.
    rows = _scenarios(random.Random(6))
    report = classifier.cross_validate(rows, draws=200)
    open_n = report.n_test - report.rule_settled
    assert report.model_only["n"] == open_n == 96  # bots and humans; the scanners are settled
    assert set(report.model_only["support"]) == {"human", "scripted_bot"}
    assert report.model_only["macro_f1"] > report.model_only["majority_f1"]
    assert report.beats_majority() and report.model_only["vs_majority_ci"][0] > 0
    # a model no better than the majority on those sessions fails the gate, however many
    # scanners the rule gets right
    same = [
        _row(c, random.Random(i), scenario_id=f"g-{i % 6}", auth_success=1, inputs=5)
        for i, c in enumerate(["scripted_bot", "human"] * 30)
    ]
    silent = [
        _row("scanner", random.Random(i), scenario_id=f"s-{i % 6}", auth_success=0, inputs=0)
        for i in range(60)
    ]
    flat = classifier.cross_validate(same + silent, draws=200)
    assert flat.per_class_f1["scanner"] == 1.0  # the rule, counted in the all-session figure
    assert not flat.beats_majority()


# ------------------------------------------------------------------ the worker


class FakeStore:
    def __init__(self, features):
        self.features, self.inserted, self.queries = features, [], []

    def rows(self, sql):
        self.queries.append(sql)
        if "actor_class FINAL" in sql and "feat" not in sql:
            done = {r["session_id"]: r["version"] for r in self.inserted}
            return [
                {"session_id": f["session_id"]}
                for f in self.features
                if done.get(f["session_id"], 0) < f["summary_version"]
            ]
        # the feature query names the sessions it wants, as the real store would honour
        return [f for f in self.features if f"'{f['session_id']}'" in sql]

    def insert(self, table, rows):
        assert table == "mirage.actor_class"
        self.inserted.extend(rows)


def _feat(sid, version=1, **over):
    base = {
        "session_id": sid, "summary_version": version, "protocol": "ssh", "inputs": 0,
        "auth_attempts": 1, "auth_success": 0, "duration_s": 1.0, "n_inputs": 0, "n_unknown": 0,
        "gap_min_s": 0.0, "gap_max_s": 0.0, "gap_mean_s": 0.0, "gap_median_s": 0.0,
        "tty_input_chunks": 0, "tty_single_byte_chunks": 0, "tty_backspaces": 0,
        "tty_paste_bursts": 0, "tty_lines": 0, "tty_key_gap_p50_s": 0.0,
    }  # fmt: skip
    base.update(over)
    return base


def test_the_worker_writes_predictions_and_reclassifies_a_session_that_grew():
    from mirage_intel import classify_worker as cw

    model = classifier.train(synthetic(60, "train", random.Random(8)))
    bot = _feat("bot", inputs=12, auth_success=1, gap_mean_s=0.1, gap_median_s=0.1, duration_s=2.0)
    store = FakeStore([_feat("silent"), bot])
    assert cw.step(store, model, {}) == 2
    by = {r["session_id"]: r for r in store.inserted}
    assert by["silent"]["actor_class"] == "scanner" and by["silent"]["decided_by"] == "rule"
    assert by["bot"]["actor_class"] == "scripted_bot" and by["bot"]["decided_by"] == "model"
    assert by["bot"]["model_version"] == model.version and by["bot"]["version"] == 1
    assert cw.step(store, model, {}) == 0  # nothing has changed
    # the silent session logs in and starts typing slowly: its summary version moves on
    store.features[0] = _feat(
        "silent",
        version=2,
        inputs=5,
        auth_success=1,
        gap_mean_s=6.0,
        gap_median_s=6.0,
        duration_s=60.0,
    )
    assert cw.step(store, model, {}) == 1
    assert store.inserted[-1]["actor_class"] == "human" and store.inserted[-1]["version"] == 2
    # nothing the worker reads is a ground-truth table
    assert not any("sim_" in q for q in store.queries)


def test_without_a_model_only_the_rule_is_applied_and_nothing_is_guessed(tmp_path):
    from mirage_intel import classify_worker as cw

    assert cw.load_model(tmp_path / "missing") is None
    store = FakeStore([_feat("silent"), _feat("busy", inputs=9, auth_success=1)])
    skipped: dict[str, int] = {}
    assert cw.step(store, None, skipped) == 1
    assert [r["session_id"] for r in store.inserted] == ["silent"]
    assert skipped == {"busy": 1}  # remembered, so it is not recomputed until it changes
    assert cw.step(store, None, skipped) == 0


def test_the_pick_is_the_simplest_candidate_shown_to_be_within_the_margin():
    from mirage_intel.experiments import classifier_bench as bench

    def candidate(name, rank, f1, gap):
        return {"name": name, "rank": rank, "model_only_macro_f1": f1, "best_minus_this_ci": gap}

    best = candidate("forest/both", (1, 2), 0.90, [0.0, 0.0])
    # Much worse, but its own interval overlapped the best one's: the old rule chose it.
    worse = candidate("logreg/event", (0, 0), 0.72, [0.05, 0.31])
    # Cannot be told apart from the best, which is not the same as being as good.
    unclear = candidate("logreg/both", (0, 2), 0.88, [-0.04, 0.09])
    assert bench.pick([worse, unclear, best])["name"] == "forest/both"
    # Shown to give up at most the margin: now the simpler one is the pick.
    close = candidate("logreg/both", (0, 2), 0.895, [-0.01, bench.MARGIN])
    assert bench.pick([worse, close, best])["name"] == "logreg/both"


def test_the_bench_compares_candidates_on_the_same_sessions():
    from mirage_intel.experiments import classifier_bench as bench

    rng = random.Random(6)
    rows = []
    for i in range(20):
        for r in synthetic(2, "train", rng):
            rows.append({**r, "scenario_id": f"sc-{i}", "group": f"sc-{i // 2}"})
    results, chosen = bench.run(rows, seeds=[0, 1], draws=60)
    by_name = {r["name"]: r for r in results}
    assert len(results) == 9
    # One choice per served variant, each among the candidates of its own feature set and
    # compared with the best of that set.
    assert chosen["full"]["features"] == "both" and chosen["event"]["features"] == "event"
    for r in results:
        assert by_name[r["best_of_set"]]["features"] == r["features"]
    assert by_name[chosen["full"]["best_of_set"]]["best_minus_this_ci"] == [0.0, 0.0]
    # The synthetic rows carry no keystroke data, so a keystroke-only model knows nothing and
    # the ablation says the full model gains over it, and nothing over the event features.
    assert chosen["full"]["gain_over"]["tty"][0] > bench.MARGIN
    assert chosen["full"]["gain_over"]["event"][1] <= bench.MARGIN
    assert by_name["logreg/event"]["model_only_macro_f1"] > 0.9
    # Every candidate is described over the same sessions and groups.
    assert len({(r["n"], r["groups"], r["rule_settled"]) for r in results}) == 1
    assert sum(chosen["full"]["mistakes"].values()) >= 0
