"""The evaluation harness: what it scores, what it refuses, and when the regression job fails.
Synthetic data and harmless texts; a toy embedding stands in for the model."""

from __future__ import annotations

import json
import random

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from mirage_intel import harness
from mirage_intel.dataset import FEATURES, META

pytestmark = pytest.mark.ml

WORDS = ["uname", "whoami", "crontab", "ps", "df", "id"]
CHOICES = {
    "classifier": {"family": "logreg", "features": "both"},
    "classifier_event": {"family": "logreg", "features": "event"},
    "tagger": {
        "name": "retrieval-toy-k1/pieces", "kind": "retrieval", "embedder": "minilm", "k": 1,
        "unit": "pieces", "threshold": 0.5, "atomic": False,
    },
    "policy": {"acting": "rules", "shadow": "linear(ridge=1,ipw)", "reward": "reward"},
}  # fmt: skip


def toy(_corpus):
    def embed(texts):
        rows = np.array(
            [[float(w in t.split()) for w in WORDS] + [0.0] for t in texts], dtype=np.float32
        )
        rows[:, -1] = (rows.sum(axis=1) == 0).astype(np.float32)
        return rows / np.linalg.norm(rows, axis=1, keepdims=True)

    return embed


def session(label, group, rng, **over):
    row = dict.fromkeys(FEATURES, 0.0)
    row.update(
        {
            "session_id": f"s{rng.random()}", "actor_class": label, "label": label,
            "group": group, "protocol": "ssh", "scenario_id": group, "real": False,
            "split": "train",
        }
    )  # fmt: skip
    row.update(over)
    return row


def sessions(separable=True, seed=0):
    rng = random.Random(seed)
    out = []
    for g in range(12):
        for _ in range(4):
            out.append(session("scanner", f"scan-{g % 4}", rng, auth_success=0, inputs=0))
            fast = rng.uniform(0.05, 0.3)
            slow = rng.uniform(3, 8) if separable else fast
            out.append(
                session("scripted_bot", f"bot-{g}", rng, auth_success=1, inputs=8, gap_mean_s=fast)
            )
            out.append(
                session("human", f"human-{g}", rng, auth_success=1, inputs=8, gap_mean_s=slow)
            )
    return out


def step_rows(procedure, technique, text, split, n=0):
    """One SSH step as the export writes it: the typed line and its one gated command."""
    common = {
        "run_id": "r1", "session_ref": f"{procedure}-{n}", "step_id": "s1",
        "session_id": f"sess-{procedure}-{n}", "protocol": "ssh", "input": text,
        "technique_id": technique, "tactic": "TA0007", "procedure_id": procedure,
        "source": "own", "scenario_id": f"sc-{split}", "split": split,
    }  # fmt: skip
    return [
        {**common, "event_id": f"{procedure}-{n}-i", "role": "input", "ts_ms": 1},
        {**common, "event_id": f"{procedure}-{n}-d", "role": "decision", "ts_ms": 2},
    ]


TECH = {"uname": "T1082", "whoami": "T1033", "crontab": "T1053.003", "ps": "T1057", "df": "T1082"}


def steps(model_can_help=True):
    rows = []
    for word, technique in TECH.items():
        rows += step_rows(f"train-{word}", technique, f"{word} -a", "train")
        rows += step_rows(f"dev-{word}", technique, f"{word} -b", "dev")
        for i in range(2):
            # a different rendering of the same technique, never seen in training
            text = f"{word} --flag{i}" if model_can_help else f"unrelated{i} {word[:1]}"
            rows += step_rows(f"test-{word}-{i}", technique, text, "test")
    return rows


def dataset(tmp_path, session_rows=None, step_list=None, decisions=None, manifest=None):
    d = tmp_path / "ds"
    d.mkdir(exist_ok=True)
    pq.write_table(pa.Table.from_pylist(session_rows or sessions()), d / "sessions.parquet")
    pq.write_table(pa.Table.from_pylist(step_list or steps()), d / "steps.parquet")
    if decisions is not None:
        pq.write_table(pa.Table.from_pylist(decisions), d / "decisions.parquet")
    (d / "sessions.manifest.json").write_text(
        json.dumps({"problems": [], "lab_seed": True, "catalogue_sha256": "x", **(manifest or {})})
    )
    return harness.Dataset.load(d)


def result_for(ds):
    return harness.Result(ds.name, ds.identity(), CHOICES)


# ------------------------------------------------------------------ the models


def test_the_classifier_is_scored_on_what_the_rule_leaves_and_gated_on_both_baselines(tmp_path):
    ds = dataset(tmp_path)
    r = result_for(ds)
    harness.score_classifier(ds, CHOICES, r, draws=200)
    assert r.gates["classifier_beats_majority"]["ok"] and r.gates["classifier_beats_rules"]["ok"]
    m = r.metrics["classifier.macro_f1"]
    assert m["value"] > 0.9 and m["ci"][0] <= m["value"] <= m["ci"][1]
    assert "classifier_event.macro_f1" in r.metrics
    assert r.reports["classifier"]["rule_settled"] == 48  # the scanners; never in the gate
    assert set(r.reports["classifier"]["model_only"]["support"]) == {"human", "scripted_bot"}


def test_a_classifier_that_cannot_tell_the_classes_apart_fails_its_gate(tmp_path):
    ds = dataset(tmp_path, session_rows=sessions(separable=False))
    r = result_for(ds)
    harness.score_classifier(ds, CHOICES, r, draws=200)
    assert not r.gates["classifier_beats_majority"]["ok"]
    assert any("classifier_beats_majority" in f for f in r.failures())


def test_the_tagger_is_fitted_on_train_and_dev_and_scored_on_test(tmp_path):
    ds = dataset(tmp_path)
    r = result_for(ds)
    harness.score_tagger(ds, CHOICES, r, draws=200, make_embed=toy, atomic_file=tmp_path / "none")
    assert r.metrics["tagger.micro_f1"]["value"] == 1.0
    assert r.reports["tagger"]["headline"]["procedures"] == 10
    assert r.gates["tagger_beats_most_frequent"]["ok"]
    assert r.metrics["tagger.above_most_frequent"]["ci"][0] > 0
    assert r.checks["index_hygiene"]["ok"]
    # the index holds the ten train and dev texts and none of the ten test ones
    assert r.checks["index_hygiene"]["detail"].startswith("10 index entries; 0 from held-out")


def test_a_tagger_no_better_than_the_most_frequent_technique_fails_its_gate(tmp_path):
    ds = dataset(tmp_path, step_list=steps(model_can_help=False))
    r = result_for(ds)
    harness.score_tagger(ds, CHOICES, r, draws=200, make_embed=toy, atomic_file=tmp_path / "none")
    assert not r.gates["tagger_beats_most_frequent"]["ok"]


def test_a_tagger_that_needs_the_public_corpus_says_so_when_it_is_not_there(tmp_path):
    ds = dataset(tmp_path)
    wants = {**CHOICES, "tagger": {**CHOICES["tagger"], "atomic": True}}
    with pytest.raises(harness.HarnessError, match="Atomic Red Team"):
        harness.score_tagger(ds, wants, result_for(ds), 50, make_embed=toy, atomic_file=None)


def test_the_shadow_policy_is_reported_against_the_rules_or_the_gate_fails(tmp_path):
    ds = dataset(tmp_path)
    r = result_for(ds)
    harness.score_policy(ds, CHOICES, r, draws=100)
    assert not r.gates["shadow_value_reported"]["ok"]  # no decisions: not a silent pass

    from test_bandit import explore_log

    rows = explore_log(n_sessions=120, per_session=5, seed=3)
    for i, row in enumerate(rows):
        row["usable"] = True
        row["split"] = "test" if int(row["session"][1:]) % 4 == 0 else "train"
        row["request_id"] = f"q{i}"
    ds = dataset(tmp_path, decisions=rows)
    r = result_for(ds)
    harness.score_policy(ds, CHOICES, r, draws=100)
    assert r.gates["shadow_value_reported"]["ok"]
    m = r.metrics["policy.shadow_minus_rules"]
    assert m["ci"][0] <= m["value"] <= m["ci"][1]
    assert r.reports["policy"]["decisions"]["sessions"] == 30
    unknown = {**CHOICES, "policy": {**CHOICES["policy"], "shadow": "no-such-learner"}}
    r = result_for(ds)
    harness.score_policy(ds, unknown, r, draws=50)
    assert not r.gates["shadow_value_reported"]["ok"]


# ------------------------------------------------------------------ integrity


def test_no_metric_is_reported_from_a_dataset_that_fails_a_check(tmp_path, monkeypatch):
    ds = dataset(tmp_path)

    def failing(ds, result, allow_unhealthy=False):
        result.check("sessions_one_split", False, "3 of 9 sessions mix splits")

    monkeypatch.setattr(harness, "integrity", failing)
    r = harness.evaluate(ds, CHOICES, draws=50, make_embed=toy)
    assert r.metrics == {} and not r.gates["integrity"]["ok"]
    assert len(r.failures()) == 2  # the check, and the gate that says nothing was reported


def test_the_checks_read_the_data_not_a_constant(tmp_path):
    rows = steps()
    rows[0]["split"] = "test"  # a train step filed under test: its session now mixes splits
    rows.append({**rows[-1], "event_id": "leak", "input": "ping 198.18.0.7"})
    wide = [{**s, "src_ip": "198.18.0.9"} for s in sessions()]
    ds = dataset(tmp_path, session_rows=wide, step_list=rows, manifest={"lab_seed": False})
    r = result_for(ds)
    harness.integrity(ds, r)
    assert not r.checks["sessions_one_split"]["ok"]
    assert not r.checks["procedures_one_split"]["ok"]
    assert not r.checks["session_columns_allowlisted"]["ok"]
    assert "src_ip" in r.checks["session_columns_allowlisted"]["detail"]
    assert not r.checks["no_lab_marker_in_inputs"]["ok"]
    assert not r.checks["collection_healthy"]["ok"]
    assert not r.checks["dataset_matches_catalogue"]["ok"]
    # none of the real catalogue's held-out procedures is in this toy dataset
    assert not r.checks["held_out_coverage"]["ok"]
    # development data may be looked at, and says so
    r = result_for(ds)
    harness.integrity(ds, r, allow_unhealthy=True)
    assert r.checks["collection_healthy"]["ok"]
    assert r.checks["collection_healthy"]["detail"].startswith("allowed for development")


def test_the_allowlist_is_the_feature_list_and_the_identity_columns():
    assert not set(META) & set(FEATURES)


# ------------------------------------------------------------------ regression


def made(tmp_path, **metrics):
    ds = dataset(tmp_path)
    r = result_for(ds)
    values = {
        "classifier.macro_f1": (0.90, [0.80, 0.97]),
        "classifier_event.macro_f1": (0.85, [0.70, 0.95]),
        "tagger.micro_f1": (0.40, [0.22, 0.58]),
        **metrics,
    }
    for name, value in values.items():
        if value is not None:
            r.metric(name, value[0], value[1])
    r.check("sessions_one_split", True, "ok")
    for gate in ("integrity", "classifier_beats_majority", "tagger_beats_most_frequent"):
        r.gate(gate, True, "met")
    return r


def test_a_run_passes_against_its_own_baseline(tmp_path):
    r = made(tmp_path)
    assert harness.regress(r, json.loads(json.dumps(r.to_json()))) == []


def test_a_metric_below_the_baselines_interval_fails_and_one_inside_it_does_not(tmp_path):
    baseline = made(tmp_path).to_json()
    inside = made(tmp_path, **{"tagger.micro_f1": (0.30, [0.15, 0.47])})
    assert harness.regress(inside, baseline) == []
    lowered = made(tmp_path, **{"tagger.micro_f1": (0.20, [0.08, 0.35])})
    (problem,) = harness.regress(lowered, baseline)
    assert "tagger.micro_f1 fell to 0.200" in problem and "0.220" in problem


def test_a_metric_missing_on_either_side_fails(tmp_path):
    full = made(tmp_path)
    without = made(tmp_path, **{"classifier_event.macro_f1": None})
    assert any("missing from this run" in p for p in harness.regress(without, full.to_json()))
    assert any("missing from the baseline" in p for p in harness.regress(full, without.to_json()))


def test_a_lost_gate_another_dataset_or_another_choice_of_models_fails(tmp_path):
    baseline = made(tmp_path).to_json()
    r = made(tmp_path)
    r.gate("tagger_beats_most_frequent", False, "interval includes zero")
    problems = harness.regress(r, baseline)
    assert any("gate tagger_beats_most_frequent" in p for p in problems)
    r = made(tmp_path)
    r.identity = {**r.identity, "steps.parquet": "0" * 64}
    assert any("different dataset" in p for p in harness.regress(r, baseline))
    r = made(tmp_path)
    r.choices = {**CHOICES, "classifier": {"family": "gbm", "features": "both"}}
    assert any("different choice of models" in p for p in harness.regress(r, baseline))
    empty = result_for(dataset(tmp_path))
    assert "no gate was evaluated" in harness.regress(empty, baseline)


# ------------------------------------------------------------------ datasets on disk


def test_a_dataset_is_identified_by_its_content(tmp_path):
    ds = dataset(tmp_path)
    before = ds.identity()
    changed = steps()
    changed[0]["input"] = "uname -r"
    assert dataset(tmp_path, step_list=changed).identity() != before
    (tmp_path / "ds" / "steps.parquet").unlink()
    with pytest.raises(harness.HarnessError, match=r"no steps\.parquet"):
        harness.Dataset.load(tmp_path / "ds")


def test_only_a_healthy_lab_seed_export_with_decisions_can_be_frozen(tmp_path):
    ds = dataset(tmp_path, manifest={"lab_seed": False, "problems": ["r1: 3 steps had no event"]})
    with pytest.raises(harness.HarnessError) as exc:
        harness.freeze(ds.directory, "nope", tmp_path / "atomic.yaml")
    message = str(exc.value)
    assert "3 steps had no event" in message and "lab seed" in message
    assert "decisions.parquet" in message
    assert not (harness.DATASETS / "nope").exists()


def test_published_rows_carry_every_metric_check_and_gate(tmp_path):
    r = made(tmp_path)
    r.gate("shadow_value_reported", False, "no decisions")
    baseline = {"metrics": {"tagger.micro_f1": {"value": 0.5, "ci": [0.3, 0.7]}}}
    rows = harness.publish_rows(r, baseline, 1_800_000_000_123_456)
    by = {row["metric"]: row for row in rows}
    assert by["tagger.micro_f1"]["baseline"] == 0.5 and by["tagger.micro_f1"]["gate"] == 255
    assert (by["tagger.micro_f1"]["ci_low"], by["tagger.micro_f1"]["ci_high"]) == (0.22, 0.58)
    assert by["gate.shadow_value_reported"]["gate"] == 0 and by["gate.integrity"]["gate"] == 1
    assert by["gate.sessions_one_split"]["gate"] == 1
    assert all(row["published_at"].endswith(".123456") for row in rows)
    assert len({row["version"] for row in rows}) == 1


# ------------------------------------------------------------------ found in review


def test_rows_filed_under_another_split_than_the_frozen_one_fail_the_check(tmp_path):
    # Every other split check passes on a dataset that is internally consistent but was split
    # some other way; only a comparison with the frozen file catches it.
    ds = dataset(tmp_path)
    r = result_for(ds)
    harness.integrity(ds, r)
    assert not r.checks["splits_match_frozen"]["ok"]  # toy procedure IDs: none is in the file
    assert "step row(s)" in r.checks["splits_match_frozen"]["detail"]


def test_a_frozen_index_or_cache_for_another_model_is_refused(tmp_path):
    from mirage_intel import tagscore as ts
    from mirage_intel import tagserve
    from mirage_intel.embedders import Cache

    ds = dataset(tmp_path)
    chosen = {**CHOICES["tagger"], "atomic": True}
    fit_on = [s for s in ts.steps_from_rows(ds.steps) if s.split in ("train", "dev")]
    model = tagserve.fit({**chosen, "atomic": False}, fit_on, toy)
    index = {"choice": tagserve.choice_identity(chosen), "model": model.to_saved(), "also_seen": []}
    path = ds.directory / "tagger.index.json"
    path.write_text(json.dumps(index))
    built, _, how = harness.build_tagger(ds, chosen, fit_on, make_embed=toy)
    assert how == "the index frozen with the dataset" and len(built.entries) == 10
    # the choice moves on (another neighbour count): the frozen index is no longer its model
    with pytest.raises(harness.HarnessError, match="names another model"):
        harness.build_tagger(ds, {**chosen, "k": 5}, fit_on, make_embed=toy)
    # ... and frozen vectors from another embedding model are not silently used either
    Cache.build("minilm", ["[ssh] uname -a"], toy(None)).save(ds.directory)
    with pytest.raises(harness.HarnessError, match="frozen vectors"):
        harness.build_tagger(ds, {**chosen, "embedder": "shellbert"}, fit_on)


def test_the_leak_guard_knows_the_fitted_commands_not_only_the_fitted_lines(tmp_path):
    from mirage_intel import tagscore as ts
    from mirage_intel import tagserve

    # Trained on a line of two commands; a held-out input that is one of them, alone, has
    # been seen word for word and must be dropped, not scored.
    rows = step_rows("train-pair", "T1082", "uname -a", "train")
    rows[0]["input"] = "uname -a ; df -h"
    rows.append({**rows[1], "event_id": "train-pair-0-d2", "input": "df -h", "ts_ms": 3})
    fit_on = ts.steps_from_rows(rows)
    assert fit_on[0].pieces == ("uname -a", "df -h")
    by_line = tagserve.scoring_context(fit_on, "line")["seen_skeletons"]
    by_piece = tagserve.scoring_context(fit_on, "pieces")["seen_skeletons"]
    held = ts.steps_from_rows(step_rows("test-df", "T1082", "df -h", "test"))[0]
    assert held.skeleton not in by_line and held.skeleton in by_piece


def test_a_metric_that_is_not_a_number_fails_the_regression(tmp_path):
    baseline = made(tmp_path).to_json()
    broken = made(tmp_path, **{"tagger.micro_f1": (float("nan"), [0.1, 0.2])})
    assert any("not a number" in p for p in harness.regress(broken, baseline))


def test_a_freeze_that_fails_leaves_nothing_behind(tmp_path, monkeypatch):
    ds = dataset(tmp_path, decisions=[{"session": "s", "usable": True, "split": "train"}])
    (ds.directory / "decisions.manifest.json").write_text("{}")
    monkeypatch.setattr(harness, "DATASETS", tmp_path / "frozen")
    monkeypatch.setattr(harness, "load_choices", lambda: CHOICES)

    def no_model(_repo):
        raise RuntimeError("the embedding model is not here")

    monkeypatch.setattr(harness, "neural_embedder", no_model)
    with pytest.raises(RuntimeError, match="not here"):
        harness.freeze(ds.directory, "broken", tmp_path / "atomic.yaml")
    assert not (tmp_path / "frozen" / "broken").exists()  # no half-frozen dataset to trip on

    # with the model, the same call freezes everything in one move
    monkeypatch.setattr(harness, "neural_embedder", lambda _repo: toy)
    target = harness.freeze(ds.directory, "whole", tmp_path / "atomic.yaml")
    names = {p.name for p in target.iterdir()}
    assert {"FROZEN.json", "tagger.index.json", "embeddings.npy", "steps.parquet"} <= names
    assert not (tmp_path / "frozen" / ".whole.partial").exists()
    assert json.loads((target / "tagger.index.json").read_text())["choice"]["unit"] == "pieces"


def test_the_live_labels_are_compared_step_by_step_with_the_offline_answer(tmp_path):
    from mirage_intel import tagscore as ts
    from mirage_intel import tagserve

    ds = dataset(tmp_path)
    chosen = CHOICES["tagger"]
    fit_on = [s for s in ts.steps_from_rows(ds.steps) if s.split in ("train", "dev")]
    model = tagserve.fit(chosen, fit_on, toy)
    tagserve.save(model, chosen, tagserve.tactic_map(fit_on, set()), {}, tmp_path / "m")
    served = tagserve.load(tmp_path / "m", toy)

    class Store:
        """The labels a worker wrote: on each held-out step's decision event."""

        def __init__(self, drop=(), wrong=(), other_version=()):
            self.rows_, self.queries = [], []
            for r in ds.steps:
                if r["split"] != "test" or r["role"] != "decision" or r["event_id"] in drop:
                    continue
                technique = "T1057" if r["event_id"] in wrong else r["technique_id"]
                version = "tagger-old" if r["event_id"] in other_version else served.version
                self.rows_.append(
                    {"event_id": r["event_id"], "technique": technique, "confidence": 1.0,
                     "version": version}
                )  # fmt: skip

        def rows(self, sql):
            self.queries.append(sql)
            return [
                r for r in self.rows_
                if f"'{r['event_id']}'" in sql and f"model_version = '{r['version']}'" in sql
            ]  # fmt: skip

    whole = harness.served_check(ds, Store(), served, draws=50)
    assert whole["held_out_steps"] == whole["same_answer"] == 10 and whole["agreement"] == 1.0
    assert whole["live_micro_f1"] == whole["offline_micro_f1"] == 1.0
    assert whole["inputs_with_two_live_labels"] == 0
    # a label the worker never wrote, one it got differently, and one from an older model
    partial = harness.served_check(
        ds,
        Store(
            drop={"test-uname-0-0-d"},
            wrong={"test-whoami-0-0-d"},
            other_version={"test-df-1-0-d"},
        ),
        served,
        draws=50,
    )
    assert partial["same_answer"] == 7 and partial["labelled_offline_only"] == 2
    assert partial["different_technique"] == 1 and partial["live_micro_f1"] < 1.0
