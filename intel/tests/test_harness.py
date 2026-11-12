"""The evaluation harness: metrics, the regression gate, and baseline round-trip. Synthetic."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest
import yaml
from mirage_intel import harness
from mirage_intel.dataset import FEATURES
from mirage_intel.techniques import Engine

pytestmark = pytest.mark.ml

RULES = {
    "rules": [
        {
            "id": "r-uname",
            "technique": "T1082",
            "tactic": "TA0007",
            "protocol": "ssh",
            "confidence": 0.9,
            "any_of": [r"\buname\b"],
        },
        {
            "id": "r-ls",
            "technique": "T1083",
            "tactic": "TA0007",
            "protocol": "ssh",
            "confidence": 0.7,
            "any_of": [r"\bls\b"],
        },
    ]
}


def eng(tmp_path: Path) -> Engine:
    (tmp_path / "r.yaml").write_text(yaml.safe_dump(RULES))
    return Engine.load(tmp_path)


def session(cls, split, rng, **over):
    base = dict.fromkeys(FEATURES, 0.0)
    base.update(
        {
            "session_id": f"s{rng.random()}",
            "actor_class": cls,
            "protocol": "ssh",
            "scenario_id": "x",
            "real": False,
            "split": split,
        }
    )
    base.update(over)
    return base


def sessions(split, rng):
    out = []
    for _ in range(20):
        out.append(session("scanner", split, rng, auth_success=0, inputs=0))
        out.append(
            session(
                "scripted_bot",
                split,
                rng,
                auth_success=1,
                inputs=rng.randint(5, 15),
                gap_mean_s=rng.uniform(0.05, 0.3),
                duration_s=rng.uniform(1, 4),
            )
        )
        out.append(
            session(
                "human",
                split,
                rng,
                auth_success=1,
                inputs=rng.randint(3, 8),
                gap_mean_s=rng.uniform(3, 8),
                duration_s=rng.uniform(20, 70),
            )
        )
    return out


def steps(split):
    return [
        {
            "protocol": "ssh",
            "input": "uname -a",
            "technique_id": "T1082",
            "source": "own",
            "split": split,
        },
        {
            "protocol": "ssh",
            "input": "ls /tmp",
            "technique_id": "T1083",
            "source": "own",
            "split": split,
        },
        {
            "protocol": "ssh",
            "input": "ls /",
            "technique_id": "T1083",
            "source": "atomic",
            "split": split,
        },
        {
            "protocol": "ssh",
            "input": "cat x",
            "technique_id": "T1005",
            "source": "own",
            "split": split,
        },
    ]


def test_evaluate_scores_both_models_and_sets_gates(tmp_path):
    rng = random.Random(0)
    data = sessions("train", rng) + sessions("test", rng)
    m = harness.evaluate(data, steps("test"), eng(tmp_path), "sha-1")
    assert m.classifier["macro_f1"] > m.classifier["rules_only_f1"]
    assert m.gates["classifier_beats_rules"] and m.gates["classifier_beats_majority"]
    assert m.tagger["micro_f1"] > 0
    assert m.gates["tagger_beats_most_frequent"] is True
    assert m.n_steps == 4


def _metrics(macro: float = 0.8, micro: float = 0.6) -> harness.Metrics:
    return harness.Metrics(
        dataset_sha256="sha-1",
        n_sessions=10,
        n_steps=10,
        classifier={"macro_f1": macro, "rules_only_f1": 0.2, "majority_f1": 0.1},
        tagger={"micro_f1": micro},
        gates={
            "classifier_beats_rules": True,
            "classifier_beats_majority": True,
            "tagger_beats_most_frequent": True,
        },
    )


def test_regression_passes_against_its_own_baseline():
    m = _metrics()
    assert harness.regress(m, json.loads(json.dumps(_asdict(m)))) == []


def test_regression_catches_a_drop_a_dip_and_a_wrong_dataset():
    m = _metrics(macro=0.80)
    baseline = _asdict(m)
    baseline["classifier"]["macro_f1"] = 0.99  # it used to be near-perfect
    assert any("classifier.macro_f1 fell" in p for p in harness.regress(m, baseline))
    baseline["classifier"]["macro_f1"] = 0.82  # within tolerance: no regression
    assert harness.regress(m, baseline) == []
    assert any(
        "different dataset" in p
        for p in harness.regress(m, {**_asdict(m), "dataset_sha256": "other"})
    )


def test_gate_fails_when_a_model_does_not_beat_its_baseline(tmp_path):
    # one class only in training: no model, so it cannot beat rules -> gate false
    rng = random.Random(3)
    train = [session("scripted_bot", "train", rng, inputs=5, auth_success=1) for _ in range(6)]
    test = [session("scripted_bot", "test", rng, inputs=5, auth_success=1) for _ in range(4)]
    m = harness.evaluate(train + test, [], eng(tmp_path), "sha-1")
    assert m.gates.get("classifier_beats_rules") is False
    assert any("gate classifier_beats_rules" in p for p in harness.regress(m, _asdict(m)))


def _asdict(m: harness.Metrics) -> dict:
    from dataclasses import asdict

    return asdict(m)
