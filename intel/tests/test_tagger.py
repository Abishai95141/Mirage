"""The technique rule engine and the tagger's scoring, on synthetic benign rules and steps."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from mirage_intel import tagger
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
            "confidence": 0.6,
            "any_of": [r"\bls\b"],
        },
        {
            "id": "r-web-env",
            "technique": "T1552.001",
            "tactic": "TA0006",
            "protocol": "http",
            "confidence": 0.95,
            "all_of": [r"GET ", r"\.env"],
        },
    ],
    "session_rules": [
        {
            "id": "r-brute",
            "technique": "T1110.001",
            "tactic": "TA0006",
            "confidence": 0.9,
            "when": {"failed_before_success": {">=": 3}, "auth_success": {">=": 1}},
        },
    ],
}


def engine(tmp_path: Path, doc: dict = RULES) -> Engine:
    (tmp_path / "r.yaml").write_text(yaml.safe_dump(doc))
    return Engine.load(tmp_path)


def test_rules_compile_and_match_by_protocol(tmp_path):
    e = engine(tmp_path)
    assert e.best("ssh", "uname -a").technique == "T1082"
    assert e.best("ssh", "ls -la /tmp").technique == "T1083"
    assert e.best("ssh", "GET /.env") is None  # http rule does not fire on ssh
    assert e.best("http", "GET /.env").technique == "T1552.001"
    assert e.last_tactic("ssh", "uname -a") == "TA0007"
    assert e.best("ssh", "echo hello") is None  # abstains


def test_strongest_confidence_wins_when_several_fire(tmp_path):
    doc = {
        "rules": RULES["rules"]
        + [
            {
                "id": "r-uname-weak",
                "technique": "T1592",
                "tactic": "TA0043",
                "protocol": "ssh",
                "confidence": 0.3,
                "any_of": [r"\buname\b"],
            },
        ]
    }
    e = engine(tmp_path, doc)
    hits = e.tag_input("ssh", "uname -a")
    assert [h.technique for h in hits] == ["T1082", "T1592"]
    assert e.best("ssh", "uname -a").technique == "T1082"


def test_session_rule_fires_on_the_summary(tmp_path):
    e = engine(tmp_path)
    assert [
        h.technique for h in e.tag_session({"failed_before_success": 5, "auth_success": 1})
    ] == ["T1110.001"]
    assert e.tag_session({"failed_before_success": 1, "auth_success": 1}) == []


def test_bad_rules_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="bad technique"):
        engine(
            tmp_path,
            {"rules": [{"id": "x", "technique": "nope", "tactic": "TA0007", "any_of": ["a"]}]},
        )
    with pytest.raises(ValueError, match="no patterns"):
        engine(tmp_path, {"rules": [{"id": "y", "technique": "T1082", "tactic": "TA0007"}]})
    dup = tmp_path / "dupdir"
    dup.mkdir()
    (dup / "a.yaml").write_text(
        yaml.safe_dump(
            {"rules": [{"id": "r-x", "technique": "T1082", "tactic": "TA0007", "any_of": ["z"]}]}
        )
    )
    (dup / "b.yaml").write_text(
        yaml.safe_dump(
            {"rules": [{"id": "r-x", "technique": "T1083", "tactic": "TA0007", "any_of": ["q"]}]}
        )
    )
    with pytest.raises(ValueError, match="duplicate"):
        Engine.load(dup)


def test_scoring_counts_fired_correct_and_abstention(tmp_path):
    e = engine(tmp_path)
    steps = [
        {"protocol": "ssh", "input": "uname -a", "technique_id": "T1082", "source": "own"},
        {"protocol": "ssh", "input": "ls /tmp", "technique_id": "T1083", "source": "own"},
        {
            "protocol": "ssh",
            "input": "ls /tmp",
            "technique_id": "T1005",
            "source": "atomic",
        },  # wrong truth
        {"protocol": "ssh", "input": "echo hi", "technique_id": "", "source": "corpus"},  # abstain
        {"protocol": "http", "input": "GET /.env", "technique_id": "T1552.001", "source": "own"},
    ]
    r = tagger.score(e, steps)
    assert r.n == 5 and r.predicted == 4 and r.correct == 3
    assert r.abstention == 0.2  # one of five abstained
    assert r.by_source["own"]["precision"] == 1.0
    assert r.by_source["atomic"]["precision"] == 0.0  # fired T1083 but truth was T1005
    assert 0 < r.micro_f1 <= 1
