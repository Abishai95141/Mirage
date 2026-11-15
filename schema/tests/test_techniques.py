"""The technique rule engine's matching: what an input looks like when a pattern sees it."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from mirage_schema import techniques
from mirage_schema.techniques import Engine, normalise

RULES = {
    "rules": [
        {
            "id": "accounts",
            "technique": "T1087.001",
            "tactic": "TA0007",
            "protocol": "ssh",
            "confidence": 0.9,
            "any_of": ["cat /etc/passwd"],  # written with one space, as a rule author would
        },
        {
            "id": "whole-line",
            "technique": "T1082",
            "tactic": "TA0007",
            "protocol": "ssh",
            "confidence": 0.8,
            "any_of": ["^uname -a$"],
        },
        {
            "id": "web-env",
            "technique": "T1552.001",
            "tactic": "TA0006",
            "protocol": "http",
            "confidence": 0.9,
            "all_of": ["^GET ", r"/\.env$"],
        },
    ],
    "session_rules": [
        {
            "id": "brute",
            "technique": "T1110.001",
            "tactic": "TA0006",
            "when": {"failed_before_success": {">=": 3}, "auth_success": {">=": 1}},
        }
    ],
}


def engine(tmp_path: Path) -> Engine:
    (tmp_path / "r.yaml").write_text(yaml.safe_dump(RULES))
    return Engine.load(tmp_path)


@pytest.mark.parametrize(
    ("raw", "normal"),
    [
        ("uname -a", "uname -a"),
        ("  uname   -a  ", "uname -a"),
        ("uname\t-a\r\n", "uname -a"),
        ("cat  /etc/passwd |\n  grep   root", "cat /etc/passwd | grep root"),
        ("", ""),
        (" \t\n", ""),
    ],
)
def test_normalise_collapses_whitespace_and_strips(raw, normal):
    assert normalise(raw) == normal
    assert normalise(normalise(raw)) == normal  # idempotent


def test_normalise_does_nothing_else():
    # Case, quoting, paths and separators are the attacker's and stay as sent.
    for text in ("Cat /ETC/Passwd", "echo 'a b' \"c\"", "a;b&&c|d", "GET /a%20b?x=1"):
        assert normalise(text) == text
    # It does not parse the shell: whitespace inside quotes collapses like any other.
    assert normalise("echo 'a   b'") == "echo 'a b'"


@pytest.mark.parametrize(
    "text",
    [
        "cat /etc/passwd",
        "cat    /etc/passwd",
        "cat\t/etc/passwd",
        "  cat /etc/passwd  ",
        "CAT  /etc/passwd",  # case was already the pattern's business (IGNORECASE)
    ],
)
def test_extra_whitespace_does_not_slip_past_a_rule(tmp_path, text):
    hit = engine(tmp_path).best("ssh", text)
    assert hit is not None and hit.rule_id == "accounts"


def test_anchors_see_the_stripped_input(tmp_path):
    e = engine(tmp_path)
    assert e.best("ssh", " uname  -a\n").rule_id == "whole-line"
    assert e.best("ssh", "uname -a; id") is None
    assert e.best("http", "GET   /.env ").rule_id == "web-env"
    assert e.last_tactic("ssh", "\tuname -a") == "TA0007"  # the policy service's entry point


def test_matching_is_part_of_the_version(tmp_path, monkeypatch):
    before = engine(tmp_path).version
    assert before.startswith("rules-") and engine(tmp_path).version == before
    monkeypatch.setattr(techniques, "MATCHING", "something-else")
    assert engine(tmp_path).version != before  # same rule files, different matching


def test_session_rules_read_the_summary_they_are_given(tmp_path):
    e = engine(tmp_path)
    assert [h.rule_id for h in e.tag_session({"failed_before_success": 3, "auth_success": 1})] == [
        "brute"
    ]
    assert e.tag_session({"failed_before_success": 3, "auth_success": 0}) == []
    assert e.tag_session({"failed_before_success": 2, "auth_success": 1}) == []
