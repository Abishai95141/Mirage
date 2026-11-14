"""The dataset export's queries and row building. No ClickHouse: the SQL is checked as text."""

from __future__ import annotations

import re

import pytest
from mirage_intel import dataset

pytestmark = pytest.mark.ml


@pytest.mark.parametrize("name", ["SESSIONS_SQL", "STEPS_SQL"])
def test_table_alias_comes_before_final(name):
    # ClickHouse wants `table AS alias FINAL`. `table FINAL AS alias` is a syntax error, and it
    # was only found when the export first ran against a live store (14 November 2026).
    sql = getattr(dataset, name)
    assert not re.search(r"\bFINAL\s+AS\b", sql), f"{name}: put the alias before FINAL"


def test_share_unknown_uses_the_separate_failed_count():
    raw = [
        {
            "session_id": "s1",
            "actor_class": "scripted_bot",
            "protocol": "ssh",
            "scenario_id": "x",
            "real": 0,
            "inputs": 4,
            "decisions": 4,
            "fallbacks": 0,
            "auth_attempts": 3,
            "auth_success": 1,
            "duration_s": 2.0,
            "n_inputs": 4,
            "n_unknown": 1,
            "gap_min_s": 0.1,
            "gap_max_s": 0.5,
            "gap_mean_s": 0.3,
            "gap_median_s": 0.3,
        }
    ]
    rows = dataset.build_rows(raw, {"x": "train"})
    assert rows[0]["share_unknown"] == 0.25
    assert rows[0]["failed_before_success"] == 2
    assert dataset.build_rows(raw, {}) == []  # a scenario outside the frozen split is dropped


def test_a_silent_connection_is_scanner_behaviour_whoever_made_it():
    # A bot's failed password guess: no login, no input. Nothing the decoy sees tells it from
    # a scanner's, and the class definition (spec 2.3) calls it scanner.
    assert dataset.session_label("scripted_bot", auth_success=0, inputs=0) == "scanner"
    assert dataset.session_label("scripted_bot", auth_success=1, inputs=0) == "scripted_bot"
    assert dataset.session_label("scripted_bot", auth_success=0, inputs=3) == "scripted_bot"
    assert dataset.session_label("human", auth_success=1, inputs=4) == "human"


def test_rows_carry_a_group_and_a_label_that_are_never_features():
    raw = {
        "session_id": "s1",
        "actor_class": "human",
        "protocol": "ssh",
        "scenario_id": "human-probe-files",
        "real": 0,
        "inputs": 4,
        "decisions": 4,
        "fallbacks": 0,
        "auth_attempts": 1,
        "auth_success": 1,
        "duration_s": 30.0,
        "n_inputs": 4,
        "n_unknown": 0,
        "gap_min_s": 2.0,
        "gap_max_s": 9.0,
        "gap_mean_s": 5.0,
        "gap_median_s": 5.0,
    }
    splits = {"human-probe-files": "train"}
    row = dataset.build_rows([raw], splits, {"human-probe-files": "bot-probe-files"})[0]
    assert row["group"] == "bot-probe-files" and row["label"] == "human"
    assert dataset.build_rows([raw], splits)[0]["group"] == "human-probe-files"
    assert {"group", "label"} <= dataset.FORBIDDEN and not set(dataset.FEATURES) & dataset.FORBIDDEN


def test_run_selection_is_validated_before_it_reaches_the_query():
    one = dataset.with_runs(dataset.SESSIONS_SQL, ["r20261114165915-282795"])
    assert "AND run_id IN ('r20261114165915-282795')" in one and "/*runs*/" not in one
    assert "/*runs*/" not in dataset.with_runs(dataset.STEPS_SQL, None)
    with pytest.raises(ValueError, match="not a run ID"):
        dataset.with_runs(dataset.STEPS_SQL, ["x' OR '1'='1"])


def test_scenario_groups_file_a_variant_under_its_base():
    groups = dataset.scenario_groups(dataset.ROOT / "lab" / "scenarios")
    assert groups["human-probe-files"] == "bot-probe-files"
    assert groups["bot-probe-files"] == "bot-probe-files"
    # every variant names a scenario that exists
    assert all(base in groups for base in groups.values())
