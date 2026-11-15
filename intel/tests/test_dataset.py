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
    rows, dropped = dataset.build_rows(raw, {"x": "train"})
    assert rows[0]["share_unknown"] == 0.25
    assert rows[0]["failed_before_success"] == 2
    assert dropped == []
    # a scenario outside the frozen split is not silently lost: it is reported
    assert dataset.build_rows(raw, {}) == ([], ["s1"])


def test_a_session_without_access_is_scanner_behaviour_whoever_made_it():
    # A bot's failed password guess, or its request to a web page it never logged in to.
    # Nothing a content-blind model sees tells it from a scanner's, and the class definition
    # (spec 2.3) calls it scanner.
    access = dataset.has_access
    assert not access("ssh", auth_success=0, auth_attempts=3, inputs=0)
    assert not access("http", auth_success=0, auth_attempts=0, inputs=3)  # a path sweep
    assert not access("http", auth_success=0, auth_attempts=2, inputs=5)  # sprayed logins
    assert access("ssh", auth_success=1, auth_attempts=4, inputs=0)
    assert access("mysql", auth_success=1, auth_attempts=1, inputs=6)
    # Redis here asks for no password: a command is activity with access ...
    assert access("redis", auth_success=0, auth_attempts=0, inputs=2)
    assert not access("redis", auth_success=0, auth_attempts=0, inputs=0)
    # ... unless the session was asked for one and never got in.
    assert not access("redis", auth_success=0, auth_attempts=2, inputs=3)
    assert dataset.session_label("scripted_bot", access=False) == "scanner"
    assert dataset.session_label("scripted_bot", access=True) == "scripted_bot"
    assert dataset.session_label("human", access=True) == "human"


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
    row = dataset.build_rows([raw], splits, {"human-probe-files": "bot-probe-files"})[0][0]
    assert row["group"] == "bot-probe-files" and row["label"] == "human"
    assert dataset.build_rows([raw], splits)[0][0]["group"] == "human-probe-files"
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


RAW = {
    "session_id": "s1",
    "actor_class": "scripted_bot",
    "protocol": "ssh",
    "scenario_id": "x",
    "real": 0,
    "inputs": 4,
    "decisions": 4,
    "fallbacks": 3,
    "auth_attempts": 1,
    "auth_success": 1,
    "duration_s": 2.0,
    "n_inputs": 4,
    "n_unknown": 0,
    "gap_min_s": 0.1,
    "gap_max_s": 0.5,
    "gap_mean_s": 0.3,
    "gap_median_s": 0.3,
    "tty_input_chunks": 40,
    "tty_single_byte_chunks": 36,
    "tty_backspaces": 2,
    "tty_paste_bursts": 1,
    "tty_lines": 4,
    "tty_key_gap_p50_s": 0.18,
}


def test_the_sessions_table_has_exactly_the_allowed_columns(tmp_path):
    # Section 5, item 8, on the real file: identity and ground truth, then behaviour features,
    # and nothing else. A sim_*, address, time or policy-service column cannot ride along.
    import pyarrow.parquet as pq

    rows, _ = dataset.build_rows([RAW], {"x": "train"})
    dataset.write_parquet(rows, tmp_path / "sessions.parquet", {})
    columns = set(pq.read_table(tmp_path / "sessions.parquet").column_names)
    assert columns == set(dataset.META) | set(dataset.FEATURES)
    assert not {"decisions", "fallbacks", "src_ip", "src_port", "timing_profile"} & columns
    assert not any(c.startswith(("sim_", "ts", "start_", "end_")) for c in columns)
    assert not set(dataset.FEATURES) & set(dataset.META)


def test_keystroke_features_come_from_the_tty_counts():
    row = dataset.build_rows([RAW], {"x": "train"})[0][0]
    assert row["tty_single_byte_share"] == 0.9 and row["tty_chunks_per_line"] == 10.0
    assert row["tty_backspaces"] == 2.0 and row["tty_key_gap_p50_s"] == 0.18
    quiet = dataset.build_rows([{**RAW, "tty_input_chunks": 0}], {"x": "train"})[0][0]
    assert quiet["tty_single_byte_share"] == 0.0 and quiet["tty_chunks_per_line"] == 0.0


def test_a_recording_of_a_person_is_test_only_and_its_own_group():
    raw = {**RAW, "real": 1, "scenario_id": dataset.RECORDED, "actor_class": "human"}
    row = dataset.build_rows([raw], {})[0][0]
    assert row["split"] == "test" and row["group"] == "recorded:s1" and row["real"] is True


RUN = {
    "run_id": "r20261114165915-282795",
    "final": 1,
    "no_event": 0,
    "mismatch": 0,
    "connections_unmatched": 0,
    "catalogue_sha256": "cat",
}


def test_an_unhealthy_run_cannot_become_a_dataset():
    assert dataset.run_problems([RUN], [RUN["run_id"]], "cat") == []
    assert any(
        "no_event = 2" in p for p in dataset.run_problems([{**RUN, "no_event": 2}], None, "cat")
    )
    assert any(
        "mismatch = 1" in p for p in dataset.run_problems([{**RUN, "mismatch": 1}], None, "cat")
    )
    assert any("not final" in p for p in dataset.run_problems([{**RUN, "final": 0}], None, "cat"))
    assert any(
        "truth_steps_missing" in p
        for p in dataset.run_problems([{**RUN, "truth_steps_missing": 3}], None, "cat")
    )
    assert any("different catalogue" in p for p in dataset.run_problems([RUN], None, "other"))
    # a run joined without its closing record, or with records that failed validation
    for column in ("incomplete", "truth_invalid"):
        got = dataset.run_problems([{**RUN, column: 2}], None, "cat")
        assert any(f"{column} = 2" in p for p in got), column
    assert any(
        "no such capture run" in p
        for p in dataset.run_problems([RUN], ["r20261114000000-aaaaaa"], "cat")
    )
    assert dataset.run_problems([], None, "cat") == ["no capture run to export"]


class FakeStore:
    def __init__(self, runs, sessions, steps):
        self.runs, self.sessions, self.steps = runs, sessions, steps

    def rows(self, sql):
        if "sim_runs FINAL WHERE mode = 'capture'" in sql and "sim_labels_current" not in sql:
            return self.runs
        return self.steps if "sim_labels_current" in sql else self.sessions


def _catalogue_and_split():
    from mirage_lab.models import Catalogue

    cat = Catalogue.load(dataset.ROOT / "lab" / "catalogue")
    return cat, dataset.FrozenSplit.load()


def test_export_refuses_and_says_why(tmp_path):
    cat, split = _catalogue_and_split()
    run = {**RUN, "catalogue_sha256": cat.sha256}
    session = {**RAW, "scenario_id": "bot-probe-files"}
    bad = FakeStore([{**run, "mismatch": 4}], [session], [])
    with pytest.raises(dataset.DatasetError, match="mismatch = 4"):
        dataset.export(bad, split, cat, tmp_path)
    unknown = FakeStore([run], [{**RAW, "scenario_id": "not-in-the-split"}], [])
    with pytest.raises(dataset.DatasetError, match="scenario with no split"):
        dataset.export(unknown, split, cat, tmp_path)
    # the escape hatch exports, and the manifest carries the reason it must not be frozen
    manifest = dataset.export(bad, split, cat, tmp_path, allow_unhealthy=True)
    assert manifest["problems"] and manifest["n_sessions"] == 1
    good = dataset.export(FakeStore([run], [session], []), split, cat, tmp_path)
    assert good["problems"] == [] and good["rows_sha256"] and good["steps_sha256"]
    assert good["split_sha256"] == split.sha256 and good["runs"][0]["run_id"] == run["run_id"]


def test_an_input_carrying_a_lab_marker_is_caught():
    step = {"event_id": "e1", "input": "ping -c1 198.18.0.7"}
    assert dataset.leak_scan([step], set()) == ["e1: address"]
    assert dataset.leak_scan(
        [{"event_id": "e2", "input": "echo sysinfo-uname-all"}], {"sysinfo-uname-all"}
    ) == ["e2: id"]
    assert (
        dataset.leak_scan([{"event_id": "e3", "input": "cat /etc/hostname"}], {"sysinfo-uname-all"})
        == []
    )
    assert dataset.leak_scan([{"event_id": "e4", "input": "touch honeypot.txt"}], set()) == [
        "e4: marker"
    ]


def test_the_lab_seed_matches_the_makefile():
    makefile = (dataset.ROOT / "Makefile").read_text()
    assert f"LAB_SEED := {dataset.LAB_SEED}" in makefile


def test_the_session_query_names_its_columns_and_does_not_coalesce_a_join():
    # Two bugs only a live database showed (15 November 2026). `f.*` came back as
    # `f.session_id`; and coalesce() over an unmatched LEFT JOIN kept ClickHouse's '' and
    # emptied every SSH session's events.
    sql = dataset.with_runs(dataset.SESSIONS_SQL, None)
    assert "f.*" not in sql and "coalesce(m." not in sql
    for column in dataset.FEATURE_COLUMNS:
        assert f"f.{column} AS {column}" in sql
    assert "if(m.session_id != '', m.session_id, e.session_id) AS lsid" in sql
    # every column the row builder reads is selected
    needed = {"session_id", "protocol", "inputs", "auth_attempts", "auth_success", "duration_s",
              "n_unknown", "gap_min_s", "gap_max_s", "gap_mean_s", "gap_median_s"}  # fmt: skip
    assert needed <= set(dataset.FEATURE_COLUMNS)


def test_an_export_whose_timing_features_are_all_zero_is_refused(tmp_path):
    cat, split = _catalogue_and_split()
    run = {**RUN, "catalogue_sha256": cat.sha256}
    flat = [
        {**RAW, "session_id": f"s{i}", "scenario_id": "bot-probe-files", "gap_max_s": 0.0}
        for i in range(10)
    ]
    with pytest.raises(dataset.DatasetError, match="timing features are not being computed"):
        dataset.export(FakeStore([run], flat, []), split, cat, tmp_path)
