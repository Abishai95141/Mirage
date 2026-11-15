"""Keystroke statistics from synthetic TTY logs in Cowrie's format."""

from __future__ import annotations

import struct

from mirage_pipeline import ttystats as t

H = struct.Struct("<iLiiLL")


def rec(op: int, direction: int, ts: float, data: bytes = b"") -> bytes:
    sec = int(ts)
    return H.pack(op, 0, len(data), direction, sec, round((ts - sec) * 1_000_000)) + data


def log(*parts: bytes) -> bytes:
    return rec(t.OP_OPEN, 0, 100.0) + b"".join(parts) + rec(t.OP_CLOSE, 0, 160.0)


def typed(text: bytes, start: float, gap: float = 0.2) -> bytes:
    return b"".join(
        rec(t.OP_WRITE, t.TYPE_INPUT, start + i * gap, bytes([c])) for i, c in enumerate(text)
    )


def test_typing_arrives_one_key_at_a_time():
    s = t.stats(log(typed(b"uname -a\r", 101.0), rec(t.OP_WRITE, t.TYPE_OUTPUT, 103.0, b"Linux\n")))
    assert s.input_chunks == 9 and s.single_byte_chunks == 9 and s.input_bytes == 9
    assert s.paste_bursts == 0 and s.lines == 1 and s.truncated == 0
    assert abs(s.key_gap_p50_s - 0.2) < 1e-3
    assert s.duration_s == 60.0  # open to close


def test_a_program_sends_a_whole_line_in_one_write():
    s = t.stats(
        log(
            rec(t.OP_WRITE, t.TYPE_INPUT, 101.0, b"uname -a\n"),
            rec(t.OP_WRITE, t.TYPE_INPUT, 101.3, b"cat /etc/passwd\n"),
        )
    )
    assert s.input_chunks == 2 and s.single_byte_chunks == 0 and s.paste_bursts == 2
    assert s.lines == 2 and abs(s.key_gap_p50_s - 0.3) < 1e-3


def test_corrections_are_counted():
    s = t.stats(log(typed(b"unmae\x7f\x7f\x7fame\r", 101.0)))
    assert s.backspaces == 3 and s.single_byte_chunks == s.input_chunks == 12


def test_output_is_not_input():
    s = t.stats(log(rec(t.OP_WRITE, t.TYPE_OUTPUT, 101.0, b"x" * 500)))
    assert s.input_chunks == 0 and s.input_bytes == 0 and s.key_gap_p50_s == 0.0


def test_a_cut_off_log_keeps_what_came_before_the_damage():
    whole = log(typed(b"ls\r", 101.0))
    cut = whole[: len(whole) - 30]  # the tail is missing
    s = t.stats(cut)
    assert s.truncated == 1 and 1 <= s.input_chunks <= 3
    assert t.stats(b"") == t.Stats()  # an empty file is not an error
    assert t.stats(b"\x00\x01garbage").truncated == 1


def test_a_length_that_overruns_the_file_stops_the_parse():
    bad = H.pack(t.OP_WRITE, 0, 10_000, t.TYPE_INPUT, 101, 0) + b"abc"
    s = t.stats(rec(t.OP_OPEN, 0, 100.0) + typed(b"id\r", 100.5) + bad)
    assert s.truncated == 1 and s.input_chunks == 3  # the three real keystrokes survive


def test_a_huge_log_is_read_only_up_to_the_cap(monkeypatch):
    monkeypatch.setattr(t, "MAX_LOG_BYTES", 400)
    s = t.stats(log(typed(b"a" * 200, 101.0, gap=0.01)))
    assert s.truncated == 1 and 0 < s.input_chunks < 200


def test_quantiles():
    assert t._quantile([], 0.5) == 0.0
    assert t._quantile([1.0], 0.9) == 1.0
    assert t._quantile([0.0, 1.0, 2.0, 3.0, 4.0], 0.5) == 2.0
    assert abs(t._quantile([0.0, 10.0], 0.1) - 1.0) < 1e-9


def test_the_indexer_reads_finished_logs_once(tmp_path):
    from mirage_pipeline.artifacts import scan_tty

    done = "a" * 64
    (tmp_path / done).write_bytes(log(typed(b"id\r", 101.0)))
    (tmp_path / "20261114-173000-abc123-0i.log").write_bytes(b"still being written")
    (tmp_path / ("b" * 64)).symlink_to(tmp_path / done)  # never followed
    known: set[str] = set()
    rows = scan_tty(tmp_path, known)
    assert [r["sha256"] for r in rows] == [done]
    assert rows[0]["input_chunks"] == 3 and rows[0]["single_byte_chunks"] == 3
    assert scan_tty(tmp_path, known) == []  # already read
    assert scan_tty(tmp_path / "missing", set()) == []
