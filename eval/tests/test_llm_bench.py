"""The live-model bench's own logic: the command list, the join with the responder's
records, and the numbers it reports. (The run itself needs a decoy, a reference host and a
model; `make llm-bench` on the lab host.)"""

from __future__ import annotations

from collections import Counter

from eval.probes import llm_bench
from mirage_lab.models import check_run_safety


def answer(source: str, started: str, total_ms: float, first_ms: float | None = 10.0) -> dict:
    return {
        "stdout": "x\n",
        "stderr": "",
        "exit_code": 0,
        "first_ms": first_ms,
        "total_ms": total_ms,
        "started": started,
        "source": source,
    }


def record(source: str, timestamp: str, **over: object) -> dict:
    base = {
        "src_ip": source,
        "timestamp": timestamp,
        "outcome": "end",
        "rung": "model",
        "output_tokens": 40,
        "prompt_tokens": 600,
    }
    return base | over


def test_the_command_list_is_fixed_and_every_line_may_run_on_a_real_host():
    commands = llm_bench.load_commands()
    assert len(commands) >= 50
    assert len({c.id for c in commands}) == len(commands)
    per_class = Counter(c.cls for c in commands)
    assert set(per_class) == set(llm_bench.CLASSES)
    assert min(per_class.values()) >= 8
    for command in commands:
        assert check_run_safety(command.cmd) == [], command.id
        assert "\n" not in command.cmd
        # What a state-changing command makes, it makes under /tmp.
        if command.cls == "state-changing":
            assert "/tmp" in command.cmd, command.id


def test_an_answer_gets_the_records_of_its_own_source_and_time():
    doc = {
        "rows": [
            {
                "id": "a",
                "cls": "stateless",
                "first": answer("192.0.2.5", "2026-11-17T10:00:00.000Z", 900.0),
                "again": answer("192.0.2.5", "2026-11-17T10:00:02.000Z", 20.0),
            }
        ]
    }
    records = [
        record("192.0.2.5", "2026-11-17T10:00:00.100Z"),
        record("192.0.2.5", "2026-11-17T10:00:02.005Z", rung="cache"),
        record("192.0.2.9", "2026-11-17T10:00:00.200Z"),  # another source
        record("192.0.2.5", "2026-11-17T09:59:00.000Z"),  # the same source, a minute before
    ]
    llm_bench.join(doc, records)
    row = doc["rows"][0]
    assert [r["timestamp"] for r in row["first"]["records"]] == ["2026-11-17T10:00:00.100Z"]
    assert [r["rung"] for r in row["again"]["records"]] == ["cache"]
    assert llm_bench.answered_by(row["first"]) == "model"
    assert llm_bench.answered_by(row["again"]) == "cache"


def test_who_answered():
    assert llm_bench.answered_by({"records": []}) == "emulator"
    assert llm_bench.answered_by({}) == "emulator"
    aborted = {"records": [record("s", "t", outcome="abort", reason="deadline:first_line")]}
    assert llm_bench.answered_by(aborted) == "fallback:deadline:first_line"
    # A line of two commands, one from the cache and one from the model, is the model's.
    mixed = {"records": [record("s", "t", rung="cache"), record("s", "t")]}
    assert llm_bench.answered_by(mixed) == "model"


def test_the_summary_counts_only_the_models_answers_in_its_times():
    def row(
        cls: str, total: float, ok: bool, records: list[dict], again: dict | None = None
    ) -> dict:
        first = answer("192.0.2.1", "2026-11-17T10:00:00Z", total) | {"records": records}
        return {
            "id": cls,
            "cmd": "x",
            "cls": cls,
            "first": first,
            "again": again,
            "ok": ok,
            "same": ok and total < 1000,
            "difference": ""
            if ok and total < 1000
            else "stdout line 1 is 'a', the real host's is 'b'",
            "problems": [] if ok else ["exit code 1, the reference's is 0"],
            "reference": answer("192.0.2.2", "2026-11-17T10:00:00Z", 5.0),
        }

    cached = answer("192.0.2.1", "2026-11-17T10:00:03Z", 12.0) | {
        "records": [record("192.0.2.1", "t", rung="cache")]
    }
    doc = {
        "kind": "sequential",
        "sessions": 1,
        "rows": [
            row("stateless", 800.0, True, [record("192.0.2.1", "t")], cached),
            row("stateless", 1200.0, False, [record("192.0.2.1", "t", output_tokens=80)]),
            row("stateless", 30.0, False, []),  # the emulator answered: not the model's time
            row(
                "state-changing",
                15.0,
                False,
                [record("192.0.2.1", "t", outcome="abort", reason="truncated")],
            ),
        ],
    }
    summary = llm_bench.summarise(doc)
    stateless = summary["classes"]["stateless"]
    assert (stateless["commands"], stateless["by_model"], stateless["pass"]) == (3, 2, 1)
    assert stateless["total_ms_median"] == 1000.0
    assert stateless["output_tokens_median"] == 60.0
    assert (stateless["cache_hits"], stateless["cache_total_ms_median"]) == (1, 12.0)
    assert summary["classes"]["state-changing"]["by_model"] == 0
    assert summary["answered_by"] == {"emulator": 1, "fallback:truncated": 1, "model": 2}
    assert summary["classes"]["all"]["commands"] == 4
    text = llm_bench.table(summary) + llm_bench.failures(doc)
    assert "| stateless | 3 | 2 | 1 of 2 | 1 of 2 |" in text
    assert "fallback:truncated" in text and "exit code 1" in text


def test_the_stricter_bar_is_the_real_hosts_answer_line_for_line():
    def got(stdout: str, code: int = 0) -> llm_bench.Answer:
        return llm_bench.Answer(stdout=stdout, exit_code=code)

    real = got("360: 2 2 2 3 3 5\n")
    assert llm_bench.first_difference(got("360: 2 2 2 3 3 5\n"), real) == ""
    assert "line 1" in llm_bench.first_difference(got("2 2 3 3 5\n"), real)
    assert "exit status 1" in llm_bench.first_difference(got("360: 2 2 2 3 3 5\n", 1), real)
    assert "<no line>" in llm_bench.first_difference(got(""), real)
    # What differs between hosts and moments is masked: another date is the same answer.
    a, b = got("Nov 17 14:01 /tmp/d\n"), got("Nov 18 09:30 /tmp/d\n")
    assert llm_bench.first_difference(a, b) == ""


def test_a_pass_the_decoy_mostly_answered_itself_is_not_a_measure_of_the_model():
    # As it happened: the responder unhealthy on a busy host, 47 of 55 from the emulator.
    assert llm_bench.not_asked(
        {"answered_by": {"emulator": 47, "fallback:deadline": 5, "model": 3}}
    )
    assert not llm_bench.not_asked(
        {"answered_by": {"emulator": 5, "fallback:deadline": 7, "model": 43}}
    )
    assert not llm_bench.not_asked({"answered_by": {}})
