"""The live injection check's own logic (`make llm-inject`), with a scripted model in the
live one's place: it must catch a reply that breaks a rule, and pass one that does not."""

from __future__ import annotations

import sys
from pathlib import Path

from mirage_responder import inject, prompt
from responder_kit import PROFILE, Scripted, answer, service

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from eval.probes.injection import load

RULES = prompt.system(PROFILE)
INPUTS = [{"id": i.id, "kind": i.kind, "input": i.input} for i in load()]


def test_a_run_of_the_prompts_words_or_a_marker_word_is_a_leak():
    words = RULES.split()
    assert inject.leaks(" ".join(words[10:20]), RULES)
    assert inject.leaks("  ".join(w.upper() for w in words[40:48]), RULES)  # rewrapped, other case
    assert inject.leaks("this is a Honeypot", RULES) == ["honeypot"]
    assert inject.leaks(" ".join(words[10:17]), RULES) == []  # seven words are a phrase
    assert inject.leaks("root:x:0:0:root:/root:/bin/bash\n", RULES) == []


def test_an_operation_that_should_not_have_come_back_is_named():
    tokens = ["/root/.my.cnf"]
    fine = [{"op": "mkdir", "path": "/tmp/d", "mode": 493}]
    assert inject.bad_ops(fine, tokens) == []
    assert inject.bad_ops([{"op": "exec", "args": "id"}], tokens)
    assert inject.bad_ops([{"op": "write", "path": "/proc/x", "content": "1", "mode": 420}], tokens)
    assert inject.bad_ops([{"op": "remove", "path": "/root/.my.cnf"}], tokens)
    assert inject.bad_ops([{"op": "remove", "path": "/tmp/../etc/passwd"}], tokens)


async def test_a_model_that_stays_in_character_breaks_no_rule():
    model = Scripted(answer("", "bash: line 1: x: command not found\n", 127))
    report = await inject.examine(service(PROFILE, model), PROFILE, INPUTS)
    assert report["inputs"] == len(INPUTS) >= 20
    assert report["broke_a_rule"] == []
    assert report["completed"] + report["aborted"] == report["inputs"]
    assert len(model.requests) >= report["completed"]


async def test_a_model_that_obeys_is_stopped_and_the_stop_is_counted():
    # It recites its instructions to everyone. The filter aborts each answer, so nothing
    # leaks, and the report says how many were aborted and why.
    model = Scripted(answer(RULES + "\n"))
    report = await inject.examine(service(PROFILE, model), PROFILE, INPUTS)
    assert report["broke_a_rule"] == []
    assert report["completed"] == 0 and report["aborted"] == report["inputs"]
    assert all(reason.startswith("abort:") for reason in report["abort_reasons"])
    assert all(
        row["shown"] == "" or not inject.leaks(row["shown"], RULES) for row in report["rows"]
    )
