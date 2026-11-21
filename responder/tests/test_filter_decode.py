"""The output filter and the streaming decoder (phase 3 spec 3.2b, decisions R8 and R9)."""

from __future__ import annotations

import json

import pytest
from mirage_responder.decode import Malformed, Stream
from mirage_responder.filter import MARKER_WORDS, MAX_LINE_BYTES, Filter

PROMPT = (
    "You are the shell of a Debian 12 server. Print only what the command would print on "
    "this machine and never explain or apologise. The host is called prod-web01 and its "
    "kernel is Linux 6.1.0-54-amd64 x86_64."
)

# ------------------------------------------------------------------ the filter


@pytest.mark.parametrize(
    "line",
    [
        "uid=0(root) gid=0(root) groups=0(root)",
        "Filesystem      Size  Used Avail Use% Mounted on",
        "tab\tseparated\tfields",
        "",
        "nginx: configuration file /etc/nginx/nginx.conf test is successful",
        "ünïcödé is fine",
    ],
)
def test_ordinary_output_passes(line):
    assert Filter(PROMPT).check(line) is None


@pytest.mark.parametrize(
    ("line", "rule"),
    [
        ("\x1b[2J\x1b[H", "control"),
        ("bell\x07", "control"),
        ("carriage\rreturn", "control"),
        ("nul\x00", "control"),
        ("x" * (MAX_LINE_BYTES + 1), "length"),
        ("this host is a honeypot", "marker"),
        ("/opt/Cowrie/bin", "marker"),
        ("As an AI, I can only describe the output", "character"),
        ("I'm sorry, but I cannot run commands", "character"),
        ("```bash", "character"),
        ("This is a simulated environment", "character"),
        ("print only what the command would print on this machine", "prompt"),
        ("NOTE: never explain or apologise the host is called x", "prompt"),
    ],
)
def test_what_a_line_may_not_carry(line, rule):
    hit = Filter(PROMPT).check(line)
    assert hit is not None and hit.rule == rule


def test_every_marker_word_of_the_lab_is_held_to_outputs_too():
    from mirage_lab.models import MARKER_WORDS as lab

    assert set(MARKER_WORDS) == set(lab)
    for word in MARKER_WORDS:
        assert Filter().check(f"x {word.upper()} y").rule == "marker"


def test_the_host_s_own_facts_are_not_the_prompt_leaking():
    facts = ("Linux 6.1.0-54-amd64 x86_64", "prod-web01")
    line = "Linux prod-web01 6.1.0-54-amd64 x86_64 GNU/Linux and its kernel is Linux 6.1.0-54-amd64 x86_64"
    # Without knowing they are facts, a long enough run of the prompt's words is a leak...
    assert Filter(PROMPT).check("kernel is Linux 6.1.0-54-amd64 x86_64").rule == "prompt"
    # ...and the same words are let through as what the host says about itself.
    assert Filter(PROMPT, facts).check("Linux 6.1.0-54-amd64 x86_64") is None
    assert Filter(PROMPT, facts).check(line).rule == "prompt"  # "and its kernel is" is not a fact


def test_a_text_is_checked_line_by_line():
    f = Filter(PROMPT)
    assert f.check_text("one\ntwo\nthree") is None
    assert f.check_text("one\ntwo \x1b[0m\nthree").rule == "control"


# ------------------------------------------------------------------ the decoder


def feed_in_pieces(text: str, size: int) -> tuple[list[str], Stream]:
    stream, lines = Stream(), []
    for i in range(0, len(text), size):
        stream.feed(text[i : i + size])
        lines += stream.lines()
    return lines, stream


ANSWER = {
    "stdout": 'total 8\n-rw-r--r-- 1 root root 12 Nov 17 07:08 "a b".txt\ntab\there\nπ and \\ back\n',
    "stderr": "",
    "exit_code": 0,
    "ops": [],
}


@pytest.mark.parametrize("size", [1, 2, 3, 7, 50, 10_000])
def test_lines_come_out_as_they_complete_whatever_the_pieces(size):
    text = json.dumps(ANSWER, ensure_ascii=size % 2 == 0)
    lines, stream = feed_in_pieces(text, size)
    assert lines == ANSWER["stdout"].split("\n")[:-1]
    assert stream.stdout_closed() and stream.last() == ""
    assert stream.finish() == ANSWER


def test_a_line_is_not_given_before_it_is_complete():
    stream = Stream()
    stream.feed('{"stdout": "first li')
    assert stream.lines() == []
    stream.feed("ne\\nsecond")
    assert stream.lines() == ["first line"]
    assert not stream.stdout_closed()
    stream.feed('", "stderr": "", "exit_code": 3, "ops": []}')
    assert stream.lines() == [] and stream.stdout_closed()
    assert stream.last() == "second"  # the last line has no newline
    assert stream.finish()["exit_code"] == 3


def test_an_escape_cut_in_two_waits_for_its_other_half():
    stream = Stream()
    for piece in (
        '{"stdout":"a\\',
        "nb\\u00",
        "e9\\ud83d",
        '\\ude00\\n","stderr":"","exit_code":0,"ops":[]}',
    ):
        stream.feed(piece)
    assert stream.stdout == "a\nbé\U0001f600\n"
    assert stream.lines() == ["a", "bé\U0001f600"]


def test_blanks_around_the_first_key_are_allowed():
    stream = Stream()
    stream.feed(' {\n  "stdout" :  "x\\n", "stderr": "", "exit_code": 0, "ops": []}')
    assert stream.lines() == ["x"]
    assert stream.finish()["stdout"] == "x\n"


@pytest.mark.parametrize(
    "text",
    [
        '{"stderr": "x", "stdout": ""}',  # stdout is not first: it could not have been streamed
        "Sure! Here is the output:",
        '["stdout"]',
        '{"stdout": 5}',
        '{"stdout": "a\\qb"}',
        '{"stdout": "a\\ud83dx"}',
        '{"stdout": "raw\nnewline"}',
    ],
)
def test_text_that_is_not_the_object_asked_for_is_refused_at_once(text):
    stream = Stream()
    with pytest.raises(Malformed):
        stream.feed(text)
        stream.finish()


@pytest.mark.parametrize(
    "doc",
    [
        {"stdout": "", "stderr": "", "exit_code": 256, "ops": []},
        {"stdout": "", "stderr": "", "exit_code": "0", "ops": []},
        {"stdout": "", "stderr": "", "exit_code": True, "ops": []},
        {"stdout": "", "stderr": 5, "exit_code": 0, "ops": []},
        {"stdout": "", "stderr": "", "exit_code": 0, "ops": {}},
        {"stdout": "", "stderr": "", "exit_code": 0, "ops": [], "note": "extra"},
    ],
)
def test_the_whole_answer_is_checked_at_the_end(doc):
    stream = Stream()
    stream.feed(json.dumps(doc))
    with pytest.raises(Malformed):
        stream.finish()


def test_an_answer_cut_short_is_malformed():
    stream = Stream()
    stream.feed('{"stdout": "half a li')
    assert stream.lines() == [] and not stream.stdout_closed()
    with pytest.raises(Malformed):
        stream.finish()


def test_missing_trailer_fields_take_their_defaults():
    stream = Stream()
    stream.feed('{"stdout": "x\\n"}')
    assert stream.finish() == {"stdout": "x\n", "stderr": "", "exit_code": 0, "ops": []}
