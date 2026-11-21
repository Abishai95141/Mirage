"""The responder service (phase 3 spec 3.2b): the contract of ``POST /v1/respond``, every
budget, the cache, the filter, and what is written down."""

from __future__ import annotations

import asyncio
import json
import time

import pytest
from fastapi.testclient import TestClient
from mirage_responder.app import (
    MIN_ALLOWANCE,
    SESSION_TOKENS,
    SOURCE_TOKENS,
    Settings,
    create_app,
)
from mirage_responder.backends import BackendError, Recording, Replay, Unrecorded, Usage
from responder_kit import TMP, TOKEN, Scripted, answer, replies, request, service, shell

from mirage_schema.respond import Abort, End, Out, Resync, parse_reply

AUTH = {"Authorization": f"Bearer {TOKEN}"}
PASSWD = "caleb:x:1000:1000:Caleb Reyes,,,:/home/caleb:/bin/bash\n"


def kinds(items) -> list[str]:
    return [item.type for item in items]


def text(items) -> str:
    return "".join(i.line + ("\n" if i.newline else "") for i in items if isinstance(i, Out))


def last_record(responder) -> dict:
    return responder.log.records[-1]


# ------------------------------------------------------------------ over HTTP


def client(profile, backend, **over) -> TestClient:
    return TestClient(create_app(Settings(token=TOKEN, profile=profile, backend=backend, **over)))


def post(c: TestClient, req) -> list:
    response = c.post("/v1/respond", headers=AUTH, json=req.model_dump(mode="json"))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    return [parse_reply(line) for line in response.text.splitlines()]


def test_an_answer_is_lines_then_an_end(profile):
    c = client(profile, Scripted(answer(PASSWD + "second line\n")))
    items = post(c, request())
    assert kinds(items) == ["out", "out", "end"]
    assert text(items) == PASSWD + "second line\n"
    end = items[-1]
    assert (end.rung, end.exit_code, end.stderr, end.ops) == ("model", 0, "", [])
    assert end.prompt_tokens == 300 and end.output_tokens > 0
    assert end.first_ms is not None and end.total_ms >= end.first_ms


def test_the_token_is_required_and_a_bad_request_is_refused(profile):
    c = client(profile, Scripted(answer("x\n")))
    body = request().model_dump(mode="json")
    assert c.post("/v1/respond", json=body).status_code == 401
    wrong = {"Authorization": "Bearer " + "x" * 32}
    assert c.post("/v1/respond", headers=wrong, json=body).status_code == 401
    assert c.post("/v1/respond", headers=AUTH, json=body | {"argv": []}).status_code == 422
    assert c.post("/v1/respond", headers=AUTH, json=body | {"budget": None}).status_code == 422
    over = body | {"budget": {"max_tokens": 401, "deadline_ms": 1000}}
    assert c.post("/v1/respond", headers=AUTH, json=over).status_code == 422
    assert c.post("/v1/respond", headers=AUTH, content=b"{not json").status_code == 422


def test_health_is_the_backends(profile):
    backend = Scripted(answer("x\n"))
    c = client(profile, backend)
    assert c.get("/healthz").status_code == 200
    backend.up = False
    assert c.get("/healthz").status_code == 503


def test_the_service_serves_nothing_else(profile):
    c = client(profile, Scripted(answer("x\n")))
    for path in ("/docs", "/openapi.json", "/redoc", "/v1/sessions"):
        assert c.get(path).status_code == 404


def test_a_failure_inside_an_answer_still_ends_in_a_record_the_decoy_can_act_on(profile):
    c = client(profile, Scripted(answer("x\n"), fail=RuntimeError("unforeseen")))
    assert post(c, request()) == [Abort(reason="error")]


# ------------------------------------------------------------------ classes and the cache


async def test_a_reading_answer_is_cached_and_the_repeat_is_the_same(profile):
    backend = Scripted(answer(PASSWD, "", 0))
    responder = service(profile, backend)
    first = await replies(responder, request())
    again = await replies(responder, request(request_id="r2", session_id="s2"))
    assert len(backend.requests) == 1  # the second never reached the model
    assert text(first) == text(again) == PASSWD
    assert (first[-1].rung, again[-1].rung) == ("model", "cache")
    assert again[-1].output_tokens == 0  # a cached answer spends nothing
    assert last_record(responder)["rung"] == "cache"
    assert responder.sessions.get("s2").tokens_spent == 0


async def test_a_state_reading_answer_is_kept_for_its_state_only(profile):
    backend = Scripted(lambda r: answer(f"answer {len(backend.requests)}\n"))
    responder = service(profile, backend)
    small = [*TMP, {"path": "/tmp/a", "type": "file", "mode": 0o644, "uid": 0, "size": 3}]
    grown = [*TMP, {"path": "/tmp/a", "type": "file", "mode": 0o644, "uid": 0, "size": 9}]
    one = await replies(responder, shell("md5sum /tmp/a", slice=small))
    two = await replies(responder, shell("md5sum /tmp/a", slice=small))
    three = await replies(responder, shell("md5sum /tmp/a", slice=grown))
    four = await replies(responder, shell("md5sum  /tmp/a", slice=grown))  # spacing aside
    assert [text(x) for x in (one, two, three, four)] == [
        "answer 1\n",
        "answer 1\n",
        "answer 2\n",
        "answer 2\n",
    ]
    # Another state is another sampling seed: the two answers are independent draws.
    assert backend.requests[0].seed != backend.requests[1].seed


async def test_a_command_not_in_the_table_is_buffered_and_never_cached(profile):
    ops = [{"op": "mkdir", "path": "/tmp/build", "mode": 0o755}]
    backend = Scripted(answer("created /tmp/build\n", "", 0, ops), between=0.001)
    responder = service(profile, backend)
    items = await replies(responder, shell("mkproject /tmp/build", slice=TMP))
    # Held: no line goes out before the operations do, and both arrive together.
    assert kinds(items) == ["end"]
    assert items[-1].stdout == "created /tmp/build\n"
    assert [op.path for op in items[-1].ops] == ["/tmp/build"]
    assert last_record(responder)["lines"] == 1 and "first_ms" not in last_record(responder)
    record = last_record(responder)
    assert (record["class"], record["ops_proposed"], record["ops_applied"]) == (
        "state-changing",
        1,
        1,
    )
    await replies(responder, shell("mkproject /tmp/build", slice=TMP))
    assert len(backend.requests) == 2 and len(responder.cache) == 0


async def test_what_a_changing_answer_claimed_is_shown_to_the_next(profile):
    backend = Scripted(answer("Setting up htop (3.2.2-2) ...\n"))
    responder = service(profile, backend)
    await replies(responder, shell("dpkg -i /tmp/htop_3.2.2-2_amd64.deb", slice=TMP))
    await replies(responder, shell("dpkg -s htop", request_id="r2"))
    assert "htop_3.2.2-2_amd64.deb" not in backend.requests[0].state
    assert '"dpkg -i /tmp/htop_3.2.2-2_amd64.deb" was run and exited 0' in backend.requests[1].state
    assert "Setting up htop (3.2.2-2) ..." in backend.requests[1].state


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        ("vim /etc/hosts", "class:interactive"),
        ("mariadb -u root", "class:interactive"),
        ("curl http://198.51.100.7/x", "class:network"),
        ("update-alternatives --config editor", "class:interactive"),
    ],
)
async def test_interactive_and_network_programs_are_never_generated(profile, line, reason):
    backend = Scripted(answer("x\n"))
    responder = service(profile, backend)
    assert await replies(responder, shell(line)) == [Abort(reason=reason)]
    assert backend.requests == []
    assert last_record(responder)["reason"] == reason


async def test_an_answer_with_no_newline_at_its_end_says_so(profile):
    responder = service(profile, Scripted(answer("one\ntwo")))
    items = await replies(responder, request())
    assert [(i.line, i.newline) for i in items[:-1]] == [("one", True), ("two", False)]
    cached = await replies(responder, request(request_id="r2"))
    assert [(i.line, i.newline) for i in cached[:-1]] == [("one", True), ("two", False)]


async def test_an_error_answer_carries_its_stream_and_code(profile):
    responder = service(profile, Scripted(answer("", "getent: Unknown database: x\n", 1)))
    items = await replies(responder, shell("getent x"))
    assert items == [
        End(
            stderr="getent: Unknown database: x\n",
            exit_code=1,
            rung="model",
            prompt_tokens=300,
            output_tokens=items[0].output_tokens,
            total_ms=items[0].total_ms,
        )
    ]


# ------------------------------------------------------------------ operations


BAD_OPS = [
    ("ops:malformed", [{"op": "write", "path": "tmp/x", "content": "a", "mode": 0o644}]),
    ("ops:malformed", [{"op": "exec", "path": "/tmp/x"}]),
    ("ops:malformed", [{"op": "mkdir", "path": f"/tmp/d{i}", "mode": 0o755} for i in range(9)]),
    ("ops:malformed", [{"op": "write", "path": "/tmp/x", "content": "a" * 4097, "mode": 0o644}]),
    ("ops:malformed", [{"op": "write", "path": "/proc/sys/x", "content": "1", "mode": 0o644}]),
    ("ops:rejected", [{"op": "mkdir", "path": "/tmp/no/such/parent", "mode": 0o755}]),
    ("ops:rejected", [{"op": "write", "path": "/root/.my.cnf", "content": "x", "mode": 0o600}]),
    ("ops:rejected", [{"op": "remove", "path": "/root/.my.cnf"}]),
    ("ops:rejected", [{"op": "cd", "path": "/nowhere"}]),
    (
        "ops:rejected",  # the second is refused, so the first is not applied either
        [
            {"op": "mkdir", "path": "/tmp/fine", "mode": 0o755},
            {"op": "mkdir", "path": "/var/absent/x", "mode": 0o755},
        ],
    ),
]


@pytest.mark.parametrize(("reason", "ops"), BAD_OPS)
async def test_one_bad_operation_rejects_the_whole_answer(profile, reason, ops):
    responder = service(profile, Scripted(answer("done\n", "", 0, ops)))
    token = {"path": "/root/.my.cnf", "type": "file", "mode": 0o600, "uid": 0, "size": 80}
    items = await replies(responder, shell("setup-tool --run", slice=[*TMP, token]))
    assert items == [Abort(reason=reason)]  # and not one line of it was shown
    record = last_record(responder)
    assert (record["outcome"], record["reason"], record["ops_applied"]) == ("abort", reason, 0)
    assert responder.sessions.get("s1").facts == []  # nothing it claimed is held to be true


async def test_a_user_without_permission_cannot_be_given_the_change(profile):
    ops = [{"op": "write", "path": "/etc/cron.d/x", "content": "x", "mode": 0o644}]
    responder = service(profile, Scripted(answer("", "", 0, ops)))
    etc = [{"path": "/etc/cron.d", "type": "dir", "mode": 0o755, "uid": 0, "gid": 0}]
    as_caleb = shell("setup-tool", user="caleb", uid=1000, gid=1000, slice=etc)
    assert await replies(responder, as_caleb) == [Abort(reason="ops:rejected")]
    as_root = shell("setup-tool", request_id="r2", session_id="s2", slice=etc)
    assert kinds(await replies(responder, as_root)) == ["end"]


async def test_a_command_that_only_reads_changes_nothing(profile):
    ops = [{"op": "remove", "path": "/tmp/a"}]
    responder = service(profile, Scripted(answer("d41d8cd9  /tmp/a\n", "", 0, ops)))
    seen = [*TMP, {"path": "/tmp/a", "type": "file", "mode": 0o644, "uid": 0, "size": 0}]
    items = await replies(responder, shell("md5sum /tmp/a", slice=seen))
    assert items[-1] == Abort(reason="ops:reading_class")
    assert len(responder.cache) == 0


# ------------------------------------------------------------------ the journal and resync


def journal(*entries: tuple) -> list[dict]:
    return [{"seq": seq, "op": op, **fields} for seq, op, fields in entries]


async def test_the_journal_is_folded_before_the_command_is_answered(profile):
    backend = Scripted(answer("x\n"))
    responder = service(profile, backend)
    made = journal((1, "mkdir", {"path": "/opt/app", "mode": 0o755, "uid": 0, "gid": 0}))
    await replies(responder, shell("tree /opt", journal=made, journal_to=1))
    assert '"/opt/app" (dir)' in backend.requests[0].state
    more = journal((2, "cd", {"path": "/opt/app"}))
    await replies(
        responder,
        shell("tree .", request_id="r2", cwd="/opt/app", journal_from=2, journal=more),
    )
    assert responder.sessions.get("s1").journal_seq == 2


async def test_a_journal_that_does_not_join_is_answered_with_resync(profile):
    backend = Scripted(answer("x\n"))
    responder = service(profile, backend)
    # A session this responder has never seen, picked up in the middle: it was restarted.
    middle = journal((7, "mkdir", {"path": "/opt/b", "mode": 0o755, "uid": 0, "gid": 0}))
    late = shell("tree /opt", journal_from=7, journal=middle, journal_to=7)
    assert await replies(responder, late) == [Resync(have=0)]
    assert backend.requests == [] and last_record(responder)["outcome"] == "resync"

    # The decoy sends the whole journal, and the answer is made from all of it.
    whole = journal(
        (1, "mkdir", {"path": "/opt/a", "mode": 0o755, "uid": 0, "gid": 0}),
        (7, "mkdir", {"path": "/opt/b", "mode": 0o755, "uid": 0, "gid": 0}),
    )
    assert kinds(await replies(responder, shell("tree /opt", journal=whole, journal_to=7))) == [
        "out",
        "end",
    ]
    assert '"/opt/a" (dir)' in backend.requests[0].state

    # A gap in a session that is held: entries 8 and 9 were never sent.
    gap = journal((10, "remove", {"path": "/opt/a"}))
    after = shell("tree /opt", request_id="r3", journal_from=10, journal=gap, journal_to=10)
    assert await replies(responder, after) == [Resync(have=7)]


async def test_another_deployments_request_is_not_answered(profile):
    backend = Scripted(answer("x\n"))
    responder = service(profile, backend)
    assert await replies(responder, request(deployment_id="web-db-2")) == [
        Abort(reason="other_deployment")
    ]
    assert backend.requests == []


# ------------------------------------------------------------------ budgets


async def test_an_input_line_over_a_kibibyte(profile):
    backend = Scripted(answer("x\n"))
    responder = service(profile, backend)
    long = "getent passwd " + "a" * 1011  # 1,025 bytes
    assert await replies(responder, shell(long)) == [Abort(reason="input_too_long")]
    assert kinds(await replies(responder, shell(long[:-1], request_id="r2"))) == ["out", "end"]
    assert len(backend.requests) == 1


async def test_the_answers_own_allowance_is_what_the_model_is_given(profile):
    backend = Scripted(answer("x\n"))
    responder = service(profile, backend)
    await replies(responder, request(budget={"max_tokens": 120, "deadline_ms": 5000}))
    assert backend.requests[0].max_tokens == 120
    # Too few tokens to hold an answer's four fields is not worth asking the model for.
    small = shell(
        "getent group",
        request_id="r2",
        budget={"max_tokens": MIN_ALLOWANCE - 1, "deadline_ms": 5000},
    )
    assert await replies(responder, small) == [Abort(reason="budget:answer")]
    assert len(backend.requests) == 1


async def test_a_session_runs_out_of_tokens(profile):
    backend = Scripted(answer("ok\n"), usage=Usage(300, 1400))
    responder = service(profile, backend)
    for n in range(2):
        assert kinds(await replies(responder, shell(f"job-{n}", request_id=f"r{n}"))) == ["end"]
    # 2,800 of 3,000 spent: the third is given what is left, and the fourth nothing.
    await replies(responder, shell("job-2", request_id="r2"))
    assert backend.requests[2].max_tokens == SESSION_TOKENS - 2800
    assert await replies(responder, shell("job-3", request_id="r3")) == [
        Abort(reason="budget:session")
    ]
    assert len(backend.requests) == 3
    # Another session of the same source is not held to this one's spending.
    other = shell("job-0", request_id="r9", session_id="s2")
    assert kinds(await replies(responder, other)) == ["end"]


async def test_a_source_address_runs_out_for_the_day(profile):
    backend = Scripted(answer("ok\n"), usage=Usage(300, 1500))
    responder = service(profile, backend)
    now = [86400.0 * 20000]
    responder.sources.clock = lambda: now[0]
    sessions = SOURCE_TOKENS // 3000
    for s in range(sessions):
        for n in range(2):
            items = await replies(responder, shell(f"job-{n}", session_id=f"s{s}"))
            assert kinds(items) == ["end"]
    fresh = shell("job-0", session_id="s-new")
    assert await replies(responder, fresh) == [Abort(reason="budget:source")]
    assert last_record(responder)["reason"] == "budget:source"

    elsewhere = shell("job-0", session_id="s-other", src={"ip": "198.51.100.4", "port": 1})
    assert kinds(await replies(responder, elsewhere)) == ["end"]
    now[0] += 86400  # the next day
    assert kinds(await replies(responder, fresh)) == ["end"]


async def test_one_answer_at_a_time(profile):
    backend = Scripted(answer("a\nb\nc\n"), piece=4, between=0.01)
    responder = service(profile, backend, concurrency=1)
    slow = responder.answer(shell("md5sum /tmp/a", slice=TMP))
    assert isinstance(await anext(slow), Out)  # the first is in the making
    second = shell("md5sum /tmp/b", request_id="r2", session_id="s2", slice=TMP)
    assert await replies(responder, second) == [Abort(reason="busy")]
    rest = [item async for item in slow]
    assert kinds(rest) == ["out", "out", "end"]
    assert responder.in_flight == 0
    assert kinds(await replies(responder, second)) == ["out", "out", "out", "end"]


async def test_four_at_once_where_four_are_allowed(profile):
    backend = Scripted(answer("a\n"), between=0.01)
    responder = service(profile, backend, concurrency=4)
    asks = [shell(f"md5sum /tmp/{n}", session_id=f"s{n}", slice=TMP) for n in range(5)]
    results = await asyncio.gather(*(replies(responder, a) for a in asks))
    ended = [r for r in results if isinstance(r[-1], End)]
    assert len(ended) == 4
    assert [r for r in results if r == [Abort(reason="busy")]] != []


async def test_the_first_line_is_late(profile):
    backend = Scripted(answer("a\n"), before=0.5)
    responder = service(profile, backend, first_line_s=0.05)
    began = asyncio.get_running_loop().time()
    assert await replies(responder, request()) == [Abort(reason="deadline:first_line")]
    assert asyncio.get_running_loop().time() - began < 0.3  # it fell back in time
    assert backend.closed == 1 and responder.in_flight == 0  # and the model was let go


async def test_the_first_line_deadline_is_for_answers_that_are_streamed(profile):
    backend = Scripted(answer("built\n"), before=0.12)
    responder = service(profile, backend, first_line_s=0.05)
    # A command that may change things is held whole, so only the whole deadline binds it.
    assert kinds(await replies(responder, shell("make-thing"))) == ["end"]
    # And a reading command that prints nothing is not late for having no first line.
    quiet = Scripted(answer("", "", 1), piece=30, between=0.04)
    responder = service(profile, quiet, first_line_s=0.05)
    assert kinds(await replies(responder, shell("cmp /tmp/a /tmp/b", slice=TMP))) == ["end"]


async def test_the_whole_answer_is_late(profile):
    backend = Scripted(answer("a\nb\nc\nd\ne\nf\n"), piece=4, between=0.03)
    responder = service(profile, backend)
    ask = request(budget={"max_tokens": 400, "deadline_ms": 100})
    items = await replies(responder, ask)
    assert items[-1] == Abort(reason="deadline")
    assert 1 <= len(items) - 1 < 6  # some lines were out; the rest never came
    record = last_record(responder)
    assert record["reason"] == "deadline" and record["output_tokens"] > 0
    assert responder.sessions.get("s1").tokens_spent == record["output_tokens"]


@pytest.mark.parametrize(
    ("backend", "reason"),
    [
        (Scripted("", fail=BackendError("status 503")), "backend"),
        (Scripted("", fail=Unrecorded("abc")), "unrecorded"),
        (Scripted('["stdout"]'), "malformed"),
        (Scripted('{"stdout":"a\\n","stderr":"","exit_code":0,"ops":[],"note":"hi"}'), "malformed"),
        (Scripted('{"stdout":"a\\n","stderr":"","exit_code":"zero","ops":[]}'), "malformed"),
        (Scripted('{"stdout":"a\\nb\\nc', usage=Usage(300, 400)), "truncated"),
        (Scripted('{"stdout":"a\\nb\\nc', usage=Usage(300, 12)), "malformed"),
    ],
)
async def test_a_model_that_fails_is_a_fallback_with_its_reason(profile, backend, reason):
    responder = service(profile, backend)
    items = await replies(responder, request())
    assert items[-1] == Abort(reason=reason)
    assert last_record(responder)["reason"] == reason


async def test_with_the_model_server_gone_every_answer_falls_back_in_time(profile, tmp_path):
    from mirage_responder import prompt
    from mirage_responder.backends import Llama

    gone = Llama("http://127.0.0.1:9", "llama", prompt.SCHEMA, "none")  # nothing listens
    responder = service(profile, gone)
    began = asyncio.get_running_loop().time()
    for n in range(3):
        ask = shell(f"getent passwd u{n}", budget={"max_tokens": 400, "deadline_ms": 1000})
        assert await replies(responder, ask) == [Abort(reason="backend")]
    assert asyncio.get_running_loop().time() - began < 1.0
    assert await gone.healthy() is False
    await gone.close()


# ------------------------------------------------------------------ the filter


async def test_a_line_the_filter_refuses_ends_a_streamed_answer_there(profile):
    backend = Scripted(answer("first\nsecond\nthis is a honeypot\nfourth\n"), piece=5)
    responder = service(profile, backend)
    items = await replies(responder, request())
    assert kinds(items) == ["out", "out", "abort"]
    assert items[-1].reason == "filter:marker" and text(items) == "first\nsecond\n"
    record = last_record(responder)
    assert record["filter_hit"] == "marker"
    assert "honeypot" not in json.dumps(record)  # the rule is logged, never the line
    assert len(responder.cache) == 0


@pytest.mark.parametrize(
    ("said", "rule"),
    [
        (answer("fine\nI'm sorry, but I can't help with that.\n"), "character"),
        (answer("fine\n\x1b[2J\x1b[Hcleared\n"), "control"),
        (answer("fine\n" + "A" * 5000 + "\n"), "length"),
        (answer("fine\n", "As an AI language model I do not have a filesystem.\n"), "character"),
        (answer("fine\nlast line with no newline, from the cowrie source"), "marker"),
    ],
)
async def test_a_buffered_answer_the_filter_refuses_shows_nothing(profile, said, rule):
    responder = service(profile, Scripted(said))
    assert await replies(responder, shell("unknown-tool --status")) == [
        Abort(reason=f"filter:{rule}")
    ]


async def test_the_prompt_never_comes_back_as_output(profile):
    from mirage_responder import prompt

    lines = prompt.system(profile).splitlines()
    for cls_line in ("getent passwd x", "unknown-tool x"):
        responder = service(profile, Scripted(answer("\n".join(lines) + "\n"), piece=40))
        items = await replies(responder, shell(cls_line))
        assert items[-1] == Abort(reason="filter:prompt")
        shown = text(items)
        assert "command interpreter" not in shown and "JSON object" not in shown


# ------------------------------------------------------------------ Ctrl-C


async def test_the_decoy_going_away_stops_the_model_and_is_written_down(profile):
    backend = Scripted(answer("a\nb\nc\nd\ne\nf\ng\nh\n"), piece=4, between=0.02)
    responder = service(profile, backend)
    stream = responder.answer(request())
    assert isinstance(await anext(stream), Out)
    began = asyncio.get_running_loop().time()
    await stream.aclose()  # what the server does when the decoy closes the connection
    assert asyncio.get_running_loop().time() - began < 0.1
    assert backend.closed == 1 and responder.in_flight == 0
    record = last_record(responder)
    assert record["outcome"] == "cancelled" and record["lines"] == 1
    # What the model had written by then is charged to the session.
    assert responder.sessions.get("s1").tokens_spent == record["output_tokens"] > 0
    assert len(responder.cache) == 0  # half an answer is not kept
    # And the next command is answered.
    assert kinds(await replies(responder, request(request_id="r2")))[-1] == "end"


# ------------------------------------------------------------------ records and replay


async def test_every_request_leaves_one_record_and_no_generated_line(profile, tmp_path):
    log = tmp_path / "log" / "answers.json"
    responder = service(profile, Scripted(answer("SECRET-LOOKING-OUTPUT\n")), log_path=log)
    await replies(responder, request())
    await replies(responder, request(request_id="r2"))
    await replies(responder, shell("vim x", request_id="r3"))
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r["request_id"] for r in records] == ["r1", "r2", "r3"]
    assert [r.get("rung") for r in records] == ["model", "cache", None]
    first = records[0]
    assert first["eventid"] == "responder.answer" and first["outcome"] == "end"
    assert (first["session_id"], first["deployment_id"], first["src_ip"]) == (
        "s1",
        "web-db-1",
        "203.0.113.9",
    )
    assert (first["class"], first["verb"], first["lines"]) == ("stateless", "getent", 1)
    assert first["backend"] == "scripted" and first["model_version"] == "test-model-1"
    assert first["prompt_tokens"] == 300 and first["first_ms"] <= first["total_ms"]
    assert "SECRET-LOOKING-OUTPUT" not in log.read_text()
    assert "caleb" not in log.read_text()  # nor the input: the decoy's own event has it


async def test_replay_gives_the_recorded_answers_and_refuses_the_rest(profile, tmp_path):
    def say(r):
        return answer(f"{len(r.command)} bytes\n", "", 0, [])

    live = service(profile, Recording(Scripted(say), tmp_path / "rec"))
    asks = [
        shell("md5sum /tmp/a", slice=TMP),
        shell("unknown-tool --version", request_id="r2"),
    ]
    recorded = [await replies(live, a) for a in asks]

    def stable(items, rung):
        out = [i.model_dump(exclude={"total_ms", "first_ms"}) for i in items]
        return [x | {"rung": rung} if x["type"] == "end" else x for x in out]

    for _ in range(2):
        again = service(profile, Replay(tmp_path / "rec"))  # a fresh service, an empty cache
        replayed = [await replies(again, a) for a in asks]
        # Line for line and token for token what was recorded; only the rung's name differs.
        assert [stable(r, "replay") for r in replayed] == [stable(r, "replay") for r in recorded]
        assert [r[-1].rung for r in replayed] == ["replay", "replay"]
        never = shell("md5sum /tmp/never-recorded", request_id="r3", slice=TMP)
        assert await replies(again, never) == [Abort(reason="unrecorded")]


async def test_a_record_is_what_the_pipeline_maps(profile, tmp_path):
    """The record the service writes and the mapper the normaliser runs are two ends of one
    format: each field the mapper needs is one the service writes."""
    from mirage_schema import Outcome, Source
    from mirage_schema.mappings import responder as mapping

    log = tmp_path / "answers.json"
    responder = service(profile, Scripted(answer("x\n")), log_path=log)
    await replies(responder, request())
    await replies(responder, shell("vim x", request_id="r2"))
    events = [mapping.map_record(json.loads(line)) for line in log.read_text().splitlines()]
    assert [e.outcome for e in events] == [Outcome.SUCCESS, Outcome.FAILURE]
    first = events[0]
    assert (first.source, first.session_id, first.sensor) == (Source.RESPONDER, "s1", "web-db-1")
    assert first.payload["request_id"] == "r1" and first.payload["rung"] == "model"
    assert events[1].payload["reason"] == "class:interactive"


# ------------------------------------------------------------------ the same thing twice


async def test_a_session_asked_the_same_thing_in_the_same_state_is_told_the_same(profile):
    # `factor` has no class, so the cache never keeps it, and a model does not repeat itself:
    # here it answers differently every time it is asked.
    count = iter(range(100))
    model = Scripted(lambda _request: answer(f"360: answer {next(count)}\n"))
    responder = service(profile, model)
    first = await replies(responder, shell("factor 360", slice=TMP))
    again = await replies(responder, shell("factor 360", slice=TMP, request_id="r2", seq=4))
    assert len(model.requests) == 1  # the second was not put to the model
    assert first[-1].stdout == again[-1].stdout == "360: answer 0\n"
    assert again[-1].rung == "cache" and again[-1].ops == []
    # Another session is another conversation with the host.
    other = await replies(responder, shell("factor 360", slice=TMP, session_id="s2"))
    assert other[-1].stdout == "360: answer 1\n"


async def test_what_a_session_was_told_holds_only_while_the_state_does(profile):
    count = iter(range(100))
    model = Scripted(lambda _request: answer(f"{next(count)}\n"))
    responder = service(profile, model)
    seen = [
        *TMP,
        {"path": "/tmp/f", "type": "file", "mode": 0o644, "uid": 0, "size": 3, "head": "abc"},
    ]
    grown = [
        *TMP,
        {"path": "/tmp/f", "type": "file", "mode": 0o644, "uid": 0, "size": 6, "head": "abcdef"},
    ]
    one = await replies(responder, shell("sum /tmp/f", slice=seen))
    two = await replies(responder, shell("sum /tmp/f", slice=seen, request_id="r2"))
    three = await replies(responder, shell("sum /tmp/f", slice=grown, request_id="r3"))
    assert [r[-1].stdout for r in (one, two, three)] == ["0\n", "0\n", "1\n"]
    # Somewhere else it is another question too.
    four = await replies(responder, shell("sum /tmp/f", slice=seen, request_id="r4", cwd="/tmp"))
    assert four[-1].stdout == "2\n"


async def test_an_answer_that_changed_something_is_not_kept_for_the_session(profile):
    made = answer("", ops=[{"op": "mkdir", "path": "/tmp/d", "mode": "755"}])
    model = Scripted(made)
    responder = service(profile, model)
    first = await replies(responder, shell("install -d /tmp/d", slice=TMP))
    assert [op.op for op in first[-1].ops] == ["mkdir"]
    # The decoy has not reported the change yet; asked again, the model is asked again.
    await replies(responder, shell("install -d /tmp/d", slice=TMP, request_id="r2"))
    assert len(model.requests) == 2


# ------------------------------------------------------------------ where a program stands

WEEK = 7 * 86400.0


def refused(responder) -> list[str]:
    return [s["verb"] for s in responder.cache.standings() if s["state"] == "refused"]


async def test_a_program_that_could_not_be_answered_stays_refused_for_the_next_login(profile):
    # As the consistency probes found it: the first answer misses its deadline, the emulator
    # says "cannot execute binary file", and a minute later another login is given a working
    # program. The first answer decides.
    slow = Scripted(answer("ANSI_X3.4-1968\n"), before=0.5)
    responder = service(profile, slow, first_line_s=0.05, refusal_s=WEEK)
    first = await replies(responder, shell("locale charmap"))
    assert first == [Abort(reason="deadline:first_line")]
    assert last_record(responder)["standing"] == "refused"
    slow.before = 0.0  # the model is quick again
    again = await replies(responder, shell("locale charmap", session_id="s2"))
    assert again == [Abort(reason="refused")]
    assert len(slow.requests) == 1  # and it is not asked
    # Any use of the program: the emulator's words were about the program, not the options.
    other = await replies(responder, shell("/usr/bin/locale -a", session_id="s3"))
    assert other == [Abort(reason="refused")]
    # Another program is not touched.
    assert isinstance((await replies(responder, shell("factor 360", session_id="s4")))[-1], End)
    assert refused(responder) == ["locale"]


async def test_a_program_that_answered_first_is_never_refused_afterwards(profile):
    model = Scripted(lambda _r: answer("ok\n"))
    responder = service(profile, model, first_line_s=0.05, refusal_s=WEEK)
    assert isinstance((await replies(responder, shell("locale charmap")))[-1], End)
    model.before = 0.5
    late = await replies(responder, shell("locale language", session_id="s2"))
    assert late == [Abort(reason="deadline:first_line")]  # this once the emulator answers
    assert "standing" not in last_record(responder) and refused(responder) == []
    model.before = 0.0
    assert isinstance(
        (await replies(responder, shell("locale territory", session_id="s3")))[-1], End
    )


async def test_a_refusal_lapses_and_can_be_forgiven(profile):
    slow = Scripted(answer("x\n"), before=0.5)
    responder = service(profile, slow, first_line_s=0.05, refusal_s=WEEK)
    await replies(responder, shell("locale charmap"))
    cache, deployment = responder.cache, profile["deployment_id"]
    assert cache.standing(deployment, "locale") == "refused"
    # A week on, the host has been repaired.
    assert cache.standing(deployment, "locale", now=time.time() + WEEK + 1) is None
    await replies(responder, shell("locale charmap", session_id="s2"))
    assert cache.standing(deployment, "locale") == "refused"
    assert cache.forgive("locale") == 1 and cache.standings() == []


async def test_what_is_not_about_the_program_decides_nothing(profile):
    responder = service(profile, Scripted(answer("x\n")), refusal_s=WEEK)
    # A class that is never generated, another deployment's request, an input too long.
    assert (await replies(responder, shell("vi /etc/hosts")))[0].reason.startswith("class:")
    await replies(responder, shell("locale charmap", deployment_id="other"))
    await replies(responder, shell("locale " + "9" * 2000))
    assert responder.cache.standings() == []
    # And with standings off (the default of the code, and `replay`'s always), none is kept.
    off = service(profile, Scripted(answer("x\n"), before=0.5), first_line_s=0.05)
    await replies(off, shell("locale charmap"))
    assert off.cache.standings() == []
    assert (await replies(off, shell("locale charmap", session_id="s2"))) == [
        Abort(reason="deadline:first_line")
    ]
