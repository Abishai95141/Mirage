"""The answer cache and the model backends (phase 3 spec 3.2b)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from mirage_responder import prompt
from mirage_responder.backends import (
    BackendError,
    Llama,
    ModelRequest,
    Recording,
    Replay,
    Unrecorded,
    Usage,
    recording_path,
)
from mirage_responder.cache import Answer, Cache
from responder_kit import Scripted, answer


def model_request(command: str = "uptime", **over) -> ModelRequest:
    fields = {
        "system": "the server",
        "state": "the state",
        "command": command,
        "max_tokens": 400,
        "temperature": 0.2,
        "seed": 7,
        "schema_version": "1:abc",
    }
    return ModelRequest(**(fields | over))


async def collect(backend, request: ModelRequest) -> tuple[str, Usage]:
    text, usage = "", Usage()
    async for item in backend.generate(request):
        if isinstance(item, Usage):
            usage = item
        else:
            text += item
    return text, usage


# ------------------------------------------------------------------ the cache


def test_a_kept_answer_comes_back_and_is_counted(tmp_path: Path):
    cache = Cache(tmp_path / "c" / "cache.db", "m1", "p1")
    assert cache.get("web-db-1", "uname -r", "") is None
    cache.put("web-db-1", "uname -r", "", Answer("6.1.0-18-amd64\n", "", 0, 9))
    assert cache.get("web-db-1", "uname -r", "") == Answer("6.1.0-18-amd64\n", "", 0, 9)
    assert (cache.hits, cache.misses, len(cache)) == (1, 1, 1)


def test_the_key_is_the_deployment_the_command_and_the_state():
    cache = Cache(":memory:", "m1", "p1")
    cache.put("web-db-1", "ls /tmp", "f1", Answer("a\n", "", 0))
    assert cache.get("web-db-2", "ls /tmp", "f1") is None  # another deployment
    assert cache.get("web-db-1", "ls /tmp", "f2") is None  # another state
    assert cache.get("web-db-1", "ls  /tmp", "f1") is None  # the caller normalises
    assert cache.get("web-db-1", "ls /tmp", "f1") is not None


@pytest.mark.parametrize("versions", [("m2", "p1"), ("m1", "p2")])
def test_another_model_or_prompt_invalidates_an_entry(tmp_path: Path, versions):
    path = tmp_path / "cache.db"
    first = Cache(path, "m1", "p1")
    first.put("d", "uname -r", "", Answer("x\n", "", 0))
    first.close()
    second = Cache(path, *versions)
    assert second.get("d", "uname -r", "") is None
    assert len(second) == 0  # dropped when met, not merely skipped


def test_the_cache_survives_a_restart(tmp_path: Path):
    path = tmp_path / "cache.db"
    first = Cache(path, "m1", "p1")
    first.put("d", "uname -r", "", Answer("x\n", "warn\n", 3, 4))
    first.close()
    assert Cache(path, "m1", "p1").get("d", "uname -r", "") == Answer("x\n", "warn\n", 3, 4)


def test_eviction_and_the_promotion_list():
    cache = Cache(":memory:", "m1", "p1")
    cache.put("d", "uname -r", "", Answer("x\n", "", 0))
    cache.put("d", "ls /tmp", "f1", Answer("a\n", "", 0))
    cache.put("d", "ls /tmp", "f2", Answer("b\n", "", 0))
    for _ in range(3):
        cache.get("d", "ls /tmp", "f1")
    cache.get("d", "ls /tmp", "f2")
    cache.get("d", "uname -r", "")
    assert cache.most_answered() == [("d", "ls /tmp", 4), ("d", "uname -r", 1)]
    assert cache.evict("d", "uname -r", "") is True
    assert cache.evict("d", "uname -r", "") is False
    assert cache.get("d", "uname -r", "") is None


# ------------------------------------------------------------------ replay and recording


def test_the_request_key_covers_every_field():
    base = model_request()
    assert base.key() == model_request().key()
    for change in (
        {"system": "another server"},
        {"state": "another state"},
        {"command": "uptime -s"},
        {"max_tokens": 399},
        {"temperature": 0.3},
        {"seed": 8},
        {"schema_version": "2:abc"},
    ):
        assert model_request(**change).key() != base.key(), change


async def test_a_recording_replays_byte_for_byte(tmp_path: Path):
    text = answer(" 10:14:02 up 41 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n")
    live = Scripted(text, usage=Usage(310, 41, 290))
    recorded = Recording(live, tmp_path / "rec")
    assert (recorded.name, recorded.model_version) == ("scripted", "test-model-1")
    request = model_request()
    assert await collect(recorded, request) == (text, Usage(310, 41, 290))

    kept = json.loads(recording_path(tmp_path / "rec", request.key()).read_text())
    assert kept["text"] == text and kept["request"]["command"] == "uptime"
    assert kept["model"] == "test-model-1"

    replay = Replay(tmp_path / "rec", piece=5)
    for _ in range(2):  # the same answer every time, whatever the piece size
        assert await collect(replay, request) == (text, Usage(310, 41, 290))
    assert await collect(Replay(tmp_path / "rec", piece=1000), request) == (
        text,
        Usage(310, 41, 290),
    )


async def test_replay_fails_on_what_it_has_no_recording_of(tmp_path: Path):
    replay = Replay(tmp_path)
    with pytest.raises(Unrecorded):
        await collect(replay, model_request("id"))
    assert await replay.healthy() is True
    assert await Replay(tmp_path / "absent").healthy() is False


async def test_an_answer_that_failed_is_not_recorded(tmp_path: Path):
    recorded = Recording(Scripted("{", fail=BackendError("gone")), tmp_path)
    with pytest.raises(BackendError):
        await collect(recorded, model_request())
    assert list(tmp_path.iterdir()) == []


# ------------------------------------------------------------------ the llama backend


def llama(handler) -> Llama:
    backend = Llama("http://llm:8080/", "llama", prompt.SCHEMA, "qwen-test")
    backend._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return backend


def sse(*events: dict | str) -> bytes:
    lines = [f"data: {e if isinstance(e, str) else json.dumps(e)}\n\n" for e in events]
    return "".join(lines).encode()


async def test_llama_sends_the_schema_and_the_seed_and_reads_the_stream():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"], seen["body"] = str(request.url), json.loads(request.content)
        body = sse(
            {"choices": [{"delta": {"role": "assistant"}}]},
            {"choices": [{"delta": {"content": '{"stdout":"a'}}]},
            {"choices": [{"delta": {"content": '\\n","stderr":"","exit_code":0,"ops":[]}'}}]},
            {
                "choices": [],
                "usage": {
                    "prompt_tokens": 443,
                    "completion_tokens": 17,
                    "prompt_tokens_details": {"cached_tokens": 426},
                },
            },
            "[DONE]",
        )
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    backend = llama(handler)
    text, usage = await collect(backend, model_request())
    assert json.loads(text) == {"stdout": "a\n", "stderr": "", "exit_code": 0, "ops": []}
    assert usage == Usage(443, 17, 426)
    body = seen["body"]
    assert seen["url"] == "http://llm:8080/v1/chat/completions"
    assert body["seed"] == 7 and body["temperature"] == 0.2 and body["max_tokens"] == 400
    assert body["stream"] is True and body["cache_prompt"] is True
    assert body["response_format"]["json_schema"]["schema"] == prompt.SCHEMA
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert body["messages"][0]["content"] == "the server"  # the fixed part first, alone
    assert "tools" not in body  # the model is given no tool
    await backend.close()


@pytest.mark.parametrize(
    "handler",
    [
        lambda request: httpx.Response(503, content=b"loading model"),
        lambda request: httpx.Response(200, content=b"data: {not json\n\n"),
    ],
)
async def test_llama_failures_are_backend_errors(handler):
    backend = llama(handler)
    with pytest.raises(BackendError):
        await collect(backend, model_request())


async def test_llama_that_cannot_be_reached():
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    backend = llama(refuse)
    with pytest.raises(BackendError):
        await collect(backend, model_request())
    assert await backend.healthy() is False


async def test_llama_is_healthy_once_every_slot_has_read_the_fixed_part():
    seen: list[dict] = []
    up = True

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200 if up else 503)
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": ""}}]})

    backend = llama(handler)
    backend.prime_with("THE FIXED PART", 4)
    assert await backend.healthy() is True
    # Four requests, one for each slot, each the fixed part and one token and no more.
    assert len(seen) == 4
    assert all(
        body["messages"][0] == {"role": "system", "content": "THE FIXED PART"} for body in seen
    )
    assert all(
        body["max_tokens"] == 1 and body["cache_prompt"] and not body["stream"] for body in seen
    )
    assert await backend.healthy() is True
    assert len(seen) == 4  # once is enough while the server stays up
    up = False
    assert await backend.healthy() is False
    up = True
    assert await backend.healthy() is True
    assert len(seen) == 8  # a server that came back has empty slots again


async def test_llama_whose_slots_cannot_be_primed_is_not_healthy():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200 if request.url.path == "/health" else 500)

    backend = llama(handler)
    backend.prime_with("THE FIXED PART", 2)
    assert await backend.healthy() is False
    assert await backend.healthy() is False  # and it tries again at the next check


async def test_llama_health_is_the_servers_own():
    states = iter([200, 503])
    backend = llama(lambda request: httpx.Response(next(states)))
    assert await backend.healthy() is True
    assert await backend.healthy() is False  # still loading its model
