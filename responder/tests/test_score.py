"""The held-out scorer's judgement and counting, with a stand-in for the model server."""

from __future__ import annotations

import json

import httpx
from mirage_responder import score


def real(stdout: str = "ok\n", stderr: str = "", code: int = 0) -> str:
    return json.dumps({"stdout": stdout, "stderr": stderr, "exit_code": code, "ops": []})


def test_an_answer_is_the_real_hosts_or_it_is_not():
    assert score.judge(real(), real()) == "same"
    # Spacing and key order of the JSON are not the answer; its three values are.
    assert score.judge('{"exit_code":0,"stderr":"","stdout":"ok\\n","ops":[]}', real()) == "same"
    assert score.judge(real(stderr="warning\n"), real()) == "stdout"
    assert score.judge(real(code=1), real()) == "stdout"
    assert score.judge(real("other\n"), real()) == "wrong"
    assert score.judge(real("", "x: not found\n", 127), real("", "y: not found\n", 127)) == "wrong"
    assert score.judge("not json", real()) == "broken"
    assert score.judge("[1]", real()) == "broken"
    assert score.judge(None, real()) == "broken"


async def test_rows_are_put_as_in_service_and_counted(monkeypatch):
    asked: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        asked.append(body)
        said = real("right\n") if "good" in body["messages"][1]["content"] else real("wrong\n")
        if "down" in body["messages"][1]["content"]:
            return httpx.Response(500)
        return httpx.Response(200, json={"choices": [{"message": {"content": said}}]})

    original = httpx.AsyncClient

    def client(**kwargs):
        return original(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(score.httpx, "AsyncClient", client)
    rows = [
        {"cmd": f"c{i}", "source": src, "answer": real("right\n"),
         "messages": [{"role": "system", "content": "S"}, {"role": "user", "content": kind}]}
        for i, (src, kind) in enumerate([("seed", "good"), ("seed", "bad"), ("option", "good"), ("option", "down")])
    ]  # fmt: skip
    out = await score.score(rows, "http://llm:8080", parallel=2, samples=5)
    assert (out["rows"], out["same"], out["wrong"], out["broken"]) == (4, 2, 1, 1)
    assert out["by_source"] == {"option": {"rows": 2, "same": 1}, "seed": {"rows": 2, "same": 1}}
    assert {s["cmd"] for s in out["samples"]} == {"c1", "c3"}
    assert all(b["response_format"]["json_schema"]["schema"] == score.prompt.SCHEMA for b in asked)
    assert all(
        b["max_tokens"] == 400 and b["temperature"] == score.prompt.TEMPERATURE for b in asked
    )


async def test_asked_twice_the_count_of_equal_answers_is_reported(monkeypatch):
    seen: dict[str, int] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["temperature"] == 0.0
        kind = body["messages"][1]["content"]
        seen[kind] = seen.get(kind, 0) + 1
        # "steady" says the same both times; "wavering" does not.
        said = real("a\n") if kind == "steady" or seen[kind] == 1 else real("b\n")
        return httpx.Response(200, json={"choices": [{"message": {"content": said}}]})

    original = httpx.AsyncClient
    monkeypatch.setattr(
        score.httpx,
        "AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )
    rows = [
        {"cmd": kind, "source": "seed", "answer": real("a\n"),
         "messages": [{"role": "system", "content": "S"}, {"role": "user", "content": kind}]}
        for kind in ("steady", "wavering")
    ]  # fmt: skip
    out = await score.score(rows, "http://llm:8080", 2, 0, temperature=0.0, twice=True)
    assert (out["same"], out["repeats_the_same"], out["temperature"]) == (2, 1, 0.0)
    assert seen == {"steady": 2, "wavering": 2}
