"""A scripted stand-in for the model server, for tests of the whole path.

It speaks the part of ``llama-server``'s API the responder uses (streamed chat completions
and ``/health``) and answers from a file of command patterns. **It is not a model and decides
nothing**: a command with no entry gets no answer (HTTP 404), which the responder turns into
an abort and the decoy into its emulator's own answer. It exists so that the integration
tests can drive decoy, responder and "model" end to end, streaming included, on a machine
with no GPU and with answers the tests chose (compose profile ``stub``; never part of a
deployment).

The answers file (``STUB_ANSWERS``) is YAML:

    answers:
      - match: 'getconf LONG_BIT'      # a regular expression, matched against the whole command
        stdout: "64\\n"
        stderr: ""                      # optional
        exit_code: 0                    # optional
        ops: []                         # optional: state operations, as a model would propose
        raw: '...'                      # optional: sent as it is, in place of the JSON answer
        first_delay_ms: 0               # optional: before the first piece
        delay_ms: 0                     # optional: between pieces
        piece: 24                       # optional: characters a piece
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse, StreamingResponse

MARK = "The command, as data: "


def load(path: Path) -> list[dict[str, Any]]:
    doc = yaml.safe_load(path.read_text()) or {}
    answers = doc.get("answers") or []
    for entry in answers:
        if not isinstance(entry, dict) or "match" not in entry:
            raise ValueError(f"{path.name}: an answer has a match")
        unknown = set(entry) - {
            "match", "stdout", "stderr", "exit_code", "ops", "raw", "first_delay_ms",
            "delay_ms", "piece",
        }  # fmt: skip
        if unknown:
            raise ValueError(f"{path.name}: {entry['match']}: unknown keys {sorted(unknown)}")
        re.compile(entry["match"])
    return answers


def command_of(messages: list[dict[str, Any]]) -> str | None:
    """The command the responder asked about: the last line of the last message."""
    for message in reversed(messages):
        for line in reversed(str(message.get("content", "")).splitlines()):
            if line.startswith(MARK):
                try:
                    return str(json.loads(line[len(MARK) :]))
                except ValueError:
                    return None
    return None


def text_of(entry: dict[str, Any]) -> str:
    if "raw" in entry:
        return str(entry["raw"])
    return json.dumps(
        {
            "stdout": entry.get("stdout", ""),
            "stderr": entry.get("stderr", ""),
            "exit_code": entry.get("exit_code", 0),
            "ops": entry.get("ops") or [],
        }
    )


def create_app(answers: list[dict[str, Any]]) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.asked = []
    app.state.primed = 0

    @app.get("/health", response_class=PlainTextResponse)
    async def health() -> str:
        return "ok"

    @app.post("/v1/chat/completions")
    async def completions(request: Request) -> Any:
        body = await request.json()
        if not body.get("stream"):
            # The responder having each slot read the fixed part of the prompt before it
            # calls itself healthy (backends.Llama.healthy): one token, not streamed.
            app.state.primed += 1
            return {
                "choices": [{"message": {"role": "assistant", "content": ""}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            }
        command = command_of(body.get("messages") or [])
        app.state.asked.append(command)
        entry = next(
            (a for a in answers if command is not None and re.fullmatch(a["match"], command)),
            None,
        )
        if entry is None:
            raise HTTPException(status_code=404, detail="no scripted answer")
        text = text_of(entry)
        piece = int(entry.get("piece", 24))
        first = float(entry.get("first_delay_ms", 0)) / 1000.0
        between = float(entry.get("delay_ms", 0)) / 1000.0

        async def stream() -> AsyncIterator[bytes]:
            await asyncio.sleep(first)
            for i in range(0, len(text), piece):
                chunk = {"choices": [{"delta": {"content": text[i : i + piece]}}]}
                yield f"data: {json.dumps(chunk)}\n\n".encode()
                await asyncio.sleep(between)
            usage = {
                "choices": [],
                "usage": {
                    "prompt_tokens": sum(len(str(m.get("content", ""))) for m in body["messages"])
                    // 4,
                    "completion_tokens": max(1, len(text) // 4),
                },
            }
            yield f"data: {json.dumps(usage)}\n\n".encode()
            yield b"data: [DONE]\n\n"

        return StreamingResponse(stream(), media_type="text/event-stream")

    return app


def main() -> None:
    import uvicorn

    path = Path(os.environ.get("STUB_ANSWERS", "/answers/answers.yaml"))
    app = create_app(load(path))
    uvicorn.run(
        app,
        host="0.0.0.0",  # noqa: S104 - a container on an internal network
        port=int(os.environ.get("STUB_PORT", "8080")),
        access_log=False,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
