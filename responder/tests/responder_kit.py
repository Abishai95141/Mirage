"""What the responder's tests share: a profile as the generator writes one, a request, and a
backend that says what a test tells it to."""

from __future__ import annotations

import asyncio
import json
import shlex
from collections.abc import AsyncIterator, Callable
from typing import Any

from mirage_responder.app import Responder, Settings, create_app
from mirage_responder.backends import ModelRequest, Usage
from pydantic import BaseModel

from mirage_schema.respond import RespondRequest

TOKEN = "t" * 32
PROFILE: dict[str, Any] = {
    "version": 1,
    "deployment_id": "web-db-1",
    "hostname": "srv-web-03",
    "os": "Debian GNU/Linux 12 (bookworm)",
    "kernel": "Linux 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01) x86_64",
    "kernel_release": "6.1.0-18-amd64",
    "arch": "amd64",
    "address": "10.20.4.17",
    "timezone": "Etc/UTC",
    "hardware": {"cpu_model": "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz", "cpus": 2},
    "users": [
        {"name": "root", "uid": 0, "home": "/root"},
        {"name": "caleb", "uid": 1000, "home": "/home/caleb"},
    ],
    "services": [
        {"name": "sshd", "version": "OpenSSH_9.2p1 Debian-2+deb12u3", "port": 22},
        {"name": "nginx", "version": "1.22.1", "port": 80},
    ],
    "token_paths": ["/root/.my.cnf"],
}
# The directories most tests' commands name, as the decoy would show them.
TMP = [
    {"path": "/tmp", "type": "dir", "mode": 0o1777, "uid": 0, "gid": 0},
    {"path": "/root", "type": "dir", "mode": 0o700, "uid": 0, "gid": 0},
]


def request(**over: Any) -> RespondRequest:
    body = {
        "request_id": "r1",
        "session_id": "s1",
        "deployment_id": "web-db-1",
        "seq": 3,
        "src": {"ip": "203.0.113.9", "port": 40000},
        "user": "root",
        "uid": 0,
        "cwd": "/root",
        "argv": ["getent", "passwd", "caleb"],
        "input": "getent passwd caleb",
        "budget": {"max_tokens": 400, "deadline_ms": 10000},
    }
    return RespondRequest.model_validate(body | over)


def shell(line: str, **over: Any) -> RespondRequest:
    """A request for a command line, cut into words as a shell would cut it."""
    return request(input=line, argv=shlex.split(line), **over)


def answer(stdout: str = "", stderr: str = "", exit_code: int = 0, ops: list | None = None) -> str:
    """An answer as a model writes one: the four fields, stdout first."""
    return json.dumps(
        {"stdout": stdout, "stderr": stderr, "exit_code": exit_code, "ops": ops or []}
    )


class Scripted:
    """A backend that answers from a function of the request, in pieces, as slowly as told."""

    name = "scripted"
    model_version = "test-model-1"

    def __init__(
        self,
        say: str | Callable[[ModelRequest], str],
        *,
        piece: int = 9,
        before: float = 0.0,
        between: float = 0.0,
        usage: Usage | None = None,
        fail: Exception | None = None,
    ) -> None:
        self.say, self.piece, self.before, self.between = say, piece, before, between
        self.usage, self.fail = usage, fail
        self.requests: list[ModelRequest] = []
        self.closed = 0
        self.up = True

    async def generate(self, request: ModelRequest) -> AsyncIterator[str | Usage]:
        self.requests.append(request)
        text = self.say(request) if callable(self.say) else self.say
        try:
            await asyncio.sleep(self.before)
            if self.fail is not None:
                raise self.fail
            for i in range(0, len(text), self.piece):
                yield text[i : i + self.piece]
                await asyncio.sleep(self.between)
            yield self.usage or Usage(prompt_tokens=300, output_tokens=max(1, len(text) // 4))
        finally:
            self.closed += 1

    async def healthy(self) -> bool:
        return self.up


def service(profile: dict[str, Any], backend: Any, **over: Any) -> Responder:
    """A responder with nothing on disk: its records are kept in memory."""
    settings = Settings(token=TOKEN, profile=profile, backend=backend, **over)
    return create_app(settings).state.responder


async def replies(responder: Responder, req: RespondRequest) -> list[BaseModel]:
    return [item async for item in responder.answer(req)]
