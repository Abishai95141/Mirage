"""Model backends (docs/06-phase-3-spec.md, decision R10): three behind one interface.

``replay``     serves recorded answers. It is what CI uses and the default everywhere a model
               is not running. A request with no recording is an error, never a guess, so a
               changed scenario or prompt forces a new recording.
``llama``      a ``llama-server`` on the internal model network (the Linux host).
``llama-dev``  the same client pointed at a developer's own server; it exists only under a
               compose profile that refuses to start beside a published edge.

A recording is keyed by a hash of the whole model request: the prompt in all its parts and
every sampling parameter. :class:`Recording` wraps a live backend and writes what it said.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx

log = logging.getLogger("mirage_responder.backends")


@dataclass(frozen=True)
class ModelRequest:
    system: str  # the fixed part: the same for every request of a profile
    state: str  # what this session has done, and what the command can see
    command: str  # the input, as data
    max_tokens: int
    temperature: float
    seed: int
    schema_version: str

    def key(self) -> str:
        text = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(text.encode()).hexdigest()

    def messages(self) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": self.system},
            {"role": "user", "content": self.state + "\n\n" + self.command},
        ]


@dataclass(frozen=True)
class Usage:
    prompt_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0


class BackendError(RuntimeError):
    """The model could not be asked, or stopped answering."""


class Unrecorded(BackendError):
    """``replay`` was asked something it has no recording of."""


class Backend(Protocol):
    name: str
    model_version: str

    def generate(self, request: ModelRequest) -> AsyncIterator[str | Usage]:
        """The answer's text in pieces, then its usage."""
        ...

    async def healthy(self) -> bool: ...


def recording_path(directory: Path, key: str) -> Path:
    return directory / f"{key}.json"


class Replay:
    name = "replay"

    def __init__(self, directory: Path, piece: int = 48) -> None:
        self.directory, self._piece = directory, piece
        self.model_version = "replay"

    async def generate(self, request: ModelRequest) -> AsyncIterator[str | Usage]:
        path = recording_path(self.directory, request.key())
        if not path.is_file():
            raise Unrecorded(request.key())
        doc = json.loads(path.read_text())
        text = doc["text"]
        for i in range(0, len(text), self._piece):
            yield text[i : i + self._piece]
        usage = doc.get("usage") or {}
        yield Usage(
            int(usage.get("prompt_tokens", 0)),
            int(usage.get("output_tokens", 0)),
            int(usage.get("cached_tokens", 0)),
        )

    async def healthy(self) -> bool:
        return self.directory.is_dir()


class Recording:
    """A live backend whose every answer is written down for ``replay``."""

    def __init__(self, inner: Backend, directory: Path) -> None:
        self.inner, self.directory = inner, directory
        self.name, self.model_version = inner.name, inner.model_version
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            log.warning("recordings directory %s: %s", directory, exc)

    async def generate(self, request: ModelRequest) -> AsyncIterator[str | Usage]:
        pieces: list[str] = []
        usage = Usage()
        async for item in self.inner.generate(request):
            if isinstance(item, Usage):
                usage = item
            else:
                pieces.append(item)
            yield item
        doc: dict[str, Any] = {
            "key": request.key(),
            "model": self.inner.model_version,
            "request": asdict(request),
            "text": "".join(pieces),
            "usage": asdict(usage),
        }
        path = recording_path(self.directory, request.key())
        try:
            path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        except OSError as exc:
            # The answer was given; that it could not be written down is not the session's
            # trouble. (Found live: a bind mount the service's user may not write.)
            log.warning("recording %s not written: %s", path.name, exc)

    async def healthy(self) -> bool:
        return await self.inner.healthy()

    def prime_with(self, system: str, slots: int) -> None:
        prime = getattr(self.inner, "prime_with", None)
        if prime is not None:
            prime(system, slots)


class Llama:
    """A ``llama-server`` (llama.cpp), over its OpenAI-compatible streaming endpoint, with the
    answer's JSON schema enforced by the server's grammar."""

    def __init__(self, url: str, name: str, schema: dict[str, Any], model: str = "") -> None:
        self.url, self.name, self._schema = url.rstrip("/"), name, schema
        self.model_version = model or "unknown"
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=2.0))
        self._prime: tuple[str, int] | None = None
        self._primed = False
        self._priming = asyncio.Lock()

    async def generate(self, request: ModelRequest) -> AsyncIterator[str | Usage]:
        body = {
            "messages": request.messages(),
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "seed": request.seed,
            "stream": True,
            "stream_options": {"include_usage": True},
            "cache_prompt": True,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "answer", "strict": True, "schema": self._schema},
            },
        }
        usage = Usage()
        try:
            async with self._client.stream(
                "POST", f"{self.url}/v1/chat/completions", json=body
            ) as response:
                if response.status_code != 200:
                    raise BackendError(f"status {response.status_code}")
                async for line in response.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    event = json.loads(data)
                    for choice in event.get("choices") or []:
                        piece = (choice.get("delta") or {}).get("content")
                        if piece:
                            yield piece
                    if event.get("usage"):
                        u = event["usage"]
                        details = u.get("prompt_tokens_details") or {}
                        usage = Usage(
                            int(u.get("prompt_tokens", 0)),
                            int(u.get("completion_tokens", 0)),
                            int(details.get("cached_tokens", 0)),
                        )
        except (httpx.HTTPError, ValueError) as exc:
            raise BackendError(type(exc).__name__) from exc
        yield usage

    def prime_with(self, system: str, slots: int) -> None:
        """The fixed part of every prompt of this deployment, and how many answers the server
        makes at once. See :meth:`healthy`."""
        self._prime, self._primed = (system, max(1, slots)), False

    async def healthy(self) -> bool:
        """The server is up, and every one of its slots has read the fixed part of the prompt.

        A slot that has not must read it before the first answer it gives, and reading 900
        tokens takes longer than the first line may (1.8 s on the lab host's GPU, against
        1.5 s). So the first answers after a start would all be fallbacks, one for each
        slot. Instead the slots are made to read it once, all at the same moment so that
        each takes one request, and until they have the backend is not healthy and the
        decoy does not ask. A server that went away and came back is primed again."""
        try:
            response = await self._client.get(f"{self.url}/health", timeout=2.0)
        except httpx.HTTPError:
            self._primed = False
            return False
        if response.status_code != 200:
            self._primed = False
            return False
        if self._prime is None or self._primed:
            return True
        if self._priming.locked():
            return False  # another check is at it
        async with self._priming:
            self._primed = await self._read_the_fixed_part()
        return self._primed

    async def _read_the_fixed_part(self) -> bool:
        assert self._prime is not None
        system, slots = self._prime
        body = {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": "true"},
            ],
            "max_tokens": 1,
            "temperature": 0.0,
            "cache_prompt": True,
            "stream": False,
        }

        async def one() -> bool:
            try:
                reply = await self._client.post(f"{self.url}/v1/chat/completions", json=body)
            except httpx.HTTPError:
                return False
            return reply.status_code == 200

        return all(await asyncio.gather(*(one() for _ in range(slots))))

    async def close(self) -> None:
        await self._client.aclose()
