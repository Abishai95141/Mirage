"""The responder service (docs/06-phase-3-spec.md, 3.2b): ``POST /v1/respond``.

One request passes through, in this order: the journal (does it join what is held?), the
command's class (is it one that may be generated at all?), the budgets, the cache, the model,
and on the way out the decoder, the output filter and the validation of any operations.
Whatever goes wrong, the reply is ``abort`` with a reason, and the decoy answers as its
emulator would: an abort is safe.

Every request leaves one record in the responder's log (rung, tokens, timings, operations,
filter hits), which joins the decoy's own event on ``request_id``. The record never holds a
generated line.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import os
import threading
import time
from collections import OrderedDict
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, ValidationError

from mirage_responder import prompt
from mirage_responder.backends import Backend, BackendError, Unrecorded, Usage
from mirage_responder.cache import REFUSED, WORKS, Answer, Cache
from mirage_responder.classes import (
    CACHED,
    STREAMED,
    Classes,
    CommandClass,
    named_paths,
    normalise,
)
from mirage_responder.classes import (
    REFUSED as REFUSED_CLASSES,
)
from mirage_responder.decode import Malformed, Stream
from mirage_responder.filter import Filter
from mirage_responder.state import Rejected, Sessions
from mirage_schema.ops import parse_ops
from mirage_schema.respond import (
    MAX_INPUT_BYTES,
    Abort,
    End,
    Out,
    RespondRequest,
    Resync,
    dump,
)

log = logging.getLogger("mirage.responder")

# Budgets (spec 3.2b; defaults, revised from measurements).
SESSION_TOKENS = 3_000  # output tokens for one session
SOURCE_TOKENS = 15_000  # for one source address in one day
FIRST_LINE_S = 1.5  # a streamed answer's first line
MIN_ALLOWANCE = 48  # fewer output tokens than this cannot hold an answer's four fields
SOURCES_HELD = 16384
MAX_SAID = 64  # answers a session is held to, the oldest dropped first
# Reasons for no answer that say nothing about the program asked for.
NOT_OF_THE_PROGRAM = frozenset({"input_too_long", "other_deployment", "refused"})


@dataclass
class Settings:
    token: str
    profile: dict[str, Any]
    backend: Backend
    cache_path: Path | str = ":memory:"
    log_path: Path | None = None
    concurrency: int = 1  # answers in the making at once: one on a laptop, four on the host
    first_line_s: float = FIRST_LINE_S
    # How long a program that could not be answered stays refused for everyone on the
    # deployment (cache.STANDINGS). 0 keeps no standings; the service's default is a week.
    refusal_s: float = 0.0


class RecordLog:
    """Append-only JSON lines, one write a line."""

    def __init__(self, path: Path | None) -> None:
        self._f = None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._f = path.open("a", buffering=1, encoding="utf-8")
        self._lock = threading.Lock()
        self.records: list[dict[str, Any]] = []  # kept only when there is no file (tests)

    def write(self, record: dict[str, Any]) -> None:
        if self._f is None:
            self.records.append(record)
            return
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n"
        with self._lock:
            self._f.write(line)


@dataclass
class SourceBudget:
    """Output tokens spent for each source address today."""

    clock: Any = time.time
    spent: OrderedDict[str, tuple[int, int]] = field(default_factory=OrderedDict)

    def left(self, ip: str | None) -> int:
        if not ip:
            return SOURCE_TOKENS
        day, used = self.spent.get(ip, (0, 0))
        return SOURCE_TOKENS - (used if day == int(self.clock() // 86400) else 0)

    def spend(self, ip: str | None, tokens: int) -> None:
        if not ip or tokens <= 0:
            return
        today = int(self.clock() // 86400)
        day, used = self.spent.get(ip, (today, 0))
        self.spent[ip] = (today, tokens + (used if day == today else 0))
        self.spent.move_to_end(ip)
        while len(self.spent) > SOURCES_HELD:
            self.spent.popitem(last=False)


class Responder:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.profile = settings.profile
        self.backend = settings.backend
        self.classes = Classes.load()
        self.sessions = Sessions()
        self.sources = SourceBudget()
        self.system_text = prompt.system(self.profile)
        self.filter = Filter(self.system_text, prompt.facts(self.profile))
        self.token_paths = frozenset(self.profile.get("token_paths") or ())
        self.cache = Cache(
            settings.cache_path,
            self.backend.model_version,
            f"{prompt.PROMPT_VERSION}:{prompt.SCHEMA_VERSION}:{self.classes.version}",
            # Recordings are answers to exact requests: one that has none says nothing of
            # its program, so `replay` keeps no standings.
            0.0 if self.backend.name == "replay" else settings.refusal_s,
        )
        self.log = RecordLog(settings.log_path)
        self.in_flight = 0

    def holds_token(self, path: str) -> bool:
        return path in self.token_paths

    async def answer(self, req: RespondRequest) -> AsyncIterator[BaseModel]:
        """The reply's records, and one line in the log when it is over."""
        started = time.monotonic()
        record: dict[str, Any] = {
            "eventid": "responder.answer",
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "request_id": req.request_id,
            "session_id": req.session_id,
            "deployment_id": req.deployment_id,
            "seq": req.seq,
            "src_ip": req.src.ip,
            "verb": req.argv[0].rsplit("/", 1)[-1][:64],
            "backend": self.backend.name,
            "model_version": self.backend.model_version,
            "prompt_version": prompt.PROMPT_VERSION,
            "lines": 0,
            "ops_proposed": 0,
            "ops_applied": 0,
            "prompt_tokens": 0,
            "output_tokens": 0,
        }
        # Each layer closes the one inside it: when the decoy goes away (Ctrl-C), closing this
        # generator must reach the model's stream now, not when the collector gets to it.
        try:
            async with contextlib.aclosing(self._answer(req, record, started)) as items:
                async for item in items:
                    if isinstance(item, Out):
                        record["lines"] += 1
                        took = round((time.monotonic() - started) * 1000, 1)
                        record.setdefault("first_ms", took)
                    elif isinstance(item, Abort):
                        record["outcome"], record["reason"] = "abort", item.reason
                    elif isinstance(item, Resync):
                        record["outcome"] = "resync"
                    elif isinstance(item, End):
                        record["outcome"], record["rung"] = "end", item.rung
                        record["exit_code"] = item.exit_code
                        record["lines"] += len(_lines(item.stdout))
                    yield item
        finally:
            record["total_ms"] = round((time.monotonic() - started) * 1000, 1)
            record.setdefault("outcome", "cancelled")  # the decoy went away (Ctrl-C)
            self._note_standing(req, record)
            self.log.write(record)

    def _note_standing(self, req: RespondRequest, record: dict[str, Any]) -> None:
        """The first answer about a program decides where it stands on this deployment. An
        answer that could not be given, with nothing shown, was answered by the emulator's
        "cannot execute binary file": from then on the program is refused, so that the
        next login is told the same. What a refusal does not come from: the command's class
        and the budgets, which the decoy is told the same way every time, and a request
        that was never this deployment's."""
        outcome, reason = record.get("outcome"), str(record.get("reason", ""))
        if outcome == "end" and record.get("rung") == "model":
            self.cache.stand(req.deployment_id, record["verb"], WORKS)
        elif (
            outcome == "abort"
            and record["lines"] == 0
            and reason not in NOT_OF_THE_PROGRAM
            and not reason.startswith(("class:", "budget:"))
        ) and self.cache.stand(req.deployment_id, record["verb"], REFUSED, reason):
            record["standing"] = REFUSED

    async def _answer(
        self, req: RespondRequest, record: dict[str, Any], started: float
    ) -> AsyncIterator[BaseModel]:
        if len(req.input.encode()) > MAX_INPUT_BYTES:
            yield Abort(reason="input_too_long")
            return
        if req.deployment_id != self.profile["deployment_id"]:
            yield Abort(reason="other_deployment")
            return
        held = self.sessions.get(req.session_id)
        if (held is None and req.journal_from != 1) or (
            held is not None and not held.joins(req.journal_from)
        ):
            yield Resync(have=held.journal_seq if held else 0)
            return
        session = self.sessions.open(req)
        session.fold(req.journal_from, req.journal)
        session.env = dict(req.env)

        cls = self.classes.of(req.argv)
        record["class"] = cls.value
        if cls in REFUSED_CLASSES:
            yield Abort(reason=f"class:{cls.value}")
            return
        if self.cache.standing(req.deployment_id, record["verb"]) == REFUSED:
            yield Abort(reason="refused")
            return
        allowance = min(
            req.budget.max_tokens,
            SESSION_TOKENS - session.tokens_spent,
            self.sources.left(req.src.ip),
        )
        if allowance < MIN_ALLOWANCE:
            which = "source"
            if SESSION_TOKENS - session.tokens_spent < MIN_ALLOWANCE:
                which = "session"
            elif req.budget.max_tokens < MIN_ALLOWANCE:
                which = "answer"
            yield Abort(reason=f"budget:{which}")
            return

        command = normalise(req.argv)
        paths = named_paths(req.argv, req.cwd)
        fingerprint = "" if cls is CommandClass.STATELESS else session.fingerprint(paths, req.slice)
        if cls in CACHED:
            kept = self.cache.get(req.deployment_id, command, fingerprint)
            if kept is not None:
                for line, newline in _lines(kept.stdout):
                    yield Out(line=line, newline=newline)
                yield End(
                    stderr=kept.stderr,
                    exit_code=kept.exit_code,
                    rung="cache",
                    total_ms=round((time.monotonic() - started) * 1000, 1),
                )
                return

        # A command of a class the cache does not keep (one that changes something, or one
        # no class is known for) is still told the same thing twice: this session's own
        # answer to the same command in the same state. A model asked again does not repeat
        # itself (8 of 20 repeats differed in the bench, with the same seed), and a host that
        # answers `factor 360` two ways is no host. An answer that changed something is
        # never kept: after it the state is another, and so is the key.
        told = session.said.get((command, session.fingerprint(paths, req.slice)))
        if told is not None:
            stdout, stderr, exit_code = told
            if cls in STREAMED:
                for line, newline in _lines(stdout):
                    yield Out(line=line, newline=newline)
            yield End(
                stdout="" if cls in STREAMED else stdout,
                stderr=stderr,
                exit_code=exit_code,
                rung="cache",
                total_ms=round((time.monotonic() - started) * 1000, 1),
            )
            return

        if self.in_flight >= self.settings.concurrency:
            yield Abort(reason="busy")
            return
        self.in_flight += 1
        making = self._generate(req, record, started, session, cls, command, fingerprint, allowance)
        try:
            async with contextlib.aclosing(making) as items:
                async for item in items:
                    yield item
        finally:
            self.in_flight -= 1

    async def _generate(
        self,
        req: RespondRequest,
        record: dict[str, Any],
        started: float,
        session: Any,
        cls: CommandClass,
        command: str,
        fingerprint: str,
        allowance: int,
    ) -> AsyncIterator[BaseModel]:
        request = prompt.build(self.profile, session, req, command, fingerprint, allowance)
        stream, usage, shown = Stream(), Usage(), 0
        streaming = cls in STREAMED
        loop = asyncio.get_running_loop()
        whole_by = loop.time() + req.budget.deadline_ms / 1000.0
        first_by = min(whole_by, loop.time() + self.settings.first_line_s)
        reason = None

        def spent() -> None:
            # What the model wrote is charged however the answer ends: aborted, refused by
            # the filter, or cut off by the decoy going away. Without the model's own count
            # (it stopped early), four characters to a token.
            tokens = usage.output_tokens or -(-stream.size // 4)
            record["prompt_tokens"], record["output_tokens"] = usage.prompt_tokens, tokens
            session.tokens_spent += tokens
            self.sources.spend(req.src.ip, tokens)

        # The model is waited on one piece at a time, each wait bounded by the deadline in
        # force: the first line's until a line is out (or stdout turned out to be empty), the
        # whole answer's after. No record is yielded while a deadline is armed, so a deadline
        # can only ever interrupt the wait for the model.
        pieces = self.backend.generate(request).__aiter__()
        try:
            while reason is None:
                waiting_for_first = streaming and not shown and not stream.stdout_closed()
                by = first_by if waiting_for_first else whole_by
                try:
                    piece = await asyncio.wait_for(anext(pieces), max(by - loop.time(), 0.0))
                except StopAsyncIteration:
                    break
                except TimeoutError:
                    reason = "deadline:first_line" if waiting_for_first else "deadline"
                    break
                if isinstance(piece, Usage):
                    usage = piece
                    continue
                stream.feed(piece)
                if not streaming:
                    continue
                for line in stream.lines():
                    hit = self.filter.check(line)
                    if hit:
                        reason = f"filter:{hit.rule}"
                        break
                    shown += 1
                    yield Out(line=line)
        except Unrecorded:
            reason = "unrecorded"
        except BackendError:
            reason = "backend"
        except Malformed:
            reason = "malformed"
        finally:
            spent()
            closing = getattr(pieces, "aclose", None)
            if closing is not None:
                with contextlib.suppress(Exception):
                    await closing()
        if reason:
            if reason.startswith("filter:"):
                record["filter_hit"] = reason.split(":", 1)[1]
            yield Abort(reason=reason)
            return

        try:
            doc = stream.finish()
            ops = parse_ops(prompt.modes(doc["ops"]))
        except Malformed:
            # A model stopped at its token limit leaves its JSON open: the commonest cause.
            cut = usage.output_tokens >= request.max_tokens
            reason = "truncated" if cut else "malformed"
        except ValueError:
            reason = "ops:malformed"
        else:
            record["ops_proposed"] = len(ops)
            hit = self.filter.check_text(doc["stderr"])
            rest = [] if streaming else _lines(doc["stdout"])
            if streaming and stream.last():
                rest = [(doc["stdout"].rsplit("\n", 1)[-1], False)]
            for line, _newline in rest:
                hit = hit or self.filter.check(line)
            if hit:
                reason = f"filter:{hit.rule}"
                record["filter_hit"] = hit.rule
            elif ops and streaming:
                reason = "ops:reading_class"  # a command that only reads changes nothing
            else:
                try:
                    session.validate(ops, req.slice, self.holds_token)
                except Rejected as exc:
                    reason = "ops:rejected"
                    record["ops_rejected"] = str(exc)[:200]
        if reason:
            yield Abort(reason=reason)
            return
        if streaming:
            for line, newline in rest:  # a last line with no newline at its end
                yield Out(line=line, newline=newline)
        record["ops_applied"] = len(ops)  # as far as the responder decides; the decoy applies
        if cls is CommandClass.STATE_CHANGING:
            # What this answer claimed stays true for the session: a later answer is shown it.
            said = doc["stdout"].strip().splitlines()
            session.assert_fact(
                f"{json.dumps(command[:120])} was run and exited {doc['exit_code']}"
                + (
                    f", printing {len(said)} lines ending {json.dumps(said[-1][:80])}"
                    if said
                    else ""
                )
            )
        if cls in CACHED:
            self.cache.put(
                req.deployment_id,
                command,
                fingerprint,
                Answer(doc["stdout"], doc["stderr"], doc["exit_code"], record["output_tokens"]),
            )
        if not ops and cls is not CommandClass.VOLATILE:
            # For this session, in this state (see _answer). A volatile command shows
            # something that moves by the second, and is asked afresh.
            key = (command, session.fingerprint(named_paths(req.argv, req.cwd), req.slice))
            session.said[key] = (doc["stdout"], doc["stderr"], doc["exit_code"])
            while len(session.said) > MAX_SAID:
                session.said.popitem(last=False)
        yield End(
            # A held answer goes whole, with its operations: the decoy applies them before
            # it shows a line, and shows none if it refuses them.
            stdout="" if streaming else doc["stdout"],
            stderr=doc["stderr"],
            exit_code=doc["exit_code"],
            ops=ops,
            rung="replay" if self.backend.name == "replay" else "model",
            prompt_tokens=usage.prompt_tokens,
            output_tokens=record["output_tokens"],
            first_ms=record.get("first_ms"),
            total_ms=round((time.monotonic() - started) * 1000, 1),
        )


def _lines(stdout: str) -> list[tuple[str, bool]]:
    """(line, whether it ends in a newline) for each line of an answer's stdout."""
    if not stdout:
        return []
    parts = stdout.split("\n")
    out = [(part, True) for part in parts[:-1]]
    if parts[-1]:
        out.append((parts[-1], False))
    return out


def create_app(settings: Settings) -> FastAPI:
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=os.environ.get("LOG_LEVEL", "INFO"), format="%(levelname)s %(name)s %(message)s"
        )
    responder = Responder(settings)
    # A live backend reads the fixed part of the prompt into every slot before it calls
    # itself healthy (backends.Llama.healthy).
    prime = getattr(settings.backend, "prime_with", None)
    if prime is not None:
        prime(prompt.system(settings.profile), settings.concurrency)
    expected = f"Bearer {settings.token}".encode()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.responder = responder

    @app.get("/healthz", response_class=PlainTextResponse)
    async def healthz() -> PlainTextResponse:
        # Healthy means an answer could be made now: the decoy lists `respond` among what it
        # supports only while this says so (spec 3.1).
        ok = await responder.backend.healthy()
        return PlainTextResponse("ok" if ok else "backend down", status_code=200 if ok else 503)

    @app.post("/v1/respond")
    async def respond(request: Request, authorization: str = Header(default="")) -> Any:
        if not hmac.compare_digest(authorization.encode(), expected):
            raise HTTPException(status_code=401)
        try:
            req = RespondRequest.model_validate(await request.json())
        except (ValidationError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)[:500]) from exc

        async def body() -> AsyncIterator[bytes]:
            try:
                async with contextlib.aclosing(responder.answer(req)) as items:
                    async for item in items:
                        yield dump(item)
            except Exception:  # an answer must end in a record the decoy can act on
                log.exception("answer failed")
                yield dump(Abort(reason="error"))

        return StreamingResponse(body(), media_type="application/x-ndjson")

    return app
