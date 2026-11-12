"""Policy service v0: ``POST /v1/decide`` (gate contract v1, spec section 3).

Every decision is written as one JSON line to the decision log, which Vector tails and
publishes to ``raw.policy.decision``. The decoy's own event records what it actually applied;
this record says why. The two join on ``request_id``.
"""

from __future__ import annotations

import hmac
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import ValidationError

from mirage_policy.rules import RuleSet
from mirage_schema.policy import DecideRequest, Decision, as_dict

RULES_DIR = Path(__file__).parent / "rulesets"


@dataclass
class Settings:
    token: str
    log_path: Path
    rule_files: list[Path]

    @classmethod
    def from_env(cls) -> Settings:
        token = os.environ.get("POLICY_TOKEN", "")
        if len(token) < 16:
            raise SystemExit("POLICY_TOKEN must be set (at least 16 characters); run make env")
        files: list[Path] = []
        if os.environ.get("POLICY_SELFTEST") == "1":
            files.append(RULES_DIR / "selftest.yaml")
        extra = os.environ.get("POLICY_RULES")
        files.append(Path(extra) if extra else RULES_DIR / "default.yaml")
        log_path = Path(os.environ.get("POLICY_LOG", "/var/log/mirage-policy/decisions.json"))
        return cls(token=token, log_path=log_path, rule_files=files)


class DecisionLog:
    """Append-only JSON lines. One write per line, so a line is never interleaved."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._f = path.open("a", buffering=1, encoding="utf-8")
        self._lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n"
        with self._lock:
            self._f.write(line)

    def close(self) -> None:
        self._f.close()


def create_app(settings: Settings) -> FastAPI:
    rules = RuleSet.load(*settings.rule_files)
    log = DecisionLog(settings.log_path)
    expected = f"Bearer {settings.token}".encode()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.rules = rules

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz() -> str:
        return "ok"

    @app.post("/v1/decide")
    async def decide(request: Request, authorization: str = Header(default="")) -> JSONResponse:
        started = time.perf_counter()
        if not hmac.compare_digest(authorization.encode(), expected):
            raise HTTPException(status_code=401)
        try:
            req = DecideRequest.model_validate(await request.json())
        except (ValidationError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)[:500]) from exc

        rule = rules.decide(req)
        decision = Decision(
            action=rule.action,
            output=rule.output,
            exit_code=rule.exit_code,
            delay_ms=rule.delay_ms,
            decision_id=str(uuid.uuid4()),
            propensity=1.0,  # deterministic rules; the phase 2 bandit logs real propensities
            rule_id=rule.id,
            rules_version=rules.version,
        )
        body = decision.model_dump(mode="json", exclude_none=True)
        latency_us = round((time.perf_counter() - started) * 1e6)
        log.write(
            {
                "eventid": "policy.decision",
                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "request": as_dict(req),
                "input": req.input_text(),
                **body,
                "latency_us": latency_us,
            }
        )
        return JSONResponse(body)

    return app
