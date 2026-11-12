"""Asyncio client for the policy service (gate contract v1).

Same failure semantics as the Cowrie gate from spike S1: anything other than a valid, timely
decision means ``allow``, recorded as a fallback with its reason. The decoy never waits longer
than the timeout and never tells the client that a policy service exists.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import ValidationError

from mirage_schema.policy import Action, DecideRequest, Decision, as_dict


@dataclass(frozen=True)
class Applied:
    """The decision a decoy applies, including fallbacks."""

    action: Action
    output: str = ""
    exit_code: int | None = None
    delay_ms: int = 0
    decision_id: str | None = None
    propensity: float | None = None
    rule_id: str | None = None
    rules_version: str | None = None
    fallback: bool = False
    fallback_reason: str | None = None
    latency_ms: float = 0.0

    @classmethod
    def allow_fallback(cls, reason: str, latency_ms: float) -> Applied:
        return cls(Action.ALLOW, fallback=True, fallback_reason=reason, latency_ms=latency_ms)


class GateClient:
    def __init__(
        self,
        url: str | None,
        token: str = "",
        timeout_ms: int = 50,
        idle_ms: int = 2000,
    ) -> None:
        self.url = url
        self.timeout_s = timeout_ms / 1000.0
        self._token = token
        self._client = (
            httpx.AsyncClient(
                http1=True,
                http2=False,
                timeout=httpx.Timeout(self.timeout_s),
                # Drop idle connections before the service's keep-alive timeout (5 s), so a
                # request never races the server closing its connection (spike S1).
                limits=httpx.Limits(max_keepalive_connections=8, keepalive_expiry=idle_ms / 1000),
                headers={"Authorization": f"Bearer {token}"},
            )
            if url
            else None
        )

    @classmethod
    def from_env(cls) -> GateClient:
        return cls(
            os.environ.get("POLICY_URL") or None,
            os.environ.get("POLICY_TOKEN", ""),
            int(os.environ.get("POLICY_TIMEOUT_MS", "50")),
            int(os.environ.get("POLICY_IDLE_MS", "2000")),
        )

    async def decide(self, req: DecideRequest) -> Applied:
        started = time.monotonic()

        def ms() -> float:
            return round((time.monotonic() - started) * 1000, 2)

        if self._client is None or self.url is None:
            return Applied.allow_fallback("disabled", 0.0)
        body = as_dict(req)
        try:
            async with asyncio.timeout(self.timeout_s):
                resp = await self._post(body, started)
        except TimeoutError:
            return Applied.allow_fallback("timeout", ms())
        except httpx.HTTPError as exc:
            return Applied.allow_fallback(f"error:{type(exc).__name__}", ms())
        if resp.status_code != 200:
            return Applied.allow_fallback(f"status:{resp.status_code}", ms())
        try:
            d = Decision.model_validate(resp.json())
        except (ValidationError, ValueError):
            return Applied.allow_fallback("malformed", ms())
        return Applied(
            action=d.action,
            output=d.output,
            exit_code=d.exit_code,
            delay_ms=d.delay_ms,
            decision_id=d.decision_id,
            propensity=d.propensity,
            rule_id=d.rule_id,
            rules_version=d.rules_version,
            latency_ms=ms(),
        )

    async def _post(self, body: dict[str, Any], started: float) -> httpx.Response:
        assert self._client is not None and self.url is not None
        try:
            return await self._client.post(self.url, json=body)
        except (httpx.RemoteProtocolError, httpx.ReadError):
            # A reused connection the server had just closed. Retry once if time remains.
            if time.monotonic() - started < self.timeout_s:
                return await self._client.post(self.url, json=body)
            raise

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
