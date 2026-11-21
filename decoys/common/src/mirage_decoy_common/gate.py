"""Asyncio client for the policy service (gate contract v1).

Same failure semantics as the Cowrie gate from spike S1: anything other than a valid, timely
decision means ``allow``, recorded as a fallback with its reason. The decoy never waits longer
than the timeout and never tells the client that a policy service exists.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import socket
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import ValidationError

from mirage_schema.policy import V1_ACTIONS, Action, DecideRequest, Decision, as_dict


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


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


class GateClient:
    """The decoy side of the gate.

    Measured in Gate 1: a lookup of the service's name through Docker's DNS on
    every new connection can use most of the 50 ms budget on Docker Desktop. So
    the address is resolved in the background (every ``refresh_s``, and at once
    after a failed connect, e.g. when the service restarts at a new address) and
    requests go to it directly with the service's own Host header. Connections
    are kept for ``idle_ms`` (60 s in compose), just under the service's 75 s
    keep-alive, so an attacker's pause does not cost a new connection.
    """

    def __init__(
        self,
        url: str | None,
        token: str = "",
        timeout_ms: int = 50,
        idle_ms: int = 2000,
        refresh_s: float = 30.0,
    ) -> None:
        self.url = url
        self.timeout_s = timeout_ms / 1000.0
        self.refresh_s = refresh_s
        self._parts = urlsplit(url) if url else None
        host = self._parts.hostname if self._parts else None
        self._hostname = host or ""
        self._address: str | None = host if host and _is_ip(host) else None
        self._resolver: asyncio.Task[None] | None = None
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
            float(os.environ.get("POLICY_REFRESH_MS", "30000")) / 1000,
        )

    # ------------------------------------------------------------------ address

    def target(self) -> tuple[str, dict[str, str]]:
        """The URL to post to and extra headers: the resolved address with the service's
        name in Host once known, the configured URL until then."""
        assert self.url is not None and self._parts is not None
        if self._address is None or self._address == self._hostname:
            return self.url, {}
        host = f"[{self._address}]" if ":" in self._address else self._address
        netloc = f"{host}:{self._parts.port}" if self._parts.port else host
        return urlunsplit(self._parts._replace(netloc=netloc)), {"Host": self._parts.netloc}

    async def resolve(self) -> None:
        loop = asyncio.get_running_loop()
        port = self._parts.port if self._parts else None
        with contextlib.suppress(OSError):
            infos = await loop.getaddrinfo(self._hostname, port, type=socket.SOCK_STREAM)
            # IPv4 first: the service listens on both, and IPv4 avoids any v6 fallback delay.
            infos.sort(key=lambda i: i[0] != socket.AF_INET)
            if infos:
                self._address = str(infos[0][4][0])

    async def _refresh(self) -> None:
        while True:
            await self.resolve()
            await asyncio.sleep(self.refresh_s)

    def _start_resolving(self) -> None:
        if self._resolver is None and self._hostname and not _is_ip(self._hostname):
            self._resolver = asyncio.get_running_loop().create_task(self._refresh())

    async def decide(self, req: DecideRequest) -> Applied:
        started = time.monotonic()

        def ms() -> float:
            return round((time.monotonic() - started) * 1000, 2)

        if self._client is None or self.url is None:
            return Applied.allow_fallback("disabled", 0.0)
        self._start_resolving()
        body = as_dict(req)
        try:
            async with asyncio.timeout(self.timeout_s):
                resp = await self._post(body, started)
        except TimeoutError:
            return Applied.allow_fallback("timeout", ms())
        except httpx.HTTPError as exc:
            if isinstance(exc, httpx.ConnectError) and self._resolver is not None:
                # The service may have moved (restarted): look it up again now.
                asyncio.get_running_loop().create_task(self.resolve())
            return Applied.allow_fallback(f"error:{type(exc).__name__}", ms())
        if resp.status_code != 200:
            return Applied.allow_fallback(f"status:{resp.status_code}", ms())
        try:
            d = Decision.model_validate(resp.json())
        except (ValidationError, ValueError):
            return Applied.allow_fallback("malformed", ms())
        if d.action not in V1_ACTIONS:
            # Contract v2's actions are for a decoy that listed them in ``supports``. This
            # one lists none, so being sent one is the service's mistake: the input is
            # answered as it would have been, and the mistake is recorded.
            return Applied.allow_fallback("unsupported", ms())
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
        url, headers = self.target()
        try:
            return await self._client.post(url, json=body, headers=headers)
        except (httpx.RemoteProtocolError, httpx.ReadError):
            # A reused connection the server had just closed. Retry once if time remains.
            if time.monotonic() - started < self.timeout_s:
                return await self._client.post(url, json=body, headers=headers)
            raise

    async def close(self) -> None:
        if self._resolver is not None:
            self._resolver.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._resolver
        if self._client is not None:
            await self._client.aclose()
