"""Per-connection session: identity, the event log, gating and artifacts.

Every decoy we write logs through :class:`Session`, so the raw records share one shape (the
``decoy`` mapping in ``mirage_schema.mappings`` reads them):

``eventid``     ``<protocol>.<event>``, e.g. ``redis.input``, ``mysql.login.failed``
``timestamp``   ISO 8601 UTC with microseconds and ``Z``
``session``     12 hex characters, unique per connection
``sensor``      the deployment ID
``protocol``, ``src_ip``, ``src_port``, ``dst_ip``, ``dst_port``

Each input unit gets a ``seq`` from 1; its gate decision and its ``<protocol>.input`` event
carry the same ``seq`` and ``request_id``, which is what Gate 1 test 1-4 counts.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mirage_decoy_common.gate import Applied, GateClient
from mirage_decoy_common.proxyproto import ProxyInfo
from mirage_schema.policy import DecideRequest, Protocol

INLINE_CAP = 4096  # content beyond this goes to the artifact store; events keep the head


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class EventLog:
    """Append-only JSON lines, one write per record."""

    def __init__(self, path: Path | None) -> None:
        self._lock = threading.Lock()
        self._f = None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._f = path.open("a", buffering=1, encoding="utf-8")
        self.records: list[dict[str, Any]] = []  # kept only when there is no file (tests)

    def write(self, record: dict[str, Any]) -> None:
        if self._f is None:
            self.records.append(record)
            return
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=False, default=str)
        with self._lock:
            self._f.write(line + "\n")


class ArtifactStore:
    """Write-once files named by SHA-256, mode 0400 (spec 1.8). Never executed or parsed."""

    def __init__(self, root: Path | None, max_bytes: int = 50 * 1024 * 1024) -> None:
        self.root = root
        self.max_bytes = max_bytes

    def put(self, data: bytes) -> tuple[str, bool]:
        """Store ``data``; returns (sha256, stored). Oversized data is hashed, not stored."""
        digest = hashlib.sha256(data).hexdigest()
        if self.root is None or len(data) > self.max_bytes:
            return digest, False
        path = self.root / digest
        if not path.exists():
            self.root.mkdir(parents=True, exist_ok=True)
            tmp = self.root / f".{digest}.{secrets.token_hex(4)}"
            tmp.write_bytes(data)
            os.chmod(tmp, 0o400)
            tmp.replace(path)
        return digest, True


class Decoy:
    """Process-wide context shared by every session of one decoy."""

    def __init__(
        self,
        protocol: Protocol,
        gate: GateClient,
        log: EventLog,
        artifacts: ArtifactStore,
        deployment_id: str,
    ) -> None:
        self.protocol = protocol
        self.gate = gate
        self.log = log
        self.artifacts = artifacts
        self.deployment_id = deployment_id

    @classmethod
    def from_env(cls, protocol: Protocol, default_log: str) -> Decoy:
        log_path = os.environ.get("DECOY_LOG", default_log)
        art = os.environ.get("ARTIFACT_DIR")
        return cls(
            protocol,
            GateClient.from_env(),
            EventLog(Path(log_path) if log_path else None),
            ArtifactStore(Path(art) if art else None),
            os.environ.get("DEPLOYMENT_ID", "dev"),
        )


class Session:
    def __init__(self, decoy: Decoy, peer: ProxyInfo) -> None:
        self.decoy = decoy
        self.peer = peer
        self.id = secrets.token_hex(6)
        self.seq = 0
        self.started = time.monotonic()
        self.user: str | None = None
        self.ended = False

    @property
    def protocol(self) -> Protocol:
        return self.decoy.protocol

    def emit(self, event: str, **fields: Any) -> dict[str, Any]:
        rec = {
            "eventid": f"{self.protocol.value}.{event}",
            "timestamp": now_iso(),
            "session": self.id,
            "sensor": self.decoy.deployment_id,
            "protocol": self.protocol.value,
            "src_ip": self.peer.src_ip,
            "src_port": self.peer.src_port,
            "dst_ip": self.peer.dst_ip,
            "dst_port": self.peer.dst_port,
            **fields,
        }
        self.decoy.log.write(rec)
        return rec

    def connect(self) -> None:
        self.emit("session.connect")

    def close(self) -> None:
        if not self.ended:
            self.ended = True
            self.emit(
                "session.closed",
                duration=round(time.monotonic() - self.started, 3),
                inputs=self.seq,
            )

    async def gate(self, *, known: bool = True, **fields: Any) -> tuple[int, str, Applied]:
        """Number the next input, ask the gate, log the applied decision.

        Returns (seq, request_id, applied)."""
        self.seq += 1
        req = DecideRequest(
            request_id=str(uuid.uuid4()),
            session_id=self.id,
            deployment_id=self.decoy.deployment_id,
            seq=self.seq,
            protocol=self.protocol,
            src={"ip": self.peer.src_ip, "port": self.peer.src_port},
            known=known,
            **fields,
        )
        applied = await self.decoy.gate.decide(req)
        self.emit(
            "policy.decision",
            seq=self.seq,
            request_id=req.request_id,
            input=req.input_text(),
            known=known,
            action=applied.action.value,
            fallback=applied.fallback,
            fallback_reason=applied.fallback_reason,
            decision_id=applied.decision_id,
            propensity=applied.propensity,
            rule_id=applied.rule_id,
            rules_version=applied.rules_version,
            latency_ms=applied.latency_ms,
        )
        return self.seq, req.request_id, applied

    def content(self, data: bytes, kind: str) -> dict[str, Any]:
        """Describe captured content for an event; content over 4 KiB goes to the artifact
        store and is announced with an ``artifact`` event."""
        digest = hashlib.sha256(data).hexdigest()
        out: dict[str, Any] = {"size": len(data), "sha256": digest}
        if len(data) <= INLINE_CAP:
            out["text"] = data.decode(errors="replace")
            return out
        out["head"] = data[:INLINE_CAP].decode(errors="replace")
        _, stored = self.decoy.artifacts.put(data)
        self.emit("artifact", sha256=digest, size=len(data), kind=kind, stored=stored)
        return out
