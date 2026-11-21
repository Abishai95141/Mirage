"""Cowrie JSON log record -> MirageEvent.

Event IDs and attributes follow Cowrie's own reference, ``docs/OUTPUT.rst`` at v3.1.6
(commit ea9513e). Class choices agree with Cowrie's own OCSF output module
(``src/cowrie/core/ocsf.py``, OCSF 1.8.0): connect/close are SSH Activity on an SSH session,
the TTY recording is File System Activity. Unknown event IDs are not dropped: they map to class
``unknown`` with the raw record kept, so a Cowrie upgrade that adds events never loses data.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from mirage_schema.events import (
    Endpoint,
    EventClass,
    MirageEvent,
    Outcome,
    PolicyRef,
    Source,
    utc_now,
)

_NS = uuid.UUID("6f0d7a4e-2a52-4c1e-9a43-6d6972616765")  # fixed namespace for event IDs

# Attributes every Cowrie event carries; they become envelope fields, not payload.
SHARED = {
    "eventid",
    "message",
    "sensor",
    "timestamp",
    "session",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
}

# Canonical payload names, so that features do not depend on each source's spelling.
RENAME = {
    "input": "command",
    "version": "client_version",
    "shasum": "sha256",
    "hasshAlgorithms": "hassh_algorithms",
    "kexAlgs": "kex_algs",
    "keyAlgs": "key_algs",
    "encCS": "enc_algs",
    "macCS": "mac_algs",
    "compCS": "comp_algs",
    "langCS": "lang_algs",
}

S, F, U = Outcome.SUCCESS, Outcome.FAILURE, Outcome.UNKNOWN
C = EventClass

# eventid -> (class, action, outcome)
TABLE: dict[str, tuple[EventClass, str, Outcome]] = {
    "cowrie.session.connect": (C.NETWORK_ACTIVITY, "connect", S),
    "cowrie.session.closed": (C.NETWORK_ACTIVITY, "disconnect", S),
    "cowrie.session.params": (C.SSH_ACTIVITY, "session_params", U),
    "cowrie.client.version": (C.SSH_ACTIVITY, "client_version", U),
    "cowrie.client.kex": (C.SSH_ACTIVITY, "client_kex", U),
    "cowrie.client.kex_unexpected": (C.SSH_ACTIVITY, "kex_unexpected", F),
    "cowrie.client.malformed_packet": (C.SSH_ACTIVITY, "malformed_packet", F),
    "cowrie.client.size": (C.SSH_ACTIVITY, "terminal_size", U),
    "cowrie.client.var": (C.SSH_ACTIVITY, "set_env", U),
    "cowrie.client.fingerprint": (C.AUTHENTICATION, "pubkey_offer", U),
    "cowrie.login.success": (C.AUTHENTICATION, "login", S),
    "cowrie.login.failed": (C.AUTHENTICATION, "login", F),
    # command.input is logged for every line entered, before Cowrie knows whether the command
    # exists; an unknown command additionally produces command.failed. So input is "unknown".
    "cowrie.command.input": (C.PROCESS_ACTIVITY, "command", U),
    "cowrie.command.success": (C.PROCESS_ACTIVITY, "command", S),
    "cowrie.command.failed": (C.PROCESS_ACTIVITY, "command", F),
    "cowrie.command.chpasswd": (C.AUTHENTICATION, "password_change", U),
    "cowrie.session.input": (C.PROCESS_ACTIVITY, "stdin_input", U),
    "cowrie.session.file_download": (C.FILE_ACTIVITY, "download", S),
    "cowrie.session.file_download.failed": (C.FILE_ACTIVITY, "download", F),
    "cowrie.session.file_upload": (C.FILE_ACTIVITY, "upload", S),
    "cowrie.log.open": (C.FILE_ACTIVITY, "ttylog_open", U),
    "cowrie.log.closed": (C.FILE_ACTIVITY, "ttylog_closed", U),
    # Emitted by the MIRAGE policy gate in our Cowrie fork (spike S1).
    "cowrie.policy.decision": (C.POLICY_DECISION, "decide", U),
    # Changes to the session's emulated filesystem (MIRAGE fork, patch 0003); op in payload.
    "cowrie.fs.change": (C.FILE_ACTIVITY, "fs_change", S),
    # How a command was answered, where it was not the emulator alone (fork patches 0009 and
    # 0018). Neither is an input: the command's own event is. The outcome of `respond` is set
    # from the record below (answered, or not).
    "cowrie.render.served": (C.PROCESS_ACTIVITY, "rendered", S),
    "cowrie.mirage.respond": (C.PROCESS_ACTIVITY, "responded", U),
    # The policy planted a file holding a token (patch 0018); `planted` says whether it did.
    "cowrie.mirage.plant": (C.FILE_ACTIVITY, "token_planted", U),
    # passwd or chpasswd changed a password and said so (patch 0019). The attempt, successful
    # or not, is cowrie.command.chpasswd above; this is the change that was kept.
    "cowrie.mirage.credential": (C.AUTHENTICATION, "password_changed", S),
    "cowrie.direct-tcpip.request": (C.NETWORK_ACTIVITY, "tunnel_request", U),
    "cowrie.direct-tcpip.data": (C.NETWORK_ACTIVITY, "tunnel_data", U),
    "cowrie.direct-tcpip.redirect": (C.NETWORK_ACTIVITY, "tunnel_redirect", U),
    "cowrie.direct-tcpip.tunnel": (C.NETWORK_ACTIVITY, "tunnel_proxied", U),
    "cowrie.direct-tcpip.ja4": (C.NETWORK_ACTIVITY, "tunnel_tls_fingerprint", U),
    "cowrie.direct-tcpip.ja4h": (C.NETWORK_ACTIVITY, "tunnel_http_fingerprint", U),
    "cowrie.tunnelproxy-tcpip.data": (C.NETWORK_ACTIVITY, "tunnel_data", U),
    "cowrie.telnet.option": (C.NETWORK_ACTIVITY, "telnet_option", U),
    "cowrie.telnet.error": (C.NETWORK_ACTIVITY, "telnet_error", F),
    "cowrie.telnet.exploit_attempt": (C.AUTHENTICATION, "exploit_attempt", U),
    "cowrie.telnet.exploit_success": (C.AUTHENTICATION, "exploit_attempt", S),
}

# For these events Cowrie's dst_ip/dst_port name the destination the attacker *asked for*,
# not the honeypot. Keep them out of the envelope's dst.
_REQUESTED_DST = {k for k in TABLE if k.startswith(("cowrie.direct-tcpip.", "cowrie.tunnelproxy"))}


def _endpoint(ip: Any, port: Any) -> Endpoint:
    return Endpoint(ip=ip or None, port=int(port) if port not in (None, "") else None)


def _event_id(record: dict[str, Any]) -> str:
    digest = hashlib.sha256(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()
    return str(uuid.uuid5(_NS, f"cowrie:{digest}"))


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def map_record(record: dict[str, Any], *, ingest_ts: datetime | None = None) -> MirageEvent:
    """Map one Cowrie JSON record. Raises ``KeyError``/``ValueError`` on a malformed record."""
    eventid: str = record["eventid"]
    event_class, action, outcome = TABLE.get(
        eventid, (EventClass.UNKNOWN, eventid.removeprefix("cowrie."), Outcome.UNKNOWN)
    )

    payload = {RENAME.get(k, k): v for k, v in record.items() if k not in SHARED}
    if eventid == "cowrie.command.input" and "realm" in payload:
        action = "stdin_input"  # a line fed to an interactive command, not a shell command

    if (
        eventid in ("cowrie.session.connect", "cowrie.session.closed")
        and record.get("protocol") == "ssh"
    ):
        event_class = EventClass.SSH_ACTIVITY

    if eventid == "cowrie.mirage.respond":
        # The record's own word for how it ended stays in the payload under another name:
        # `outcome` is the envelope's.
        payload["respond_outcome"] = payload.pop("outcome", None)
        outcome = Outcome.SUCCESS if record.get("outcome") == "answered" else Outcome.FAILURE
    elif eventid == "cowrie.mirage.plant":
        outcome = Outcome.SUCCESS if record.get("planted") else Outcome.FAILURE

    policy = None
    if eventid == "cowrie.policy.decision":
        payload["command"] = payload.pop("command", record.get("input"))
        outcome = Outcome.FAILURE if record.get("fallback") else Outcome.SUCCESS
        if record.get("action"):
            policy = PolicyRef(
                decision_id=record.get("decision_id") or f"fallback:{record.get('request_id')}",
                action=record["action"],
                propensity=record.get("propensity"),
            )

    if eventid in _REQUESTED_DST:
        payload["requested_dst_ip"] = record.get("dst_ip")
        payload["requested_dst_port"] = record.get("dst_port")
        dst = Endpoint()
    else:
        dst = _endpoint(record.get("dst_ip"), record.get("dst_port"))

    return MirageEvent(
        event_id=_event_id(record),
        ts=_parse_ts(record["timestamp"]),
        ingest_ts=ingest_ts or utc_now(),
        source=Source.COWRIE,
        event_class=event_class,
        session_id=record.get("session"),
        sensor=record.get("sensor"),
        src=_endpoint(record.get("src_ip"), record.get("src_port")),
        dst=dst,
        protocol=record.get("protocol"),
        action=action,
        outcome=outcome,
        payload=payload,
        policy=policy,
        raw=record,
    )
