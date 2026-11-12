import asyncio
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mirage_decoy_common.gate import GateClient
from mirage_decoy_common.proxyproto import ProxyError, ProxyInfo, build_header, parse_header
from mirage_decoy_common.server import connection_handler
from mirage_decoy_common.session import ArtifactStore, Decoy, EventLog, Session
from mirage_schema.policy import Action, DecideRequest, Protocol


@pytest.mark.parametrize(
    ("src", "dst"),
    [("203.0.113.7", "172.20.0.5"), ("2001:db8::1", "fd00::5")],
)
def test_proxy_v2_round_trip(src, dst):
    raw = build_header(src, 40000, dst, 6379)
    info = parse_header(raw[:16], raw[16:])
    assert (info.src_ip, info.src_port, info.dst_ip, info.dst_port) == (src, 40000, dst, 6379)


def test_proxy_v2_mixed_family_unmaps_ipv4():
    raw = build_header("198.51.100.1", 1, "2001:db8::2", 2)
    assert parse_header(raw[:16], raw[16:]).src_ip == "198.51.100.1"


def test_proxy_rejects_garbage_and_v1():
    with pytest.raises(ProxyError):
        parse_header(b"PROXY TCP4 1.2.", b"")
    raw = bytearray(build_header("1.2.3.4", 1, "5.6.7.8", 2))
    raw[12] = 0x11  # version 1 in the v2 framing
    with pytest.raises(ProxyError):
        parse_header(bytes(raw[:16]), bytes(raw[16:]))


class _Policy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    mode = "ok"

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.headers.get("Authorization") != "Bearer secret-token-xxxxxxxx":
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if _Policy.mode == "slow":
            import time

            time.sleep(0.3)
        out = (
            b"{not json"
            if _Policy.mode == "garbage"
            else json.dumps(
                {
                    "action": "fake_error",
                    "output": body["argv"][0],
                    "exit_code": 3,
                    "decision_id": "d1",
                    "propensity": 1.0,
                    "rule_id": "r",
                }
            ).encode()
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


@pytest.fixture
def policy_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Policy)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _Policy.mode = "ok"
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1/decide"
    srv.shutdown()


REQ = DecideRequest(request_id="r1", protocol=Protocol.REDIS, argv=["CONFIG", "GET", "dir"])


async def test_gate_applies_decision(policy_url):
    g = GateClient(policy_url, "secret-token-xxxxxxxx", timeout_ms=1000)
    a = await g.decide(REQ)
    assert a.action is Action.FAKE_ERROR and a.output == "CONFIG" and a.exit_code == 3
    assert not a.fallback and a.decision_id == "d1"
    await g.close()


@pytest.mark.parametrize(
    ("mode", "token", "reason"),
    [
        ("ok", "wrong-token-xxxxxxxxxx", "status:401"),
        ("garbage", "secret-token-xxxxxxxx", "malformed"),
        ("slow", "secret-token-xxxxxxxx", "timeout"),
    ],
)
async def test_gate_falls_back_to_allow(policy_url, mode, token, reason):
    _Policy.mode = mode
    g = GateClient(policy_url, token, timeout_ms=100)
    a = await g.decide(REQ)
    assert a.action is Action.ALLOW and a.fallback and a.fallback_reason == reason
    assert a.latency_ms < 250
    await g.close()


async def test_gate_service_down_and_disabled():
    a = await GateClient("http://127.0.0.1:9/v1/decide", "x", timeout_ms=100).decide(REQ)
    assert a.action is Action.ALLOW and a.fallback and a.fallback_reason.startswith("error:")
    b = await GateClient(None).decide(REQ)
    assert b.fallback and b.fallback_reason == "disabled"


def _decoy(tmp_path=None):
    return Decoy(
        Protocol.REDIS, GateClient(None), EventLog(None), ArtifactStore(tmp_path), "dep-test"
    )


async def test_session_numbers_inputs_and_logs_decisions():
    d = _decoy()
    s = Session(d, ProxyInfo("203.0.113.5", 5555, "172.20.0.2", 6379))
    s.connect()
    seq1, rid1, _ = await s.gate(argv=["PING"])
    seq2, _, _ = await s.gate(argv=["INFO"])
    s.close()
    s.close()  # idempotent
    ids = [r["eventid"] for r in d.log.records]
    assert ids == [
        "redis.session.connect",
        "redis.policy.decision",
        "redis.policy.decision",
        "redis.session.closed",
    ]
    assert (seq1, seq2) == (1, 2)
    dec = d.log.records[1]
    assert dec["request_id"] == rid1 and dec["input"] == "PING" and dec["fallback"] is True
    assert dec["src_ip"] == "203.0.113.5" and dec["sensor"] == "dep-test"
    assert d.log.records[-1]["inputs"] == 2


def test_content_inline_and_artifact(tmp_path):
    d = _decoy(tmp_path)
    s = Session(d, ProxyInfo("203.0.113.5", 1, None, None))
    small = s.content(b"hello", "redis.value")
    assert small["text"] == "hello" and small["size"] == 5
    big = b"x" * 5000
    meta = s.content(big, "redis.value")
    assert len(meta["head"]) == 4096 and "text" not in meta
    stored = tmp_path / meta["sha256"]
    assert stored.read_bytes() == big and oct(os.stat(stored).st_mode & 0o777) == "0o400"
    art = d.log.records[-1]
    assert art["eventid"] == "redis.artifact" and art["stored"] is True


async def test_server_requires_proxy_header():
    d = _decoy()
    seen = []

    async def handler(session, reader, writer):
        seen.append(session.peer.src_ip)
        writer.write(b"+PONG\r\n")
        await writer.drain()

    srv = await asyncio.start_server(connection_handler(d, handler), "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    async with srv:
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"PING\r\n" + b"\0" * 20)  # no PROXY header
        await w.drain()
        assert await r.read() == b""  # dropped silently
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(build_header("203.0.113.9", 4321, "127.0.0.1", port))
        await w.drain()
        assert await r.read() == b"+PONG\r\n"
    assert seen == ["203.0.113.9"]
