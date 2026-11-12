"""Shared harness for the database decoy tests: fake gate, PROXY header, a real asyncio server.

The Redis tests talk to the server directly with a PROXY v2 header (as the edge does). The
MySQL tests reach it through a small relay that injects the header, so PyMySQL - which cannot
send PROXY itself - exercises the same require_proxy path the stack uses.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import struct
from pathlib import Path
from typing import ClassVar

import pytest

from mirage_decoy_common.gate import Applied, GateClient
from mirage_decoy_common.proxyproto import build_header
from mirage_decoy_common.session import ArtifactStore, Decoy, EventLog
from mirage_profiles.generator import render
from mirage_schema.policy import Action, Protocol

ROOT = Path(__file__).resolve().parents[3]
SRC_IP = "203.0.113.9"
DST_IP = "10.0.0.5"


@pytest.fixture(scope="session")
def profile_dir(tmp_path_factory) -> Path:
    return render(ROOT / "decoys/profiles/web-db.yaml", 7, tmp_path_factory.mktemp("prof") / "p")


class FakeGate:
    """Returns one decision for every input; records the requests."""

    def __init__(self, applied: Applied | None = None) -> None:
        self.applied = applied
        self.reqs: list = []

    async def decide(self, req):
        self.reqs.append(req)
        return self.applied if self.applied is not None else Applied(Action.ALLOW)

    async def close(self) -> None:
        pass


def decoy(protocol: Protocol, gate: GateClient | None = None, artifacts=None) -> Decoy:
    return Decoy(
        protocol, gate or GateClient(None), EventLog(None), ArtifactStore(artifacts), "dep-test"
    )


# ------------------------------------------------------------------ redis client


def resp(*args: bytes) -> bytes:
    out = f"*{len(args)}\r\n".encode()
    for a in args:
        out += f"${len(a)}\r\n".encode() + a + b"\r\n"
    return out


async def read_reply(r: asyncio.StreamReader) -> tuple[bytes, object]:
    """One complete RESP value: its exact bytes plus a decoded Python value."""
    raw = bytearray()

    async def line() -> bytes:
        got = await r.readuntil(b"\r\n")
        raw.extend(got)
        return got

    first = await line()
    t, rest = first[:1], first[1:-2]
    if t == b":":
        return bytes(raw), int(rest)
    if t in (b"+", b"-"):
        return bytes(raw), rest.decode()
    if t in (b"$", b"="):
        n = int(rest)
        if n < 0:
            return bytes(raw), None
        data = await r.readexactly(n + 2)
        raw.extend(data)
        return bytes(raw), data[:-2]
    if t in (b"*", b"%", b">"):
        n = int(rest) * (2 if t == b"%" else 1)
        items = []
        for _ in range(n):
            sub, value = await read_reply(r)
            raw.extend(sub)
            items.append(value)
        if t == b"%":
            return bytes(raw), dict(zip(items[::2], items[1::2], strict=True))
        return bytes(raw), items
    raise AssertionError(f"unknown reply type {t!r}")


class RedisConn:
    """One client connection to the Redis decoy, speaking RESP and inline."""

    # Every connection a test opened; the server fixture closes leftovers, because from Python
    # 3.12 Server.wait_closed() waits for all connections and a failed test would hang.
    opened: ClassVar[list[RedisConn]] = []

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.r, self.w = reader, writer
        RedisConn.opened.append(self)

    @classmethod
    async def close_all(cls) -> None:
        while cls.opened:
            await cls.opened.pop().close()

    @classmethod
    async def connect(cls, port: int, src: str = SRC_IP) -> RedisConn:
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(build_header(src, 40000 + (port % 1000), DST_IP, 6379))
        await w.drain()
        return cls(r, w)

    async def cmd(self, *args: bytes) -> tuple[bytes, object]:
        self.w.write(resp(*args))
        await self.w.drain()
        return await read_reply(self.r)

    async def inline(self, line: bytes) -> tuple[bytes, object]:
        self.w.write(line + b"\r\n")
        await self.w.drain()
        return await read_reply(self.r)

    async def send(self, data: bytes) -> None:
        self.w.write(data)
        await self.w.drain()

    async def close(self) -> None:
        self.w.close()
        with contextlib.suppress(ConnectionError):
            await self.w.wait_closed()


# ------------------------------------------------------------------ mysql clients


class MysqlRaw:
    """A minimal sync MySQL client (raw sockets) for byte-level protocol assertions."""

    def __init__(self, port: int, user: str, password: str, database: str | None = None) -> None:
        import pymysql

        self.conn = pymysql.connect(
            host="127.0.0.1",
            port=port,
            user=user,
            password=password,
            database=database,
            autocommit=True,
        )
        self.cur = self.conn.cursor()

    def query(self, sql: str):
        self.cur.execute(sql)
        if self.cur.description is None:
            return None, self.cur.rowcount
        return (
            [d[:2] for d in self.cur.description],
            [list(r) for r in self.cur.fetchall()],
        )

    def close(self) -> None:
        self.conn.close()


class Relay:
    """A local TCP relay that fronts the decoy with a PROXY v2 header."""

    def __init__(self, target_port: int, src_ip: str = SRC_IP, dst_port: int = 3306) -> None:
        self.target, self.src_ip, self.dst_port = target_port, src_ip, dst_port
        self.server: asyncio.AbstractServer | None = None
        self.port = 0

    async def start(self) -> Relay:
        self.server = await asyncio.start_server(self._pipe_in, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def _pipe_in(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            up_r, up_w = await asyncio.open_connection("127.0.0.1", self.target)
        except OSError:
            writer.close()
            return
        up_w.write(build_header(self.src_ip, 50000, DST_IP, self.dst_port))
        await up_w.drain()
        out = asyncio.ensure_future(self._pipe(reader, up_w))
        back = asyncio.ensure_future(self._pipe(up_r, writer))
        await asyncio.gather(out, back, return_exceptions=True)

    @staticmethod
    async def _pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        try:
            while data := await r.read(65536):
                w.write(data)
                await w.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            with contextlib.suppress(ConnectionError):
                w.close()


def handshake_of(payload: bytes) -> dict:
    """Parse a protocol-10 handshake the way the reference extractor does."""
    end = payload.index(b"\0", 1)
    i = end + 1
    (thread_id,) = struct.unpack("<I", payload[i : i + 4])
    i += 4 + 8 + 1
    cap_lo, charset, status, cap_hi, auth_len = struct.unpack("<HBHHB", payload[i : i + 8])
    i += 8
    reserved = payload[i : i + 10]
    i += 10 + max(13, auth_len - 8)
    plugin = payload[i:].rstrip(b"\0").decode()
    return {
        "protocol": payload[0],
        "server_version": payload[1:end].decode(),
        "thread_id": thread_id,
        "capabilities": cap_lo | cap_hi << 16,
        "charset": charset,
        "status": status,
        "auth_data_len": auth_len,
        "reserved_hex": reserved.hex(),
        "auth_plugin": plugin,
        "len": len(payload),
    }


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
