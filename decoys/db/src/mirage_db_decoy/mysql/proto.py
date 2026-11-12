"""MySQL wire protocol (MariaDB 10.11 flavour): packet framing, handshake, auth, replies.

Framing and packet shapes follow the protocol the reference speaks (measured handshake in the
profile); only what the decoy answers is implemented. The decoy never offers TLS, never sends a
LOCAL INFILE request, and never speaks a protocol version other than the handshake's.
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import string
import struct
from dataclasses import dataclass, field
from typing import Any

MAX_PACKET_BODY = 0xFFFFFF

# Capability flags the decoy acts on (handshake flags come from the profile verbatim).
CLIENT_CONNECT_WITH_DB = 1 << 3
CLIENT_PROTOCOL_41 = 1 << 9
CLIENT_SSL = 1 << 11
CLIENT_SECURE_CONNECTION = 1 << 15
CLIENT_MULTI_STATEMENTS = 1 << 16
CLIENT_PLUGIN_AUTH = 1 << 19
CLIENT_CONNECT_ATTRS = 1 << 20
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 1 << 21
CLIENT_DEPRECATE_EOF = 1 << 24

SERVER_MORE_RESULTS_EXISTS = 1 << 3

# COM_* constants (client -> server).
COM_QUIT = 0x01
COM_INIT_DB = 0x02
COM_QUERY = 0x03
COM_FIELD_LIST = 0x05
COM_PING = 0x0E
COM_STMT_PREPARE = 0x16

COMMAND_NAMES = {
    0x01: "COM_QUIT",
    0x02: "COM_INIT_DB",
    0x03: "COM_QUERY",
    0x05: "COM_FIELD_LIST",
    0x08: "COM_DELAYED_INSERT",
    0x09: "COM_CHANGE_USER",
    0x0A: "COM_BINLOG_DUMP",
    0x0C: "COM_STATISTICS",
    0x0D: "COM_PROCESS_INFO",
    0x0E: "COM_PING",
    0x10: "COM_PROCESS_KILL",
    0x11: "COM_DEBUG",
    0x12: "COM_SLEEP",
    0x14: "COM_PROCESS_KILL",
    0x15: "COM_RESET_CONNECTION",
    0x16: "COM_STMT_PREPARE",
    0x17: "COM_STMT_EXECUTE",
    0x18: "COM_STMT_SEND_LONG_DATA",
    0x19: "COM_STMT_CLOSE",
    0x1A: "COM_STMT_RESET",
    0x1B: "COM_SET_OPTION",
    0x1D: "COM_STMT_FETCH",
    0x1F: "COM_RESET_CONNECTION",
    0x20: "COM_BEGIN",
}

SCRAMBLE_CHARS = string.ascii_letters + string.digits


class PacketTooBig(Exception):
    """A client packet over max_allowed_packet (error 1153, then the connection ends)."""


def lenenc_int(n: int) -> bytes:
    if n < 251:
        return bytes([n])
    if n < 1 << 16:
        return b"\xfc" + n.to_bytes(2, "little")
    if n < 1 << 24:
        return b"\xfd" + n.to_bytes(3, "little")
    return b"\xfe" + n.to_bytes(8, "little")


def lenenc_bytes(b: bytes) -> bytes:
    return lenenc_int(len(b)) + b


def read_lenenc_int(data: bytes, i: int) -> tuple[int, int]:
    if i >= len(data):
        raise ValueError("truncated length-encoded integer")
    first = data[i]
    i += 1
    if first < 0xFB:
        return first, i
    sizes = {0xFB: 0, 0xFC: 2, 0xFD: 3, 0xFE: 8}
    n = sizes[first]
    return int.from_bytes(data[i : i + n], "little"), i + n


def make_scramble() -> bytes:
    """20 printable bytes, split 8 + 12 by the handshake (no NULs, as MariaDB generates)."""
    return "".join(secrets.choice(SCRAMBLE_CHARS) for _ in range(20)).encode()


def native_password(password: str, scramble: bytes) -> bytes:
    """mysql_native_password: SHA1(pw) XOR SHA1(scramble + SHA1(SHA1(pw))); empty for no pw."""
    if not password:
        return b""
    # mysql_native_password is defined in terms of SHA-1; there is no choice of hash here.
    stage1 = hashlib.sha1(password.encode()).digest()  # noqa: S324
    stage2 = hashlib.sha1(stage1).digest()  # noqa: S324
    mixed = hashlib.sha1(scramble + stage2).digest()  # noqa: S324
    return bytes(a ^ b for a, b in zip(stage1, mixed, strict=True))


def handshake_payload(
    capabilities: int,
    server_version: str,
    thread_id: int,
    scramble: bytes,
    charset: int,
    status: int,
    auth_data_len: int,
    reserved: bytes,
    plugin: str,
) -> bytes:
    """Protocol 10 initial handshake, byte-for-byte the reference's layout (incl. the 10-byte
    reserved block, whose last 4 bytes carry MariaDB's extended capabilities)."""
    return (
        bytes([10])
        + server_version.encode()
        + b"\x00"
        + thread_id.to_bytes(4, "little")
        + scramble[:8]
        + b"\x00"
        + (capabilities & 0xFFFF).to_bytes(2, "little")
        + bytes([charset])
        + status.to_bytes(2, "little")
        + (capabilities >> 16).to_bytes(2, "little")
        + bytes([auth_data_len])
        + reserved
        + scramble[8:20]
        + b"\x00"
        + plugin.encode()
        + b"\x00"
    )


@dataclass
class HandshakeResponse:
    capabilities: int
    max_packet: int
    charset: int
    username: str
    auth_response: bytes
    database: str | None = None
    plugin: str | None = None
    attrs: dict[str, str] = field(default_factory=dict)
    ssl_request: bool = False


def parse_handshake_response(data: bytes) -> HandshakeResponse:
    """Parse the client's answer to the handshake (or a bare SSLRequest)."""
    capabilities, max_packet, charset = struct.unpack("<IIB", data[:9])
    if len(data) <= 32 and capabilities & CLIENT_SSL:  # SSLRequest: no credentials follow
        return HandshakeResponse(capabilities, max_packet, charset, "", b"", ssl_request=True)
    i = 9 + 23  # reserved
    end = data.index(b"\x00", i)
    username = data[i:end].decode(errors="replace")
    i = end + 1
    if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
        n, i = read_lenenc_int(data, i)
        auth = data[i : i + n]
        i += n
    elif capabilities & CLIENT_SECURE_CONNECTION:
        n = data[i]
        auth = data[i + 1 : i + 1 + n]
        i += 1 + n
    else:
        end = data.index(b"\x00", i)
        auth, i = data[i:end], end + 1
    database = None
    if capabilities & CLIENT_CONNECT_WITH_DB and i < len(data):
        end = data.index(b"\x00", i)
        database = data[i:end].decode(errors="replace") or None
        i = end + 1
    plugin = None
    if capabilities & CLIENT_PLUGIN_AUTH and i < len(data):
        end = data.index(b"\x00", i)
        plugin = data[i:end].decode(errors="replace")
        i = end + 1
    attrs: dict[str, str] = {}
    if capabilities & CLIENT_CONNECT_ATTRS and i < len(data):
        total, i = read_lenenc_int(data, i)
        stop = min(len(data), i + total)
        while i < stop:
            n, i = read_lenenc_int(data, i)
            key = data[i : i + n].decode(errors="replace")
            i += n
            if i >= stop:
                break
            n, i = read_lenenc_int(data, i)
            attrs[key] = data[i : i + n].decode(errors="replace")
            i += n
    return HandshakeResponse(
        capabilities, max_packet, charset, username, auth, database, plugin, attrs
    )


def auth_switch_payload(plugin: str, scramble: bytes) -> bytes:
    return b"\xfe" + plugin.encode() + b"\x00" + scramble + b"\x00"


def ok_packet(caps: int, status: int, affected: int = 0, insert_id: int = 0) -> bytes:
    out = b"\x00" + lenenc_int(affected) + lenenc_int(insert_id)
    if caps & CLIENT_PROTOCOL_41:
        out += status.to_bytes(2, "little") + b"\x00\x00"
    return out


def eof_packet(caps: int, status: int, warnings: int = 0) -> bytes:
    if caps & CLIENT_DEPRECATE_EOF:
        return b"\xfe" + ok_packet(caps, status)[1:]  # an OK packet with the EOF header byte
    return b"\xfe" + warnings.to_bytes(2, "little") + status.to_bytes(2, "little")


def err_packet(caps: int, code: int, message: str, sqlstate: str = "HY000") -> bytes:
    return (
        b"\xff"
        + code.to_bytes(2, "little")
        + b"#"
        + sqlstate[:5].encode()
        + message.encode(errors="replace")
    )


@dataclass
class Column:
    name: str
    type: int
    org_name: str = ""
    table: str = ""
    org_table: str = ""
    charset: int = 45  # utf8mb4_general_ci, the handshake's
    length: int = 0
    flags: int = 0
    decimals: int = 0

    def packet(self, caps: int) -> bytes:
        return (
            lenenc_bytes(b"def")
            + lenenc_bytes(b"")
            + lenenc_bytes(self.table.encode())
            + lenenc_bytes(self.org_table.encode())
            + lenenc_bytes(self.name.encode())
            + lenenc_bytes((self.org_name or self.name).encode())
            + lenenc_int(0x0C)
            + self.charset.to_bytes(2, "little")
            + self.length.to_bytes(4, "little")
            + bytes([self.type])
            + self.flags.to_bytes(2, "little")
            + bytes([self.decimals])
            + b"\x00\x00"
        )


def _value_bytes(v: Any) -> bytes:
    if v is None:
        return b"\xfb"
    if isinstance(v, bytes):
        return lenenc_bytes(v)
    if isinstance(v, float):
        return lenenc_bytes(repr(v).encode())
    return lenenc_bytes(str(v).encode())


def result_packets(
    caps: int, status: int, columns: list[Column], rows: list[list[Any]], more: bool = False
) -> list[bytes]:
    """A full result set, one payload per packet: column count, one definition per column,
    EOF (unless deprecated), one packet per row, terminator."""
    st = status | SERVER_MORE_RESULTS_EXISTS if more else status
    out = [lenenc_int(len(columns))]
    out += [c.packet(caps) for c in columns]
    if not (caps & CLIENT_DEPRECATE_EOF):
        out.append(eof_packet(caps, st))
    out += [b"".join(_value_bytes(v) for v in row) for row in rows]
    out.append(eof_packet(caps, st))
    return out


class Wire:
    """Framed packet reader/writer over an asyncio stream.

    Every command is one exchange: the client's packet arrives with sequence number n and the
    server answers with n+1, n+2, ... - one number per frame, continuation frames included.
    """

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, max_packet: int
    ) -> None:
        self.reader, self.writer, self.max_packet = reader, writer, max_packet
        self.seq = 0

    async def read(self) -> bytes:
        """One client packet. Raises PacketTooBig (1153) above max_allowed_packet, or
        IncompleteReadError at EOF."""
        header = await self.reader.readexactly(4)
        n = header[0] | header[1] << 8 | header[2] << 16
        self.seq = header[3]
        if n > self.max_packet:
            # Consume nothing else: the caller answers 1153 and closes, as MariaDB does.
            raise PacketTooBig(n)
        return await self.reader.readexactly(n)

    def write(self, payload: bytes) -> None:
        """One packet. A payload of 16 MiB - 1 or more is split into frames, each with the
        next sequence number, ending with a short (possibly empty) frame."""
        off = 0
        while True:
            self.seq = (self.seq + 1) & 0xFF
            chunk = payload[off : off + MAX_PACKET_BODY]
            self.writer.write(len(chunk).to_bytes(3, "little") + bytes([self.seq]) + chunk)
            off += MAX_PACKET_BODY
            if len(chunk) < MAX_PACKET_BODY:
                break

    def write_all(self, payloads: list[bytes]) -> None:
        for payload in payloads:
            self.write(payload)

    async def drain(self) -> None:
        await self.writer.drain()

    async def discard(self, n: int, timeout: float = 2.0) -> None:
        """Read and drop up to ``n`` bytes (the rest of a refused packet). Closing with them
        unread makes the kernel reset the connection, which can destroy the error reply
        before the client reads it."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while n > 0:
            left = deadline - loop.time()
            if left <= 0:
                return
            try:
                chunk = await asyncio.wait_for(self.reader.read(min(n, 65536)), left)
            except (TimeoutError, ConnectionError):
                return
            if not chunk:
                return
            n -= len(chunk)
