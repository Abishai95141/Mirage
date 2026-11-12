"""PROXY protocol v2 reader for the decoys we write (spec section 2).

Only the edge can reach a decoy, and the edge always sends a v2 header, so a connection without
one is refused: it can only come from inside the decoy network, which should never happen.
LOCAL commands (sent by health checks) carry no client address and are accepted as such.
"""

from __future__ import annotations

import asyncio
import ipaddress
import struct
from dataclasses import dataclass

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
MAX_TLV_BYTES = 512  # the edge sends no TLVs; cap what we would read


class ProxyError(ValueError):
    pass


@dataclass(frozen=True)
class ProxyInfo:
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    local: bool = False


def parse_header(header: bytes, body: bytes) -> ProxyInfo:
    """Parse the 16-byte fixed header plus its address block."""
    if header[:12] != SIGNATURE:
        raise ProxyError("missing PROXY v2 signature")
    ver_cmd, fam = header[12], header[13]
    if ver_cmd >> 4 != 2:
        raise ProxyError("not PROXY protocol version 2")
    cmd = ver_cmd & 0x0F
    if cmd == 0:  # LOCAL
        return ProxyInfo(None, None, None, None, local=True)
    if cmd != 1:
        raise ProxyError(f"unknown PROXY command {cmd}")
    af, proto = fam >> 4, fam & 0x0F
    if proto != 1:
        raise ProxyError("only TCP over PROXY is supported")
    if af == 1:
        if len(body) < 12:
            raise ProxyError("short IPv4 address block")
        src, dst, sport, dport = struct.unpack("!4s4sHH", body[:12])
        return ProxyInfo(
            str(ipaddress.IPv4Address(src)), sport, str(ipaddress.IPv4Address(dst)), dport
        )
    if af == 2:
        if len(body) < 36:
            raise ProxyError("short IPv6 address block")
        src, dst, sport, dport = struct.unpack("!16s16sHH", body[:36])
        s, d = ipaddress.IPv6Address(src), ipaddress.IPv6Address(dst)
        return ProxyInfo(str(s.ipv4_mapped or s), sport, str(d.ipv4_mapped or d), dport)
    raise ProxyError(f"unsupported address family {af}")


async def read_proxy_header(reader: asyncio.StreamReader, timeout: float = 5.0) -> ProxyInfo:
    async with asyncio.timeout(timeout):
        header = await reader.readexactly(16)
        if header[:12] != SIGNATURE:
            raise ProxyError("missing PROXY v2 signature")
        (length,) = struct.unpack("!H", header[14:16])
        if length > 216 + MAX_TLV_BYTES:
            raise ProxyError("PROXY header too long")
        body = await reader.readexactly(length)
    return parse_header(header, body)


def build_header(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> bytes:
    """Build a v2 PROXY header (used by tests, which play the edge)."""
    s, d = ipaddress.ip_address(src_ip), ipaddress.ip_address(dst_ip)
    if s.version == 4 and d.version == 4:
        body = s.packed + d.packed + struct.pack("!HH", src_port, dst_port)
        fam = 0x11
    else:
        s6 = s if s.version == 6 else ipaddress.IPv6Address(f"::ffff:{s}")
        d6 = d if d.version == 6 else ipaddress.IPv6Address(f"::ffff:{d}")
        body = s6.packed + d6.packed + struct.pack("!HH", src_port, dst_port)
        fam = 0x21
    return SIGNATURE + bytes([0x21, fam]) + struct.pack("!H", len(body)) + body
