"""RESP framing, ported from Redis 7.0's networking.c so malformed input fails the same way.

Requests: multibulk arrays of bulk strings, or inline lines split like ``sdssplitargs``.
Replies are plain Python values encoded for the client's protocol version (2 or 3).
"""

from __future__ import annotations

import re

PROTO_INLINE_MAX = 64 * 1024
MBULK_MAX = 1024 * 1024
CRLF = b"\r\n"
_SPACE = b" \t\n\r\v\f"
_LL = re.compile(rb"0|-?[1-9][0-9]{0,18}")


class ProtocolError(Exception):
    pass


class Simple(bytes):
    """``+`` status reply."""


class Error(bytes):
    """``-`` error reply; holds the text after the dash, e.g. ``b"ERR syntax error"``."""


class Verbatim(bytes):
    """Bulk in RESP2, ``=`` verbatim text in RESP3 (INFO, CLIENT LIST)."""


class Map(list):
    """List of (key, value) pairs: a flat array in RESP2, ``%`` in RESP3."""


OK = Simple(b"OK")


def err(msg: str | bytes) -> Error:
    return Error(b"ERR " + (msg.encode() if isinstance(msg, str) else msg))


def string2ll(b: bytes | bytearray) -> int | None:
    """Redis's strict integer parser: no sign on zero, no leading zeros or spaces."""
    if not _LL.fullmatch(b):
        return None
    v = int(b)
    return v if -(2**63) <= v < 2**63 else None


def encode(v: object, proto: int = 2) -> bytes:
    if isinstance(v, Simple):
        return b"+" + v + CRLF
    if isinstance(v, Error):
        # Redis maps CR and LF to spaces in errors so a reply can never break framing.
        return b"-" + v.replace(b"\r", b" ").replace(b"\n", b" ") + CRLF
    if isinstance(v, bool):
        return b":1\r\n" if v else b":0\r\n"
    if isinstance(v, int):
        return b":%d\r\n" % v
    if isinstance(v, Verbatim) and proto == 3:
        return b"=%d\r\ntxt:" % (len(v) + 4) + v + CRLF
    if isinstance(v, bytes | bytearray):
        return b"$%d\r\n" % len(v) + bytes(v) + CRLF
    if isinstance(v, str):
        return encode(v.encode(), proto)
    if v is None:
        return b"_\r\n" if proto == 3 else b"$-1\r\n"
    if isinstance(v, Map):
        head = b"%%%d\r\n" % len(v) if proto == 3 else b"*%d\r\n" % (2 * len(v))
        return head + b"".join(encode(k, proto) + encode(x, proto) for k, x in v)
    if isinstance(v, list | tuple):
        return b"*%d\r\n" % len(v) + b"".join(encode(x, proto) for x in v)
    raise TypeError(type(v))


def split_args(line: bytes) -> list[bytes]:
    """Port of ``sdssplitargs``: quotes, ``\\xHH`` and C escapes, as redis-cli and telnet send."""
    out: list[bytes] = []
    i, n = 0, len(line)
    while True:
        while i < n and line[i] in _SPACE:
            i += 1
        if i >= n:
            return out
        cur = bytearray()
        inq = insq = done = False
        while not done:
            c = line[i] if i < n else None
            if inq:
                if c is None:
                    raise ProtocolError("unbalanced quotes in request")
                if (
                    c == 0x5C
                    and i + 3 < n
                    and line[i + 1] == 0x78
                    and _ishex(line[i + 2])
                    and _ishex(line[i + 3])
                ):
                    cur.append(int(line[i + 2 : i + 4], 16))
                    i += 3
                elif c == 0x5C and i + 1 < n:
                    i += 1
                    cur.append(
                        {0x6E: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x61: 7}.get(line[i], line[i])
                    )
                elif c == 0x22:
                    if i + 1 < n and line[i + 1] not in _SPACE:
                        raise ProtocolError("unbalanced quotes in request")
                    done = True
                else:
                    cur.append(c)
            elif insq:
                if c is None:
                    raise ProtocolError("unbalanced quotes in request")
                if c == 0x5C and i + 1 < n and line[i + 1] == 0x27:
                    i += 1
                    cur.append(0x27)
                elif c == 0x27:
                    if i + 1 < n and line[i + 1] not in _SPACE:
                        raise ProtocolError("unbalanced quotes in request")
                    done = True
                else:
                    cur.append(c)
            elif c is None or c in b" \n\r\t\0":
                done = True
            elif c == 0x22:
                inq = True
            elif c == 0x27:
                insq = True
            else:
                cur.append(c)
            if i < n:
                i += 1
        out.append(bytes(cur))


def _ishex(c: int) -> bool:
    return c in b"0123456789abcdefABCDEF"


class Parser:
    """Incremental request parser. ``next()`` returns argv, ``[]`` for an empty request,
    or None when more bytes are needed; it raises ProtocolError like processInputBuffer."""

    def __init__(self, max_bulk: int) -> None:
        self.buf = bytearray()
        self.pos = 0
        self.max_bulk = max_bulk
        self._left: int | None = None
        self._args: list[bytes] = []

    def feed(self, data: bytes) -> None:
        if self.pos > 65536:
            del self.buf[: self.pos]
            self.pos = 0
        self.buf += data

    @property
    def pending(self) -> int:
        return len(self.buf) - self.pos

    def next(self, auth_required: bool = False) -> list[bytes] | None:
        if self._left is None:
            if self.pos >= len(self.buf):
                return None
            if self.buf[self.pos] != 0x2A:
                return self._inline()
            if not self._count(auth_required):
                return None
            if self._left is None:
                return []
        return self._bulks(auth_required)

    def _inline(self) -> list[bytes] | None:
        nl = self.buf.find(b"\n", self.pos)
        if nl < 0:
            if self.pending > PROTO_INLINE_MAX:
                raise ProtocolError("too big inline request")
            return None
        line = bytes(self.buf[self.pos : nl])
        self.pos = nl + 1
        if line.endswith(b"\r"):
            line = line[:-1]
        return split_args(line)

    def _line(self, too_big: str) -> int | None:
        cr = self.buf.find(b"\r", self.pos)
        if cr < 0:
            if self.pending > PROTO_INLINE_MAX:
                raise ProtocolError(too_big)
            return None
        # Redis waits for one byte after CR and skips it without checking it is LF.
        return cr if cr + 1 < len(self.buf) else None

    def _count(self, auth_required: bool) -> bool:
        cr = self._line("too big mbulk count string")
        if cr is None:
            return False
        ll = string2ll(self.buf[self.pos + 1 : cr])
        if ll is None or ll > MBULK_MAX:
            raise ProtocolError("invalid multibulk length")
        if ll > 10 and auth_required:
            raise ProtocolError("unauthenticated multibulk length")
        self.pos = cr + 2
        if ll > 0:
            self._left, self._args = ll, []
        return True

    def _bulks(self, auth_required: bool) -> list[bytes] | None:
        while self._left:
            if self.pos >= len(self.buf):
                return None
            cr = self._line("too big bulk count string")
            if cr is None:
                return None
            if self.buf[self.pos] != 0x24:
                raise ProtocolError(f"expected '$', got '{chr(self.buf[self.pos])}'")
            ll = string2ll(self.buf[self.pos + 1 : cr])
            if ll is None or ll < 0 or ll > self.max_bulk:
                raise ProtocolError("invalid bulk length")
            if ll > 16384 and auth_required:
                raise ProtocolError("unauthenticated bulk length")
            start = cr + 2
            if len(self.buf) - start < ll + 2:
                return None
            self._args.append(bytes(self.buf[start : start + ll]))
            self.pos = start + ll + 2
            self._left -= 1
        args, self._args, self._left = self._args, [], None
        return args
