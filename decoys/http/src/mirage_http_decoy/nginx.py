"""nginx 1.22.1 as Debian 12 ships it: request-line rules, URI normalisation and framing.

Everything a client can see comes from the rendered ``http.json``; the constants here are the
parts of nginx's source (``ngx_http_parse.c``, ``ngx_http_special_response.c``) that the
profile does not carry because they never vary between deployments.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from email.utils import formatdate, parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote_to_bytes

# ngx_http_status_lines; codes missing here get "HTTP/1.1 <code> " with a trailing space.
REASONS = {
    200: "OK", 301: "Moved Permanently", 302: "Moved Temporarily", 304: "Not Modified",
    400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden",
    404: "Not Found", 405: "Not Allowed", 406: "Not Acceptable", 408: "Request Time-out",
    409: "Conflict", 410: "Gone", 411: "Length Required", 412: "Precondition Failed",
    413: "Request Entity Too Large", 414: "Request-URI Too Large",
    415: "Unsupported Media Type", 416: "Requested Range Not Satisfiable",
    421: "Misdirected Request", 429: "Too Many Requests", 500: "Internal Server Error",
    501: "Not Implemented", 502: "Bad Gateway", 503: "Service Temporarily Unavailable",
    504: "Gateway Time-out", 505: "HTTP Version Not Supported", 507: "Insufficient Storage",
}  # fmt: skip
# ngx_http_special_response_handler turns keep-alive off after these.
CLOSE_AFTER = frozenset({400, 413, 414, 500, 501})
HEADER_TOO_LARGE = 494  # sent as 400 with its own page
# msie_padding (on by default) appends this to 4xx/5xx pages for MSIE and Chrome user agents.
PADDING = b"<!-- a padding to disable MSIE and Chrome friendly error page -->\r\n" * 6
LINE_MAX = 8192  # large_client_header_buffers 4 8k
HEAD_MAX = 4 * 8192
OFF_T_MAX = 2**63 - 1

_METHOD, _TARGET = rb"[A-Z_-]+", rb"[/A-Za-z][\x21-\x7e\x80-\xff]*"
_VERSION_SO_FAR = rb"H(?:T(?:T(?:P(?:/(?:\d+(?:\.\d*)?)?)?)?)?)?"
# Any prefix of a line nginx would accept; a byte outside it is refused at once.
_PARTIAL = re.compile(
    rb"(?:%s(?: +(?:%s(?: +(?:%s)?)? *\r?)?)?)?" % (_METHOD, _TARGET, _VERSION_SO_FAR)
)
_FULL = re.compile(rb"(%s) +(%s)(?: +HTTP/(\d+)\.(\d+))? *\r?" % (_METHOD, _TARGET))
_ABSOLUTE = re.compile(rb"[A-Za-z][A-Za-z0-9+.-]*://([^/?]*)([/?].*)?", re.S)
_BAD_ESCAPE = re.compile(rb"%(?![0-9A-Fa-f]{2})")
_HEAD_END = re.compile(rb"\n\r?\n")
_NAME = re.compile(rb"[A-Za-z0-9-]+")


@dataclass(frozen=True)
class RequestLine:
    method: str
    target: bytes
    major: int
    minor: int
    end: int  # index just past the line's LF

    @property
    def version(self) -> str:
        return "0.9" if self.major == 0 else f"{self.major}.{self.minor}"


def request_line(buf: bytes) -> RequestLine | int | None:
    """Parse the request line as nginx does, byte by byte: an invalid prefix is rejected as soon
    as it arrives (a TLS ClientHello gets its 400 at once). Returns the line, an error status, or
    None when more bytes are needed. ``buf`` has its leading blank lines stripped."""
    nl = buf.find(b"\n")
    line = buf if nl < 0 else buf[:nl]
    if not _PARTIAL.fullmatch(line[:LINE_MAX]):
        return 400
    if len(line) > LINE_MAX:
        return 414
    if nl < 0:
        return None
    m = _FULL.fullmatch(line)
    if not m:
        return 400
    method, target = m[1].decode(), m[2]
    if m[3] is None:
        major, minor = 0, 9
    else:
        major, minor = int(m[3]), int(m[4])
        if major > 99 or minor > 99:
            return 400
        if major > 1:
            return 505
    return RequestLine(method, target, major, minor, nl + 1)


def head_end(buf: bytes, start: int) -> int | None:
    """Index just past the blank line ending the header block, or None. Raises ValueError when
    the block outgrows nginx's header buffers."""
    m = _HEAD_END.search(buf, start - 1)
    if m:
        block = buf[start : m.end()]
        if len(block) > HEAD_MAX or any(len(x) > LINE_MAX for x in block.split(b"\n")):
            raise ValueError("header too large")
        return m.end()
    if len(buf) - start > HEAD_MAX or len(buf) - (buf.rfind(b"\n") + 1) > LINE_MAX:
        raise ValueError("header too large")
    return None


def header_lines(block: bytes) -> list[tuple[bytes, bytes, bool]]:
    """(name, value, valid) per line. nginx ignores lines whose name is not [A-Za-z0-9-]
    (ignore_invalid_headers on, underscores_in_headers off) instead of rejecting them."""
    out = []
    for line in block.split(b"\n"):
        line = line.removesuffix(b"\r")
        if line:
            name, sep, value = line.partition(b":")
            out.append((name, value.strip(b" \t"), bool(sep) and bool(_NAME.fullmatch(name))))
    return out


def split_target(target: bytes) -> tuple[str, str | None, str | None] | None:
    """(path, query, host) as ngx_http_parse_complex_uri leaves them (merge_slashes on, dot
    segments resolved, %XX decoded), or None where nginx answers 400."""
    host = None
    if not target.startswith(b"/"):
        m = _ABSOLUTE.fullmatch(target)
        if not m:
            return None
        host, target = m[1].decode("latin-1").lower(), m[2] or b"/"
        target = b"/" + target if target.startswith(b"?") else target
    raw, q, query = target.partition(b"?")
    raw = raw.split(b"#", 1)[0]
    if _BAD_ESCAPE.search(raw):
        return None
    decoded = unquote_to_bytes(raw)
    if b"\0" in decoded:
        return None
    parts: list[bytes] = []
    segs = decoded.split(b"/")[1:]
    for seg in segs:
        if seg == b"..":
            if not parts:
                return None
            parts.pop()
        elif seg not in (b"", b"."):
            parts.append(seg)
    trailing = bool(parts) and segs[-1] in (b"", b".", b"..")
    path = b"/" + b"/".join(parts) + (b"/" if trailing else b"")
    return path.decode(errors="replace"), query.decode(errors="replace") if q else None, host


def valid_host(value: bytes) -> str | None:
    """ngx_http_validate_host: lower-cased, port and one trailing dot dropped; None means 400."""
    h = value.decode("latin-1").lower()
    h = h[: h.find("]") + 1] if h.startswith("[") else h.split(":", 1)[0]
    h = h.removesuffix(".")
    return None if not h or "/" in h or ".." in h else h


def friendly_ua(ua: str) -> bool:
    """ngx_http_process_user_agent's msie/chrome flags, which switch on msie_padding."""
    if "Opera" in ua:
        return False
    i = ua.find("MSIE ")
    if i >= 0 and i + 7 < len(ua):
        return True
    return "Gecko/" not in ua and "Chrome/" in ua


def http_date(epoch: float | None = None) -> str:
    return formatdate(time.time() if epoch is None else epoch, usegmt=True)


def parse_http_date(value: str) -> int | None:
    try:
        return int(parsedate_to_datetime(value).timestamp())
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


def etag_matches(header: str, etag: str) -> bool:
    """ngx_http_test_if_match with weak comparison, as If-None-Match uses it."""
    if header.strip() == "*":
        return True
    return any(t.strip().removeprefix("W/") == etag for t in header.split(","))


@dataclass
class Response:
    status: int
    body: bytes = b""
    content_type: str | None = "text/html"
    static: bool = False  # a file: Last-Modified, ETag and Accept-Ranges
    location: str | None = None


def sent_body(resp: Response, head: bool) -> bytes:
    # A 304 keeps the file's body only so that its ETag carries the file's length.
    return b"" if head or resp.status == 304 else resp.body


class Profile:
    """The rendered ``http.json``."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.deployment_id: str | None = data.get("deployment_id")
        self.server: str = data["server"]
        self.routes: dict[str, dict[str, Any]] = {r["path"]: r for r in data["routes"]}
        self.errors: dict[str, dict[str, Any]] = data["errors"]
        self.ok_order: list[str] = data["ok_header_order"]
        self.max_body: int = data["max_body_bytes"]
        self.mtime: int = data["last_modified_epoch"]
        # Every directory a route lives in exists on the real host, so nginx would redirect
        # "/.git" to "/.git/" and refuse to list "/.git/".
        self.dirs = {p[: i + 1] for p in self.routes for i, c in enumerate(p) if c == "/"}

    @classmethod
    def load(cls, path: Path) -> Profile:
        return cls(json.loads(path.read_text()))

    def etag(self, length: int) -> str:
        return f'"{self.mtime:x}-{length:x}"'

    def error_body(self, code: int) -> bytes:
        if code == HEADER_TOO_LARGE:
            title, h1 = "400 Request Header Or Cookie Too Large", "400 Bad Request"
            extra = "<center>Request Header Or Cookie Too Large</center>\r\n"
        elif ref := self.errors.get(str(code)):
            return ref["body"].encode()
        elif code in REASONS and code >= 300:
            title = h1 = f"{code} {REASONS[code]}"
            extra = ""
        else:
            return b""
        return (
            f"<html>\r\n<head><title>{title}</title></head>\r\n<body>\r\n"
            f"<center><h1>{h1}</h1></center>\r\n{extra}"
            f"<hr><center>{self.server}</center>\r\n</body>\r\n</html>\r\n"
        ).encode()

    def error(self, code: int, ua: str = "", v10: bool = True) -> Response:
        body = self.error_body(code)
        if body and code >= 400 and v10 and friendly_ua(ua):
            body += PADDING
        status = 400 if code == HEADER_TOO_LARGE else code
        return Response(status, body, "text/html" if body else None)

    def frame(self, resp: Response, *, keepalive: bool, head: bool, v09: bool) -> bytes:
        body = sent_body(resp, head)
        if v09:  # HTTP/0.9 has no status line or headers
            return body
        ref = self.errors.get(str(resp.status))
        status_line = (
            ref["status_line"] if ref else f"HTTP/1.1 {resp.status} " + REASONS.get(resp.status, "")
        )
        if ref:
            order = ref["header_order"]
        else:
            order = self.ok_order if resp.static else self.errors["404"]["header_order"]
        h = {"Server": self.server, "Date": http_date()}
        if resp.content_type:
            h["Content-Type"] = resp.content_type
        if resp.status != 304:
            h["Content-Length"] = str(len(resp.body))
        if resp.static:
            h["Last-Modified"] = http_date(self.mtime)
            h["ETag"] = self.etag(len(resp.body))
            if resp.status != 304:
                h["Accept-Ranges"] = "bytes"
        if resp.location:
            h["Location"] = resp.location
        h["Connection"] = "keep-alive" if keepalive else "close"
        lines = [status_line, *(f"{k}: {h[k]}" for k in order if k in h)]
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace") + body
