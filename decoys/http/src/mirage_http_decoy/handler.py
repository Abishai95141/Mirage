"""One connection: read requests as nginx frames them, gate each one, answer from the profile.

The request line is parsed here, to nginx's rules, because h11 accepts lines nginx refuses and
refuses some it accepts. h11 then validates and frames the headers that decide the body (Host,
Content-Length, Transfer-Encoding, Expect) and decodes the body. Every response is written
here byte for byte; nothing h11 or Python would say ever reaches the client.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import html
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, quote

import h11

from mirage_decoy_common.gate import Applied
from mirage_decoy_common.session import Session
from mirage_http_decoy import nginx
from mirage_http_decoy.nginx import Profile, RequestLine, Response
from mirage_schema.policy import BODY_HEAD_CAP, Action, truncate

READ_SIZE = 65536
HEADER_TIMEOUT = 60.0  # client_header_timeout
KEEPALIVE_TIMEOUT = 65.0  # Debian's nginx.conf
BODY_TIMEOUT = SEND_TIMEOUT = 60.0
LINGER_TIME, LINGER_TIMEOUT = 30.0, 5.0  # lingering_time, lingering_timeout
KEEPALIVE_REQUESTS = 1000
FIELD_CAP = 1024
GATE_HEADERS = ("host", "user-agent", "content-type", "content-length")
FRAMING = (b"host", b"content-length", b"transfer-encoding", b"expect")
CONTINUE = b"HTTP/1.1 100 Continue\r\n\r\n"
_DIGITS = re.compile(r"[0-9]+")


@dataclass
class Request:
    method: str | None = None
    target: str | None = None
    version: str | None = None
    headers: list[tuple[bytes, bytes, bool]] = field(default_factory=list)
    path: str | None = None
    query: str | None = None
    host: str | None = None
    body: bytes = b""
    declared: int | None = None  # Content-Length of a body refused unread
    raw: bytes | None = None  # the bytes of a request nginx would refuse

    @classmethod
    def from_line(cls, rl: RequestLine | None, raw: bytes) -> Request:
        if rl is not None:
            target: bytes | None = rl.target
            req = cls(rl.method, rl.target.decode(errors="replace"), rl.version)
        else:  # best effort on bytes nginx refused
            parts = raw.split(b"\n", 1)[0].rstrip(b"\r").split(b" ")
            target = parts[1][: nginx.LINE_MAX] if parts[1:] else None
            req = cls(truncate(parts[0], 64), truncate(target, nginx.LINE_MAX))
        if target and (split := nginx.split_target(target)):
            req.path, req.query, req.host = split
        return req

    def header(self, name: str) -> str | None:
        n = name.encode()
        vals = (v.decode("latin-1") for k, v, ok in self.headers if ok and k.lower() == n)
        return next(vals, None)


class Handler:
    def __init__(self, profile: Profile) -> None:
        self.profile = profile

    async def __call__(
        self, session: Session, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        conn = Connection(self.profile, session, reader, writer)
        while await conn.next_request():
            pass


class Connection:
    def __init__(
        self, profile: Profile, session: Session, r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        self.p, self.s, self.r, self.w = profile, session, r, w
        self.buf = b""
        self.count = 0
        peer = session.peer
        sock = w.get_extra_info("sockname") or ("127.0.0.1", 80)
        self.local = (peer.dst_ip, peer.dst_port) if peer.dst_ip else (sock[0], sock[1])

    async def _read(self, timeout: float) -> bytes:
        try:
            async with asyncio.timeout(timeout):
                return await self.r.read(READ_SIZE)
        except TimeoutError:
            return b""  # nginx closes on its timeouts without a word, as on EOF

    async def next_request(self) -> bool:
        """Serve one request; True when the connection stays open."""
        self.count += 1
        while True:
            self.buf = self.buf.lstrip(b"\r\n")  # nginx skips blank lines before a request
            if self.buf:
                rl = nginx.request_line(self.buf)
                if isinstance(rl, int):
                    return await self.reject(rl)
                if rl is not None:
                    if nginx.split_target(rl.target) is None or (
                        rl.major == 0 and rl.method != "GET"
                    ):
                        return await self.reject(400, rl)  # an HTTP/0.9 refusal is body-only too
                    if rl.major == 0:  # HTTP/0.9: no headers to wait for
                        return await self.request(rl, rl.end)
                    try:
                        end = nginx.head_end(self.buf, rl.end)
                    except ValueError:
                        return await self.reject(nginx.HEADER_TOO_LARGE, rl)
                    if end is not None:
                        return await self.request(rl, end)
            first = self.count == 1 or bool(self.buf)
            data = await self._read(HEADER_TIMEOUT if first else KEEPALIVE_TIMEOUT)
            if not data:
                if self.buf:
                    await self.reject(None)  # an unfinished request is recorded, not answered
                return False
            self.buf += data

    async def reject(self, code: int | None, rl: RequestLine | None = None) -> bool:
        raw, self.buf = self.buf, b""
        req = Request.from_line(rl, raw)
        req.raw = raw
        await self.finish(req, code, respond=code is not None)
        return False

    async def request(self, rl: RequestLine, end: int) -> bool:
        head, self.buf = self.buf[:end], self.buf[end:]
        req = Request.from_line(rl, head)
        if rl.major == 0:
            self.buf = b""
            return await self.finish(req, None)
        req.headers = nginx.header_lines(head[rl.end :])
        valid = [(k.lower(), v) for k, v, ok in req.headers if ok]
        n = Counter(k for k, _ in valid)
        cl, te = req.header("content-length"), req.header("transfer-encoding")
        host = nginx.valid_host(dict(valid)[b"host"]) if n[b"host"] else ""
        # The order of ngx_http_process_request_header, which decides 400 against 501.
        bad = None
        if (
            any(b"\0" in k + v for k, v, _ in req.headers)
            or any(n[k] > 1 for k in FRAMING[:3])
            or host is None
            or (cl is not None and (not _DIGITS.fullmatch(cl) or int(cl) > nginx.OFF_T_MAX))
            or (te is not None and (rl.minor == 0 or (cl is not None and te.lower() == "chunked")))
        ):
            bad = 400
        elif te is not None and te.lower() != "chunked":
            bad = 501
        req.host = req.host or host or None
        conn = h11.Connection(h11.SERVER, max_incomplete_event_size=nginx.HEAD_MAX)
        if bad is None:
            synth = b"GET / HTTP/1.%d\r\n" % (1 if rl.minor else 0)
            synth += b"".join(k + b": " + v + b"\r\n" for k, v in valid if k in FRAMING)
            try:
                conn.receive_data(synth + b"\r\n" + self.buf)
                conn.next_event()
            except h11.RemoteProtocolError as exc:
                bad = 501 if exc.error_status_hint == 501 else 400  # missing Host, mostly
        if bad is not None:
            req.raw, self.buf = head, b""
            return await self.finish(req, bad)

        keepalive = rl.minor >= 1
        for k, v in valid:  # ngx_http_process_connection: substring matches, last one wins
            if k == b"connection":
                lv = v.lower()
                keepalive = False if b"close" in lv else True if b"keep-alive" in lv else keepalive
        if cl is not None and int(cl) > self.p.max_body:  # decided before reading the body
            req.declared, self.buf = int(cl), b""
            return await self.finish(req, 413)

        body, continued = bytearray(), False
        while True:
            try:
                ev = conn.next_event()
            except h11.RemoteProtocolError:  # a broken chunked body
                req.body, self.buf = bytes(body), b""
                return await self.finish(req, 400)
            if isinstance(ev, h11.Data):
                body += ev.data
                if len(body) > self.p.max_body:
                    req.body, self.buf = bytes(body), b""
                    return await self.finish(req, 413)
            elif isinstance(ev, h11.EndOfMessage):
                break
            else:
                if conn.they_are_waiting_for_100_continue and not continued:
                    continued = True
                    self.w.write(CONTINUE)
                data = await self._read(BODY_TIMEOUT)
                if not data:  # the client went away: nginx answers nothing
                    req.body, self.buf = bytes(body), b""
                    return await self.finish(req, None, respond=False)
                conn.receive_data(data)
        req.body, self.buf = bytes(body), conn.trailing_data[0]
        return await self.finish(req, None, keepalive)

    async def finish(
        self, req: Request, error: int | None, keepalive: bool = False, respond: bool = True
    ) -> bool:
        """Gate the request, apply the decision, answer and log. ``error`` is the status nginx
        gives before routing (400, 413, 414, 501, 505); ``respond`` is False once the client
        is gone."""
        route = self.p.routes.get(req.path or "") if error is None else None
        seq, rid, applied = await self.s.gate(
            known=route is not None,
            method=req.method,
            path=req.path,
            query=req.query,
            headers={
                h: truncate(v, FIELD_CAP) for h in GATE_HEADERS if (v := req.header(h)) is not None
            },
            body_len=req.declared if req.declared is not None else len(req.body),
            body_sha256=hashlib.sha256(req.body).hexdigest(),
            body_head=truncate(req.body, BODY_HEAD_CAP),
        )
        if route and route.get("capture") and req.method == "POST":
            self.capture(req, route, seq, rid)
        if applied.action is Action.DELAY:
            await asyncio.sleep(applied.delay_ms / 1000)
        resp = None
        if respond and applied.action is not Action.TERMINATE:
            resp = self.decide(req, route, error, applied)
        head, v09 = req.method == "HEAD", req.version == "0.9"
        wire = b""
        if resp is not None:
            keepalive = (
                keepalive
                and error is None
                and resp.status not in nginx.CLOSE_AFTER
                and not v09
                and self.count < KEEPALIVE_REQUESTS
            )
            wire = self.p.frame(resp, keepalive=keepalive, head=head, v09=v09)
            self.w.write(wire)
        else:
            keepalive = False
        status = resp.status if resp is not None else None
        sent = nginx.sent_body(resp, head) if resp is not None else b""
        extra: dict[str, Any] = {}
        if req.raw is not None:
            extra["raw"] = self.s.content(req.raw, "http.raw")
        self.s.emit(
            "request",
            seq=seq,
            request_id=rid,
            method=req.method,
            path=req.path,
            query=req.query,
            target=req.target,
            http_version=req.version,
            headers=[[truncate(k, FIELD_CAP), truncate(v, FIELD_CAP)] for k, v, _ in req.headers],
            user_agent=truncate(req.header("user-agent"), FIELD_CAP),
            body=self.s.content(req.body, "http.body"),
            status=status,
            response_bytes=len(wire),
            response_sha256=hashlib.sha256(sent).hexdigest(),
            route=route["path"] if route else None,
            outcome="success" if status is not None and status < 400 else "failure",
            **extra,
        )
        if resp is not None:
            async with asyncio.timeout(SEND_TIMEOUT):
                await self.w.drain()
            if not keepalive and (error is not None or status in nginx.CLOSE_AFTER):
                await self.linger()
        return keepalive

    def decide(
        self, req: Request, route: dict[str, Any] | None, error: int | None, applied: Applied
    ) -> Response:
        ua, v10 = req.header("user-agent") or "", req.version != "0.9"
        if applied.action is Action.FAKE_SUCCESS:
            dynamic = bool(route and route.get("capture"))
            return Response(200, applied.output.encode(), "text/html", static=not dynamic)
        if applied.action is Action.FAKE_ERROR:
            code = min(max(500 if applied.exit_code is None else applied.exit_code, 400), 599)
            if applied.output:
                return Response(code, applied.output.encode(), "text/html")
            return self.p.error(code, ua, v10)
        if error is not None:
            return self.p.error(error, ua, v10)
        return self.serve(req, route, ua, v10)

    def serve(self, req: Request, route: dict[str, Any] | None, ua: str, v10: bool) -> Response:
        m, path, dirs = req.method, req.path or "/", self.p.dirs
        if m == "TRACE":  # refused in ngx_http_process_request_header, before any location
            return self.p.error(405, ua, v10)
        if route is not None:
            if route["status"] >= 400 and not route.get("body"):  # deny all: every method
                return self.p.error(route["status"], ua, v10)
            methods = set(route["methods"]) | ({"HEAD"} if "GET" in route["methods"] else set())
            if m not in methods:
                return self.p.error(405, ua, v10)
            if route.get("redirect") and m != "POST":  # a PHP redirect: no body
                resp = Response(302, b"", route.get("content_type"))
                here = self.absolute(req, path + (f"?{req.query}" if req.query else ""))
                resp.location = self.absolute(
                    req, route["redirect"].replace("{self}", quote(here, safe=""))
                )
                return resp
            body = self.post_body(req, route) if m == "POST" else route["body"]
            resp = Response(route["status"], body.encode(), route["content_type"])
            # Files carry Last-Modified and ETag; PHP output and every POST reply do not.
            resp.static = not (route.get("capture") or route.get("dynamic") or m == "POST")
            if resp.static and resp.status == 200 and self.not_modified(req, len(resp.body)):
                resp.status, resp.content_type = 304, None
            return resp
        is_dir = path in dirs or path + "/" in dirs
        if is_dir and m not in ("GET", "HEAD", "POST"):  # the static module checks this first
            return self.p.error(405, ua, v10)
        if path + "/" in dirs:
            resp = self.p.error(301, ua, v10)
            q = f"?{req.query}" if req.query else ""
            resp.location = self.absolute(req, f"{path}/{q}")
            return resp
        return self.p.error(403 if path in dirs else 404, ua, v10)

    def not_modified(self, req: Request, length: int) -> bool:
        """ngx_http_not_modified_filter with if_modified_since exact."""
        ims, inm = req.header("if-modified-since"), req.header("if-none-match")
        if ims is None and inm is None:
            return False
        if ims is not None and nginx.parse_http_date(ims) != self.p.mtime:
            return False
        return inm is None or nginx.etag_matches(inm, self.p.etag(length))

    def absolute(self, req: Request, path: str) -> str:
        """An absolute URL on this server, as nginx (port_in_redirect) and PHP build them."""
        ip, port = self.local
        host = req.host or (f"[{ip}]" if ":" in str(ip) else str(ip))
        suffix = f":{port}" if port and port != 80 else ""
        return f"http://{host}{suffix}{path}"

    @staticmethod
    def form(req: Request) -> dict[str, str] | None:
        """A urlencoded form body (the first value of each field), or None for other bodies."""
        ctype = (req.header("content-type") or "").lower()
        if ctype and not ctype.startswith("application/x-www-form-urlencoded"):
            return None
        form: dict[str, str] = {}
        for k, v in parse_qsl(req.body, keep_blank_values=True):
            form.setdefault(k.decode(errors="replace"), v.decode(errors="replace"))
        return form

    def post_body(self, req: Request, route: dict[str, Any]) -> str:
        """The page a POST gets. A route with ``post_bodies`` answers as a login form does:
        differently for an empty, a known and an unknown username (WordPress names which one it
        was). ``{username}`` is replaced with the submitted name, HTML-escaped."""
        fields = route.get("fields") or []
        user = (self.form(req) or {}).get(fields[0], "") if fields else ""
        user = truncate(user, FIELD_CAP) or ""
        bodies = route.get("post_bodies")
        if bodies:
            known = {u.lower() for u in route.get("known_users", [])}
            key = "empty" if not user else "known" if user.lower() in known else "unknown"
            tmpl = bodies.get(key) or bodies["unknown"]
        else:
            tmpl = route.get("post_body") or route["body"]
        return tmpl.replace("{username}", html.escape(user, quote=True))

    def capture(self, req: Request, route: dict[str, Any], seq: int, rid: str) -> None:
        form = self.form(req)
        if form is None:
            return
        user_f, pass_f = route["fields"][:2]
        if user_f in form or pass_f in form:
            self.s.emit(
                "login.failed",
                seq=seq,
                request_id=rid,
                username=truncate(form.get(user_f), FIELD_CAP),
                password=truncate(form.get(pass_f), FIELD_CAP),
                form=route["path"],
            )

    async def linger(self) -> None:
        """lingering_close: stop writing, drain what the client still sends, then close, so the
        client reads the error page instead of a reset."""
        with contextlib.suppress(Exception):
            self.w.write_eof()
            loop = asyncio.get_running_loop()
            end = loop.time() + LINGER_TIME
            while loop.time() < end:
                async with asyncio.timeout(LINGER_TIMEOUT):
                    if not await self.r.read(READ_SIZE):
                        break
