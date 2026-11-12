"""HTTP, Redis and MySQL drivers for the scenario runner.

Each is an ordinary client on a socket that already carries the PROXY v2 header the lab edge
passed through, so the decoy logs the simulated source address and port. They share the SSH
driver's interface (``login``, ``run``, ``alive``, ``close``, ``conn``), so the runner's step
and reaction logic does not care which protocol it is driving.

The one subtlety is the hash each step carries for the join: it must be taken over the exact
string the decoy records as the gated input (``DecideRequest.input_text`` in the policy
contract) -- for HTTP the request line ``"GET /path"``, for Redis the space-joined argv, for
MySQL the SQL text. ``run`` returns that canonical string's hash in ``Result.sha256``.
"""

from __future__ import annotations

import contextlib
import socket
from datetime import UTC, datetime

from mirage_lab.drivers.base import AuthPhase, LoginResult, Result
from mirage_lab.net import Conn, Dialer
from mirage_lab.timing import Timing
from mirage_schema.groundtruth import input_hash

HTTP_PORT, REDIS_PORT, MYSQL_PORT = 8080, 6379, 3306
CRLF = bytes([13, 10])


def now() -> datetime:
    return datetime.now(UTC)


class _Reader:
    """A buffered reader over a blocking socket: read a line, exactly N bytes, or all."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = bytearray()
        self.eof = False

    def _fill(self) -> bool:
        try:
            chunk = self.sock.recv(65536)
        except (TimeoutError, OSError):
            self.eof = True
            return False
        if not chunk:
            self.eof = True
            return False
        self.buf += chunk
        return True

    def line(self) -> bytes:
        while CRLF not in self.buf:
            if not self._fill():
                line, self.buf = bytes(self.buf), bytearray()
                return line
        i = self.buf.index(CRLF)
        line = bytes(self.buf[: i + 2])
        del self.buf[: i + 2]
        return line

    def exactly(self, n: int) -> bytes:
        while len(self.buf) < n and self._fill():
            pass
        out, self.buf = bytes(self.buf[:n]), self.buf[n:]
        return out

    def rest(self) -> bytes:
        while self._fill():
            pass
        out, self.buf = bytes(self.buf), bytearray()
        return out


# ------------------------------------------------------------------ HTTP


class HTTPDriver:
    """One HTTP request per step, each on its own connection (``Connection: close``). A step's
    input is its request line; a body may follow it, sent as a form post."""

    def __init__(self, dialer: Dialer, timing: Timing, user_agent: str) -> None:
        self.dialer, self.timing, self.user_agent = dialer, timing, user_agent
        self.conn: Conn | None = None

    def login(self, guesses: int) -> LoginResult:
        return LoginResult(ok=True)  # HTTP has no session login; connections are per request

    def alive(self) -> bool:
        return True

    def run(self, line: str) -> Result:
        parts = line.split(None, 2)
        method = parts[0] if parts else "GET"
        target = parts[1] if len(parts) > 1 else "/"
        body = parts[2].encode() if len(parts) > 2 else b""
        canonical = f"{method} {target}"
        started = now()
        try:
            conn = self.dialer.connect(HTTP_PORT)
        except OSError:
            return Result(sent=False, alive=True)
        self.conn = conn
        head = (
            f"{method} {target} HTTP/1.1\r\nHost: localhost\r\n"
            f"User-Agent: {self.user_agent}\r\nConnection: close\r\n"
        )
        if body:
            head += (
                "Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\n"
            )
        try:
            conn.sock.sendall(head.encode() + b"\r\n" + body)
            raw = _Reader(conn.sock).rest()
        except OSError:
            raw = b""
        finally:
            self._shut(conn)
        text = raw.decode(errors="replace")
        return Result(
            sent=True,
            output=text,
            alive=True,
            conn=conn,
            started=started,
            ended=now(),
            sha256=input_hash(canonical),
        )

    @staticmethod
    def _shut(conn: Conn) -> None:
        with contextlib.suppress(OSError):
            conn.sock.close()
        conn.closed = now()

    def close(self) -> None:
        pass


# ------------------------------------------------------------------ Redis


def _resp(tokens: list[str]) -> bytes:
    out = b"*%d" % len(tokens) + CRLF
    for t in tokens:
        b = t.encode()
        out += b"$%d" % len(b) + CRLF + b + CRLF
    return out


class RedisDriver:
    """One persistent connection; each step is one command, sent as a RESP array."""

    def __init__(self, dialer: Dialer, timing: Timing) -> None:
        self.dialer, self.timing = dialer, timing
        self.conn: Conn | None = None
        self.reader: _Reader | None = None
        self._alive = False

    def login(self, guesses: int) -> LoginResult:
        try:
            self.conn = self.dialer.connect(REDIS_PORT)
        except OSError:
            return LoginResult(ok=False)
        self.reader = _Reader(self.conn.sock)
        self._alive = True
        return LoginResult(ok=True)

    def alive(self) -> bool:
        return self._alive

    def run(self, line: str) -> Result:
        tokens = line.split()
        canonical = " ".join(tokens)
        started = now()
        if self.conn is None or self.reader is None:
            return Result(sent=False, alive=False)
        try:
            self.conn.sock.sendall(_resp(tokens))
            reply = self._reply(self.reader)
        except OSError:
            self._alive = False
            return Result(sent=True, alive=False, conn=self.conn, started=started, ended=now(),
                          sha256=input_hash(canonical))  # fmt: skip
        if self.reader.eof:
            self._alive = False
        return Result(
            sent=True,
            output=reply,
            alive=self._alive,
            conn=self.conn,
            started=started,
            ended=now(),
            sha256=input_hash(canonical),
        )

    def _reply(self, r: _Reader) -> str:
        """One RESP value as text (enough of RESP2/RESP3 for the decoy's replies)."""
        line = r.line()
        if not line:
            return ""
        kind, body = line[:1], line[1:-2]
        if kind in (b"+", b"-", b":"):
            return line.decode(errors="replace").rstrip("\r\n")
        if kind in (b"$", b"="):
            n = int(body or b"-1")
            if n < 0:
                return "(nil)"
            data = r.exactly(n + 2)
            return data[:-2].decode(errors="replace")
        if kind in (b"*", b"%", b">", b"~"):
            n = int(body or b"0")
            count = n * 2 if kind == b"%" else n
            return "\n".join(self._reply(r) for _ in range(max(count, 0)))
        return line.decode(errors="replace")

    def close(self) -> None:
        if self.conn is not None:
            with contextlib.suppress(OSError):
                self.conn.sock.close()
            self.conn.closed = now()
        self._alive = False


# ------------------------------------------------------------------ MySQL


class MySQLDriver:
    """A PyMySQL connection over the pre-connected socket; each step is one query."""

    def __init__(self, dialer: Dialer, timing: Timing, user: str, password: str) -> None:
        self.dialer, self.timing = dialer, timing
        self.user, self.password = user, password
        self.conn: Conn | None = None
        self._db = None

    def login(self, guesses: int) -> LoginResult:
        import pymysql

        started = now()
        try:
            conn = self.dialer.connect(MYSQL_PORT)
        except OSError:
            return LoginResult(ok=False)
        self.conn = conn
        try:
            db = pymysql.connections.Connection(
                user=self.user,
                password=self.password,
                host=self.dialer.target_ip,
                port=MYSQL_PORT,
                defer_connect=True,
                read_timeout=15,
                write_timeout=15,
                autocommit=True,
            )
            db.connect(conn.sock)
            self._db = db
            ok = True
        except pymysql.MySQLError:
            ok = False
        return LoginResult(ok=ok, phases=[AuthPhase(conn, started, now(), 1, ok)])

    def alive(self) -> bool:
        return self._db is not None and self._db.open

    def run(self, line: str) -> Result:
        import pymysql

        if self._db is None or not self._db.open:
            return Result(sent=False, alive=False, conn=self.conn)
        started = now()
        try:
            with self._db.cursor() as cur:
                cur.execute(line)
                rows = cur.fetchall() if cur.description is not None else None
                output = (
                    "\n".join(str(r) for r in rows) if rows is not None else f"{cur.rowcount} rows"
                )
        except pymysql.MySQLError as exc:
            output = f"ERROR {exc.args[0]}: {exc.args[1]}" if len(exc.args) > 1 else str(exc)
        return Result(
            sent=True,
            output=output,
            alive=self.alive(),
            conn=self.conn,
            started=started,
            ended=now(),
            sha256=input_hash(line),
        )

    def close(self) -> None:
        if self._db is not None:
            with contextlib.suppress(Exception):
                self._db.close()
        if self.conn is not None:
            self.conn.closed = now()
