"""HTTP, Redis and MySQL drivers: request framing and the canonical hash the join needs.

No sockets: a fake socket records what was sent and replays a canned reply. MySQL's handshake
is covered live (tests/integration/test_lab.py).
"""

from __future__ import annotations

import random
from datetime import UTC, datetime

from mirage_lab.drivers.plain import HTTPDriver, RedisDriver, _Reader, _resp
from mirage_lab.net import Conn
from mirage_lab.timing import make
from mirage_schema.groundtruth import input_hash

TIMING = make("bot-fast", random.Random(0))


class FakeSocket:
    def __init__(self, reply: bytes = b"") -> None:
        self.sent = bytearray()
        self._reply = reply
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, n: int) -> bytes:
        out, self._reply = self._reply[:n], self._reply[n:]
        return out

    def setsockopt(self, *a) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class FakeDialer:
    def __init__(self, sock: FakeSocket) -> None:
        self.sock, self.target_ip, self.src_ip = sock, "172.26.0.2", "198.18.0.9"
        self.opened: list[Conn] = []
        self._port = 40001

    def connect(self, dst_port: int, timeout: float = 10.0) -> Conn:
        conn = Conn(self.sock, self.src_ip, self._port, self.target_ip, dst_port, datetime.now(UTC))
        self._port += 1
        self.opened.append(conn)
        return conn


def test_reader_line_exactly_rest():
    r = _Reader(FakeSocket(b"first\r\nsecond\r\nleftover"))
    assert r.line() == b"first\r\n"
    assert r.exactly(6) == b"second"
    assert r.rest() == b"\r\nleftover"
    assert r.line() == b""  # nothing left, no hang


def test_http_sends_the_request_line_and_hashes_it():
    sock = FakeSocket(b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 2\r\n\r\nhi")
    driver = HTTPDriver(FakeDialer(sock), TIMING, "curl/8.5.0")
    assert driver.login(0).ok
    r = driver.run("GET /.env")
    assert bytes(sock.sent).startswith(b"GET /.env HTTP/1.1\r\n")
    assert b"User-Agent: curl/8.5.0\r\n" in sock.sent
    assert b"Connection: close\r\n" in sock.sent
    assert r.sha256 == input_hash("GET /.env")  # the decoy logs "GET /.env" as the input
    assert "200" in r.output and r.output.endswith("hi")
    assert r.alive and r.conn is sock_conn(driver)


def sock_conn(driver: HTTPDriver) -> Conn:
    return driver.conn


def test_http_post_carries_a_body_but_hashes_only_the_request_line():
    sock = FakeSocket(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    driver = HTTPDriver(FakeDialer(sock), TIMING, "Wget/1.21")
    r = driver.run("POST /wp-login.php log=admin&pwd=x")
    assert b"POST /wp-login.php HTTP/1.1\r\n" in sock.sent
    assert b"Content-Length: 15\r\n" in sock.sent and sock.sent.endswith(b"log=admin&pwd=x")
    assert r.sha256 == input_hash("POST /wp-login.php")


def test_resp_framing():
    assert _resp(["SET", "k", "v"]) == b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n"
    assert _resp(["PING"]) == b"*1\r\n$4\r\nPING\r\n"


def test_redis_sends_resp_and_hashes_the_joined_argv():
    sock = FakeSocket(b"+PONG\r\n")
    driver = RedisDriver(FakeDialer(sock), TIMING)
    assert driver.login(0).ok
    r = driver.run("PING")
    assert sock.sent == _resp(["PING"])
    assert r.output == "+PONG"
    assert r.sha256 == input_hash("PING") and r.alive


def test_redis_reads_a_bulk_and_an_array_reply():
    driver = RedisDriver(FakeDialer(FakeSocket(b"$5\r\nhello\r\n")), TIMING)
    driver.login(0)
    assert driver.run("GET x").output == "hello"
    d2 = RedisDriver(FakeDialer(FakeSocket(b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n")), TIMING)
    d2.login(0)
    r = d2.run("KEYS *")
    assert r.output == "foo\nbar" and r.sha256 == input_hash("KEYS *")


def test_redis_multiple_spaces_collapse_like_the_decoys_argv():
    sock = FakeSocket(b"+OK\r\n")
    driver = RedisDriver(FakeDialer(sock), TIMING)
    driver.login(0)
    r = driver.run("SET   k   v")
    assert sock.sent == _resp(["SET", "k", "v"])
    assert r.sha256 == input_hash("SET k v")


def test_a_connection_that_fails_is_reported_not_swallowed():
    # The runner writes what broke on the session's record (gap register R1); for that the
    # driver has to say, and to say that nothing was sent.
    class Refusing(FakeDialer):
        def connect(self, dst_port: int, timeout: float = 10.0) -> Conn:
            raise ConnectionRefusedError(61, "Connection refused")

    refusing = Refusing(FakeSocket())
    r = HTTPDriver(refusing, TIMING, "curl/8.5.0").run("GET /")
    assert r.sent is False and r.error.startswith("ConnectionRefusedError")
    assert r.started <= r.ended
    assert RedisDriver(refusing, TIMING).login(0).error.startswith("ConnectionRefusedError")

    class Dropping(FakeSocket):
        def sendall(self, data: bytes) -> None:
            raise BrokenPipeError(32, "Broken pipe")

    driver = RedisDriver(FakeDialer(Dropping()), TIMING)
    assert driver.login(0).ok
    r = driver.run("PING")
    assert r.sent and not r.alive and r.error.startswith("BrokenPipeError")
    assert r.started <= r.ended
