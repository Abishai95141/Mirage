#!/usr/bin/env python3
"""Check the showcase from where a visitor stands, before its link is opened.

Run on the lab host after `make showcase-preview` (`make showcase-check` does). It talks to
the preview port on this machine and to nothing else, with the standard library only, and it
never prints the console's password: it reads it from .env and uses it.

What it shows:

1. the dashboards answer anyone, and nobody can sign in to them;
2. the console answers nobody without its password, and slows someone guessing;
3. a page on another site cannot open a terminal with a signed-in visitor's browser;
4. with the password, a visitor gets the decoy's shell, and the session is recorded, whether
   they leave by the shell or by closing the tab;
5. the console's container can reach the lab edge and the proxy's network, and not this
   machine.

Exit status 0 when every check passes.

It leaves two sessions in the store under the console's scenario name, typed by this script
and not by a person. That name is in no split, so they cannot reach a dataset.
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
USER = "presenter"
CONSOLE = "mirage-showcase-console-1"
PROBLEMS: list[str] = []


def env(name: str, default: str = "") -> str:
    for line in (ROOT / ".env").read_text().splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1] or default
    return default


HOST, PORT = "127.0.0.1", int(env("SHOWCASE_PORT", "3301"))


def basic(password: str) -> str:
    return "Basic " + base64.b64encode(f"{USER}:{password}".encode()).decode()


def check(ok: bool, what: str, detail: str = "") -> bool:
    print(
        ("  ok    " if ok else "  FAIL  ") + what + (f"  [{detail}]" if detail and not ok else "")
    )
    if not ok:
        PROBLEMS.append(what)
    return ok


def get(path: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection(HOST, PORT, timeout=15)
    try:
        conn.request("GET", path, headers=headers or {})
        r = conn.getresponse()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
    finally:
        conn.close()


# ------------------------------------------------------------------ a WebSocket, by hand


class Terminal:
    """A browser's side of the console's terminal: enough of RFC 6455 and of ttyd's protocol
    (first message a JSON with the token; then '0' + keys out, '0' + screen in)."""

    def __init__(
        self, password: str | None, origin: str | None = None, ticket: str | None = None
    ) -> None:
        """``password``: send it on the connection, as most browsers do. ``ticket``: send the
        sign-in cookie, which is all Safari sends."""
        self.sock = socket.create_connection((HOST, PORT), timeout=15)
        key = base64.b64encode(os.urandom(16)).decode()
        shown = f"Authorization: {basic(password)}\r\n" if password else ""
        shown += f"Cookie: mirage_console={ticket}\r\n" if ticket else ""
        request = (
            f"GET /console/ws HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: tty\r\nOrigin: {origin or f'http://{HOST}:{PORT}'}\r\n"
            f"{shown}\r\n"
        )
        self.sock.sendall(request.encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            head += chunk
        self.status = int(head.split(b" ", 2)[1]) if head.startswith(b"HTTP/") else 0
        self.buffer = head.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in head else b""
        self.screen = b""
        self.closed = self.status != 101

    def _send(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        n = len(payload)
        head = bytes([0x80 | opcode])
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + struct.pack("!H", n)
        else:
            head += bytes([0x80 | 127]) + struct.pack("!Q", n)
        self.sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def start(self, token: str) -> None:
        self._send(2, json.dumps({"AuthToken": token, "columns": 100, "rows": 30}).encode())

    def keys(self, text: str) -> None:
        self._send(2, b"0" + text.encode())

    def _need(self, n: int) -> bytes | None:
        while len(self.buffer) < n:
            try:
                chunk = self.sock.recv(65536)
            except (TimeoutError, OSError):
                return None
            if not chunk:
                self.closed = True
                return None
            self.buffer += chunk
        out, self.buffer = self.buffer[:n], self.buffer[n:]
        return out

    def _frame(self) -> None:
        head = self._need(2)
        if head is None:
            return
        opcode, n = head[0] & 0x0F, head[1] & 0x7F
        if n == 126:
            n = struct.unpack("!H", self._need(2) or b"\0\0")[0]
        elif n == 127:
            n = struct.unpack("!Q", self._need(8) or b"\0" * 8)[0]
        payload = self._need(n) if n else b""
        if payload is None:
            return
        if opcode == 8:
            self.closed = True
        elif opcode == 9:
            self._send(10, payload)
        elif opcode in (1, 2, 0) and payload[:1] == b"0":
            self.screen += payload[1:]

    def text(self) -> str:
        """What is on the screen, without the terminal's control sequences."""
        return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", self.screen.decode("utf-8", "replace"))

    def wait_for(self, pattern: str, seconds: float = 25.0) -> bool:
        """Read until the screen matches ``pattern`` or the terminal closes."""
        deadline = time.monotonic() + seconds
        self.sock.settimeout(1.0)
        while time.monotonic() < deadline:
            if re.search(pattern, self.text()):
                return True
            if self.closed:
                return False
            self._frame()
        return bool(re.search(pattern, self.text()))

    def wait_closed(self, seconds: float = 15.0) -> bool:
        deadline = time.monotonic() + seconds
        self.sock.settimeout(1.0)
        while not self.closed and time.monotonic() < deadline:
            self._frame()
        return self.closed

    def drop(self) -> None:
        """Go away the way a closed tab does: no goodbye."""
        self.sock.close()


# ------------------------------------------------------------------ the checks


def recorded() -> int | None:
    """How many of the console's sessions have their ground truth written."""
    cmd = "grep -ls showcase-visitor /var/lib/mirage-lab/* 2>/dev/null | wc -l"
    r = subprocess.run(
        ["docker", "exec", CONSOLE, "sh", "-c", cmd], capture_output=True, text=True, timeout=30
    )
    return int(r.stdout.strip() or 0) if r.returncode == 0 else None


def dashboards() -> None:
    print("the dashboards, as anyone:")
    status, _h, body = get("/api/health")
    check(status == 200 and b"ok" in body, "they answer without a login", f"{status}")
    status, headers, _b = get("/")
    check(status in (200, 302), "the front page opens", f"{status}")
    check(headers.get("x-robots-tag", "").startswith("noindex"), "search engines are told no")
    status, _h, _b = get("/api/admin/settings")
    check(status in (401, 403), "the admin interface refuses a visitor", f"{status}")
    conn = http.client.HTTPConnection(HOST, PORT, timeout=15)
    try:
        body = json.dumps({"user": "admin", "password": "admin"})
        conn.request("POST", "/login", body, {"Content-Type": "application/json"})
        status = conn.getresponse().status
    finally:
        conn.close()
    check(status != 200, "nobody can sign in to them", f"{status}")
    # A viewer may ask Grafana how it reaches the store. The answer must not hold a secret.
    secrets = [env(n) for n in ("CLICKHOUSE_SHOWCASE_PASSWORD", "CLICKHOUSE_PASSWORD")]
    said = b"".join(
        get(path)[2] for path in ("/api/datasources", "/api/datasources/uid/clickhouse")
    )
    leaked = any(secret and secret.encode() in said for secret in secrets)
    check(not leaked, "they do not give out a store password")
    # A panel's query, as a visitor's browser sends it. A page that opens but whose panels
    # cannot reach the store looks fine to every check above (found 15 Nov 2026).
    query = {
        "from": "now-30d",
        "to": "now",
        "queries": [
            {
                "refId": "A",
                "datasource": {"type": "grafana-clickhouse-datasource", "uid": "clickhouse"},
                "editorType": "sql",
                "queryType": "table",
                "format": 1,
                "rawSql": "SELECT count() AS n FROM mirage.session_summary",
            }
        ],
    }
    conn = http.client.HTTPConnection(HOST, PORT, timeout=30)
    try:
        conn.request(
            "POST", "/api/ds/query", json.dumps(query), {"Content-Type": "application/json"}
        )
        r = conn.getresponse()
        status, body = r.status, r.read()
    finally:
        conn.close()
    try:
        frame = json.loads(body)["results"]["A"]["frames"][0]
        sessions = frame["data"]["values"][0][0]
    except (ValueError, KeyError, IndexError, TypeError):
        sessions = None
    detail = f"{status}: {body[:160]!r}"
    check(status == 200 and sessions is not None, "their panels can read the store", detail)
    check(bool(sessions), "and there is something to show", f"{sessions} sessions in the store")


def gate(password: str) -> tuple[str | None, str | None]:
    print("the console, without its password:")
    status, headers, _b = get("/console/")
    asked = "MIRAGE console" in headers.get("www-authenticate", "")
    check(status == 401 and asked, "it asks for the password", f"{status}")
    status, _h, _b = get("/console/token")
    check(status == 401, "the token is not given out", f"{status}")
    visitor = {"Cf-Connecting-Ip": "192.0.2.77"}  # a made-up visitor, so only it is slowed
    codes = [
        get("/console/", {**visitor, "Authorization": basic(f"wrong-{i}")})[0] for i in range(14)
    ]
    check(codes[0] == 401, "a wrong password is refused", f"{codes[0]}")
    check(429 in codes, "someone guessing is made to wait", f"{codes}")
    status, _h, _b = get("/console/", {**visitor, "Authorization": basic(password)})
    check(status == 429, "and waits even with the right one, for a while", f"{status}")

    print("the console, with its password:")
    login = {"Authorization": basic(password)}
    status, headers, body = get("/console/", login)
    check(status == 200 and b"<html" in body.lower(), "the terminal page opens", f"{status}")
    cookie = headers.get("set-cookie", "")
    found = re.match(r"mirage_console=([0-9a-f]{64}); ", cookie)
    ticket = found.group(1) if found else None
    kept = "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/console/" in cookie
    check(bool(ticket) and kept, "a signed-in browser is handed its ticket")
    check(password not in cookie, "the ticket does not hold the password")
    status, _h, body = get("/console/token", login)
    token = json.loads(body).get("token") if status == 200 else None
    check(bool(token), "a signed-in browser gets its token", f"{status}")
    elsewhere = Terminal(password, origin="https://elsewhere.example")
    refused = elsewhere.status != 101
    if not refused:
        elsewhere.start(token or "")
        refused = not elsewhere.wait_for("MIRAGE showcase console", 4)
    elsewhere.drop()
    check(refused, "a page on another site cannot open a terminal")
    nobody = Terminal(None)
    check(
        nobody.status == 401,
        "nor can a connection with neither password nor ticket",
        f"{nobody.status}",
    )
    nobody.drop()
    forged = Terminal(None, ticket="0" * 64)
    check(forged.status == 401, "nor one with a made-up ticket", f"{forged.status}")
    forged.drop()
    status, _h, _b = get("/console/", {"Cookie": "mirage_console=" + "f" * 64})
    check(status == 401, "nor does a made-up ticket open the page", f"{status}")
    status, _h, _b = get("/console/token", {"Cookie": f"mirage_console={ticket}"})
    check(status == 200, "the real ticket is taken in place of the password", f"{status}")
    return token, ticket


def sessions(password: str, token: str, ticket: str | None) -> None:
    print("a visitor's session:")
    before = recorded()
    t = Terminal(password)
    if not check(t.status == 101, "the terminal connects", f"{t.status}"):
        return
    t.start(token)
    check(t.wait_for("recorded and shown on the public dashboards"), "they are told it is recorded")
    check(t.wait_for(r"recording from 198\.18\.\d+\.\d+"), "it comes from a simulated address")
    check(t.wait_for(r"[#$] ?$"), "the decoy gives a shell")
    t.screen = b""
    t.keys("whoami\r")
    check(t.wait_for(r"(?m)^root\r?$"), "the decoy answers what is typed")
    t.keys("exit\r")
    check(t.wait_for(r'"run_id": "r\d+-[0-9a-f]+"') or t.closed, "leaving ends the session")
    check(t.wait_closed(), "and the terminal closes")
    t.drop()

    t = Terminal(None, ticket=ticket)  # as Safari connects: the ticket, no password
    if check(t.status == 101, "a second terminal connects with the ticket alone", f"{t.status}"):
        t.start(token)
        if check(t.wait_for(r"[#$] ?$"), "its shell opens"):
            t.keys("uname -a\r")
            t.wait_for("Linux", 10)
        t.drop()  # the tab is closed
    time.sleep(4)
    after = recorded()
    if before is None or after is None:
        check(False, "the console's records can be counted", "docker exec failed")
    else:
        check(
            after - before == 2,
            "both sessions were recorded, the closed tab's too",
            f"{after - before}",
        )


def inside(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "exec", CONSOLE, *args], capture_output=True, text=True, timeout=60
    )


def container() -> None:
    """What the console's container can reach, asked from inside it with the recorder's own
    probe. A visitor types into the decoy, not into this container; this is what is left to
    someone who broke out of the terminal server."""
    print("the console's container:")
    r = inside("mirage-lab", "check")
    check(
        r.returncode == 0 and "one side network allowed" in r.stdout,
        "it passes the isolation check",
    )
    routes = [ln.split() for ln in inside("cat", "/proc/net/route").stdout.splitlines()[1:]]
    nets = [
        ipaddress.IPv4Network((int.from_bytes(bytes.fromhex(c[1])[::-1]), 16), strict=False)
        for c in routes
        if len(c) > 7 and c[7] == "0000FFFF"
    ]
    check(
        len(nets) == 2 and not any(c[1] == "00000000" for c in routes), "two networks, no way out"
    )
    # This machine, by every address a container might try: each network's gateway address,
    # the machine's own addresses, and the other Docker bridges.
    here = subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split()
    here = [a for a in here if ":" not in a]
    targets = sorted({str(n.network_address + 1) for n in nets} | set(here))
    private = [a for a in targets if ipaddress.ip_address(a).is_private]
    probes = [f"{a}:{port}" for a in private for port in (22, 8123, 4222)]
    r = inside(
        "mirage-lab", "check", "--timeout", "2", *[x for t in probes for x in ("--probe", t)]
    )
    try:
        ends = json.loads(r.stdout)
    except ValueError:
        ends = {}
    reached = sorted(t for t, end in ends.items() if end.get("state") == "open")
    check(
        bool(ends) and not reached,
        f"it cannot reach this machine ({len(private)} addresses, 3 ports each)",
        ", ".join(reached) or "the probe did not run",
    )


def main() -> int:
    password = env("SHOWCASE_CONSOLE_PASSWORD")
    if not password:
        print("no SHOWCASE_CONSOLE_PASSWORD in .env; run make env", file=sys.stderr)
        return 2
    try:
        get("/-/proxy-health")
    except OSError as exc:
        print(
            f"nothing answers on {HOST}:{PORT} ({exc}); run make showcase-preview", file=sys.stderr
        )
        return 2
    dashboards()
    token, ticket = gate(password)
    if token:
        sessions(password, token, ticket)
    container()
    print(f"\n{len(PROBLEMS)} problem(s)" + ("" if not PROBLEMS else ": " + "; ".join(PROBLEMS)))
    return 1 if PROBLEMS else 0


if __name__ == "__main__":
    sys.exit(main())
