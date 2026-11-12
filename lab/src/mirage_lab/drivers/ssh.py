"""SSH driver: password guessing, an interactive shell or exec requests, and SFTP uploads.

It is an ordinary paramiko client on a socket that already carries the PROXY header. Each
simulated actor has its own client banner and algorithm order, as different tools do, so the
pipeline's fingerprint link does not merge unrelated lab actors (spec section 2).
"""

from __future__ import annotations

import contextlib
import io
import random
import re
import time
from datetime import UTC, datetime

import paramiko

from mirage_lab.drivers.base import AuthPhase, LoginResult, Result
from mirage_lab.net import Conn, Dialer
from mirage_lab.timing import Timing
from mirage_schema.groundtruth import input_hash

PORT = 2222
BANNERS = (
    "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
    "OpenSSH_9.6p1 Debian-4",
    "OpenSSH_7.4",
    "libssh_0.10.6",
    "libssh2_1.11.0",
    "Go",
    "PuTTY_Release_0.81",
    "paramiko_3.4.0",
    "JSCH-0.2.17",
    "AsyncSSH_2.14.2",
)
# Wrong guesses come from the short list every credential-stuffing run starts with.
COMMON_PASSWORDS = (
    "123456", "password", "admin", "root", "12345678", "qwerty", "123123", "1234", "abc123",
    "toor", "changeme", "letmein", "welcome", "P@ssw0rd", "111111", "test", "ubuntu", "raspberry",
)  # fmt: skip
# Client strings a web scanner or tool might send; one per actor (used by the HTTP driver).
HTTP_USER_AGENTS = (
    "curl/8.5.0",
    "Wget/1.21.4",
    "python-requests/2.32.3",
    "Go-http-client/1.1",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (compatible; masscan/1.3)",
    "zgrab/0.x",
    "libwww-perl/6.77",
)
ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
PROMPT = re.compile(r"[#$] $")


def now() -> datetime:
    return datetime.now(UTC)


class Fingerprint:
    """One actor's client identity: a banner and an order for each algorithm list."""

    def __init__(self, rng: random.Random) -> None:
        self.banner = rng.choice(BANNERS)
        self.seed = rng.getrandbits(32)
        self.user_agent = rng.choice(HTTP_USER_AGENTS)

    def apply(self, transport: paramiko.Transport) -> None:
        transport.local_version = f"SSH-2.0-{self.banner}"
        order = random.Random(self.seed)
        opts = transport.get_security_options()
        for name in ("kex", "ciphers", "digests", "key_types"):
            values = list(getattr(opts, name))
            order.shuffle(values)
            setattr(opts, name, tuple(values))


class SSHDriver:
    def __init__(
        self,
        dialer: Dialer,
        timing: Timing,
        fingerprint: Fingerprint,
        user: str,
        password: str,
        channel: str = "shell",
    ) -> None:
        self.dialer, self.timing, self.fingerprint = dialer, timing, fingerprint
        self.user, self.password, self.channel = user, password, channel
        self.conn: Conn | None = None
        self.transport: paramiko.Transport | None = None
        self.shell: paramiko.Channel | None = None

    # ------------------------------------------------------------------ connection and login

    def _open(self) -> tuple[Conn, paramiko.Transport]:
        conn = self.dialer.connect(PORT)
        transport = paramiko.Transport(conn.sock)
        self.fingerprint.apply(transport)
        transport.start_client(timeout=15)
        return conn, transport

    def login(self, guesses: int, per_connection: int = 3) -> LoginResult:
        """``guesses`` wrong passwords, a few per connection as real tools do, then the right
        one. Every connection used is reported with its window, for the label join."""
        wrong = [p for p in COMMON_PASSWORDS if p != self.password]
        self.timing.rng.shuffle(wrong)
        todo = [wrong[i % len(wrong)] for i in range(guesses)] + [self.password]
        result = LoginResult(ok=False)
        while todo:
            try:
                conn, transport = self._open()
            except (OSError, paramiko.SSHException):
                return result
            started, attempts, success = now(), 0, False
            for _ in range(per_connection):
                if not todo:
                    break
                password = todo.pop(0)
                attempts += 1
                try:
                    transport.auth_password(self.user, password)
                    success = True
                    break
                except paramiko.AuthenticationException:
                    time.sleep(self.timing.gap())
                except (paramiko.SSHException, OSError, EOFError):
                    break  # the server hung up; carry on with a new connection
            result.phases.append(AuthPhase(conn, started, now(), attempts, success))
            if success:
                self.conn, self.transport, result.ok = conn, transport, True
                return result
            transport.close()
            time.sleep(self.timing.gap())
        return result

    def alive(self) -> bool:
        return self.transport is not None and self.transport.is_active()

    # ------------------------------------------------------------------ steps

    def run(self, line: str) -> Result:
        if not self.alive():
            return Result(sent=False, alive=False, conn=self.conn)
        try:
            if self.channel == "exec":
                return self._exec(line)
            return self._shell(line)
        except (paramiko.SSHException, OSError, EOFError):
            return Result(
                sent=True, alive=self.alive(), conn=self.conn, sha256=input_hash(line), ended=now()
            )

    def _exec(self, line: str) -> Result:
        assert self.transport is not None
        started = now()
        chan = self.transport.open_session(timeout=15)
        chan.settimeout(20)
        chan.exec_command(line)
        chunks = []
        with contextlib.suppress(TimeoutError):
            while data := chan.recv(65536):
                chunks.append(data)
        status = chan.recv_exit_status() if chan.exit_status_ready() or chan.closed else None
        chan.close()
        return Result(
            sent=True,
            output=b"".join(chunks).decode(errors="replace"),
            status=status,
            alive=self.alive(),
            conn=self.conn,
            started=started,
            ended=now(),
            sha256=input_hash(line),
        )

    def _ensure_shell(self) -> paramiko.Channel:
        if self.shell is None:
            assert self.transport is not None
            chan = self.transport.open_session(timeout=15)
            chan.get_pty(term="xterm-256color", width=160, height=48)
            chan.invoke_shell()
            self.shell = chan
            self._read_to_prompt(15)
        return self.shell

    def _read_to_prompt(
        self, timeout: float, quiet: float = 0.12, stuck: float = 1.2
    ) -> tuple[str, bool, bool]:
        """Everything the shell sends until it shows a prompt and goes quiet, the output stops
        at something that is not a shell prompt, or the timeout. Returns (text, still open,
        saw a shell prompt). "No prompt but gone quiet" means an interactive command is waiting
        for input (``useradd``, ``passwd``, ``vim`` ...); the caller aborts it."""
        chan = self.shell
        assert chan is not None
        buf, deadline, last = b"", time.monotonic() + timeout, time.monotonic()
        while time.monotonic() < deadline:
            if chan.recv_ready():
                data = chan.recv(65536)
                if not data:
                    return ANSI.sub("", buf.decode(errors="replace")), False, False
                buf += data
                last = time.monotonic()
                continue
            if chan.closed or chan.eof_received:
                return ANSI.sub("", buf.decode(errors="replace")), False, False
            text = ANSI.sub("", buf.decode(errors="replace"))
            idle = time.monotonic() - last
            if PROMPT.search(text) and idle >= quiet:
                return text, True, True
            if buf and idle >= stuck:
                return text, True, False  # stopped, but not at a shell prompt
            time.sleep(0.01)
        return ANSI.sub("", buf.decode(errors="replace")), not chan.closed, False

    def _shell(self, line: str) -> Result:
        chan = self._ensure_shell()
        started = now()
        for text, pause in self.timing.strokes(line):
            if pause:
                time.sleep(pause)
            chan.sendall(text.encode())
        chan.sendall(b"\n")
        text, open_, saw_prompt = self._read_to_prompt(30)
        if open_ and not saw_prompt:
            # An interactive command is prompting. Abort it (Ctrl-C) so it does not consume the
            # next step's line as its input; the command's own cowrie.command.input already
            # fired, so this step is still captured and labelled.
            chan.sendall(b"\x03")
            extra, open_, _ = self._read_to_prompt(10)
            text += extra
        # Drop the echoed line and the closing prompt; what is left is the command's output.
        body = text.split("\n", 1)[1] if "\n" in text else ""
        body = body.rsplit("\n", 1)[0] + "\n" if "\n" in body else ""
        return Result(
            sent=True,
            output=body.replace("\r", ""),
            alive=open_ and self.alive(),
            conn=self.conn,
            started=started,
            ended=now(),
            sha256=input_hash(line),
        )

    def upload(self, path: str, data: bytes) -> Result:
        if not self.alive():
            return Result(sent=False, alive=False, conn=self.conn)
        assert self.transport is not None
        started = now()
        try:
            sftp = paramiko.SFTPClient.from_transport(self.transport)
            assert sftp is not None
            sftp.putfo(io.BytesIO(data), path)
            sftp.close()
            ok = True
        except (paramiko.SSHException, OSError, EOFError):
            ok = False
        return Result(
            sent=True,
            output="",
            status=0 if ok else 1,
            alive=self.alive(),
            conn=self.conn,
            started=started,
            ended=now(),
            sha256=input_hash(data),
        )

    def close(self) -> None:
        with contextlib.suppress(Exception):
            if self.shell is not None:
                self.shell.close()
        with contextlib.suppress(Exception):
            if self.transport is not None:
                self.transport.close()
        if self.conn is not None:
            self.conn.closed = now()
