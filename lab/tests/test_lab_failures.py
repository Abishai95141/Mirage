"""What the runner writes when a session goes wrong (gap register R1).

The first explore run lost six sessions to one path: the SSH connection dropped under a step,
the driver answered with a result that had an end time and no start, the step record's start
came out after its end, the schema refused it, and the exception left the session without its
record. The join then had no connection to match, so every step of the session was
``no_event``. These tests drive that path through the real SSH driver, on a transport that
dies, and through the runner's own guard.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import paramiko
import pytest
from test_lab import GOOD, Scripted, drive, steps_of

from mirage_lab.drivers.base import AuthPhase, LoginResult, Result
from mirage_lab.drivers.ssh import Fingerprint, SSHDriver
from mirage_lab.net import Conn
from mirage_schema.groundtruth import input_hash


class Channel:
    """An exec or shell channel that answers one line of output and closes."""

    def __init__(self, output: bytes = b"Linux host 6.1\n", fail_on: str = "") -> None:
        self.output, self.fail_on, self.closed, self.sent = output, fail_on, False, b""

    def _maybe_fail(self, name: str) -> None:
        if name == self.fail_on:
            raise paramiko.SSHException("Channel closed.")

    def settimeout(self, seconds):
        pass

    def set_combine_stderr(self, flag):
        pass

    def get_pty(self, **kw):
        self._maybe_fail("get_pty")

    def invoke_shell(self):
        self._maybe_fail("invoke_shell")

    def exec_command(self, line):
        self._maybe_fail("exec_command")

    def sendall(self, data):
        self._maybe_fail("sendall")
        self.sent += data

    def recv(self, n):
        self._maybe_fail("recv")
        out, self.output = self.output, b""
        return out

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return 0

    def close(self):
        self.closed = True


class Transport:
    """Opens ``good`` channels, then is gone: the next channel cannot be opened."""

    def __init__(self, good: int, channel=Channel) -> None:
        self.good, self.channel, self.active = good, channel, True

    def is_active(self):
        return self.active

    def open_session(self, timeout=None):
        if self.good <= 0:
            raise paramiko.SSHException("SSH session not active")
        self.good -= 1
        return self.channel()

    def close(self):
        self.active = False


def dropping(good: int, channel=Channel) -> type[SSHDriver]:
    """The real SSH driver, logged in over a transport that dies after ``good`` channels."""

    class Dropping(SSHDriver):
        def login(self, guesses):
            t = datetime.now(UTC)
            self.conn = Conn(None, self.dialer.src_ip, 40001, self.dialer.target_ip, 2222, t)
            self.dialer.opened.append(self.conn)
            self.transport = Transport(good, channel)
            return LoginResult(True, [AuthPhase(self.conn, t, t, 1, True)])

    return Dropping


def sane(records: list[dict]) -> None:
    """Every step and session record starts no later than it ends."""
    for r in records:
        if r["kind"] != "run":
            assert datetime.fromisoformat(r["start_ts"]) <= datetime.fromisoformat(r["end_ts"]), r


# ------------------------------------------------------------------ the driver


def bare_driver(channel_mode: str, transport) -> SSHDriver:
    class NoDial:
        src_ip, target_ip, opened = "198.18.0.9", "172.26.0.2", ()

    import random

    from mirage_lab.timing import make

    rng = random.Random(1)
    driver = SSHDriver(
        NoDial(), make("bot-fast", rng), Fingerprint(rng), "root", "pw", channel_mode
    )
    driver.transport = transport
    return driver


def test_a_step_on_a_dead_connection_has_a_start_and_says_nothing_was_sent():
    # The path that lost the sessions: the transport still looked alive, the channel would not
    # open. Nothing reached the decoy, so the result must not claim it did.
    result = bare_driver("exec", Transport(good=0)).run("uname -a")
    assert result.started is not None and result.ended is not None
    assert result.started <= result.ended
    assert result.sent is False and "SSHException" in result.error
    shell = bare_driver("shell", Transport(good=0)).run("uname -a")
    assert shell.started <= shell.ended and shell.sent is False and shell.error


def test_a_step_that_was_sent_before_the_connection_dropped_is_still_a_sent_step():
    # The exec request was accepted and the read broke: the decoy has the input, so the step
    # ran and the join should look for it.
    lost = type("Lost", (Channel,), {})
    driver = bare_driver("exec", Transport(good=1, channel=lambda: lost(fail_on="recv")))
    result = driver.run("uname -a")
    assert result.sent is True and result.sha256 == input_hash("uname -a")
    assert result.started <= result.ended and "SSHException" in result.error
    # ... but a request the server never accepted was not sent
    refused = bare_driver("exec", Transport(good=1, channel=lambda: lost(fail_on="exec_command")))
    assert refused.run("uname -a").sent is False
    # a shell line counts as sent once its newline has gone
    half = bare_driver("shell", Transport(good=1, channel=lambda: lost(fail_on="sendall")))
    half._read_to_prompt = lambda *a, **k: ("# ", True, True)
    assert half.run("uname -a").sent is False


def test_an_upload_that_could_not_open_its_channel_was_not_sent(monkeypatch):
    def refuse(transport):
        raise paramiko.SSHException("Channel closed.")

    monkeypatch.setattr(paramiko.SFTPClient, "from_transport", staticmethod(refuse))
    result = bare_driver("shell", Transport(good=0)).upload("/tmp/x", b"data")
    assert result.sent is False and result.started <= result.ended and result.error


# ------------------------------------------------------------------ the runner


def test_a_dropped_connection_still_ends_in_a_session_record(tmp_path):
    """The regression test for R1: the real driver's failure path, through the runner."""
    records, _actor, raised = drive(tmp_path, dropping(good=1))
    assert raised is None  # a dropped connection is an outcome, not a crash
    sane(records)
    got = steps_of(records)
    assert got["a"] == ("ran", "ok")
    assert got["b"][0] == "failed"  # tried, and nothing reached the decoy
    assert all(got[s] == ("skipped", "unchecked") for s in "cde")
    (session,) = [r for r in records if r["kind"] == "session"]
    assert session["connections"][0]["src"]["port"] == 40001
    assert session["error"].startswith("b: SSHException")
    # the join reads only "ran" as something to look for
    assert [r["step_id"] for r in records if r["kind"] == "step" and r["status"] == "ran"] == [
        "login-0",
        "a",
    ]


def test_a_healthy_session_record_has_no_error_key(tmp_path):
    # A join built before the field existed forbids unknown keys; a healthy record must be
    # exactly what it was.
    records, _actor, raised = drive(tmp_path, type("D", (Scripted,), {"answers": GOOD}))
    assert raised is None
    (session,) = [r for r in records if r["kind"] == "session"]
    assert "error" not in session


def test_a_result_without_a_start_cannot_break_the_record(tmp_path):
    # Whatever a driver returns, the step record is written with start <= end. This is the
    # shape the SSH driver used to return.
    class NoStart(Scripted):
        def run(self, line):
            late = datetime.now(UTC) - timedelta(seconds=5)
            return Result(
                sent=True, alive=False, conn=self.conn, sha256=input_hash(line), ended=late
            )

    records, _actor, raised = drive(tmp_path, NoStart)
    assert raised is None
    sane(records)
    assert steps_of(records)["a"][0] == "ran"
    assert len([r for r in records if r["kind"] == "session"]) == 1


def test_an_unexpected_exception_is_recorded_on_the_session_and_still_raised(tmp_path):
    class Broken(Scripted):
        def run(self, line):
            if len(self.sent) == 1:
                raise RuntimeError("driver bug")
            return super().run(line)

    records, _actor, raised = drive(tmp_path, type("B", (Broken,), {"answers": GOOD}))
    assert isinstance(raised, RuntimeError)  # the run reports it and exits non-zero
    sane(records)
    got = steps_of(records)
    assert got["a"] == ("ran", "ok")
    assert all(got[s] == ("skipped", "unchecked") for s in "bcde")  # every step has a record
    (session,) = [r for r in records if r["kind"] == "session"]
    assert session["error"] == "RuntimeError: driver bug"


def test_a_driver_s_own_value_error_is_not_mistaken_for_a_refused_input(tmp_path):
    # The guard that skips an input the lint refuses used to catch every ValueError, so a
    # driver that failed after sending looked like a step that was never sent.
    class Confused(Scripted):
        def run(self, line):
            raise ValueError("bad reply")

    records, _actor, raised = drive(tmp_path, Confused)
    assert isinstance(raised, ValueError)
    (session,) = [r for r in records if r["kind"] == "session"]
    assert "bad reply" in session["error"]


def test_a_login_that_cannot_connect_is_recorded_when_a_connection_exists(tmp_path):
    class HalfOpen(Scripted):
        def login(self, guesses):
            t = datetime.now(UTC)
            return LoginResult(False, [AuthPhase(self.conn, t, t, 1, False)], error="OSError: gone")

    records, _actor, raised = drive(tmp_path, HalfOpen)
    assert raised is None
    (session,) = [r for r in records if r["kind"] == "session"]
    assert session["error"] == "login: OSError: gone"
    assert all(steps_of(records)[s][0] == "skipped" for s in "abcde")


def test_ssh_login_survives_a_server_that_hangs_up_during_the_handshake(monkeypatch):
    # paramiko reports a close during key exchange as EOFError, which is not an OSError.
    import random

    from mirage_lab.drivers import ssh
    from mirage_lab.timing import make

    class Sock:
        closed = False

        def close(self):
            self.closed = True

    class Dial:
        src_ip, target_ip = "198.18.0.9", "172.26.0.2"

        def __init__(self):
            self.opened = []

        def connect(self, port):
            conn = Conn(Sock(), self.src_ip, 40001, self.target_ip, port, datetime.now(UTC))
            self.opened.append(conn)
            return conn

    class Hangup:
        def __init__(self, sock):
            pass

        def get_security_options(self):
            return type("O", (), {"kex": (), "ciphers": (), "digests": (), "key_types": ()})()

        def start_client(self, timeout=None):
            raise EOFError

        def close(self):
            pass

    monkeypatch.setattr(ssh.paramiko, "Transport", Hangup)
    rng = random.Random(1)
    dial = Dial()
    driver = SSHDriver(dial, make("bot-fast", rng), Fingerprint(rng), "root", "pw")
    result = driver.login(0)
    assert result.ok is False and result.error == "EOFError"
    assert dial.opened[0].closed is not None and dial.opened[0].sock.closed


@pytest.mark.parametrize("field", ["started", "ended"])
def test_step_times_fall_back_without_inverting(tmp_path, field):
    class Partial(Scripted):
        def run(self, line):
            r = super().run(line)
            setattr(r, field, None)
            return r

    records, _actor, raised = drive(tmp_path, type("P", (Partial,), {"answers": GOOD}))
    assert raised is None
    sane(records)
