"""The human recorder (spec decision Q8, gap register M6).

No terminal and no decoy here: the relay runs between a socket pair and a pseudo-terminal, and
the SSH transport is a stand-in. What is checked is what can go wrong without either: the
records a recording writes, the terminal being put back, and the refusals.
"""

from __future__ import annotations

import contextlib
import json
import os
import pty
import signal
import socket
import termios
from datetime import UTC, datetime

import paramiko
import pytest
from test_lab import CATALOGUE, ROOT

from mirage_lab import cli, record, safety
from mirage_lab.net import RANGES, Conn
from mirage_lab.runner import Settings
from mirage_lab.truth import TRUTH_NAME, TruthWriter
from mirage_schema.groundtruth import RunRecord, SessionTruth, parse_record


class Chan:
    """A shell channel over one end of a socket pair; the test holds the decoy's end."""

    def __init__(self) -> None:
        self.sock, self.decoy = socket.socketpair()
        self.sizes: list[tuple[int, int]] = []
        self.pty: dict | None = None
        self.shell = False

    def fileno(self) -> int:
        return self.sock.fileno()

    def recv(self, n: int) -> bytes:
        return self.sock.recv(n)

    def sendall(self, data: bytes) -> None:
        self.sock.sendall(data)

    def resize_pty(self, width: int, height: int) -> None:
        self.sizes.append((width, height))

    def get_pty(self, **kw) -> None:
        self.pty = kw

    def invoke_shell(self) -> None:
        self.shell = True


@pytest.fixture
def chan():
    c = Chan()
    yield c
    c.sock.close()
    c.decoy.close()


@pytest.fixture
def pipes():
    """(stdin read, stdin write, stdout read, stdout write)."""
    fds = (*os.pipe(), *os.pipe())
    yield fds
    for fd in fds:
        with contextlib.suppress(OSError):
            os.close(fd)


@pytest.fixture
def terminal():
    """A pseudo-terminal: (the side a keyboard would be on, the side the program holds)."""
    master, slave = pty.openpty()
    yield master, slave
    os.close(master)
    os.close(slave)


def never() -> None:
    return None


def modes(fd: int) -> list:
    """The terminal's settings, without the kernel's own "input is pending" state bit (macOS
    sets it when the modes change; it is not a mode)."""
    attrs = termios.tcgetattr(fd)
    attrs[3] &= ~getattr(termios, "PENDIN", 0)
    return attrs


# ------------------------------------------------------------------ the relay


def test_keys_go_to_the_decoy_until_the_local_input_ends(chan, pipes):
    stdin, keyboard, _screen, stdout = pipes
    os.write(keyboard, b"whoami\r")
    os.close(keyboard)
    record.relay(chan, stdin, stdout, never)
    chan.sock.close()
    assert chan.decoy.recv(100) == b"whoami\r" and chan.decoy.recv(100) == b""


def test_output_comes_back_until_the_shell_closes(chan, pipes):
    stdin, _keyboard, screen, stdout = pipes
    chan.decoy.sendall(b"root\r\n# ")
    chan.decoy.close()
    record.relay(chan, stdin, stdout, never)  # the keyboard is silent; the shell's close ends it
    assert os.read(screen, 100) == b"root\r\n# "


def test_the_escape_key_ends_the_recording_and_is_not_sent(chan, pipes):
    stdin, keyboard, _screen, stdout = pipes
    os.write(keyboard, b"ls" + record.ESCAPE + b"rm")
    record.relay(chan, stdin, stdout, never)
    chan.sock.close()
    assert chan.decoy.recv(100) == b"ls" and chan.decoy.recv(100) == b""


def test_a_window_size_change_is_passed_on(chan, pipes):
    stdin, keyboard, _screen, stdout = pipes
    sizes = [(120, 40)]
    os.write(keyboard, b"x")
    os.close(keyboard)
    record.relay(chan, stdin, stdout, lambda: sizes.pop() if sizes else None)
    assert chan.sizes == [(120, 40)]


def test_window_size_comes_from_the_terminal_or_a_default(terminal, pipes):
    _master, slave = terminal
    assert record.window(slave) == (80, 24)  # a new pseudo-terminal says 0 by 0
    termios.tcsetwinsize(slave, (40, 120))
    assert record.window(slave) == (120, 40)
    assert record.window(pipes[0]) == (80, 24)  # not a terminal at all


# ------------------------------------------------------------------ the terminal


def test_the_terminal_is_raw_during_the_relay_and_restored_after(terminal):
    _master, slave = terminal
    before = modes(slave)
    handler = signal.getsignal(signal.SIGWINCH)
    seen = {}

    class Peek(Chan):
        def recv(self, n):
            seen["lflag"] = termios.tcgetattr(slave)[3]
            return b""  # the shell closed

    peek = Peek()
    peek.decoy.close()
    record.interact(peek, slave, slave)
    peek.sock.close()
    assert before[3] & termios.ICANON and before[3] & termios.ECHO  # it started cooked
    assert not seen["lflag"] & (termios.ICANON | termios.ECHO | termios.ISIG)  # raw while relaying
    assert modes(slave) == before
    assert signal.getsignal(signal.SIGWINCH) == handler


def test_the_terminal_is_restored_when_the_relay_raises(terminal):
    _master, slave = terminal
    before = modes(slave)

    class Broken(Chan):
        def recv(self, n):
            raise RuntimeError("relay bug")

    broken = Broken()
    broken.decoy.close()
    with pytest.raises(RuntimeError):
        record.interact(broken, slave, slave)
    broken.sock.close()
    assert modes(slave) == before


def test_a_window_change_signal_reaches_the_decoy(terminal):
    _master, slave = terminal
    termios.tcsetwinsize(slave, (30, 100))

    class Resizing(Chan):
        polls = 0

        def recv(self, n):
            # the first read stands for a person resizing the window mid-session
            self.polls += 1
            if self.polls == 1:
                os.kill(os.getpid(), signal.SIGWINCH)
                return b"x"
            return b""

    c = Resizing()
    c.decoy.sendall(b"go")
    c.decoy.close()
    record.interact(c, slave, slave)
    c.sock.close()
    assert c.sizes == [(100, 30)]


# ------------------------------------------------------------------ the ground truth


def conn_at(ip: str = "198.18.0.77") -> Conn:
    return Conn(None, ip, 41234, "172.26.0.2", 2222, datetime.now(UTC))


def read(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_a_recording_is_written_as_a_real_human_session_and_a_closing_run(tmp_path):
    truth = TruthWriter(tmp_path / "gt")
    conn = conn_at()
    started = conn.opened
    conn.closed = ended = datetime.now(UTC)
    record.write_truth(truth, "r20261114120000-abc123", conn, started, ended, CATALOGUE, "abc1234")
    truth.close()
    session, run = read(tmp_path / "gt")
    assert isinstance(parse_record(session), SessionTruth)
    assert isinstance(parse_record(run), RunRecord)
    assert {k: session[k] for k in ("kind", "real", "actor_class", "timing_profile", "mode")} == {
        "kind": "session",
        "real": True,
        "actor_class": "human",
        "timing_profile": "recorded",
        "mode": "capture",
    }
    assert session["scenario_id"] == "recorded-human" and session["protocol"] == "ssh"
    assert session["session_ref"] == "r20261114120000-abc123/recorded-human/0/0"
    assert session["actor_ref"] == "r20261114120000-abc123/recorded-human/0"
    (c,) = session["connections"]
    assert (c["src"]["ip"], c["src"]["port"], c["dst"]["port"]) == ("198.18.0.77", 41234, 2222)
    assert c["closed_ts"] is not None and "error" not in session
    # the run record is what lets the join finalise it: one session, no steps
    assert (run["kind"], run["run_id"], run["mode"]) == ("run", session["run_id"], "capture")
    assert (run["sessions"], run["steps"], run["scenarios"]) == (1, 0, ["recorded-human"])
    assert run["catalogue_sha256"] == CATALOGUE.sha256 and run["code_version"] == "abc1234"
    assert truth.counts == {"session": 1, "run": 1}  # and nothing that claims to be a step


def test_a_recording_cut_short_says_so(tmp_path):
    truth = TruthWriter(tmp_path / "gt")
    conn = conn_at()
    now = datetime.now(UTC)
    record.write_truth(truth, "r1", conn, now, now, CATALOGUE, "dev", "EOFError")
    truth.close()
    assert read(tmp_path / "gt")[0]["error"] == "EOFError"


# ------------------------------------------------------------------ a whole recording


class Transport:
    def __init__(self, chan: Chan | None, auth: Exception | None = None) -> None:
        self.chan, self.auth, self.closed, self.login = chan, auth, False, None

    def auth_password(self, user, password):
        self.login = (user, password)
        if self.auth:
            raise self.auth

    def open_session(self, timeout=None):
        return self.chan

    def close(self):
        self.closed = True


def lab(tmp_path, monkeypatch, transport) -> tuple[Settings, list]:
    (tmp_path / "cowrie").mkdir()
    (tmp_path / "cowrie/userdb.txt").write_text("root:x:secret-pw\nphil:x:other-pw\n")
    dialled = []

    def open_transport(dialer, fingerprint):
        dialled.append(dialer)
        conn = Conn(None, dialer.src_ip, 40500, dialer.target_ip, 2222, datetime.now(UTC))
        return conn, transport

    monkeypatch.setattr(record, "open_transport", open_transport)
    settings = Settings("172.26.0.2", tmp_path / "out", tmp_path, code_version="abc1234")
    return settings, dialled


def test_a_recording_end_to_end(tmp_path, monkeypatch, chan, terminal):
    _master, slave = terminal
    termios.tcsetwinsize(slave, (50, 132))
    before = modes(slave)
    transport = Transport(chan)
    settings, dialled = lab(tmp_path, monkeypatch, transport)
    chan.decoy.sendall(b"Last login: never\r\n# ")
    chan.decoy.close()  # the person logs straight out

    summary = record.run(settings, CATALOGUE, "root", stdin=slave, stdout=slave)

    assert transport.login == ("root", "secret-pw")  # the profile's password, as the runner uses
    assert chan.shell and chan.pty["width"] == 132 and chan.pty["height"] == 50
    assert transport.closed and modes(slave) == before
    # a fresh address from the capture range, through the same relay as every lab session
    (dialer,) = dialled
    assert dialer.target_ip == "172.26.0.2" and dialer.src_ip == summary["src_ip"] == "198.18.0.1"
    assert __import__("ipaddress").ip_address(dialer.src_ip) in RANGES["capture"]
    assert (tmp_path / "out/addresses.capture").read_text() == "1"
    assert summary["sessions"] == 1 and summary["error"] is None
    (path,) = (tmp_path / "out").glob(TRUTH_NAME + "*")
    assert path.name == f"{TRUTH_NAME}.{summary['run_id']}"
    session, run = read(path)
    assert session["real"] is True and session["actor_class"] == "human"
    assert session["connections"][0]["src"]["ip"] == "198.18.0.1"
    truth = parse_record(session)
    assert truth.start_ts <= truth.connections[0].opened_ts <= truth.end_ts
    assert run["code_version"] == "abc1234"


def test_two_recordings_come_from_two_addresses(tmp_path, monkeypatch, terminal):
    _master, slave = terminal
    transport = Transport(None)
    settings, _dialled = lab(tmp_path, monkeypatch, transport)
    ips = []
    for _ in range(2):
        transport.chan = c = Chan()
        c.decoy.close()
        ips.append(record.run(settings, CATALOGUE, stdin=slave, stdout=slave)["src_ip"])
        c.sock.close()
    assert ips == ["198.18.0.1", "198.18.0.2"]
    assert len(list((tmp_path / "out").glob(TRUTH_NAME + "*"))) == 2  # one file per recording


def test_a_connection_that_drops_mid_session_is_still_recorded(tmp_path, monkeypatch, terminal):
    _master, slave = terminal

    class Dropping(Chan):
        def recv(self, n):
            raise paramiko.SSHException("Server connection dropped")

    c = Dropping()
    c.decoy.close()
    settings, _dialled = lab(tmp_path, monkeypatch, Transport(c))
    summary = record.run(settings, CATALOGUE, stdin=slave, stdout=slave)
    c.sock.close()
    assert summary["error"].startswith("SSHException")
    (path,) = (tmp_path / "out").glob(TRUTH_NAME + "*")
    session, run = read(path)
    assert session["error"].startswith("SSHException") and run["sessions"] == 1


def test_no_shell_means_no_human_session(tmp_path, monkeypatch, chan, terminal):
    # The login is the recorder's, not the person's. If it fails nobody typed anything, and a
    # record marked real and human would be a lie.
    _master, slave = terminal
    denied = Transport(chan, auth=paramiko.AuthenticationException("Authentication failed."))
    settings, _dialled = lab(tmp_path, monkeypatch, denied)
    with pytest.raises(record.RecordError, match="did not give a shell: AuthenticationException"):
        record.run(settings, CATALOGUE, stdin=slave, stdout=slave)
    assert denied.closed and list((tmp_path / "out").glob(TRUTH_NAME + "*")) == []


def test_a_recording_needs_a_terminal(tmp_path, monkeypatch, chan, pipes):
    settings, dialled = lab(tmp_path, monkeypatch, Transport(chan))
    with pytest.raises(record.RecordError, match="needs a terminal"):
        record.run(settings, CATALOGUE, stdin=pipes[0], stdout=pipes[3])
    # refused before anything was taken or opened
    assert dialled == [] and not (tmp_path / "out").exists()


def test_a_recording_as_a_user_the_profile_does_not_have_is_refused(
    tmp_path, monkeypatch, chan, terminal
):
    _master, slave = terminal
    settings, dialled = lab(tmp_path, monkeypatch, Transport(chan))
    with pytest.raises(ValueError, match="no password for 'nobody'"):
        record.run(settings, CATALOGUE, "nobody", stdin=slave, stdout=slave)
    assert dialled == [] and not (tmp_path / "out").exists()


# ------------------------------------------------------------------ the command


def main(*args: str) -> None:
    cli.main(["--catalogue", str(ROOT / "lab/catalogue"), *args])


def test_record_refuses_when_the_target_check_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(safety, "ROUTE4", tmp_path / "no-proc")
    monkeypatch.setattr(record, "run", lambda *a, **k: pytest.fail("the recorder started"))
    with pytest.raises(SystemExit, match="refusing to run: no /proc/net/route"):
        main("record")

    def outside(target):
        raise safety.SafetyError("target address 93.184.216.34 is outside the lab network")

    monkeypatch.setattr(safety, "require_lab", outside)
    with pytest.raises(SystemExit, match=r"refusing to run: target address .* is outside the lab"):
        main("record", "--user", "phil")


def test_record_passes_its_arguments_and_always_captures(tmp_path, monkeypatch, capsys):
    calls = []

    def fake(settings, catalogue, user):
        calls.append((settings, user))
        return {"run_id": "r1", "sessions": 1, "src_ip": "198.18.0.1", "error": None}

    monkeypatch.setattr(safety, "require_lab", lambda target: "172.26.0.2")
    monkeypatch.setattr(record, "run", fake)
    monkeypatch.setenv("LAB_OUT", str(tmp_path / "out"))
    monkeypatch.setenv("PROFILE_DIR", str(tmp_path / "profile"))
    main("record")
    main("record", "--user", "phil")
    assert [user for _s, user in calls] == ["root", "phil"]
    settings = calls[0][0]
    assert settings.target_ip == "172.26.0.2" and settings.mode == "capture"
    assert settings.out_dir == tmp_path / "out" and settings.profile_dir == tmp_path / "profile"
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["run_id"] == "r1"


@pytest.mark.parametrize(
    "args",
    [["record", "lab/scenarios/smoke"], ["record", "--mode", "explore"], ["record", "--user"]],
)
def test_record_takes_no_scenarios_and_no_mode(args, monkeypatch, capsys):
    monkeypatch.setattr(record, "run", lambda *a, **k: pytest.fail("the recorder started"))
    with pytest.raises(SystemExit) as exit_:
        main(*args)
    assert exit_.value.code == 2 and "usage:" in capsys.readouterr().err


def test_a_recording_that_could_not_start_exits_with_the_reason(monkeypatch):
    def fail(*a, **k):
        raise record.RecordError("a recording needs a terminal; run it from a shell, without -T")

    monkeypatch.setattr(safety, "require_lab", lambda target: "172.26.0.2")
    monkeypatch.setattr(record, "run", fail)
    with pytest.raises(SystemExit, match="not recorded: a recording needs a terminal"):
        main("record")
