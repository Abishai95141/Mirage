"""The human recorder (spec decision Q8): a person types a real SSH session into the decoy.

The human class has no real data, and a "human" timing profile is our own generator, which a
classifier would learn to recognise. So a recording goes the way every lab session goes
(through the lab edge, behind the same target check, from a fresh simulated address in the
capture range) and differs only in who is typing. Its ground truth says so: ``real``,
``actor_class: human``, ``timing_profile: recorded``. It has no steps, because nobody scripted
what the person did; the join labels the session, not its inputs. A run record closes it, so
the join finalises it like any run. Real recordings are for testing only.
"""

from __future__ import annotations

import contextlib
import os
import random
import re
import select
import signal
import termios
import time
import tty
from collections.abc import Callable
from datetime import datetime
from typing import Any

import paramiko

from mirage_lab.drivers.base import failure
from mirage_lab.drivers.ssh import Fingerprint, open_transport
from mirage_lab.models import Catalogue
from mirage_lab.net import AddressPool, Conn, Dialer
from mirage_lab.runner import (
    Settings,
    endpoint,
    new_run_id,
    now,
    root_password,
    scenarios_hash,
)
from mirage_lab.truth import TruthWriter, prune, run_file
from mirage_schema.groundtruth import Connection, RunRecord, SessionTruth

SCENARIO_ID = "recorded-human"
SCENARIO_NAME = r"[a-z0-9][a-z0-9-]{3,63}"  # as models.ID
ESCAPE = b"\x1d"  # Ctrl-]: ends the recording from this side when the decoy stops answering
POLL_S = 0.2  # how long a window-size change can wait to be noticed


class RecordError(RuntimeError):
    """The recording could not start. Nothing was recorded."""


def window(fd: int) -> tuple[int, int]:
    """(columns, rows) of the terminal on ``fd``; 80 by 24 where it does not say."""
    try:
        cols, rows = os.get_terminal_size(fd)
    except OSError:
        return 80, 24
    return cols or 80, rows or 24


def _write_all(fd: int, data: bytes) -> None:
    while data:
        data = data[os.write(fd, data) :]


def relay(
    chan: Any,
    stdin: int,
    stdout: int,
    resized: Callable[[], tuple[int, int] | None],
    stopped: Callable[[], bool] = lambda: False,
) -> None:
    """Bytes both ways, as they come, until the shell closes, the local input ends, the
    escape key is pressed or ``stopped`` says so. Keys go out in the chunks the terminal
    delivers them, so typing stays typing and a paste stays a paste: that is what the
    keystroke statistics measure. ``resized`` returns the new window size when it has changed
    since the last call."""
    while not stopped():
        ready, _, _ = select.select([chan, stdin], [], [], POLL_S)
        size = resized()
        if size is not None:
            chan.resize_pty(width=size[0], height=size[1])
        if chan in ready:
            data = chan.recv(65536)
            if not data:
                return
            _write_all(stdout, data)
        if stdin in ready:
            data = os.read(stdin, 1024)
            if not data:
                return
            keys, escaped, _ = data.partition(ESCAPE)
            if keys:
                chan.sendall(keys)
            if escaped:
                return


def interact(chan: Any, stdin: int, stdout: int, max_s: float | None = None) -> str | None:
    """Run the relay with the terminal in raw mode, and put the terminal back however the
    relay ends. A window-size change only sets a flag in the signal handler; the relay sends
    it. Sending from the handler could deadlock on the transport's own lock.

    A hangup or a request to stop ends the relay the same way, so a person who closes the
    window still leaves a session with its ground truth; so does ``max_s`` seconds passing.
    Returns "limit" or "hangup" when one of those ended it, else None.

    Both mode changes take effect at once (``TCSANOW``). The usual choice waits for pending
    output to drain, and a terminal that has stopped reading would then hold the recorder
    here for ever, before it has written the session's ground truth."""
    saved = termios.tcgetattr(stdin)
    changed = [False]
    ended: list[str | None] = [None]
    deadline = None if max_s is None else time.monotonic() + max_s

    def on_winch(*_: object) -> None:
        changed[0] = True

    def on_stop(*_: object) -> None:
        ended[0] = "hangup"

    def stopped() -> bool:
        if ended[0] is None and deadline is not None and time.monotonic() >= deadline:
            ended[0] = "limit"
        return ended[0] is not None

    def resized() -> tuple[int, int] | None:
        if not changed[0]:
            return None
        changed[0] = False
        return window(stdin)

    previous = {
        signal.SIGWINCH: signal.signal(signal.SIGWINCH, on_winch),
        signal.SIGHUP: signal.signal(signal.SIGHUP, on_stop),
        signal.SIGTERM: signal.signal(signal.SIGTERM, on_stop),
    }
    try:
        tty.setraw(stdin, termios.TCSANOW)
        relay(chan, stdin, stdout, resized, stopped)
    finally:
        # A terminal that has gone away (the window was closed) has no mode to put back.
        with contextlib.suppress(termios.error):
            termios.tcsetattr(stdin, termios.TCSANOW, saved)
        for number, handler in previous.items():
            signal.signal(number, handler)
    return ended[0]


def write_truth(
    truth: TruthWriter,
    run_id: str,
    conn: Conn,
    started: datetime,
    ended: datetime,
    catalogue: Catalogue,
    code_version: str,
    error: str | None = None,
    scenario_id: str = SCENARIO_ID,
) -> None:
    """The session, marked real and human, and the run record that closes it."""
    actor_ref = f"{run_id}/{scenario_id}/0"
    truth.write(
        SessionTruth(
            run_id=run_id,
            scenario_id=scenario_id,
            session_ref=f"{actor_ref}/0",
            protocol="ssh",
            actor_ref=actor_ref,
            actor_class="human",
            timing_profile="recorded",
            real=True,
            mode="capture",
            connections=[
                Connection(
                    src=endpoint(conn.src_ip, conn.src_port),
                    dst=endpoint(conn.dst_ip, conn.dst_port),
                    opened_ts=conn.opened,
                    closed_ts=conn.closed or ended,
                )
            ],
            start_ts=started,
            end_ts=ended,
            error=error,
        )
    )
    truth.write(
        RunRecord(
            run_id=run_id,
            mode="capture",
            started_ts=started,
            ended_ts=ended,
            seed=0,
            attack_version=catalogue.attack_version,
            catalogue_sha256=catalogue.sha256,
            scenarios_sha256=scenarios_hash([]),  # no scenario file produced this
            code_version=code_version,
            scenarios=[scenario_id],
            sessions=1,
            steps=0,
        )
    )


def run(
    settings: Settings,
    catalogue: Catalogue,
    user: str = "root",
    stdin: int = 0,
    stdout: int = 1,
    scenario_id: str = SCENARIO_ID,
    max_s: float | None = None,
) -> dict[str, Any]:
    """Record one session and return its summary. The caller has already made the target
    check; ``settings.target_ip`` is the lab edge. ``scenario_id`` names where the recording
    was made (the showcase's console uses its own), so the two kinds can be told apart.
    ``max_s`` ends the session from this side after that many seconds."""
    if not re.fullmatch(SCENARIO_NAME, scenario_id):
        raise RecordError(f"{scenario_id!r} is not a scenario ID")
    if not (os.isatty(stdin) and os.isatty(stdout)):
        raise RecordError("a recording needs a terminal; run it from a shell, without -T")
    password = root_password(settings.profile_dir, user)  # from the profile, as the runner does
    run_id = new_run_id()
    rng = random.Random(run_id)
    src_ip = AddressPool(settings.out_dir / "addresses.capture", "capture").take(1)[0]
    dialer = Dialer(settings.target_ip, src_ip, rng)
    started = now()
    try:
        # Its own banner and algorithm order, like any lab actor, so the sessioniser's
        # fingerprint link does not merge two recordings into one actor.
        conn, transport = open_transport(dialer, Fingerprint(rng))
    except (paramiko.SSHException, OSError, EOFError) as exc:
        raise RecordError(f"could not reach the decoy: {failure(exc)}") from exc
    shell, error = False, None
    try:
        transport.auth_password(user, password)
        cols, rows = window(stdin)
        chan = transport.open_session(timeout=15)
        chan.get_pty(term=os.environ.get("TERM") or "xterm-256color", width=cols, height=rows)
        chan.invoke_shell()
        shell = True
        _write_all(
            stdout, f"recording from {src_ip}; exit the shell or press Ctrl-] to end\r\n".encode()
        )
        if interact(chan, stdin, stdout, max_s) == "limit":
            with contextlib.suppress(OSError):
                _write_all(stdout, b"\r\nthe session's time limit was reached\r\n")
    except (paramiko.SSHException, OSError, EOFError) as exc:
        error = failure(exc)  # a connection that failed is an outcome, and is recorded as one
    except BaseException as exc:
        error = failure(exc)
        raise
    finally:
        with contextlib.suppress(Exception):
            transport.close()
        conn.closed = now()
        if shell:
            # From the moment a person could type, the session is always described: a session
            # without its record is one the join cannot match (gap register R1).
            prune(settings.out_dir, settings.truth_keep_days)
            truth = TruthWriter(run_file(settings.out_dir, run_id))
            write_truth(
                truth,
                run_id,
                conn,
                started,
                conn.closed,
                catalogue,
                settings.code_version,
                error,
                scenario_id,
            )
            truth.close()
    if not shell:
        # Nobody typed anything, so there is no human session to describe.
        raise RecordError(f"the decoy did not give a shell: {error}")
    return {"run_id": run_id, "sessions": 1, "src_ip": src_ip, "error": error}
