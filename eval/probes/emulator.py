"""Two groups of the fingerprint suite (phase 3 spec 3.4) that need a real host beside the
decoy: emulator fidelity and response time.

Both send the fixed list in ``commands.yaml`` over exec channels, as root, to the decoy and to
the reference host, from one place and in one run.

- **Fidelity.** The decoy's answer is held against the reference's by the fidelity check
  (``mirage_profiles.fidelity``): exit code, streams, shape, and the facts the two are known
  to differ in. That check is deliberately loose, so a command may ask for more: patterns
  the two answers must agree on (a glob that is not expanded still gives one line), or
  ``exact``, where the two must be the same line for line once numbers, dates and addresses
  are masked. The reference host carries the same profile as the decoy (its host name, its
  accounts), so most answers about identity, the shell and small files are the same on both.
- **Response time.** The same request is timed on both, alternately, and the medians are
  compared. Both paths cross one proxy on the lab network, so that cost is on both sides.
"""

from __future__ import annotations

import re
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from eval.probes.default_tells import Result
from eval.probes.net import Target
from mirage_profiles import fidelity

COMMANDS = Path(__file__).with_name("commands.yaml")
DEADLINE_S = 20.0
# Response time (spec 3.4): the decoy's median is within a factor of two of the reference's,
# or within 30 ms of it. Defaults, revised from measurements.
FACTOR, SLACK_MS = 2.0, 30.0
NO_STATUS = -1  # the channel ended, or the deadline passed, with no exit status


@dataclass(frozen=True)
class Command:
    id: str
    cmd: str
    same: tuple[str, ...] = ()
    time: str | None = None
    exact: bool = False


def load_commands(path: Path = COMMANDS) -> list[Command]:
    doc = yaml.safe_load(path.read_text())
    out, seen = [], set()
    for item in doc["commands"]:
        unknown = set(item) - {"id", "cmd", "same", "time", "exact"}
        if unknown:
            raise ValueError(f"{path.name}: {item.get('id')}: unknown keys {sorted(unknown)}")
        if item["id"] in seen:
            raise ValueError(f"{path.name}: {item['id']} is listed twice")
        seen.add(item["id"])
        for pattern in item.get("same", ()):
            re.compile(pattern)
        out.append(
            Command(
                item["id"],
                item["cmd"],
                tuple(item.get("same", ())),
                item.get("time"),
                bool(item.get("exact", False)),
            )
        )
    return out


class Exec:
    """One SSH login. Each command is an exec request on a channel of its own."""

    def __init__(self, target: Target | str, user: str, password: str) -> None:
        self.client = Target.parse(target).ssh(user, password)

    def run(self, command: str, deadline: float = DEADLINE_S) -> tuple[fidelity.Observed, float]:
        """What the command printed and returned, and the seconds from the request to its
        exit status. A channel that fails or never reports a status is an answer too, and one
        no real server gives: it comes back with ``NO_STATUS``."""
        import paramiko

        started = time.monotonic()
        out, err = b"", b""
        try:
            chan = self.client.get_transport().open_session(timeout=deadline)
            chan.settimeout(0.05)
            chan.exec_command(command)
            while time.monotonic() - started < deadline:
                moved = False
                if chan.recv_ready():
                    out, moved = out + chan.recv(65536), True
                if chan.recv_stderr_ready():
                    err, moved = err + chan.recv_stderr(65536), True
                if chan.exit_status_ready() and not moved:
                    break
                if not moved:
                    time.sleep(0.001)
            took = time.monotonic() - started
            code = chan.recv_exit_status() if chan.exit_status_ready() else NO_STATUS
            while chan.recv_ready():
                out += chan.recv(65536)
            while chan.recv_stderr_ready():
                err += chan.recv_stderr(65536)
            chan.close()
        except (paramiko.SSHException, OSError, EOFError) as exc:
            return fidelity.Observed(
                out.decode(errors="replace"), f"<channel: {exc}>", NO_STATUS
            ), (time.monotonic() - started)
        return fidelity.Observed(
            out.decode(errors="replace"), err.decode(errors="replace"), code
        ), took

    def close(self) -> None:
        self.client.close()


def facts(decoy: Exec, reference: Exec) -> list[fidelity.Fact]:
    """What the two hosts are known to differ in, asked of each."""
    out = []
    for name, command in (("hostname", "hostname"),):
        ref, dec = reference.run(command)[0].stdout.strip(), decoy.run(command)[0].stdout.strip()
        if ref and dec:
            out.append(fidelity.Fact(name, ref, dec))
    return out


def disagreements(command: Command, got: fidelity.Observed, want: fidelity.Observed) -> list[str]:
    """The command's ``same`` patterns that one host's answer matches and the other's does not."""
    out = []
    for pattern in command.same:
        mine = re.search(pattern, got.stdout + "\n" + got.stderr) is not None
        theirs = re.search(pattern, want.stdout + "\n" + want.stderr) is not None
        if mine != theirs:
            out.append(
                f"/{pattern}/ {'matches' if theirs else 'does not match'} the reference's answer "
                f"and {'matches' if mine else 'does not match'} the decoy's"
            )
    return out


def first_difference(command: Command, got: fidelity.Observed, want: fidelity.Observed) -> str:
    """For a command marked ``exact``: where the decoy's answer, after masking what varies
    between hosts and moments, stops being the reference's. Empty when it never does."""
    if not command.exact:
        return ""
    for stream in ("stdout", "stderr"):
        mine = fidelity.mask(getattr(got, stream)).splitlines()
        theirs = fidelity.mask(getattr(want, stream)).splitlines()
        for i in range(max(len(mine), len(theirs))):
            a = mine[i] if i < len(mine) else "<no line>"
            b = theirs[i] if i < len(theirs) else "<no line>"
            if a != b:
                return f"{stream} line {i + 1} is {a[:60]!r}, the reference's is {b[:60]!r}"
    return ""


def judge(command: Command, got: fidelity.Observed, want: fidelity.Observed, known) -> Result:
    if want.exit_code == NO_STATUS:
        # The reference host did not answer: nothing can be said about the decoy from it.
        return Result("ssh", f"`{command.cmd}`", "fail", f"the reference host: {want.stderr[:80]}")
    problems = list(fidelity.check(got, want, known).problems)
    if got.exit_code == NO_STATUS:
        problems = [f"no exit status ({got.stderr[:60].strip()})"]
    problems += disagreements(command, got, want)
    different = first_difference(command, got, want)
    if different:
        problems.append(different)
    detail = "; ".join(problems)
    if problems:
        shown = (got.stdout or got.stderr).strip().splitlines()
        detail += f" | decoy: {shown[0][:70]!r}" if shown else " | decoy: nothing"
    return Result("ssh", f"`{command.cmd}`", "fail" if problems else "pass", detail)


def check_fidelity(
    decoy: Exec, reference: Exec, commands: list[Command]
) -> tuple[list[tuple[str, Result]], list[dict[str, Any]]]:
    """(check ID suffix, result) for each command, and what each host answered, for the
    report. The answers are ordinary administrative output from a throwaway host."""
    known = facts(decoy, reference)
    results, seen = [], []
    for command in commands:
        want, _ = reference.run(command.cmd)
        got, _ = decoy.run(command.cmd)
        results.append((command.id, judge(command, got, want, known)))
        seen.append(
            {
                "id": command.id,
                "reference": {"exit": want.exit_code, "streams": want.streams()},
                "decoy": {"exit": got.exit_code, "streams": got.streams()},
            }
        )
    return results, seen


@dataclass
class Timing:
    id: str
    cls: str
    decoy_ms: list[float] = field(default_factory=list)
    reference_ms: list[float] = field(default_factory=list)

    @property
    def medians(self) -> tuple[float, float]:
        return statistics.median(self.decoy_ms), statistics.median(self.reference_ms)


def within(decoy_ms: float, reference_ms: float) -> bool:
    """The response-time rule: within a factor of two either way, or within 30 ms."""
    if abs(decoy_ms - reference_ms) <= SLACK_MS:
        return True
    return reference_ms / FACTOR <= decoy_ms <= reference_ms * FACTOR


def check_timing(
    decoy: Exec, reference: Exec, commands: list[Command], samples: int = 30
) -> tuple[list[tuple[str, Result]], list[Timing]]:
    timed = [c for c in commands if c.time]
    timings = [Timing(c.id, c.time or "") for c in timed]
    for command in timed:  # one unrecorded run each: the first use of a path is slower
        decoy.run(command.cmd)
        reference.run(command.cmd)
    for _ in range(samples):
        for command, timing in zip(timed, timings, strict=True):
            timing.reference_ms.append(reference.run(command.cmd)[1] * 1000)
            timing.decoy_ms.append(decoy.run(command.cmd)[1] * 1000)
    results = []
    for command, timing in zip(timed, timings, strict=True):
        mine, theirs = timing.medians
        results.append(
            (
                command.id,
                Result(
                    "ssh",
                    f"`{command.cmd}` ({timing.cls}) takes about as long as on the real host",
                    "pass" if within(mine, theirs) else "fail",
                    f"decoy {mine:.1f} ms, reference {theirs:.1f} ms, medians of {samples}",
                ),
            )
        )
    return results, timings
