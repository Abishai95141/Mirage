"""The consistency group of the fingerprint suite (phase 3 spec 3.4, "responder consistency").

A host may be wrong about a detail and pass; a host that contradicts itself is caught by
anyone who asks twice. This group holds the decoy to itself, whoever gives the answer (the
emulator, the render library, the cache or the model), on the commands only the last rung can
answer:

- **Asked again, the same.** A command whose answer cannot change is sent twice in one login
  and once more in a second login. All three answers must be the same.
- **Told and seen agree.** A command that changes a file says whether it worked (its exit
  status); the emulator's own commands then look. A file reported made must be there with
  what was put in it, a file reported removed must be gone, and a command that failed must
  have changed nothing.

It needs no reference host. With the responder on recorded answers and no recording for
these commands, the emulator answers them all ("cannot execute binary file", nothing
changed) and every check passes without having tested the model: run it with the live
backend (`make llm-up`, then `make probe PROBE_ARGS="--groups consistency"`) for the result
to say anything about the model's rung.

Spike S2's three wrong answers, which the spec lists with this group, are fixed checks of
the emulator group (`s2-*` in commands.yaml): the emulator answers all three now.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from eval.probes.default_tells import Result

# Commands with one right answer for the life of a deployment, which the decoy's emulator has
# no command class for. (id, command line)
REPEATS = (
    ("package-record", "dpkg -s openssh-server"),
    ("package-policy", "apt-cache policy nginx"),
    ("password-ageing", "chage -l root"),
    ("last-login", "lastlog -u root"),
    ("client-version", "redis-cli --version"),
    ("octal-dump", "od -c /etc/hostname"),
    ("checksum", "cksum /etc/hostname"),
    ("path-walk", "namei -l /etc/ssh/sshd_config"),
    ("factors", "factor 360"),
    ("libraries", "ldd /bin/ls"),
)


@dataclass(frozen=True)
class Trip:
    """A command that changes a file, and how the emulator's own commands see the result.

    ``look`` prints one line; ``done`` is what that line is when the change was made and
    ``undone`` what it is when nothing changed. Everything stays under /tmp and ``clean``
    removes it."""

    id: str
    before: str
    change: str
    look: str
    done: str
    undone: str
    clean: str


TRIPS = (
    Trip(
        "make-directory",
        "",
        "install -d -m 750 /tmp/pc-d",
        "ls -ld /tmp/pc-d 2>/dev/null | cut -c1-10 | grep . || echo absent",
        "drwxr-x---",
        "absent",
        "rmdir /tmp/pc-d",
    ),
    Trip(
        "install-file",
        "",
        "install -m 600 /etc/hostname /tmp/pc-i",
        "cmp -s /etc/hostname /tmp/pc-i 2>/dev/null; cat /tmp/pc-i 2>/dev/null | wc -c",
        "",  # compared with the size of /etc/hostname, below
        "0",
        "rm -f /tmp/pc-i",
    ),
    Trip(
        "truncate",
        "",
        "truncate -s 10 /tmp/pc-t",
        "cat /tmp/pc-t 2>/dev/null | wc -c",
        "10",
        "0",
        "rm -f /tmp/pc-t",
    ),
    Trip(
        "unlink",
        "echo x > /tmp/pc-u",
        "unlink /tmp/pc-u",
        "ls /tmp/pc-u >/dev/null 2>&1 && echo there || echo absent",
        "absent",
        "there",
        "rm -f /tmp/pc-u",
    ),
    Trip(
        "hard-link",
        "echo linked > /tmp/pc-l",
        "link /tmp/pc-l /tmp/pc-m",
        "cat /tmp/pc-m 2>/dev/null | grep . || echo absent",
        "linked",
        "absent",
        "rm -f /tmp/pc-l /tmp/pc-m",
    ),
    Trip(
        "shred",
        "echo x > /tmp/pc-s",
        "shred -u /tmp/pc-s",
        "ls /tmp/pc-s >/dev/null 2>&1 && echo there || echo absent",
        "absent",
        "there",
        "rm -f /tmp/pc-s",
    ),
)
MARK = "pc-status="


class Login(Protocol):
    def run(self, command: str) -> tuple[Any, float]: ...


def _said(observed: Any) -> tuple[str, str, int]:
    return (observed.stdout, observed.stderr, observed.exit_code)


def _short(observed: Any) -> str:
    text = (observed.stdout or observed.stderr).strip().splitlines()
    return repr(text[0][:70]) if text else f"nothing, exit {observed.exit_code}"


def check_repeats(first: Login, second: Login) -> list[tuple[str, Result]]:
    out = []
    for name, command in REPEATS:
        one, _ = first.run(command)
        two, _ = first.run(command)
        other, _ = second.run(command)
        same = _said(one) == _said(two)
        out.append(
            (
                f"twice-{name}",
                Result(
                    "ssh",
                    f"`{command}` asked twice in one login answers the same",
                    "pass" if same else "fail",
                    "" if same else f"first {_short(one)}, then {_short(two)}",
                ),
            )
        )
        same = _said(one) == _said(other)
        out.append(
            (
                f"again-{name}",
                Result(
                    "ssh",
                    f"`{command}` answers a second login as it answered the first",
                    "pass" if same else "fail",
                    "" if same else f"first login {_short(one)}, second {_short(other)}",
                ),
            )
        )
    return out


def trip_line(trip: Trip) -> str:
    """One command line: set up, change, say the status, look, clean up."""
    before = f"{trip.before}; " if trip.before else ""
    return f"{before}{trip.change}; echo {MARK}$?; {trip.look}; {trip.clean} 2>/dev/null"


def judge_trip(trip: Trip, stdout: str, done: str) -> tuple[bool, str]:
    """Whether what the command reported agrees with what was then seen."""
    lines = stdout.splitlines()
    at = next((i for i, line in enumerate(lines) if line.startswith(MARK)), None)
    if at is None:
        return False, "the line never reported the command's status"
    status = lines[at][len(MARK) :].strip()
    seen = lines[at + 1].strip() if len(lines) > at + 1 else ""
    if status == "0":
        return seen == done, "" if seen == done else f"reported done, then seen {seen!r}"
    return (
        seen == trip.undone,
        "" if seen == trip.undone else f"reported failed ({status}), then seen {seen!r}",
    )


def check_trips(login: Login) -> list[tuple[str, Result]]:
    size, _ = login.run("cat /etc/hostname | wc -c")
    out = []
    for trip in TRIPS:
        done = trip.done or size.stdout.strip()
        observed, _ = login.run(trip_line(trip))
        ok, why = judge_trip(trip, observed.stdout, done)
        out.append(
            (
                f"trip-{trip.id}",
                Result(
                    "ssh",
                    f"after `{trip.change}`, what is seen agrees with what it reported",
                    "pass" if ok else "fail",
                    why,
                ),
            )
        )
    return out


def check_kept(login: Login) -> list[tuple[str, Result]]:
    """What one command of a login changed, the next command of that login sees."""
    made, _ = login.run(f"install -d /tmp/pc-keep; echo {MARK}$?")
    seen, _ = login.run("ls -d /tmp/pc-keep >/dev/null 2>&1 && echo there || echo absent")
    login.run("rmdir /tmp/pc-keep 2>/dev/null")
    reported = MARK + "0" in made.stdout
    there = seen.stdout.strip() == "there"
    return [
        (
            "kept-for-the-login",
            Result(
                "ssh",
                "a directory one command reported making is there for the login's next command",
                "pass" if reported == there else "fail",
                ""
                if reported == there
                else f"reported {'made' if reported else 'failed'}, then seen "
                f"{seen.stdout.strip()!r}",
            ),
        )
    ]


def run(first: Login, second: Login) -> list[tuple[str, Result]]:
    return check_repeats(first, second) + check_trips(first) + check_kept(first)
