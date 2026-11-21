"""The fleet group of the fingerprint suite (phase 3 spec 3.4): two deployments of one image.

Two real hosts installed from one image differ in what an installation gives each of them
(its name, its keys, its addresses, its accounts, its secrets) and agree in everything the
image fixes (the release, the kernel, the packages and their versions). A fleet of decoys
that shares a host key, or that differs in its kernel, is a fleet someone can enumerate.

The same commands are sent to two running decoys rendered from different seeds. Each is
either an *identity* command, whose answers must differ, or an *image* command, whose answers
must be the same. What the hardware fixes (`lscpu`, `nproc`) must be the same exactly when the
two deployments claim the same hardware class.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from eval.probes.default_tells import Result

# (check ID suffix, command, what it shows). Answers must differ between two deployments.
IDENTITY = (
    ("hostname", "hostname", "host name"),
    ("machine-id", "cat /etc/machine-id", "machine ID"),
    ("host-key", "cat /etc/ssh/ssh_host_ed25519_key.pub", "SSH host key"),
    ("address", "echo $SSH_CONNECTION | cut -d' ' -f3", "own address"),
    ("hosts-file", "cat /etc/hosts", "/etc/hosts"),
    ("root-password", "grep '^root:' /etc/shadow", "root's password hash"),
    ("accounts", "cut -d: -f1 /etc/passwd", "accounts"),
    ("boot-id", "cat /proc/sys/kernel/random/boot_id", "boot ID"),
    ("disk-ids", "blkid", "file-system IDs"),
    ("network-card", "cat /sys/class/net/*/address", "network card's address"),
    ("web-credential", "cat /var/www/html/.env", "the web application's credentials"),
)
# Answers must be the same on two deployments of one image.
IMAGE = (
    ("os-release", "cat /etc/os-release", "OS release"),
    ("debian-version", "cat /etc/debian_version", "Debian version"),
    ("kernel-release", "uname -r", "kernel release"),
    ("kernel-build", "uname -v", "kernel build"),
    ("ssh-version", "ssh -V", "OpenSSH version"),
    ("nginx-version", "nginx -v", "nginx version"),
    ("shells", "cat /etc/shells", "/etc/shells"),
    ("sshd-config", "cat /etc/ssh/sshd_config", "sshd's configuration"),
    ("system-account", "id www-data", "a system account's IDs"),
    ("programs", "ls /usr/bin", "the programs installed"),
    ("nginx-layout", "ls -R /etc/nginx", "nginx's configuration layout"),
)
# Answers must be the same exactly when the two claim one hardware class.
HARDWARE = (
    ("processors", "nproc", "processor count"),
    ("cpu", "lscpu", "CPU"),
)


def hardware_class(profile: Path) -> str | None:
    host = json.loads((profile / "host.json").read_text())
    return (host.get("hardware") or {}).get("class")


def compare(first: Any, second: Any, same_class: bool | None) -> list[tuple[str, Result]]:
    """(check ID suffix, result) for every fleet check. ``first`` and ``second`` are logged-in
    hosts with a ``run(command)`` that gives what it printed (``emulator.Exec``)."""
    out: list[tuple[str, Result]] = []

    def answers(command: str) -> tuple[Any, Any]:
        return first.run(command)[0], second.run(command)[0]

    def text(o: Any) -> str:
        return (o.stdout + o.stderr).strip()

    for suffix, command, what in IDENTITY:
        a, b = answers(command)
        if not text(a) or not text(b) or a.exit_code != 0 or b.exit_code != 0:
            problem = f"no answer to compare (exit {a.exit_code} and {b.exit_code})"
        elif text(a) == text(b):
            problem = f"both say {text(a).splitlines()[0][:60]!r}"
        else:
            problem = ""
        out.append(
            (
                f"differs-{suffix}",
                Result("ssh", f"two deployments differ in their {what}", _status(problem), problem),
            )
        )
    for suffix, command, what in IMAGE:
        a, b = answers(command)
        if not text(a) and not text(b):
            problem = "neither gave an answer"
        elif (text(a), a.exit_code) != (text(b), b.exit_code):
            problem = _first_difference(text(a), text(b))
        else:
            problem = ""
        out.append(
            (
                f"same-{suffix}",
                Result("ssh", f"two deployments agree on the {what}", _status(problem), problem),
            )
        )
    for suffix, command, what in HARDWARE:
        if same_class is None:
            continue
        a, b = answers(command)
        same = text(a) == text(b)
        wanted = "the same" if same_class else "different"
        problem = "" if same == same_class else f"one class: {same_class}; same answer: {same}"
        out.append(
            (
                f"hardware-{suffix}",
                Result(
                    "ssh",
                    f"{what}: {wanted}, as their hardware classes are",
                    _status(problem),
                    problem,
                ),
            )
        )
    return out


def _status(problem: str) -> str:
    return "fail" if problem else "pass"


def _first_difference(a: str, b: str) -> str:
    one, other = a.splitlines(), b.splitlines()
    for i in range(max(len(one), len(other))):
        x = one[i] if i < len(one) else "<no line>"
        y = other[i] if i < len(other) else "<no line>"
        if x != y:
            return f"line {i + 1}: {x[:50]!r} against {y[:50]!r}"
    return "they differ"
