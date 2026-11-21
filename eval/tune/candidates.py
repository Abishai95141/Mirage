"""Candidate commands for the tuning set: what to ask the real host.

Nothing here is an answer. A candidate is a command line and where it came from; the
labeller (label.py) runs each on a throwaway reference host and keeps what was printed.

Where candidates come from:

``seed``     written by hand (seeds.yaml): invocations a person looking around a server
             runs, of programs the decoy has no emulation for.
``version``  ``PROGRAM --version``, for every such program that has one.
``help``     ``PROGRAM --help``, where the text is short enough to be an answer.
``option``   each option a program's own help lists, alone and with a small file, so that
             the set covers the program's formats and its errors, not one invocation of it.
``misuse``   an option the program does not have: every program says so in its own words.

A program is left out when the decoy emulates it (the model is never asked), when the
responder never generates for it (interactive programs, network clients), or when running
it would change the host it runs on (``UNSAFE``): the labelling host is thrown away, but an
answer recorded after `shred /etc/hostname` would be an answer about a broken host.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

SEEDS = Path(__file__).with_name("seeds.yaml")
# Small text files every Debian 12 has, shown whole in a request's file view (1,024 bytes).
FIXTURES = ("/etc/hostname", "/etc/shells", "/etc/issue")
MAX_HELP_CHARS = 1600
MAX_OPTIONS = 12  # of one program's options tried
# Programs whose point is to change the machine, take a terminal, or reach another host.
UNSAFE = frozenset(
    """
    halt poweroff reboot shutdown init telinit runlevel kill killall killall5 pkill skill snice
    mkfs mke2fs mkswap mkfs.ext2 mkfs.ext3 mkfs.ext4 mkfs.minix mkfs.bfs mkfs.cramfs
    fdisk sfdisk cfdisk parted wipefs blkdiscard badblocks fsck e2fsck fsck.ext2 fsck.ext3
    fsck.ext4 fsck.minix fsck.cramfs resize2fs tune2fs debugfs dd shred rm rmdir mv cp
    ln link unlink mknod mkfifo mkdir install truncate touch chmod chown chgrp chattr
    mount umount swapon swapoff losetup pivot_root switch_root chroot unshare nsenter
    su sudo login newgrp sg runuser passwd chpasswd chgpasswd gpasswd chfn chsh vipw vigr
    useradd userdel usermod groupadd groupdel groupmod adduser deluser addgroup delgroup
    newusers pwconv pwunconv grpconv grpunconv
    apt apt-get apt-key dpkg dpkg-reconfigure dpkg-divert dpkg-statoverride dpkg-trigger
    update-alternatives update-rc.d invoke-rc.d service start-stop-daemon systemctl
    deb-systemd-helper deb-systemd-invoke debconf-set-selections
    sysctl hwclock date hostname domainname dnsdomainname ip tc bridge
    nginx sshd mariadbd mysqld mariadbd-safe mysqld_safe redis-server redis-sentinel
    mariadb mysql redis-cli ssh scp sftp ssh-keygen ssh-add ssh-agent ssh-keyscan
    vi vim nano ed ex view more less pager top watch script scriptreplay agetty getty
    bash sh dash rbash perl gawk awk sed xargs find env nohup nice ionice chrt taskset
    timeout setsid flock sulogin wall write mesg
    """.split()  # noqa: SIM905 - a list of names reads better as words than as literals
)


@dataclass(frozen=True)
class Candidate:
    cmd: str
    program: str
    source: str  # seed | version | help | option | misuse


_OPTION = re.compile(r"^\s{1,8}(-[A-Za-z0-9])(?:[ ,]|$)(?:\s*(--[a-z][a-z0-9-]+))?(=?\[?[A-Z<])?")


def options_of(help_text: str) -> list[str]:
    """The short options a help text lists that take no argument, in its order."""
    out: list[str] = []
    for line in help_text.splitlines():
        match = _OPTION.match(line)
        if match is None or match[3]:
            continue
        rest = line[match.end() :].lstrip()
        if re.match(r"[A-Z]{2,}|<", rest):  # "-n NUM", "-f <file>": it wants a value
            continue
        if match[1] not in out and match[1] not in ("-h", "-V"):
            out.append(match[1])
    return out


def load_seeds(path: Path = SEEDS) -> list[Candidate]:
    doc = yaml.safe_load(path.read_text())
    out = []
    for cmd in doc["commands"]:
        program = cmd.split()[0].rsplit("/", 1)[-1]
        out.append(Candidate(cmd, program, "seed"))
    return out


def build(
    programs: list[str],
    helps: dict[str, tuple[int, str]],
    versions: dict[str, tuple[int, str]],
    emulated: set[str],
    refused: set[str],
    seeds: list[Candidate],
) -> list[Candidate]:
    """Every candidate, seeds first. ``helps`` and ``versions`` map a program to the exit
    status and text of ``--help`` and ``--version`` on the reference host."""
    out: list[Candidate] = []
    seen: set[str] = set()

    def add(cmd: str, program: str, source: str) -> None:
        if cmd not in seen:
            seen.add(cmd)
            out.append(Candidate(cmd, program, source))

    for seed in seeds:
        if seed.program not in emulated:
            add(seed.cmd, seed.program, "seed")
    for program in programs:
        if program in emulated or program in refused or program in UNSAFE:
            continue
        code, text = versions.get(program, (1, ""))
        if code == 0 and text.strip():
            add(f"{program} --version", program, "version")
        code, text = helps.get(program, (1, ""))
        if code != 0 or not text.strip():
            continue
        if len(text) <= MAX_HELP_CHARS:
            add(f"{program} --help", program, "help")
        add(f"{program} --frobnicate", program, "misuse")
        add(program, program, "option")
        add(f"{program} {FIXTURES[0]}", program, "option")
        for option in options_of(text)[:MAX_OPTIONS]:
            add(f"{program} {option}", program, "option")
            for fixture in FIXTURES[:2]:
                add(f"{program} {option} {fixture}", program, "option")
    return out


def _read(directory: Path, program: str, flag: str) -> tuple[int, str]:
    stem = directory / f"{program}.{flag}"
    try:
        code = int(stem.with_name(stem.name + ".code").read_text().strip())
    except (OSError, ValueError):
        return 1, ""
    text = stem.read_text(errors="replace") if stem.exists() else ""
    return code, text


def refused_verbs() -> set[str]:
    """The programs the responder never generates for (its class table)."""
    table = Path(__file__).resolve().parents[2] / "responder/src/mirage_responder/classes.yaml"
    doc = yaml.safe_load(table.read_text())
    return {
        verb
        for verb, entry in doc["commands"].items()
        if entry.get("class") in ("interactive", "network")
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(prog="python -m eval.tune.candidates")
    ap.add_argument("--help-dir", type=Path, required=True, help="what --help and --version print")
    ap.add_argument("--emulated", type=Path, required=True, help="the decoy's command names")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    programs = [n for n in (args.help_dir / "names.txt").read_text().split() if n]
    emulated = set(args.emulated.read_text().split())
    built = build(
        programs,
        {p: _read(args.help_dir, p, "help") for p in programs},
        {p: _read(args.help_dir, p, "version") for p in programs},
        emulated,
        refused_verbs(),
        load_seeds(),
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        "".join(
            json.dumps({"cmd": c.cmd, "program": c.program, "source": c.source}) + "\n"
            for c in built
        )
    )
    by_source: dict[str, int] = {}
    for c in built:
        by_source[c.source] = by_source.get(c.source, 0) + 1
    print(f"{len(built)} candidates of {len({c.program for c in built})} programs: {by_source}")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
