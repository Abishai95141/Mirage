"""Render-library probe (phase 3 spec 3.2a; Gate 3 test 3): does the running SSH decoy answer
the library's commands as the real hosts did?

    uv run python -m eval.probes.render_library [--ssh 127.0.0.1:2222] [--profile build/profile]

For every entry of the deployment's library (``<profile>/cowrie/rendered.json``) the command
is sent over an exec channel, as root, and what comes back (stdout, stderr and the exit
status) is held against the entry's record: by the fidelity check, and byte for byte. Then
the edges: an argument the library does not hold is not answered from it, an answer that is
root's alone is not given to another account, and the files under /proc that change by the
second are there, well formed and moving.

It needs nothing but the decoy: the policy service may be stopped (the integration test
stops it and runs this again).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

from eval.probes.default_tells import ROOT, Result
from eval.probes.net import Target
from mirage_profiles import fidelity


class Session:
    """One SSH login; each command runs on an exec channel of its own."""

    def __init__(self, target: Target | str, user: str, password: str) -> None:
        self.client = Target.parse(target).ssh(user, password)

    def run(self, command: str) -> tuple[fidelity.Observed, float]:
        started = time.monotonic()
        _stdin, out, err = self.client.exec_command(command, timeout=20)
        code = out.channel.recv_exit_status()
        took = time.monotonic() - started
        text = out.read().decode(errors="replace"), err.read().decode(errors="replace")
        return fidelity.Observed(text[0], text[1], code), took

    def close(self) -> None:
        self.client.close()


def accounts(profile: Path) -> tuple[str, tuple[str, str] | None]:
    """Root's password and one other account, from the profile's user database."""
    root, other = "", None
    for line in (profile / "cowrie/userdb.txt").read_text().splitlines():
        if line.startswith("#") or line.count(":") < 2:
            continue
        user, _, password = line.split(":", 2)
        if user == "root" and not root:
            root = password
        elif user != "root" and other is None:
            other = (user, password)
    return root, other


def check_entries(shell: Session, library: dict[str, Any]) -> list[Result]:
    results = []
    for entry in library["entries"]:
        argv = " ".join(entry["argv"])
        want = fidelity.Observed(entry["stdout"], entry["stderr"], entry["exit_code"])
        got, took = shell.run(argv)
        verdict = fidelity.check(got, want)
        results.append(
            Result(
                "ssh",
                f"`{argv}` has the record's exit code, streams and shape",
                "pass" if verdict.ok else "fail",
                "; ".join(verdict.problems),
            )
        )
        same = (got.stdout, got.stderr) == (want.stdout, want.stderr)
        results.append(
            Result(
                "ssh",
                f"`{argv}` prints the record",
                "pass" if same else "fail",
                "" if same else f"got {(got.stdout + got.stderr)[:120]!r}",
            )
        )
        # The prompt must not come back sooner than the real command's quickest run.
        quickest = min(entry["ms"]) / 1000.0
        results.append(
            Result(
                "ssh",
                f"`{argv}` takes no less time than on the real host",
                "pass" if took >= quickest else "fail",
                f"{took * 1000:.0f} ms; the record's quickest run is {quickest * 1000:.0f} ms",
            )
        )
    return results


def check_edges(
    target: Target | str, shell: Session, library: dict[str, Any], other: tuple[str, str] | None
) -> list[Result]:
    results = []

    def add(check: str, ok: bool, detail: str = "") -> None:
        results.append(Result("ssh", check, "pass" if ok else "fail", detail))

    by_argv = {" ".join(e["argv"]): e for e in library["entries"]}
    if "ss -tln" in by_argv:
        got, _ = shell.run("ss --no-such-option")
        add(
            "an argument the library does not hold is not answered from it",
            got.stdout != by_argv["ss -tln"]["stdout"],
            got.stdout[:80],
        )
        got, _ = shell.run("ss -tln | wc -l")
        lines = by_argv["ss -tln"]["stdout"].count("\n")
        add("a library answer goes down a pipe", got.stdout.strip() == str(lines), got.stdout[:40])
    if "nginx -v" in by_argv:
        got, _ = shell.run("nginx -v 2>/dev/null; echo status=$?")
        add("a library answer's stderr can be sent away", got.stdout == "status=0\n", got.stdout)
        got, _ = shell.run("PATH=/usr/bin nginx -v")
        add(
            "a program outside PATH is not found",
            "command not found" in got.stderr + got.stdout and got.exit_code == 127,
            (got.stderr + got.stdout)[:80],
        )
    rooted = [e for e in library["entries"] if e["who"] == "root"]
    if rooted and other is not None:
        entry = rooted[0]
        user = Session(target, *other)
        try:
            got, _ = user.run(" ".join([entry["program"], *entry["argv"][1:]]))
        finally:
            user.close()
        same = (got.stdout, got.stderr, got.exit_code) == (
            entry["stdout"],
            entry["stderr"],
            entry["exit_code"],
        )
        add(f"root's answer to `{' '.join(entry['argv'])}` is not given to {other[0]}", not same)
    return results


def check_proc(shell: Session, host: dict[str, Any]) -> list[Result]:
    results = []

    def add(check: str, ok: bool, detail: str = "") -> None:
        results.append(Result("ssh", check, "pass" if ok else "fail", detail))

    load, _ = shell.run("cat /proc/loadavg")
    add(
        "/proc/loadavg has its five fields",
        re.fullmatch(r"\d+\.\d\d \d+\.\d\d \d+\.\d\d \d+/\d+ \d+\n", load.stdout) is not None,
        load.stdout[:60],
    )
    said, _ = shell.run("uptime")
    loads = re.search(r"load average: ([\d.]+), ([\d.]+), ([\d.]+)", said.stdout)
    add(
        "/proc/loadavg agrees with uptime",
        loads is not None and load.stdout.split()[:3] == list(loads.groups()),
        f"{load.stdout[:14]!r} against {said.stdout.strip()[-40:]!r}",
    )
    first, _ = shell.run("cat /proc/stat")
    rows = {ln.split()[0]: ln.split()[1:] for ln in first.stdout.splitlines() if ln.split()}
    cores = [name for name in rows if re.fullmatch(r"cpu\d+", name)]
    cpus = (host.get("hardware") or {}).get("cpus")
    add(
        "/proc/stat has a line for each of the class's processors",
        bool(cores) and (cpus is None or len(cores) == cpus) and "cpu" in rows,
        f"{len(cores)} processor lines, the class has {cpus}",
    )
    up, _ = shell.run("cat /proc/uptime")
    seconds = float(up.stdout.split()[0]) if up.stdout.split() else -1.0
    boot = int(rows["btime"][0]) if rows.get("btime") else 0
    add(
        "/proc/stat's boot time agrees with /proc/uptime",
        boot > 0 and abs(boot + seconds - time.time()) < 30,
        f"btime {boot}, up {seconds:.0f} s",
    )
    if cores:
        ticks = sum(int(v) for v in rows[cores[0]])
        add(
            "/proc/stat's processor time agrees with the uptime",
            seconds > 0 and abs(ticks / 100.0 - seconds) < max(30.0, 0.02 * seconds),
            f"{ticks / 100.0:.0f} s of processor time, up {seconds:.0f} s",
        )
    time.sleep(1.5)
    second, _ = shell.run("cat /proc/stat")
    add(
        "/proc/stat moves between two reads",
        bool(first.stdout) and first.stdout != second.stdout,
    )
    return results


def run(target: Target | str, profile: Path) -> list[Result]:
    library = json.loads((profile / "cowrie/rendered.json").read_text())
    host = json.loads((profile / "host.json").read_text())
    password, other = accounts(profile)
    shell = Session(target, "root", password)
    try:
        results = check_entries(shell, library)
        results += check_edges(target, shell, library, other)
        if library.get("proc"):
            results += check_proc(shell, host)
    finally:
        shell.close()
    return results


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m eval.probes.render_library")
    ap.add_argument("--ssh", default="127.0.0.1:2222")
    ap.add_argument("--profile", type=Path, default=ROOT / "build/profile")
    args = ap.parse_args(argv)
    results = run(args.ssh, args.profile)
    for r in results:
        print(f"{r.status:5} {r.check}" + (f"  ({r.detail})" if r.detail else ""))
    failed = sum(r.status == "fail" for r in results)
    print(f"{len(results) - failed} pass, {failed} fail")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
