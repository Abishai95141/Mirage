"""Label the candidates: run each on a real Debian 12 host and keep what it printed.

    uv run python -m eval.tune.label --candidates build/tune/candidates.jsonl \\
        --out build/tune/labels.jsonl

The host is a throwaway container of the reference image with no network (the lab host;
needs `make reference-image`). Each command runs three times as root in /root, with the
environment a session over SSH has and nothing on standard input. A label is kept with
everything needed to judge it later (build.py decides): whether the three runs agreed,
whether it ran out of time, and whether it left the host as it found it. A command that
changed a watched file or left something behind is marked, and the host is replaced before
the next one: an answer recorded on a host a command has broken is not an answer.

With each label goes the file view the decoy would send with the same command (the fork's
``mirage_state.view``): what is at the paths the command names, the directories holding
them and the working directory. It is read from the labelling host itself, which is the
image the decoy's own file system was built from.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import posixpath
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

IMAGE = "mirage/reference:debian-12"
NAME = "mirage-tune-label"
HOSTNAME = "tunehost"  # replaced by each row's own host name when the set is built
CWD = "/root"
ENV = {
    "HOME": "/root",
    "USER": "root",
    "LOGNAME": "root",
    "SHELL": "/bin/bash",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
}
RUNS = 3
DEADLINE_S = 5
MAX_BYTES = 16 * 1024
HEAD_BYTES, MAX_CHILDREN, MAX_FILE = 1024, 200, 64 * 1024  # the fork's own limits
WATCHED = "/etc/hostname /etc/shells /etc/issue /etc/passwd /etc/group /etc/hosts"
# One line that changes if a command left a mark: the watched files, and what is in the
# directories a command is most likely to write to.
STATE = (
    f"cat {WATCHED} 2>&1 | sha256sum; ls -A /tmp /root /var/tmp 2>&1 | sha256sum; ls /ready 2>&1"
)
VIEW = r"""
facts() { stat -c '%a|%u|%g|%s' "$1"; }
for p in "$@"; do
  if [ -L "$p" ]; then
    printf 'L|%s|%s\n' "$(facts "$p")" "$(readlink "$p")"
  elif [ -d "$p" ]; then
    printf 'D|%s|' "$(facts "$p")"
    ls -A1 "$p" 2>/dev/null | LC_ALL=C sort | head -n 200 | base64 -w0
    echo
  elif [ -f "$p" ]; then
    printf 'F|%s|' "$(facts "$p")"
    head -c 1024 "$p" | base64 -w0
    echo
  elif [ -e "$p" ]; then
    printf 'O|%s|\n' "$(facts "$p")"
  else
    echo 'M'
  fi
done
"""


def docker(
    *args: str, stdin: bytes | None = None, timeout: float = 60
) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args],
        input=stdin,
        stdin=None if stdin is not None else subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


class Host:
    """The labelling host. ``fresh`` throws it away and starts another."""

    def __init__(self) -> None:
        self.baseline = ""
        self.starts = 0

    def fresh(self) -> None:
        docker("rm", "-f", NAME)
        made = docker("create", "--network", "none", "--name", NAME, "--hostname", HOSTNAME, IMAGE)
        if made.returncode != 0:
            raise SystemExit(f"no labelling host: {made.stderr.decode()[:300]}")
        docker("start", NAME)
        for _ in range(120):
            if docker("exec", NAME, "test", "-f", "/ready").returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise SystemExit("the labelling host did not come up")
        self.starts += 1
        self.baseline = self.state()

    def exec(self, script: str, *args: str, timeout: float = 30) -> subprocess.CompletedProcess:
        env = [x for k, v in ENV.items() for x in ("-e", f"{k}={v}")]
        return docker(
            "exec", "-u", "0", "-w", CWD, *env, NAME, "bash", "-c", script, "bash", *args,
            timeout=timeout,
        )  # fmt: skip

    def state(self) -> str:
        return self.exec(STATE).stdout.decode(errors="replace")

    def run(self, cmd: str) -> dict[str, Any]:
        """One candidate, RUNS times: what it printed, and whether that can be a label."""
        seen = []
        began = time.monotonic()
        for _ in range(RUNS):
            try:
                done = self.exec(
                    f'timeout {DEADLINE_S} bash -c "$1" < /dev/null', cmd, timeout=DEADLINE_S + 20
                )
            except subprocess.TimeoutExpired:
                return {"timed_out": True}
            if done.returncode in (124, 137):
                return {"timed_out": True}
            seen.append((done.stdout[:MAX_BYTES], done.stderr[:MAX_BYTES], done.returncode))
        out, err, code = seen[0]
        label: dict[str, Any] = {
            "exit_code": code,
            "fixed": all(run == seen[0] for run in seen),
            "ms": round((time.monotonic() - began) * 1000 / RUNS),
            "big": len(out) >= MAX_BYTES or len(err) >= MAX_BYTES,
        }
        try:
            label["stdout"], label["stderr"] = out.decode("utf8"), err.decode("utf8")
        except UnicodeDecodeError:
            label["binary"] = True
        return label

    def view(self, paths: list[str]) -> list[dict[str, Any]]:
        if not paths:
            return []
        done = self.exec(VIEW, *paths)
        entries = []
        for path, line in zip(
            paths, done.stdout.decode(errors="replace").splitlines(), strict=False
        ):
            entries.append(entry(path, line))
        return entries


def entry(path: str, line: str) -> dict[str, Any]:
    """One path of the view, from the line VIEW printed for it."""
    kind, _, rest = line.partition("|")
    if kind == "M" or not rest:
        return {"path": path, "type": "missing"}
    mode, uid, gid, size, tail = ([*rest.split("|", 4), ""])[:5]
    out: dict[str, Any] = {
        "path": path,
        "type": {"L": "link", "D": "dir", "F": "file"}.get(kind, "other"),
        "mode": int(mode, 8) & 0o7777,
        "uid": int(uid),
        "gid": int(gid),
        "size": int(size),
    }
    if kind == "L":
        out["target"] = tail
    elif kind == "D":
        names = base64.b64decode(tail).decode("utf8", "replace").splitlines()
        out["children"] = sorted(names)[:MAX_CHILDREN]
    elif kind == "F" and 0 < int(size) <= MAX_FILE:
        data = base64.b64decode(tail)
        if data and b"\0" not in data:
            with contextlib.suppress(UnicodeDecodeError):
                out["head"] = data[:HEAD_BYTES].decode("utf8")
    return out


def wanted_paths(argv: list[str], cwd: str = CWD) -> tuple[list[str], set[str]]:
    """The paths the decoy's view holds for a command, and which of them it lists or reads:
    the fork's ``named_paths`` and ``view``, restated."""
    named = []
    for arg in argv[1:]:
        if not arg or "\0" in arg or (arg.startswith("-") and "=" not in arg):
            continue
        value = arg.split("=", 1)[1] if "=" in arg and not arg.startswith("/") else arg
        if value:
            path = value if value.startswith("/") else posixpath.join(cwd, value)
            named.append(posixpath.normpath(path))
    named = list(dict.fromkeys(named))
    wanted = [*named, *(posixpath.dirname(p) for p in named), cwd]
    return list(dict.fromkeys(wanted)), {*named, cwd}


def main(argv: list[str] | None = None) -> int:
    import shlex

    ap = argparse.ArgumentParser(prog="python -m eval.tune.label")
    ap.add_argument("--candidates", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=0, help="label only the first N (a trial)")
    args = ap.parse_args(argv)
    rows = [json.loads(line) for line in args.candidates.read_text().splitlines() if line.strip()]
    if args.limit:
        rows = rows[: args.limit]
    done = set()
    if args.out.exists():  # a run that was stopped goes on where it was
        done = {
            json.loads(line)["cmd"] for line in args.out.read_text().splitlines() if line.strip()
        }
    host = Host()
    host.fresh()
    views: dict[str, dict[str, Any]] = {}
    kept = 0
    with args.out.open("a") as out:
        for number, row in enumerate(rows, 1):
            if row["cmd"] in done:
                continue
            label = host.run(row["cmd"])
            after = host.state()
            label["changed"] = after != host.baseline
            if not label["changed"] and not label.get("timed_out") and not label.get("binary"):
                try:
                    words = shlex.split(row["cmd"])
                except ValueError:
                    words = row["cmd"].split()
                paths, listed = wanted_paths(words)
                missing = [p for p in paths if p not in views]
                for found in host.view(missing):
                    views[found["path"]] = found
                view = []
                for path in paths:
                    seen = dict(views.get(path, {"path": path, "type": "missing"}))
                    if path not in listed:  # a directory merely holding a named path
                        seen.pop("children", None)
                        seen.pop("head", None)
                    view.append(seen)
                label["slice"] = view
                kept += 1
            out.write(json.dumps({**row, **label, "hostname": HOSTNAME, "cwd": CWD}) + "\n")
            out.flush()
            if label["changed"] or "/ready" not in after:
                host.fresh()
                views.clear()
            if number % 100 == 0:
                print(
                    f"{number} of {len(rows)} run, {kept} usable so far, {host.starts} hosts",
                    file=sys.stderr,
                )
    docker("rm", "-f", NAME)
    print(
        f"{len(rows)} candidates, {kept} labelled this run, {host.starts} hosts used -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
