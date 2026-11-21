"""The live-model bench (docs/06-phase-3-spec.md, 3.2c): how long an answer from the model
takes through the whole path, and how often it would pass for the real host's.

It has two halves, because no one place sees everything.

``run``     inside the lab network (the probe image). Every command of ``llm_commands.yaml``
            is sent to the decoy as an attacker would send it, an exec request over SSH, and
            once to the real reference host. Timed from the request: the first byte back and
            the exit status. Each of the decoy's answers is held against the reference host's
            by the fidelity check (``mirage_profiles.fidelity``), the same check the render
            library's entries pass. A sequential pass sends each command twice in one login
            (the second answer is the cache's, where the class allows one); a parallel pass
            sends them from several logins at once.
``report``  on the host. It joins a run with the responder's own records (who answered: the
            model, the cache, or the emulator after an abort, and why; tokens) and writes the
            tables.

A login is one session to the responder, with a budget of tokens, and a source address has a
budget for the day. The bench is not an attacker to be slowed: it logs in afresh for every
command and announces a new documentation-range source for each, so no answer here is an
abort for budget.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import threading
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from eval.probes.net import Target, probe_source
from mirage_profiles import fidelity

COMMANDS = Path(__file__).with_name("llm_commands.yaml")
CLASSES = ("stateless", "state-reading", "state-changing")
DEADLINE_S = 20.0
NO_STATUS = -1


@dataclass(frozen=True)
class Command:
    id: str
    cmd: str
    cls: str


def load_commands(path: Path = COMMANDS) -> list[Command]:
    doc = yaml.safe_load(path.read_text())
    out: list[Command] = []
    seen: set[str] = set()
    for item in doc["commands"]:
        unknown = set(item) - {"id", "cmd", "class"}
        if unknown:
            raise ValueError(f"{path.name}: {item.get('id')}: unknown keys {sorted(unknown)}")
        if item["id"] in seen:
            raise ValueError(f"{path.name}: {item['id']} is listed twice")
        if item["class"] not in CLASSES:
            raise ValueError(f"{path.name}: {item['id']}: no class called {item['class']!r}")
        seen.add(item["id"])
        out.append(Command(item["id"], item["cmd"], item["class"]))
    return out


@dataclass
class Answer:
    """One exec request: what came back and when."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int = NO_STATUS
    first_ms: float | None = None  # the first byte of either stream
    total_ms: float = 0.0
    started: str = ""  # UTC, for the join with the responder's records
    source: str = ""

    def observed(self) -> fidelity.Observed:
        return fidelity.Observed(self.stdout, self.stderr, self.exit_code)


def exec_timed(client: Any, command: str, source: str, deadline: float = DEADLINE_S) -> Answer:
    """One command on a channel of its own, timed from the request."""
    import paramiko

    answer = Answer(started=datetime.now(UTC).isoformat().replace("+00:00", "Z"), source=source)
    begun = time.monotonic()
    out, err = b"", b""
    try:
        chan = client.get_transport().open_session(timeout=deadline)
        chan.settimeout(0.05)
        chan.exec_command(command)
        while time.monotonic() - begun < deadline:
            moved = False
            if chan.recv_ready():
                out, moved = out + chan.recv(65536), True
            if chan.recv_stderr_ready():
                err, moved = err + chan.recv_stderr(65536), True
            if moved and answer.first_ms is None:
                answer.first_ms = round((time.monotonic() - begun) * 1000, 1)
            if chan.exit_status_ready() and not moved:
                break
            if not moved:
                time.sleep(0.001)
        answer.total_ms = round((time.monotonic() - begun) * 1000, 1)
        if chan.exit_status_ready():
            answer.exit_code = chan.recv_exit_status()
        while chan.recv_ready():
            out += chan.recv(65536)
        while chan.recv_stderr_ready():
            err += chan.recv_stderr(65536)
        chan.close()
    except (paramiko.SSHException, OSError, EOFError) as exc:
        answer.total_ms = round((time.monotonic() - begun) * 1000, 1)
        err += f"<channel: {exc}>".encode()
    answer.stdout, answer.stderr = out.decode(errors="replace"), err.decode(errors="replace")
    return answer


def first_difference(got: Answer, want: Answer) -> str:
    """Where an answer stops being the real host's, masked; empty if it never does."""
    if got.exit_code != want.exit_code:
        return f"exit status {got.exit_code}, the real host's is {want.exit_code}"
    for stream in ("stdout", "stderr"):
        mine = fidelity.mask(getattr(got, stream)).splitlines()
        theirs = fidelity.mask(getattr(want, stream)).splitlines()
        for i in range(max(len(mine), len(theirs))):
            a = mine[i] if i < len(mine) else "<no line>"
            b = theirs[i] if i < len(theirs) else "<no line>"
            if a != b:
                return f"{stream} line {i + 1} is {a[:60]!r}, the real host's is {b[:60]!r}"
    return ""


@dataclass
class Row:
    """One command's part of a run."""

    id: str
    cmd: str
    cls: str
    first: dict[str, Any] = field(default_factory=dict)  # the first answer in a login
    again: dict[str, Any] | None = None  # the same command once more, same login
    reference: dict[str, Any] | None = None
    ok: bool = False  # the first answer passes the fidelity check
    problems: list[str] = field(default_factory=list)
    # The stricter bar: the same as the real host's line for line and in its exit status,
    # once what differs between hosts and moments (numbers, dates, addresses) is masked.
    same: bool = False
    difference: str = ""
    again_same: bool | None = None  # the second answer is the first's, byte for byte


class Bench:
    def __init__(
        self, ssh: str, reference: str, user: str, password: str, proxy: bool, seed: int
    ) -> None:
        self.ssh, self.reference_target = ssh, reference
        self.user, self.password, self.proxy = user, password, proxy
        self.rng = random.Random(seed)
        self._lock = threading.Lock()

    def source(self) -> str:
        with self._lock:
            return probe_source(self.rng)

    def login(self, where: str) -> tuple[Any, str]:
        source = self.source()
        target = Target.parse(where, source if self.proxy else None)
        return target.ssh(self.user, self.password), source

    def truth(self, commands: list[Command]) -> dict[str, Answer]:
        """What the real host answers, each command once, one login."""
        client, source = self.login(self.reference_target)
        try:
            return {c.id: exec_timed(client, c.cmd, source) for c in commands}
        finally:
            client.close()

    def one(self, command: Command, truth: Answer | None, twice: bool) -> Row:
        client, source = self.login(self.ssh)
        try:
            first = exec_timed(client, command.cmd, source)
            again = exec_timed(client, command.cmd, source) if twice else None
        finally:
            client.close()
        row = Row(command.id, command.cmd, command.cls, asdict(first))
        if again is not None:
            row.again = asdict(again)
            row.again_same = (again.stdout, again.stderr, again.exit_code) == (
                first.stdout,
                first.stderr,
                first.exit_code,
            )
        if truth is not None:
            row.reference = asdict(truth)
            verdict = fidelity.check(first.observed(), truth.observed())
            row.ok, row.problems = verdict.ok, list(verdict.problems)
            row.difference = first_difference(first, truth)
            row.same = not row.difference
        return row

    def sequential(self, commands: list[Command], truth: dict[str, Answer]) -> list[Row]:
        return [self.one(c, truth.get(c.id), twice=True) for c in commands]

    def parallel(
        self, commands: list[Command], truth: dict[str, Answer], sessions: int
    ) -> list[Row]:
        """The commands shared out among ``sessions`` logins' worth of workers, all at once."""
        rows: list[Row | None] = [None] * len(commands)

        def work(offset: int) -> None:
            for index in range(offset, len(commands), sessions):
                command = commands[index]
                rows[index] = self.one(command, truth.get(command.id), twice=False)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(sessions)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return [row for row in rows if row is not None]


def run(args: argparse.Namespace) -> int:
    commands = load_commands(args.commands)
    if args.only:
        wanted = set(args.only.split(","))
        commands = [c for c in commands if c.id in wanted]
    password = next(
        line.split(":", 2)[2]
        for line in (args.profile / "cowrie" / "userdb.txt").read_text().splitlines()
        if line.startswith(f"{args.user}:")
    )
    bench = Bench(args.ssh, args.reference, args.user, password, args.proxy, args.seed)
    began = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    truth = bench.truth(commands) if args.reference else {}
    if args.sessions > 1:
        rows = bench.parallel(commands, truth, args.sessions)
    else:
        rows = bench.sequential(commands, truth)
    doc = {
        "kind": "parallel" if args.sessions > 1 else "sequential",
        "sessions": args.sessions,
        "began": began,
        "ended": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "target": args.ssh,
        "reference": args.reference,
        "rows": [asdict(row) for row in rows],
    }
    args.out.write_text(json.dumps(doc, indent=1))
    passed = sum(1 for row in rows if row.ok)
    print(f"{doc['kind']}: {len(rows)} commands, {passed} pass the fidelity check -> {args.out}")
    return 0


# ----------------------------------------------------------------------------- the report


def _when(text: str) -> float:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def join(doc: dict[str, Any], records: list[dict[str, Any]]) -> None:
    """Give each answer of a run the responder's records of it: those from its source
    address made between its request and its end. A command line of several commands has
    several; one the emulator answered by itself has none."""
    by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_source[record.get("src_ip", "")].append(record)
    for row in doc["rows"]:
        for key in ("first", "again"):
            answer = row.get(key)
            if not answer:
                continue
            start = _when(answer["started"]) - 0.05
            end = start + answer["total_ms"] / 1000 + 0.5
            answer["records"] = [
                r
                for r in by_source.get(answer["source"], ())
                if start <= _when(r["timestamp"]) <= end
            ]


def answered_by(answer: dict[str, Any]) -> str:
    """Who gave this answer: ``model``, ``cache``, ``fallback:<reason>`` or ``emulator``."""
    records = answer.get("records") or []
    if not records:
        return "emulator"
    aborted = [r for r in records if r.get("outcome") != "end"]
    if aborted:
        return "fallback:" + str(aborted[0].get("reason") or aborted[0].get("outcome"))
    return "cache" if all(r.get("rung") == "cache" for r in records) else "model"


def _median(values: list[float]) -> float | None:
    return round(statistics.median(values), 1) if values else None


def _p95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))], 1)


def summarise(doc: dict[str, Any]) -> dict[str, Any]:
    """The run's numbers: by command class, for answers the model gave."""
    out: dict[str, Any] = {"kind": doc["kind"], "sessions": doc["sessions"], "classes": {}}
    who = Counter(answered_by(row["first"]) for row in doc["rows"])
    out["answered_by"] = dict(sorted(who.items()))
    for cls in (*CLASSES, "all"):
        rows = [r for r in doc["rows"] if cls in (r["cls"], "all")]
        live = [r for r in rows if answered_by(r["first"]) == "model"]
        firsts = [r["first"]["first_ms"] for r in live if r["first"]["first_ms"] is not None]
        totals = [r["first"]["total_ms"] for r in live]
        tokens = [
            sum(int(x.get("output_tokens", 0)) for x in r["first"].get("records", ())) for r in live
        ]
        prompts = [
            sum(int(x.get("prompt_tokens", 0)) for x in r["first"].get("records", ())) for r in live
        ]
        cached = [
            r["again"]["total_ms"]
            for r in rows
            if r.get("again") and answered_by(r["again"]) == "cache"
        ]
        reference = [r["reference"]["total_ms"] for r in rows if r.get("reference")]
        out["classes"][cls] = {
            "commands": len(rows),
            "by_model": len(live),
            "pass": sum(1 for r in live if r["ok"]),
            "same": sum(1 for r in live if r.get("same")),
            "first_ms_median": _median(firsts),
            "first_ms_p95": _p95(firsts),
            "total_ms_median": _median(totals),
            "total_ms_p95": _p95(totals),
            "output_tokens_median": _median([float(t) for t in tokens]),
            "prompt_tokens_median": _median([float(t) for t in prompts]),
            "cache_total_ms_median": _median(cached),
            "cache_hits": len(cached),
            "reference_total_ms_median": _median(reference),
        }
    return out


def table(summary: dict[str, Any]) -> str:
    head = (
        "| Class | Commands | Answered by the model | Pass the check | Same as the real host "
        "| First byte, median (p95) "
        "| Whole answer, median (p95) | Output tokens, median | From the cache, median "
        "| Reference host, median |\n" + "| --- " * 10 + "|\n"
    )

    def ms(value: float | None, tail: float | None = None) -> str:
        if value is None:
            return "none"
        return f"{value:.0f} ms" + (f" ({tail:.0f})" if tail is not None else "")

    lines = []
    for cls, c in summary["classes"].items():
        lines.append(
            f"| {cls} | {c['commands']} | {c['by_model']} | {c['pass']} of {c['by_model']} "
            f"| {c['same']} of {c['by_model']} "
            f"| {ms(c['first_ms_median'], c['first_ms_p95'])} "
            f"| {ms(c['total_ms_median'], c['total_ms_p95'])} "
            f"| {c['output_tokens_median'] if c['output_tokens_median'] is not None else 'none'} "
            f"| {ms(c['cache_total_ms_median'])} ({c['cache_hits']} hits) "
            f"| {ms(c['reference_total_ms_median'])} |"
        )
    return head + "\n".join(lines) + "\n"


def failures(doc: dict[str, Any]) -> str:
    """Every answer that was not the model's, or was not the real host's, with why."""
    lines = []
    for row in doc["rows"]:
        who = answered_by(row["first"])
        if who != "model":
            lines.append(f"- `{row['id']}` ({row['cls']}): {who}")
        elif not row["ok"]:
            lines.append(f"- `{row['id']}` ({row['cls']}): {'; '.join(row['problems'][:2])}")
        elif not row.get("same"):
            why = row.get("difference", "")
            lines.append(f"- `{row['id']}` ({row['cls']}): passes the check, but {why}")
    return "\n".join(lines) + ("\n" if lines else "")


def not_asked(summary: dict[str, Any]) -> bool:
    """Whether a pass says nothing about the model: every command of the list is one the
    decoy has no answer of its own for, so when the emulator answered more than half, the
    responder was not being asked (found on 18 November 2026: 47 of 55, on a host still busy
    from a rebuild, reported as "6 pass the check")."""
    who = summary["answered_by"]
    total = sum(who.values())
    return total > 0 and who.get("emulator", 0) > total / 2


def report(args: argparse.Namespace) -> int:
    records = [json.loads(line) for line in args.records.read_text().splitlines() if line.strip()]
    out: dict[str, Any] = {"model": args.model, "gpu_memory": args.gpu_memory, "runs": []}
    text = []
    unmeasured: list[str] = []
    for path in args.runs:
        doc = json.loads(path.read_text())
        join(doc, records)
        summary = summarise(doc)
        out["runs"].append({"file": path.name, "summary": summary, "rows": doc["rows"]})
        title = (
            "One command at a time"
            if doc["kind"] == "sequential"
            else f"{doc['sessions']} sessions at once"
        )
        text.append(f"### {title}\n\n{table(summary)}\nWho answered: {summary['answered_by']}\n")
        if not_asked(summary):
            unmeasured.append(title)
            text.append(
                "**This pass does not measure the model.** The decoy answered most commands "
                "itself, so the responder was not asked: it was not healthy when the pass ran "
                "(a busy host makes its health check time out). Run the bench again.\n"
            )
        missed = failures(doc)
        if missed:
            text.append(f"Not the model's, or not passing:\n\n{missed}")
    args.out.write_text(json.dumps(out, indent=1))
    print("\n".join(text))
    return 2 if unmeasured else 0


def main(argv: list[str] | None = None) -> int:
    import os

    env = os.environ
    ap = argparse.ArgumentParser(prog="python -m eval.probes.llm_bench")
    sub = ap.add_subparsers(dest="what", required=True)
    r = sub.add_parser("run", help="inside the lab network: send the commands, time the answers")
    r.add_argument("--ssh", default=env.get("PROBE_SSH", "127.0.0.1:2222"))
    r.add_argument("--reference", default=env.get("PROBE_REFERENCE", ""))
    r.add_argument("--profile", type=Path, default=Path(env.get("PROFILE_DIR", "build/profile")))
    r.add_argument("--proxy", action="store_true", default=env.get("PROBE_PROXY") == "1")
    r.add_argument("--user", default="root")
    r.add_argument("--commands", type=Path, default=COMMANDS)
    r.add_argument("--only", default="", help="comma-separated command IDs")
    r.add_argument("--sessions", type=int, default=1, help="logins at once (1: sequential)")
    r.add_argument("--seed", type=int, default=1)
    r.add_argument("--out", type=Path, required=True)
    r.set_defaults(func=run)
    p = sub.add_parser("report", help="on the host: join runs with the responder's records")
    p.add_argument("--records", type=Path, required=True, help="the responder's answers.json")
    p.add_argument("--model", default="")
    p.add_argument("--gpu-memory", default="")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("runs", type=Path, nargs="+")
    p.set_defaults(func=report)
    args = ap.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
