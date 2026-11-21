"""Assemble the tuning set from the labels (label.py).

    uv run python -m eval.tune.build --labels build/tune/labels.jsonl \\
        --profile build/profile/responder/responder.json --out build/tune/set

A row is one request as the responder would put it to the model (the same code builds the
prompt: ``mirage_responder.prompt``) and the answer the real host gave, as the JSON object
the model is to write. What is kept, and why not the rest:

- only a label that can be an answer: the three runs agreed, nothing was left behind, it is
  text, and it fits the answer's token limit;
- nothing that is true of the labelling host and false of a decoy: output that names the
  container it ran in, or a time of day;
- for one program, no more than CAP rows, and no more than two with the same answer (a
  program says "Try '--help'" to most wrong options: once or twice teaches it);
- no command of the bench (eval/probes/llm_commands.yaml), in any split.

Each row gets one of a few identities (host name, address), chosen by its command, and the
labelling host's own name is replaced by that identity's wherever it appears: in the
answer and in the file view. The model is to read the name from the prompt.

Splits, by hash, so that a rebuilt set splits the same way:

``train``             nine tenths of the invocations of eight tenths of the programs
``val``               every invocation of one tenth of the programs: for early stopping
``test_programs``     every invocation of another tenth, and of half the bench's programs:
                      programs the model has never seen
``test_invocations``  the held-back tenth of the trained programs' invocations
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from mirage_responder import prompt
from mirage_responder.state import Session

from eval.probes import llm_bench
from mirage_schema.respond import RespondRequest

MAX_ANSWER_CHARS = 1600  # about the 400 tokens an answer may take
CAP, SAME_ANSWER_CAP, EMPTY_CAP = 24, 2, 2
IDENTITIES = (
    ("web01", "10.2.117.32"),
    ("app-prod-2", "10.40.8.15"),
    ("db-replica", "172.20.3.7"),
    ("srv-edge-11", "192.168.50.21"),
)
_OF_THE_HOST = re.compile(r"docker|containerd|overlay|buildkit|kubepods|cgroup|/proc/\d+", re.I)
_CLOCK = re.compile(r"\b\d{1,2}:\d{2}(:\d{2})?\b")
_SECRET = re.compile(r"\$(?:1|5|6|y|2[aby]|argon2\w*)\$[./A-Za-z0-9$=,+-]{8,}|PRIVATE KEY")


def bucket(text: str, of: int) -> int:
    return int.from_bytes(hashlib.sha256(text.encode()).digest()[:4], "big") % of


def refusal(row: dict[str, Any]) -> str | None:
    """Why a label cannot be a training answer; None if it can."""
    if set(row["cmd"]) & set(";|&<>`$*()\n"):
        # The labeller runs a command through a shell; one the shell would change on the way
        # was not the command the row says it was.
        return "not one plain command"
    if row.get("timed_out"):
        return "ran out of time"
    if row.get("binary"):
        return "not text"
    if row.get("changed"):
        return "changed the host"
    if not row.get("fixed"):
        return "three runs differed"
    if row.get("big") or len(row["stdout"]) + len(row["stderr"]) > MAX_ANSWER_CHARS:
        return "longer than an answer may be"
    said = row["stdout"] + row["stderr"]
    if _OF_THE_HOST.search(said):
        return "names the host it was recorded on"
    if _CLOCK.search(said):
        return "holds a time of day"
    if _SECRET.search(said) or _SECRET.search(json.dumps(row.get("slice") or [])):
        # A password hash or a private key, even a labelling host's own, is not for a
        # training set: the model would learn to print one, and the set leaves this machine.
        return "holds a password hash or a key"
    return None


def choose(rows: list[dict[str, Any]], bench: set[str]) -> tuple[list[dict[str, Any]], Counter]:
    """The labels that become rows, and a count of why the others did not."""
    left: Counter = Counter()
    kept: list[dict[str, Any]] = []
    per_program: Counter = Counter()
    same: Counter = Counter()
    empty: Counter = Counter()
    # Hand-written invocations first, then the rest in a fixed order.
    order = sorted(rows, key=lambda r: (r["source"] != "seed", bucket(r["cmd"], 1 << 30)))
    for row in order:
        why = refusal(row)
        if why is None and row["cmd"] in bench:
            why = "a command of the bench"
        answer = (row.get("stdout"), row.get("stderr"), row.get("exit_code"))
        if why is None and per_program[row["program"]] >= CAP:
            why = "the program has its share"
        if why is None and same[(row["program"], answer)] >= SAME_ANSWER_CAP:
            why = "the same answer again"
        if why is None and not (row["stdout"] or row["stderr"]):
            if empty[row["program"]] >= EMPTY_CAP:
                why = "another empty answer"
            else:
                empty[row["program"]] += 1
        if why is not None:
            left[why] += 1
            continue
        per_program[row["program"]] += 1
        same[(row["program"], answer)] += 1
        kept.append(row)
    return kept, left


def split_of(row: dict[str, Any], unseen: set[str]) -> str:
    program = row["program"]
    if program in unseen:
        return "test_programs"
    part = bucket("program:" + program, 10)
    if part == 0:
        return "test_programs"
    if part == 1:
        return "val"
    return "test_invocations" if bucket("cmd:" + row["cmd"], 10) == 0 else "train"


def unseen_programs(bench: list[llm_bench.Command]) -> set[str]:
    """Half the bench's programs, to be met only in the test."""
    programs = sorted({shlex.split(c.cmd)[0] for c in bench})
    return set(programs[::2])


def example(row: dict[str, Any], profile: dict[str, Any], split: str) -> dict[str, Any]:
    hostname, address = IDENTITIES[bucket("identity:" + row["cmd"], len(IDENTITIES))]
    was = row.get("hostname", "")

    def named(text: str) -> str:
        return text.replace(was, hostname) if was else text

    mine = {**profile, "hostname": hostname, "address": address}
    mine["users"] = [u for u in profile.get("users", []) if u.get("uid") == 0]
    view = json.loads(named(json.dumps(row.get("slice") or [])))
    try:
        argv = shlex.split(row["cmd"])
    except ValueError:
        argv = row["cmd"].split()
    req = RespondRequest.model_validate(
        {
            "request_id": "tune",
            "session_id": "tune",
            "deployment_id": profile["deployment_id"],
            "seq": 1,
            "user": "root",
            "uid": 0,
            "cwd": row.get("cwd", "/root"),
            "argv": argv,
            "input": row["cmd"],
            "interactive": False,
            "slice": view,
            "budget": {"max_tokens": 400, "deadline_ms": 10000},
        }
    )
    answer = {
        "stdout": named(row["stdout"]),
        "stderr": named(row["stderr"]),
        "exit_code": row["exit_code"],
        "ops": [],
    }
    return {
        "id": hashlib.sha256(row["cmd"].encode()).hexdigest()[:12],
        "cmd": row["cmd"],
        "program": row["program"],
        "source": row["source"],
        "split": split,
        "messages": [
            {"role": "system", "content": prompt.system(mine)},
            {
                "role": "user",
                "content": prompt.state(Session(profile["deployment_id"]), req)
                + "\n\n"
                + prompt.command(req),
            },
        ],
        "answer": json.dumps(answer, ensure_ascii=False),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.tune.build")
    ap.add_argument("--labels", type=Path, required=True)
    ap.add_argument("--profile", type=Path, required=True, help="a deployment's responder.json")
    ap.add_argument("--out", type=Path, required=True, help="a directory: one file a split")
    args = ap.parse_args(argv)
    labels = [json.loads(line) for line in args.labels.read_text().splitlines() if line.strip()]
    profile = json.loads(args.profile.read_text())
    bench = llm_bench.load_commands()
    kept, left = choose(labels, {c.cmd for c in bench})
    unseen = unseen_programs(bench)
    by_split: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in kept:
        split = split_of(row, unseen)
        by_split[split].append(example(row, profile, split))
    args.out.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "labels": len(labels),
        "left_out": dict(left.most_common()),
        "splits": {},
    }
    for split in ("train", "val", "test_programs", "test_invocations"):
        rows = sorted(by_split.get(split, []), key=lambda r: r["id"])
        (args.out / f"{split}.jsonl").write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
        )
        chars = [len(r["messages"][0]["content"]) + len(r["messages"][1]["content"]) for r in rows]
        report["splits"][split] = {
            "rows": len(rows),
            "programs": len({r["program"] for r in rows}),
            "by_source": dict(Counter(r["source"] for r in rows)),
            "prompt_tokens_about": round(sum(chars) / 4 / max(1, len(rows))),
            "answer_tokens_about": round(
                sum(len(r["answer"]) for r in rows) / 4 / max(1, len(rows))
            ),
        }
    (args.out / "report.json").write_text(json.dumps(report, indent=1))
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
