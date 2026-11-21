"""The tuning set's own logic: which commands are asked, which labels become rows, and how
they are split. (The labelling itself needs a reference host: `python -m eval.tune.label`.)"""

from __future__ import annotations

import json
from pathlib import Path

from eval.probes import llm_bench
from eval.tune import build, candidates, label

PROFILE = {
    "version": 1,
    "deployment_id": "web-db-1",
    "hostname": "web01",
    "os": "Debian GNU/Linux 12 (bookworm)",
    "kernel": "Linux 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01) x86_64",
    "kernel_release": "6.1.0-18-amd64",
    "arch": "amd64",
    "address": "10.20.4.17",
    "timezone": "Etc/UTC",
    "hardware": {"cpu_model": "AMD EPYC-Rome Processor", "cpus": 2},
    "users": [
        {"name": "root", "uid": 0, "home": "/root"},
        {"name": "caleb", "uid": 1000, "home": "/home/caleb"},
    ],
    "services": [{"name": "sshd", "version": "OpenSSH_9.2p1", "port": 22}],
    "token_paths": [],
}


def labelled(cmd: str, stdout: str = "ok\n", source: str = "option", **more) -> dict:
    return {
        "cmd": cmd,
        "program": cmd.split()[0],
        "source": source,
        "stdout": stdout,
        "stderr": "",
        "exit_code": 0,
        "fixed": True,
        "changed": False,
        "hostname": "tunehost",
        "cwd": "/root",
        "slice": [],
        **more,
    }


# ------------------------------------------------------------------ candidates


def test_the_seeds_are_plain_commands_and_none_is_a_bench_command():
    seeds = candidates.load_seeds()
    assert len(seeds) >= 200 and len({s.cmd for s in seeds}) == len(seeds)
    bench = {c.cmd for c in llm_bench.load_commands()}
    assert not [s.cmd for s in seeds if s.cmd in bench]
    for seed in seeds:
        # One command, nothing a shell acts on: it is run as written on the labelling host.
        assert not set(seed.cmd) & set(";|&<>`$*()\n"), seed.cmd


def test_options_are_read_from_a_programs_own_help():
    text = (
        "Usage: tool [OPTION]... FILE\n"
        "  -a, --all            show everything\n"
        "  -n NUM               how many\n"
        "  -f, --file=FILE      read FILE\n"
        "  -q                   say nothing\n"
        "  -h, --help           this text\n"
        "  -a                   listed twice\n"
    )
    assert candidates.options_of(text) == ["-a", "-q"]


def test_candidates_leave_out_what_the_model_is_never_asked_and_what_would_break_the_host():
    helps = {p: (0, "  -a  all\n") for p in ("od", "ls", "shred", "top", "nohelp")}
    helps["nohelp"] = (1, "")
    versions = {p: (0, f"{p} 1.0\n") for p in helps}
    built = candidates.build(
        ["od", "ls", "shred", "top", "nohelp"],
        helps,
        versions,
        emulated={"ls"},
        refused={"top"},
        seeds=[candidates.Candidate("od -c /etc/shells", "od", "seed")],
    )
    programs = {c.program for c in built}
    assert programs == {"od", "nohelp"}  # ls is emulated, top is refused, shred changes the host
    cmds = [c.cmd for c in built]
    assert cmds[0] == "od -c /etc/shells"  # seeds first
    assert {
        "od --version",
        "od --help",
        "od --frobnicate",
        "od",
        "od -a",
        "od -a /etc/hostname",
    } <= set(cmds)
    assert [c for c in cmds if c.startswith("nohelp")] == ["nohelp --version"]
    assert len(cmds) == len(set(cmds))


# ------------------------------------------------------------------ the labeller's view


def test_the_view_is_the_decoys_own():
    paths, listed = label.wanted_paths(["od", "-c", "/etc/hostname", "notes", "--file=/tmp/x"])
    assert paths == ["/etc/hostname", "/root/notes", "/tmp/x", "/etc", "/root", "/tmp"]
    assert listed == {"/etc/hostname", "/root/notes", "/tmp/x", "/root"}
    assert label.entry("/etc/hostname", "F|644|0|0|6|d2ViMDEK") == {
        "path": "/etc/hostname", "type": "file", "mode": 0o644, "uid": 0, "gid": 0, "size": 6,
        "head": "web01\n",
    }  # fmt: skip
    assert label.entry("/etc", "D|755|0|0|4096|YgphCg==")["children"] == ["a", "b"]
    assert label.entry("/bin", "L|777|0|0|7|usr/bin")["target"] == "usr/bin"
    assert label.entry("/nope", "M") == {"path": "/nope", "type": "missing"}
    assert "head" not in label.entry("/bin/ls", "F|755|0|0|151344|f0VMRgIBAQAA")  # too big to show


# ------------------------------------------------------------------ building


def test_a_label_that_cannot_be_an_answer_is_left_out_with_its_reason():
    assert build.refusal(labelled("od x")) is None
    for row, why in (
        (labelled("dpkg-query -f=${Version} bash"), "not one plain command"),
        (labelled("a", timed_out=True), "ran out of time"),
        (labelled("a", binary=True), "not text"),
        (labelled("a", changed=True), "changed the host"),
        (labelled("a", fixed=False), "three runs differed"),
        (labelled("a", stdout="x" * 2000), "longer than an answer may be"),
        (labelled("a", stdout="docker-default (enforce)\n"), "names the host it was recorded on"),
        (labelled("a", stdout="up since 21:16\n"), "holds a time of day"),
        (
            labelled(
                "a", stdout="root:$y$j9T$abcdefghijklmnop$qrstuvwxyz0123456789:19900:0:99999:7:::\n"
            ),
            "holds a password hash or a key",
        ),
        (
            labelled("a", stdout="-----BEGIN OPENSSH PRIVATE KEY-----\n"),
            "holds a password hash or a key",
        ),
        (
            labelled(
                "a",
                slice=[
                    {
                        "path": "/etc/shadow",
                        "type": "file",
                        "head": "root:$6$saltsalt$hashhashhashhash:1::\n",
                    }
                ],
            ),
            "holds a password hash or a key",
        ),
    ):
        assert build.refusal(row) == why


def test_one_program_gets_its_share_and_no_answer_too_often():
    rows = [labelled(f"tool -{c}", stdout="Try 'tool --help'\n") for c in "abcdef"]
    rows += [labelled(f"tool {n}", stdout=f"{n}\n") for n in range(40)]
    rows += [
        labelled("tool quiet1", stdout=""),
        labelled("tool quiet2", stdout=""),
        labelled("tool quiet3", stdout=""),
    ]
    rows += [labelled("factor 360", stdout="360: 2 2 2 3 3 5\n")]
    kept, left = build.choose(rows, bench={"factor 360"})
    tool = [r for r in kept if r["program"] == "tool"]
    assert len(tool) == build.CAP
    assert sum(1 for r in tool if r["stdout"].startswith("Try")) <= build.SAME_ANSWER_CAP
    assert sum(1 for r in tool if not r["stdout"]) <= build.EMPTY_CAP
    assert left["a command of the bench"] == 1 and not [r for r in kept if r["cmd"] == "factor 360"]
    assert left["the same answer again"] + left["the program has its share"] >= 4


def test_the_split_is_by_program_and_the_same_every_time():
    bench = llm_bench.load_commands()
    unseen = build.unseen_programs(bench)
    assert 15 <= len(unseen) <= 30
    rows = [labelled(f"prog{p} arg{a}") for p in range(60) for a in range(10)]
    where: dict[str, set[str]] = {}
    for row in rows:
        where.setdefault(row["program"], set()).add(build.split_of(row, unseen))
    # A program is trained on, or it is not: never both.
    for program, splits in where.items():
        assert splits <= {"train", "test_invocations"} or len(splits) == 1, program
    counted = [s for splits in where.values() for s in splits]
    assert {"train", "val", "test_programs", "test_invocations"} <= set(counted)
    assert build.split_of(rows[0], unseen) == build.split_of(dict(rows[0]), unseen)
    assert (
        build.split_of(labelled("locale -k LC_TIME"), unseen) == "test_programs"
        or "locale" not in unseen
    )


def test_a_row_is_the_responders_own_prompt_and_the_real_answer_under_one_identity():
    row = labelled(
        "od -c /etc/hostname",
        stdout="0000000   t   u   n   e   h   o   s   t  \\n\n",
        slice=[
            {
                "path": "/etc/hostname",
                "type": "file",
                "mode": 0o644,
                "uid": 0,
                "gid": 0,
                "size": 9,
                "head": "tunehost\n",
            }
        ],
    )
    row["stdout"] = "tunehost says hello\n"
    made = build.example(row, PROFILE, "train")
    system, user = (m["content"] for m in made["messages"])
    host = next(name for name, _ in build.IDENTITIES if f"host name: {name}" in system)
    answer = json.loads(made["answer"])
    assert list(answer) == ["stdout", "stderr", "exit_code", "ops"]
    assert answer == {"stdout": f"{host} says hello\n", "stderr": "", "exit_code": 0, "ops": []}
    # The labelling host's name is nowhere, and the identity's is in the file view too.
    assert "tunehost" not in system + user + made["answer"]
    assert f'"{host}\\n"' in user and 'The command, as data: "od -c /etc/hostname"' in user
    assert "typed at a terminal: no" in user
    # Only accounts the labelling host has: its answers know no others.
    assert "caleb" not in system and "root (uid 0" in system
    assert made["split"] == "train" and len(made["id"]) == 12


def test_building_writes_one_file_a_split_and_a_report(tmp_path):
    labels = tmp_path / "labels.jsonl"
    rows = [labelled(f"prog{p} arg{a}", stdout=f"{p}-{a}\n") for p in range(40) for a in range(6)]
    rows.append(labelled("prog1 broke", changed=True))
    labels.write_text("".join(json.dumps(r) + "\n" for r in rows))
    profile = tmp_path / "responder.json"
    profile.write_text(json.dumps(PROFILE))
    out = tmp_path / "set"
    assert build.main(["--labels", str(labels), "--profile", str(profile), "--out", str(out)]) == 0
    report = json.loads((out / "report.json").read_text())
    assert report["labels"] == 241 and report["left_out"] == {"changed the host": 1}
    total = 0
    for split in ("train", "val", "test_programs", "test_invocations"):
        lines = Path(out / f"{split}.jsonl").read_text().splitlines()
        assert len(lines) == report["splits"][split]["rows"]
        total += len(lines)
    assert total == 240
    assert report["splits"]["train"]["rows"] > report["splits"]["val"]["rows"] > 0
