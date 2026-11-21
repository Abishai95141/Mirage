"""Inputs that really run (arm R of phase 3's depth comparison): the run-safety rules, the
runner's refusal at send time, what it keeps of a failed check, and the arm report."""

from __future__ import annotations

import json

import pytest
from test_lab import Scripted, drive

from mirage_lab import arms
from mirage_lab.models import (
    DEMO,
    DEPTH,
    PHASE2,
    Catalogue,
    Procedure,
    Scenario,
    check_run_safety,
    lint,
)
from mirage_lab.runner import FAILED_CHECKS
from mirage_lab.slots import Slots

# One input per rule. None of these is in the catalogue; they are here so that the rules are
# shown to fire, and they are inert as text.
REFUSED = {
    "process flood": ":(){ :|:& };:",
    "loops without end": "while true; do date; done",
    "writes without end": "yes > /tmp/out",
    "fills disk or memory": "fallocate -l 50G /tmp/big",
    "endless device with no count": "dd if=/dev/zero of=/tmp/big bs=1M",
    "raw device": "cat /dev/sda",
    "kernel": "modprobe dummy",
    "container's boundary": "ls /var/run/docker.sock",
    "whole host": "shutdown -h now",
    "literal address": "ssh root@8.8.8.8 id",
}
ALLOWED = [
    "uname -a",
    "mount",  # listing what is mounted
    "mount | grep proc",
    "kill 4242",
    "dd if=/dev/zero of=/tmp/small bs=1k count=4",
    "ssh root@192.0.2.10 id",  # a documentation address
    "ip addr show dev lo; ss -ltn 127.0.0.1",
    "yes | head -n 3",
    "cat /proc/1/status",
    "for f in a b c; do echo $f; done",
    "ifconfig eth0 netmask 255.255.255.0",
]


@pytest.mark.parametrize("rule", sorted(REFUSED))
def test_each_run_safety_rule_fires(rule):
    problems = check_run_safety(REFUSED[rule])
    assert problems and any(rule in p for p in problems), problems
    assert all(REFUSED[rule] not in p for p in problems)  # a problem names the rule, not the input


@pytest.mark.parametrize("text", ALLOWED)
def test_ordinary_administration_is_not_refused(text):
    assert check_run_safety(text) == []


def catalogue(**sets: str) -> Catalogue:
    """procedure id -> its set; every procedure's text is the same refused input."""
    procs = {
        pid: Procedure(id=pid, technique="T1529", tactic="TA0040", source="own", protocol="ssh", template="shutdown -h now")
        for pid in sets
    }  # fmt: skip
    return Catalogue(attack_version="20.1", procedures=procs, sha256="x", set_of=dict(sets))


def one_step(pid: str) -> Scenario:
    return Scenario.model_validate(
        {
            "id": "probe-run",
            "actor": {"class": "scripted_bot", "timing": "bot-fast"},
            "sessions": [{"protocol": "ssh", "steps": [{"id": "s1", "procedure": pid}]}],
        }
    )


def test_the_lint_holds_depth_procedures_to_the_rules_and_only_those():
    cat = catalogue(**{"old-stop": PHASE2, "d-stop": DEPTH})
    # A phase 2 procedure is only ever sent to an emulator.
    assert lint(one_step("old-stop"), cat, Slots.names()) == []
    problems = lint(one_step("d-stop"), cat, Slots.names())
    assert len(problems) == 1 and "really runs" in problems[0] and "shutdown" not in problems[0]
    # Demo 3's second part runs in a sandbox, so its set is held to the same rules.
    demo = lint(one_step("h-stop"), catalogue(**{"h-stop": DEMO}), Slots.names())
    assert len(demo) == 1 and "really runs" in demo[0]


DOC = """
id: test-real
actor: {class: scripted_bot, timing: bot-fast, patience: 3}
sessions:
  - protocol: ssh
    channel: exec
    login: {user: root}
    steps:
      - {id: a, procedure: sysinfo-uname-all, expect: "Linux"}
      - {id: b, procedure: owner-id, expect: "uid=0"}
"""


def test_on_a_real_host_a_refused_input_is_never_sent(tmp_path):
    def swap(actor):
        actor.catalogue = Catalogue(
            attack_version="20.1",
            sha256="x",
            procedures={
                "sysinfo-uname-all": Procedure(
                    id="sysinfo-uname-all", technique="T1082", tactic="TA0007", source="own",
                    protocol="ssh", template="shutdown -h now",
                ),
                "owner-id": Procedure(
                    id="owner-id", technique="T1033", tactic="TA0007", source="own",
                    protocol="ssh", template="id",
                ),
            },
        )  # fmt: skip

    made = []

    def factory(*a):
        made.append(type("D", (Scripted,), {"answers": {r"^id$": ("uid=0(root)\n", 0)}})(*a))
        return made[-1]

    records, _actor, raised = drive(tmp_path, factory, DOC, prepare=swap, real_host=True)
    assert raised is None
    assert made[0].sent == ["id"]  # the refused input never left
    steps = {r["step_id"]: (r["status"], r["outcome"]) for r in records if r["kind"] == "step"}
    assert steps["a"] == ("skipped", "unchecked") and steps["b"] == ("ran", "ok")
    # Against an emulator the same input is allowed, as it always was.
    made.clear()
    drive(tmp_path / "decoy", factory, DOC, prepare=swap) if (
        tmp_path / "decoy"
    ).mkdir() is None else None
    assert made[0].sent == ["shutdown -h now", "id"]


def test_a_failed_check_on_a_real_host_is_kept_without_the_input(tmp_path):
    answers = {r"^uname": ("uname -a\nGNU/Hurd box 0.9\n", 0), r"^id$": ("uid=0(root)\n", 0)}

    def factory(*a):
        return type("D", (Scripted,), {"answers": answers})(*a)

    _records, _actor, raised = drive(tmp_path, factory, DOC, real_host=True)
    assert raised is None
    (kept,) = [json.loads(line) for line in (tmp_path / FAILED_CHECKS).read_text().splitlines()]
    assert kept["scenario_id"] == "test-real" and kept["step"] == "a"
    assert kept["procedure_id"] == "sysinfo-uname-all" and kept["expect"] == "Linux"
    # What the host answered is kept; the line that repeats the input (a terminal's echo) is not.
    assert kept["output"] == "GNU/Hurd box 0.9" and "uname" not in kept["output"]
    # Against an emulator nothing of the kind is written.
    (tmp_path / "decoy").mkdir()
    drive(tmp_path / "decoy", factory, DOC)
    assert not (tmp_path / "decoy" / FAILED_CHECKS).exists()
    # Unless the run asks for it (the depth comparison's emulator arms do). That changes
    # nothing else: the run-safety rules stay a real host's.
    (tmp_path / "arm").mkdir()
    drive(tmp_path / "arm", factory, DOC, keep_failed=True)
    (kept,) = [
        json.loads(line) for line in (tmp_path / "arm" / FAILED_CHECKS).read_text().splitlines()
    ]
    assert kept["procedure_id"] == "sysinfo-uname-all" and kept["output"] == "GNU/Hurd box 0.9"


def test_the_arm_report_counts_what_the_runner_recorded_as_succeeded(tmp_path):
    def step(sid, proc, technique, status, outcome, session="r1/s/0", evidence="input"):
        return {
            "kind": "step", "run_id": "r1", "scenario_id": "depth-x", "session_ref": session,
            "step_id": sid, "procedure_id": proc, "technique_id": technique, "status": status,
            "outcome": outcome, "evidence": evidence,
        }  # fmt: skip

    rows = [
        step("login-0", "", None, "ran", "ok", evidence="auth"),
        step("s1", "d-a", "T1082", "ran", "ok"),
        step("s2", "d-b", "T1033", "ran", "failed"),
        step("s2~2", "d-b", "T1033", "ran", "ok"),  # the retry is the attempt that counts
        step("s3", "d-c", "T1082", "ran", "ok"),  # a technique already counted
        step("s4", "d-d", "T1070.004", "ran", "failed"),
        step("s5", "d-e", "T1053.003", "skipped", "unchecked"),
        {"kind": "session", "run_id": "r1", "scenario_id": "depth-x", "session_ref": "r1/s/0"},
    ]
    (tmp_path / "groundtruth.json.r1").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    (tmp_path / FAILED_CHECKS).write_text('{"step": "s4"}\n')
    out = arms.report(tmp_path)
    (session,) = out["per_session"]
    assert session["steps"] == 5 and session["succeeded"] == 3 and session["not_sent"] == 1
    assert session["techniques"] == 2 and session["techniques_possible"] == 4
    assert session["check_failed"] == [("s4", "d-d")] and session["sent"] == 4
    assert out["scenarios"]["depth-x"]["checks_failed"] == [("s4", "d-d")]
    assert out["techniques_per_session"] == 2.0 and out["failed_checks_recorded"] == 1
    assert out["sessions_with_every_check_passing"] == 0
