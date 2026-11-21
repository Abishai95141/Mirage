"""Gate contract v2 and the state operations (phase 3 spec, sections 3 and 3.1)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from mirage_schema.ops import MAX_OPS, MAX_WRITE_BYTES, Op, OpKind, parse_ops, protected
from mirage_schema.policy import (
    V1_ACTIONS,
    V2_ACTIONS,
    Action,
    Budget,
    DecideRequest,
    Decision,
    Tier,
)

BASE = {"request_id": "r1", "protocol": "ssh", "argv": ["id"]}


def test_v2_adds_three_actions_and_changes_no_v1_one():
    assert {a.value for a in V1_ACTIONS} == {
        "allow",
        "delay",
        "fake_success",
        "fake_error",
        "terminate",
    }
    assert {a.value for a in V2_ACTIONS} == {"respond", "plant_token", "escalate"}
    assert set(Action) == V1_ACTIONS | V2_ACTIONS


def test_a_v1_request_supports_nothing_new():
    req = DecideRequest.model_validate(BASE)
    assert req.supports == [] and req.tier is None and req.known is True


def test_supports_keeps_the_new_actions_it_knows_once_each():
    req = DecideRequest.model_validate(
        BASE
        | {"supports": ["respond", "allow", "teleport", "respond", 7, "escalate"], "tier": "none"}
    )
    # A v1 action is not something to "support", and an unknown word is a newer decoy's.
    assert req.supports == [Action.RESPOND, Action.ESCALATE]
    assert req.tier is Tier.NONE
    assert DecideRequest.model_validate(BASE | {"supports": "respond"}).supports == []
    assert DecideRequest.model_validate(BASE | {"tier": "imagined"}).tier is None


def test_a_decision_carries_a_budget_operations_or_a_sandbox():
    respond = Decision.model_validate(
        {
            "action": "respond",
            "decision_id": "d",
            "budget": {"max_tokens": 400, "deadline_ms": 10000},
        }
    )
    assert respond.budget == Budget(max_tokens=400, deadline_ms=10000)
    plant = Decision.model_validate(
        {
            "action": "plant_token",
            "decision_id": "d",
            "ops": [
                {"op": "write", "path": "/root/.my.cnf", "content": "[client]\n", "mode": 0o600}
            ],
        }
    )
    assert plant.ops is not None and plant.ops[0].op is OpKind.WRITE
    assert Decision.model_validate(
        {"action": "escalate", "decision_id": "d", "sandbox": "s-1"}
    ).sandbox
    # A v1 decision is what it was.
    plain = Decision.model_validate({"action": "allow", "decision_id": "d"})
    assert plain.budget is None and plain.ops is None and plain.sandbox is None


@pytest.mark.parametrize(
    "budget", [{"max_tokens": 0, "deadline_ms": 10}, {"max_tokens": 401, "deadline_ms": 10},
               {"max_tokens": 10, "deadline_ms": 10001}, {"max_tokens": 10}]
)  # fmt: skip
def test_a_budget_outside_its_limits_is_refused(budget):
    with pytest.raises(ValidationError):
        Decision.model_validate({"action": "respond", "decision_id": "d", "budget": budget})


def test_a_decision_with_a_bad_operation_is_refused_whole():
    with pytest.raises(ValidationError):
        Decision.model_validate(
            {
                "action": "plant_token",
                "decision_id": "d",
                "ops": [{"op": "write", "path": "x", "content": ""}],
            }
        )


# ------------------------------------------------------------------ operations

GOOD = [
    {"op": "mkdir", "path": "/tmp/a"},
    {"op": "mkdir", "path": "/tmp/a", "mode": 0o700},
    {"op": "write", "path": "/tmp/a/f", "content": "x\n"},
    {"op": "write", "path": "/tmp/a/f", "content": "", "mode": 0o600},
    {"op": "remove", "path": "/tmp/a/f"},
    {"op": "rename", "path": "/tmp/a", "to": "/tmp/b"},
    {"op": "chmod", "path": "/tmp/b", "mode": 0o755},
    {"op": "chown", "path": "/tmp/b", "uid": 33},
    {"op": "chown", "path": "/tmp/b", "uid": 33, "gid": 33},
    {"op": "cd", "path": "/var/log"},
    {"op": "cd", "path": "/proc"},  # looking is allowed where writing is not
    {"op": "setenv", "name": "EDITOR", "value": "vi"},
    {"op": "unsetenv", "name": "EDITOR"},
    {"op": "proc_start", "args": "sleep 600"},
    {"op": "proc_end", "pid": 4242},
]


@pytest.mark.parametrize("raw", GOOD)
def test_each_kind_of_operation_in_its_right_shape(raw):
    assert Op.model_validate(raw).op.value == raw["op"]


def test_the_vocabulary_is_the_eleven_kinds_of_the_spec():
    assert {k.value for k in OpKind} == {
        "mkdir", "write", "remove", "rename", "chmod", "chown", "cd", "setenv", "unsetenv",
        "proc_start", "proc_end",
    }  # fmt: skip
    assert {raw["op"] for raw in GOOD} == {k.value for k in OpKind}


BAD = [
    ({"op": "write", "path": "/tmp/f"}, "needs"),
    ({"op": "mkdir", "path": "tmp/a"}, "not absolute"),
    ({"op": "mkdir", "path": "/tmp/../etc/a"}, "not normalised"),
    ({"op": "mkdir", "path": "/tmp/a/"}, "not normalised"),
    ({"op": "rename", "path": "/tmp/a", "to": "b"}, "not absolute"),
    ({"op": "write", "path": "/proc/sysrq-trigger", "content": "b"}, "kernel"),
    ({"op": "remove", "path": "/dev/null"}, "kernel"),
    ({"op": "chmod", "path": "/sys", "mode": 0o777}, "kernel"),
    ({"op": "rename", "path": "/tmp/a", "to": "/dev/shm/a"}, "kernel"),
    ({"op": "remove", "path": "/"}, "root"),
    ({"op": "write", "path": "/tmp/f", "content": "x" * (MAX_WRITE_BYTES + 1)}, "over"),
    ({"op": "chown", "path": "/tmp/f"}, "uid or a gid"),
    ({"op": "chmod", "path": "/tmp/f", "mode": 0o10000}, "4095"),
    ({"op": "setenv", "name": "1X", "value": "v"}, "variable name"),
    ({"op": "setenv", "name": "X=Y", "value": "v"}, "variable name"),
    ({"op": "mkdir", "path": "/tmp/a", "content": "x"}, "does not take"),
    ({"op": "cd", "path": "/tmp", "mode": 0o755}, "does not take"),
    ({"op": "proc_end", "pid": 1}, "greater than or equal to 2"),
    ({"op": "exec", "path": "/bin/sh"}, "Input should be"),
    ({"op": "mkdir", "path": "/tmp/a", "extra": 1}, "Extra inputs"),
]


@pytest.mark.parametrize(("raw", "why"), BAD)
def test_a_malformed_operation_is_refused_and_says_why(raw, why):
    with pytest.raises(ValueError, match=why):
        parse_ops([raw])


def test_one_bad_operation_refuses_the_whole_answer_and_names_it():
    with pytest.raises(ValueError, match=r"operation 2: .*not absolute"):
        parse_ops([GOOD[0], {"op": "mkdir", "path": "relative"}, GOOD[2]])


def test_at_most_eight_operations_in_one_answer():
    assert len(parse_ops([GOOD[0]] * MAX_OPS)) == MAX_OPS == 8
    with pytest.raises(ValueError, match="at most 8"):
        parse_ops([GOOD[0]] * (MAX_OPS + 1))
    assert parse_ops(None) == [] and parse_ops([]) == []
    with pytest.raises(ValueError, match="not a list"):
        parse_ops({"op": "mkdir"})


def test_the_kernel_s_directories_and_what_is_under_them():
    assert protected("/proc") and protected("/proc/1/cmdline") and protected("/dev/null")
    assert not protected("/process") and not protected("/devel/x") and not protected("/tmp")


# ------------------------------------------------------------------ the shared cases


def expand(value):
    """'@repeat:X:N' is X written N times; the cases file keeps long values short."""
    if isinstance(value, str):
        return re.sub(r"@repeat:(.):(\d+)", lambda m: m.group(1) * int(m.group(2)), value)
    if isinstance(value, list):
        return [expand(v) for v in value]
    if isinstance(value, dict):
        return {k: expand(v) for k, v in value.items()}
    return value


CASES = json.loads((Path(__file__).parent / "ops_cases.json").read_text())["cases"]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_the_shared_cases_get_their_verdicts(case):
    """The SSH decoy checks operations with code of its own (it does not carry this
    package). The same file of cases is run there, so the two cannot drift apart."""
    ops = expand(case["ops"])
    if case["ok"]:
        assert len(parse_ops(ops)) == len(ops or [])
    else:
        with pytest.raises(ValueError):
            parse_ops(ops)


def test_the_cases_cover_every_operation_both_ways():
    kinds = {k.value for k in OpKind}
    accepted = {o["op"] for c in CASES if c["ok"] for o in (c["ops"] or [])}
    refused = {
        o.get("op") for c in CASES if not c["ok"] and isinstance(c["ops"], list)
        for o in c["ops"] if isinstance(o, dict)
    }  # fmt: skip
    assert kinds <= accepted and kinds <= refused
    assert len(CASES) >= 100


def test_a_program_that_is_not_there_has_a_tier_of_its_own():
    """Decided 17 November 2026: "command not found" is an answer the decoy has, so an input
    naming a program the host lacks is not one for the responder."""
    req = DecideRequest.model_validate(BASE | {"tier": "absent", "known": False})
    assert req.tier is Tier.ABSENT and req.tier is not Tier.NONE
    assert {t.value for t in Tier} == {"emulated", "rendered", "none", "absent"}
