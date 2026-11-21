"""The answer ladder's fourth rung, end to end (phase 3 spec 3.1 and 3.2b; Gate 3 tests 1, 4
and 5 as far as they go without a model).

The SSH decoy, the policy service under rules v2, the responder, and a scripted stand-in for
the model server (compose profile ``stub``; see ``mirage_responder.stub``). The stand-in is
not a model: these tests check the path, not what a model would say. Each command used is one
the deployed image has a program for and the emulator does not answer (``locale``, ``od``,
``install``), so its tier is ``none``.

The module brings the stand-in up and points the responder at it, and puts the responder back
on ``replay`` when it is done. It runs in file order: later tests stop and start services.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from datetime import UTC, datetime

import paramiko
import pytest

from .conftest import ROOT, docker, unavailable
from .test_gate1 import Shell, _password, poll

pytestmark = pytest.mark.integration

COMPOSE = [
    "compose", "--env-file", str(ROOT / ".env"), "-f", str(ROOT / "compose/docker-compose.yml"),
    "--profile", "stub",
]  # fmt: skip
STUB = {
    "RESPONDER_BACKEND": "llama-dev",
    "RESPONDER_LLM_URL": "http://llm-stub:8080",
    "RESPONDER_MODEL": "stub-1",
}
EMULATOR = "cannot execute binary file"  # what the emulator says of a program it lacks
HEALTH_S = 5  # the decoy's check of the responder


def compose(*args: str, env: dict[str, str] | None = None, check: bool = True):
    return subprocess.run(
        ["docker", *COMPOSE, *args],
        capture_output=True,
        text=True,
        check=check,
        timeout=300,
        env=os.environ | (env or {}),
    )


def responder_up(env: dict[str, str] | None = None) -> None:
    compose("up", "-d", "--wait", "--force-recreate", "responder", env=env)
    # Until the decoy has found it again: one check fails at the old address and has the
    # name looked up again, the next passes.
    time.sleep(2 * HEALTH_S + 2)


@pytest.fixture(scope="module", autouse=True)
def stubbed(env):
    if docker("inspect", "mirage-responder-1", check=False).returncode != 0:
        unavailable("no responder container; run make up")
    compose("up", "-d", "--wait", "llm-stub", env=STUB)
    responder_up(STUB)
    yield
    compose("stop", "llm-stub", check=False)
    compose("rm", "-f", "llm-stub", check=False)
    responder_up()  # back on replay


def forgive() -> None:
    """Forget which programs the responder refuses (it refuses a program for the whole
    deployment once it could not answer for it, and these tests make it fail on purpose)."""
    compose("exec", "-T", "responder", "python", "-m", "mirage_responder.candidates", "forgive")


@pytest.fixture(autouse=True)
def forgiven(stubbed):
    forgive()


@pytest.fixture(scope="module")
def port(env) -> int:
    return int(env.get("SSH_PORT", "2222"))


def run(port: int, command: str, timeout: float = 20.0) -> tuple[str, str, int]:
    """One exec request, as root: stdout, stderr and the exit status."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "127.0.0.1", port, "root", _password(), look_for_keys=False, allow_agent=False, timeout=15
    )
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        out, err = stdout.read().decode(), stderr.read().decode()
        return out, err, stdout.channel.recv_exit_status()
    finally:
        client.close()


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")


def responded(clickhouse, t0: str, command: str, how: str) -> dict:
    """The decoy's event for a command it asked the responder about."""
    rows = poll(
        clickhouse,
        "SELECT session_id, outcome, payload FROM mirage.events FINAL "
        f"WHERE source = 'cowrie' AND action = 'responded' AND ts >= '{t0}' "
        f"AND JSONExtractString(payload, 'command') = '{command}' "
        f"AND JSONExtractString(payload, 'respond_outcome') = '{how}' ORDER BY ts DESC",
    )
    return rows[0] | {"payload": json.loads(rows[0]["payload"])}


# ------------------------------------------------------------------ an answer


def test_a_command_the_emulator_lacks_is_answered_and_every_record_joins(clickhouse, port):
    t0 = now()
    out, err, status = run(port, "locale charmap")
    assert (out, err, status) == ("ANSI_X3.4-1968\n", "", 0)

    event = responded(clickhouse, t0, "locale charmap", "answered")
    sid, request_id = event["session_id"], event["payload"]["request_id"]
    assert event["outcome"] == "success" and event["payload"]["rung"] in ("model", "cache")
    # The decoy's decision event, the policy's record and the responder's record are the same
    # request.
    joined = poll(
        clickhouse,
        "SELECT source, action, JSONExtractString(payload, 'rule_id') AS rule, "
        "JSONExtractString(payload, 'answer_outcome') AS answer FROM mirage.events FINAL "
        f"WHERE session_id = '{sid}' AND JSONExtractString(payload, 'request_id') = '{request_id}'",
        lambda rows: {r["source"] for r in rows} >= {"cowrie", "policy", "responder"},
    )
    by = {(r["source"], r["action"]): r for r in joined}
    assert by[("policy", "decide")]["rule"] == "v2.respond-to-the-unknown"
    assert by[("responder", "answer")]["answer"] == "end"
    assert ("cowrie", "decide") in by
    # Nothing unmapped came out of any of it.
    unknown = clickhouse(
        f"SELECT action FROM mirage.events FINAL WHERE session_id = '{sid}' AND class = 'unknown'"
    )
    assert unknown == []


def test_the_same_question_from_another_session_is_answered_from_the_cache(clickhouse, port):
    run(port, "locale charmap")
    t0 = now()
    assert run(port, "locale charmap")[0] == "ANSI_X3.4-1968\n"
    event = responded(clickhouse, t0, "locale charmap", "answered")
    assert event["payload"]["rung"] == "cache"


def test_a_streamed_answer_goes_through_a_pipe_and_a_redirection(port):
    out, _, _ = run(port, "od -c /etc/hostname | wc -l; od -c /etc/hostname > /tmp/o; cat /tmp/o")
    assert out.splitlines()[0] == "2"
    assert out.splitlines()[-1] == "0000006"


def test_an_answers_operations_are_applied_before_it_is_shown(clickhouse, port):
    t0 = now()
    out, err, _status = run(port, "mkfifo /tmp/itest-made; echo $?; ls -ld /tmp/itest-made")
    assert err == "" and out.splitlines()[0] == "0"
    assert out.splitlines()[1].startswith("drwxr-xr-x") and out.rstrip().endswith("/tmp/itest-made")
    event = responded(clickhouse, t0, "mkfifo /tmp/itest-made", "answered")
    assert event["payload"]["ops_applied"] == 1
    made = poll(
        clickhouse,
        "SELECT JSONExtractString(payload, 'op') AS op FROM mirage.events FINAL "
        f"WHERE session_id = '{event['session_id']}' AND action = 'fs_change' "
        "AND JSONExtractString(payload, 'path') = '/tmp/itest-made'",
    )
    assert made[0]["op"] == "mkdir"  # reported as a command's own mkdir is

    out, _, _ = run(
        port, "ssh-keygen -q -f /tmp/itest-file; cat /tmp/itest-file; ls -l /tmp/itest-file"
    )
    assert out.splitlines()[0] == "from the answer" and out.splitlines()[1].startswith("-rw-------")


def test_operations_that_cannot_be_applied_leave_the_emulators_answer(clickhouse, port):
    t0 = now()
    out, err, _status = run(port, "mkfifo /tmp/itest-absent/x/y; echo $?; ls /tmp/itest-absent")
    assert "must never be shown" not in out + err
    assert EMULATOR in err and out.splitlines()[0] == "126"
    assert "No such file or directory" in err  # and nothing was made
    event = responded(clickhouse, t0, "mkfifo /tmp/itest-absent/x/y", "fallback")
    assert event["payload"]["reason"] == "ops:rejected" and event["outcome"] == "failure"


def test_a_line_the_filter_refuses_never_reaches_the_session(clickhouse, port):
    t0 = now()
    out, err, _ = run(port, "locale -m")
    assert "honeypot" not in (out + err).lower()
    # Its first line had been shown when the second was refused: the answer is cut there.
    assert out == "C\n"
    event = responded(clickhouse, t0, "locale -m", "cut")
    assert event["payload"]["reason"] == "filter:marker"


def test_a_first_line_that_is_late_is_a_fallback_in_time(clickhouse, port):
    t0 = now()
    began = time.monotonic()
    out, err, _status = run(port, "locale -k LC_TIME")
    took = time.monotonic() - began
    assert EMULATOR in err and out == ""
    assert took < 3.5, f"the fallback took {took:.1f} s; the first line's deadline is 1.5 s"
    event = responded(clickhouse, t0, "locale -k LC_TIME", "fallback")
    assert event["payload"]["reason"] == "deadline:first_line"


# ------------------------------------------------------------------ while an answer is pending


def test_a_program_that_fell_back_once_is_refused_for_the_next_login_too(clickhouse, port):
    # Found by the consistency probes with the live model: a late answer made the emulator
    # say the program cannot be executed, and the next login was given a working one.
    out, err, _ = run(port, "locale -k LC_TIME")  # the stand-in is late with this one
    assert EMULATOR in out + err
    t0 = now()
    out, err, _ = run(port, "locale charmap")  # which it would answer at once
    assert EMULATOR in out + err and "ANSI_X3.4-1968" not in out
    event = responded(clickhouse, t0, "locale charmap", "fallback")
    assert event["payload"]["reason"] == "refused"
    forgive()
    assert run(port, "locale charmap")[0] == "ANSI_X3.4-1968\n"


def test_ctrl_c_stops_a_streamed_answer_at_once_and_the_responder_is_told(clickhouse, port):
    t0 = now()
    shell = Shell(port)
    try:
        shell.chan.send(b"od -c /etc/hosts\n")
        deadline = time.time() + 10
        got = b""
        while b"slow 1" not in got and time.time() < deadline:
            time.sleep(0.05)
            got += shell._drain()
        assert b"slow 1" in got, got
        sent = time.monotonic()
        shell.chan.send(b"\x03")
        prompt = b""
        while b"# " not in prompt and time.monotonic() - sent < 2:
            time.sleep(0.01)
            prompt += shell._drain()
        took = time.monotonic() - sent
        assert b"^C" in prompt and b"# " in prompt
        assert took < 0.5, f"the prompt came back {took * 1000:.0f} ms after Ctrl-C"
        time.sleep(1.5)
        after = shell.run("echo still-here")
        assert "slow 8" not in (got + prompt).decode() + after and "still-here" in after
    finally:
        shell.close()
    responded(clickhouse, t0, "od -c /etc/hosts", "cancelled")
    poll(
        clickhouse,
        "SELECT 1 FROM mirage.events FINAL WHERE source = 'responder' "
        f"AND ts >= '{t0}' AND JSONExtractString(payload, 'answer_outcome') = 'cancelled'",
    )


def test_what_is_typed_meanwhile_runs_after_the_answer(port):
    shell = Shell(port)
    marker = f"typed-{uuid.uuid4().hex[:8]}"
    try:
        shell.chan.send(f"od -c /etc/shells\necho {marker}\n".encode())
        deadline = time.time() + 15
        got = b""
        while got.count(marker.encode()) < 2 and time.time() < deadline:
            time.sleep(0.1)
            got += shell._drain()
        text = got.decode(errors="replace")
        # The marker appears twice: as typed (the terminal's echo), and as echo's output.
        assert text.rindex(marker) > text.index("shells 3"), text
    finally:
        shell.close()


# ------------------------------------------------------------------ when something is down


def test_a_restarted_responder_answers_the_same_session_after_one_resync(clickhouse, port):
    t0 = now()
    shell = Shell(port)
    try:
        shell.run("mkdir /tmp/before-restart; mkfifo /tmp/itest-made", wait=2.0)
        responder_up(STUB)  # the responder forgets every session
        answer = shell.run("od -c /etc/hostname", wait=3.0)
        assert "0000006" in answer, answer
    finally:
        shell.close()
    event = responded(clickhouse, t0, "od -c /etc/hostname", "answered")
    records = poll(
        clickhouse,
        "SELECT JSONExtractString(payload, 'answer_outcome') AS how FROM mirage.events FINAL "
        f"WHERE source = 'responder' AND session_id = '{event['session_id']}' "
        f"AND JSONExtractString(payload, 'request_id') = '{event['payload']['request_id']}'",
        lambda rows: len(rows) >= 2,
    )
    assert sorted(r["how"] for r in records) == ["end", "resync"]


def test_with_the_model_server_stopped_every_answer_falls_back_in_time(clickhouse, port):
    """Within one health check of the model server stopping, the decoy has learned that no
    answer can be made and stops asking (the next test). This one is about the seconds before
    it has learned: an answer asked for then falls back, in time, and is recorded as one.

    Whether a command lands in those seconds depends on when the decoy last checked, which a
    test cannot see. So the server is killed just after the decoy is known to have seen it
    healthy, and a try in which the decoy had already learned (the policy was not asked for
    `respond`) is made again. Stopping the server gently and running the command once, as
    this test first did, failed about one full run in two."""
    command = "locale language"
    try:
        for _ in range(4):
            compose("up", "-d", "--wait", "llm-stub", env=STUB)
            time.sleep(HEALTH_S + 2)  # the decoy's check since then found it healthy
            compose("kill", "llm-stub")
            t0 = now()
            began = time.monotonic()
            out, err, _ = run(port, command)
            took = time.monotonic() - began
            # Either way the session sees the emulator's answer, and promptly.
            assert EMULATOR in err and out == ""
            assert took < 3.0, f"the fallback took {took:.1f} s"
            decided = poll(
                clickhouse,
                "SELECT JSONExtractString(policy, 'action') AS policy_action "
                f"FROM mirage.events FINAL WHERE source = 'policy' AND ts >= '{t0}' "
                f"AND JSONExtractString(payload, 'command') = '{command}' ORDER BY ts DESC",
            )
            if decided[0]["policy_action"] != "respond":
                continue  # the decoy had learned already: not the case under test
            event = responded(clickhouse, t0, command, "fallback")
            assert event["payload"]["reason"] == "backend"
            return
        pytest.fail("in four tries the decoy had learned of the stopped server before the command")
    finally:
        compose("up", "-d", "--wait", "llm-stub", env=STUB)


def test_with_the_responder_stopped_the_decoy_stops_offering_it(clickhouse, port):
    compose("stop", "responder")
    try:
        time.sleep(HEALTH_S + 3)  # the decoy's next check fails
        t0 = now()
        out, err, _ = run(port, "locale territory")
        assert EMULATOR in err and out == ""
        # The policy was told the decoy could not, and did not ask: no respond decision.
        rows = poll(
            clickhouse,
            "SELECT JSONExtractString(policy, 'action') AS policy_action, "
            "JSONExtractRaw(payload, 'request') AS request "
            f"FROM mirage.events FINAL WHERE source = 'policy' AND ts >= '{t0}' "
            "AND JSONExtractString(payload, 'command') = 'locale territory'",
        )
        assert rows[0]["policy_action"] == "allow"
        assert "respond" not in json.loads(rows[0]["request"])["supports"]
    finally:
        responder_up(STUB)
    # And when it is back, it is offered again.
    assert run(port, "locale territory")[0] == "United States\n"
