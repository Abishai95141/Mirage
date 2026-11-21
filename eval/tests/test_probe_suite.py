"""The fingerprint suite's own logic (phase 3 spec 3.4): how a probe connects, how a check
gets its ID, what the known-gaps file may and may not excuse, and the comparison rules."""

from __future__ import annotations

import copy
import ipaddress
import socket
import threading

import pytest

from eval.probes import emulator, suite, transport
from eval.probes.default_tells import Result
from eval.probes.net import SIGNATURE, Target, is_probe_source, probe_source
from eval.probes.ssh_probes import BANNER_PROBES, NAME_LISTS
from mirage_lab.models import check_run_safety
from mirage_lab.net import RANGES
from mirage_profiles.fidelity import Observed

# ------------------------------------------------------------------ connecting


def test_a_target_is_host_and_port_and_keeps_being_one():
    t = Target.parse("lab-edge:2222")
    assert (t.host, t.port, t.source, str(t)) == ("lab-edge", 2222, None, "lab-edge:2222")
    assert Target.parse(t) is t
    for bad in ("lab-edge", "lab-edge:ssh", ":22"):
        with pytest.raises(ValueError):
            Target.parse(bad)


def test_a_probe_announces_a_documentation_address_and_never_a_lab_one():
    for _ in range(200):
        source = probe_source()
        assert is_probe_source(source)
        assert not any(ipaddress.ip_address(source) in net for net in RANGES.values())
    for net in RANGES.values():
        with pytest.raises(ValueError, match="documentation"):
            Target.parse("lab-edge:2222", str(net.network_address + 9))


def test_the_proxy_header_goes_first_and_names_the_source():
    server = socket.create_server(("127.0.0.1", 0))
    port = server.getsockname()[1]
    got: list[bytes] = []

    def serve() -> None:
        conn, _ = server.accept()
        with conn:
            conn.settimeout(2)
            got.append(conn.recv(4096))

    thread = threading.Thread(target=serve)
    thread.start()
    with Target.parse(f"127.0.0.1:{port}", "203.0.113.7").connect(2) as sock:
        sock.sendall(b"")
    thread.join(3)
    server.close()
    header = got[0]
    assert header.startswith(SIGNATURE + b"\x21\x11")
    assert socket.inet_aton("203.0.113.7") == header[16:20]
    assert socket.inet_aton("127.0.0.1") == header[20:24]
    assert int.from_bytes(header[26:28], "big") == port


def test_without_a_source_nothing_is_sent_ahead():
    server = socket.create_server(("127.0.0.1", 0))
    port = server.getsockname()[1]
    with Target.parse(f"127.0.0.1:{port}").connect(2) as sock:
        conn, _ = server.accept()
        sock.sendall(b"hello")
        assert conn.recv(16) == b"hello"
        conn.close()
    server.close()


# ------------------------------------------------------------------ IDs and known gaps


def checks(**status: bool) -> suite.Report:
    report = suite.Report()
    for cid, ok in status.items():
        cid = cid.replace("__", ".")
        report.checks.append(suite.Check(cid, cid.split(".", 1)[0], cid, ok))
    return report


def test_a_check_s_id_is_its_group_protocol_and_text():
    made = suite.from_results(
        "tells", [Result("ssh", "HASSH-server equals OpenSSH 9.2p1", "gap", "x")]
    )
    assert made[0].id == "tells.ssh.hassh-server-equals-openssh-9-2p1"
    assert made[0].ok is False  # a probe's own "gap" is a failure here: the file excuses it
    named = suite.from_pairs("emulator", [("ls-root", Result("ssh", "`ls /`", "pass"))])
    assert (named[0].id, named[0].ok) == ("emulator.ls-root", True)


def test_an_unlisted_failure_fails_the_run_and_a_listed_one_does_not():
    report = checks(tells__a=True, tells__b=False)
    assert not suite.judge(report, {}).ok
    verdict = suite.judge(report, {"tells.b": {"reason": "r", "owner": "o"}})
    assert verdict.ok and [c.id for c in verdict.known] == ["tells.b"]


def test_a_listed_check_that_passes_fails_the_run():
    verdict = suite.judge(checks(tells__a=True), {"tells.a": {"reason": "r", "owner": "o"}})
    assert not verdict.ok and [c.id for c in verdict.stale] == ["tells.a"]


def test_an_entry_naming_no_check_fails_the_run_only_if_its_group_ran():
    gaps = {
        "tells.gone": {"reason": "r", "owner": "o"},
        "timing.elsewhere": {"reason": "r", "owner": "o"},
    }
    verdict = suite.judge(checks(tells__a=True), gaps)
    assert not verdict.ok and verdict.missing == ["tells.gone"]
    # The timing group did not run, so its entry cannot be judged and is left alone.
    assert suite.judge(checks(tells__a=True), {"timing.elsewhere": gaps["timing.elsewhere"]}).ok


def test_two_checks_may_not_share_an_id():
    report = checks(tells__a=True)
    report.checks.append(suite.Check("tells.a", "tells", "again", True))
    with pytest.raises(ValueError, match="share an ID"):
        suite.judge(report, {})


def test_the_gaps_file_needs_a_reason_and_an_owner(tmp_path):
    path = tmp_path / "gaps.yaml"
    path.write_text("gaps:\n  - {id: tells.a, reason: because, owner: D12}\n")
    assert suite.load_gaps(path) == {"tells.a": {"reason": "because", "owner": "D12"}}
    path.write_text("gaps:\n  - {id: tells.a, reason: because}\n")
    with pytest.raises(ValueError, match="owner"):
        suite.load_gaps(path)
    path.write_text(
        "gaps:\n  - {id: tells.a, reason: r, owner: o}\n  - {id: tells.a, reason: r, owner: o}\n"
    )
    with pytest.raises(ValueError, match="twice"):
        suite.load_gaps(path)


def test_the_committed_gaps_file_loads():
    for entry in suite.load_gaps().values():
        assert len(entry["reason"]) > 20, "a gap's reason says what is wrong, in a sentence"


def test_a_group_that_needs_the_reference_host_is_skipped_without_one(tmp_path):
    (tmp_path / "cowrie").mkdir()
    (tmp_path / "cowrie/userdb.txt").write_text("root:x:secret\n")
    where = suite.Where(Target("127.0.0.1", 1), None, None, None, None, tmp_path)
    report = suite.run(where, ("transport", "emulator", "timing"))
    assert report.checks == [] and set(report.skipped) == {"transport", "emulator", "timing"}


# ------------------------------------------------------------------ transport


def probe_result() -> dict:
    return {
        "kexinit": {
            "banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7",
            "banner_line_ending": "CRLF",
            "kexinit_before_client_id": False,
            "padding_all_zero": True,
            "first_kex_packet_follows": 0,
            "hassh_server": "aa",
            "algorithms": {name: ["a", "b"] for name in NAME_LISTS},
        },
        "banners": {
            name: {"reply_text": "", "closed": False, "kexinit_sent": True}
            for name in BANNER_PROBES
        },
    }


def test_two_servers_that_behave_alike_pass_every_transport_check():
    pairs = transport.compare(probe_result(), probe_result())
    assert len(pairs) == 6 + len(NAME_LISTS) + len(BANNER_PROBES)
    assert all(r.status == "pass" for _, r in pairs)
    assert len({suffix for suffix, _ in pairs}) == len(pairs)


def test_each_transport_difference_fails_its_own_check():
    decoy = copy.deepcopy(probe_result())
    decoy["kexinit"]["hassh_server"] = "bb"
    decoy["kexinit"]["algorithms"]["mac_s2c"] = ["b", "a"]
    decoy["banners"]["version_2.2"] = {
        "reply_text": "Protocol major versions differ.\\x0a",
        "closed": True,
        "kexinit_sent": False,
    }
    failed = {s: r for s, r in transport.compare(probe_result(), decoy) if r.status == "fail"}
    assert set(failed) == {"hassh-server", "algorithms-mac-s2c", "reply-version-2-2"}
    assert "other order" in failed["algorithms-mac-s2c"].detail
    assert "Protocol major versions differ" in failed["reply-version-2-2"].detail


# ------------------------------------------------------------------ the command list


def test_the_command_list_loads_and_every_line_may_run_on_a_real_host():
    commands = emulator.load_commands()
    assert len(commands) >= 60
    assert len({c.id for c in commands}) == len(commands)
    # A line break inside a command is deliberate in these (bash acts on lines: what a
    # refused expansion drops, where a function's error is said to be) and a slip anywhere else.
    several_lines = {
        "sh-bad-substitution-next-line",
        "sh-cond-malformed-next-line",
        "sh-function-error-line",
        "sh-here-document",
    }
    for command in commands:
        assert check_run_safety(command.cmd) == [], command.id
        assert ("\n" in command.cmd) == (command.id in several_lines), command.id
    timed = {c.time for c in commands if c.time}
    assert {"builtin", "read", "list", "report", "library", "missing"} <= timed


def test_a_command_list_with_a_stray_key_or_a_repeated_id_is_refused(tmp_path):
    path = tmp_path / "commands.yaml"
    path.write_text("commands:\n  - {id: a, cmd: id, expect: x}\n")
    with pytest.raises(ValueError, match="unknown keys"):
        emulator.load_commands(path)
    path.write_text("commands:\n  - {id: a, cmd: id}\n  - {id: a, cmd: pwd}\n")
    with pytest.raises(ValueError, match="twice"):
        emulator.load_commands(path)


def test_an_answer_like_the_reference_s_passes_and_a_different_one_says_how():
    command = emulator.Command("id", "id")
    want = Observed("uid=0(root) gid=0(root) groups=0(root)\n", "", 0)
    assert emulator.judge(command, want, want, ()).status == "pass"
    wrong = emulator.judge(command, Observed("", "bash: id: command not found\n", 127), want, ())
    assert wrong.status == "fail" and "exit code 127" in wrong.detail
    assert "command not found" in wrong.detail


def test_a_pattern_the_two_hosts_disagree_on_fails_the_check():
    command = emulator.Command("glob", "echo /etc/host*", same=(r"\*",))
    real = Observed("/etc/host.conf /etc/hostname /etc/hosts\n", "", 0)
    literal = Observed("/etc/host*\n", "", 0)
    result = emulator.judge(command, literal, real, ())
    assert result.status == "fail" and "does not match the reference" in result.detail
    assert emulator.judge(command, real, real, ()).status == "pass"


def test_an_exact_command_must_match_line_for_line_after_masking():
    loose = emulator.Command("id", "id nobody")
    exact = emulator.Command("id", "id nobody", exact=True)
    real = Observed("uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)\n", "", 0)
    wrong = Observed("uid=65534(nobody) gid=65534(nobody) groups=65534(nobody)\n", "", 0)
    other = Observed("uid=1001(nobody) gid=1001(nogroup) groups=1001(nogroup)\n", "", 0)
    assert emulator.judge(loose, wrong, real, ()).status == "pass"  # the shape check alone
    caught = emulator.judge(exact, wrong, real, ())
    assert caught.status == "fail" and "stdout line 1" in caught.detail
    assert emulator.judge(exact, other, real, ()).status == "pass"  # numbers are masked
    # A date masks to the same thing in either format: that takes a pattern, not `exact`.
    month = Observed("-rw-r--r-- 1 root root 1032 Nov 17 07:08 /etc/passwd\n", "", 0)
    iso = Observed("-rw-r--r-- 1 root root 1032 2026-11-17 07:08 /etc/passwd\n", "", 0)
    listing = emulator.Command("ls", "ls -l /etc/passwd", exact=True)
    assert emulator.judge(listing, iso, month, ()).status == "pass"
    dated = emulator.Command("ls", "ls -l /etc/passwd", same=(r"[A-Z][a-z]{2} [ \d]\d \d\d:\d\d",))
    assert emulator.judge(dated, iso, month, ()).status == "fail"


def test_a_channel_with_no_exit_status_fails_and_a_silent_reference_proves_nothing():
    command = emulator.Command("id", "id")
    want = Observed("uid=0(root)\n", "", 0)
    dead = Observed("", "<channel: closed>", emulator.NO_STATUS)
    assert "no exit status" in emulator.judge(command, dead, want, ()).detail
    unknown = emulator.judge(command, want, dead, ())
    assert unknown.status == "fail" and "the reference host" in unknown.detail


# ------------------------------------------------------------------ response time


@pytest.mark.parametrize(
    ("decoy", "reference", "ok"),
    [
        (10.0, 10.0, True),
        (39.0, 10.0, True),  # within 30 ms
        (45.0, 10.0, False),  # 35 ms more, and over twice
        (190.0, 100.0, True),  # within a factor of two
        (210.0, 100.0, False),
        (55.0, 100.0, True),
        (40.0, 100.0, False),  # more than twice as fast is a tell too
    ],
)
def test_the_response_time_rule(decoy, reference, ok):
    assert emulator.within(decoy, reference) is ok


class Fixed:
    """A host that answers every command at once and reports a fixed time."""

    def __init__(self, seconds: float) -> None:
        self.seconds, self.calls = seconds, 0

    def run(self, command: str):
        self.calls += 1
        return Observed("x\n", "", 0), self.seconds


def test_timing_runs_each_timed_command_on_both_hosts_and_compares_medians():
    commands = [
        emulator.Command("pwd", "pwd", time="builtin"),
        emulator.Command("id", "id"),
        emulator.Command("ls", "ls /", time="list"),
    ]
    decoy, reference = Fixed(0.300), Fixed(0.010)
    pairs, timings = emulator.check_timing(decoy, reference, commands, samples=5)
    assert [s for s, _ in pairs] == ["pwd", "ls"]
    assert all(r.status == "fail" and "300.0 ms" in r.detail for _, r in pairs)
    assert decoy.calls == reference.calls == 2 * (5 + 1)  # one unrecorded run first
    assert [len(t.decoy_ms) for t in timings] == [5, 5]
    alike, _ = emulator.check_timing(Fixed(0.012), Fixed(0.010), commands, samples=3)
    assert all(r.status == "pass" for _, r in alike)


# ------------------------------------------------------------------ fleet


class Host:
    """A logged-in host that answers from a table; anything else is 'command not found'."""

    def __init__(self, answers: dict[str, str]) -> None:
        self.answers = answers

    def run(self, command: str):
        if command in self.answers:
            return Observed(self.answers[command], "", 0), 0.0
        return Observed("", "bash: command not found\n", 127), 0.0

    def close(self) -> None:
        pass


def deployment(n: int, **change: str) -> Host:
    from eval.probes import fleet

    answers = {cmd: f"{what} of host {n}\n" for _, cmd, what in fleet.IDENTITY}
    answers |= {cmd: f"{what} of the image\n" for _, cmd, what in fleet.IMAGE}
    answers |= {cmd: "the class's\n" for _, cmd, _ in fleet.HARDWARE}
    return Host(answers | change)


def test_two_deployments_that_differ_and_agree_where_real_hosts_do_pass():
    from eval.probes import fleet

    pairs = fleet.compare(deployment(1), deployment(2), same_class=True)
    assert len(pairs) == len(fleet.IDENTITY) + len(fleet.IMAGE) + len(fleet.HARDWARE)
    assert all(r.status == "pass" for _, r in pairs), [s for s, r in pairs if r.status != "pass"]
    assert len({s for s, _ in pairs}) == len(pairs)


def test_a_shared_identity_value_fails_its_check_and_says_what_is_shared():
    from eval.probes import fleet

    shared = {"echo $SSH_CONNECTION | cut -d' ' -f3": "192.168.0.1\n"}
    failed = {
        s: r
        for s, r in fleet.compare(deployment(1, **shared), deployment(2, **shared), True)
        if r.status == "fail"
    }
    assert set(failed) == {"differs-address"}
    assert "192.168.0.1" in failed["differs-address"].detail


def test_an_identity_command_with_no_answer_proves_nothing_and_fails():
    from eval.probes import fleet

    one, two = deployment(1), deployment(2)
    del one.answers["blkid"], two.answers["blkid"]
    failed = {s for s, r in fleet.compare(one, two, True) if r.status == "fail"}
    assert failed == {"differs-disk-ids"}


def test_a_difference_in_what_the_image_fixes_fails_and_shows_the_line():
    from eval.probes import fleet

    other = deployment(2, **{"uname -r": "6.1.0-99-amd64\n"})
    failed = {s: r for s, r in fleet.compare(deployment(1), other, True) if r.status == "fail"}
    assert set(failed) == {"same-kernel-release"}
    assert "line 1" in failed["same-kernel-release"].detail


def test_hardware_answers_agree_exactly_when_the_classes_do():
    from eval.probes import fleet

    alike = fleet.compare(deployment(1), deployment(2), same_class=False)
    assert {s for s, r in alike if r.status == "fail"} == {"hardware-processors", "hardware-cpu"}
    bigger = deployment(2, nproc="4\n", lscpu="another CPU\n")
    assert all(r.status == "pass" for _, r in fleet.compare(deployment(1), bigger, False))
    assert {s for s, r in fleet.compare(deployment(1), bigger, True) if r.status == "fail"} == {
        "hardware-processors",
        "hardware-cpu",
    }
    # With no hardware class on one side there is nothing to hold the answers against.
    none = fleet.compare(deployment(1), bigger, same_class=None)
    assert not any(s.startswith("hardware-") for s, _ in none)


def test_the_fleet_group_is_skipped_without_a_second_deployment(tmp_path):
    (tmp_path / "cowrie").mkdir()
    (tmp_path / "cowrie/userdb.txt").write_text("root:x:secret\n")
    where = suite.Where(Target("127.0.0.1", 1), None, None, None, None, tmp_path)
    report = suite.run(where, ("fleet",))
    assert report.checks == [] and "second deployment" in report.skipped["fleet"]
