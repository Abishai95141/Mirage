"""The fidelity check (phase 3 spec, section 5), on outputs of the kinds it has to judge."""

from __future__ import annotations

import pytest

from mirage_profiles.fidelity import Fact, Observed, check, mask

FREE_REF = """\
               total        used        free      shared  buff/cache   available
Mem:           15912        7204         412         391        8683        8707
Swap:           4095         212        3883
"""
FREE_OK = """\
               total        used        free      shared  buff/cache   available
Mem:            3915         611        2380           1        1085        3304
Swap:              0           0           0
"""
CPUINFO_REF = """\
processor\t: 0
vendor_id\t: AuthenticAMD
model name\t: AMD Ryzen 5 5600 6-Core Processor
cpu MHz\t\t: 3493.286
flags\t\t: fpu vme de pse

processor\t: 1
vendor_id\t: AuthenticAMD
model name\t: AMD Ryzen 5 5600 6-Core Processor
cpu MHz\t\t: 3493.286
flags\t\t: fpu vme de pse
"""
CPUINFO_ONE = """\
processor\t: 0
vendor_id\t: AuthenticAMD
model name\t: AMD EPYC-Milan Processor
cpu MHz\t\t: 2794.748
flags\t\t: fpu vme de pse
"""
DF_REF = """\
Filesystem      Size  Used Avail Use% Mounted on
udev            7.8G     0  7.8G   0% /dev
/dev/sda5       457G  214G  220G  50% /
tmpfs           1.6G  2.1M  1.6G   1% /run
"""
PS_REF = """\
    PID TTY          TIME CMD
      1 ?        00:00:02 systemd
    812 ?        00:00:00 sshd: root@pts/0
   1204 pts/0    00:00:00 bash
"""


def test_the_mask_hides_what_varies_and_keeps_the_rest():
    assert mask("up 3 days,  4:12,  1 user,  load average: 0.08, 0.03, 0.01") == (
        "up <n> days, <time>, <n> user, load average: <n>, <n>, <n>"
    )
    assert mask("inet 10.0.2.15/24 brd 10.0.2.255 scope global ens3") == (
        "inet <ip> brd <ip> scope global ens3"
    )
    assert mask("link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff") == (
        "link/ether <mac> brd <mac>"
    )
    assert mask("Linux web01 6.1.0-37-amd64 #1 SMP Debian 6.1.140-1 (2025-05-22) x86_64") == (
        "Linux web01 <n>.<n>-<n>-amd64 #<n> SMP Debian <n>.<n>-<n> (<date>) x86_64"
    )
    assert mask("-rw-r--r-- 1 root root 4.0K Nov 15 22:15 notes") == (
        "-rw-r--r-- <n> root root <size> <date> notes"
    )
    assert mask("Sat Nov 15 22:15:03 IST 2026") == "<date>"
    assert mask("inet6 fe80::5054:ff:fe12:3456/64 scope link") == "inet6 <ip> scope link"
    assert mask("inet6 2001:db8:12:34:5054:ff:fe12:3456/64") == "inet6 <ip>"
    assert mask("22:15:03 up 1 day") == "<time> up <n> day"
    assert mask("machine-id 4f6c1d9a0b7e4c3d8a2f5e6b7c8d9e0f") == "machine-id <hex>"
    assert mask("MemTotal:       16303428 kB") == "MemTotal: <size>"
    # Words that only look like hex are left alone: no digit, or no letter, no mask.
    assert mask("decade facade 123456") == "decade facade <n>"


def test_a_table_passes_with_other_numbers_and_fails_with_another_header():
    assert check(Observed(FREE_OK), Observed(FREE_REF)).ok
    verdict = check(Observed(FREE_OK.replace("buff/cache", "buffers")), Observed(FREE_REF))
    assert not verdict.ok and verdict.shape == "table" and "header" in verdict.problems[0]
    # A row with a column too few is not a row of this table.
    short = FREE_OK.replace("Swap:              0           0           0", "Swap: 0")
    assert "rows of [2] fields" in check(Observed(short), Observed(FREE_REF)).problems[0]


def test_a_table_may_have_more_or_fewer_rows():
    more = DF_REF + "/dev/sdb1        98G   12G   81G  13% /srv\n"
    assert check(Observed(more), Observed(DF_REF)).ok
    fewer = "\n".join(DF_REF.splitlines()[:3]) + "\n"
    assert check(Observed(fewer), Observed(DF_REF)).ok


def test_a_table_whose_last_column_is_free_text_takes_longer_rows():
    more = PS_REF + "   1310 pts/0    00:00:00 ps -o pid,tty,time,cmd --sort start_time\n"
    assert check(Observed(more), Observed(PS_REF)).ok
    assert not check(
        Observed(PS_REF.replace("   1204 pts/0    00:00:00 bash", "1204")), Observed(PS_REF)
    ).ok


def test_key_and_value_output_needs_the_same_keys_in_the_same_order():
    # One processor where the reference has two: the same block, so the same shape.
    assert check(Observed(CPUINFO_ONE), Observed(CPUINFO_REF)).ok
    dropped = CPUINFO_ONE.replace("cpu MHz\t\t: 2794.748\n", "")
    verdict = check(Observed(dropped), Observed(CPUINFO_REF))
    assert verdict.shape == "keyvalue" and verdict.problems == ["missing keys ['cpu MHz']"]
    added = CPUINFO_ONE + "bogomips\t: 5589.49\n"
    assert (
        "keys the reference lacks ['bogomips']"
        in check(Observed(added), Observed(CPUINFO_REF)).problems[0]
    )
    swapped = "\n".join(reversed(CPUINFO_ONE.splitlines())) + "\n"
    assert "different order" in check(Observed(swapped), Observed(CPUINFO_REF)).problems[0]
    assert (
        "not key and value lines" in check(Observed("x86_64\n"), Observed(CPUINFO_REF)).problems[0]
    )


def test_equals_sign_files_are_key_and_value_too_and_the_delimiter_counts():
    ref = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\n'
    assert check(Observed(ref.replace("12", "13")), Observed(ref)).ok
    colons = ref.replace("=", ": ")
    assert "keys end in ':'" in check(Observed(colons), Observed(ref)).problems[0]


def test_an_error_must_be_the_same_error():
    ref = Observed(
        stderr="ls: cannot access '/nonexistent': No such file or directory\n", exit_code=2
    )
    assert check(ref, ref).ok and check(ref, ref).shape == "error"
    other = Observed(stderr="ls: /nonexistent: not found\n", exit_code=2)
    assert check(other, ref).problems == ["the error text differs from the reference's"]
    assert "exit code 1" in check(Observed(stderr=ref.stderr, exit_code=1), ref).problems[0]
    # The same words on the wrong stream are a different answer.
    wrong_stream = Observed(stdout=ref.stderr, exit_code=2)
    assert any("output on stdout" in p for p in check(wrong_stream, ref).problems)


def test_a_message_on_stderr_is_compared_as_text_whatever_the_exit_code():
    # `nginx -v` says its version on stderr and exits 0: still a fixed message.
    ref = Observed(stderr="nginx version: nginx/1.22.1\n")
    assert check(ref, ref).ok and check(ref, ref).shape == "error"
    assert check(Observed(stderr="nginx version: nginx/1.24.0\n"), ref).ok  # numbers are masked
    assert check(Observed(stderr="nginx/1.22.1\n"), ref).problems == [
        "the error text differs from the reference's"
    ]
    assert not check(Observed(stdout=ref.stderr), ref).ok


def test_free_text_is_held_to_its_length():
    ref = Observed("Linux build 6.17.0-6-generic #6-Ubuntu SMP x86_64 GNU/Linux\n")
    assert check(Observed("Linux web01 6.1.0-37-amd64 #1 SMP x86_64 GNU/Linux\n"), ref).ok
    assert "words on its line" in check(Observed("Linux\n"), ref).problems[0]
    long = Observed("\n".join(f"line {i}" for i in range(20)) + "\n")
    assert check(Observed("\n".join(f"row {i}" for i in range(23)) + "\n"), long).ok
    assert (
        "30 lines, the reference has 20"
        in check(Observed("\n".join(f"row {i}" for i in range(30)) + "\n"), long).problems[0]
    )


def test_a_command_that_prints_nothing_must_print_nothing():
    assert check(Observed(), Observed()).ok and check(Observed(), Observed()).shape == "empty"
    assert not check(Observed("done\n"), Observed()).ok


@pytest.mark.parametrize(
    ("candidate", "problem"),
    [
        (CPUINFO_ONE, None),
        (CPUINFO_ONE.replace("AMD EPYC-Milan Processor", "Intel Xeon"), "is missing where"),
        (CPUINFO_ONE + "\n" + CPUINFO_REF.split("\n\n")[0] + "\n", "is still there"),
    ],
)
def test_a_fact_the_class_fixes_must_be_the_class_s(candidate, problem):
    facts = [Fact("cpu model", "AMD Ryzen 5 5600 6-Core Processor", "AMD EPYC-Milan Processor")]
    verdict = check(Observed(candidate), Observed(CPUINFO_REF), facts)
    assert verdict.ok if problem is None else any(problem in p for p in verdict.problems)


def test_a_fact_the_reference_does_not_show_is_not_asked_for():
    facts = [Fact("hostname", "build-host", "web01")]
    assert check(Observed(FREE_OK), Observed(FREE_REF), facts).ok
    # And a value that is part of the expected one is not a leak of the reference's.
    ref, cand = Observed("host: web\n"), Observed("host: web01\n")
    assert check(cand, ref, [Fact("hostname", "web", "web01")]).ok


def test_a_free_text_last_column_may_be_one_word_where_the_reference_has_none():
    header = "UID          PID    PPID  C STIME TTY          TIME CMD\n"
    reference = Observed(
        header
        + "root           1       0  0 07:08 ?        00:00:00 /bin/sh /entrypoint.sh\n"
        + "root          30       1  0 07:08 ?        00:00:00 sshd: /usr/sbin/sshd [listener]\n"
    )
    machine = Observed(
        header
        + "root           1       0  0 Nov14 ?        00:00:03 /sbin/init\n"
        + "root           2       0  0 Nov14 ?        00:00:00 [kthreadd]\n"
    )
    assert check(machine, reference).ok
    # A row shorter than the header is still not a row of this table.
    short = Observed(header + "root           1       0  0 Nov14 ?        00:00:03\n")
    verdict = check(short, reference)
    assert not verdict.ok and "rows of [7] fields" in verdict.problems[0]
