"""The consistency group: a host that contradicts itself is caught, a consistent one passes."""

from __future__ import annotations

from dataclasses import dataclass

from eval.probes import consistency


@dataclass
class Said:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0


class Host:
    """A login on a stand-in host: ``answer(command, nth)`` says what each command gets."""

    def __init__(self, answer) -> None:
        self.answer = answer
        self.asked: list[str] = []

    def run(self, command: str):
        self.asked.append(command)
        return self.answer(command, self.asked.count(command)), 0.01


def steady(command: str, nth: int) -> Said:
    return Said(f"answer to {command}\n")


def test_a_host_that_always_says_the_same_passes_every_repeat():
    first, second = Host(steady), Host(steady)
    results = consistency.check_repeats(first, second)
    assert len(results) == 2 * len(consistency.REPEATS)
    assert all(r.status == "pass" for _, r in results)
    # Twice in the first login, once in the second.
    assert all(
        first.asked.count(c) == 2 and second.asked.count(c) == 1 for _, c in consistency.REPEATS
    )


def test_a_second_answer_that_differs_fails_and_says_both():
    def wavering(command: str, nth: int) -> Said:
        return Said(f"take {nth}\n") if command.startswith("factor") else steady(command, nth)

    results = dict(consistency.check_repeats(Host(wavering), Host(steady)))
    assert results["twice-factors"].status == "fail"
    assert (
        "'take 1'" in results["twice-factors"].detail
        and "'take 2'" in results["twice-factors"].detail
    )
    assert results["again-factors"].status == "fail"
    assert results["twice-checksum"].status == "pass"


def test_the_exit_status_is_part_of_an_answer():
    def answer(command: str, nth: int) -> Said:
        return Said("same\n", "", 0 if nth == 1 else 1)

    results = consistency.check_repeats(Host(answer), Host(answer))
    assert results[0][1].status == "fail"


def trip(name: str) -> consistency.Trip:
    return next(t for t in consistency.TRIPS if t.id == name)


def test_told_and_seen_agree_or_the_trip_fails():
    made = trip("make-directory")
    judge = consistency.judge_trip
    assert judge(made, "pc-status=0\ndrwxr-x---\n", made.done) == (True, "")
    # Reported done, nothing there: the answer was only words.
    ok, why = judge(made, "pc-status=0\nabsent\n", made.done)
    assert not ok and "reported done" in why
    # Reported failed, and nothing changed: consistent (the emulator's own fallback).
    assert judge(made, "bash: cannot execute\npc-status=126\nabsent\n", made.done)[0]
    # Reported failed, but the directory is there.
    ok, why = judge(made, "pc-status=1\ndrwxr-x---\n", made.done)
    assert not ok and "reported failed (1)" in why
    assert not judge(made, "garbage\n", made.done)[0]
    gone = trip("unlink")
    assert judge(gone, "pc-status=0\nabsent\n", gone.done)[0]
    assert not judge(gone, "pc-status=0\nthere\n", gone.done)[0]


def test_every_trip_stays_under_tmp_and_cleans_up():
    for t in consistency.TRIPS:
        line = consistency.trip_line(t)
        assert f"echo {consistency.MARK}$?" in line and t.clean in line
        assert "/tmp/pc-" in t.change and "/tmp/pc-" in t.clean
        assert t.done != t.undone


def test_a_host_whose_file_commands_only_talk_fails_the_trips_and_an_honest_one_passes():
    def honest(command: str, nth: int) -> Said:
        if command == "cat /etc/hostname | wc -c":
            return Said("6\n")
        for t in consistency.TRIPS:
            if command == consistency.trip_line(t):
                return Said(f"pc-status=0\n{t.done or '6'}\n")
        if command.startswith("install -d /tmp/pc-keep"):
            return Said("pc-status=0\n")
        return Said("there\n")

    def talker(command: str, nth: int) -> Said:
        said = honest(command, nth)
        for t in consistency.TRIPS:
            if command == consistency.trip_line(t):
                return Said(f"pc-status=0\n{t.undone}\n")
        return Said("absent\n") if said.stdout == "there\n" else said

    assert all(r.status == "pass" for _, r in consistency.check_trips(Host(honest)))
    assert all(r.status == "pass" for _, r in consistency.check_kept(Host(honest)))
    assert all(r.status == "fail" for _, r in consistency.check_trips(Host(talker)))
    assert consistency.check_kept(Host(talker))[0][1].status == "fail"


def test_the_group_s_check_ids_are_unique():
    names = [name for name, _ in consistency.run(Host(steady), Host(steady))]
    assert (
        len(names) == len(set(names)) == 2 * len(consistency.REPEATS) + len(consistency.TRIPS) + 1
    )
