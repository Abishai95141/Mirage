"""The state manager (phase 3 spec 3.1): the mirror built from the decoy's journal, and the
validation of the operations a model proposes."""

from __future__ import annotations

import pytest
from mirage_responder.state import (
    SESSION_FILES,
    SESSION_PROCESSES,
    SESSION_WRITE_BYTES,
    Rejected,
    Session,
    Sessions,
)

from mirage_schema.ops import parse_ops
from mirage_schema.respond import FsEntry, JournalEntry, RespondRequest


def request(**over) -> RespondRequest:
    body = {
        "request_id": "r1",
        "session_id": "s1",
        "deployment_id": "web-db-1",
        "user": "root",
        "uid": 0,
        "cwd": "/root",
        "argv": ["stat", "/tmp/a"],
        "input": "stat /tmp/a",
        "budget": {"max_tokens": 400, "deadline_ms": 10000},
    }
    return RespondRequest.model_validate(body | over)


def entry(seq: int, op: str, **fields) -> JournalEntry:
    return JournalEntry(seq=seq, op=op, **fields)


def slice_(*entries: tuple) -> list[FsEntry]:
    out = []
    for path, kind, *rest in entries:
        mode, uid = [*rest, None, None][:2]
        out.append(FsEntry(path=path, type=kind, mode=mode, uid=uid, gid=uid))
    return out


TMP = slice_(("/tmp", "dir", 0o1777, 0), ("/root", "dir", 0o700, 0))
nothing = lambda _path: False  # noqa: E731 - no planted tokens in most of these tests


def session(uid: int = 0) -> Session:
    return Session(profile_id="web-db-1", user="root" if uid == 0 else "caleb", uid=uid, gid=uid)


# ------------------------------------------------------------------ the journal


def test_the_mirror_follows_the_journal():
    s = session()
    s.fold(
        1,
        [
            entry(1, "mkdir", path="/tmp/d", mode=0o755, uid=0),
            entry(2, "create", path="/tmp/d/f", mode=0o644, size=12, uid=0),
            entry(3, "chmod", path="/tmp/d/f", mode=0o600),
            entry(4, "rename", path="/tmp/d/f", new_path="/tmp/d/g"),
            entry(5, "cd", path="/tmp/d"),
            entry(6, "setenv", name="EDITOR", value="vi"),
            entry(7, "proc_start", pid=4242, args="sleep 600"),
        ],
    )
    assert s.journal_seq == 7
    assert s.mirror["/tmp/d"].type == "dir"
    assert s.mirror["/tmp/d/f"].type == "missing"
    assert (s.mirror["/tmp/d/g"].type, s.mirror["/tmp/d/g"].mode) == ("file", 0o600)
    assert s.cwd == "/tmp/d" and s.env == {"EDITOR": "vi"}
    assert list(s.processes) == [4242] and s.processes[4242].args == "sleep 600"
    s.fold(
        8,
        [
            entry(8, "remove", path="/tmp/d"),
            entry(9, "unsetenv", name="EDITOR"),
            entry(10, "proc_end", pid=4242),
        ],
    )
    assert s.mirror["/tmp/d"].type == "missing" and "/tmp/d/g" not in s.mirror
    assert s.env == {} and s.processes == {}


def test_a_journal_that_overlaps_is_not_folded_twice_and_one_from_the_start_replaces_all():
    s = session()
    s.fold(
        1, [entry(1, "create", path="/tmp/a", size=5), entry(2, "create", path="/tmp/b", size=5)]
    )
    assert (s.bytes_written, s.files_made) == (10, 2)
    s.fold(
        2, [entry(2, "create", path="/tmp/b", size=5), entry(3, "create", path="/tmp/c", size=5)]
    )
    assert (s.journal_seq, s.bytes_written, s.files_made) == (3, 15, 3)
    s.fold(1, [entry(1, "create", path="/tmp/z", size=1)])
    assert set(s.mirror) == {"/tmp/z"} and (s.journal_seq, s.bytes_written) == (1, 1)


def test_whether_a_journal_joins_what_is_held():
    s = session()
    assert s.joins(1)  # from the start always does
    assert not Session("p", journal_seq=0).joins(3)  # a gap: entries 1 and 2 were never seen
    s.fold(1, [entry(1, "mkdir", path="/tmp/a"), entry(2, "mkdir", path="/tmp/b")])
    assert s.joins(3) and s.joins(2) and not s.joins(5)


# ------------------------------------------------------------------ validation


def ops(*raw: dict):
    return parse_ops(list(raw))


def test_a_file_made_in_a_directory_that_is_known_to_be_there():
    s = session()
    made = s.validate(ops({"op": "write", "path": "/tmp/note", "content": "x\n"}), TMP, nothing)
    assert [o.path for o in made] == ["/tmp/note"]


def test_operations_of_one_answer_build_on_each_other():
    s = session()
    s.validate(
        ops(
            {"op": "mkdir", "path": "/tmp/d"},
            {"op": "write", "path": "/tmp/d/f", "content": "x"},
            {"op": "rename", "path": "/tmp/d/f", "to": "/tmp/d/g"},
            {"op": "chmod", "path": "/tmp/d/g", "mode": 0o600},
            {"op": "remove", "path": "/tmp/d/g"},
            {"op": "remove", "path": "/tmp/d"},
        ),
        TMP,
        nothing,
    )


@pytest.mark.parametrize(
    ("raw", "why"),
    [
        ({"op": "write", "path": "/srv/app/x", "content": ""}, "nothing is known of the parent"),
        ({"op": "mkdir", "path": "/tmp", "mode": 0o755}, "exists"),
        ({"op": "write", "path": "/tmp", "content": ""}, "not a file"),
        ({"op": "remove", "path": "/tmp/absent"}, "nothing is known of the path"),
        ({"op": "rename", "path": "/tmp/gone", "to": "/tmp/x"}, "does not exist"),
        ({"op": "cd", "path": "/srv"}, "not a directory"),
        ({"op": "proc_end", "pid": 999}, "not a process this session started"),
        ({"op": "rename", "path": "/root", "to": "/nowhere/x"}, "new path's parent"),
    ],
)
def test_what_cannot_be_applied_is_refused_and_says_which_operation(raw, why):
    s = session()
    known = [*TMP, FsEntry(path="/tmp/gone", type="missing")]
    with pytest.raises(Rejected, match=why) as caught:
        s.validate(ops({"op": "setenv", "name": "A", "value": "b"}, raw), known, nothing)
    assert "operation 2" in str(caught.value)


def test_a_path_holding_a_planted_token_is_never_touched():
    s = session()
    known = slice_(("/var/www/html", "dir", 0o755, 0), ("/var/www/html/.env", "file", 0o644, 0))
    held = lambda path: path == "/var/www/html/.env"  # noqa: E731
    for raw in (
        {"op": "write", "path": "/var/www/html/.env", "content": "x"},
        {"op": "remove", "path": "/var/www/html/.env"},
        {"op": "chmod", "path": "/var/www/html/.env", "mode": 0o600},
        {"op": "rename", "path": "/var/www/html/.env", "to": "/var/www/html/old"},
    ):
        with pytest.raises(Rejected, match="planted token"):
            s.validate(ops(raw), known, held)
    # and nothing may be moved over it either
    known.append(FsEntry(path="/var/www/html/a", type="file", mode=0o644, uid=0))
    with pytest.raises(Rejected, match="planted token"):
        s.validate(
            ops({"op": "rename", "path": "/var/www/html/a", "to": "/var/www/html/.env"}),
            known,
            held,
        )


def test_a_user_without_the_right_is_refused_and_root_is_not():
    known = slice_(
        ("/tmp", "dir", 0o1777, 0),
        ("/etc", "dir", 0o755, 0),
        ("/etc/hosts", "file", 0o644, 0),
        ("/home/caleb", "dir", 0o755, 1000),
        ("/home/caleb/notes", "file", 0o644, 1000),
    )
    caleb = session(uid=1000)
    caleb.validate(ops({"op": "write", "path": "/tmp/x", "content": ""}), known, nothing)
    caleb.validate(
        ops({"op": "write", "path": "/home/caleb/notes", "content": "a"}), known, nothing
    )
    caleb.validate(ops({"op": "chmod", "path": "/home/caleb/notes", "mode": 0o600}), known, nothing)
    for raw, why in (
        ({"op": "write", "path": "/etc/hosts", "content": ""}, "may not write the file"),
        ({"op": "write", "path": "/etc/new", "content": ""}, "may not write there"),
        ({"op": "mkdir", "path": "/etc/d"}, "may not write there"),
        ({"op": "remove", "path": "/etc/hosts"}, "may not write there"),
        ({"op": "chmod", "path": "/etc/hosts", "mode": 0o666}, "only the owner"),
        ({"op": "chown", "path": "/home/caleb/notes", "uid": 0}, "only root"),
    ):
        with pytest.raises(Rejected, match=why):
            caleb.validate(ops(raw), known, nothing)
        session().validate(ops(raw), known, nothing)  # root may do each of them


def test_a_directory_with_something_in_it_is_not_removed():
    s = session()
    known = slice_(
        ("/tmp", "dir", 0o1777, 0), ("/tmp/d", "dir", 0o755, 0), ("/tmp/d/f", "file", 0o644, 0)
    )
    with pytest.raises(Rejected, match="not empty"):
        s.validate(ops({"op": "remove", "path": "/tmp/d"}), known, nothing)


def test_the_session_s_caps_hold_across_answers():
    s = session()
    big = "x" * 4096
    s.bytes_written = SESSION_WRITE_BYTES - 4096
    s.validate(ops({"op": "write", "path": "/tmp/a", "content": big}), TMP, nothing)
    s.bytes_written += 1
    with pytest.raises(Rejected, match="written their limit"):
        s.validate(ops({"op": "write", "path": "/tmp/a", "content": big}), TMP, nothing)
    s.bytes_written, s.files_made = 0, SESSION_FILES
    with pytest.raises(Rejected, match="limit of files"):
        s.validate(ops({"op": "write", "path": "/tmp/new", "content": ""}), TMP, nothing)
    s.files_made = 0
    for pid in range(100, 100 + SESSION_PROCESSES):
        s.fold(s.journal_seq + 1, [entry(s.journal_seq + 1, "proc_start", pid=pid, args="sleep 1")])
    with pytest.raises(Rejected, match="started their limit"):
        s.validate(ops({"op": "proc_start", "args": "sleep 2"}), TMP, nothing)
    s.validate(ops({"op": "proc_end", "pid": 100}), TMP, nothing)


def test_validating_changes_nothing():
    s = session()
    s.validate(
        ops({"op": "mkdir", "path": "/tmp/d"}, {"op": "proc_start", "args": "sleep 9"}),
        TMP,
        nothing,
    )
    assert s.mirror == {} and s.processes == {} and s.bytes_written == 0
    # The same answer validates again: nothing of the first was kept.
    s.validate(ops({"op": "mkdir", "path": "/tmp/d"}), TMP, nothing)


def test_the_decoy_s_slice_is_newer_than_the_mirror():
    s = session()
    s.fold(1, [entry(1, "create", path="/tmp/f", size=3, mode=0o644, uid=0)])
    gone = [*TMP, FsEntry(path="/tmp/f", type="missing")]
    with pytest.raises(Rejected, match="does not exist"):
        s.validate(ops({"op": "chmod", "path": "/tmp/f", "mode": 0o600}), gone, nothing)
    s.validate(
        ops({"op": "chmod", "path": "/tmp/f", "mode": 0o600}), TMP, nothing
    )  # from the mirror


# ------------------------------------------------------------------ the fingerprint


def test_the_fingerprint_follows_what_a_reading_command_can_see():
    s = session()
    a = s.fingerprint(
        ["/tmp/a"],
        [*TMP, FsEntry(path="/tmp/a", type="file", mode=0o644, uid=0, size=3, head="one")],
    )
    assert a == s.fingerprint(
        ["/tmp/a"],
        [*TMP, FsEntry(path="/tmp/a", type="file", mode=0o644, uid=0, size=3, head="one")],
    )
    other_text = s.fingerprint(
        ["/tmp/a"],
        [*TMP, FsEntry(path="/tmp/a", type="file", mode=0o644, uid=0, size=3, head="two")],
    )
    other_mode = s.fingerprint(
        ["/tmp/a"],
        [*TMP, FsEntry(path="/tmp/a", type="file", mode=0o600, uid=0, size=3, head="one")],
    )
    missing = s.fingerprint(["/tmp/a"], [*TMP, FsEntry(path="/tmp/a", type="missing")])
    assert len({a, other_text, other_mode, missing}) == 4
    s.cwd = "/tmp"
    assert s.fingerprint(["/tmp/a"], TMP) != session().fingerprint(["/tmp/a"], TMP)
    s2 = session()
    s2.env["PATH"] = "/usr/bin"
    assert s2.fingerprint([], TMP) != session().fingerprint([], TMP)
    s3 = session()
    s3.env["EDITOR"] = "vi"  # not something an answer can depend on
    assert s3.fingerprint([], TMP) == session().fingerprint([], TMP)


# ------------------------------------------------------------------ the sessions held


def test_sessions_are_bounded_and_forgotten_after_an_hour():
    clock = [0.0]
    held = Sessions(max_sessions=2, ttl_s=3600, now=lambda: clock[0])
    a = held.open(request(session_id="a"))
    held.open(request(session_id="b"))
    held.open(request(session_id="a"))  # used again: the least recently used is now b
    held.open(request(session_id="c"))
    assert held.get("b") is None and held.get("a") is a and len(held) == 2
    clock[0] = 3601
    assert held.get("a") is None and len(held) == 1
    fresh = held.open(request(session_id="a", cwd="/var", user="caleb", uid=1000))
    assert fresh is not a and (fresh.cwd, fresh.user, fresh.uid, fresh.journal_seq) == (
        "/var",
        "caleb",
        1000,
        0,
    )


def test_facts_are_a_short_list_of_the_latest():
    s = session()
    for n in range(40):
        s.assert_fact(f"package p{n} is not installed")
    s.assert_fact("package p39 is not installed")
    assert len(s.facts) == 32 and s.facts[-1] == "package p39 is not installed"
    assert "package p0 is not installed" not in s.facts
