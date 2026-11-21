"""The render library (phase 3 spec 3.2a): what may be an entry, what a deployment is given,
and the leak guards of section 5."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from mirage_profiles import generator, hardware, inventory, library

ROOT = Path(__file__).resolve().parents[3]
PROFILE = ROOT / "decoys/profiles/web-db.yaml"
RENDERED = ROOT / "decoys/profiles/rendered"
CLASSES = hardware.HardwareClass.available()
INVENTORY = yaml.safe_load((RENDERED / "inventory.yaml").read_text())
EXCLUDED = library.load_excluded(RENDERED / "excluded.yaml")
PROMOTED = library.load_promoted()
RENDERABLE = library.renderable(INVENTORY, PROMOTED)


def doc(*rows: tuple[str, int, int, bool]) -> dict:
    """An inventory with these (argv, corpus count, lab count, render) rows."""
    return {
        "sources": {"corpus": {"wrongly_answered": 20}, "lab": {"wrongly_answered": 10}},
        "entries": [
            {"argv": argv, "render": render, "corpus": {"count": c}, "lab": {"count": n}}
            for argv, c, n, render in rows
        ],
    }


def record(argv: str, **more) -> library.Record:
    base = {"program": f"/usr/bin/{argv.split()[0]}", "ms": [4, 2, 2, 2, 2], "user_same": True}
    return library.Record(argv, **{**base, "stdout": "ok\n", **more})


# ------------------------------------------------------------------ building


def test_an_entry_is_what_the_reference_host_printed():
    built, problems = library.build(
        doc(("ss -tln", 0, 6, True)),
        {"ss -tln": record("ss -tln", stdout="State Recv-Q\nLISTEN 0\n")},
        {"hostname": "ref"},
        [],
        {},
    )
    assert problems == []
    (entry,) = built[library.ANY]
    assert (entry.source, entry.who, entry.exit_code) == ("reference-container", "any", 0)
    assert entry.stdout == "State Recv-Q\nLISTEN 0\n" and entry.ms == [4, 2, 2, 2, 2]
    assert entry.inventory == {"corpus": 0, "lab": 6}


def test_a_command_the_inventory_does_not_count_cannot_be_an_entry():
    # Section 5's leak guard: the library cannot be filled from anywhere but the inventory.
    built, problems = library.build(
        doc(("lsmem", 0, 0, True)), {"lsmem": record("lsmem")}, {}, [], {}
    )
    assert built[library.ANY] == []
    assert problems == ["lsmem: no count in any inventory source"]


def test_only_commands_the_inventory_marks_renderable_are_built():
    built, problems = library.build(
        doc(("mysql -e <arg>", 0, 9, False)), {"mysql -e <arg>": record("mysql")}, {}, [], {}
    )
    assert built[library.ANY] == [] and problems == []


def test_an_excluded_command_is_left_out_without_being_a_problem():
    built, problems = library.build(
        doc(("ss -ant", 0, 1, True)), {"ss -ant": record("ss -ant")}, {}, [], {"ss -ant": "why"}
    )
    assert built[library.ANY] == [] and problems == []


@pytest.mark.parametrize(
    ("records", "problem"),
    [
        ({}, "not recorded on the reference host"),
        ({"lsipc": library.Record("lsipc", "")}, "the reference host has no such command"),
        ({"lsipc": record("lsipc", fixed=False)}, "not a fixed answer"),
    ],
)
def test_what_cannot_be_an_entry_is_reported(records, problem):
    built, problems = library.build(doc(("lsipc", 1, 0, True)), records, {}, [], {})
    assert built[library.ANY] == []
    assert len(problems) == 1 and problem in problems[0]


def test_an_answer_only_root_gets_is_roots_alone():
    built, _ = library.build(
        doc(("sshd -t", 0, 1, True)), {"sshd -t": record("sshd -t", user_same=False)}, {}, [], {}
    )
    assert built[library.ANY][0].who == "root"


def test_the_recording_hosts_own_name_becomes_a_slot():
    built, _ = library.build(
        doc(("hostnamectl", 2, 0, True)),
        {"hostnamectl": record("hostnamectl", stdout=" Static hostname: 231824b33a0b\n")},
        {"hostname": "231824b33a0b"},
        [],
        {},
    )
    (entry,) = built[library.ANY]
    assert entry.stdout == " Static hostname: {{hostname}}\n"
    assert entry.recorded == {"hostname": "231824b33a0b"}
    assert entry.slots() == ["hostname"]


def test_a_command_every_class_recorded_is_taken_from_the_classes():
    classes = [hardware.HardwareClass.load(c) for c in CLASSES]
    built, problems = library.build(
        doc(("nproc", 6, 1, True)), {"nproc": record("nproc", stdout="12\n")}, {}, classes, {}
    )
    assert problems == [] and built[library.ANY] == []
    for c in classes:
        (entry,) = built[c.id]
        assert entry.source == "class-record"
        assert entry.stdout == f"{c.facts['cpus']}\n"  # the class's, not the reference host's 12


def test_a_class_command_that_is_true_only_for_a_moment_is_not_an_entry():
    classes = [hardware.HardwareClass.load(CLASSES[0])]
    built, problems = library.build(
        doc(("uptime", 3, 0, True)), {"uptime": record("uptime")}, {}, classes, {}
    )
    assert built[classes[0].id] == []
    assert "true only for a moment" in problems[0]


def test_writing_is_the_same_every_time_and_reads_back(tmp_path):
    built, _ = library.build(
        doc(("nginx -v", 0, 5, True), ("nginx -V", 1, 0, True)),
        {
            "nginx -v": record("nginx -v", stdout="", stderr="nginx version: nginx/1.22.1\n"),
            "nginx -V": record("nginx -V", stdout="", stderr="built with OpenSSL\nconfigure\n"),
        },
        {},
        [],
        {},
    )
    first = {p.name: p.read_bytes() for p in library.write(built, tmp_path / "debian-12")}
    second = {p.name: p.read_bytes() for p in library.write(built, tmp_path / "debian-12")}
    assert first == second and len(first) == 2  # -v and -V are two files on any file system
    assert len({name.lower() for name in first}) == 2
    back = library.load(None, tmp_path)
    assert [e.argv for e in back] == ["nginx -V", "nginx -v"]
    assert back == sorted(built[library.ANY], key=lambda e: e.argv)
    assert back[1].shape == "error" and back[1].streams == "stderr"


def test_the_version_names_exactly_these_entries():
    a = library.Entry("nproc", "/usr/bin/nproc", "class-record", "any", 0, [1], "2\n", "", {})
    b = library.Entry("nproc", "/usr/bin/nproc", "class-record", "any", 0, [1], "4\n", "", {})
    assert library.version([a]) == library.version([a])
    assert library.version([a]) != library.version([b])


def test_what_record_sh_wrote_is_read_back(tmp_path):
    def put(stem: str, cmd: str, program: str, meta: str, out: str, user: tuple[str, str, str]):
        (tmp_path / f"{stem}.cmd").write_text(cmd + "\n")
        (tmp_path / f"{stem}.program").write_text(program + "\n")
        if not program:
            return
        (tmp_path / f"{stem}.meta").write_text(meta + "\n")
        (tmp_path / f"{stem}.out").write_text(out)
        (tmp_path / f"{stem}.err").write_text("")
        (tmp_path / f"{stem}.user.out").write_text(user[0])
        (tmp_path / f"{stem}.user.err").write_text(user[1])
        (tmp_path / f"{stem}.user.code").write_text(user[2] + "\n")

    put("001", "nproc", "/usr/bin/nproc", "0 yes 12 1 1 1 1", "12\n", ("12\n", "", "0"))
    put("002", "sshd -t", "/usr/sbin/sshd", "0 yes 26 7 7 7 8", "", ("", "no hostkeys\n", "1"))
    lscpu = "Architecture: x86_64\nCPU(s): 12\nCPU(s) scaling MHz: 77%\n"
    put(
        "003",
        "lscpu",
        "/usr/bin/lscpu",
        "0 no 18 6 5 6 6",
        lscpu,
        (lscpu.replace("77", "83"), "", "0"),
    )
    put("004", "lshw", "", "", "", ("", "", ""))
    put(
        "005",
        "df -h",
        "/usr/bin/df",
        "0 yes 2 2 2 1 1",
        "Filesystem Size\n/ 1G\n",
        ("other\n", "", "0"),
    )
    (tmp_path / "identity.txt").write_text("hostname=abc123\ndebian_version=12.15\n")
    (tmp_path / "image.txt").write_text("sha256:feed\n")

    records, identity = library.load_records(tmp_path)
    assert identity == {"hostname": "abc123", "debian_version": "12.15", "image": "sha256:feed"}
    assert records["nproc"].ms == [12, 1, 1, 1, 1] and records["nproc"].user_same
    assert records["sshd -t"].fixed and not records["sshd -t"].user_same
    # Root's own runs differed, and the other account's answer has the same keys.
    assert not records["lscpu"].fixed and records["lscpu"].user_same
    assert records["lshw"].program == ""
    assert not records["df -h"].user_same  # a fixed answer that differs is root's alone


# ---------------------------------------------------------- the committed library


def committed() -> list[tuple[str, library.Entry]]:
    out = []
    for directory in [library.ANY, *CLASSES]:
        for path in sorted((RENDERED / library.DISTRIBUTION / directory).glob("*.yaml")):
            out.append((directory, library.Entry(**yaml.safe_load(path.read_text()))))
    return out


def test_every_committed_entry_names_its_inventory_source():
    counted = {e["argv"]: library.counts(e, INVENTORY) for e in RENDERABLE}
    assert committed()
    for directory, entry in committed():
        assert entry.argv in counted, f"{directory}/{entry.argv} is not in the inventory"
        assert entry.inventory == counted[entry.argv]
        assert any(entry.inventory.values()), f"{directory}/{entry.argv} has no count"


def test_every_renderable_inventory_command_is_an_entry_or_excluded_with_a_reason():
    for class_id in CLASSES:
        have = {e.argv for e in library.load(class_id)}
        for item in RENDERABLE:
            assert (item["argv"] in have) != (item["argv"] in EXCLUDED), item["argv"]
    assert all(len(why) > 40 for why in EXCLUDED.values())
    assert set(EXCLUDED) <= {e["argv"] for e in library.renderable(INVENTORY)}


def test_a_committed_entry_holds_a_fixed_answer_and_nothing_of_its_recorder():
    for directory, entry in committed():
        text = entry.stdout + entry.stderr
        assert entry.who in ("any", "root") and entry.ms and all(t >= 0 for t in entry.ms)
        assert entry.program.startswith("/usr/") and entry.program.endswith(
            "/" + entry.argv.split()[0]
        )
        assert hardware.CAPTURE_HOSTNAME not in text and hardware.CAPTURE_MAC not in text
        assert entry.source == (
            "reference-container" if directory == library.ANY else "class-record"
        )
        assert not any(word.startswith("<") for word in entry.argv.split())


@pytest.mark.parametrize("seed", [1, 7, 42, 1234])
def test_every_entry_passes_the_fidelity_check_for_a_deployment(tmp_path, seed):
    # Gate 3 test 3. The render itself refuses an entry that fails; this shows each verdict.
    generator.render(PROFILE, seed, tmp_path)
    host = json.loads((tmp_path / "host.json").read_text())
    hw = hardware.HardwareClass.load(host["hardware_class"])
    values = {"hostname": host["hostname"], "mac": host["mac"]}
    entries = library.load(hw.id)
    assert len(entries) == host["render_library"]["entries"] >= 7
    for entry in entries:
        verdict = library.check(entry, values, hw, {"nginx version": "1.22.1"})
        assert verdict.ok, (entry.argv, verdict.problems)
    served = json.loads((tmp_path / "cowrie/rendered.json").read_text())
    said = {" ".join(e["argv"]): e for e in served["entries"]}
    assert said["lscpu"]["stdout"].count(hw.facts["cpu_model"]) == 1
    assert said["nproc"]["stdout"] == f"{hw.facts['cpus']}\n"
    assert hw.facts["root_device"] in said["df -h"]["stdout"]
    assert "{{" not in json.dumps(served)


def test_an_entry_that_still_shows_its_recorder_stops_the_render():
    bad = library.Entry(
        "hostnamectl", "/usr/bin/hostnamectl", "reference-container", "any", 0, [3],
        "Static hostname: {{hostname}}\nPretty hostname: ref-host\n", "", {"corpus": 1},
        recorded={"hostname": "ref-host"},
    )  # fmt: skip
    with pytest.raises(ValueError, match=r"hostnamectl.*fails the fidelity check"):
        library.render_for([bad], {"hostname": "web01"})
    good = library.Entry(**{**bad.__dict__, "stdout": "Static hostname: {{hostname}}\n"})
    served = library.render_for([good], {"hostname": "web01"})
    assert served["entries"][0]["stdout"] == "Static hostname: web01\n"
    assert served["entries"][0]["argv"] == ["hostnamectl"]


def test_one_seed_gives_one_library_and_classes_differ_in_the_hardware_alone(tmp_path):
    def served(seed: int, where: str) -> tuple[bytes, dict]:
        out = tmp_path / where
        generator.render(PROFILE, seed, out)
        raw = (out / "cowrie/rendered.json").read_bytes()
        return raw, json.loads(raw)

    assert served(7, "a")[0] == served(7, "b")[0]  # byte-identical per seed
    by_class: dict[str, dict] = {}
    for seed in range(1, 40):
        lib = served(seed, f"s{seed}")[1]
        if lib["hardware_class"] in by_class:
            # Two seeds of one class: the same answers (no entry has a slot today), and
            # the same version.
            assert by_class[lib["hardware_class"]]["entries"] == lib["entries"]
            assert by_class[lib["hardware_class"]]["version"] == lib["version"]
        by_class.setdefault(lib["hardware_class"], lib)
        if len(by_class) == len(CLASSES):
            break
    assert set(by_class) == set(CLASSES)
    one, two = (by_class[c] for c in CLASSES[:2])
    differ = {
        " ".join(a["argv"]) for a, b in zip(one["entries"], two["entries"], strict=True) if a != b
    }
    assert differ == {"lscpu", "nproc", "df -h"}
    assert one["version"] != two["version"]


def test_the_decoy_is_told_where_its_library_is_and_what_it_holds(tmp_path):
    generator.render(PROFILE, 7, tmp_path)
    host = json.loads((tmp_path / "host.json").read_text())
    served = json.loads((tmp_path / "cowrie/rendered.json").read_text())
    held = len(library.load(host["hardware_class"]))
    assert held >= 7  # the inventory's seven, and what has been promoted since
    assert host["render_library"] == {"version": served["version"], "entries": held}
    cfg = (tmp_path / "cowrie/cowrie.cfg").read_text()
    assert "[mirage]\n" in cfg and "render_library = /cowrie/deployment/rendered.json" in cfg
    # What the decoy needs for the /proc files that change by the second.
    assert served["proc"]["stat"].startswith("cpu  ") and served["proc"]["recorded_uptime_s"] > 0
    assert served["proc"]["loadavg"].count(" ") == 4
    # The fixed text behind `df` is now what `df` prints; the library answers `df -h`.
    hw = hardware.HardwareClass.load(host["hardware_class"])
    plain = next(c for c in hw.commands() if c["argv"] == "df")
    assert (tmp_path / "cowrie/txtcmds/usr/bin/df").read_text() == plain["stdout"]
    assert "1K-blocks" in plain["stdout"]


# ------------------------------------------------------------------ coverage


def test_coverage_is_a_share_of_everything_answered_wrongly():
    d = doc(("lscpu", 7, 0, True), ("ss -tln", 0, 6, True), ("mysql -e <arg>", 5, 2, False))
    tables = inventory.Tables(frozenset({"ls"}), frozenset({"lscpu"}), frozenset({"ss", "getent"}))
    held_out = ["ss -tln; ls", "ss -tln", "getent passwd", "getent passwd nobody", "frobnicate"]
    cover = library.coverage(d, {"lscpu", "ss -tln"}, held_out, tables)
    assert cover["corpus"] == {"answered": 7, "of": 20, "share": 0.35}
    assert cover["lab"] == {"answered": 6, "of": 10, "share": 0.6}
    # Held out: ss twice (answered), getent twice (one of them a report, not in the
    # library); `ls` is answered by the emulator and the unknown program is no one's fault.
    assert cover["held-out"] == {"answered": 2, "of": 4, "share": 0.5, "a_library_could": 3}


def test_held_out_lines_are_the_test_halfs_and_no_others(tmp_path):
    (tmp_path / "cat").mkdir()
    (tmp_path / "scn").mkdir()
    (tmp_path / "cat/a.yaml").write_text(
        yaml.safe_dump(
            {
                "procedures": [
                    {"id": "p-dev", "protocol": "ssh", "template": "nproc"},
                    {"id": "p-test", "protocol": "ssh", "template": "ss -tln"},
                    {"id": "p-http", "protocol": "http", "template": "GET /"},
                    {"id": "p-unplaced", "protocol": "ssh", "template": "lscpu"},
                ]
            }
        )
    )
    steps = [{"procedure": p} for p in ("p-dev", "p-test", "p-test", "p-http", "p-unplaced")]
    (tmp_path / "scn/s.yaml").write_text(yaml.safe_dump({"sessions": [{"steps": steps}]}))
    split = tmp_path / "split.yaml"
    split.write_text(
        yaml.safe_dump({"procedures": {"dev": ["p-dev"], "test": ["p-test", "p-http"]}})
    )
    assert library.held_out_lines(tmp_path / "cat", tmp_path / "scn", split) == ["ss -tln"] * 2


def test_the_review_shows_every_answer_and_what_is_left_out():
    built, problems = library.build(
        doc(("nginx -v", 0, 5, True), ("ss -ant", 0, 1, True), ("lsipc", 1, 0, True)),
        {"nginx -v": record("nginx -v", stdout="", stderr="nginx version: nginx/1.22.1\n")},
        {"image": "sha256:feed", "debian_version": "12.15", "arch": "amd64"},
        [],
        {"ss -ant": "It lists the caller's own connection."},
    )
    text = library.review(built, {"ss -ant": "It lists the caller's own connection."}, problems, {})
    assert "### `nginx -v`" in text and "nginx version: nginx/1.22.1" in text
    assert "output on stderr" in text and "lab 5" in text
    assert "- `ss -ant`: It lists the caller's own connection." in text
    assert "**Not built:** lsipc: not recorded" in text


def test_a_file_name_is_safe_and_keeps_cases_apart():
    assert library.slug("ss -tln") == "ss-tln"
    assert library.slug("df -h") == "df-h"
    assert library.slug("nginx -V") != library.slug("nginx -v")
    assert library.slug("findmnt /") == "findmnt"


# ------------------------------------------------------------------ promotion (spec 3.2b)


def cached(command: str, fingerprint: str = "", hits: int = 0, stdout: str = "ok\n") -> dict:
    return {
        "command": command,
        "fingerprint": fingerprint,
        "hits": hits,
        "stdout": stdout,
        "stderr": "",
        "exit_code": 0,
    }


def test_what_the_model_was_asked_becomes_a_candidate_when_a_fixed_entry_could_answer_it():
    promoted, left = library.candidates(
        [
            cached("openssl version", hits=3),
            cached("locale"),
            cached("od -c /etc/hostname", fingerprint="f1"),  # depends on the session's files
            cached("perl -e 'unlink q(/etc/passwd)'"),  # not a plain command
            cached("getent passwd root; id"),
            cached("ss -ant"),
            cached("ss -tln"),
        ],
        doc(("ss -tln", 0, 6, True)),
        [{"argv": "locale", "answered": 5}],
        {"ss -ant": "its answer lists every connection, the caller's own among them"},
    )
    assert promoted == [
        {"argv": "locale", "answered": 5},
        {"argv": "openssl version", "answered": 4},
    ]
    assert left == {
        "od -c /etc/hostname": "its answer depends on the session's state",
        "perl -e 'unlink q(/etc/passwd)'": "not one plain command",
        "getent passwd root; id": "not one plain command",
        "ss -ant": "excluded from the library (excluded.yaml)",
        "ss -tln": "already in the inventory",
    }


def test_a_promoted_command_is_built_like_any_other_and_says_where_it_came_from():
    promoted = [
        {"argv": "openssl version", "answered": 4},
        {"argv": "ldd /bin/ls", "answered": 1, "left": "five runs did not print the same"},
    ]
    assert [e["argv"] for e in library.renderable(doc(), promoted)] == ["openssl version"]
    built, problems = library.build(
        doc(),
        {"openssl version": record("openssl version", stdout="OpenSSL 3.0.22 25 Aug 2026\n")},
        {"hostname": "ref"},
        [],
        {},
        promoted,
    )
    assert problems == []
    (entry,) = built[library.ANY]
    assert entry.inventory == {"responder": 4} and entry.stdout.startswith("OpenSSL 3.0.22")
    # One the reference host has not answered yet is reported, as an inventory command is.
    _, problems = library.build(doc(), {}, {"hostname": "ref"}, [], {}, promoted)
    assert problems == ["openssl version: not recorded on the reference host (run record.sh)"]


def test_the_promoted_list_reads_back_as_written(tmp_path):
    promoted = [
        {"argv": "locale", "answered": 2},
        {"argv": "ldd /bin/ls", "answered": 1, "left": "x"},
    ]
    path = tmp_path / "promoted.yaml"
    path.write_text(library.dump_promoted(promoted))
    assert library.load_promoted(path) == promoted
    assert library.load_promoted(tmp_path / "none.yaml") == []


def test_a_cached_answer_is_held_to_what_the_reference_host_said():
    records = {
        "openssl version": record(
            "openssl version", stdout="OpenSSL 3.0.22 25 Aug 2026 (Library)\n"
        ),
        "locale charmap": record("locale charmap", stdout="ANSI_X3.4-1968\n"),
        "ldd /bin/ls": record("ldd /bin/ls", fixed=False),
    }
    verdicts = library.cache_verdicts(
        [
            cached("openssl version", stdout="OpenSSL 3.0.13 30 Jan 2024\n"),
            cached("locale charmap", stdout="ANSI_X3.4-1968\n"),
            cached("ldd /bin/ls"),  # no fixed answer to hold it to
            cached("factor 360"),  # the reference host was not asked
            cached("locale charmap", fingerprint="f1", stdout="C\n"),  # a session's own
        ],
        records,
    )
    assert [(v["command"], v["same"]) for v in verdicts] == [
        ("openssl version", False),
        ("locale charmap", True),
    ]
    # "The same" is the stricter bar: the wrong version above has the right shape.
    assert set(verdicts[0]) == {"command", "fingerprint", "passes", "same", "problems"}
