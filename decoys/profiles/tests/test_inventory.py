"""The render inventory (phase 3 spec 3.2a): cutting shell lines into commands, reducing each
to a normalised argv, sorting them into kinds, and ranking what the decoy answers wrongly."""

from __future__ import annotations

import json

import yaml

from mirage_profiles import inventory as inv

TABLES = inv.Tables(
    emulated=frozenset({"cat", "echo", "uname", "grep", "wc", "cd", "rm", "chmod", "sh", "pkill"}),
    static_text=frozenset({"lscpu", "nproc", "df", "top", "pkill"}),
    reference=frozenset(
        {"lscpu", "nproc", "df", "top", "ss", "ip", "getent", "nginx", "lsblk", "tar"}
    ),
)


def test_a_line_is_cut_into_its_simple_commands():
    line = "cd /tmp; uname -a && cat /proc/cpuinfo | grep name | wc -l || echo none"
    assert inv.simple_commands(line) == [
        ["cd", "/tmp"],
        ["uname", "-a"],
        ["cat", "/proc/cpuinfo"],
        ["grep", "name"],
        ["wc", "-l"],
        ["echo", "none"],
    ]


def test_redirections_assignments_and_wrappers_are_not_the_command():
    assert inv.simple_commands("LC_ALL=C sudo lscpu 2>/dev/null >> /tmp/out") == [["lscpu"]]
    assert inv.simple_commands("nohup ./run.sh > /dev/null 2>&1 &") == [["./run.sh"]]
    assert inv.simple_commands("df -h < /dev/null") == [["df", "-h"]]


def test_a_command_inside_a_substitution_is_counted_too():
    assert inv.simple_commands("echo $(nproc) `lscpu`") == [["echo"], ["nproc"], ["lscpu"]]
    # A keyword and the command it leads are two things: only the keyword is shell syntax.
    assert inv.simple_commands("if [ -f /x ]; then nproc; fi") == [
        ["if"],
        ["[", "-f", "/x", "]"],
        ["then"],
        ["nproc"],
        ["fi"],
    ]


def test_a_broken_line_is_still_read():
    # Bots send unclosed quotes. The words still count.
    assert inv.simple_commands("echo 'unclosed; lscpu")[-1] == ["lscpu"]


def test_normalised_argv_keeps_options_and_fixed_paths_and_names_operands_by_kind():
    n = inv.normalise
    assert n(["cat", "/proc/cpuinfo"]) == "cat /proc/cpuinfo"
    assert n(["/usr/bin/lscpu"]) == "lscpu"
    assert n(["rm", "-rf", "/tmp/a", "/var/tmp/b", "c.txt"]) == "rm -rf <path> <arg>"
    assert n(["ping", "-c", "3", "198.51.100.7"]) == "ping -c <n> <ip>"
    assert n(["wget", "http://198.51.100.7/x.sh", "-O-"]) == "wget <url> -O-"
    assert n(["tar", "--directory=/srv", "-xzf", "a.tgz"]) == "tar --directory=<arg> -xzf <arg>"
    assert n(["./run.sh", "9f8e7d6c5b4a"]) == "./run.sh <hex>"
    # A catalogue template's slot is an operand like any other.
    assert inv.simple_commands("cat {{path}} | grep {{word1}}") == [
        ["cat", "SLOT"],
        ["grep", "SLOT"],
    ]
    assert n(["cat", "SLOT"]) == "cat <arg>" and n(["cat", "/tmp/SLOT"]) == "cat <path>"


def test_a_subcommand_is_kept_and_what_follows_it_is_not():
    n = inv.normalise
    assert n(["ip", "addr"]) == "ip addr" and n(["ip", "-4", "addr", "show", "eth0"]) == (
        "ip -4 addr <arg>"
    )
    assert n(["getent", "passwd", "root"]) == "getent passwd <arg>"


def test_kinds():
    k = lambda line: inv.kind_of(inv.simple_commands(line)[0], TABLES)
    assert k("uname -a") == "answered"
    assert k("lscpu") == "static-text"
    assert k("pkill -9 x") == "answered"  # implemented and a text file: the implementation wins
    assert k("ss -tln") == "missing"
    assert k("lockr -ia .ssh") == "absent"  # no real server has it either
    assert k("if true") == "shell" and k("fi") == "shell"
    assert k("./payload") == "own-file" and k("/tmp/.x/run") == "own-file"
    assert k("/usr/bin/lscpu") == "static-text"  # a system path is the command, not a file


def test_only_a_command_that_just_reports_with_nothing_left_open_is_renderable():
    yes = [
        "lscpu",
        "df -h",
        "ss -tln",
        "ss -ant",
        "nginx -v",
        "ip addr",
        "ip -4 route",
        "getent passwd",
    ]
    no = [
        "ss -K",  # an option that acts
        "nginx -s reload",
        "nginx",  # starts the server
        "ip addr <arg>",  # an operand left open
        "ip link set",  # not a subcommand that reports
        "getent passwd <arg>",
        "vmstat <n>",
        "dpkg -i <path>",
        "rm -rf <path>",
        "top",
    ]
    assert [key for key in yes if not inv.is_report(key)] == []
    assert [key for key in no if inv.is_report(key)] == []
    assert inv.is_report("df /") and inv.is_report("dpkg -l") and not inv.is_report("dpkg -l <arg>")


def test_the_inventory_ranks_by_the_mean_share_and_leaves_out_what_is_right(tmp_path):
    corpus = ["lscpu; lscpu | grep Model; nproc", "uname -a; lockr -ia .ssh", "if x; then ./a; fi"]
    lab = ["ss -tln", "ss -tln; nproc", "cat {{path}}"]
    built = inv.build({"corpus": corpus, "lab": lab}, TABLES, {"corpus": {"what": "c"}})
    by = {e["argv"]: e for e in built.entries}
    assert "lockr -ia <arg>" not in by and "uname -a" not in by  # absent and answered
    assert built.kinds["corpus"]["absent"] == 2 and built.kinds["corpus"]["answered"] == 2
    # corpus wrong: lscpu x2, nproc, if, then, ./a, fi = 7; lab wrong: ss x2, nproc = 3
    assert built.sources["corpus"]["wrongly_answered"] == 7
    assert built.sources["lab"]["wrongly_answered"] == 3 and built.sources["corpus"]["what"] == "c"
    assert by["lscpu"]["corpus"] == {"count": 2, "share": round(2 / 7, 4)}
    assert by["ss -tln"]["lab"] == {"count": 2, "share": round(2 / 3, 4)}
    # ss is only in the smaller source and still leads: sources weigh the same.
    assert [e["argv"] for e in built.entries][:3] == ["ss -tln", "nproc", "lscpu"]
    assert by["ss -tln"]["render"] and by["lscpu"]["render"] and not by["./a"]["render"]
    assert built.entries[-1]["cumulative"] == 1.0
    assert inv.coverage(built, {"lscpu", "nproc"}) == {
        "corpus": round(3 / 7, 4),
        "lab": round(1 / 3, 4),
    }
    # It reads back as YAML, with its notes in front.
    text = built.dump()
    assert text.startswith("# Written by `make render-inventory`")
    assert yaml.safe_load(text)["entries"][0]["argv"] == "ss -tln"


def test_lab_lines_leave_out_every_test_procedure_and_weigh_by_steps(tmp_path):
    cat, scen = tmp_path / "catalogue", tmp_path / "scenarios"
    cat.mkdir()
    scen.mkdir()
    procs = [
        {"id": "p-dev", "protocol": "ssh", "template": "lscpu"},
        {"id": "p-test", "protocol": "ssh", "template": "lsblk"},
        {"id": "p-train", "protocol": "ssh", "template": "nproc"},
        {"id": "p-unplaced", "protocol": "ssh", "template": "df -h"},
        {"id": "p-http", "protocol": "http", "template": "GET /"},
    ]
    (cat / "a.yaml").write_text(yaml.safe_dump({"procedures": procs}))
    steps = [
        {"id": f"s{i}", "procedure": p}
        for i, p in enumerate(["p-dev", "p-dev", "p-test", "p-train", "p-unplaced", "p-http"])
    ]
    (scen / "s.yaml").write_text(yaml.safe_dump({"id": "s", "sessions": [{"steps": steps}]}))
    split = tmp_path / "split.yaml"
    split.write_text(
        yaml.safe_dump(
            {"procedures": {"train": ["p-train"], "dev": ["p-http"], "test": ["p-test"]}}
        )
    )
    depth = tmp_path / "depth.yaml"
    depth.write_text(yaml.safe_dump({"procedures": {"dev": ["p-dev"], "test": []}}))
    lines, used = inv.lab_lines(cat, scen, [split, depth])
    assert sorted(lines) == ["lscpu", "lscpu", "nproc"] and used == {"dev": 2, "train": 1}


def test_corpus_lines_are_the_input_events(tmp_path):
    log = tmp_path / "cowrie.json"
    events = [
        {"eventid": "cowrie.command.input", "input": "lscpu"},
        {"eventid": "cowrie.login.success", "username": "root"},
        {"eventid": "cowrie.command.input", "input": ""},
    ]
    log.write_text("\n".join(json.dumps(e) for e in events) + "\nnot json\n")
    assert list(inv.corpus_lines(log)) == ["lscpu"]
