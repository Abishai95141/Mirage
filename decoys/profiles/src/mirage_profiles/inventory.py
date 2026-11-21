"""The render inventory (phase 3 spec 3.2a, decision R5): which commands the SSH decoy answers
wrongly, ranked by how often they are sent.

A list made by reading the test scenarios would score well and generalise to nothing, so the
volume comes from data that is not a test set: the public Cowrie corpus sample, and the lab
procedures outside every test split (weighted by the scenario steps that send them). A
shell line is cut into simple commands, each is reduced to a normalised argv (the command,
its options, and its operands by kind), and each is put in one of these kinds:

    answered     the emulator implements it (not in the inventory)
    static-text  the emulator prints a fixed text for it, the same on every deployment
    missing      a real Debian 12 server has the command; the emulator does not
    absent       a real server has no such command either: "command not found" is right
    shell        shell syntax the emulator's shell does not have (if, for, while ...)
    own-file     a file the attacker brought, run by its path

``static-text`` and ``missing`` are what a render library can answer, where the command only
reports (``render: true``). The rest is listed so that coverage is a share of everything the
decoy gets wrong, not of what happens to be easy.
"""

from __future__ import annotations

import json
import re
import shlex
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

TARGET_SHARE = 0.8
KEYWORDS = frozenset(
    [
        "if",
        "then",
        "else",
        "elif",
        "fi",
        "for",
        "while",
        "until",
        "do",
        "done",
        "case",
        "esac",
        "function",
        "select",
        "in",
        "time",
        "coproc",
    ]
)
# Keywords that are followed by a command on the same line ("then nproc", "do sleep 1").
LEADERS = frozenset({"if", "then", "else", "elif", "do", "while", "until", "time"})
# Verbs that are a report only with an option: bare, they start a server or do nothing.
NEEDS_OPTION = frozenset({"nginx", "sshd", "dpkg"})
# Words that run another command: the command is what follows them.
WRAPPERS = frozenset({"sudo", "nohup", "command", "exec", "builtin", "nice", "setsid", "stdbuf"})
# Commands that only report on the machine: answering one from a file changes nothing a later
# command could notice. A command is a report here when its verb is listed, every option it
# has is allowed for that verb (None: any option), its subcommand is allowed (for the verbs
# that take one), and it has no other operand. Anything else the emulator lacks is left to the
# later rungs (the state manager, the responder), which can keep state.
_ANY = None
REPORTS: dict[str, frozenset[str] | None] = {
    **dict.fromkeys(
        [
            "arch",
            "blkid",
            "df",
            "dmesg",
            "dmidecode",
            "dnsdomainname",
            "findmnt",
            "free",
            "hostid",
            "lsblk",
            "lscpu",
            "lshw",
            "lsipc",
            "lslogins",
            "lsmem",
            "lsmod",
            "lsns",
            "lspci",
            "lsusb",
            "lsof",
            "mount",
            "nproc",
            "swapon",
            "tty",
            "uptime",
            "vmstat",
            "systemd-detect-virt",
            "virt-what",
            "locale",
            "getcap",
        ],
        _ANY,
    ),
    "ss": frozenset("-" + c for c in "tlnpuaxewmioHhrs46")
    | {"--listening", "--tcp", "--udp", "--numeric", "--processes", "--all"},
    "nginx": frozenset({"-v", "-V", "-t", "-T"}),
    "sshd": frozenset({"-t", "-T", "-V"}),
    "dpkg": frozenset({"-l", "--list", "--get-selections", "--print-architecture"}),
    "ip": _ANY,
    "getent": _ANY,
    "openssl": _ANY,
    "hostnamectl": _ANY,
    "timedatectl": _ANY,
    "localectl": _ANY,
    "getconf": _ANY,
}
# Verbs whose first bare word is a subcommand, and the subcommands that only report.
SUBCOMMANDS: dict[str, frozenset[str]] = {
    "ip": frozenset(
        [
            "a",
            "addr",
            "address",
            "l",
            "link",
            "r",
            "route",
            "n",
            "neigh",
            "neighbor",
            "rule",
            "maddr",
        ]
    ),
    "getent": frozenset(["passwd", "group", "hosts", "services", "protocols", "networks"]),
    "openssl": frozenset({"version"}),
    "hostnamectl": frozenset({"status"}),
    "timedatectl": frozenset({"status", "show"}),
    "localectl": frozenset({"status"}),
    "getconf": frozenset(
        {"LONG_BIT", "PAGE_SIZE", "PAGESIZE", "_NPROCESSORS_ONLN", "_NPROCESSORS_CONF"}
    ),
}
_SUBCOMMAND_WORD = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
# Paths that name a fixed thing on every host stay in the argv; any other path is a path.
_FIXED_PATH = re.compile(
    r"^/(?:proc|sys|dev|etc|boot|var/log|var/run|run|usr/(?:s?bin|lib)|s?bin)(?:/|$)"
)
_SEPARATOR = re.compile(r"^[;&|(){}]+$")
_REDIRECT = re.compile(r"^[<>&|]*[<>][<>&|]*$")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SLOT = re.compile(r"\{\{[a-z_]+\d*\}\}")
_IP = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:[:/]\d+)?$")
_URL = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
_NUM = re.compile(r"^[+-]?\d+(?:\.\d+)?[a-zA-Z%]{0,2}$")
_HEX = re.compile(r"^[0-9a-fA-F]{8,}$")
_OPTION = re.compile(r"^--?[A-Za-z0-9][A-Za-z0-9_-]*(=.*)?$")


def tokens(line: str) -> list[str]:
    """``line`` as shell words, with operators as words of their own."""
    line = _SLOT.sub("SLOT", line).replace("\n", " ; ").replace("`", " ( ")
    lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()<>{}")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:  # an unclosed quote: bots send broken lines, and they still count
        return re.findall(r"[;&|(){}<>]+|[^\s;&|(){}<>]+", line.replace("'", " ").replace('"', " "))


def simple_commands(line: str) -> list[list[str]]:
    """The simple commands in a shell line, each as its argv: redirections dropped, leading
    assignments dropped, a command inside ``$( )`` or backticks counted as its own."""
    commands: list[list[str]] = []
    current: list[str] = []
    skip = False
    for tok in tokens(line):
        if skip:  # the target of a redirection
            skip = False
            continue
        if _REDIRECT.match(tok):
            if current and current[-1].isdigit():
                current.pop()  # the file descriptor in "2>"
            skip = not tok.endswith("&") or tok in (">&", "<&")
            continue
        if _SEPARATOR.match(tok):
            if current:
                commands.append(current)
            current = []
            continue
        if tok in ("$", "!"):
            continue
        current.append(tok)
    if current:
        commands.append(current)
    out = []
    for argv in commands:
        while argv:
            if _ASSIGNMENT.match(argv[0]) or argv[0] in WRAPPERS:
                argv = argv[1:]
            elif argv[0] in LEADERS and len(argv) > 1:
                out.append(argv[:1])  # the keyword, then the command it leads
                argv = argv[1:]
            else:
                out.append(argv)
                break
    return out


def _operand(arg: str) -> str:
    if arg == "SLOT" or ("SLOT" in arg and "/" not in arg):
        return "<arg>"
    if _URL.match(arg):
        return "<url>"
    if _IP.match(arg):
        return "<ip>"
    if _NUM.match(arg):
        return "<n>"
    if _HEX.match(arg):
        return "<hex>"
    if "/" in arg or arg.startswith(("~", ".")):
        return arg if _FIXED_PATH.match(arg) and "SLOT" not in arg and "*" not in arg else "<path>"
    return "<arg>"


def normalise(argv: list[str]) -> str:
    """The command's base name, its options as written, and each operand by kind. Repeated
    operands of one kind are one (``rm a b c`` and ``rm a`` are the same command)."""
    verb = argv[0].rsplit("/", 1)[-1] if not argv[0].startswith(("./", "~")) else argv[0]
    words = [verb]
    subcommand_open = verb in SUBCOMMANDS
    for arg in argv[1:]:
        if subcommand_open and not arg.startswith("-"):
            subcommand_open = False
            if _SUBCOMMAND_WORD.match(arg) and arg != "SLOT":
                words.append(arg)  # the subcommand, as written
                continue
        word = arg.split("=", 1)[0] + "=<arg>" if _OPTION.match(arg) and "=" in arg else arg
        word = word if _OPTION.match(arg) else _operand(arg)
        if not (word.startswith("<") and words[-1] == word):
            words.append(word)
    return " ".join(words)


@dataclass(frozen=True)
class Tables:
    """What the emulator implements and what a real Debian 12 server has."""

    emulated: frozenset[str]
    static_text: frozenset[str]
    reference: frozenset[str]

    @classmethod
    def load(cls, emulator: Path, reference: Path) -> Tables:
        e = json.loads(emulator.read_text())
        ref = {w for w in reference.read_text().split() if not w.startswith("#")}
        base = lambda names: frozenset(n.rsplit("/", 1)[-1] for n in names)
        return cls(base(e["commands"]), base(e["txtcmds"]), frozenset(ref))


def is_report(key: str) -> bool:
    """Whether a normalised argv is a command that only reports, with nothing left open: it
    can then be answered from a file, the same answer every time the same words are typed."""
    verb, *rest = key.split(" ")
    if verb not in REPORTS or any(word.startswith("<") for word in rest):
        return False
    allowed = REPORTS[verb]
    options = []
    for word in (w.split("=", 1)[0] for w in rest if w.startswith("-")):
        # "-tln" is "-t -l -n"
        bundled = len(word) > 2 and not word.startswith("--")
        options += ["-" + c for c in word[1:]] if bundled else [word]
    operands = [w for w in rest if not w.startswith("-")]
    if allowed is not None and any(o not in allowed for o in options):
        return False
    if verb in NEEDS_OPTION and not options:
        return False
    if verb in SUBCOMMANDS:
        if not operands or operands[0] not in SUBCOMMANDS[verb]:
            return False
        return all(o in ("show", "list") for o in operands[1:])
    # A fixed system path is the one kind of operand a report may have (df /, findmnt /).
    return all(o.startswith("/") for o in operands)


def kind_of(argv: list[str], tables: Tables) -> str:
    first = argv[0]
    verb = first.rsplit("/", 1)[-1]
    if first in KEYWORDS or first in ("[[", "]]", "((", "))"):
        return "shell"
    if "/" in first and not _FIXED_PATH.match(first):
        return "own-file"
    if verb in tables.emulated:  # a command the emulator implements wins over a text file
        return "answered"
    if verb in tables.static_text:
        return "static-text"
    return "missing" if verb in tables.reference else "absent"


def corpus_lines(path: Path) -> Iterable[str]:
    """The input lines of a Cowrie JSON log (one event a line)."""
    with path.open() as f:
        for raw in f:
            try:
                event = json.loads(raw)
            except ValueError:
                continue
            if event.get("eventid") == "cowrie.command.input" and event.get("input"):
                yield event["input"]


def lab_lines(
    catalogue: Path, scenarios: Path, splits: list[Path]
) -> tuple[list[str], dict[str, int]]:
    """The SSH templates of the procedures outside every test split, once for each scenario
    step that sends them. A procedure no split places is left out: it could be a test one."""
    where: dict[str, str] = {}
    for split in splits:
        for name, ids in (yaml.safe_load(split.read_text()).get("procedures") or {}).items():
            where.update(dict.fromkeys(ids, name))
    templates: dict[str, str] = {}
    for file in sorted(catalogue.glob("*.yaml")):
        for proc in yaml.safe_load(file.read_text()).get("procedures") or []:
            if proc.get("protocol") == "ssh" and proc.get("template"):
                templates[proc["id"]] = proc["template"]
    lines: list[str] = []
    used: Counter[str] = Counter()
    for file in sorted(scenarios.rglob("*.yaml")):
        doc = yaml.safe_load(file.read_text()) or {}
        for session in doc.get("sessions") or []:
            for step in session.get("steps") or []:
                pid = step.get("procedure")
                if pid in templates and where.get(pid) not in (None, "test"):
                    lines.append(templates[pid])
                    used[where[pid]] += 1
    return lines, dict(used)


@dataclass
class Inventory:
    sources: dict[str, Any]
    kinds: dict[str, dict[str, int]]
    entries: list[dict[str, Any]] = field(default_factory=list)

    def dump(self) -> str:
        head = (
            "# Written by `make render-inventory` (mirage_profiles.inventory). Do not edit.\n"
            "# Commands the SSH decoy answers wrongly, ranked by how often they are sent, from\n"
            "# data that is not a test set. `share` is of that source's wrongly answered\n"
            "# volume; `rank_share` is the mean of the two; `cumulative` runs down the list.\n"
        )
        doc = {
            "target_share": TARGET_SHARE,
            "sources": self.sources,
            "volume_by_kind": self.kinds,
            "entries": self.entries,
        }
        return head + yaml.safe_dump(doc, sort_keys=False, width=100)


def build(sources: dict[str, Iterable[str]], tables: Tables, notes: dict[str, Any]) -> Inventory:
    """Rank the wrongly answered commands of ``sources`` (name -> shell lines)."""
    counts: dict[str, Counter[str]] = {}
    kinds: dict[str, Counter[str]] = {}
    kind_by_key: dict[str, str] = {}
    lines_seen: dict[str, int] = {}
    for name, lines in sources.items():
        counts[name], kinds[name], lines_seen[name] = Counter(), Counter(), 0
        for line in lines:
            lines_seen[name] += 1
            for argv in simple_commands(line):
                kind = kind_of(argv, tables)
                kinds[name][kind] += 1
                if kind != "answered":
                    key = normalise(argv)
                    counts[name][key] += 1
                    kind_by_key[key] = kind
    # "absent" is not the decoy's mistake: a real host says "command not found" too.
    wrong = {
        name: sum(n for key, n in c.items() if kind_by_key[key] != "absent")
        for name, c in counts.items()
    }
    rows = []
    for key, kind in kind_by_key.items():
        if kind == "absent":
            continue
        shares = {
            name: (counts[name][key] / wrong[name] if wrong[name] else 0.0) for name in counts
        }
        rows.append((sum(shares.values()) / len(shares), key, kind, shares))
    rows.sort(key=lambda r: (-r[0], r[1]))
    entries, running = [], 0.0
    for rank_share, key, kind, shares in rows:
        running += rank_share
        entry: dict[str, Any] = {"argv": key, "kind": kind}
        entry["render"] = kind in ("static-text", "missing") and is_report(key)
        for name in counts:
            entry[name] = {"count": counts[name][key], "share": round(shares[name], 4)}
        entry["rank_share"] = round(rank_share, 4)
        entry["cumulative"] = round(running, 4)
        entries.append(entry)
    described = {
        name: {**notes.get(name, {}), "lines": lines_seen[name], "wrongly_answered": wrong[name]}
        for name in counts
    }
    return Inventory(
        described, {name: dict(sorted(k.items())) for name, k in kinds.items()}, entries
    )


def coverage(inventory: Inventory, answered: set[str]) -> dict[str, float]:
    """The share of each source's wrongly answered volume that ``answered`` (a set of
    normalised argv) covers."""
    out = {}
    for name, note in inventory.sources.items():
        total = note["wrongly_answered"]
        hit = sum(e[name]["count"] for e in inventory.entries if e["argv"] in answered)
        out[name] = round(hit / total, 4) if total else 0.0
    return out
