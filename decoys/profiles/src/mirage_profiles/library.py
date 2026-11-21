"""The render library (phase 3 spec 3.2a): answers to the commands the SSH decoy's emulator
lacks, or answers with a text that is the same on every honeypot.

An entry is one command, by its normalised argv, and what a real Debian 12 host printed for
it: on which stream, with which exit code, in how long. Nothing in an entry is written by a
person or a model. It comes from one of two records:

    class-record         where the answer depends on the machine: what a Debian 12 virtual
                         machine of the hardware class printed (``hardware/<class>``).
    reference-container  where it does not: what a container of the reference image printed
                         (``rendered/record/record.sh``).

Three rules decide what the library holds.

1. The inventory names the command, with a count in data that is not a test set. An entry
   with no count fails the build, so the library cannot be filled from the test scenarios.
2. The answer is fixed: the same every time the command is typed on that machine. A command
   whose answer names the caller's own connection, or a process ID, is not, and is listed in
   ``excluded.yaml`` with the reason. It is left to a rung that keeps state.
3. Rendered for a deployment, the answer passes the fidelity check against its record.

The committed entries are ``rendered/debian-12/<class>/`` and ``rendered/debian-12/any/``
(the commands that do not depend on the class). A profile's render writes the entries of its
class, with its own values in their slots, to ``cowrie/rendered.json``; the fork's serving
patch answers from that file.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mirage_profiles import fidelity, hardware, inventory

HERE = Path(__file__).resolve().parents[2]
RENDERED = HERE / "rendered"
DISTRIBUTION = "debian-12"
ANY = "any"  # the directory of entries that do not depend on the hardware class
_HEAD = "# Written by `mirage-profile render-library`; do not edit. What a real host printed.\n"


class _Block(yaml.SafeDumper):
    """Text of several lines as a block, so that a person can read an entry."""


def _text(dumper: yaml.SafeDumper, value: str) -> yaml.Node:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_Block.add_representer(str, _text)


@dataclass
class Record:
    """What the reference container printed for one command (``record.sh``)."""

    argv: str
    program: str
    exit_code: int = 0
    fixed: bool = True  # five runs printed the same
    ms: list[int] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    user_same: bool = False  # an account with no privileges gets the same answer


@dataclass
class Entry:
    argv: str
    program: str
    source: str  # class-record | reference-container
    who: str  # any | root: whose question this answers
    exit_code: int
    ms: list[int]
    stdout: str
    stderr: str
    inventory: dict[str, int]
    shape: str = ""
    streams: str = ""
    # The recording host's own values for this entry's slots, so that the record can be
    # told from a deployment's answer.
    recorded: dict[str, str] = field(default_factory=dict)

    def observed(self, values: dict[str, str]) -> fidelity.Observed:
        return fidelity.Observed(
            hardware.fill(self.stdout, values), hardware.fill(self.stderr, values), self.exit_code
        )

    def slots(self) -> list[str]:
        return sorted(set(hardware.SLOT.findall(self.stdout + self.stderr)))


def slug(argv: str) -> str:
    """A file name for an argv that keeps ``-v`` and ``-V`` apart on any file system."""
    out = []
    for ch in argv:
        if ch.isascii() and (ch.islower() or ch.isdigit()):
            out.append(ch)
        elif ch.isascii() and ch.isupper():
            out.append(ch.lower() + "_")
        else:
            out.append("-")
    return re.sub(r"-+", "-", "".join(out)).strip("-")


def renderable(
    doc: dict[str, Any], promoted: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """The commands a library can answer: the inventory's, in the inventory's order, then
    those promoted from the live model's answers (``promoted.yaml``)."""
    out = [e for e in doc.get("entries") or [] if e.get("render")]
    have = {e["argv"] for e in out}
    out += [
        {"argv": p["argv"], "render": True, "answered": int(p.get("answered", 1))}
        for p in promoted or []
        if p["argv"] not in have and not p.get("left")
    ]
    return out


def counts(entry: dict[str, Any], doc: dict[str, Any]) -> dict[str, int]:
    if "answered" in entry:
        return {"responder": int(entry["answered"])}
    return {name: int(entry[name]["count"]) for name in doc["sources"]}


# ---------------------------------------------------------------- promotion (spec 3.2b)
#
# The live model is the last rung, and what it says is right about one time in five
# (docs/experiments/phase-3/llm-bench.md). A command whose answer is the same for every
# session need not be generated twice, or at all: once the model has been asked for it, the
# real host is asked too, and its answer becomes an entry. The responder's cache says what
# was asked; `promoted.yaml` is the list, kept in the repository and read by a person.

PROMOTED = RENDERED / "promoted.yaml"
# One simple command: a name and plain arguments. Nothing a shell would act on, so that what
# an attacker typed can be run on the reference container as it stands.
_PLAIN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+-]*( [A-Za-z0-9_./=:@%+,-]+)*")


def load_promoted(path: Path = PROMOTED) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return list(yaml.safe_load(path.read_text()) or [])


def candidates(
    cached: list[dict[str, Any]],
    doc: dict[str, Any],
    promoted: list[dict[str, Any]],
    excluded: dict[str, str],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """``promoted`` with what the responder's cache adds, and why each other cached command
    was left. A cached row is {command, fingerprint, hits}: one with no fingerprint is a
    stateless command's, the same for every session, which is what a fixed entry can hold."""
    listed = {p["argv"]: dict(p) for p in promoted}
    inventoried = {e["argv"] for e in doc.get("entries") or [] if e.get("render")}
    left: dict[str, str] = {}
    for row in cached:
        argv = str(row["command"])
        answered = int(row.get("hits", 0)) + 1
        if row.get("fingerprint"):
            left[argv] = "its answer depends on the session's state"
        elif not _PLAIN.fullmatch(argv):
            left[argv] = "not one plain command"
        elif argv in excluded:
            left[argv] = "excluded from the library (excluded.yaml)"
        elif argv in inventoried:
            left[argv] = "already in the inventory"
        elif argv in listed:
            listed[argv]["answered"] = max(int(listed[argv].get("answered", 1)), answered)
        else:
            listed[argv] = {"argv": argv, "answered": answered}
    return sorted(listed.values(), key=lambda p: p["argv"]), left


def dump_promoted(promoted: list[dict[str, Any]]) -> str:
    head = (
        "# Commands promoted from the live model's answers to the render library (phase 3 spec\n"
        "# 3.2b). Written by `make render-candidates` from the responder's cache: stateless\n"
        "# commands the model was asked, each one plain command. `make render-record` asks the\n"
        "# reference host for each, and `make render-library` makes an entry of every answer\n"
        "# that is fixed. `answered` is how often the responder was asked for the command;\n"
        "# `left` is why the reference host's answer could not be an entry (the command then\n"
        "# stays with the responder). Delete an entry to have it considered afresh.\n"
    )
    return head + yaml.safe_dump(promoted, sort_keys=False, default_flow_style=False)


def cache_verdicts(
    cached: list[dict[str, Any]], records: dict[str, Record]
) -> list[dict[str, Any]]:
    """Each cached answer the reference host has now answered too, held to that answer: the
    fidelity check, and the stricter bar of being the same line for line once numbers, dates
    and addresses are masked. One that is not the same is to be evicted (spec 3.2b)."""
    out = []
    for row in cached:
        record = records.get(str(row["command"]))
        if record is None or not record.program or not record.fixed or row.get("fingerprint"):
            continue
        said = fidelity.Observed(row["stdout"], row["stderr"], int(row["exit_code"]))
        true = fidelity.Observed(record.stdout, record.stderr, record.exit_code)
        verdict = fidelity.check(said, true)
        same = said.exit_code == true.exit_code and all(
            fidelity.mask(getattr(said, s)) == fidelity.mask(getattr(true, s))
            for s in ("stdout", "stderr")
        )
        out.append(
            {
                "command": row["command"],
                "fingerprint": row.get("fingerprint", ""),
                "passes": verdict.ok,
                "same": same,
                "problems": verdict.problems[:2],
            }
        )
    return out


def load_excluded(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    return {row["argv"]: row["why"].strip() for row in yaml.safe_load(path.read_text()) or []}


def load_records(directory: Path) -> tuple[dict[str, Record], dict[str, str]]:
    """What ``record.sh`` wrote: {argv: record}, and the recording host's own values."""
    identity = dict(
        line.split("=", 1)
        for line in (directory / "identity.txt").read_text().splitlines()
        if "=" in line
    )
    identity["image"] = (directory / "image.txt").read_text().strip()
    records = {}
    for cmd_file in sorted(directory.glob("*.cmd")):
        stem = cmd_file.with_suffix("")
        argv = cmd_file.read_text().strip()
        program = stem.with_suffix(".program").read_text().strip()
        if not program:
            records[argv] = Record(argv, "")
            continue
        code, same, *times = stem.with_suffix(".meta").read_text().split()
        out = stem.with_suffix(".out").read_text(errors="replace")
        err = stem.with_suffix(".err").read_text(errors="replace")
        user = (
            Path(f"{stem}.user.out").read_text(errors="replace"),
            Path(f"{stem}.user.err").read_text(errors="replace"),
            Path(f"{stem}.user.code").read_text().strip(),
        )
        fixed = same == "yes"
        user_same = user == (out, err, code)
        if not fixed and not user_same and user[2] == code:
            # Root's own runs differed (a value that moves, such as the CPU's speed just
            # now), so the other account's answer cannot be told apart by its bytes. It is
            # the same answer when it has the same shape.
            mine, theirs = fidelity.Observed(out, err, int(code)), fidelity.Observed(*user[:2])
            user_same = fidelity.check(theirs, mine).ok
        records[argv] = Record(
            argv, program, int(code), fixed, [int(t) for t in times], out, err, user_same
        )
    return records, identity


def build(
    doc: dict[str, Any],
    records: dict[str, Record],
    identity: dict[str, str],
    classes: list[hardware.HardwareClass],
    excluded: dict[str, str],
    promoted: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, list[Entry]], list[str]]:
    """The library's entries by directory (a class ID or ``any``), and what stopped any
    inventory command from becoming one. An empty second value means every renderable
    inventory command is either an entry or excluded with a reason."""
    library: dict[str, list[Entry]] = {ANY: [], **{c.id: [] for c in classes}}
    problems: list[str] = []
    said = {c.id: {row["argv"]: row for row in c.commands()} for c in classes}
    own = [(identity["hostname"], "hostname")] if identity.get("hostname") else []
    for item in renderable(doc, promoted):
        argv = item["argv"]
        if argv in excluded:
            continue
        seen = counts(item, doc)
        if not any(seen.values()):
            problems.append(f"{argv}: no count in any inventory source")
            continue
        record = records.get(argv)
        if record is None:
            problems.append(f"{argv}: not recorded on the reference host (run record.sh)")
            continue
        if not record.program:
            problems.append(f"{argv}: the reference host has no such command")
            continue
        who = "any" if record.user_same else "root"
        if all(argv in said[c.id] for c in classes) and classes:
            # The answer depends on the machine: each class's own record is the entry.
            for c in classes:
                row = said[c.id][argv]
                if row.get("volatile"):
                    problems.append(f"{argv}: its answer is true only for a moment ({c.id})")
                    continue
                library[c.id].append(
                    Entry(
                        argv,
                        record.program,
                        "class-record",
                        who,
                        int(row["exit_code"]),
                        [int(row["ms"])],
                        row["stdout"],
                        row["stderr"],
                        seen,
                    )
                )
            continue
        if not record.fixed:
            problems.append(f"{argv}: five runs did not print the same; not a fixed answer")
            continue
        library[ANY].append(
            Entry(
                argv,
                record.program,
                "reference-container",
                who,
                record.exit_code,
                record.ms,
                hardware.to_slots(record.stdout, own),
                hardware.to_slots(record.stderr, own),
                seen,
            )
        )
    capture = {
        "hostname": hardware.CAPTURE_HOSTNAME,
        "mac": hardware.CAPTURE_MAC,
        **{slot: address for address, slot in hardware.CAPTURE_NET.items()},
    }
    for entries in library.values():
        for entry in entries:
            reference = fidelity.Observed(entry.stdout, entry.stderr, entry.exit_code)
            entry.shape = fidelity.check(reference, reference).shape
            entry.streams = reference.streams()
            was = capture if entry.source == "class-record" else dict((s, v) for v, s in own)
            entry.recorded = {slot: was[slot] for slot in entry.slots() if slot in was}
    return library, problems


def write(library: dict[str, list[Entry]], dest: Path) -> list[Path]:
    """Replace the committed entries under ``dest`` with ``library``. The same library
    always gives the same files."""
    written = []
    for directory, entries in sorted(library.items()):
        target = dest / directory
        target.mkdir(parents=True, exist_ok=True)
        for old in target.glob("*.yaml"):
            old.unlink()
        for entry in entries:
            path = target / f"{slug(entry.argv)}.yaml"
            body = yaml.dump(asdict(entry), Dumper=_Block, sort_keys=False, width=1000)
            path.write_text(_HEAD + body)
            written.append(path)
    return written


def load(class_id: str | None, base: Path = RENDERED) -> list[Entry]:
    """The entries a deployment of ``class_id`` gets: its class's and the common ones, by
    argv. A deployment with no class gets the common ones."""
    entries = []
    for directory in [ANY] + ([class_id] if class_id else []):
        for path in sorted((base / DISTRIBUTION / directory).glob("*.yaml")):
            entries.append(Entry(**yaml.safe_load(path.read_text())))
    return sorted(entries, key=lambda e: e.argv)


def version(entries: list[Entry]) -> str:
    """A short name for exactly these entries: any change to one gives another."""
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda e: e.argv):
        digest.update(json.dumps(asdict(entry), sort_keys=True).encode())
    return digest.hexdigest()[:12]


def facts_for(
    entry: Entry,
    hw: hardware.HardwareClass | None,
    values: dict[str, str],
    known: dict[str, str],
) -> list[fidelity.Fact]:
    """The facts an answer must agree with: what the class fixes (its CPU, its disk), what
    the reference image fixes (``known``: its nginx version), and the deployment's own
    values where the record shows the recording host's."""
    facts = [fidelity.Fact(name, value, value) for name, value in sorted(known.items())]
    if hw is not None and entry.source == "class-record":
        f = hw.facts
        fixed = {"CPU model": f["cpu_model"], "root device": f["root_device"]}
        facts += [fidelity.Fact(name, value, value) for name, value in fixed.items()]
    facts += [
        fidelity.Fact(slot, was, values[slot])
        for slot, was in sorted(entry.recorded.items())
        if slot in values
    ]
    return facts


def check(
    entry: Entry,
    values: dict[str, str],
    hw: hardware.HardwareClass | None = None,
    known: dict[str, str] | None = None,
) -> fidelity.Verdict:
    """The fidelity check of one entry as a deployment will print it (its slots filled with
    ``values``) against its record (the same slots with the recording host's own values)."""
    reference = entry.observed({**values, **entry.recorded})
    facts = facts_for(entry, hw, values, known or {})
    return fidelity.check(entry.observed(values), reference, facts)


def render_for(
    entries: list[Entry],
    values: dict[str, str],
    hw: hardware.HardwareClass | None = None,
    known: dict[str, str] | None = None,
) -> dict[str, Any]:
    """What a deployment's decoy serves: every entry with this deployment's values, checked.
    An entry that fails the check stops the render: a wrong answer must not reach a decoy."""
    served = []
    for entry in entries:
        verdict = check(entry, values, hw, known)
        if not verdict.ok:
            raise ValueError(f"render library: {entry.argv!r} fails the fidelity check: "
                             + "; ".join(verdict.problems))  # fmt: skip
        seen = entry.observed(values)
        served.append(
            {
                "argv": entry.argv.split(" "),
                "program": entry.program,
                "who": entry.who,
                "exit_code": entry.exit_code,
                "ms": entry.ms,
                "stdout": seen.stdout,
                "stderr": seen.stderr,
            }
        )
    return {"distribution": DISTRIBUTION, "version": version(entries), "entries": served}


def held_out_lines(catalogue: Path, scenarios: Path, split: Path) -> list[str]:
    """The SSH templates of the procedures in ``split``'s test half, once for each scenario
    step that sends them. Read only to count: nothing here is printed or kept."""
    doc = yaml.safe_load(split.read_text())
    test = set((doc.get("procedures") or {}).get("test") or [])
    templates = {}
    for file in sorted(catalogue.glob("*.yaml")):
        for proc in yaml.safe_load(file.read_text()).get("procedures") or []:
            if proc["id"] in test and proc.get("protocol") == "ssh" and proc.get("template"):
                templates[proc["id"]] = proc["template"]
    lines = []
    for file in sorted(scenarios.rglob("*.yaml")):
        for session in (yaml.safe_load(file.read_text()) or {}).get("sessions") or []:
            for step in session.get("steps") or []:
                if step.get("procedure") in templates:
                    lines.append(templates[step["procedure"]])
    return lines


def coverage(
    doc: dict[str, Any], answered: set[str], held_out: list[str], tables: inventory.Tables
) -> dict[str, dict[str, Any]]:
    """The share of the wrongly answered volume the library answers: on each inventory
    source, and on the held-out lines, which are counted the same way and never listed."""
    out: dict[str, dict[str, Any]] = {}
    for name, note in doc["sources"].items():
        hit = sum(e[name]["count"] for e in doc["entries"] if e["argv"] in answered)
        total = note["wrongly_answered"]
        out[name] = {"answered": hit, "of": total, "share": round(hit / total, 4) if total else 0.0}
    built = inventory.build({"held-out": held_out}, tables, {})
    total = built.sources["held-out"]["wrongly_answered"]
    hit = sum(e["held-out"]["count"] for e in built.entries if e["argv"] in answered)
    can = sum(e["held-out"]["count"] for e in built.entries if e["render"])
    out["held-out"] = {
        "answered": hit,
        "of": total,
        "share": round(hit / total, 4) if total else 0.0,
        "a_library_could": can,
    }
    return out


def review(
    library: dict[str, list[Entry]],
    excluded: dict[str, str],
    problems: list[str],
    identity: dict[str, str],
) -> str:
    """The file a person reads before the entries are committed (spec 3.2a, step 4): every
    entry's whole answer, where it came from, and what the library leaves out."""
    lines = [
        "# Render library: review",
        "",
        "Written by `mirage-profile render-library`. Every answer below is what a real Debian 12",
        "host printed; nothing was typed in. Read each one as an attacker would: is there anything",
        "in it that the decoy's story does not support?",
        "",
        f"Reference image: `{identity.get('image', '?')}`, Debian "
        f"{identity.get('debian_version', '?')}, {identity.get('arch', '?')}.",
        "",
    ]
    for directory, entries in sorted(library.items()):
        if not entries:
            continue
        where = "any hardware class" if directory == ANY else f"class `{directory}`"
        lines += [f"## {where}", ""]
        for entry in entries:
            seen = ", ".join(f"{name} {n}" for name, n in entry.inventory.items())
            lines += [
                f"### `{entry.argv}`",
                "",
                f"- From: {entry.source}; program `{entry.program}`; answers "
                f"{'any user' if entry.who == 'any' else 'root only'}.",
                f"- Exit code {entry.exit_code}; output on {entry.streams}; shape {entry.shape}; "
                f"measured {', '.join(map(str, entry.ms))} ms.",
                f"- Inventory count: {seen}. Slots: {', '.join(entry.slots()) or 'none'}.",
                "",
            ]
            for name, text in (("stdout", entry.stdout), ("stderr", entry.stderr)):
                if text:
                    lines += [f"{name}:", "", "```", text.rstrip("\n"), "```", ""]
    lines += ["## Left out", ""]
    if not excluded and not problems:
        lines += ["Nothing.", ""]
    for argv, why in sorted(excluded.items()):
        lines += [f"- `{argv}`: {why}"]
    for problem in problems:
        lines += [f"- **Not built:** {problem}"]
    return "\n".join(lines).rstrip() + "\n"
