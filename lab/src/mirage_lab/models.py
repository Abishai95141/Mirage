"""Scenario and catalogue files, and the lint that runs before anything is sent.

A procedure is one concrete way of doing a technique: a template with slots. Procedures live
in the catalogue and scenarios only name them, so a procedure's text exists in one place and
the train/test split by procedure can be checked by content (spec section 5).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from mirage_schema.groundtruth import TACTIC_ID, TECHNIQUE_ID, ActorClass

ID = r"^[a-z0-9][a-z0-9-]{3,63}$"  # procedures and scenarios: long enough to search for
STEP_ID = r"^[a-z0-9][a-z0-9-]{0,31}$"  # local to a session
CAPTURE_NAME = r"^[a-z][a-z0-9_]{0,31}$"  # local to a scenario
DEFAULT_SPLIT = "/lab/split.yaml"  # where the runner's container mounts eval/split.yaml
SLOT_RE = re.compile(r"\{\{([a-z]+\d*)\}\}")
# What an input must never contain: it would hand the label, or the fact that this is a lab,
# to anything that reads the command (spec section 3, "Lint").
TECHNIQUE_IN_TEXT = re.compile(r"\bTA?\d{4}(\.\d{3})?\b")
MARKER_WORDS = ("mirage", "atomic", "scenario", "selftest", "gate1", "honeypot", "cowrie")

Protocol = Literal["ssh", "http", "redis", "mysql"]

# The catalogue holds three sets of procedures. The phase 2 set is frozen: its hash pins the
# phase 2 split and every dataset made from it. Phase 3's depth procedures (spec 3.0) live in
# files of their own, are hashed apart and get a split of their own, so adding or correcting
# one never unpins anything of phase 2. Demo 3's procedures (spec 3.8) were written after both
# of those were frozen, so they are a third set, hashed apart again. It is in no split: its
# steps are neither training nor evaluation data unless something takes them in on purpose.
PHASE2, DEPTH, DEMO = "phase2", "depth", "demo"
DEPTH_FILE = re.compile(r"^9\d*-depth-.+\.yaml$")  # lab/catalogue/9*-depth-*.yaml
DEMO_FILE = re.compile(r"^9\d*-demo-.+\.yaml$")  # lab/catalogue/9*-demo-*.yaml
DEPTH_SPLIT = "split-depth.yaml"  # beside the phase 2 split file
# The sets with inputs that really run somewhere: depth scenarios on the reference host, and
# demo 3's second part in a sandbox. Their inputs are held to the run-safety rules below.
REAL_HOST_SETS = frozenset({DEPTH, DEMO})


def set_of_file(name: str) -> str:
    """The catalogue set a file belongs to, from its name."""
    if DEPTH_FILE.match(name):
        return DEPTH
    return DEMO if DEMO_FILE.match(name) else PHASE2


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _compiled(regex: str, what: str) -> re.Pattern[str]:
    """The pattern, or a ValueError a validator can raise: pydantic reports those, where a
    bare ``re.error`` would surface as a traceback."""
    try:
        return re.compile(regex)
    except re.error as exc:
        raise ValueError(f"{what} is not a regular expression: {exc}") from exc


class Procedure(_Strict):
    id: str = Field(pattern=ID)
    technique: str | None = Field(default=None, pattern=TECHNIQUE_ID)
    tactic: str | None = Field(default=None, pattern=TACTIC_ID)
    source: Literal["own", "atomic", "corpus"]
    protocol: Protocol
    kind: Literal["input", "upload", "auth"] = "input"
    template: str | None = None
    ref: str | None = None  # where it came from, e.g. an Atomic Red Team test GUID

    @model_validator(mode="after")
    def _consistent(self) -> Procedure:
        if (self.technique is None) != (self.tactic is None):
            raise ValueError(f"{self.id}: technique and tactic are given together or not at all")
        if self.kind == "input" and not self.template:
            raise ValueError(f"{self.id}: an input procedure needs a template")
        if self.kind != "input" and self.template and self.kind == "auth":
            raise ValueError(f"{self.id}: an auth procedure has no template")
        return self

    def slots(self) -> list[str]:
        return SLOT_RE.findall(self.template or "")


class Catalogue(_Strict):
    attack_version: str
    procedures: dict[str, Procedure]
    sha256: str  # of every file loaded
    set_of: dict[str, str] = Field(default_factory=dict)  # procedure ID -> its set
    set_sha256: dict[str, str] = Field(default_factory=dict)  # each set, hashed as the whole is

    @classmethod
    def load(cls, directory: Path) -> Catalogue:
        """Every ``*.yaml`` in the directory, in name order. One ATT&CK version for all."""
        procedures: dict[str, Procedure] = {}
        versions: set[str] = set()
        digest = hashlib.sha256()
        by_set: dict[str, Any] = {}
        set_of: dict[str, str] = {}
        files = sorted(directory.glob("*.yaml"))
        if not files:
            raise ValueError(f"no catalogue files in {directory}")
        for path in files:
            raw = path.read_bytes()
            which = set_of_file(path.name)
            for d in (digest, by_set.setdefault(which, hashlib.sha256())):
                d.update(path.name.encode() + b"\0" + raw)
            doc = yaml.safe_load(raw) or {}
            versions.add(str(doc.get("attack_version", "")))
            for item in doc.get("procedures", []):
                proc = Procedure.model_validate(item)
                if proc.id in procedures:
                    raise ValueError(f"{path.name}: procedure {proc.id} is defined twice")
                procedures[proc.id] = proc
                set_of[proc.id] = which
        if len(versions) != 1 or "" in versions:
            raise ValueError(f"catalogue files must all name one attack_version, got {versions}")
        return cls(
            attack_version=versions.pop(),
            procedures=procedures,
            sha256=digest.hexdigest(),
            set_of=set_of,
            set_sha256={k: d.hexdigest() for k, d in by_set.items()},
        )

    def only(self, which: str) -> Catalogue:
        """One set as a catalogue of its own, with that set's hash. The phase 2 set's hash is
        what the catalogue's was before any depth file existed."""
        if which not in self.set_sha256:
            raise KeyError(f"the catalogue has no {which} procedures")
        keep = {pid: p for pid, p in self.procedures.items() if self.set_of[pid] == which}
        return Catalogue(
            attack_version=self.attack_version,
            procedures=keep,
            sha256=self.set_sha256[which],
            set_of={pid: which for pid in keep},
            set_sha256={which: self.set_sha256[which]},
        )

    def set_of_scenario(self, scenario: Scenario) -> str | None:
        """The set a scenario's procedures come from, or ``None`` if it mixes sets or names a
        procedure the catalogue does not have (the lint reports both)."""
        used = {st.procedure for s in scenario.sessions for st in s.steps}
        used |= {s.login.procedure for s in scenario.sessions if s.login.procedure}
        sets = {self.set_of.get(pid) for pid in used}
        return sets.pop() if len(sets) == 1 else None


class Goto(_Strict):
    goto: str


class Capture(_Strict):
    """A value the actor takes from a step's output and keeps under a name, for a later
    session's login (``password_from``). It is how a simulated attacker uses what the decoy
    showed it instead of what the runner happens to know: if the decoy withholds the value,
    the actor does not have it."""

    name: str = Field(pattern=CAPTURE_NAME)
    regex: str  # searched in the output; its one group is the value

    @model_validator(mode="after")
    def _one_group(self) -> Capture:
        if _compiled(self.regex, f"capture {self.name}").groups != 1:
            raise ValueError(f"capture {self.name}: the regex must have exactly one group")
        return self


class Step(_Strict):
    id: str = Field(pattern=STEP_ID)
    procedure: str
    with_: dict[str, str] = Field(default_factory=dict, alias="with")
    expect: str | None = None  # regex searched in the output
    expect_status: int | None = None  # exit status; exec channels only
    capture: Capture | None = None  # a miss fails the step, as a failed ``expect`` does
    on_fail: Literal["continue", "retry", "leave"] | Goto = "continue"
    retries: int = Field(default=1, ge=1, le=5)

    @model_validator(mode="after")
    def _expect_compiles(self) -> Step:
        if self.expect is not None:
            _compiled(self.expect, f"step {self.id}: expect")
        return self


class Login(_Strict):
    user: str = "root"
    guesses: int = Field(default=0, ge=0, le=50)  # failed attempts before the right password
    procedure: str | None = None  # the auth procedure the guessing is labelled with
    # Log in with a value an earlier session captured, not the profile's password. If the
    # capture missed, the login is tried with an empty password and fails.
    password_from: str | None = Field(default=None, pattern=CAPTURE_NAME)


class SessionActor(_Strict):
    """A session's own actor class and pacing, when they differ from the scenario's (the
    demo that reuses stolen credentials sweeps the web as a scanner, then logs in to the
    database as a bot, from a second address)."""

    class_: ActorClass = Field(alias="class")
    timing: Literal["scan", "bot-fast", "bot-slow", "human"]


class SessionSpec(_Strict):
    protocol: Protocol
    channel: Literal["shell", "exec"] = "shell"
    login: Login = Field(default_factory=Login)
    gap_s: float = Field(default=0.0, ge=0.0, le=3600.0)  # pause before this session
    source: int = Field(default=1, ge=1, le=8)  # which simulated address the session dials from
    actor: SessionActor | None = None  # overrides the scenario's actor for this session
    steps: list[Step] = Field(default_factory=list)


class Actor(_Strict):
    class_: ActorClass = Field(alias="class")
    timing: Literal["scan", "bot-fast", "bot-slow", "human"]
    patience: int = Field(default=2, ge=0, le=20)  # failed steps tolerated before leaving


class Scenario(_Strict):
    id: str = Field(pattern=ID)
    actor: Actor
    # Set on a scenario that repeats another one's steps under a different actor (a human-paced
    # twin of a bot scenario, say). The two are held out together when the classifier is scored,
    # so a model never trains on one and is tested on the other.
    variant_of: str | None = Field(default=None, pattern=ID)
    sessions: list[SessionSpec] = Field(min_length=1)

    @classmethod
    def load(cls, path: Path) -> Scenario:
        data = yaml.safe_load(path.read_text())
        if not isinstance(data, dict) or "sessions" not in data:
            # A folder given as SCENARIOS is read recursively, so /lab picks up the procedure
            # catalogue and the split files too. Say that, not what the model expected.
            kind = (
                " (it is a procedure catalogue)"
                if isinstance(data, dict) and "procedures" in data
                else ""
            )
            raise NotAScenario(
                f"{path} is not a scenario file{kind}. Scenario files are under /lab/scenarios: "
                "for example SCENARIOS=/lab/scenarios/demo"
            )
        return cls.model_validate(data)


class NotAScenario(ValueError):
    """A file given as a scenario that is not one: the runner and the lint refuse it by name."""


def render(template: str, values: dict[str, str]) -> str:
    return SLOT_RE.sub(lambda m: values[m.group(1)], template)


def check_input(text: str, forbidden_ids: tuple[str, ...] = ()) -> list[str]:
    """Problems with one rendered input. Run on every input, every time, before it is sent."""
    problems = []
    if text != text.strip() or "\n" in text or "\r" in text:
        problems.append("input must be one line with no surrounding whitespace")
    if TECHNIQUE_IN_TEXT.search(text):
        problems.append("input contains an ATT&CK ID")
    low = text.lower()
    for word in MARKER_WORDS:
        if word in low:
            problems.append(f"input contains the marker word {word!r}")
    for ident in forbidden_ids:
        if ident and ident.lower() in low:
            problems.append(f"input contains the ID {ident!r}")
    return problems


# ---------------------------------------------------------------- inputs that really run
#
# Against a decoy nothing is executed. On the reference host (arm R of phase 3's depth
# comparison) and in the sandbox every input runs as root in a real, throwaway container.
# That container has no egress and tight limits, and these rules are the second line: an
# input that tries to leave the container, reach its host or exhaust a resource is refused
# by the lint for every depth procedure, and again by the runner on the rendered input
# before it is sent to a real host. A deny list cannot prove an input safe; it stops the
# known ways of doing harm and anything new is caught, if at all, by the container.

_IPV4 = re.compile(r"(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\w.])")
# Addresses an input may name literally: loopback, "any", netmasks and the three ranges
# reserved for documentation. Everything a scenario aims at comes from a slot.
_OPEN_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("127.0.0.0/8", "0.0.0.0/32", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
_FILL_SOURCE = re.compile(r"\bif=/dev/(zero|urandom|random|full)\b")
_RUN_SAFETY: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("starts a process flood", re.compile(r":\s*\(\s*\)\s*\{[^}]*\|[^}]*&[^}]*\}")),
    (
        "loops without end",
        re.compile(
            r"\bwhile\s+(true|:|1|\[\s*1\s*\])(\s|;)|\buntil\s+false\b|\bfor\s*\(\(\s*;\s*;"
        ),
    ),
    ("writes without end", re.compile(r"(^|[;&|]\s*)yes\b(?![^|]*\|\s*head\b)")),
    (
        "fills disk or memory",
        re.compile(r"\bfallocate\b|\bstress(-ng)?\b|\btruncate\s+(-s|--size)[= ]*\+?\d+\s*[GgTt]"),
    ),
    (
        "touches a raw device",
        re.compile(
            r"/dev/(sd[a-z]|nvme\d|vd[a-z]|xvd[a-z]|mem\b|kmem\b|port\b|mapper/|dm-\d|loop\d)"
            r"|\b(mknod|mkfs(\.\w+)?|fdisk|parted|wipefs|losetup|blkdiscard)\b"
        ),
    ),
    (
        "reaches for the kernel",
        re.compile(
            r"\b(insmod|modprobe|rmmod|kexec|bpftool)\b|/proc/sysrq-trigger"
            r"|/proc/sys/kernel/(core_pattern|modprobe|sysrq)|\bsysctl\s+(-w|--write)\b"
        ),
    ),
    (
        "reaches for the container's boundary",
        re.compile(
            r"(docker|containerd|crio|podman)\.sock|/run/(docker|containerd|crio)\b"
            r"|\b(nsenter|unshare|pivot_root|runc|crictl|kubectl|capsh|setcap)\b"
            r"|/proc/1/(root|ns)\b|release_agent|notify_on_release"
            r"|\bmount\s+(-|/|\w+\s+/)|\bumount\b|\bchroot\b"
        ),
    ),
    (
        "stops or signals the whole host",
        re.compile(
            r"\b(reboot|shutdown|halt|poweroff|telinit)\b|\binit\s+[06]\b"
            r"|\bkill(all5)?\s+(-\w+\s+)*-?1(\s|;|$)"
        ),
    ),
)


def check_run_safety(text: str) -> list[str]:
    """Why an input may not be run on a real host; an empty list means these rules have
    nothing against it. Each problem names the rule, never the input."""
    problems = [
        f"an input that really runs {name}" for name, pattern in _RUN_SAFETY if pattern.search(text)
    ]
    if _FILL_SOURCE.search(text) and not re.search(r"\bcount=\d+", text):
        problems.append("an input that really runs copies from an endless device with no count")
    for match in _IPV4.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue  # not an address (a version number, say)
        if not any(address in net for net in _OPEN_NETS) and not match.group(0).startswith("255."):
            problems.append(
                "an input that really runs names a literal address outside the reserved ranges"
            )
            break
    return problems


@dataclass(frozen=True)
class Split:
    """The frozen split (``eval/split.yaml``, spec section 5), as far as the lab reads it."""

    procedures: dict[str, str]  # procedure ID -> train, dev or test
    scenarios: dict[str, str]  # scenario ID -> the split of its procedures


def load_split(path: Path) -> Split:
    """Read the split file, and the depth split beside it if there is one (its halves are
    ``dev`` and ``test``, held out as the phase 2 ones are). A missing phase 2 file raises
    ``OSError``: the caller decides whether that is a warning (lint) or a refusal (the
    runner)."""
    procedures: dict[str, str] = {}
    scenarios: dict[str, str] = {}
    depth = path.with_name(DEPTH_SPLIT)
    for file in (path, depth) if depth.is_file() else (path,):
        text = file.read_text()
        try:
            doc = yaml.safe_load(text)
            for split, ids in doc["procedures"].items():
                for pid in ids:
                    if pid in procedures:
                        raise ValueError(f"{file}: procedure {pid} is in two splits")
                    procedures[pid] = str(split)
            scenarios.update({str(k): str(v) for k, v in (doc.get("scenarios") or {}).items()})
        except (yaml.YAMLError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError(f"{file} is not a split file: no procedures by split") from exc
    return Split(procedures, scenarios)


def lint(
    scenario: Scenario,
    catalogue: Catalogue,
    slot_names: frozenset[str],
    splits: dict[str, str] | None = None,
    scenario_ids: Iterable[str] = (),
) -> list[str]:
    """Everything wrong with a scenario. An empty list means it may run. ``splits`` is the
    frozen split by procedure; ``scenario_ids`` are the IDs of every other scenario."""
    out: list[str] = []
    used_splits: set[str] = set()
    used_sets: set[str] = set()
    # An input must not carry any procedure's or scenario's ID, not only its own step's: a
    # command that names another procedure hands a reader the label just the same.
    forbidden = tuple(dict.fromkeys((*catalogue.procedures, scenario.id, *scenario_ids)))
    captured: set[str] = set()  # names captured by the sessions before this one
    misplaced: set[str] = set()  # demo procedures that a split file names

    def split_of(proc: Procedure) -> str:
        """The split a procedure is in. A demo procedure is in none, by design, and that
        counts as a place of its own; any other procedure needs one."""
        placed = (splits or {}).get(proc.id)
        if catalogue.set_of.get(proc.id) == DEMO:
            if placed is not None:
                misplaced.add(proc.id)
            return DEMO
        return placed or "unassigned"

    for si, session in enumerate(scenario.sessions):
        where = f"{scenario.id} session {si}"
        ids = [s.id for s in session.steps]
        if len(ids) != len(set(ids)):
            out.append(f"{where}: step IDs are not unique")
        wanted = session.login.password_from
        if wanted is not None:
            if session.protocol not in ("ssh", "mysql"):
                out.append(f"{where}: only SSH and MySQL sessions log in with a password")
            if wanted not in captured:
                out.append(
                    f"{where}: password_from names {wanted!r}, which no earlier session captures"
                )
        capturing: set[str] = set()
        # The class definitions (spec 2.3): a scanner has no authenticated activity. A session
        # that logs in and then runs steps is automated activity after access, a scripted bot.
        acting = session.actor.class_ if session.actor else scenario.actor.class_
        # Redis here asks for no login, so a step on it is activity with access too.
        if acting == "scanner" and session.protocol in ("ssh", "mysql", "redis") and session.steps:
            out.append(
                f"{where}: a scanner has no authenticated activity; "
                "give this session a scripted_bot actor or remove its steps"
            )
        if session.login.procedure is not None:
            proc = catalogue.procedures.get(session.login.procedure)
            if proc is None or proc.kind != "auth" or proc.protocol != session.protocol:
                out.append(f"{where}: login procedure must be an auth procedure for this protocol")
            elif session.protocol not in ("ssh", "mysql"):
                out.append(f"{where}: only SSH and MySQL sessions authenticate")
            else:
                # The login's procedure counts as one of the scenario's, as its steps' do.
                used_sets.add(catalogue.set_of.get(proc.id, PHASE2))
                if splits is not None:
                    used_splits.add(split_of(proc))
        for i, step in enumerate(session.steps):
            at = f"{where} step {step.id}"
            proc = catalogue.procedures.get(step.procedure)
            if proc is None:
                out.append(f"{at}: unknown procedure {step.procedure!r}")
                continue
            if proc.protocol != session.protocol:
                out.append(f"{at}: procedure is for {proc.protocol}, session is {session.protocol}")
            if proc.kind == "auth":
                out.append(f"{at}: an auth procedure belongs under login, not in steps")
            if proc.kind == "upload" and proc.protocol != "ssh":
                out.append(f"{at}: only SSH procedures can upload")
            if step.expect_status is not None and session.channel != "exec":
                out.append(f"{at}: expect_status needs an exec channel")
            if isinstance(step.on_fail, Goto):
                target = step.on_fail.goto
                if target not in ids[i + 1 :]:
                    out.append(f"{at}: goto {target!r} must name a later step")
            unknown = [s for s in proc.slots() if s.rstrip("0123456789") not in slot_names]
            if unknown:
                out.append(f"{at}: unknown slots {unknown}")
            stray = sorted(set(step.with_) - set(proc.slots()))
            if stray:
                out.append(f"{at}: 'with' names slots the procedure does not have: {stray}")
            if proc.template and not unknown:
                sample = render(proc.template, {s: step.with_.get(s, "x") for s in proc.slots()})
                for problem in check_input(sample, forbidden):
                    out.append(f"{at}: {problem}")
                if catalogue.set_of.get(proc.id) in REAL_HOST_SETS:
                    for problem in check_run_safety(sample):
                        out.append(f"{at}: {problem}")
            if step.capture is not None:
                if proc.kind == "upload":
                    out.append(f"{at}: an upload has no output to capture from")
                if step.capture.name in captured | capturing:
                    out.append(f"{at}: capture name {step.capture.name!r} is already used")
                capturing.add(step.capture.name)
            used_sets.add(catalogue.set_of.get(proc.id, PHASE2))
            if splits is not None:
                used_splits.add(split_of(proc))
        captured |= capturing
    # A depth scenario and a phase 2 one are split apart and held out apart. A scenario that
    # drew on both would tie the two splits together through its procedures.
    if len(used_sets) > 1:
        out.append(f"{scenario.id}: mixes catalogue sets {sorted(used_sets)}")
    for pid in sorted(misplaced):
        out.append(f"{scenario.id}: demo procedure {pid} is named by a split; that set has none")
    if splits is not None:
        if "unassigned" in used_splits:
            out.append(f"{scenario.id}: uses a procedure with no split")
        if len(used_splits) > 1:
            out.append(f"{scenario.id}: mixes splits {sorted(used_splits)}")
    return out
