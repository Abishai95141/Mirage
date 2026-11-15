"""Scenario and catalogue files, and the lint that runs before anything is sent.

A procedure is one concrete way of doing a technique: a template with slots. Procedures live
in the catalogue and scenarios only name them, so a procedure's text exists in one place and
the train/test split by procedure can be checked by content (spec section 5).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

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
    sha256: str

    @classmethod
    def load(cls, directory: Path) -> Catalogue:
        """Every ``*.yaml`` in the directory, in name order. One ATT&CK version for all."""
        procedures: dict[str, Procedure] = {}
        versions: set[str] = set()
        digest = hashlib.sha256()
        files = sorted(directory.glob("*.yaml"))
        if not files:
            raise ValueError(f"no catalogue files in {directory}")
        for path in files:
            raw = path.read_bytes()
            digest.update(path.name.encode() + b"\0" + raw)
            doc = yaml.safe_load(raw) or {}
            versions.add(str(doc.get("attack_version", "")))
            for item in doc.get("procedures", []):
                proc = Procedure.model_validate(item)
                if proc.id in procedures:
                    raise ValueError(f"{path.name}: procedure {proc.id} is defined twice")
                procedures[proc.id] = proc
        if len(versions) != 1 or "" in versions:
            raise ValueError(f"catalogue files must all name one attack_version, got {versions}")
        return cls(attack_version=versions.pop(), procedures=procedures, sha256=digest.hexdigest())


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
        return cls.model_validate(yaml.safe_load(path.read_text()))


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


@dataclass(frozen=True)
class Split:
    """The frozen split (``eval/split.yaml``, spec section 5), as far as the lab reads it."""

    procedures: dict[str, str]  # procedure ID -> train, dev or test
    scenarios: dict[str, str]  # scenario ID -> the split of its procedures


def load_split(path: Path) -> Split:
    """Read the split file. A missing file raises ``OSError``: the caller decides whether that
    is a warning (lint) or a refusal (the runner)."""
    text = path.read_text()
    procedures: dict[str, str] = {}
    try:
        doc = yaml.safe_load(text)
        for split, ids in doc["procedures"].items():
            for pid in ids:
                if pid in procedures:
                    raise ValueError(f"{path}: procedure {pid} is in two splits")
                procedures[pid] = str(split)
        scenarios = {str(k): str(v) for k, v in (doc.get("scenarios") or {}).items()}
    except (yaml.YAMLError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError(f"{path} is not a split file: no procedures by split") from exc
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
    # An input must not carry any procedure's or scenario's ID, not only its own step's: a
    # command that names another procedure hands a reader the label just the same.
    forbidden = tuple(dict.fromkeys((*catalogue.procedures, scenario.id, *scenario_ids)))
    captured: set[str] = set()  # names captured by the sessions before this one
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
            elif splits is not None:
                used_splits.add(splits.get(proc.id, "unassigned"))
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
            if step.capture is not None:
                if proc.kind == "upload":
                    out.append(f"{at}: an upload has no output to capture from")
                if step.capture.name in captured | capturing:
                    out.append(f"{at}: capture name {step.capture.name!r} is already used")
                capturing.add(step.capture.name)
            if splits is not None:
                used_splits.add(splits.get(proc.id, "unassigned"))
        captured |= capturing
    if splits is not None:
        if "unassigned" in used_splits:
            out.append(f"{scenario.id}: uses a procedure with no split")
        if len(used_splits) > 1:
            out.append(f"{scenario.id}: mixes splits {sorted(used_splits)}")
    return out
