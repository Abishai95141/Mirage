"""Runs scenarios against the lab edge and writes the ground truth (spec section 3).

One simulated actor per scenario instance: its own address, client fingerprint, timing draw
and slot values. Actors run concurrently; an actor's sessions run in order. Every step ends in
a ground-truth record whether it ran, failed or was skipped, so the join can account for all
of them.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import random
import re
import time
import uuid
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mirage_lab.drivers.base import Result, failure
from mirage_lab.drivers.plain import HTTPDriver, MySQLDriver, RedisDriver
from mirage_lab.drivers.ssh import Fingerprint, SSHDriver
from mirage_lab.models import (
    DEFAULT_SPLIT,
    Capture,
    Catalogue,
    Goto,
    Procedure,
    Scenario,
    SessionSpec,
    Step,
    check_input,
    lint,
    load_split,
    render,
)
from mirage_lab.net import AddressPool, Conn, Dialer
from mirage_lab.slots import Slots
from mirage_lab.timing import Timing, make
from mirage_lab.truth import KEEP_DAYS, TruthWriter, prune, run_file
from mirage_schema.groundtruth import Connection, GroundTruth, RunRecord, SessionTruth

MAX_STEPS_PER_SESSION = 400  # a bound on retries and gotos, whatever the scenario says


def now() -> datetime:
    return datetime.now(UTC)


def new_run_id() -> str:
    return f"r{datetime.now(UTC):%Y%m%d%H%M%S}-{uuid.uuid4().hex[:6]}"


class InputRefused(ValueError):
    """A rendered input tripped the lint at send time. It is never sent."""


@dataclass
class Settings:
    target_ip: str
    out_dir: Path
    profile_dir: Path
    mode: str = "capture"
    seed: int = 0
    repeat: int = 1
    workers: int = 8
    time_scale: float = 1.0
    code_version: str = "dev"
    # The frozen split, mounted into the runner's container. Without it the one-split rule
    # cannot be checked, and ``run`` refuses to start.
    split_file: Path = field(
        default_factory=lambda: Path(os.environ.get("LAB_SPLIT") or DEFAULT_SPLIT)
    )
    truth_keep_days: float = KEEP_DAYS  # see truth.prune


@dataclass
class Summary:
    run_id: str
    sessions: int = 0
    steps: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def accepted_passwords(profile_dir: Path, user: str) -> list[str]:
    """Every password the decoy accepts for ``user``, in the profile's order. A profile
    renders one to three for root, so "the" password is only the first of them."""
    userdb = profile_dir / "cowrie/userdb.txt"
    if not userdb.is_file():
        return []
    out = []
    for line in userdb.read_text().splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == user and not parts[2].startswith("!"):
            out.append(parts[2])
    return out


def root_password(profile_dir: Path, user: str) -> str:
    """The password the runner logs in with as ``user``, from the deployment profile."""
    accepted = accepted_passwords(profile_dir, user)
    if not accepted:
        raise ValueError(f"the profile has no password for {user!r}")
    return accepted[0]


def db_password(profile_dir: Path, user: str) -> str:
    """A MySQL user's password, from the deployment profile."""
    data = json.loads((profile_dir / "mysql.json").read_text())
    for row in data.get("users", []):
        if row.get("user") == user:
            return str(row.get("password", ""))
    raise ValueError(f"the profile has no MySQL user {user!r}")


def endpoint(ip: str, port: int) -> dict:
    return {"ip": ip, "port": port}


class ActorRun:
    """One simulated actor working through one scenario."""

    def __init__(
        self,
        scenario: Scenario,
        instance: int,
        src_ip: str,
        run_id: str,
        catalogue: Catalogue,
        settings: Settings,
        truth: TruthWriter,
        scenario_ids: Iterable[str] = (),
    ) -> None:
        self.scenario, self.catalogue, self.settings, self.truth = (
            scenario, catalogue, settings, truth,
        )  # fmt: skip
        self.run_id = run_id
        self.actor_ref = f"{run_id}/{scenario.id}/{instance}"
        self.rng = random.Random(f"{settings.seed}:{scenario.id}:{instance}")
        self.dialer = Dialer(settings.target_ip, src_ip, self.rng)
        self.dialers = {1: self.dialer}  # session.source -> that address's dialer
        self.timing: Timing = make(scenario.actor.timing, self.rng, settings.time_scale)
        self.slots = Slots(self.rng)
        self.fingerprint = Fingerprint(self.rng)
        self.failures = 0
        self.steps: dict[str, int] = {}
        self.driver_factory = SSHDriver  # tests put a scripted driver here
        # Every ID an input must not carry (spec section 3, "Lint"): each procedure's and each
        # scenario's, checked again on every rendered input at send time.
        self.forbidden_ids = tuple(
            dict.fromkeys((*catalogue.procedures, scenario.id, *scenario_ids))
        )
        self.captured: dict[str, str] = {}  # values steps took from the decoy's answers
        self.session_error: str | None = None  # the first failure of the session in flight

    def dialer_for(self, source: int) -> Dialer:
        """The dialer for a session's simulated address; extra addresses come from the same
        per-run pool, so two sessions of one actor can arrive from different sources."""
        if source not in self.dialers:
            pool = AddressPool(
                self.settings.out_dir / f"addresses.{self.settings.mode}", self.settings.mode
            )
            ip = pool.take(1)[0]
            self.dialers[source] = Dialer(self.settings.target_ip, ip, self.rng)
        return self.dialers[source]

    # ------------------------------------------------------------------ records

    def _step_record(
        self,
        session_ref: str,
        step_id: str,
        proc: Procedure,
        conn: Conn | None,
        result: Result | None,
        status: str,
        outcome: str = "unchecked",
        evidence: str | None = None,
        attempts: int | None = None,
    ) -> None:
        at = now()
        # Start <= end whatever the driver returned. A record the schema refuses is a record
        # the join never sees, and it used to take the session's record with it (R1).
        start = ((result.started or result.ended) if result else None) or at
        end = max((result.ended if result else None) or at, start)
        kind = evidence or {"input": "input", "upload": "upload", "auth": "auth"}[proc.kind]
        self.truth.write(
            GroundTruth(
                run_id=self.run_id,
                scenario_id=self.scenario.id,
                session_ref=session_ref,
                step_id=step_id,
                procedure_id=proc.id,
                technique_id=proc.technique,
                tactic=proc.tactic,
                attack_version=self.catalogue.attack_version,
                protocol=proc.protocol,
                src=endpoint(self.dialer.src_ip, conn.src_port if conn else 0),
                dst=endpoint(self.dialer.target_ip, conn.dst_port if conn else 0),
                evidence=kind,
                input_sha256=result.sha256 if result else None,
                start_ts=start,
                end_ts=end,
                status=status,
                outcome=outcome,
                attempts=attempts,
            )
        )
        self.steps[status] = self.steps.get(status, 0) + 1

    # ------------------------------------------------------------------ one session

    def _note(self, what: str) -> None:
        """Keep the session's first failure for its record."""
        if self.session_error is None:
            self.session_error = what

    def _password(self, spec: SessionSpec) -> str:
        """What this session logs in with. A login that names a capture uses what the actor
        read off the decoy, or nothing if it read nothing: never the profile's answer, which a
        real attacker would not have (gap register M9)."""
        if spec.login.password_from is not None:
            return self.captured.get(spec.login.password_from, "")
        if spec.protocol == "mysql":
            return db_password(self.settings.profile_dir, spec.login.user)
        return root_password(self.settings.profile_dir, spec.login.user)

    def _make_driver(self, spec: SessionSpec) -> Any:
        """The client for this session's protocol. All share the SSH driver's interface."""
        if spec.protocol == "ssh":
            driver = self.driver_factory(
                self.dialer,
                self.timing,
                self.fingerprint,
                spec.login.user,
                self._password(spec),
                spec.channel,
            )
            # The decoy may accept several passwords for one user. None of them may go out
            # as a "wrong" guess: one sent by chance logs in early, and the session loses
            # the failed attempts its scenario asked for (found by demo 1, one run in six).
            driver.accepted = frozenset(
                accepted_passwords(self.settings.profile_dir, spec.login.user)
            )
            return driver
        if spec.protocol == "http":
            return HTTPDriver(self.dialer, self.timing, self.fingerprint.user_agent)
        if spec.protocol == "redis":
            return RedisDriver(self.dialer, self.timing)
        if spec.protocol == "mysql":
            return MySQLDriver(self.dialer, self.timing, spec.login.user, self._password(spec))
        raise NotImplementedError(f"no driver for {spec.protocol}")

    def session(self, index: int, spec: SessionSpec) -> None:
        session_ref = f"{self.actor_ref}/{index}"
        if spec.gap_s:
            time.sleep(spec.gap_s * self.settings.time_scale)
        started = now()
        saved_dialer, saved_timing = self.dialer, self.timing
        actor_class = spec.actor.class_ if spec.actor is not None else self.scenario.actor.class_
        self.session_error = None
        done: set[str] = set()  # the steps that have their record
        dialer: Dialer | None = None
        driver: Any = None
        first_conn = 0
        try:
            dialer = self.dialer = self.dialer_for(spec.source)
            first_conn = len(dialer.opened)
            if spec.actor is not None:
                self.timing = make(spec.actor.timing, self.rng, self.settings.time_scale)
            driver = self._make_driver(spec)
            login = driver.login(spec.login.guesses)
            if login.error:
                self._note(f"login: {login.error}")
            if spec.login.procedure:
                proc = self.catalogue.procedures[spec.login.procedure]
                for i, phase in enumerate(login.phases):
                    result = Result(sent=True, started=phase.started, ended=phase.ended)
                    self._step_record(
                        session_ref, f"login-{i}", proc, phase.conn, result, "ran",
                        "ok" if phase.success else "failed",  # this connection's own outcome
                        attempts=phase.attempts,  # the join counts the captured ones against it
                    )  # fmt: skip
            if login.ok:
                self._steps(session_ref, spec, driver, done)
        except Exception as exc:
            # Recorded on the session, then raised: the run lists it and exits non-zero.
            self._note(failure(exc))
            raise
        finally:
            # Whatever happened, every step has a record, and a session that reached the decoy
            # has its own. Without the session record the join cannot match the connection,
            # and every step of the session reads as no_event (gap register R1).
            for step in spec.steps:
                self._skip(session_ref, step, done)
            if driver is not None:
                with contextlib.suppress(Exception):
                    driver.close()
            ended = now()
            timing = self.timing
            self.dialer, self.timing = saved_dialer, saved_timing
            conns = dialer.opened[first_conn:] if dialer is not None else []
            if conns:  # else nothing reached the decoy, so there is no session to describe
                self.truth.write(
                    SessionTruth(
                        run_id=self.run_id,
                        scenario_id=self.scenario.id,
                        session_ref=session_ref,
                        protocol=spec.protocol,
                        actor_ref=self.actor_ref,
                        actor_class=actor_class,
                        timing_profile=timing.describe(),
                        mode=self.settings.mode,
                        connections=[
                            Connection(
                                src=endpoint(c.src_ip, c.src_port),
                                dst=endpoint(c.dst_ip, c.dst_port),
                                opened_ts=c.opened,
                                closed_ts=c.closed or ended,
                            )
                            for c in conns
                        ],
                        start_ts=started,
                        end_ts=ended,
                        error=self.session_error,
                    )
                )

    def _steps(self, session_ref: str, spec: SessionSpec, driver: Any, done: set[str]) -> None:
        """Work through the steps, adding each one that gets a record to ``done``. The steps
        still missing from it when this returns, or raises, are recorded as skipped by the
        caller."""
        steps, index, budget = spec.steps, 0, MAX_STEPS_PER_SESSION
        tries: dict[str, int] = {}
        left = False
        previous_len = 0
        while index < len(steps) and budget > 0 and not left:
            budget -= 1
            step = steps[index]
            proc = self.catalogue.procedures[step.procedure]
            tries[step.id] = tries.get(step.id, 0) + 1
            attempt = f"{step.id}" if tries[step.id] == 1 else f"{step.id}~{tries[step.id]}"
            time.sleep(self.timing.gap(previous_len))
            try:
                text = self._render(step, proc)
            except InputRefused:
                # A drawn slot value tripped the input lint. Skip this step, keep the actor
                # going; never send the offending input.
                self._step_record(session_ref, attempt, proc, None, None, "skipped")
                done.add(step.id)
                index += 1
                continue
            result = self._send(proc, text, driver)
            if result.error:
                self._note(f"{attempt}: {result.error}")
            if not result.sent:
                # Nothing reached the decoy. "failed" if the step was tried and the connection
                # broke under it, "skipped" if it was already gone; the join reads both as
                # not_run and looks for no event.
                if result.error:
                    self._step_record(session_ref, attempt, proc, result.conn, result, "failed")
                else:
                    self._step_record(session_ref, attempt, proc, result.conn, None, "skipped")
                done.add(step.id)
                break
            ok, checked = self._ok(step, result)
            if step.capture is not None:
                checked, ok = True, self._capture(step.capture, result.output) and ok
            outcome = "unchecked" if not checked else ("ok" if ok else "failed")
            self._step_record(session_ref, attempt, proc, result.conn, result, "ran", outcome)
            previous_len = len(result.output)
            done.add(step.id)
            if not result.alive:
                break  # the decoy ended the session; nothing more can be sent
            if ok:
                index += 1
                continue
            self.failures += 1
            if self.failures > self.scenario.actor.patience or step.on_fail == "leave":
                left = True
            elif step.on_fail == "retry" and tries[step.id] <= step.retries:
                done.discard(step.id)
            elif isinstance(step.on_fail, Goto):
                target = next(i for i, s in enumerate(steps) if s.id == step.on_fail.goto)
                for skipped in steps[index + 1 : target]:
                    self._skip(session_ref, skipped, done)
                index = target
            else:
                index += 1

    def _skip(self, session_ref: str, step: Step, done: set[str]) -> None:
        if step.id not in done:
            done.add(step.id)
            proc = self.catalogue.procedures[step.procedure]
            self._step_record(session_ref, step.id, proc, None, None, "skipped")

    def _render(self, step: Step, proc: Procedure) -> str:
        values = self.slots.fill(proc.slots(), step.with_)
        text = render(proc.template or "", values)
        problems = check_input(text, self.forbidden_ids)
        if problems:
            # The lint passed on sample values; a drawn value tripped it. Never send it.
            raise InputRefused(f"{self.scenario.id}/{step.id}: {problems[0]}")
        return text

    def _send(self, proc: Procedure, text: str, driver: Any) -> Result:
        if proc.kind == "upload":
            return driver.upload(text, self.slots.payload(self.rng.randint(1024, 65536)))
        return driver.run(text)

    def _capture(self, capture: Capture, output: str) -> bool:
        """Keep the value the step's output shows, if it shows one. The value stays in memory:
        it may be a planted credential, and it is never written to the ground truth."""
        found = re.search(capture.regex, output)
        if found is None or found.group(1) is None:
            return False
        self.captured[capture.name] = found.group(1)
        return True

    @staticmethod
    def _ok(step: Step, result: Result) -> tuple[bool, bool]:
        """(the step succeeded, the scenario checked anything at all)."""
        ok, checked = True, False
        if step.expect is not None:
            checked = True
            ok = ok and re.search(step.expect, result.output) is not None
        if step.expect_status is not None:
            checked = True
            ok = ok and result.status == step.expect_status
        return ok, checked

    def run(self) -> None:
        for index, spec in enumerate(self.scenario.sessions):
            self.session(index, spec)


def scenarios_hash(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.name.encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def run(paths: list[Path], catalogue: Catalogue, settings: Settings) -> Summary:
    # Deduplicate by scenario id: the same scenario reached by two paths (a file and a dir that
    # contains it) must not run twice, or two jobs share an id, RNG seed and ground-truth keys.
    loaded = [Scenario.load(p) for p in paths]
    scenarios = list({s.id: s for s in loaded}.values())
    try:
        split = load_split(settings.split_file)
    except OSError as exc:
        raise ValueError(
            f"refusing to run: no frozen split at {settings.split_file} (LAB_SPLIT), so the "
            "one-split rule cannot be checked"
        ) from exc
    # The split file lists every scenario, so a run of a few still checks its inputs against
    # the IDs of all of them.
    scenario_ids = sorted({s.id for s in scenarios} | set(split.scenarios))
    problems = [
        p
        for s in scenarios
        for p in lint(s, catalogue, Slots.names(), split.procedures, scenario_ids)
    ]
    if problems:
        raise ValueError("lint failed, nothing was sent:\n  " + "\n  ".join(problems))
    run_id = new_run_id()
    jobs = [(s, k) for s in scenarios for k in range(settings.repeat)]
    # Taken before anything is written: a used-up range refuses the run and leaves no trace.
    addresses = AddressPool(settings.out_dir / f"addresses.{settings.mode}", settings.mode).take(
        len(jobs)
    )
    prune(settings.out_dir, settings.truth_keep_days)
    truth = TruthWriter(run_file(settings.out_dir, run_id))
    summary = Summary(run_id)
    started = now()
    actors = [
        ActorRun(s, k, ip, run_id, catalogue, settings, truth, scenario_ids)
        for (s, k), ip in zip(jobs, addresses, strict=True)
    ]

    def work(actor: ActorRun) -> None:
        try:
            actor.run()
        except Exception as exc:
            summary.errors.append(f"{actor.actor_ref}: {type(exc).__name__}: {exc}")

    with ThreadPoolExecutor(max_workers=max(1, settings.workers)) as pool:
        list(pool.map(work, actors))
    for actor in actors:
        for status, n in actor.steps.items():
            summary.steps[status] = summary.steps.get(status, 0) + n
    summary.sessions = truth.counts.get("session", 0)
    truth.write(
        RunRecord(
            run_id=run_id,
            mode=settings.mode,
            started_ts=started,
            ended_ts=now(),
            seed=settings.seed,
            attack_version=catalogue.attack_version,
            catalogue_sha256=catalogue.sha256,
            scenarios_sha256=scenarios_hash(paths),
            code_version=settings.code_version or os.environ.get("MIRAGE_CODE_VERSION", "dev"),
            scenarios=sorted({s.id for s in scenarios}),
            sessions=summary.sessions,
            steps=truth.counts.get("step", 0),
        )
    )
    truth.close()
    return summary
