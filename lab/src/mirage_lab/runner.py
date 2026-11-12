"""Runs scenarios against the lab edge and writes the ground truth (spec section 3).

One simulated actor per scenario instance: its own address, client fingerprint, timing draw
and slot values. Actors run concurrently; an actor's sessions run in order. Every step ends in
a ground-truth record whether it ran, failed or was skipped, so the join can account for all
of them.
"""

from __future__ import annotations

import hashlib
import os
import random
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from mirage_lab.drivers.base import Result
from mirage_lab.drivers.ssh import Fingerprint, SSHDriver
from mirage_lab.models import (
    Catalogue,
    Goto,
    Procedure,
    Scenario,
    SessionSpec,
    Step,
    check_input,
    lint,
    render,
)
from mirage_lab.net import AddressPool, Conn, Dialer
from mirage_lab.slots import Slots
from mirage_lab.timing import Timing, make
from mirage_lab.truth import TruthWriter
from mirage_schema.groundtruth import Connection, GroundTruth, RunRecord, SessionTruth

MAX_STEPS_PER_SESSION = 400  # a bound on retries and gotos, whatever the scenario says


def now() -> datetime:
    return datetime.now(UTC)


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


@dataclass
class Summary:
    run_id: str
    sessions: int = 0
    steps: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def root_password(profile_dir: Path, user: str) -> str:
    """The password the decoy accepts for ``user``, from the deployment profile."""
    for line in (profile_dir / "cowrie/userdb.txt").read_text().splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == user and not parts[2].startswith("!"):
            return parts[2]
    raise ValueError(f"the profile has no password for {user!r}")


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
    ) -> None:
        self.scenario, self.catalogue, self.settings, self.truth = (
            scenario, catalogue, settings, truth,
        )  # fmt: skip
        self.run_id = run_id
        self.actor_ref = f"{run_id}/{scenario.id}/{instance}"
        self.rng = random.Random(f"{settings.seed}:{scenario.id}:{instance}")
        self.dialer = Dialer(settings.target_ip, src_ip, self.rng)
        self.timing: Timing = make(scenario.actor.timing, self.rng, settings.time_scale)
        self.slots = Slots(self.rng)
        self.fingerprint = Fingerprint(self.rng)
        self.failures = 0
        self.steps: dict[str, int] = {}
        self.driver_factory = SSHDriver  # tests put a scripted driver here

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
    ) -> None:
        at = now()
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
                start_ts=(result.started if result and result.started else at),
                end_ts=(result.ended if result and result.ended else at),
                status=status,
                outcome=outcome,
            )
        )
        self.steps[status] = self.steps.get(status, 0) + 1

    # ------------------------------------------------------------------ one session

    def session(self, index: int, spec: SessionSpec) -> None:
        if spec.protocol != "ssh":
            raise NotImplementedError(f"no driver for {spec.protocol} yet")
        session_ref = f"{self.actor_ref}/{index}"
        if spec.gap_s:
            time.sleep(spec.gap_s * self.settings.time_scale)
        started = now()
        first_conn = len(self.dialer.opened)
        password = root_password(self.settings.profile_dir, spec.login.user)
        driver = self.driver_factory(
            self.dialer, self.timing, self.fingerprint, spec.login.user, password, spec.channel
        )
        try:
            login = driver.login(spec.login.guesses)
            if spec.login.procedure:
                proc = self.catalogue.procedures[spec.login.procedure]
                for i, phase in enumerate(login.phases):
                    result = Result(sent=True, started=phase.started, ended=phase.ended)
                    self._step_record(
                        session_ref, f"login-{i}", proc, phase.conn, result, "ran",
                        "ok" if login.ok else "failed",
                    )  # fmt: skip
            if login.ok:
                self._steps(session_ref, spec, driver)
            else:
                for step in spec.steps:
                    proc = self.catalogue.procedures[step.procedure]
                    self._step_record(session_ref, step.id, proc, None, None, "skipped")
        finally:
            driver.close()
        ended = now()
        conns = self.dialer.opened[first_conn:]
        if not conns:
            return  # nothing reached the decoy, so there is no session to describe
        self.truth.write(
            SessionTruth(
                run_id=self.run_id,
                scenario_id=self.scenario.id,
                session_ref=session_ref,
                protocol=spec.protocol,
                actor_ref=self.actor_ref,
                actor_class=self.scenario.actor.class_,
                timing_profile=self.timing.describe(),
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
            )
        )

    def _steps(self, session_ref: str, spec: SessionSpec, driver: SSHDriver) -> None:
        steps, index, budget = spec.steps, 0, MAX_STEPS_PER_SESSION
        tries: dict[str, int] = {}
        done: set[str] = set()
        left = False
        previous_len = 0
        while index < len(steps) and budget > 0 and not left:
            budget -= 1
            step = steps[index]
            proc = self.catalogue.procedures[step.procedure]
            tries[step.id] = tries.get(step.id, 0) + 1
            attempt = f"{step.id}" if tries[step.id] == 1 else f"{step.id}~{tries[step.id]}"
            time.sleep(self.timing.gap(previous_len))
            result = self._send(step, proc, driver)
            if not result.sent:
                self._step_record(session_ref, attempt, proc, result.conn, None, "skipped")
                done.add(step.id)
                break
            ok, checked = self._ok(step, result)
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
        for step in steps:
            self._skip(session_ref, step, done)

    def _skip(self, session_ref: str, step: Step, done: set[str]) -> None:
        if step.id not in done:
            done.add(step.id)
            proc = self.catalogue.procedures[step.procedure]
            self._step_record(session_ref, step.id, proc, None, None, "skipped")

    def _send(self, step: Step, proc: Procedure, driver: SSHDriver) -> Result:
        values = self.slots.fill(proc.slots(), step.with_)
        text = render(proc.template or "", values)
        problems = check_input(text, (proc.id, self.scenario.id))
        if problems:
            # The lint passed on sample values; a drawn value tripped it. Never send it.
            raise ValueError(f"{self.scenario.id}/{step.id}: {problems[0]}")
        if proc.kind == "upload":
            return driver.upload(text, self.slots.payload(self.rng.randint(1024, 65536)))
        return driver.run(text)

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
    scenarios = [Scenario.load(p) for p in paths]
    problems = [p for s in scenarios for p in lint(s, catalogue, Slots.names())]
    if problems:
        raise ValueError("lint failed, nothing was sent:\n  " + "\n  ".join(problems))
    run_id = f"r{datetime.now(UTC):%Y%m%d%H%M%S}-{uuid.uuid4().hex[:6]}"
    truth = TruthWriter(settings.out_dir / "groundtruth.json")
    jobs = [(s, k) for s in scenarios for k in range(settings.repeat)]
    addresses = AddressPool(settings.out_dir / f"addresses.{settings.mode}", settings.mode).take(
        len(jobs)
    )
    summary = Summary(run_id)
    started = now()
    actors = [
        ActorRun(s, k, ip, run_id, catalogue, settings, truth)
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
