"""Generated scenarios: current, complete, and built from IDs alone."""

from __future__ import annotations

import yaml

from mirage_lab import generate
from mirage_lab.models import Catalogue, Scenario, lint
from mirage_lab.slots import Slots

ROOT = generate.ROOT
SCENARIOS = generate.SCENARIOS


def _all() -> list[Scenario]:
    return [Scenario.load(p) for p in sorted(SCENARIOS.rglob("*.yaml"))]


def _split() -> dict:
    return yaml.safe_load((ROOT / "eval" / "split.yaml").read_text())


def test_the_checked_in_files_are_what_the_generator_writes():
    assert generate.drift(generate.generate()) == []


def test_every_procedure_is_exercised_by_some_scenario():
    # The reason coverage scenarios exist: a held-out score must cover the held-out catalogue,
    # not the part of it that hand-written scenarios happened to use.
    catalogue = Catalogue.load(ROOT / "lab" / "catalogue")
    used: set[str] = set()
    for sc in _all():
        for session in sc.sessions:
            if session.login.procedure:
                used.add(session.login.procedure)
            used.update(step.procedure for step in session.steps)
    assert sorted(set(catalogue.procedures) - used) == []


def test_a_generated_scenario_stays_inside_one_split():
    of_procedure = {pid: s for s, ids in _split()["procedures"].items() for pid in ids}
    assigned = _split()["scenarios"]
    for sc in _all():
        procs = {st.procedure for s in sc.sessions for st in s.steps}
        procs |= {s.login.procedure for s in sc.sessions if s.login.procedure}
        assert len({of_procedure[p] for p in procs}) == 1, sc.id
        assert assigned[sc.id] == of_procedure[next(iter(procs))], sc.id
        if sc.id.startswith("cover-"):
            assert sc.id.split("-")[1] == assigned[sc.id]


def test_a_human_twin_differs_from_its_original_only_in_the_actor():
    by_id = {sc.id: sc for sc in _all()}
    twins = [sc for sc in by_id.values() if sc.variant_of]
    assert len(twins) == len(generate.HUMAN_BASES)
    for twin in twins:
        base = by_id[twin.variant_of]
        assert twin.actor.class_ == "human" and twin.actor.timing == "human"
        assert base.actor.class_ == "scripted_bot"
        assert [s.model_dump() for s in twin.sessions] == [s.model_dump() for s in base.sessions]
        assert all(s.protocol == "ssh" and s.channel == "shell" for s in twin.sessions)


def test_every_scenario_passes_the_lint():
    catalogue = Catalogue.load(ROOT / "lab" / "catalogue")
    problems = [p for sc in _all() for p in lint(sc, catalogue, Slots.names())]
    assert problems == []


def test_a_scanner_cannot_have_authenticated_activity():
    # Spec 2.3: a scanner has no authenticated activity. A session that logs in and runs steps
    # is a scripted bot, whatever the scenario's author called it.
    catalogue = Catalogue.load(ROOT / "lab" / "catalogue")
    by_id = {sc.id: sc for sc in _all()}
    sweep = by_id["bot-port-sweep"].model_dump(by_alias=True)
    sweep["actor"] = {"class": "scanner", "timing": "scan", "patience": 4}
    problems = lint(Scenario.model_validate(sweep), catalogue, Slots.names())
    assert any("a scanner has no authenticated activity" in p for p in problems)
    # an HTTP path sweep is still a scanner's
    web = by_id["scanner-web-app"]
    assert web.actor.class_ == "scanner" and lint(web, catalogue, Slots.names()) == []
