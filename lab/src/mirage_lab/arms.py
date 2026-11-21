"""Runs against one arm of phase 3's depth comparison, read from the runner's own records.

The comparison's figure (phase 3 spec, section 5) is, per session, the number of distinct
ground-truth techniques among the steps the runner recorded as succeeded. It is taken from the
runner's records and from nothing else, so it is measured the same way on every arm, including
the two that have no gate and no label join behind them: stock Cowrie and the reference host.

A run against the reference host also leaves ``failed-checks.jsonl``: for every check that
failed, the pattern and what the host answered. On that arm a failed check is a broken check
(the spec's R20), and this is how it is found.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from mirage_lab.truth import TRUTH_NAME

FAILED_CHECKS = "failed-checks.jsonl"


def succeeded(step: dict[str, Any]) -> bool:
    """A step the runner sent and whose check, if it had one, held."""
    return step["status"] == "ran" and step.get("outcome", "unchecked") != "failed"


def records(directory: Path) -> list[dict[str, Any]]:
    out = []
    for path in sorted(directory.glob(TRUTH_NAME + ".*")):
        for line in path.read_text().splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


def report(directory: Path) -> dict[str, Any]:
    """Per session and per scenario: how far the attacker got. A step that was retried counts
    once, by its last attempt."""
    steps: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    scenario_of: dict[tuple[str, str], str] = {}
    errors: dict[tuple[str, str], str] = {}
    for r in records(directory):
        key = (r.get("run_id", ""), r.get("session_ref", ""))
        if r.get("kind") == "step":
            steps[key][r["step_id"].split("~")[0]] = r
            scenario_of[key] = r["scenario_id"]
        elif r.get("kind") == "session":
            scenario_of[key] = r["scenario_id"]
            if r.get("error"):
                errors[key] = r["error"]

    sessions = []
    for key in sorted(scenario_of):
        mine = list(steps.get(key, {}).values())
        work = [s for s in mine if s.get("evidence") != "auth"]
        good = [s for s in work if succeeded(s)]
        sessions.append(
            {
                "run_id": key[0],
                "session_ref": key[1],
                "scenario_id": scenario_of[key],
                "steps": len(work),
                "succeeded": len(good),
                "check_failed": sorted(
                    (s["step_id"], s["procedure_id"])
                    for s in work
                    if s["status"] == "ran" and s.get("outcome") == "failed"
                ),
                "not_sent": sum(1 for s in work if s["status"] != "ran"),
                "techniques": len({s["technique_id"] for s in good if s.get("technique_id")}),
                "techniques_possible": len(
                    {s["technique_id"] for s in work if s.get("technique_id")}
                ),
                "sent": sum(1 for s in work if s["status"] == "ran"),
                "error": errors.get(key),
            }
        )

    by_scenario: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in sessions:
        by_scenario[s["scenario_id"]].append(s)

    def mean(values: list[float]) -> float:
        return round(sum(values) / len(values), 3) if values else 0.0

    scenarios = {
        sid: {
            "sessions": len(group),
            "techniques": mean([s["techniques"] for s in group]),
            "techniques_possible": max(s["techniques_possible"] for s in group),
            "steps_succeeded": mean([s["succeeded"] for s in group]),
            "steps": max(s["steps"] for s in group),
            "checks_failed": sorted({tuple(c) for s in group for c in s["check_failed"]}),
        }
        for sid, group in sorted(by_scenario.items())
    }
    failed_file = directory / FAILED_CHECKS
    return {
        "directory": str(directory),
        "sessions": len(sessions),
        "scenarios": scenarios,
        "techniques_per_session": mean([s["techniques"] for s in sessions]),
        "steps_succeeded_per_session": mean([s["succeeded"] for s in sessions]),
        "sessions_with_every_check_passing": sum(
            1 for s in sessions if not s["check_failed"] and not s["not_sent"]
        ),
        "failed_checks_recorded": sum(1 for _ in failed_file.open())
        if failed_file.is_file()
        else 0,
        "per_session": sessions,
    }
