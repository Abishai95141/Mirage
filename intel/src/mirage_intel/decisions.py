"""The bandit's logged decisions, joined to what really happened (phase 2 spec, 2.5).

Off-policy evaluation rests on three things being true of every logged decision: the action in
the log is the action the decoy applied, the probability in the log is the probability it was
drawn with, and the reward beside it is what followed. ``explore_check`` tests the second.
This module builds the table that makes the first and third checkable:

- each policy-service decision is joined, by request ID, to the **decoy's own** decision event.
  A decoy that could not reach the policy service answered as plain emulation; the policy log
  still shows what it would have said. Those decisions, and any whose applied action differs
  from the logged one, are marked and kept out of learning and evaluation, and counted;
- decisions are ordered within their **logical** session (an HTTP session is many connections),
  and each gets its reward-to-go (``reward.py``) twice: from the tagger's labels, which exist
  for any traffic, and from the lab's ground truth, so the difference can be reported.

One row per decision, written to ``decisions.parquet``. Structural fields only: no input text.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from mirage_intel import reward
from mirage_intel.dataset import (
    ClickHouse,
    DatasetError,
    FrozenSplit,
    _env_file,
    scenario_groups,
    with_runs,
    write_parquet,
)

ROOT = Path(__file__).resolve().parents[3]

_EXPLORE_SESSIONS = (
    "SELECT session_id FROM mirage.sim_sessions FINAL WHERE mode = 'explore' /*runs*/"
)

SESSIONS_SQL = (
    "SELECT session_id, logical_session_id, scenario_id, run_id "
    "FROM mirage.sim_sessions FINAL WHERE mode = 'explore' /*runs*/"
)
RUNS_SQL = "SELECT * FROM mirage.sim_runs FINAL WHERE mode = 'explore' /*runs*/ ORDER BY started_ts"

# What the policy service logged.
POLICY_SQL = f"""
SELECT
    session_id,
    toUnixTimestamp64Micro(ts) / 1000000.0             AS ts,
    protocol,
    JSONExtractString(payload, 'request_id')           AS request_id,
    JSONExtractBool(payload, 'explore')                AS explore,
    JSONExtractRaw(payload, 'acting')                  AS acting,
    JSONExtractRaw(payload, 'allowed')                 AS allowed,
    JSONExtractRaw(payload, 'context')                 AS context,
    JSONExtractRaw(payload, 'shadow')                  AS shadow
FROM mirage.events FINAL
WHERE source = 'policy' AND class = 'policy_decision'
  AND session_id IN ({_EXPLORE_SESSIONS})
"""  # noqa: S608 - constants; run IDs are validated by with_runs

# What the decoy applied, and the event the labels hang on.
DECOY_SQL = f"""
SELECT
    event_id,
    session_id,
    JSONExtractString(payload, 'request_id')           AS request_id,
    JSONExtractString(payload, 'action')               AS applied,
    JSONExtractBool(payload, 'fallback')               AS fallback
FROM mirage.events FINAL
WHERE class = 'policy_decision' AND source != 'policy'
  AND session_id IN ({_EXPLORE_SESSIONS})
"""  # noqa: S608

TAGGED_SQL = f"""
SELECT event_id, technique FROM mirage.labels FINAL
WHERE kind = 'input' AND technique != '' AND session_id IN ({_EXPLORE_SESSIONS})
"""  # noqa: S608

TRUTH_SQL = """
SELECT event_id, technique_id AS technique FROM mirage.sim_labels_current
WHERE role = 'decision' AND technique_id != ''
  AND run_id IN (SELECT run_id FROM mirage.sim_runs FINAL WHERE mode = 'explore' /*runs*/)
"""

ARTIFACTS_SQL = f"""
SELECT session_id, toUnixTimestamp64Micro(ts) / 1000000.0 AS ts,
       JSONExtractString(payload, 'sha256') AS value
FROM mirage.events FINAL
WHERE class = 'file_activity' AND action IN ('download', 'upload', 'artifact_stored')
  AND JSONExtractString(payload, 'sha256') != ''
  AND session_id IN ({_EXPLORE_SESSIONS})
"""  # noqa: S608

# A honeytoken reached (an exposure) or used (a trigger), by the session it happened in.
TOKENS_SQL = f"""
SELECT session_id, toUnixTimestamp64Micro(ts) / 1000000.0 AS ts, token_id AS value
FROM mirage.token_exposures FINAL
WHERE session_id IN ({_EXPLORE_SESSIONS})
"""  # noqa: S608


def _json(value: Any, default: Any) -> Any:
    if isinstance(value, str):
        return json.loads(value) if value and value != "null" else default
    return default if value is None else value


def build(
    policy: list[dict],
    decoy: list[dict],
    sessions: list[dict],
    tagged: list[dict],
    truth: list[dict],
    artifacts: list[dict],
    tokens: list[dict],
    scenario_split: dict[str, str],
    groups: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """One row per logged decision, in logical-session order, with both rewards."""
    groups = groups or {}
    session_of = {s["session_id"]: s for s in sessions}
    by_request = {(d["session_id"], d["request_id"]): d for d in decoy}
    tech_tagged: dict[str, set[str]] = defaultdict(set)
    for r in tagged:
        tech_tagged[r["event_id"]].add(r["technique"])
    tech_truth: dict[str, set[str]] = defaultdict(set)
    for r in truth:
        tech_truth[r["event_id"]].add(r["technique"])

    timeline: dict[str, list[dict]] = defaultdict(list)
    for p in policy:
        sim = session_of.get(p["session_id"])
        if sim is None:
            continue
        timeline[sim["logical_session_id"] or p["session_id"]].append(p)

    def stamped(rows: list[dict]) -> dict[str, list[tuple[float, str]]]:
        out: dict[str, list[tuple[float, str]]] = defaultdict(list)
        for r in rows:
            sim = session_of.get(r["session_id"])
            if sim is not None:
                logical = sim["logical_session_id"] or r["session_id"]
                out[logical].append((float(r["ts"]), r["value"]))
        return out

    art, tok = stamped(artifacts), stamped(tokens)
    rows: list[dict[str, Any]] = []
    for logical, items in sorted(timeline.items()):
        items.sort(key=lambda p: (float(p["ts"]), p["request_id"]))
        sim = session_of[items[0]["session_id"]]
        times = [(float(p["ts"]), i) for i, p in enumerate(items, start=1)]
        decisions, seen_tagged, seen_truth = [], [], []
        parsed = []
        for i, p in enumerate(items, start=1):
            acting = _json(p["acting"], {})
            applied = by_request.get((p["session_id"], p["request_id"]))
            logged = acting.get("action", "")
            action_applied = applied["applied"] if applied else ""
            fallback = bool(applied["fallback"]) if applied else False
            parsed.append((p, acting, applied, logged, action_applied, fallback))
            # The reward follows what the decoy did, not what the log says it was told.
            decisions.append(reward.Decision(i, action_applied or logged))
            event_id = applied["event_id"] if applied else ""
            seen_tagged += [
                reward.Observation("technique", t, i - 1) for t in tech_tagged[event_id]
            ]
            seen_truth += [reward.Observation("technique", t, i - 1) for t in tech_truth[event_id]]
        shared = [
            reward.Observation(kind, value, reward.after_seq(times, ts))
            for kind, source in (("artifact", art), ("token", tok))
            for ts, value in source.get(logical, [])
        ]
        r_tagged = {
            r.seq: r.reward for r in reward.session_rewards(decisions, seen_tagged + shared)
        }
        r_truth = {r.seq: r.reward for r in reward.session_rewards(decisions, seen_truth + shared)}
        for i, (p, acting, applied, logged, action_applied, fallback) in enumerate(parsed, start=1):
            ctx = _json(p["context"], {})
            probs = acting.get("probs") or {}
            since = ctx.get("seconds_since_last")
            rows.append(
                {
                    "session": logical,
                    "scenario_id": sim["scenario_id"],
                    "group": groups.get(sim["scenario_id"], sim["scenario_id"]),
                    "split": scenario_split.get(sim["scenario_id"], ""),
                    "run_id": sim["run_id"],
                    "pos": i,
                    "n_in_session": len(items),
                    "protocol": p["protocol"],
                    "verb": str(ctx.get("verb") or ""),
                    "verb_class": str(ctx.get("verb_class") or ""),
                    "known": bool(ctx.get("known")),
                    "inputs_so_far": int(ctx.get("inputs_so_far") or 0),
                    "seconds_since_last": float(since) if since is not None else -1.0,
                    "last_tactic": str(ctx.get("last_tactic") or ""),
                    "seen_before": bool(ctx.get("seen_before")),
                    "allowed": json.dumps(_json(p["allowed"], [])),
                    "action": logged,
                    "applied": action_applied,
                    "joined": applied is not None,
                    "fallback": fallback,
                    "usable": applied is not None and not fallback and action_applied == logged,
                    "propensity": float(acting.get("propensity") or 0.0),
                    "probs": json.dumps(probs, sort_keys=True),
                    "rule_action": max(sorted(probs), key=lambda a: probs[a]) if probs else "",
                    "policy": str(acting.get("name") or ""),
                    "reward_tagged": r_tagged[i],
                    "reward_truth": r_truth[i],
                }
            )
    return rows


def health(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Whether the log can be trusted as a record of what happened (plan row V11)."""
    n = len(rows)
    unjoined = sum(1 for r in rows if not r["joined"])
    fallback = sum(1 for r in rows if r["fallback"])
    differs = sum(
        1 for r in rows if r["joined"] and not r["fallback"] and r["applied"] != r["action"]
    )
    return {
        "decisions": n,
        "sessions": len({r["session"] for r in rows}),
        "usable": sum(1 for r in rows if r["usable"]),
        "no_decoy_event": unjoined,
        "fallbacks": fallback,
        "applied_differs_from_logged": differs,
        # A fallback is the design working. An applied action that differs from the logged
        # one, or a logged decision the decoy never recorded, means the log is not a record
        # of what happened and nothing may be learned from it.
        "ok": n > 0 and differs == 0 and unjoined == 0,
    }


def export(
    ch: ClickHouse,
    split: FrozenSplit,
    out: Path,
    runs: list[str] | None = None,
    groups: dict[str, str] | None = None,
) -> dict[str, Any]:
    run_rows = ch.rows(with_runs(RUNS_SQL, runs))
    if not run_rows:
        raise DatasetError("no explore run to export")
    named = sorted(r["run_id"] for r in run_rows)

    def q(sql: str) -> list[dict]:
        return ch.rows(with_runs(sql, named))

    rows = build(
        q(POLICY_SQL), q(DECOY_SQL), q(SESSIONS_SQL), q(TAGGED_SQL), q(TRUTH_SQL),
        q(ARTIFACTS_SQL), q(TOKENS_SQL), split.scenario_split, groups,
    )  # fmt: skip
    report = {
        "runs": named,
        "reward_version": reward.REWARD_VERSION,
        **health(rows),
        "mean_reward_tagged": round(sum(r["reward_tagged"] for r in rows) / max(len(rows), 1), 4),
        "mean_reward_truth": round(sum(r["reward_truth"] for r in rows) / max(len(rows), 1), 4),
        "by_split": {
            s: sum(1 for r in rows if r["split"] == s) for s in sorted({r["split"] for r in rows})
        },
    }
    write_parquet(rows, out / "decisions.parquet", {**report, "columns": ["session"]})
    (out / "decisions.manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage-decisions")
    ap.add_argument("--out", type=Path, default=ROOT / "build" / "dataset")
    ap.add_argument("--run", action="append", dest="runs", metavar="RUN_ID")
    args = ap.parse_args(argv)
    os.environ.update({k: v for k, v in _env_file().items() if k not in os.environ})
    try:
        report = export(
            ClickHouse.from_env(),
            FrozenSplit.load(),
            args.out,
            args.runs,
            scenario_groups(ROOT / "lab" / "scenarios"),
        )
    except DatasetError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
