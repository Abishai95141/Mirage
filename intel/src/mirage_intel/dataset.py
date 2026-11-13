"""Export the labelled lab data from ClickHouse to Parquet (phase 2 spec, 2.2).

This builds two tables. The **sessions** table (one row per sessioniser session) has structural
features only -- counts, timings, outcomes -- plus the ground-truth actor class and the split;
it is the classifier's data and holds no command text. The **steps** table (one row per gated
input) carries the input text and its ground-truth technique, for the tagger; the text passes
from ClickHouse to Parquet and is never printed here.

Only ``capture`` runs are exported. ``explore`` runs carry the bandit's logged actions and are
kept apart (spec Q6). A session's split is its scenario's split, which is well defined because
no scenario spans two splits (spec section 5).

Only ``capture`` runs are exported. ``explore`` runs carry the bandit's logged actions and are
kept apart (spec Q6). A session's split is its scenario's split, which is well defined because
no scenario spans two splits (spec section 5).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pyarrow as pa
import pyarrow.parquet as pq
import yaml

from mirage_lab.models import Catalogue

ROOT = Path(__file__).resolve().parents[3]
SPLIT_FILE = ROOT / "eval" / "split.yaml"

# The input unit: one gated input, across the three protocols. n_unknown is a SEPARATE signal
# (Cowrie emits a command.failed event, outcome='failure', beside each unknown command's input),
# so it is counted over all events, not over the input rows.
_INPUT = (
    "((source = 'cowrie' AND class = 'process_activity' AND action = 'command'"
    " AND outcome = 'unknown')"
    " OR (class = 'http_activity' AND action = 'request')"
    " OR (class = 'datastore_activity' AND action = 'query'))"
)
_UNKNOWN = "(source = 'cowrie' AND action = 'command' AND outcome = 'failure')"

# One row per capture session. Events are rolled up to their LOGICAL session (the sessioniser
# groups HTTP connections via session_map), so a multi-connection session's gap/rate features
# are not zeroed. Reads use FINAL, matching the exactly-once discipline elsewhere in Phase 2.
SESSIONS_SQL = f"""
WITH ev AS (
    SELECT
        coalesce(m.session_id, e.session_id) AS lsid,
        e.ts AS ts, e.source AS source, e.class AS class, e.action AS action, e.outcome AS outcome
    FROM mirage.events FINAL AS e
    LEFT JOIN (SELECT conn_id, session_id FROM mirage.session_map FINAL) AS m
        ON e.session_id = m.conn_id
    WHERE e.source != 'policy'
),
agg AS (
    SELECT
        lsid AS session_id,
        countIf({_INPUT}) AS n_inputs,
        countIf({_UNKNOWN}) AS n_unknown,
        arraySort(groupArrayIf(toUnixTimestamp64Milli(ts), {_INPUT})) AS ts_ms
    FROM ev
    GROUP BY lsid
),
gaps AS (
    SELECT session_id, n_inputs, n_unknown,
        arrayMap(i -> ts_ms[i + 1] - ts_ms[i], range(1, length(ts_ms))) AS d
    FROM agg
)
SELECT
    ss.logical_session_id                               AS session_id,
    ss.actor_class                                      AS actor_class,
    ss.protocol                                         AS protocol,
    ss.scenario_id                                      AS scenario_id,
    ss.real                                             AS real,
    sm.inputs                                           AS inputs,
    sm.decisions                                        AS decisions,
    sm.fallbacks                                        AS fallbacks,
    sm.auth_attempts                                    AS auth_attempts,
    sm.auth_success                                     AS auth_success,
    dateDiff('millisecond', sm.start_ts, sm.end_ts) / 1000.0 AS duration_s,
    coalesce(g.n_inputs, 0)                             AS n_inputs,
    coalesce(g.n_unknown, 0)                            AS n_unknown,
    if(length(g.d) > 0, arrayMin(g.d) / 1000.0, 0.0)    AS gap_min_s,
    if(length(g.d) > 0, arrayMax(g.d) / 1000.0, 0.0)    AS gap_max_s,
    if(length(g.d) > 0, arrayAvg(g.d) / 1000.0, 0.0)    AS gap_mean_s,
    if(length(g.d) > 0, arrayReduce('quantileExact(0.5)', g.d) / 1000.0, 0.0) AS gap_median_s
FROM (SELECT * FROM mirage.sim_sessions FINAL WHERE mode = 'capture') AS ss
INNER JOIN (SELECT * FROM mirage.session_summary FINAL) AS sm
    ON ss.logical_session_id = sm.session_id
LEFT JOIN gaps AS g ON ss.logical_session_id = g.session_id
"""  # noqa: S608 - static predicates, no user input

# One row per gated input (role='decision'), with the canonical input text the decoy logged,
# and the ground-truth technique from its label. Capture runs only. No print path touches it.
STEPS_SQL = """
SELECT
    l.event_id       AS event_id,
    e.protocol       AS protocol,
    l.procedure_id   AS procedure_id,
    l.technique_id   AS technique_id,
    l.scenario_id    AS scenario_id,
    coalesce(nullIf(JSONExtractString(e.payload, 'input'), ''),
             JSONExtractString(e.payload, 'command')) AS input
FROM mirage.sim_labels_current AS l
INNER JOIN mirage.events FINAL AS e ON l.event_id = e.event_id
WHERE l.role = 'decision'
  AND l.run_id IN (SELECT run_id FROM mirage.sim_runs FINAL WHERE mode = 'capture' AND final = 1)
"""

# The columns a model may read (spec 2.3). Everything else is identity or ground truth.
FEATURES = [
    "inputs", "decisions", "fallbacks", "auth_attempts", "auth_success",
    "failed_before_success", "duration_s", "gap_min_s", "gap_max_s", "gap_mean_s",
    "gap_median_s", "share_unknown",
]  # fmt: skip
# Never a feature: source/destination addresses, IDs, times, anything from sim_*, credentials.
FORBIDDEN = {"session_id", "actor_class", "scenario_id", "real", "protocol", "split", "src_ip"}


@dataclass
class ClickHouse:
    url: str
    user: str
    password: str

    def rows(self, sql: str) -> list[dict[str, Any]]:
        r = httpx.post(
            self.url,
            params={"query": sql + "\nFORMAT JSONEachRow"},
            headers={"X-ClickHouse-User": self.user, "X-ClickHouse-Key": self.password},
            timeout=60,
        )
        r.raise_for_status()
        return [json.loads(line) for line in r.text.splitlines() if line]

    @classmethod
    def from_env(cls) -> ClickHouse:
        port = os.environ.get("CLICKHOUSE_PORT", "8123")
        return cls(
            os.environ.get("CLICKHOUSE_URL", f"http://127.0.0.1:{port}"),
            os.environ["CLICKHOUSE_USER"],
            os.environ["CLICKHOUSE_PASSWORD"],
        )


def _env_file() -> dict[str, str]:
    env: dict[str, str] = {}
    path = ROOT / ".env"
    if path.exists():
        for line in path.read_text().splitlines():
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def build_rows(raw: list[dict[str, Any]], scenario_split: dict[str, str]) -> list[dict[str, Any]]:
    """Turn ClickHouse rows into feature rows with a split; drop anything not in a capture
    scenario we know the split of."""
    out = []
    for r in raw:
        where = scenario_split.get(r["scenario_id"])
        if where is None:
            continue  # a session whose scenario is not in the frozen split
        inputs = int(r["inputs"]) or 1
        out.append(
            {
                "session_id": r["session_id"],
                "actor_class": r["actor_class"],
                "protocol": r["protocol"],
                "scenario_id": r["scenario_id"],
                "real": bool(r["real"]),
                "split": where,
                "inputs": int(r["inputs"]),
                "decisions": int(r["decisions"]),
                "fallbacks": int(r["fallbacks"]),
                "auth_attempts": int(r["auth_attempts"]),
                "auth_success": int(r["auth_success"]),
                "failed_before_success": max(int(r["auth_attempts"]) - int(r["auth_success"]), 0),
                "duration_s": float(r["duration_s"]),
                "gap_min_s": float(r["gap_min_s"]),
                "gap_max_s": float(r["gap_max_s"]),
                "gap_mean_s": float(r["gap_mean_s"]),
                "gap_median_s": float(r["gap_median_s"]),
                "share_unknown": float(r["n_unknown"]) / inputs,
            }
        )
    return out


def write_parquet(rows: list[dict[str, Any]], path: Path, manifest: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if rows:
        table = pa.Table.from_pylist(rows)
    else:
        cols = manifest.get("columns") or ["id"]
        table = pa.table({k: pa.array([], type=pa.string()) for k in cols})
    table = table.replace_schema_metadata({"mirage_manifest": json.dumps(manifest)})
    pq.write_table(table, path)


@dataclass
class FrozenSplit:
    scenario_split: dict[str, str]
    catalogue_sha256: str

    @classmethod
    def load(cls, path: Path = SPLIT_FILE) -> FrozenSplit:
        doc = yaml.safe_load(path.read_text())
        return cls(doc.get("scenarios", {}), doc.get("catalogue_sha256", ""))


def build_steps(
    raw: list[dict[str, Any]], scenario_split: dict[str, str], catalogue: Catalogue
) -> list[dict[str, Any]]:
    """Per-input rows for the tagger: input text, ground-truth technique, source, split."""
    out = []
    for r in raw:
        where = scenario_split.get(r["scenario_id"])
        proc = catalogue.procedures.get(r["procedure_id"])
        if where is None or proc is None or not r["input"]:
            continue
        out.append(
            {
                "event_id": r["event_id"],
                "protocol": r["protocol"],
                "input": r["input"],
                "technique_id": r["technique_id"] or "",
                "procedure_id": r["procedure_id"],
                "source": proc.source,
                "split": where,
            }
        )
    return out


def export(ch: ClickHouse, split: FrozenSplit, catalogue: Catalogue, out: Path) -> dict:
    steps = build_steps(ch.rows(STEPS_SQL), split.scenario_split, catalogue)
    write_parquet(steps, out / "steps.parquet", {"n_steps": len(steps), "columns": ["input"]})
    rows = build_rows(ch.rows(SESSIONS_SQL), split.scenario_split)
    by_split: dict[str, int] = {}
    by_class: dict[str, int] = {}
    for r in rows:
        by_split[r["split"]] = by_split.get(r["split"], 0) + 1
        by_class[r["actor_class"]] = by_class.get(r["actor_class"], 0) + 1
    manifest = {
        "catalogue_sha256": catalogue.sha256,
        "split_catalogue_sha256": split.catalogue_sha256,
        "code_version": os.environ.get("MIRAGE_CODE_VERSION", "dev"),
        "features": FEATURES,
        "n_sessions": len(rows),
        "n_steps": len(steps),
        "by_split": by_split,
        "by_class": by_class,
        "rows_sha256": hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest(),
    }
    write_parquet(rows, out / "sessions.parquet", manifest)
    (out / "sessions.manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage-dataset")
    ap.add_argument("--out", type=Path, default=ROOT / "build" / "dataset")
    args = ap.parse_args(argv)
    os.environ.update({k: v for k, v in _env_file().items() if k not in os.environ})
    ch = ClickHouse.from_env()
    split = FrozenSplit.load()
    catalogue = Catalogue.load(ROOT / "lab" / "catalogue")
    manifest = export(ch, split, catalogue, args.out)
    print(json.dumps({k: v for k, v in manifest.items() if k != "rows_sha256"}, indent=2))


if __name__ == "__main__":
    main()
