"""Export the labelled lab data from ClickHouse to Parquet (phase 2 spec, 2.2).

This builds two tables. The **sessions** table (one row per sessioniser session) has structural
features only -- counts, timings, outcomes -- plus the ground-truth actor class and the split;
it is the classifier's data and holds no command text. The **steps** table (one row per gated
input) carries the input text and its ground-truth technique, for the tagger; the text passes
from ClickHouse to Parquet and is never printed here.

Only ``capture`` runs are exported. ``explore`` runs carry the bandit's logged actions and are
kept apart (spec Q6). A session's split is its scenario's split, which is well defined because
no scenario spans two splits (spec section 5).

A frozen dataset names the runs it was built from (``--run``, repeatable), so sessions left in
the store by tests or ad-hoc runs do not enter it. Each session row also carries a ``group`` (its
scenario, or the scenario it is a timing variant of) and a ``label`` (the session-level class);
the classifier is scored by holding out whole groups, and reads neither as a feature.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pyarrow as pa
import pyarrow.parquet as pq
import yaml

from mirage_lab.models import Catalogue, Scenario

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

# A session's behaviour features, defined once. (The session a connection belongs to is taken
# with if(), not coalesce(): ClickHouse fills an unmatched LEFT JOIN row with '' rather than
# NULL, and coalesce() kept that empty string, so every SSH session lost its events and its
# gap features were zero. Found on the first live run of this query, 15 November 2026.)
#
# A session's behaviour features, defined once. The export below and the live classifier
# worker both build on it, so a model is served the same numbers it was trained on.
# Events are rolled up to the LOGICAL session (the sessioniser groups HTTP connections via
# session_map), so a multi-connection session's gap features are not zeroed. Reads use FINAL,
# matching the exactly-once discipline elsewhere in Phase 2. The keystroke columns come from
# the session's TTY logs (spec 2.0) and are zero where a session has none: HTTP, Redis, MySQL,
# and SSH exec requests.
FEATURE_CTES = f"""
WITH ev AS (
    SELECT
        if(m.session_id != '', m.session_id, e.session_id) AS lsid,
        e.ts AS ts, e.source AS source, e.class AS class, e.action AS action, e.outcome AS outcome
    FROM mirage.events AS e FINAL
    LEFT JOIN (SELECT conn_id, session_id FROM mirage.session_map FINAL) AS m
        ON e.session_id = m.conn_id
    WHERE e.source != 'policy' /*scope_events*/
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
),
feat AS (
    SELECT
        sm.session_id                                       AS session_id,
        sm.version                                          AS summary_version,
        sm.protocol                                         AS protocol,
        sm.inputs                                           AS inputs,
        sm.auth_attempts                                    AS auth_attempts,
        sm.auth_success                                     AS auth_success,
        dateDiff('millisecond', sm.start_ts, sm.end_ts) / 1000.0 AS duration_s,
        g.n_inputs                                          AS n_inputs,
        g.n_unknown                                         AS n_unknown,
        if(length(g.d) > 0, arrayMin(g.d) / 1000.0, 0.0)    AS gap_min_s,
        if(length(g.d) > 0, arrayMax(g.d) / 1000.0, 0.0)    AS gap_max_s,
        if(length(g.d) > 0, arrayAvg(g.d) / 1000.0, 0.0)    AS gap_mean_s,
        if(length(g.d) > 0, arrayReduce('quantileExact(0.5)', g.d) / 1000.0, 0.0) AS gap_median_s,
        tty.input_chunks                                    AS tty_input_chunks,
        tty.single_byte_chunks                              AS tty_single_byte_chunks,
        tty.backspaces                                      AS tty_backspaces,
        tty.paste_bursts                                    AS tty_paste_bursts,
        tty.lines                                           AS tty_lines,
        tty.key_gap_p50_s                                   AS tty_key_gap_p50_s
    FROM (SELECT * FROM mirage.session_summary FINAL /*scope_sessions*/) AS sm
    LEFT JOIN gaps AS g ON sm.session_id = g.session_id
    LEFT JOIN mirage.tty_by_session AS tty ON sm.session_id = tty.session_id
)
"""  # noqa: S608 - static predicates, no user input

# One row per logical capture session, with its ground truth beside the features. `LIMIT 1 BY`
# keeps one row where the join to sim_sessions (one row per connection) would otherwise repeat
# a multi-connection session once per connection.
# The columns of `feat`, named one by one wherever it is joined to another table: `f.*` comes
# back as `f.session_id` and `f.protocol` when the other side has columns of those names.
FEATURE_COLUMNS = (
    "session_id", "summary_version", "protocol", "inputs", "auth_attempts", "auth_success",
    "duration_s", "n_inputs", "n_unknown", "gap_min_s", "gap_max_s", "gap_mean_s",
    "gap_median_s", "tty_input_chunks", "tty_single_byte_chunks", "tty_backspaces",
    "tty_paste_bursts", "tty_lines", "tty_key_gap_p50_s",
)  # fmt: skip

SESSIONS_SQL = (
    FEATURE_CTES  # noqa: S608 - two constants joined; no input reaches this text
    + """
SELECT
    ss.actor_class AS actor_class,
    ss.scenario_id AS scenario_id,
    ss.real        AS real,
    /*feature_columns*/
FROM (SELECT * FROM mirage.sim_sessions FINAL WHERE mode = 'capture' /*runs*/) AS ss
INNER JOIN feat AS f ON ss.logical_session_id = f.session_id
ORDER BY session_id
LIMIT 1 BY session_id
"""
).replace("/*feature_columns*/", ",\n    ".join(f"f.{c} AS {c}" for c in FEATURE_COLUMNS))

SESSION_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")


def feature_query(session_ids: list[str] | None = None) -> str:
    """The feature rows of the given sessions (or of every session), for anything that is not
    a lab export: the classifier worker and the real-traffic check. Session IDs are checked
    before they reach the query."""
    if session_ids is None:
        scoped = FEATURE_CTES.replace("/*scope_events*/", "").replace("/*scope_sessions*/", "")
        return scoped + "SELECT * FROM feat"  # noqa: S608 - constants only
    bad = [i for i in session_ids if not SESSION_ID.match(i)]
    if bad:
        raise ValueError(f"not a session ID: {bad[:3]}")
    listed = ", ".join(f"'{i}'" for i in sorted(set(session_ids))) or "''"
    events = (  # the IDs were checked against SESSION_ID above
        f"AND (e.session_id IN ({listed}) OR e.session_id IN "  # noqa: S608
        f"(SELECT conn_id FROM mirage.session_map FINAL WHERE session_id IN ({listed})))"
    )
    scoped = FEATURE_CTES.replace("/*scope_events*/", events).replace(
        "/*scope_sessions*/", f"WHERE session_id IN ({listed})"
    )
    return scoped + "SELECT * FROM feat"  # noqa: S608 - IDs validated above


def features_of(r: dict[str, Any]) -> dict[str, float]:
    """One session's feature values from a row of ``feat``: the same function for the export
    and for the worker."""
    inputs = int(r["inputs"]) or 1
    return {
        "inputs": int(r["inputs"]),
        "auth_attempts": int(r["auth_attempts"]),
        "auth_success": int(r["auth_success"]),
        "failed_before_success": max(int(r["auth_attempts"]) - int(r["auth_success"]), 0),
        "duration_s": float(r["duration_s"]),
        "gap_min_s": float(r["gap_min_s"]),
        "gap_max_s": float(r["gap_max_s"]),
        "gap_mean_s": float(r["gap_mean_s"]),
        "gap_median_s": float(r["gap_median_s"]),
        "share_unknown": float(r.get("n_unknown") or 0) / inputs,
        **tty_features(r),
    }


# One row per labelled event of a step, with the text the decoy logged and the ground-truth
# technique. A step has one `input` event (for SSH the whole line as typed) and one `decision`
# event per gated command the line expanded to (a pipeline has several). The tagger is scored
# per step, so both are kept and `role` tells them apart. Capture runs only. No print path
# touches the text.
STEPS_SQL = """
SELECT
    l.event_id       AS event_id,
    l.run_id         AS run_id,
    l.session_ref    AS session_ref,
    l.step_id        AS step_id,
    l.role           AS role,
    e.session_id     AS session_id,
    toUnixTimestamp64Milli(e.ts) AS ts_ms,
    e.protocol       AS protocol,
    l.procedure_id   AS procedure_id,
    l.technique_id   AS technique_id,
    l.tactic         AS tactic,
    l.scenario_id    AS scenario_id,
    coalesce(nullIf(JSONExtractString(e.payload, 'input'), ''),
             JSONExtractString(e.payload, 'command')) AS input
FROM mirage.sim_labels_current AS l
INNER JOIN mirage.events AS e FINAL ON l.event_id = e.event_id
WHERE l.role IN ('input', 'decision')
  AND l.run_id IN (
      SELECT run_id FROM mirage.sim_runs FINAL WHERE mode = 'capture' AND final = 1 /*runs*/
  )
"""

# The columns a model may read (spec 2.3). Everything else is identity or ground truth.
# Event-level features exist for any Cowrie data, including the public corpus; keystroke-level
# ones need the decoy's own TTY logs.
# `decisions` and `fallbacks` are not here: they describe our own policy service (how often it
# was reachable), not the actor, and a model that reads them learns the lab's conditions.
FEATURES_EVENT = [
    "inputs", "auth_attempts", "auth_success", "failed_before_success", "duration_s",
    "gap_min_s", "gap_max_s", "gap_mean_s", "gap_median_s", "share_unknown",
]  # fmt: skip
FEATURES_TTY = [
    "tty_input_chunks", "tty_single_byte_share", "tty_chunks_per_line", "tty_backspaces",
    "tty_paste_bursts", "tty_key_gap_p50_s",
]  # fmt: skip
FEATURES = FEATURES_EVENT + FEATURES_TTY
# Never a feature: source/destination addresses, IDs, times, anything from sim_*, credentials.
FORBIDDEN = {
    "session_id", "actor_class", "label", "group", "scenario_id", "real", "protocol", "split",
    "src_ip",
}  # fmt: skip
# Every column the sessions table may have: identity and ground truth, then the features. The
# export writes exactly these, and a test fails if the Parquet file has any other (section 5,
# item 8): a `sim_*`, address or time column cannot ride along unnoticed.
META = ["session_id", "actor_class", "label", "group", "protocol", "scenario_id", "real", "split"]

LAB_SEED = 20261114  # the public profile seed frozen datasets are rendered from (spec Q16)
RECORDED = "recorded-human"  # the scenario ID the human recorder writes (spec Q8)
LAB_NETS = ("198.18.", "198.19.")  # simulated source ranges; never part of an input


class DatasetError(RuntimeError):
    """The store cannot yield a dataset worth freezing; the message says why."""


RUN_ID = re.compile(r"^r\d{14}-[0-9a-f]{6}$")

# The health of the runs a dataset is built from (spec section 3, "Join health").
RUNS_SQL = "SELECT * FROM mirage.sim_runs FINAL WHERE mode = 'capture' /*runs*/ ORDER BY started_ts"


def with_runs(sql: str, runs: list[str] | None) -> str:
    """Restrict a query to the named runs. Run IDs are checked before they reach the query."""
    sql = sql.replace("/*scope_events*/", "").replace("/*scope_sessions*/", "")
    if not runs:
        return sql.replace("/*runs*/", "")
    bad = [r for r in runs if not RUN_ID.match(r)]
    if bad:
        raise ValueError(f"not a run ID: {bad}")
    listed = ", ".join(f"'{r}'" for r in sorted(set(runs)))
    return sql.replace("/*runs*/", f"AND run_id IN ({listed})")


# Decoys that let a client act without logging in (the Redis decoy asks for no password until
# one is set). On these a session holds access from its first input.
OPEN_SERVICES = ("redis",)


def has_access(protocol: str, auth_success: int, auth_attempts: int, inputs: int) -> bool:
    """Whether the session ever acted with access: a login that succeeded, or input to a
    service that asks for none. This is the line the class definitions draw (spec 2.3): a
    scanner has no authenticated activity; a bot's or a person's activity comes after access.

    A session on an open service that tried to log in and never succeeded was asked for a
    password, so it is not counted as having access."""
    if auth_success > 0:
        return True
    return protocol in OPEN_SERVICES and auth_attempts == 0 and inputs > 0


def session_label(actor_class: str, access: bool) -> str:
    """The session-level class. The lab stamps every connection with its actor's class, but a
    session that never held access is scanner behaviour by definition (spec 2.3), whoever
    made it: a bot's failed password guess, or its one request to a web page it never logged
    in to, is not told apart from a scanner's by anything a model that does not read content
    can see. (The first classifier experiment, 15 November 2026: every error in the scanner
    class was a session without access that carried a bot's label, or the reverse.)"""
    return actor_class if access else "scanner"


class QueryError(RuntimeError):
    """A query ClickHouse refused, carrying the server's own message."""


@dataclass
class ClickHouse:
    url: str
    user: str
    password: str

    def rows(self, sql: str) -> list[dict[str, Any]]:
        # The query goes in the body, not the URL: a long query overruns the URL limit, and a
        # failure should say what ClickHouse said, which the status code alone does not.
        r = httpx.post(
            self.url,
            content=(sql + "\nFORMAT JSONEachRow").encode(),
            headers={"X-ClickHouse-User": self.user, "X-ClickHouse-Key": self.password},
            timeout=120,
        )
        if r.status_code != 200:
            raise QueryError(f"ClickHouse answered {r.status_code}: {r.text.strip()[:600]}")
        return [json.loads(line) for line in r.text.splitlines() if line]

    def insert(self, table: str, rows: list[dict[str, Any]]) -> None:
        """Append rows to one of this project's own tables (the name is checked, not quoted)."""
        if not re.fullmatch(r"mirage\.[a-z_]+", table):
            raise ValueError(f"not a table of this project: {table!r}")
        if not rows:
            return
        r = httpx.post(
            self.url,
            params={"query": f"INSERT INTO {table} FORMAT JSONEachRow"},
            content="\n".join(json.dumps(row) for row in rows).encode(),
            headers={"X-ClickHouse-User": self.user, "X-ClickHouse-Key": self.password},
            timeout=60,
        )
        if r.status_code != 200:
            raise QueryError(f"ClickHouse answered {r.status_code}: {r.text.strip()[:600]}")

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


def tty_features(r: dict[str, Any]) -> dict[str, float]:
    """Keystroke features from a session's TTY-log counts; all zero when it has no typed input."""
    chunks = int(r.get("tty_input_chunks") or 0)
    return {
        "tty_input_chunks": float(chunks),
        "tty_single_byte_share": (
            int(r.get("tty_single_byte_chunks") or 0) / chunks if chunks else 0.0
        ),
        "tty_chunks_per_line": chunks / max(int(r.get("tty_lines") or 0), 1) if chunks else 0.0,
        "tty_backspaces": float(r.get("tty_backspaces") or 0),
        "tty_paste_bursts": float(r.get("tty_paste_bursts") or 0),
        "tty_key_gap_p50_s": float(r.get("tty_key_gap_p50_s") or 0.0),
    }


def build_rows(
    raw: list[dict[str, Any]],
    scenario_split: dict[str, str],
    groups: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Turn ClickHouse rows into feature rows with a split. Returns the rows and the IDs of
    sessions whose scenario has no split, which the caller must not ignore."""
    groups = groups or {}
    out, dropped = [], []
    for r in raw:
        sid = r["scenario_id"]
        if bool(r["real"]) and sid == RECORDED:
            # A person's recording: test-only (spec Q8), and its own group.
            where, group = "test", f"recorded:{r['session_id']}"
        else:
            where, group = scenario_split.get(sid), groups.get(sid, sid)
        if where is None:
            dropped.append(r["session_id"])
            continue
        out.append(
            {
                "session_id": r["session_id"],
                "actor_class": r["actor_class"],
                "label": session_label(
                    r["actor_class"],
                    has_access(
                        r["protocol"],
                        int(r["auth_success"]),
                        int(r["auth_attempts"]),
                        int(r["inputs"]),
                    ),
                ),
                "group": group,
                "protocol": r["protocol"],
                "scenario_id": sid,
                "real": bool(r["real"]),
                "split": where,
                **features_of(r),
            }
        )
    return out, dropped


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
    sha256: str = ""  # of the split file itself

    @classmethod
    def load(cls, path: Path = SPLIT_FILE) -> FrozenSplit:
        raw = path.read_bytes()
        doc = yaml.safe_load(raw)
        return cls(
            doc.get("scenarios", {}),
            doc.get("catalogue_sha256", ""),
            hashlib.sha256(raw).hexdigest(),
        )


STEP_COLUMNS = [
    "event_id", "run_id", "session_ref", "step_id", "role", "session_id", "ts_ms", "protocol",
    "input", "technique_id", "tactic", "procedure_id", "source", "scenario_id", "split",
]  # fmt: skip


def build_steps(
    raw: list[dict[str, Any]], scenario_split: dict[str, str], catalogue: Catalogue
) -> list[dict[str, Any]]:
    """Per-event rows for the tagger: the text, its step, the ground-truth technique, the
    procedure's source, and the split."""
    out = []
    for r in raw:
        where = scenario_split.get(r["scenario_id"])
        proc = catalogue.procedures.get(r["procedure_id"])
        if where is None or proc is None or not r["input"]:
            continue
        out.append(
            {
                "event_id": r["event_id"],
                "run_id": r.get("run_id", ""),
                "session_ref": r.get("session_ref", ""),
                "step_id": r.get("step_id", ""),
                "role": r.get("role", "decision"),
                "session_id": r.get("session_id", ""),
                "ts_ms": int(r.get("ts_ms") or 0),
                "protocol": r["protocol"],
                "input": r["input"],
                # The label is the catalogue's, looked up by procedure. The store holds a copy
                # made when the run happened; if a label has been corrected since, the copy is
                # stale and the catalogue is right.
                "technique_id": proc.technique or "",
                "tactic": proc.tactic or "",
                "procedure_id": r["procedure_id"],
                "source": proc.source,
                "scenario_id": r["scenario_id"],
                "split": where,
            }
        )
    return out


def scenario_groups(directory: Path) -> dict[str, str]:
    """Scenario ID -> the group it is held out with: itself, or the scenario it is a variant of."""
    out = {}
    for path in sorted(directory.rglob("*.yaml")):
        sc = Scenario.load(path)
        out[sc.id] = sc.variant_of or sc.id
    return out


# Columns of mirage.sim_runs that must all be zero before a run may become a dataset: steps
# that ran with nothing captured, captures that were not what was sent, connections with no
# session, ground truth that never arrived or did not validate, and a join made without the
# run's closing record.
UNHEALTHY = (
    "no_event",
    "mismatch",
    "connections_unmatched",
    "truth_sessions_missing",
    "truth_steps_missing",
    "truth_invalid",
    "incomplete",
)


def run_problems(runs: list[dict[str, Any]], wanted: list[str] | None, catalogue_sha: str) -> list:
    """Why these runs must not become a dataset. An empty list means they may."""
    problems = []
    have = {r["run_id"] for r in runs}
    for missing in sorted(set(wanted or []) - have):
        problems.append(f"{missing}: no such capture run in the store")
    if not runs:
        problems.append("no capture run to export")
    for r in runs:
        rid = r["run_id"]
        if int(r.get("final", 0)) != 1:
            problems.append(f"{rid}: its join is not final")
        for column in UNHEALTHY:
            if int(r.get(column) or 0):
                problems.append(f"{rid}: {column} = {r[column]}")
        if r.get("catalogue_sha256") and r["catalogue_sha256"] != catalogue_sha:
            problems.append(f"{rid}: ran against a different catalogue than the one on disk")
    return problems


def leak_scan(steps: list[dict[str, Any]], ids: set[str]) -> list[str]:
    """Inputs that carry something only the lab knows (section 5, item 8): a simulated source
    address, a catalogue or scenario ID, a marker word. Reports event IDs, never text."""
    from mirage_lab.models import MARKER_WORDS

    needles = [n.lower() for n in (*LAB_NETS, *MARKER_WORDS, *sorted(ids)) if n]
    hits = []
    for s in steps:
        low = s["input"].lower()
        found = next((n for n in needles if n in low), None)
        if found is not None:
            kind = "address" if found in LAB_NETS else "id" if found in ids else "marker"
            hits.append(f"{s['event_id']}: {kind}")
    return hits


def _hash(rows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def export(
    ch: ClickHouse,
    split: FrozenSplit,
    catalogue: Catalogue,
    out: Path,
    runs: list[str] | None = None,
    groups: dict[str, str] | None = None,
    allow_unhealthy: bool = False,
) -> dict:
    """Export the named capture runs. Refuses a run whose join is not final and clean, a
    session whose scenario has no split, and an input that carries a lab marker; with
    ``allow_unhealthy`` it exports anyway and records why the result must not be frozen."""
    run_rows = ch.rows(with_runs(RUNS_SQL, runs))
    problems = run_problems(run_rows, runs, catalogue.sha256)
    named = sorted(r["run_id"] for r in run_rows)

    steps = build_steps(ch.rows(with_runs(STEPS_SQL, named)), split.scenario_split, catalogue)
    rows, dropped = build_rows(
        ch.rows(with_runs(SESSIONS_SQL, named)), split.scenario_split, groups
    )
    if dropped:
        problems.append(f"{len(dropped)} session(s) belong to a scenario with no split")
    flat = sum(1 for r in rows if r["inputs"] >= 2 and r["gap_max_s"] == 0.0)
    several = sum(1 for r in rows if r["inputs"] >= 2)
    if several and flat / several > 0.05:
        problems.append(
            f"{flat} of {several} sessions with two or more inputs have no gap between them: "
            "the timing features are not being computed"
        )
    leaks = leak_scan(steps, set(catalogue.procedures) | set(split.scenario_split))
    if leaks:
        problems.append(f"{len(leaks)} input(s) carry a lab address, ID or marker word")
    if problems and not allow_unhealthy:
        raise DatasetError("refusing to export:\n  " + "\n  ".join(problems))

    by_split: dict[str, int] = {}
    by_class: dict[str, int] = {}
    by_label: dict[str, int] = {}
    for r in rows:
        by_split[r["split"]] = by_split.get(r["split"], 0) + 1
        by_class[r["actor_class"]] = by_class.get(r["actor_class"], 0) + 1
        by_label[r["label"]] = by_label.get(r["label"], 0) + 1
    manifest = {
        "runs": [
            {
                k: r.get(k)
                for k in (
                    "run_id",
                    "seed",
                    "code_version",
                    "attack_version",
                    "catalogue_sha256",
                    "scenarios_sha256",
                    "sessions",
                    "steps",
                    "matched",
                    "not_run",
                )
            }
            for r in run_rows
        ],
        "problems": problems,
        "catalogue_sha256": catalogue.sha256,
        "split_catalogue_sha256": split.catalogue_sha256,
        "split_sha256": split.sha256,
        "lab_seed": os.environ.get("MIRAGE_SEED", "") == str(LAB_SEED),
        "attack_version": catalogue.attack_version,
        "features_event": FEATURES_EVENT,
        "features_tty": FEATURES_TTY,
        "n_sessions": len(rows),
        "n_steps": len({(s["run_id"], s["session_ref"], s["step_id"]) for s in steps}),
        "n_step_events": len(steps),
        "n_procedures": len({s["procedure_id"] for s in steps}),
        "by_split": by_split,
        "by_class": by_class,
        "by_label": by_label,
        "n_groups": len({r["group"] for r in rows}),
        "rows_sha256": _hash(rows),
        "steps_sha256": _hash(steps),
    }
    write_parquet(
        steps, out / "steps.parquet", {"n_step_events": len(steps), "columns": STEP_COLUMNS}
    )
    write_parquet(rows, out / "sessions.parquet", {**manifest, "columns": META + FEATURES})
    (out / "sessions.manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage-dataset")
    ap.add_argument("--out", type=Path, default=ROOT / "build" / "dataset")
    ap.add_argument(
        "--run",
        action="append",
        dest="runs",
        metavar="RUN_ID",
        help="export only this capture run (repeatable); default is every final capture run",
    )
    ap.add_argument(
        "--allow-unhealthy",
        action="store_true",
        help="export even if a run is not clean; the manifest records why it must not be frozen",
    )
    args = ap.parse_args(argv)
    os.environ.update({k: v for k, v in _env_file().items() if k not in os.environ})
    ch = ClickHouse.from_env()
    split = FrozenSplit.load()
    catalogue = Catalogue.load(ROOT / "lab" / "catalogue")
    groups = scenario_groups(ROOT / "lab" / "scenarios")
    try:
        manifest = export(ch, split, catalogue, args.out, args.runs, groups, args.allow_unhealthy)
    except DatasetError as exc:
        raise SystemExit(str(exc)) from exc
    shown = {k: v for k, v in manifest.items() if not k.endswith("_sha256")}
    print(json.dumps(shown, indent=2))


if __name__ == "__main__":
    main()
