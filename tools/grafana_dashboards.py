"""Generate the MIRAGE Grafana dashboards into compose/grafana/dashboards/.

    uv run python tools/grafana_dashboards.py        (or: make dashboards)

The JSON files are generated; edit this file, not them. Every page shares the navigation bar
(dashboard links by the ``mirage`` tag), the ClickHouse datasource and the drill-down links:
a session ID opens the Session page, an actor ID the Actors page.

Values captured from attackers (commands, paths, credentials) are shown as plain table text,
which Grafana escapes; no panel renders HTML from captured data, and captured data never
reaches a query as SQL. Template variables (typed or in the URL) are interpolated into SQL
unescaped, so a crafted URL can shape a query: Grafana therefore reads ClickHouse as a user
that can only SELECT (compose/clickhouse/users.d/grafana.xml). The ID patterns in the SQL only
keep an empty or malformed ID from matching anything; they are not the protection.

Before anything is written, ``check`` reads every page the way tests/integration/
test_dashboards.py will run it (each target of each top-level panel) and refuses a panel that
test could not reach, a variable it could not fill in, a replaced table read without FINAL, or
lab ground truth (a ``sim_*`` table) on the pages that show the models' predictions.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "compose/grafana/dashboards"
SPLIT_FILE = ROOT / "eval/split.yaml"
DS = {"type": "grafana-clickhouse-datasource", "uid": "clickhouse"}
TABLE, SERIES = 1, 0

SESSION_URL = "/d/mirage-session/mirage-session?var-session=${__value.raw}&${__url_time_range}"
ACTOR_URL = "/d/mirage-actors/mirage-actors?var-actor=${__value.raw}&${__url_time_range}"

# A session ID variable is used only if it looks like one (decoy hex IDs, http- logical IDs).
SID_OK = "match('${session}', '^[A-Za-z0-9._-]{1,64}$')"
ACTOR_OK = "match('${actor}', '^actor-[0-9a-f]{16}$')"
SRC_OK = "match('${src}', '^[0-9A-Fa-f:.]{0,45}$')"


def target(sql: str, fmt: int = TABLE, ref: str = "A") -> dict[str, Any]:
    return {"refId": ref, "datasource": DS, "editorType": "sql", "format": fmt, "rawSql": sql}


class Page:
    """A dashboard with a simple row-filling layout on Grafana's 24-column grid."""

    def __init__(self, uid: str, title: str, description: str, refresh: str = "30s") -> None:
        self.uid, self.title, self.description, self.refresh = uid, title, description, refresh
        self.panels: list[dict[str, Any]] = []
        self.variables: list[dict[str, Any]] = []
        self.x = self.y = self.row_h = 0

    def add(self, panel: dict[str, Any], w: int, h: int) -> None:
        if self.x + w > 24:
            self.x, self.y, self.row_h = 0, self.y + self.row_h, 0
        panel["id"] = len(self.panels) + 1
        panel["gridPos"] = {"x": self.x, "y": self.y, "w": w, "h": h}
        panel.setdefault("datasource", DS)
        self.panels.append(panel)
        self.x += w
        self.row_h = max(self.row_h, h)

    def newline(self) -> None:
        if self.x:
            self.x, self.y, self.row_h = 0, self.y + self.row_h, 0

    def textbox(self, name: str, label: str, default: str = "") -> None:
        self.variables.append(
            {
                "type": "textbox",
                "name": name,
                "label": label,
                "query": default,
                "current": {"text": default, "value": default},
                "hide": 0,
            }
        )

    def custom(self, name: str, label: str, values: list[str]) -> None:
        opts = [{"text": v, "value": v, "selected": i == 0} for i, v in enumerate(values)]
        self.variables.append(
            {
                "type": "custom",
                "name": name,
                "label": label,
                "query": ",".join(values),
                "options": opts,
                "current": {"text": values[0], "value": values[0]},
                "hide": 0,
            }
        )

    def json(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "title": self.title,
            "description": self.description,
            "tags": ["mirage"],
            "timezone": "utc",
            "schemaVersion": 41,
            "version": 1,
            "editable": False,
            "graphTooltip": 1,
            "refresh": self.refresh,
            "time": {"from": "now-24h", "to": "now"},
            "links": [
                {
                    "type": "dashboards",
                    "tags": ["mirage"],
                    "asDropdown": False,
                    "includeVars": False,
                    "keepTime": True,
                    "title": "MIRAGE",
                }
            ],
            "templating": {"list": self.variables},
            "panels": self.panels,
        }


# ------------------------------------------------------------------------------ panel helpers


def links(*cols: tuple[str, str, str]) -> list[dict[str, Any]]:
    """Field overrides that turn a column into a link: (column, title, url)."""
    return [
        {
            "matcher": {"id": "byName", "options": col},
            "properties": [{"id": "links", "value": [{"title": title, "url": url}]}],
        }
        for col, title, url in cols
    ]


SESSION_LINK = ("session_id", "Open session", SESSION_URL)
ACTOR_LINK = ("actor_id", "Open actor", ACTOR_URL)


def stat(title: str, sql: str, unit: str = "none", color: str = "blue", desc: str = "") -> dict:
    return {
        "type": "stat",
        "title": title,
        "description": desc,
        "targets": [target(sql)],
        "fieldConfig": {
            "defaults": {
                "unit": unit,
                "color": {"mode": "fixed", "fixedColor": color},
                "noValue": "\u2013" if color == "text" else "0",  # an en dash
            },
            "overrides": [],
        },
        "options": {
            # "/.*/" lets a stat show text (a protocol, an IP), not only numbers.
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "/.*/", "values": False},
            "colorMode": "value",
            "graphMode": "none",
            "textMode": "value",
        },
    }


# Column widths shared by every table, so timestamps and IDs are never cut off; the remaining
# columns (commands, details, evidence) share what is left.
WIDTHS = [
    (r"^(ts|start_ts|end_ts|stored_at|first_seen|last_seen|last|last_used|published_at)$", 185),
    (r"^(session_id|actor_id|a|b|exposed_in|token_id|request_id)$", 215),
    (r"^(sha256)$", 270),
    (r"^(source|protocol|outcome|type|action|reason|mime|kind|tactic|split|mode|gate)$", 115),
    (
        r"^(class|src_ip|sensor|rule_id|location|used_in|predicted_class|actor_class|decided_by|technique)$",
        150,
    ),
    (
        r"^(seq|inputs|decisions|fallbacks|tokens|artifacts|logged_in|strength|times|size|n_sessions|sessions|attempts|succeeded|exposures|uses|logins|sources|honeytokens|auth_attempts|duration_s|latency_us|status|confidence|class_confidence|agreement|scenarios|steps|matched|procedures|techniques_seen|value|ci_low|ci_high|baseline|delta)$",
        95,
    ),
]


def table(title: str, sql: str, overrides: list | None = None, desc: str = "") -> dict:
    widths = [
        {
            "matcher": {"id": "byRegexp", "options": rx},
            "properties": [{"id": "custom.width", "value": w}],
        }
        for rx, w in WIDTHS
    ]
    return {
        "type": "table",
        "title": title,
        "description": desc,
        "targets": [target(sql)],
        "fieldConfig": {
            "defaults": {"custom": {"filterable": True, "minWidth": 90}},
            "overrides": widths + (overrides or []),
        },
        "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
    }


def series(title: str, sql: str, unit: str = "short", stack: bool = True, desc: str = "") -> dict:
    return {
        "type": "timeseries",
        "title": title,
        "description": desc,
        "targets": [target(sql, SERIES)],
        "fieldConfig": {
            "defaults": {
                "unit": unit,
                "custom": {
                    "drawStyle": "bars" if stack else "line",
                    "fillOpacity": 70 if stack else 10,
                    "stacking": {"mode": "normal" if stack else "none"},
                    "lineWidth": 1,
                },
            },
            "overrides": [],
        },
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
    }


def pie(title: str, sql: str, desc: str = "") -> dict:
    return {
        "type": "piechart",
        "title": title,
        "description": desc,
        "targets": [target(sql)],
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": True},
            "pieType": "donut",
            "legend": {"displayMode": "table", "placement": "right", "values": ["value"]},
        },
    }


def bars(title: str, sql: str, desc: str = "") -> dict:
    return {
        "type": "barchart",
        "title": title,
        "description": desc,
        "targets": [target(sql)],
        "options": {
            "orientation": "horizontal",
            "showValue": "auto",
            "legend": {"showLegend": False},
        },
    }


def text(title: str, md: str) -> dict:
    return {"type": "text", "title": title, "options": {"mode": "markdown", "content": md}}


def heatmap(title: str, sql: str, row: str, desc: str = "") -> dict:
    """A heatmap of ready-made cells. The query returns ``(time, <row>, value)`` in long form,
    sorted by time; the datasource pivots it into one field per ``row`` value, and the panel
    draws each field as a row of cells, one per time step (``calculate`` off: nothing is
    re-bucketed)."""
    return {
        "type": "heatmap",
        "title": title,
        "description": desc,
        "targets": [target(sql, SERIES)],
        # Name each row by its label alone ("TA0007", not "sessions TA0007"). Only the value
        # fields: the time field has no such label.
        "fieldConfig": {
            "defaults": {},
            "overrides": [
                {
                    "matcher": {"id": "byType", "options": "number"},
                    "properties": [{"id": "displayName", "value": f"${{__field.labels.{row}}}"}],
                }
            ],
        },
        "options": {
            "calculate": False,
            "cellGap": 2,
            "color": {
                "mode": "scheme",
                "scheme": "Oranges",
                "fill": "dark-orange",
                "scale": "exponential",
                "exponent": 0.5,
                "steps": 64,
                "reverse": False,
            },
            "yAxis": {"axisPlacement": "left", "reverse": False},
            "rowsFrame": {"layout": "auto"},
            "cellValues": {"unit": "short"},
            "filterValues": {"le": 1e-9},  # an empty cell is left blank, not drawn as zero
            "showValue": "auto",
            "legend": {"show": True},
            "tooltip": {"mode": "single", "yHistogram": False, "showColorScale": True},
            "exemplars": {"color": "rgba(255,0,255,0.7)"},
        },
    }


def matrix(title: str, sql: str, row: str, desc: str = "") -> dict:
    """A heatmap of two categories: a table whose first column (``row``) names the row and
    whose other columns are counts, each cell shaded by its value on one scale for the whole
    table (Grafana's heatmap panel needs time on one axis)."""
    panel = table(
        title,
        sql,
        [
            {
                "matcher": {"id": "byName", "options": row},
                "properties": [
                    {"id": "custom.cellOptions", "value": {"type": "auto"}},
                    {"id": "custom.align", "value": "left"},
                    {"id": "custom.width", "value": 160},
                ],
            }
        ],
        desc,
    )
    panel["fieldConfig"]["defaults"] = {
        "custom": {
            "filterable": False,
            "minWidth": 90,
            "align": "center",
            "cellOptions": {"type": "color-background", "mode": "basic"},
        },
        "color": {"mode": "continuous-YlRd"},
        "min": 0,
    }
    return panel


# ------------------------------------------------------------------------------ SQL pieces

S = "mirage.session_summary FINAL"
IN_RANGE = "$__timeFilter(start_ts)"
CREDS = "arrayStringConcat(arrayMap(c -> concat(c.1, ' / ', c.2), credentials), ', ')"
CLIENT = (
    "coalesce(nullIf(JSONExtractString(fingerprints, 'client_version'), ''),"
    " nullIf(JSONExtractString(fingerprints, 'user_agent'), ''), '')"
)
# The decoy connection IDs that make up the session in ${session} (HTTP sessions span several).
SESSION_IDS = (
    f"(SELECT arrayJoin(connections) FROM {S}"
    f" WHERE session_id = '${{session}}' AND {SID_OK}"
    f" UNION ALL SELECT '${{session}}' WHERE {SID_OK})"
)
DETAIL = """multiIf(
    class = 'policy_decision', concat(JSONExtractString(payload, 'action'),
        if(JSONExtractBool(payload, 'fallback'),
           concat(' (fallback: ', JSONExtractString(payload, 'fallback_reason'), ')'), ''),
        '  ·  rule ', JSONExtractString(payload, 'rule_id'),
        '  ·  ', toString(JSONExtractFloat(payload, 'latency_ms')), ' ms'),
    class = 'authentication', concat(JSONExtractString(payload, 'username'), ' / ',
        JSONExtractString(payload, 'password')),
    class = 'http_activity', concat(JSONExtractString(payload, 'method'), ' ',
        JSONExtractString(payload, 'target'), '  →  ', toString(JSONExtractInt(payload, 'status'))),
    action = 'token_triggered', concat('honeytoken ', JSONExtractString(payload, 'token_id'),
        ' (planted at ', JSONExtractString(payload, 'planted_at'), ')'),
    action = 'fs_change', concat(JSONExtractString(payload, 'op'), ' ',
        JSONExtractString(payload, 'path'), ' ', JSONExtractString(payload, 'sha256')),
    JSONHas(payload, 'command'), JSONExtractString(payload, 'command'),
    JSONHas(payload, 'sha256'), concat(JSONExtractString(payload, 'filename'),
        JSONExtractString(payload, 'destfile'), ' ', JSONExtractString(payload, 'sha256')),
    JSONHas(payload, 'client_version'), JSONExtractString(payload, 'client_version'),
    JSONHas(payload, 'hassh'), concat('hassh ', JSONExtractString(payload, 'hassh')),
    '')"""
PROTOCOL_FILTER = "('${protocol}' = 'all' OR protocol = '${protocol}')"
SRC_FILTER = f"({SRC_OK} AND ('${{src}}' = '' OR src_ip = '${{src}}'))"

# ---- what the models said (phase 2 spec 2.7). Predictions only: mirage.labels is the tagger's
# output and mirage.actor_class the classifier's. Never a sim_* table here: those hold the
# lab's ground truth, which is what a prediction is compared with, not what a page shows.
#
# The tagger labels events, so its session_id is the decoy connection's; the sessioniser
# groups an HTTP client's connections into one logical session and records that in
# session_map. Both pieces below key on the logical session (``lsid``), the ID the Sessions
# page lists. A LEFT JOIN that finds no mapping leaves m.session_id empty (or NULL under
# join_use_nulls), and the connection's own ID is then the session's.
SESSION_MAP = "(SELECT conn_id, session_id FROM mirage.session_map FINAL)"


def tags(where: str) -> str:
    """One row per (logical session, tactic, technique) the tagger found, for labels
    matching ``where`` (a condition on mirage.labels)."""
    return (
        "SELECT DISTINCT if(m.session_id != '', m.session_id, l.session_id) AS lsid,"
        " l.tactic AS tactic, l.technique AS technique"
        " FROM (SELECT session_id, tactic, technique FROM mirage.labels FINAL"
        f" WHERE technique != '' AND {where}) AS l"
        f" LEFT JOIN {SESSION_MAP} AS m ON m.conn_id = l.session_id"
    )


def tags_by_session(where: str) -> str:
    """One row per logical session: its tactics and techniques as sorted, comma-separated text."""
    return (
        "SELECT lsid, arrayStringConcat(arraySort(groupUniqArray(tactic)), ', ') AS tactics,"
        " arrayStringConcat(arraySort(groupUniqArray(technique)), ', ') AS techniques"
        f" FROM ({tags(where)}) GROUP BY lsid"
    )


def predicted_class(where: str) -> str:
    """One row per logical session: the classifier's latest prediction (``cls``), its
    confidence and whether the scanner rule or the model made it. ``where`` is a condition on
    mirage.actor_class."""
    return (
        "SELECT if(cm.session_id != '', cm.session_id, a.session_id) AS lsid,"
        " argMax(a.actor_class, a.ts) AS cls, argMax(a.confidence, a.ts) AS cls_confidence,"
        " argMax(a.decided_by, a.ts) AS cls_decided_by"
        " FROM (SELECT session_id, actor_class, confidence, decided_by, ts"
        f" FROM mirage.actor_class FINAL WHERE {where}) AS a"
        f" LEFT JOIN {SESSION_MAP} AS cm ON cm.conn_id = a.session_id GROUP BY lsid"
    )


# A session's labels and prediction are written after it starts, so on a page that lists the
# sessions started in the time range, nothing older than the range's start can belong to one.
SINCE_FROM = "ts >= $__fromTime"


# ---- the frozen split (phase 2 spec, section 5). ClickHouse does not store it: it lives in
# eval/split.yaml, which assigns every scenario to train, dev or test. The Lab page counts
# what the lab captured for each, so the mapping is written into its SQL here. Regenerate the
# dashboards after the split is rebuilt or extended.
def split_of(column: str) -> str:
    """SQL for the split of the scenario ID in ``column``; 'unassigned' for one the frozen
    split does not list (a scenario added since, or no split file at all)."""
    scenarios: dict[str, str] = {}
    if SPLIT_FILE.exists():
        scenarios = (yaml.safe_load(SPLIT_FILE.read_text()) or {}).get("scenarios") or {}
    for name, split in scenarios.items():  # they go into SQL: accept only plain IDs
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", name) or split not in SPLITS:
            raise SystemExit(f"{SPLIT_FILE}: unexpected scenario or split: {name!r}: {split!r}")
    if not scenarios:
        return "'unassigned'"
    ids = ", ".join(f"'{name}'" for name in sorted(scenarios))
    splits = ", ".join(f"'{scenarios[name]}'" for name in sorted(scenarios))
    return f"transform({column}, [{ids}], [{splits}], 'unassigned')"


SPLITS = ("train", "dev", "test")
# train, dev, test, then anything else: the order a reader expects, not the alphabet's.
SPLIT_ORDER = (
    "indexOf(['train', 'dev', 'test'], split) = 0, indexOf(['train', 'dev', 'test'], split)"
)


# ------------------------------------------------------------------------------ pages


def overview() -> Page:
    p = Page(
        "mirage-overview",
        "MIRAGE · Overview",
        "Everything the decoys captured in the selected time range.",
    )
    q = f"FROM {S} WHERE {IN_RANGE}"
    p.add(stat("Sessions", f"SELECT count() {q}"), 6, 4)
    p.add(stat("Actors", f"SELECT uniqExact(actor_id) {q}", color="purple"), 6, 4)
    p.add(stat("Logged in", f"SELECT countIf(auth_success = 1) {q}", color="orange"), 6, 4)
    p.add(stat("Inputs", f"SELECT sum(inputs) {q}"), 6, 4)
    p.add(
        stat(
            "Honeytokens used",
            "SELECT count() FROM mirage.events FINAL WHERE action = 'token_triggered' "
            "AND $__timeFilter(ts)",
            color="red",
        ),
        6,
        4,
    )
    p.add(
        stat(
            "Artifacts",
            "SELECT count() FROM mirage.artifact_files FINAL WHERE $__timeFilter(stored_at)",
            color="green",
        ),
        6,
        4,
    )
    p.add(
        stat(
            "Policy fallbacks",
            f"SELECT sum(fallbacks) {q}",
            color="yellow",
            desc="Inputs the decoys answered without a policy decision (service down or late).",
        ),
        6,
        4,
    )
    p.add(
        stat(
            "Unmapped events",
            "SELECT count() FROM mirage.events WHERE class = 'unknown' AND $__timeFilter(ts)",
            color="red",
            desc="Events the normaliser could not classify. Should stay at 0.",
        ),
        6,
        4,
    )
    p.add(
        series(
            "Sessions by protocol",
            f"SELECT $__timeInterval(start_ts) AS time, protocol, count() AS sessions {q} "
            "GROUP BY time, protocol ORDER BY time",
        ),
        16,
        8,
    )
    p.add(
        pie("Sessions by protocol", f"SELECT protocol, count() AS sessions {q} GROUP BY protocol"),
        8,
        8,
    )
    p.add(
        table(
            "Latest honeytoken use",
            "SELECT ts, JSONExtractString(payload, 'token_id') AS token_id,"
            " JSONExtractString(payload, 'token_type') AS type,"
            " JSONExtractString(payload, 'session') AS session_id, protocol, src_ip,"
            " arrayStringConcat(JSONExtract(payload, 'exposed_in', 'Array(String)'), ', ')"
            " AS exposed_in FROM mirage.events FINAL WHERE action = 'token_triggered'"
            " AND $__timeFilter(ts) ORDER BY ts DESC LIMIT 20",
            links(SESSION_LINK),
        ),
        12,
        8,
    )
    p.add(
        bars(
            "Top sources",
            f"SELECT src_ip, count() AS sessions {q} AND src_ip != '' "
            "GROUP BY src_ip ORDER BY sessions DESC LIMIT 10",
        ),
        12,
        8,
    )
    p.add(
        table(
            "Latest sessions",
            f"SELECT start_ts, session_id, protocol, src_ip, actor_id, inputs, auth_success"
            f" AS logged_in, length(tokens) AS tokens, {CLIENT} AS client {q}"
            " ORDER BY start_ts DESC LIMIT 25",
            links(SESSION_LINK, ACTOR_LINK),
        ),
        24,
        10,
    )
    p.add(
        series(
            "Events by source",
            "SELECT $__timeInterval(ts) AS time, source, count() AS events FROM mirage.events "
            "WHERE $__timeFilter(ts) GROUP BY time, source ORDER BY time",
            desc="Pipeline throughput: normalised events per source.",
        ),
        24,
        7,
    )
    return p


def sessions() -> Page:
    p = Page(
        "mirage-sessions",
        "MIRAGE · Sessions",
        "Every session on every protocol. Click a session to open it.",
    )
    p.custom("protocol", "Protocol", ["all", "ssh", "http", "redis", "mysql"])
    p.textbox("src", "Source IP")
    where = f"WHERE {IN_RANGE} AND {PROTOCOL_FILTER} AND {SRC_FILTER}"
    q = f"FROM {S} {where}"
    p.add(stat("Sessions", f"SELECT count() {q}"), 4, 4)
    p.add(stat("Logged in", f"SELECT countIf(auth_success = 1) {q}", color="orange"), 4, 4)
    p.add(stat("Inputs", f"SELECT sum(inputs) {q}"), 4, 4)
    p.add(stat("Auth attempts", f"SELECT sum(auth_attempts) {q}", color="purple"), 4, 4)
    p.add(stat("With honeytokens", f"SELECT countIf(length(tokens) > 0) {q}", color="red"), 4, 4)
    p.add(stat("With artifacts", f"SELECT countIf(length(artifacts) > 0) {q}", color="green"), 4, 4)
    # The newest 500 sessions, then what the classifier and the tagger said about each.
    recent = (
        "SELECT start_ts, session_id, protocol, src_ip, actor_id,"
        " round(dateDiff('millisecond', start_ts, end_ts) / 1000, 1) AS duration_s,"
        " inputs, decisions, fallbacks, auth_attempts, auth_success AS logged_in,"
        f" {CREDS} AS credentials, {CLIENT} AS client, length(tokens) AS tokens,"
        f" length(artifacts) AS artifacts {q} ORDER BY start_ts DESC LIMIT 500"
    )
    p.add(
        table(
            "Recent sessions",
            "SELECT s.start_ts AS start_ts, s.session_id AS session_id, s.protocol AS protocol,"
            " s.src_ip AS src_ip, s.actor_id AS actor_id, ac.cls AS predicted_class,"
            " round(ac.cls_confidence, 2) AS class_confidence, tg.tactics AS tactics,"
            " tg.techniques AS techniques, s.duration_s AS duration_s, s.inputs AS inputs,"
            " s.decisions AS decisions, s.fallbacks AS fallbacks,"
            " s.auth_attempts AS auth_attempts, s.logged_in AS logged_in,"
            " s.credentials AS credentials, s.client AS client, s.tokens AS tokens,"
            " s.artifacts AS artifacts"
            f" FROM ({recent}) AS s"
            f" LEFT JOIN ({predicted_class(SINCE_FROM)}) AS ac ON ac.lsid = s.session_id"
            f" LEFT JOIN ({tags_by_session(SINCE_FROM)}) AS tg ON tg.lsid = s.session_id"
            " ORDER BY start_ts DESC",
            links(SESSION_LINK, ACTOR_LINK),
            desc="predicted_class is the actor classifier's prediction, tactics and techniques "
            "the tagger's labels (ATT&CK IDs). Empty where a model has said nothing yet.",
        ),
        24,
        12,
    )
    in_filter = f"(SELECT session_id {q})"
    p.add(
        pie(
            "Predicted actor class",
            "SELECT if(ac.cls = '', 'not classified', ac.cls) AS actor_class,"
            f" count() AS sessions FROM {in_filter} AS s"
            f" LEFT JOIN ({predicted_class(SINCE_FROM)}) AS ac ON ac.lsid = s.session_id"
            " GROUP BY actor_class",
            desc="The classifier's prediction for the sessions above (mirage.actor_class).",
        ),
        8,
        8,
    )
    p.add(
        bars(
            "Tactics found (sessions)",
            "SELECT t.tactic AS tactic, uniqExact(t.lsid) AS sessions"
            f" FROM ({tags(SINCE_FROM)}) AS t INNER JOIN {in_filter} AS s"
            " ON s.session_id = t.lsid GROUP BY tactic ORDER BY sessions DESC",
            desc="Sessions in which the tagger found each ATT&CK tactic (mirage.labels).",
        ),
        8,
        8,
    )
    p.add(
        bars(
            "Techniques found (sessions)",
            "SELECT t.technique AS technique, uniqExact(t.lsid) AS sessions"
            f" FROM ({tags(SINCE_FROM)}) AS t INNER JOIN {in_filter} AS s"
            " ON s.session_id = t.lsid GROUP BY technique ORDER BY sessions DESC LIMIT 15",
            desc="Sessions in which the tagger found each ATT&CK technique (mirage.labels).",
        ),
        8,
        8,
    )
    ev = (
        "FROM mirage.events WHERE $__timeFilter(ts) AND source != 'policy' "
        f"AND {PROTOCOL_FILTER} AND {SRC_FILTER}"
    )
    p.add(
        series(
            "Events by class",
            f"SELECT $__timeInterval(ts) AS time, class, count() AS events {ev} "
            "GROUP BY time, class ORDER BY time",
        ),
        24,
        7,
    )
    p.add(
        table(
            "Top commands (SSH)",
            "SELECT JSONExtractString(payload, 'command') AS command, count() AS times,"
            f" uniqExact(session_id) AS sessions {ev} AND source = 'cowrie'"
            " AND class = 'process_activity' AND action = 'command' AND outcome = 'unknown'"
            " GROUP BY command ORDER BY times DESC LIMIT 50",
        ),
        8,
        10,
    )
    p.add(
        table(
            "Top paths (HTTP)",
            "SELECT JSONExtractString(payload, 'method') AS method,"
            " JSONExtractString(payload, 'path') AS path,"
            " JSONExtractInt(payload, 'status') AS status, count() AS times"
            f" {ev} AND class = 'http_activity' GROUP BY method, path, status"
            " ORDER BY times DESC LIMIT 50",
        ),
        8,
        10,
    )
    p.add(
        table(
            "Credentials tried",
            "SELECT protocol, JSONExtractString(payload, 'username') AS username,"
            " JSONExtractString(payload, 'password') AS password, count() AS attempts,"
            " countIf(outcome = 'success') AS succeeded"
            f" {ev} AND class = 'authentication' AND action = 'login'"
            " GROUP BY protocol, username, password ORDER BY attempts DESC LIMIT 100",
        ),
        8,
        10,
    )
    return p


def session() -> Page:
    p = Page(
        "mirage-session",
        "MIRAGE · Session",
        "One session: what the client sent, what the gate decided, and what it left behind.",
        refresh="",
    )
    p.textbox("session", "Session ID")
    one = f"FROM {S} WHERE session_id = '${{session}}' AND {SID_OK}"
    p.add(
        text(
            "",
            "Paste a session ID above, or click one on the **Sessions** or **Overview** page. "
            "The time picker does not apply here: a session is shown whole.",
        ),
        24,
        2,
    )
    p.add(stat("Protocol", f"SELECT protocol {one}", color="text"), 4, 4)
    p.add(stat("Source", f"SELECT src_ip {one}", color="text"), 4, 4)
    p.add(
        stat("Started", f"SELECT toUnixTimestamp64Milli(start_ts) {one}", "dateTimeAsIso", "text"),
        4,
        4,
    )
    p.add(
        stat(
            "Duration",
            f"SELECT dateDiff('millisecond', start_ts, end_ts) / 1000 {one}",
            "s",
            "text",
        ),
        4,
        4,
    )
    p.add(stat("Inputs", f"SELECT inputs {one}"), 4, 4)
    p.add(
        stat("Logged in", f"SELECT if(auth_success = 1, 'yes', 'no') {one}", color="orange"), 4, 4
    )
    p.add(
        table(
            "Summary",
            f"SELECT actor_id, sensor, decisions, fallbacks, {CREDS} AS credentials, fingerprints,"
            " arrayStringConcat(tokens, ', ') AS honeytokens,"
            " arrayStringConcat(artifacts, ', ') AS artifacts,"
            f" arrayStringConcat(connections, ', ') AS connections {one}",
            links(ACTOR_LINK),
        ),
        24,
        4,
    )
    p.add(
        table(
            "Predicted actor class",
            "SELECT actor_class, round(confidence, 3) AS confidence, decided_by, model_version, ts"
            f" FROM mirage.actor_class FINAL WHERE session_id IN {SESSION_IDS} ORDER BY ts DESC",
            desc="The actor classifier's prediction for this session, and whether the scanner "
            "rule or the model made it. A prediction, recomputed as the session grows.",
        ),
        8,
        7,
    )
    p.add(
        table(
            "Tactics and techniques",
            "SELECT l.ts AS ts, l.kind AS kind, l.tactic AS tactic, l.technique AS technique,"
            " round(l.confidence, 2) AS confidence, e.input AS input, l.rule_id AS rule_id,"
            " l.model_version AS model_version"
            " FROM (SELECT event_id, ts, kind, tactic, technique, confidence, rule_id,"
            f" model_version FROM mirage.labels FINAL WHERE session_id IN {SESSION_IDS}"
            " AND technique != '') AS l"
            " LEFT JOIN (SELECT event_id, if(JSONExtractString(payload, 'command') != '',"
            " JSONExtractString(payload, 'command'), JSONExtractString(payload, 'input'))"
            f" AS input FROM mirage.events FINAL WHERE session_id IN {SESSION_IDS}"
            " AND class = 'policy_decision' AND source != 'policy') AS e"
            " ON e.event_id = l.event_id ORDER BY ts",
            desc="The tagger's labels (ATT&CK IDs): one row per labelled input, and one per "
            "session-level rule (kind = session, which has no single input).",
        ),
        16,
        7,
    )
    p.add(
        table(
            "Timeline",
            f"SELECT ts, action, {DETAIL} AS detail, outcome, class, source,"
            " JSONExtractInt(payload, 'seq') AS seq FROM mirage.events FINAL"
            f" WHERE session_id IN {SESSION_IDS} AND source != 'policy' ORDER BY ts, seq",
            desc="Every event in order. A policy_decision row precedes the input it decided.",
        ),
        24,
        16,
    )
    p.add(
        table(
            "Linked sessions",
            "SELECT if(a = '${session}', b, a) AS session_id, reason, strength, evidence, ts"
            f" FROM mirage.actor_links FINAL WHERE (a = '${{session}}' OR b = '${{session}}')"
            f" AND {SID_OK} ORDER BY strength DESC, ts",
            links(SESSION_LINK),
            desc="Why this session is grouped with others into one actor.",
        ),
        14,
        7,
    )
    p.add(
        table(
            "Artifacts",
            "SELECT sha256, any(size) AS size, any(mime) AS mime, any(source) AS source,"
            " any(stored_at) AS stored_at FROM mirage.artifacts ARRAY JOIN sessions AS s"
            f" WHERE s IN {SESSION_IDS} GROUP BY sha256 ORDER BY stored_at",
        ),
        10,
        7,
    )
    p.add(
        table(
            "Policy service records",
            "SELECT ts, JSONExtractString(payload, 'request', 'request_id') AS request_id,"
            " JSONExtractString(payload, 'command') AS input,"
            " JSONExtractString(policy, 'action') AS action,"
            " JSONExtractString(payload, 'rule_id') AS rule_id,"
            " JSONExtractString(payload, 'rules_version') AS rules_version,"
            " JSONExtractInt(payload, 'latency_us') AS latency_us"
            f" FROM mirage.events FINAL WHERE source = 'policy' AND session_id IN {SESSION_IDS}"
            " ORDER BY ts",
            desc="The policy service's own record of each decision, joined on request_id.",
        ),
        24,
        7,
    )
    p.add(
        text(
            "Terminal replay (SSH)",
            "Cowrie records every SSH terminal. The **Timeline** lists the recording as "
            "`ttylog_closed`; replay it with:\n\n"
            "```\ndocker exec mirage-cowrie-1 /cowrie/cowrie-env/bin/python3 -m "
            "cowrie.scripts.playlog -m 1 /cowrie/cowrie-git/<ttylog path>\n```",
        ),
        24,
        4,
    )
    return p


def actors() -> Page:
    p = Page(
        "mirage-actors",
        "MIRAGE · Actors",
        "Sessions grouped by the links between them: honeytoken use (strongest), SSH "
        "fingerprint plus credentials, and the same source within 24 hours (weakest).",
    )
    p.textbox("actor", "Actor ID")
    p.add(
        table(
            "Actors",
            "SELECT actor_id, count() AS sessions,"
            " arrayStringConcat(arraySort(groupUniqArray(protocol)), ', ') AS protocols,"
            " uniqExact(src_ip) AS sources, min(start_ts) AS first_seen,"
            " max(end_ts) AS last_seen, sum(inputs) AS inputs,"
            " countIf(auth_success = 1) AS logins,"
            " length(groupUniqArrayArray(tokens)) AS honeytokens"
            f" FROM {S} WHERE {IN_RANGE} GROUP BY actor_id"
            " ORDER BY length(groupUniqArrayArray(tokens)) DESC, sessions DESC LIMIT 500",
            links(ACTOR_LINK),
        ),
        24,
        10,
    )
    graph = {
        "type": "nodeGraph",
        "title": "Selected actor: sessions and links",
        "description": "Nodes are sessions; edges are links, labelled with their reason.",
        "targets": [
            target(
                "SELECT session_id AS id, protocol AS title, src_ip AS subtitle,"
                " concat(toString(inputs), ' in') AS mainstat,"
                " formatDateTime(start_ts, '%d %b %H:%i') AS secondarystat"
                f" FROM {S} WHERE actor_id = '${{actor}}' AND {ACTOR_OK} LIMIT 300",
                ref="nodes",
            ),
            target(
                "SELECT concat(a, '|', b, '|', reason) AS id, a AS source, b AS target,"
                " reason AS mainstat FROM mirage.actor_links FINAL"
                f" WHERE a IN (SELECT session_id FROM {S} WHERE actor_id = '${{actor}}'"
                f" AND {ACTOR_OK}) LIMIT 1000",
                ref="edges",
            ),
        ],
    }
    p.add(graph, 24, 12)
    p.add(
        table(
            "Selected actor: sessions",
            f"SELECT start_ts, session_id, protocol, src_ip, inputs, {CREDS} AS credentials,"
            f" {CLIENT} AS client, arrayStringConcat(tokens, ', ') AS honeytokens"
            f" FROM {S} WHERE actor_id = '${{actor}}' AND {ACTOR_OK} ORDER BY start_ts",
            links(SESSION_LINK),
        ),
        14,
        9,
    )
    p.add(
        table(
            "Selected actor: links",
            "SELECT reason, strength, a, b, evidence, ts FROM mirage.actor_links FINAL"
            f" WHERE a IN (SELECT session_id FROM {S} WHERE actor_id = '${{actor}}'"
            f" AND {ACTOR_OK}) ORDER BY strength DESC, ts",
            links(("a", "Open session", SESSION_URL), ("b", "Open session", SESSION_URL)),
        ),
        10,
        9,
    )
    p.add(
        pie(
            "Links by reason",
            "SELECT reason, count() AS links FROM mirage.actor_links FINAL"
            " WHERE $__timeFilter(ts) GROUP BY reason",
        ),
        8,
        7,
    )
    p.add(
        series(
            "New links",
            "SELECT $__timeInterval(ts) AS time, reason, count() AS links"
            " FROM mirage.actor_links FINAL WHERE $__timeFilter(ts) GROUP BY time, reason"
            " ORDER BY time",
        ),
        16,
        7,
    )
    return p


def tokens() -> Page:
    p = Page(
        "mirage-tokens",
        "MIRAGE · Honeytokens",
        "Planted tokens, which sessions reached where they are planted, and which used them.",
    )
    p.add(
        table(
            "Planted tokens",
            "SELECT t.token_id AS token_id, t.type AS type, t.planted_at AS planted_at,"
            " t.username AS username, t.value AS value,"
            " ifNull(e.n, 0) AS exposures, ifNull(u.n, 0) AS uses, u.last AS last_used"
            # Only the current deployment's tokens: each sessioniser start reloads them, so
            # rows from an earlier render keep an older loaded_at.
            " FROM (SELECT * FROM mirage.tokens FINAL WHERE loaded_at ="
            " (SELECT max(loaded_at) FROM mirage.tokens)) AS t"
            " LEFT JOIN (SELECT token_id, count() AS n FROM mirage.token_exposures FINAL"
            " GROUP BY token_id) AS e ON e.token_id = t.token_id"
            " LEFT JOIN (SELECT JSONExtractString(payload, 'token_id') AS token_id,"
            " count() AS n, max(ts) AS last FROM mirage.events FINAL"
            " WHERE action = 'token_triggered' GROUP BY token_id) AS u"
            " ON u.token_id = t.token_id ORDER BY uses DESC, token_id"
            " SETTINGS join_use_nulls = 1",
            desc="Values are this deployment's own fake credentials and records.",
        ),
        24,
        7,
    )
    p.add(
        table(
            "Uses (token.triggered)",
            "SELECT ts, JSONExtractString(payload, 'token_id') AS token_id,"
            " JSONExtractString(payload, 'session') AS session_id, protocol, src_ip,"
            " JSONExtractString(payload, 'trigger_class') AS used_in,"
            " arrayStringConcat(JSONExtract(payload, 'exposed_in', 'Array(String)'), ', ')"
            " AS exposed_in FROM mirage.events FINAL WHERE action = 'token_triggered'"
            " AND $__timeFilter(ts) ORDER BY ts DESC LIMIT 500",
            links(SESSION_LINK),
        ),
        24,
        9,
    )
    p.add(
        table(
            "Exposures",
            "SELECT ts, token_id, session_id, location FROM mirage.token_exposures FINAL"
            " WHERE $__timeFilter(ts) ORDER BY ts DESC LIMIT 500",
            links(SESSION_LINK),
            desc="A session reached a place a token is planted, e.g. read /var/www/html/.env.",
        ),
        14,
        9,
    )
    p.add(
        series(
            "Uses over time",
            "SELECT $__timeInterval(ts) AS time, JSONExtractString(payload, 'token_type')"
            " AS type, count() AS uses FROM mirage.events FINAL WHERE action = 'token_triggered'"
            " AND $__timeFilter(ts) GROUP BY time, type ORDER BY time",
        ),
        10,
        9,
    )
    return p


def artifacts() -> Page:
    p = Page(
        "mirage-artifacts",
        "MIRAGE · Artifacts",
        "Files the decoys stored: uploads, downloads, redirected writes, large bodies. "
        "Never executed; the indexer only hashes them and reads their type.",
    )
    q = "FROM mirage.artifacts WHERE $__timeFilter(stored_at)"
    p.add(stat("Stored files", f"SELECT count() {q}", color="green"), 6, 4)
    p.add(stat("Total size", f"SELECT sum(size) {q}", "bytes", "green"), 6, 4)
    p.add(stat("Distinct types", f"SELECT uniqExact(mime) {q}", color="green"), 6, 4)
    p.add(
        stat(
            "Seen in sessions",
            f"SELECT uniqExact(s) FROM (SELECT arrayJoin(sessions) AS s {q})",
            color="green",
        ),
        6,
        4,
    )
    p.add(
        table(
            "Artifacts",
            "SELECT stored_at, sha256, size, mime, source, first_seen, last_seen,"
            " sessions[1] AS session_id, length(sessions) AS n_sessions"
            f" {q} ORDER BY stored_at DESC LIMIT 500",
            links(SESSION_LINK),
            desc="session_id is the first session the hash appeared in.",
        ),
        16,
        12,
    )
    p.add(pie("By type", f"SELECT mime, count() AS files {q} GROUP BY mime"), 8, 6)
    p.add(pie("By decoy", f"SELECT source, count() AS files {q} GROUP BY source"), 8, 6)
    return p


def policy() -> Page:
    p = Page(
        "mirage-policy",
        "MIRAGE · Policy",
        "What the policy gate decided, which rules fired, how fast, when decoys fell back, and "
        "how often the shadow policy would have done the same.",
    )
    d = "FROM mirage.events WHERE class = 'policy_decision' AND source != 'policy' AND $__timeFilter(ts)"
    srv = "FROM mirage.events WHERE source = 'policy' AND $__timeFilter(ts)"
    p.add(stat("Decisions", f"SELECT count() {d}"), 6, 4)
    p.add(
        stat(
            "Fallbacks",
            f"SELECT countIf(JSONExtractBool(payload, 'fallback')) {d}",
            color="yellow",
        ),
        6,
        4,
    )
    p.add(
        stat(
            "Gate latency p95 (decoy side)",
            f"SELECT quantile(0.95)(JSONExtractFloat(payload, 'latency_ms')) {d}"
            " AND NOT JSONExtractBool(payload, 'fallback')",
            "ms",
            "purple",
        ),
        6,
        4,
    )
    p.add(
        stat(
            "Service latency p95",
            f"SELECT quantile(0.95)(JSONExtractInt(payload, 'latency_us')) / 1000 {srv}",
            "ms",
            "purple",
        ),
        6,
        4,
    )
    p.add(
        series(
            "Decisions by action",
            "SELECT $__timeInterval(ts) AS time, JSONExtractString(payload, 'action') AS action,"
            f" count() AS decisions {d} GROUP BY time, action ORDER BY time",
        ),
        16,
        8,
    )
    p.add(
        pie(
            "Actions",
            f"SELECT JSONExtractString(payload, 'action') AS action, count() AS n {d}"
            " GROUP BY action",
        ),
        8,
        8,
    )
    # The bandit (spec 2.5): the enriched fields live on the service-side record (source=policy).
    svc_d = "FROM mirage.events WHERE source = 'policy' AND $__timeFilter(ts)"
    p.add(
        stat(
            "Explore share",
            f"SELECT countIf(JSONExtractBool(payload, 'explore')) / count() {svc_d}",
            "percentunit",
            "orange",
            desc="Fraction of decisions where the exploring policy acted (lab explore range).",
        ),
        6,
        4,
    )
    p.add(
        pie(
            "Explored actions",
            "SELECT JSONExtractString(payload, 'acting', 'action') AS action, count() AS n"
            f" {svc_d} AND JSONExtractBool(payload, 'explore') GROUP BY action",
            desc="What the exploring policy chose, over the action mask.",
        ),
        9,
        8,
    )
    p.add(
        series(
            "Explore vs rules",
            "SELECT $__timeInterval(ts) AS time,"
            " if(JSONExtractBool(payload, 'explore'), 'explore', 'rules') AS mode,"
            f" count() AS decisions {svc_d} GROUP BY time, mode ORDER BY time",
        ),
        9,
        8,
    )
    # Shadow agreement (spec 2.7): on each decision the shadow policy logs a probability for
    # every allowed action; it "agrees" when its most probable action is the one taken.
    # Records from before the shadow was logged on explored decisions have none and are left
    # out, not counted as disagreement.
    shadowed = (
        "FROM (SELECT ts, JSONExtractBool(payload, 'explore') AS explored,"
        " JSONExtractString(payload, 'shadow', 'name') AS shadow,"
        " JSONExtractString(payload, 'shadow', 'version') AS shadow_version,"
        " JSONExtractString(payload, 'acting', 'action') AS taken,"
        " arrayReverseSort(x -> x.2,"
        " JSONExtractKeysAndValues(payload, 'shadow', 'probs', 'Float64'))[1].1 AS preferred"
        f" {svc_d} AND JSONHas(payload, 'shadow', 'probs'))"
    )
    mode = "if(explored, 'explored', 'rules decided') AS mode"
    p.add(
        stat(
            "Shadow agreement",
            f"SELECT avg(preferred = taken) {shadowed}",
            "percentunit",
            "green",
            desc="Share of decisions where the shadow policy's most probable action is the "
            "action that was taken.",
        ),
        6,
        8,
    )
    agreement = series(
        "Shadow agreement over time",
        f"SELECT $__timeInterval(ts) AS time, {mode}, avg(preferred = taken) AS agreement"
        f" {shadowed} GROUP BY time, mode ORDER BY time",
        "percentunit",
        stack=False,
        desc="The same share over time, apart for decisions the exploring policy made and "
        "decisions the rules made. An explored decision departs from the rules' action about "
        "as often as the policy explores, so its agreement with any shadow is lower by design.",
    )
    agreement["fieldConfig"]["defaults"].update(min=0, max=1)
    p.add(agreement, 18, 8)
    p.add(
        table(
            "Shadow policies",
            f"SELECT shadow, shadow_version, {mode}, count() AS decisions,"
            " round(avg(preferred = taken), 3) AS agreement, max(ts) AS last"
            f" {shadowed} GROUP BY shadow, shadow_version, mode ORDER BY last DESC",
            desc="Which policy shadowed. 'shadow-fallback(epsilon-greedy)' means no trained "
            "model was loaded: the service says so instead of naming a model.",
        ),
        24,
        6,
    )
    p.add(
        series(
            "Gate latency p95 by decoy",
            "SELECT $__timeInterval(ts) AS time, source,"
            " quantile(0.95)(JSONExtractFloat(payload, 'latency_ms')) AS p95_ms"
            f" {d} AND NOT JSONExtractBool(payload, 'fallback') GROUP BY time, source"
            " ORDER BY time",
            "ms",
            stack=False,
        ),
        12,
        8,
    )
    p.add(
        table(
            "Rules",
            "SELECT JSONExtractString(payload, 'rule_id') AS rule_id,"
            " JSONExtractString(payload, 'rules_version') AS rules_version,"
            " JSONExtractString(payload, 'action') AS action, count() AS decisions,"
            f" max(ts) AS last {d} AND NOT JSONExtractBool(payload, 'fallback')"
            " GROUP BY rule_id, rules_version, action ORDER BY decisions DESC",
        ),
        12,
        8,
    )
    p.add(
        table(
            "Fallbacks",
            "SELECT ts, source, session_id, JSONExtractString(payload, 'fallback_reason')"
            " AS reason, JSONExtractString(payload, 'command') AS input"
            f" {d} AND JSONExtractBool(payload, 'fallback') ORDER BY ts DESC LIMIT 200",
            links(SESSION_LINK),
            desc="The decoy answered as its plain emulation would: no decision arrived in time.",
        ),
        24,
        8,
    )
    return p


def lab() -> Page:
    p = Page(
        "mirage-lab",
        "MIRAGE · Lab",
        "The simulation lab: scenario runs, how cleanly the ground truth joined, the actors "
        "and protocols exercised, what was captured for each side of the frozen split, and the "
        "latest evaluation metrics beside their baselines.",
    )
    runs = "FROM mirage.sim_runs FINAL WHERE final = 1 AND $__timeFilter(ended_ts)"
    p.add(stat("Runs", f"SELECT count() {runs}"), 6, 4)
    p.add(stat("Sessions", f"SELECT sum(sessions) {runs}"), 6, 4)
    p.add(
        stat(
            "Steps matched",
            f"SELECT sum(matched) {runs}",
            color="green",
            desc="Scenario steps whose input was captured and joined to its label.",
        ),
        6,
        4,
    )
    p.add(
        stat(
            "Join misses",
            f"SELECT sum(no_event) + sum(mismatch) {runs}",
            color="red",
            desc="no_event + mismatch. Must be zero for a run to feed a dataset (spec 3).",
        ),
        6,
        4,
    )
    p.add(
        table(
            "Runs",
            "SELECT ended_ts, run_id, mode, sessions, matched, no_event, mismatch, not_run,"
            f" connections, connections_unmatched {runs} ORDER BY ended_ts DESC LIMIT 200",
            desc="Every lab run and its join health.",
        ),
        24,
        8,
    )
    steps = "FROM mirage.sim_steps FINAL WHERE $__timeFilter(start_ts)"
    p.add(
        bars(
            "Steps by join state",
            f"SELECT state, count() AS n {steps} GROUP BY state ORDER BY n DESC",
        ),
        8,
        8,
    )
    p.add(
        pie(
            "Sessions by actor class",
            "SELECT actor_class, count() AS n FROM mirage.sim_sessions FINAL GROUP BY actor_class",
        ),
        8,
        8,
    )
    p.add(
        bars(
            "Steps by protocol",
            f"SELECT protocol, count() AS n {steps} GROUP BY protocol ORDER BY n DESC",
        ),
        8,
        8,
    )
    p.add(
        table(
            "Techniques exercised",
            "SELECT technique_id, tactic, count() AS steps,"
            f" countIf(state = 'matched') AS matched {steps} AND technique_id != ''"
            " GROUP BY technique_id, tactic ORDER BY steps DESC LIMIT 200",
            desc="Ground-truth techniques the lab has run, and how many joined.",
        ),
        24,
        8,
    )
    # Split sizes (spec 2.7): what the lab captured for each side of the frozen split. Ground
    # truth is the subject here, so the sim_* tables are the right source on this page.
    in_runs = f"run_id IN (SELECT run_id {runs})"
    p.add(
        table(
            "Split sizes",
            f"SELECT {split_of('scenario_id')} AS split, uniqExact(scenario_id) AS scenarios,"
            " uniqExact(run_id, session_ref) AS sessions, count() AS steps,"
            " countIf(state = 'matched') AS matched, uniqExact(procedure_id) AS procedures,"
            " uniqExactIf(technique_id, technique_id != '') AS techniques_seen"
            f" FROM mirage.sim_steps FINAL WHERE {in_runs} GROUP BY split ORDER BY {SPLIT_ORDER}",
            desc="Scenarios, simulated sessions and steps captured for each side of the frozen "
            "split (eval/split.yaml), from the final runs in the time range. 'unassigned' is a "
            "scenario the split does not list.",
        ),
        14,
        6,
    )
    p.add(
        table(
            "Sessions by split and actor class",
            f"SELECT {split_of('scenario_id')} AS split,"
            " uniqExactIf((run_id, session_ref), actor_class = 'scanner') AS scanner,"
            " uniqExactIf((run_id, session_ref), actor_class = 'scripted_bot') AS scripted_bot,"
            " uniqExactIf((run_id, session_ref), actor_class = 'human') AS human,"
            " uniqExact(run_id, session_ref) AS sessions"
            f" FROM mirage.sim_sessions FINAL WHERE {in_runs} GROUP BY split"
            f" ORDER BY {SPLIT_ORDER}",
            desc="The scenarios' own actor classes (ground truth), per side of the split.",
        ),
        10,
        6,
    )
    # The evaluation harness publishes its latest numbers; one row per dataset and metric.
    metrics = "FROM mirage.eval_metrics FINAL"
    p.add(
        stat(
            "Gates met",
            f"SELECT countIf(gate = 1) {metrics}",
            color="green",
            desc="Gate metrics of the latest evaluation that meet their threshold.",
        ),
        4,
        4,
    )
    p.add(
        stat(
            "Gates not met",
            f"SELECT countIf(gate = 0) {metrics}",
            color="red",
            desc="Gate metrics of the latest evaluation that miss their threshold.",
        ),
        4,
        4,
    )
    p.add(
        stat(
            "Last evaluation",
            f"SELECT toUnixTimestamp64Milli(published_at) {metrics}"
            " ORDER BY published_at DESC LIMIT 1",
            "dateTimeAsIso",
            "text",
            desc="When the evaluation harness last published.",
        ),
        16,
        4,
    )
    p.add(
        table(
            "Latest evaluation metrics and baselines",
            "SELECT m.dataset AS dataset, m.metric AS metric, round(m.value, 4) AS value,"
            " round(m.ci_low, 4) AS ci_low, round(m.ci_high, 4) AS ci_high,"
            " round(m.baseline, 4) AS baseline, round(m.value - m.baseline, 4) AS delta,"
            " multiIf(m.gate = 1, 'met', m.gate = 0, 'NOT MET', '') AS gate,"
            " m.detail AS detail, m.published_at AS published_at"
            " FROM mirage.eval_metrics AS m FINAL ORDER BY dataset, metric",
            [
                {
                    "matcher": {"id": "byName", "options": "gate"},
                    "properties": [
                        {
                            "id": "mappings",
                            "value": [
                                {
                                    "type": "value",
                                    "options": {
                                        "met": {"color": "green", "index": 0},
                                        "NOT MET": {"color": "red", "index": 1},
                                    },
                                }
                            ],
                        },
                        {"id": "custom.cellOptions", "value": {"type": "color-text"}},
                    ],
                }
            ],
            desc="Each metric beside the baseline it is compared with; ci_low and ci_high are "
            "its bootstrap interval, delta is value minus baseline. The gate column is empty "
            "for a metric that is reported but is not a gate. Not limited by the time range.",
        ),
        24,
        10,
    )
    return p


def alerts() -> Page:
    p = Page(
        "mirage-alerts",
        "MIRAGE · Alerts",
        "Sessions and actors worth an analyst's attention: a honeytoken reached, an artifact "
        "captured, or Persistence or Impact seen. The tactic heatmaps show what the tagger "
        "found, by day and by predicted actor class.",
    )
    a = "FROM mirage.alerts FINAL WHERE $__timeFilter(end_ts)"
    # notEmpty(reasons): an actor merged into another leaves a retired row with empty arrays
    # (compose/clickhouse/init.sql). Filtered in a subquery, before any column is renamed.
    aa = (
        "FROM (SELECT * FROM mirage.actor_alerts FINAL"
        " WHERE notEmpty(reasons) AND $__timeFilter(end_ts))"
    )
    lab = "FROM mirage.labels FINAL WHERE technique != '' AND $__timeFilter(ts)"
    p.add(stat("Alerts", f"SELECT count() {a}", color="red"), 6, 4)
    p.add(
        stat(
            "Honeytoken alerts", f"SELECT countIf(has(reasons, 'honeytoken')) {a}", color="orange"
        ),
        6,
        4,
    )
    p.add(stat("Impact alerts", f"SELECT countIf(has(reasons, 'impact')) {a}", color="red"), 6, 4)
    p.add(stat("Sessions labelled", "SELECT uniqExact(session_id) " + lab, color="blue"), 6, 4)
    p.add(
        table(
            "Actor alerts",
            "SELECT end_ts, actor_id, length(session_ids) AS sessions,"
            " arrayStringConcat(src_ips, ', ') AS src_ips,"
            " arrayStringConcat(protocols, ', ') AS protocols,"
            " arrayStringConcat(actor_classes, ', ') AS actor_classes,"
            " arrayStringConcat(reasons, ', ') AS reasons,"
            " arrayStringConcat(tactics, ', ') AS tactics,"
            " arrayStringConcat(techniques, ', ') AS techniques,"
            " arrayStringConcat(tokens, ', ') AS honeytokens, length(artifacts) AS n_artifacts,"
            # all_sessions, not session_ids: an alias with the column's name would be what
            # length() and [1] see, and they need the array.
            " inputs, session_ids[1] AS session_id,"
            " arrayStringConcat(session_ids, ', ') AS all_sessions, start_ts"
            f" {aa} ORDER BY end_ts DESC LIMIT 200",
            links(SESSION_LINK, ACTOR_LINK),
            desc="One row per actor: every session, address and predicted class the links "
            "group under it, so an attack that moves between addresses is one alert. "
            "session_id opens the actor's first session; actor_id opens the actor.",
        ),
        24,
        8,
    )
    p.add(
        table(
            "Recent alerts",
            "SELECT end_ts, session_id, src_ip, protocol, arrayStringConcat(reasons, ', ') AS reasons,"
            " arrayStringConcat(techniques, ', ') AS techniques, inputs"
            f" {a} ORDER BY end_ts DESC LIMIT 200",
            links(SESSION_LINK),
            desc="One row per session that triggered; newest first.",
        ),
        24,
        8,
    )
    p.add(
        pie(
            "Alerts by reason",
            f"SELECT arrayJoin(reasons) AS reason, count() AS n {a} GROUP BY reason",
        ),
        8,
        8,
    )
    p.add(
        heatmap(
            "Tactic heatmap: by day",
            # Every day of the range is a column for every tactic (WITH FILL), so a quiet day
            # is an empty cell, not a missing one; the day before the range pads the left
            # edge so there are always two columns to size a cell from. The outer ORDER BY
            # puts the rows back in time order, which the datasource needs to pivot them.
            "SELECT time, tactic, sessions FROM (SELECT toStartOfDay(t.day_ts) AS time,"
            " t.tactic AS tactic, uniqExact(t.lsid) AS sessions FROM ("
            "SELECT if(m.session_id != '', m.session_id, l.session_id) AS lsid,"
            " l.tactic AS tactic, l.ts AS day_ts"
            " FROM (SELECT session_id, tactic, ts FROM mirage.labels FINAL"
            " WHERE technique != '' AND $__timeFilter(ts)) AS l"
            f" LEFT JOIN {SESSION_MAP} AS m ON m.conn_id = l.session_id) AS t"
            " GROUP BY time, tactic ORDER BY tactic, time WITH FILL"
            " FROM toStartOfDay($__fromTime) - INTERVAL 1 DAY TO $__toTime STEP INTERVAL 1 DAY)"
            " ORDER BY time, tactic",
            row="tactic",
            desc="Sessions in which the tagger found each ATT&CK tactic, per day (UTC). "
            "Widen the time range to see more days.",
        ),
        16,
        8,
    )
    p.add(
        matrix(
            "Tactic heatmap: by predicted actor class",
            "SELECT t.tactic AS tactic,"
            " uniqExactIf(t.lsid, ac.cls = 'scanner') AS scanner,"
            " uniqExactIf(t.lsid, ac.cls = 'scripted_bot') AS scripted_bot,"
            " uniqExactIf(t.lsid, ac.cls = 'human') AS human,"
            " uniqExactIf(t.lsid, ac.cls NOT IN ('', 'scanner', 'scripted_bot', 'human'))"
            " AS other_class,"
            " uniqExactIf(t.lsid, ac.cls = '') AS not_classified"
            f" FROM ({tags('$__timeFilter(ts)')}) AS t"
            f" LEFT JOIN ({predicted_class('1')}) AS ac ON ac.lsid = t.lsid"
            " GROUP BY tactic ORDER BY tactic",
            row="tactic",
            desc="Sessions in which the tagger found each tactic, by the class the actor "
            "classifier predicted for the session. Both are model output (mirage.labels, "
            "mirage.actor_class), not the lab's ground truth.",
        ),
        24,
        9,
    )
    p.add(
        bars(
            "Top techniques",
            f"SELECT technique, count() AS labels {lab} GROUP BY technique ORDER BY labels DESC"
            " LIMIT 25",
        ),
        24,
        8,
    )
    return p


PAGES = [overview, sessions, session, actors, tokens, artifacts, policy, lab, alerts]


# ------------------------------------------------------------------------------ self-check

# Pages that show what the models said about real sessions. They may never read lab ground
# truth (docs/07-phase-2-completion.md, rule 1), and must read both models' output.
PREDICTION_PAGES = {"mirage-sessions", "mirage-session"}
# Tables whose rows are replaced by a newer version: a read without FINAL can count a row twice.
REPLACED = (
    "session_summary|session_map|labels|actor_class|alerts|actor_alerts|eval_metrics"
    "|sim_runs|sim_steps|sim_sessions"
)
# The variables tests/integration/test_dashboards.py knows how to fill in.
TEST_VARIABLES = {"session", "actor", "protocol", "src"}


def check(page: Page) -> None:
    """Refuse to write a page the integration test could not exercise or that breaks a rule
    the audit set. The test runs every target of every top-level panel; this keeps a panel
    from hiding where it does not look, and catches by reading what it would catch by running."""

    def fail(panel: dict[str, Any], why: str) -> None:
        raise SystemExit(f"{page.uid} / {panel.get('title') or panel['type']}: {why}")

    declared = {v["name"] for v in page.variables}
    for panel in page.panels:
        if "panels" in panel:
            fail(panel, "nested panels (a row) are not seen by the dashboard test")
        targets = panel.get("targets", [])
        if panel["type"] != "text" and not targets:
            fail(panel, "a panel without a query")
        for t in targets:
            sql = t.get("rawSql", "")
            if not sql.strip() or not t.get("refId"):
                fail(panel, "a target needs rawSql and a refId")
            used = set(re.findall(r"\$\{(\w+)\}", sql))
            if not used <= declared & TEST_VARIABLES:
                fail(
                    panel,
                    f"variables {sorted(used - (declared & TEST_VARIABLES))} are not "
                    "declared on the page, or the dashboard test cannot fill them in",
                )
            if page.uid in PREDICTION_PAGES and "sim_" in sql:
                fail(panel, "a sim_* table (lab ground truth) on a page of predictions")
            for m in re.finditer(rf"\bmirage\.({REPLACED})\b(?! (AS \w+ )?FINAL\b)", sql):
                fail(panel, f"mirage.{m.group(1)} is read without FINAL")
    if page.uid in PREDICTION_PAGES:
        everything = " ".join(t["rawSql"] for p in page.panels for t in p.get("targets", []))
        for needed in ("mirage.labels", "mirage.actor_class"):
            if needed not in everything:
                raise SystemExit(f"{page.uid}: shows nothing from {needed}")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    pages = [make() for make in PAGES]
    for page in pages:
        check(page)
    for page in pages:
        path = OUT / f"{page.uid}.json"
        path.write_text(json.dumps(page.json(), indent=1, ensure_ascii=False) + "\n")
        print(f"wrote {path.relative_to(OUT.parents[2])} ({len(page.panels)} panels)")


if __name__ == "__main__":
    main()
