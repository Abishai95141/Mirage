"""Tagger worker (spec 2.4 labelling, 2.7 alerts): ``events.normalised.>`` -> labels and alerts.

For each gated input in a batch it runs the technique rule engine and writes one row to
``mirage.labels``. Then, for every session the batch touched, it recomputes from ClickHouse:

* the **session-rule labels** (spec 2.4). A session rule sees the logical unit, not one
  connection: the session plus the same actor's earlier sessions that led up to it, so "several
  failed logins, then a success" is found although every SSH connection is its own session.
  The label lands on the session being summarised, which for a brute force is the one that
  succeeded;
* the **session alert** in ``mirage.alerts``, when the session reached a honeytoken, captured
  an artifact, or showed Persistence or Impact;
* the **actor alert** in ``mirage.actor_alerts``: one row per actor with any of those reasons
  across its sessions, naming every session and address the sessioniser linked to it.

Everything is recomputed, not appended, so a redelivered batch cannot double-count, and a
restart rebuilds from the same tables.

A batch cannot see what other services write afterwards: the sessioniser adds the
``token.triggered`` finding, the actor links and the session summary a moment later, straight
to ClickHouse. So a **reconciliation sweep** runs on a timer and repeats the recomputation for
the sessions that changed recently, a bounded number per sweep (:meth:`Tagger.sweep`).

The rule engine lives in ``mirage_schema`` so this worker and the policy service share it
without the intel package's heavy libraries. With only the benign starter rules it labels
discovery; the offensive rules land later, and the worker picks them up with no code change.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import nats
from nats.js.api import AckPolicy, ConsumerConfig

from mirage_pipeline.normaliser import CHUNK, ClickHouse, Settings, _retry, ensure_streams
from mirage_pipeline.rows import _ch_ts
from mirage_schema import MirageEvent
from mirage_schema.techniques import Engine

log = logging.getLogger("mirage.tagger")
HEALTH = Path("/tmp/mirage-tagger.alive")  # noqa: S108 container-private

PERSISTENCE, IMPACT = "TA0003", "TA0040"

UNIT_WINDOW_S = 3600.0  # how far back a session rule looks for the same actor's sessions
SWEEP_EVERY_S = 15.0
SWEEP_WINDOW_S = 300.0  # a change is reconciled if it is at most this old
SWEEP_LIMIT = 500  # changed sessions read per source per sweep
RETIRED_TS = "1970-01-01 00:00:00.000000"  # the time on a retired actor alert

# Aggregate a session's honeytokens and artifacts from its events (structural, no labels).
EVIDENCE_SQL = """
SELECT
    session_id,
    anyIf(src_ip, src_ip != '')                               AS src_ip,
    anyIf(protocol, protocol != '')                           AS protocol,
    countIf((source = 'cowrie' AND class = 'process_activity' AND action = 'command'
             AND outcome = 'unknown')
            OR (class = 'http_activity' AND action = 'request')
            OR (class = 'datastore_activity' AND action = 'query'))  AS inputs,
    countIf(class = 'authentication' AND action = 'login')    AS auth_attempts,
    countIf(class = 'authentication' AND action = 'login' AND outcome = 'success') AS auth_success,
    min(ts)                                                   AS start_ts,
    max(ts)                                                   AS end_ts,
    arraySort(groupUniqArrayIf(JSONExtractString(payload, 'token_id'),
        action = 'token_triggered'))                          AS tokens,
    arraySort(groupUniqArrayIf(JSONExtractString(payload, 'sha256'),
        class = 'file_activity'
        AND action IN ('download', 'upload', 'artifact_stored')
        AND JSONExtractString(payload, 'sha256') != ''))      AS artifacts
FROM mirage.events FINAL
WHERE session_id IN {ids:Array(String)} AND source != 'policy'
GROUP BY session_id
"""

LABELS_SQL = """
SELECT session_id,
       arraySort(groupUniqArray(tactic))    AS tactics,
       arraySort(groupUniqArray(technique)) AS techniques
FROM mirage.labels FINAL
WHERE session_id IN {ids:Array(String)} AND technique != ''
GROUP BY session_id
"""

# The sessioniser's row for each of these sessions. An HTTP connection has no row of its own:
# it is one of the `connections` of the logical session that holds it.
MEMBERS_SQL = """
SELECT session_id, actor_id, connections
FROM mirage.session_summary FINAL
WHERE session_id IN {ids:Array(String)} OR hasAny(connections, {ids:Array(String)})
"""

# Candidate earlier sessions for the session rules: the same actors', and, for a session the
# sessioniser has not summarised yet, the same source address's.
EARLIER_SQL = """
SELECT session_id, actor_id, src_ip, protocol, start_ts, end_ts, inputs, auth_attempts,
       auth_success, connections
FROM mirage.session_summary FINAL
WHERE (has({actors:Array(String)}, actor_id) OR has({ips:Array(String)}, src_ip))
  AND end_ts >= parseDateTime64BestEffort({lo:String}, 6, 'UTC')
"""

ACTOR_SESSIONS_SQL = """
SELECT session_id, actor_id, src_ip, protocol, start_ts, end_ts, inputs, tokens, artifacts,
       connections
FROM mirage.session_summary FINAL
WHERE actor_id IN {actors:Array(String)}
"""

# The classifier's predictions (spec 2.3). Never a sim_* table: those hold ground truth.
ACTOR_CLASS_SQL = """
SELECT session_id, actor_class
FROM mirage.actor_class FINAL
WHERE session_id IN {ids:Array(String)}
"""

# Live actor alerts that name any of these actors or sessions. One whose actor no longer owns
# its sessions (two actors were linked into one) is retired by the next write.
ACTOR_ALERTS_SQL = """
SELECT actor_id, session_ids
FROM mirage.actor_alerts FINAL
WHERE (has({actors:Array(String)}, actor_id) OR hasAny(session_ids, {ids:Array(String)}))
  AND notEmpty(reasons)
"""

# What changed recently, newest first, for the sweep. The sessioniser stamps a summary with
# time.time_ns() whenever a session gets an event, a token, an artifact or an actor link.
CHANGED_SUMMARIES_SQL = """
SELECT session_id, connections, version
FROM mirage.session_summary FINAL
WHERE version > {after:UInt64}
ORDER BY version DESC
LIMIT {limit:UInt32}
"""

# token.triggered findings: the one kind of event written after its batch was published.
CHANGED_FINDINGS_SQL = """
SELECT session_id, max(ingest_ts) AS changed
FROM mirage.events FINAL
WHERE source = 'pipeline' AND action = 'token_triggered' AND session_id != ''
  AND ingest_ts > parseDateTime64BestEffort({after:String}, 6, 'UTC')
GROUP BY session_id
ORDER BY changed DESC
LIMIT {limit:UInt32}
"""

# Labels another writer added. Session-rule labels are left out: the sweep writes those
# itself, and reading them back would make every sweep trigger the next.
CHANGED_LABELS_SQL = """
SELECT session_id, max(version) AS changed
FROM mirage.labels FINAL
WHERE version > {after:UInt64} AND kind != 'session' AND session_id != ''
GROUP BY session_id
ORDER BY changed DESC
LIMIT {limit:UInt32}
"""


# Predictions the classifier worker wrote (it stamps `ts` when it writes one). They arrive
# after the summary they were computed from, so an actor alert built earlier lacks them.
CHANGED_CLASSES_SQL = """
SELECT session_id, max(ts) AS changed
FROM mirage.actor_class FINAL
WHERE ts > parseDateTime64BestEffort({after:String}, 6, 'UTC') AND session_id != ''
GROUP BY session_id
ORDER BY changed DESC
LIMIT {limit:UInt32}
"""


@dataclass
class Config:
    base: Settings
    rules_dir: Path
    attack_version: str
    unit_window_s: float = UNIT_WINDOW_S
    sweep_every_s: float = SWEEP_EVERY_S
    sweep_window_s: float = SWEEP_WINDOW_S
    sweep_limit: int = SWEEP_LIMIT
    # Whether the rules label single inputs. Off when the tagger experiment found the rules
    # in front of the learned layer made it worse (eval/choices.yaml): the model worker then
    # writes input labels alone. Session rules and alerts run either way.
    input_rules: bool = True

    @classmethod
    def from_env(cls) -> Config:
        env = os.environ
        return cls(
            base=Settings.from_env(),
            rules_dir=Path(env.get("TECHNIQUE_RULES", "/rules")),
            attack_version=env.get("ATTACK_VERSION", "20.1"),
            unit_window_s=float(env.get("TAGGER_UNIT_WINDOW_S", UNIT_WINDOW_S)),
            sweep_every_s=float(env.get("TAGGER_SWEEP_EVERY_S", SWEEP_EVERY_S)),
            sweep_window_s=float(env.get("TAGGER_SWEEP_WINDOW_S", SWEEP_WINDOW_S)),
            sweep_limit=int(env.get("TAGGER_SWEEP_LIMIT", SWEEP_LIMIT)),
            input_rules=env.get("TAGGER_INPUT_RULES", "on").lower() not in ("off", "0", "false"),
        )


def _dt(value: str) -> datetime:
    """A ClickHouse DateTime64 string as an aware datetime."""
    return datetime.fromisoformat(value.replace(" ", "T")).replace(tzinfo=UTC)


def decision_text(ev: MirageEvent) -> str | None:
    """The input a gate decision was made on: the executed command (cowrie) or the canonical
    input (http/redis/mysql). None when this event is not a gate decision."""
    if ev.event_class.value != "policy_decision" or ev.source.value == "policy":
        return None
    payload = ev.payload
    return payload.get("command") or payload.get("input") or ""


def alert_reasons(tactics: list[str], tokens: list[str], artifacts: list[str]) -> list[str]:
    reasons = []
    if tokens:
        reasons.append("honeytoken")
    if artifacts:
        reasons.append("artifact")
    if PERSISTENCE in tactics:
        reasons.append("persistence")
    if IMPACT in tactics:
        reasons.append("impact")
    return reasons


def actor_alert(
    actor_id: str,
    sessions: list[dict[str, Any]],
    labelled: dict[str, Any],
    classes: dict[str, set[str]],
    version: int,
) -> dict[str, Any] | None:
    """One actor's alert from its sessions' summaries, or None when nothing about the actor is
    worth an alert. Every array is sorted and distinct."""
    # Labels and predictions are keyed by the decoy's session ID, which for HTTP is the
    # connection, so look under the logical session and under each of its connections.
    ids = {i for s in sessions for i in (s["session_id"], *s["connections"])}
    tactics = sorted({t for i in ids for t in labelled.get(i, {}).get("tactics", []) if t})
    techniques = sorted({t for i in ids for t in labelled.get(i, {}).get("techniques", []) if t})
    tokens = sorted({t for s in sessions for t in s["tokens"] if t})
    artifacts = sorted({a for s in sessions for a in s["artifacts"] if a})
    reasons = sorted(alert_reasons(tactics, tokens, artifacts))
    if not reasons:
        return None
    return {
        "actor_id": actor_id,
        "version": version,
        "session_ids": sorted({s["session_id"] for s in sessions}),
        "src_ips": sorted({s["src_ip"] for s in sessions if s["src_ip"]}),
        "protocols": sorted({s["protocol"] for s in sessions if s["protocol"]}),
        "actor_classes": sorted({c for i in ids for c in classes.get(i, ()) if c}),
        "reasons": reasons,
        "tactics": tactics,
        "techniques": techniques,
        "tokens": tokens,
        "artifacts": artifacts,
        "inputs": sum(int(s["inputs"]) for s in sessions),
        "start_ts": _ch_ts(min(_dt(s["start_ts"]) for s in sessions)),
        "end_ts": _ch_ts(max(_dt(s["end_ts"]) for s in sessions)),
    }


def retired_actor_alert(actor_id: str, version: int) -> dict[str, Any]:
    """The row that replaces an actor's alert when the actor no longer has one: its sessions
    were linked into another actor, whose row now names them. The table has no deletes, so the
    newest version of the old row is emptied; readers keep rows with ``notEmpty(reasons)``."""
    empty: dict[str, Any] = {
        k: []
        for k in (
            "session_ids",
            "src_ips",
            "protocols",
            "actor_classes",
            "reasons",
            "tactics",
            "techniques",
            "tokens",
            "artifacts",
        )
    }
    return {
        "actor_id": actor_id,
        "version": version,
        **empty,
        "inputs": 0,
        "start_ts": RETIRED_TS,
        "end_ts": RETIRED_TS,
    }


class Tagger:
    def __init__(
        self,
        engine: Engine,
        ch: ClickHouse,
        attack_version: str,
        *,
        unit_window_s: float = UNIT_WINDOW_S,
        sweep_window_s: float = SWEEP_WINDOW_S,
        sweep_limit: int = SWEEP_LIMIT,
        input_rules: bool = True,
    ) -> None:
        self.input_rules = input_rules
        self.engine = engine
        self.ch = ch
        self.attack_version = attack_version
        self.unit_window = timedelta(seconds=unit_window_s)
        self.sweep_window = timedelta(seconds=sweep_window_s)
        self.sweep_limit = sweep_limit
        # Changes already reconciled, so a change is recomputed once although every sweep
        # reads the whole window again: (source, session, marker) -> when it was handled.
        self._reconciled: dict[tuple[str, str, str], datetime] = {}

    def labels(self, events: list[MirageEvent], version: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        if not self.input_rules:
            return rows
        for ev in events:
            text = decision_text(ev)
            if text is None:
                continue
            hit = self.engine.best(ev.protocol or "any", text)
            if hit is None:
                continue
            rows.append(
                {
                    "event_id": ev.event_id,
                    "version": version,
                    "session_id": ev.session_id or "",
                    "protocol": ev.protocol or "",
                    "kind": "input",
                    "technique": hit.technique,
                    "tactic": hit.tactic,
                    "confidence": hit.confidence,
                    "rule_id": hit.rule_id,
                    "model_version": self.engine.version,
                    "attack_version": self.attack_version,
                    "ts": _ch_ts(ev.ts),
                }
            )
        return rows

    @staticmethod
    def touched(events: list[MirageEvent]) -> set[str]:
        return {ev.session_id for ev in events if ev.session_id}

    async def write_labels(self, rows: list[dict[str, Any]]) -> None:
        await self.ch.insert(rows, "mirage.labels")

    async def _select(
        self, sql: str, ids: Sequence[str], name: str = "ids"
    ) -> list[dict[str, Any]]:
        """A query over a list of IDs (its ``name`` parameter), a bounded number at a time."""
        rows: list[dict[str, Any]] = []
        for i in range(0, len(ids), CHUNK):
            rows += await self.ch.select(sql, **{name: list(ids[i : i + CHUNK])})
        return rows

    # ------------------------------------------------------------------ session rules

    @staticmethod
    def _summary(ev: dict[str, Any], earlier: Iterable[dict[str, Any]] = ()) -> dict[str, int]:
        """The structural summary a SessionRule matches on, over the logical unit: this
        session and the earlier sessions of its actor that led up to it (:meth:`earlier`).
        ``failed_before_success`` is therefore the actor's failed logins before this session's
        success, across connections; without a success it is the failed logins so far."""
        unit = [ev, *earlier]
        attempts = sum(int(s.get("auth_attempts", 0)) for s in unit)
        success = sum(int(s.get("auth_success", 0)) for s in unit)
        return {
            "inputs": sum(int(s.get("inputs", 0)) for s in unit),
            "auth_attempts": attempts,
            "auth_success": success,
            "failed_before_success": max(attempts - success, 0),
        }

    async def members(self, ids: Sequence[str]) -> list[dict[str, Any]]:
        """The sessioniser's rows for these sessions; they carry each session's actor."""
        seen: dict[str, dict[str, Any]] = {}
        for row in await self._select(MEMBERS_SQL, ids):
            seen[row["session_id"]] = row
        return list(seen.values())

    async def earlier(
        self, evidence: dict[str, Any], members: list[dict[str, Any]]
    ) -> dict[str, list[dict[str, Any]]]:
        """For each session in ``evidence``, the sessions that belong in its logical unit: the
        same actor's sessions (``session_summary.actor_id``; the same source address while the
        sessioniser has not summarised the session yet) on the same protocol that began before
        it, were still going inside the window before it, and came after that actor's previous
        successful login. An earlier success closes its own unit, so its failures are not
        counted against the next login."""
        if not self.engine.session_rules:
            return {}
        row_of = {i: m for m in members for i in (m["session_id"], *m["connections"])}
        actors: set[str] = set()
        ips: set[str] = set()
        starts = {sid: _dt(ev["start_ts"]) for sid, ev in evidence.items() if ev.get("start_ts")}
        for sid in starts:
            actor = row_of.get(sid, {}).get("actor_id")
            if actor:
                actors.add(actor)
            elif evidence[sid].get("src_ip"):
                ips.add(evidence[sid]["src_ip"])
        if not actors and not ips:
            return {}
        candidates = await self.ch.select(
            EARLIER_SQL,
            actors=sorted(actors),
            ips=sorted(ips),
            lo=_ch_ts(min(starts.values()) - self.unit_window),
        )
        out: dict[str, list[dict[str, Any]]] = {}
        for sid, start in starts.items():
            ev = evidence[sid]
            actor = row_of.get(sid, {}).get("actor_id")
            before = []
            for c in candidates:
                if c["session_id"] == sid or sid in c["connections"]:
                    continue  # the session itself, or the logical session that holds it
                if c["protocol"] != ev.get("protocol"):
                    continue
                same = c["actor_id"] == actor if actor else c["src_ip"] == ev.get("src_ip")
                began, ended = _dt(c["start_ts"]), _dt(c["end_ts"])
                if same and began < start and ended >= start - self.unit_window:
                    before.append((began, c))
            unit = []
            for _, c in sorted(before, key=lambda pair: pair[0], reverse=True):
                if int(c["auth_success"]):
                    break
                unit.append(c)
            if unit:
                out[sid] = unit
        return out

    def session_labels(
        self,
        evidence: dict[str, Any],
        version: int,
        earlier: dict[str, list[dict[str, Any]]] | None = None,
    ) -> list[dict[str, Any]]:
        """Apply the session-level rules to each session's structural summary (spec 2.4). These
        catch what no single input shows -- e.g. several failed logins, then a success. With
        ``earlier`` (from :meth:`earlier`) the summary covers the session's logical unit."""
        rows = []
        for sid, ev in evidence.items():
            for hit in self.engine.tag_session(self._summary(ev, (earlier or {}).get(sid, ()))):
                rows.append(
                    {
                        "event_id": f"session:{sid}:{hit.rule_id}",
                        "version": version,
                        "session_id": sid,
                        "protocol": ev.get("protocol", ""),
                        "kind": "session",
                        "technique": hit.technique,
                        "tactic": hit.tactic,
                        "confidence": hit.confidence,
                        "rule_id": hit.rule_id,
                        "model_version": self.engine.version,
                        "attack_version": self.attack_version,
                        "ts": ev["end_ts"],
                    }
                )
        return rows

    # ------------------------------------------------------------------ session alerts

    def alert_rows(
        self, ids: list[str], evidence: dict[str, Any], labelled: dict[str, Any], version: int
    ) -> list[dict[str, Any]]:
        out = []
        for sid in ids:
            ev = evidence.get(sid)
            if ev is None:
                continue
            lab = labelled.get(sid, {})
            tactics = lab.get("tactics", [])
            reasons = alert_reasons(tactics, ev["tokens"], ev["artifacts"])
            if not reasons:
                continue
            out.append(
                {
                    "session_id": sid,
                    "version": version,
                    "src_ip": ev["src_ip"],
                    "protocol": ev["protocol"],
                    "reasons": reasons,
                    "tactics": tactics,
                    "techniques": lab.get("techniques", []),
                    "tokens": ev["tokens"],
                    "artifacts": ev["artifacts"],
                    "inputs": int(ev["inputs"]),
                    "start_ts": ev["start_ts"],
                    "end_ts": ev["end_ts"],
                }
            )
        return out

    async def alerts(self, session_ids: set[str], version: int) -> list[dict[str, Any]]:
        """Fetch the evidence and labels for these sessions and return their alert rows."""
        if not session_ids:
            return []
        ids = sorted(session_ids)
        evidence = {r["session_id"]: r for r in await self.ch.select(EVIDENCE_SQL, ids=ids)}
        labelled = {r["session_id"]: r for r in await self.ch.select(LABELS_SQL, ids=ids)}
        return self.alert_rows(ids, evidence, labelled, version)

    # ------------------------------------------------------------------ actor alerts

    async def actor_alerts(self, actor_ids: Iterable[str], version: int) -> list[dict[str, Any]]:
        """The ``mirage.actor_alerts`` rows for these actors, recomputed from the sessioniser's
        summaries, the labels and the classifier's predictions: one row per actor with an alert
        reason, and an emptied row for any earlier alert these sessions have outgrown."""
        actors = sorted({a for a in actor_ids if a})
        if not actors:
            return []
        sessions = await self._select(ACTOR_SESSIONS_SQL, actors, "actors")
        existing: set[str] = set()
        for i in range(0, max(len(sessions), 1), CHUNK):
            rows = await self.ch.select(
                ACTOR_ALERTS_SQL,
                actors=actors,
                ids=[s["session_id"] for s in sessions[i : i + CHUNK]],
            )
            existing |= {r["actor_id"] for r in rows}
        # An alert under another actor's ID names sessions that are now these actors': the
        # sessioniser linked the two. Recompute that actor too; if it is gone, retire its row.
        moved = sorted(existing - set(actors))
        if moved:
            sessions += await self._select(ACTOR_SESSIONS_SQL, moved, "actors")
        ids = sorted({i for s in sessions for i in (s["session_id"], *s["connections"])})
        labelled = {r["session_id"]: r for r in await self._select(LABELS_SQL, ids)}
        classes: dict[str, set[str]] = {}
        for r in await self._select(ACTOR_CLASS_SQL, ids):
            classes.setdefault(r["session_id"], set()).add(r["actor_class"])
        by_actor: dict[str, list[dict[str, Any]]] = {}
        for s in sessions:
            by_actor.setdefault(s["actor_id"], []).append(s)
        out = []
        for actor in [*actors, *moved]:
            row = actor_alert(actor, by_actor.get(actor, []), labelled, classes, version)
            if row is not None:
                out.append(row)
            elif actor in existing:
                out.append(retired_actor_alert(actor, version))
        return out

    # ------------------------------------------------------------------ batches and sweeps

    async def ready(self) -> None:
        """Fail now, with the table's name, if the store predates ``mirage.actor_alerts``
        (``make migrate`` adds it) -- not later, once per batch."""
        await self.ch.select("SELECT actor_id FROM mirage.actor_alerts FINAL LIMIT 1")

    async def recompute(
        self, ids: Sequence[str], version: int, also: Sequence[str] = ()
    ) -> tuple[int, int, int]:
        """Everything derived for these sessions, read back from ClickHouse and written again:
        session-rule labels, session alerts, and the alerts of the actors the sessions belong
        to. ``also`` names sessions whose actor is recomputed without the per-session part.
        Returns the number of rows written to each of the three."""
        ids = sorted(set(ids))
        if not ids and not also:
            return 0, 0, 0
        evidence = {r["session_id"]: r for r in await self._select(EVIDENCE_SQL, ids)}
        members = await self.members(sorted({*ids, *also}))
        # Session-level labels must land before alerts, which reads tactics back from the table.
        session_rows = self.session_labels(evidence, version, await self.earlier(evidence, members))
        await self.write_labels(session_rows)
        labelled = {r["session_id"]: r for r in await self._select(LABELS_SQL, ids)}
        alert_rows = self.alert_rows(ids, evidence, labelled, version)
        await self.ch.insert(alert_rows, "mirage.alerts")
        actor_rows = await self.actor_alerts({m["actor_id"] for m in members}, version)
        await self.ch.insert(actor_rows, "mirage.actor_alerts")
        return len(session_rows), len(alert_rows), len(actor_rows)

    async def process(self, events: list[MirageEvent]) -> tuple[int, int]:
        version = time.time_ns() // 1000
        input_rows = self.labels(events, version)
        await self.write_labels(input_rows)
        n_session, n_alerts, _ = await self.recompute(sorted(self.touched(events)), version)
        # These labels were just taken into account; the sweep need not come back for them.
        now = datetime.now(UTC)
        for row in input_rows:
            self._reconciled["label", row["session_id"], str(version)] = now
        return len(input_rows) + n_session, n_alerts

    async def sweep(self, now: datetime | None = None) -> tuple[int, int, int]:
        """Reconcile what changed outside a batch (the honeytoken race): recompute labels and
        alerts for the sessions that, within the window, got a ``token.triggered`` finding, a
        new summary from the sessioniser (new events, tokens, artifacts or actor links), a
        label from another writer, or a predicted class. Each source is read newest first and
        capped, so a sweep is bounded; a change is recomputed once. Returns (sessions, session
        alerts, actor alerts)."""
        now = now or datetime.now(UTC)
        since = now - self.sweep_window
        since_us = int(since.timestamp() * 1_000_000)
        limit = self.sweep_limit
        summaries = await self.ch.select(CHANGED_SUMMARIES_SQL, after=since_us * 1000, limit=limit)
        findings = await self.ch.select(CHANGED_FINDINGS_SQL, after=_ch_ts(since), limit=limit)
        labels = await self.ch.select(CHANGED_LABELS_SQL, after=since_us, limit=limit)
        classes = await self.ch.select(CHANGED_CLASSES_SQL, after=_ch_ts(since), limit=limit)
        for what, rows in (
            ("summaries", summaries),
            ("findings", findings),
            ("labels", labels),
            ("predicted classes", classes),
        ):
            if len(rows) >= limit:
                log.warning(
                    "sweep: %d or more changed %s in %.0f s; the oldest are not reconciled",
                    limit,
                    what,
                    self.sweep_window.total_seconds(),
                )
        fresh: list[tuple[str, str, str]] = []
        ids: set[str] = set()  # sessions (connections) to recompute in full
        also: set[str] = set()  # logical sessions whose actor alone is recomputed
        for row in summaries:
            key = ("summary", row["session_id"], str(row["version"]))
            if key in self._reconciled:
                continue
            fresh.append(key)
            also.add(row["session_id"])
            # Past the cap (a logical session with very many connections, such as a long HTTP
            # scan) only the actor is recomputed. A connection's own alert changes with its
            # events, which its batch saw, or with a finding, which the findings query returns.
            if len(ids) + len(row["connections"]) <= limit:
                ids.update(row["connections"])
        for what, rows in (("finding", findings), ("label", labels)):
            for row in rows:
                key = (what, row["session_id"], str(row["changed"]))
                if key not in self._reconciled:
                    fresh.append(key)
                    ids.add(row["session_id"])
        for row in classes:  # a prediction changes the actor's alert, nothing per session
            key = ("class", row["session_id"], str(row["changed"]))
            if key not in self._reconciled:
                fresh.append(key)
                also.add(row["session_id"])
        result = (0, 0, 0)
        if fresh:
            version = time.time_ns() // 1000
            _, n_alerts, n_actor = await self.recompute(sorted(ids), version, sorted(also))
            result = (len(ids | also), n_alerts, n_actor)
            for key in fresh:  # only now: a failed sweep is repeated in full
                self._reconciled[key] = now
        # A change leaves the queries once it is older than the window; forget it then.
        self._reconciled = {
            k: at for k, at in self._reconciled.items() if now - at <= self.sweep_window
        }
        return result


async def run(cfg: Config, stop: asyncio.Event) -> None:
    s = cfg.base
    nc = await _retry("NATS", lambda: nats.connect(s.nats_url, max_reconnect_attempts=-1))
    js = nc.jetstream()
    await ensure_streams(js)
    ch = ClickHouse(s)
    await _retry("ClickHouse", ch.ping)
    engine = Engine.load(cfg.rules_dir) if cfg.rules_dir.is_dir() else Engine([], [])
    tagger = Tagger(
        engine,
        ch,
        cfg.attack_version,
        unit_window_s=cfg.unit_window_s,
        sweep_window_s=cfg.sweep_window_s,
        sweep_limit=cfg.sweep_limit,
        input_rules=cfg.input_rules,
    )
    await _retry("ClickHouse tables", tagger.ready)
    sub = await js.pull_subscribe(
        "events.normalised.>",
        durable="tagger-v1",
        stream="EVENTS",
        config=ConsumerConfig(ack_policy=AckPolicy.EXPLICIT, ack_wait=60, max_deliver=-1),
    )
    log.info(
        "tagger running with %d rules and %d session rules (%s); sweep every %.0f s",
        len(engine.rules),
        len(engine.session_rules),
        engine.version,
        cfg.sweep_every_s,
    )
    backoff = 1.0
    swept = float("-inf")
    while not stop.is_set():
        HEALTH.touch()
        # Before the fetch, so it also runs while no events arrive: the session whose last
        # event triggered a honeytoken is exactly the one no later batch will touch.
        if time.monotonic() - swept >= cfg.sweep_every_s:
            swept = time.monotonic()
            try:
                n_sessions, n_alerts, n_actor = await tagger.sweep()
            except Exception:
                log.exception("reconciliation sweep failed; will be repeated")
            else:
                if n_sessions:
                    log.info(
                        "sweep: %d sessions, %d alerts, %d actor alerts",
                        n_sessions,
                        n_alerts,
                        n_actor,
                    )
        try:
            msgs = await sub.fetch(s.batch_size, timeout=s.batch_wait_s)
        except TimeoutError:
            continue
        events = []
        for m in msgs:
            try:
                events.append(MirageEvent.model_validate_json(m.data))
            except ValueError:
                log.warning("skipping an event that does not validate")
        try:
            n_labels, n_alerts = await tagger.process(events)
        except Exception:
            log.exception("batch of %d failed; will be redelivered", len(msgs))
            for m in msgs:
                await m.nak(delay=backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)
            continue
        backoff = 1.0
        for m in msgs:
            await m.ack()
        if n_labels or n_alerts:
            log.info("batch: %d events, %d labels, %d alerts", len(events), n_labels, n_alerts)
    await ch.close()
    await nc.drain()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.Formatter.converter = time.gmtime
    logging.getLogger("httpx").setLevel(logging.WARNING)
    stop = asyncio.Event()

    async def _main() -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        await run(Config.from_env(), stop)

    asyncio.run(_main())


def healthcheck() -> None:
    raise SystemExit(0 if HEALTH.exists() and time.time() - HEALTH.stat().st_mtime < 30 else 1)


if __name__ == "__main__":
    main()
