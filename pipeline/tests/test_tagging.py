"""The tagger worker: labelling decisions, raising session and actor alerts, and reconciling
what other services write after a batch. Fake ClickHouse, synthetic events."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from mirage_pipeline import tagging
from mirage_pipeline.rows import _ch_ts
from mirage_pipeline.tagging import Tagger, alert_reasons, decision_text
from mirage_schema import EventClass, MirageEvent, Source
from mirage_schema.techniques import Engine

NOW = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)
RULES = {
    "rules": [
        {
            "id": "disc-uname",
            "technique": "T1082",
            "tactic": "TA0007",
            "protocol": "ssh",
            "confidence": 0.9,
            "any_of": [r"\buname\b"],
        },
        {
            "id": "persist-cron",
            "technique": "T1053.003",
            "tactic": "TA0003",
            "protocol": "ssh",
            "confidence": 0.9,
            "any_of": [r"\bcrontab\b"],
        },
    ]
}


def engine(tmp_path: Path) -> Engine:
    (tmp_path / "r.yaml").write_text(yaml.safe_dump(RULES))
    return Engine.load(tmp_path)


def decision(text: str, session="s1", protocol="ssh", eid="e1") -> MirageEvent:
    return MirageEvent(
        event_id=eid,
        ts=NOW,
        ingest_ts=NOW,
        source=Source.COWRIE,
        event_class=EventClass.POLICY_DECISION,
        action="decide",
        session_id=session,
        protocol=protocol,
        payload={"command": text},
    )


class FakeCH:
    """Records inserts and answers the tagger's queries from small tables: the one named in the
    SQL, filtered the way the query's parameters say. What the tagger writes it reads back
    (labels, actor alerts), so a test sees the same thing the next query would."""

    def __init__(self, evidence=None, labels=None, *, summaries=None, classes=None) -> None:
        self.inserted: dict[str, list] = {}
        self.asked: list[tuple[str, dict]] = []
        self.fail_inserts = 0  # the next N inserts raise
        self._evidence = evidence or {}  # mirage.events, aggregated: session -> EVIDENCE row
        self._labels = labels or {}  # mirage.labels, aggregated: session -> LABELS row
        self.summaries = summaries or {}  # mirage.session_summary: session -> row
        self.classes = classes or {}  # mirage.actor_class: session -> predicted class
        self.findings: dict[str, str] = {}  # session -> ingest_ts of its token.triggered finding
        self.classified: dict[str, str] = {}  # session -> ts of its prediction in actor_class

    async def insert(self, rows, table):
        if rows and self.fail_inserts:
            self.fail_inserts -= 1
            raise RuntimeError("ClickHouse insert failed")
        self.inserted.setdefault(table, []).extend(rows)

    async def select(self, sql, **p):
        table = re.search(r"FROM (mirage\.\w+) FINAL", sql).group(1)  # every read is FINAL
        self.asked.append((table, p))
        if table == "mirage.actor_alerts":
            latest = {r["actor_id"]: r for r in self.inserted.get(table, [])}
            return [
                {"actor_id": r["actor_id"], "session_ids": r["session_ids"]}
                for r in latest.values()
                if r["reasons"]
                and (r["actor_id"] in p["actors"] or set(r["session_ids"]) & set(p["ids"]))
            ]
        if table == "mirage.actor_class":
            if "after" in p:  # CHANGED_CLASSES_SQL
                found = [(sid, ts) for sid, ts in self.classified.items() if ts > p["after"]]
                newest = sorted(found, key=lambda kv: kv[1], reverse=True)[: p["limit"]]
                return [{"session_id": sid, "changed": ts} for sid, ts in newest]
            return [
                {"session_id": i, "actor_class": self.classes[i]}
                for i in p["ids"]
                if i in self.classes
            ]
        if table == "mirage.session_summary":
            rows = list(self.summaries.values())
            if "after" in p:  # CHANGED_SUMMARIES_SQL
                rows = [r for r in rows if int(r["version"]) > p["after"]]
                return sorted(rows, key=lambda r: -int(r["version"]))[: p["limit"]]
            if "lo" in p:  # EARLIER_SQL
                return [
                    r
                    for r in rows
                    if (r["actor_id"] in p["actors"] or r["src_ip"] in p["ips"])
                    and r["end_ts"] >= p["lo"]
                ]
            if "actors" in p:  # ACTOR_SESSIONS_SQL
                return [r for r in rows if r["actor_id"] in p["actors"]]
            ids = set(p["ids"])  # MEMBERS_SQL
            return [r for r in rows if r["session_id"] in ids or ids & set(r["connections"])]
        if table == "mirage.labels":
            written = [r for r in self.inserted.get(table, []) if r["technique"]]
            if "after" in p:  # CHANGED_LABELS_SQL
                changed: dict[str, int] = {}
                for r in written:
                    if r["kind"] != "session" and r["version"] > p["after"]:
                        changed[r["session_id"]] = max(
                            r["version"], changed.get(r["session_id"], 0)
                        )
                newest = sorted(changed.items(), key=lambda kv: -kv[1])[: p["limit"]]
                return [{"session_id": sid, "changed": str(v)} for sid, v in newest]
            out = []
            for i in p["ids"]:  # LABELS_SQL
                canned = self._labels.get(i, {})
                mine = [r for r in written if r["session_id"] == i]
                tactics = sorted({*canned.get("tactics", []), *(r["tactic"] for r in mine)})
                techniques = sorted(
                    {*canned.get("techniques", []), *(r["technique"] for r in mine)}
                )
                if tactics or techniques:
                    out.append({"session_id": i, "tactics": tactics, "techniques": techniques})
            return out
        assert table == "mirage.events"
        if "after" in p:  # CHANGED_FINDINGS_SQL
            found = [(sid, ts) for sid, ts in self.findings.items() if ts > p["after"]]
            newest = sorted(found, key=lambda kv: kv[1], reverse=True)[: p["limit"]]
            return [{"session_id": sid, "changed": ts} for sid, ts in newest]
        return [self._evidence[i] for i in p["ids"] if i in self._evidence]  # EVIDENCE_SQL

    def last(self, table: str, key: str) -> dict[str, dict]:
        """The table as FINAL would show it: the newest row for each key."""
        return {r[key]: r for r in self.inserted.get(table, [])}


def test_decision_text_only_for_gate_decisions():
    assert decision_text(decision("uname -a")) == "uname -a"
    http = MirageEvent(
        event_id="e",
        ts=NOW,
        ingest_ts=NOW,
        source=Source.HTTP_DECOY,
        event_class=EventClass.POLICY_DECISION,
        action="decide",
        protocol="http",
        payload={"input": "GET /.env"},
    )
    assert decision_text(http) == "GET /.env"
    not_a_decision = MirageEvent(
        event_id="e",
        ts=NOW,
        ingest_ts=NOW,
        source=Source.COWRIE,
        event_class=EventClass.PROCESS_ACTIVITY,
        action="command",
        payload={"command": "uname -a"},
    )
    assert decision_text(not_a_decision) is None
    # the policy service's own copy is not re-labelled
    svc = MirageEvent(
        event_id="e",
        ts=NOW,
        ingest_ts=NOW,
        source=Source.POLICY,
        event_class=EventClass.POLICY_DECISION,
        action="decide",
        payload={"command": "uname -a"},
    )
    assert decision_text(svc) is None


def test_labels_are_written_for_recognised_inputs(tmp_path):
    t = Tagger(engine(tmp_path), FakeCH(), "20.1")
    rows = t.labels(
        [
            decision("uname -a", eid="a"),
            decision("echo hi", eid="b"),
            decision("crontab -e", eid="c"),
        ],
        version=10,
    )
    by_tech = {r["technique"]: r for r in rows}
    assert set(by_tech) == {"T1082", "T1053.003"}  # echo abstains
    assert by_tech["T1082"]["event_id"] == "a" and by_tech["T1082"]["rule_id"] == "disc-uname"
    assert by_tech["T1082"]["model_version"].startswith("rules-")
    assert by_tech["T1082"]["attack_version"] == "20.1"


def test_the_rules_can_be_stopped_from_labelling_single_inputs(tmp_path, monkeypatch):
    # When the tagger experiment drops the rule layer, the model worker labels inputs alone;
    # this worker still writes session labels and alerts from whatever labels exist.
    t = Tagger(engine(tmp_path), FakeCH(), "20.1", input_rules=False)
    assert t.labels([decision("uname -a", eid="a")], version=10) == []
    from mirage_pipeline.tagging import Config

    for name in ("NATS_URL", "CLICKHOUSE_URL", "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD"):
        monkeypatch.setenv(name, "x")
    assert Config.from_env().input_rules is True  # the default is unchanged
    monkeypatch.setenv("TAGGER_INPUT_RULES", "off")
    assert Config.from_env().input_rules is False


def test_alert_reasons():
    assert alert_reasons([], ["tok1"], []) == ["honeytoken"]
    assert alert_reasons([], [], ["sha"]) == ["artifact"]
    assert alert_reasons(["TA0003"], [], []) == ["persistence"]
    assert alert_reasons(["TA0040", "TA0007"], [], []) == ["impact"]
    assert alert_reasons(["TA0007"], [], []) == []  # discovery alone is not an alert
    assert alert_reasons(["TA0003", "TA0040"], ["t"], ["s"]) == [
        "honeytoken",
        "artifact",
        "persistence",
        "impact",
    ]


async def test_alerts_fire_only_for_triggering_sessions(tmp_path):
    evidence = {
        "s1": {
            "session_id": "s1",
            "src_ip": "198.18.0.5",
            "protocol": "ssh",
            "inputs": 7,
            "start_ts": "2026-11-13 12:00:00.0",
            "end_ts": "2026-11-13 12:00:09.0",
            "tokens": ["tok1"],
            "artifacts": [],
        },
        "s2": {
            "session_id": "s2",
            "src_ip": "198.18.0.6",
            "protocol": "ssh",
            "inputs": 3,
            "start_ts": "2026-11-13 12:01:00.0",
            "end_ts": "2026-11-13 12:01:03.0",
            "tokens": [],
            "artifacts": [],
        },
        "s3": {
            "session_id": "s3",
            "src_ip": "198.18.0.7",
            "protocol": "ssh",
            "inputs": 4,
            "start_ts": "2026-11-13 12:02:00.0",
            "end_ts": "2026-11-13 12:02:04.0",
            "tokens": [],
            "artifacts": [],
        },
    }
    labels = {
        "s1": {"session_id": "s1", "tactics": ["TA0007"], "techniques": ["T1082"]},
        "s2": {"session_id": "s2", "tactics": ["TA0007"], "techniques": ["T1082"]},
        "s3": {"session_id": "s3", "tactics": ["TA0003", "TA0007"], "techniques": ["T1053.003"]},
    }
    t = Tagger(engine(tmp_path), FakeCH(evidence, labels), "20.1")
    alerts = await t.alerts({"s1", "s2", "s3"}, version=10)
    by = {a["session_id"]: a for a in alerts}
    assert set(by) == {"s1", "s3"}  # s2 (discovery only, no token/artifact) does not alert
    assert by["s1"]["reasons"] == ["honeytoken"] and by["s1"]["tokens"] == ["tok1"]
    assert by["s3"]["reasons"] == ["persistence"] and by["s3"]["techniques"] == ["T1053.003"]


async def test_process_writes_both_tables(tmp_path):
    ch = FakeCH(
        {
            "s1": {
                "session_id": "s1",
                "src_ip": "",
                "protocol": "ssh",
                "inputs": 1,
                "start_ts": "2026-11-13 12:00:00.0",
                "end_ts": "2026-11-13 12:00:00.0",
                "tokens": ["tok1"],
                "artifacts": [],
            }
        },
        {"s1": {"session_id": "s1", "tactics": ["TA0007"], "techniques": ["T1082"]}},
    )
    t = Tagger(engine(tmp_path), ch, "20.1")
    n_labels, n_alerts = await t.process([decision("uname -a")])
    assert n_labels == 1 and n_alerts == 1
    assert len(ch.inserted["mirage.labels"]) == 1
    assert ch.inserted["mirage.alerts"][0]["reasons"] == ["honeytoken"]


SESSION_RULES = {
    "rules": [
        {
            "id": "disc-uname",
            "technique": "T1082",
            "tactic": "TA0007",
            "protocol": "ssh",
            "confidence": 0.9,
            "any_of": [r"\buname\b"],
        },
    ],
    "session_rules": [
        {
            "id": "persist-brute",
            "technique": "T1110.001",
            "tactic": "TA0003",
            "confidence": 0.9,
            "when": {"failed_before_success": {">=": 3}, "auth_success": {">=": 1}},
        },
    ],
}


def session_engine(tmp_path) -> Engine:
    (tmp_path / "s.yaml").write_text(yaml.safe_dump(SESSION_RULES))
    return Engine.load(tmp_path)


def test_session_rules_are_applied_and_produce_session_labels(tmp_path):
    # Regression guard for the review's #1: session rules were loaded but never run.
    t = Tagger(session_engine(tmp_path), FakeCH(), "20.1")
    evidence = {
        "s1": {
            "session_id": "s1",
            "protocol": "ssh",
            "inputs": 6,
            "auth_attempts": 5,
            "auth_success": 1,
            "end_ts": "2026-11-13 12:00:09.0",
        },
        "s2": {
            "session_id": "s2",
            "protocol": "ssh",
            "inputs": 2,
            "auth_attempts": 1,
            "auth_success": 1,
            "end_ts": "2026-11-13 12:01:00.0",
        },
    }
    rows = t.session_labels(evidence, version=10)
    by = {r["session_id"]: r for r in rows}
    assert set(by) == {"s1"}  # s2 had only one failed-less login, rule does not fire
    assert by["s1"]["kind"] == "session" and by["s1"]["technique"] == "T1110.001"
    assert by["s1"]["tactic"] == "TA0003" and by["s1"]["event_id"] == "session:s1:persist-brute"


async def test_process_writes_session_labels_then_alerts(tmp_path):
    # Persistence seen only structurally (brute-then-success) must still raise an alert.
    ev = {
        "session_id": "s1",
        "src_ip": "",
        "protocol": "ssh",
        "inputs": 6,
        "auth_attempts": 5,
        "auth_success": 1,
        "start_ts": "2026-11-13 12:00:00.0",
        "end_ts": "2026-11-13 12:00:09.0",
        "tokens": [],
        "artifacts": [],
    }
    # After the worker writes the session label, the labels read-back carries TA0003.
    ch = FakeCH(
        {"s1": ev}, {"s1": {"session_id": "s1", "tactics": ["TA0003"], "techniques": ["T1110.001"]}}
    )
    t = Tagger(session_engine(tmp_path), ch, "20.1")
    _, n_alerts = await t.process([decision("uname -a")])
    kinds = sorted(r["kind"] for r in ch.inserted["mirage.labels"])
    assert kinds == ["input", "session"]  # both an input label and a session label were written
    assert n_alerts == 1 and ch.inserted["mirage.alerts"][0]["reasons"] == ["persistence"]


# ------------------------------------------------------------------ shared builders

T0 = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)


def at(seconds: float) -> str:
    return _ch_ts(T0 + timedelta(seconds=seconds))


def evid(sid, *, start=0.0, end=None, ip="198.18.0.5", protocol="ssh", inputs=0, attempts=0,
         success=0, tokens=(), artifacts=()) -> dict:  # fmt: skip
    """One row of EVIDENCE_SQL: a decoy session's own events, aggregated."""
    return {
        "session_id": sid, "src_ip": ip, "protocol": protocol, "inputs": inputs,
        "auth_attempts": attempts, "auth_success": success, "start_ts": at(start),
        "end_ts": at(start + 1 if end is None else end), "tokens": list(tokens),
        "artifacts": list(artifacts),
    }  # fmt: skip


def summ(sid, actor, *, start=0.0, end=None, ip="198.18.0.5", protocol="ssh", inputs=0,
         attempts=0, success=0, tokens=(), artifacts=(), connections=None, version=1) -> dict:  # fmt: skip
    """One row of mirage.session_summary, as the sessioniser writes it."""
    return {
        "session_id": sid, "actor_id": actor, "src_ip": ip, "protocol": protocol,
        "start_ts": at(start), "end_ts": at(start + 1 if end is None else end), "inputs": inputs,
        "auth_attempts": attempts, "auth_success": success, "tokens": list(tokens),
        "artifacts": list(artifacts), "connections": list(connections or [sid]),
        "version": str(version),
    }  # fmt: skip


def by_id(rows: list[dict]) -> dict[str, dict]:
    return {r["session_id"]: r for r in rows}


# ------------------------------------------------------------------ R4: session rules on the unit


def brute_force(ch: FakeCH, tmp_path) -> Tagger:
    """Three SSH connections of one actor: two that fail, then one that gets in."""
    ch._evidence = by_id(
        [
            evid("c1", start=0, attempts=2),
            evid("c2", start=10, attempts=1),
            evid("c3", start=20, attempts=2, success=1, inputs=3),
        ]
    )
    return Tagger(session_engine(tmp_path), ch, "20.1")


async def test_failed_logins_on_earlier_connections_count_towards_the_one_that_succeeded(tmp_path):
    # Each SSH connection is its own session: 2 + 1 failures, then 1 failure and the success.
    # No single connection has three failures and a success; the actor does.
    ch = FakeCH(
        summaries=by_id(
            [
                summ("c1", "actor-a", start=0, attempts=2),
                summ("c2", "actor-a", start=10, attempts=1),
                summ("c3", "actor-a", start=20, attempts=2, success=1, inputs=3),
            ]
        )
    )
    t = brute_force(ch, tmp_path)
    assert t.session_labels(ch._evidence, version=1) == []  # per connection: nothing, as before

    await t.recompute(["c1", "c2", "c3"], version=10)
    (label,) = ch.inserted["mirage.labels"]
    # The label lands on the session that succeeded, not on the ones that failed.
    assert label["event_id"] == "session:c3:persist-brute" and label["session_id"] == "c3"
    assert (label["kind"], label["technique"]) == ("session", "T1110.001")

    earlier = await t.earlier(ch._evidence, await t.members(["c3"]))
    assert [s["session_id"] for s in earlier["c3"]] == ["c2", "c1"]
    # The summary keeps its key names; the numbers are the unit's.
    assert t._summary(ch._evidence["c3"], earlier["c3"]) == {
        "inputs": 3,
        "auth_attempts": 5,
        "auth_success": 1,
        "failed_before_success": 4,
    }


async def test_the_unit_falls_back_to_the_source_address_until_the_actor_is_known(tmp_path):
    # The sessioniser has summarised the two failed connections but not yet the third.
    ch = FakeCH(
        summaries=by_id(
            [
                summ("c1", "actor-a", start=0, attempts=2),
                summ("c2", "actor-a", start=10, attempts=1),
                summ("x1", "actor-z", start=5, attempts=9, ip="198.18.0.77"),  # someone else
            ]
        )
    )
    t = brute_force(ch, tmp_path)
    await t.recompute(["c3"], version=10)
    assert [r["event_id"] for r in ch.inserted["mirage.labels"]] == ["session:c3:persist-brute"]
    earlier = await t.earlier(ch._evidence, await t.members(["c3"]))
    assert [s["session_id"] for s in earlier["c3"]] == ["c2", "c1"]


@pytest.mark.parametrize(
    ("change", "why"),
    [
        ({"actor_id": "actor-b"}, "another actor's failures"),
        ({"protocol": "mysql"}, "failures on another service"),
        ({"start_ts": at(-7200), "end_ts": at(-7190)}, "failures before the window"),
        ({"start_ts": at(30), "end_ts": at(31)}, "failures after the success"),
    ],
)
async def test_what_is_outside_the_unit_is_not_counted(tmp_path, change, why):
    ch = FakeCH(
        summaries=by_id(
            [
                {**summ("c1", "actor-a", start=0, attempts=2), **change},
                summ("c2", "actor-a", start=10, attempts=1),
                summ("c3", "actor-a", start=20, attempts=2, success=1),
            ]
        )
    )
    t = brute_force(ch, tmp_path)
    await t.recompute(["c3"], version=10)
    # Without c1's two, the actor made 1 + 1 failed attempts before the success: under three.
    assert ch.inserted.get("mirage.labels", []) == [], why


async def test_each_session_in_a_batch_gets_its_own_actor_and_its_own_window(tmp_path):
    # One recompute, three sessions that succeed. The candidates for all of them come back
    # from one query, so each must take only what is its own.
    ch = FakeCH(
        summaries=by_id(
            [
                summ("c1", "actor-a", start=0, attempts=2),
                summ("c2", "actor-a", start=10, attempts=1),
                summ("c3", "actor-a", start=20, attempts=2, success=1),
                # another actor, who logs straight in while actor-a is guessing
                summ("y3", "actor-b", start=15, attempts=1, success=1, ip="198.18.0.6"),
                # actor-c failed four times three hours ago; today's login is not a brute force
                summ("o1", "actor-c", start=-10800, attempts=4, ip="198.18.0.7"),
                summ("o3", "actor-c", start=30, attempts=1, success=1, ip="198.18.0.7"),
                # actor-d was the same three hours ago, and that is the session being recomputed:
                # it stretches the query's range far enough back to return o1
                summ("d3", "actor-d", start=-10700, attempts=1, success=1, ip="198.18.0.8"),
            ]
        )
    )
    t = brute_force(ch, tmp_path)
    for sid, start, ip in (("y3", 15, "6"), ("o3", 30, "7"), ("d3", -10700, "8")):
        ch._evidence[sid] = evid(sid, start=start, attempts=1, success=1, ip=f"198.18.0.{ip}")
    await t.recompute(["c3", "y3", "o3", "d3"], version=10)
    assert [r["session_id"] for r in ch.inserted["mirage.labels"]] == ["c3"]
    (earlier,) = [p for table, p in ch.asked if "lo" in p]
    assert earlier["lo"] == at(-10700 - 3600)  # one query, reaching back from the oldest


async def test_an_earlier_success_closes_its_own_unit(tmp_path):
    # Four failures and a success an hour's work ago; now the same actor logs straight in.
    # Those failures led to the first login, not to this one.
    ch = FakeCH(
        summaries=by_id(
            [
                summ("c1", "actor-a", start=0, attempts=4),
                summ("c2", "actor-a", start=10, attempts=1, success=1),
                summ("c3", "actor-a", start=20, attempts=1, success=1),
            ]
        )
    )
    t = brute_force(ch, tmp_path)
    ch._evidence["c2"] = evid("c2", start=10, attempts=1, success=1)
    ch._evidence["c3"] = evid("c3", start=20, attempts=1, success=1)
    await t.recompute(["c2", "c3"], version=10)
    assert [r["session_id"] for r in ch.inserted["mirage.labels"]] == ["c2"]


async def test_an_http_connection_is_not_counted_twice_through_its_logical_session(tmp_path):
    # An HTTP connection has no summary of its own: it is one of its logical session's
    # connections. That row describes the connection itself, so it is not an "earlier" session.
    ch = FakeCH(
        {"h2": evid("h2", start=20, protocol="http", attempts=2, success=1)},
        summaries=by_id(
            [summ("http-1", "actor-a", protocol="http", attempts=4, connections=["h1", "h2"])]
        ),
    )
    t = Tagger(session_engine(tmp_path), ch, "20.1")
    assert await t.earlier(ch._evidence, await t.members(["h2"])) == {}


# ------------------------------------------------------------------ V2: actor alerts


def demo_2() -> FakeCH:
    """Demo 2's shape: a web session reads the planted credential; a MySQL session from a
    second address uses it. The sessioniser has linked both to one actor by the honeytoken."""
    return FakeCH(
        labels={
            "w1": {"session_id": "w1", "tactics": ["TA0043"], "techniques": ["T1595.003"]},
            "w2": {"session_id": "w2", "tactics": ["TA0006"], "techniques": ["T1552.001"]},
            "m1": {"session_id": "m1", "tactics": ["TA0009", "TA0001"], "techniques": ["T1078"]},
        },
        summaries=by_id(
            [
                summ(
                    "http-web",
                    "actor-a",
                    start=0,
                    end=30,
                    ip="198.18.0.5",
                    protocol="http",
                    inputs=12,
                    connections=["w1", "w2"],
                ),
                summ(
                    "m1",
                    "actor-a",
                    start=60,
                    end=75,
                    ip="198.18.0.9",
                    protocol="mysql",
                    inputs=4,
                    attempts=1,
                    success=1,
                    tokens=["tok-db"],
                ),
                summ("other", "actor-z", start=5, ip="198.18.0.44", inputs=2),
            ]
        ),
        classes={"http-web": "scanner", "m1": "scripted_bot", "other": "human"},
    )


async def test_one_actor_alert_names_both_sessions_and_both_addresses(tmp_path):
    ch = demo_2()
    t = Tagger(engine(tmp_path), ch, "20.1")
    rows = await t.actor_alerts({"actor-a", "actor-z"}, version=10)
    assert rows == [
        {
            "actor_id": "actor-a",
            "version": 10,
            "session_ids": ["http-web", "m1"],  # the sessioniser's sessions, not connections
            "src_ips": ["198.18.0.5", "198.18.0.9"],
            "protocols": ["http", "mysql"],
            "actor_classes": ["scanner", "scripted_bot"],
            "reasons": ["honeytoken"],
            "tactics": ["TA0001", "TA0006", "TA0009", "TA0043"],  # labels sit on connections
            "techniques": ["T1078", "T1552.001", "T1595.003"],
            "tokens": ["tok-db"],
            "artifacts": [],
            "inputs": 16,
            "start_ts": at(0),
            "end_ts": at(75),
        }
    ]  # and nothing for actor-z, which has no reason for an alert
    for name, value in rows[0].items():
        if isinstance(value, list):
            assert value == sorted(set(value)), name


async def test_actor_classes_are_the_classifier_s_predictions_or_nothing(tmp_path):
    ch = demo_2()
    ch.classes = {}  # mirage.actor_class may be empty: no classifier worker yet
    t = Tagger(engine(tmp_path), ch, "20.1")
    (row,) = await t.actor_alerts({"actor-a"}, version=10)
    assert row["actor_classes"] == []
    classes = [p for table, p in ch.asked if table == "mirage.actor_class"]
    assert classes and set(classes[0]["ids"]) == {"http-web", "w1", "w2", "m1"}


async def test_ready_asks_for_the_actor_alerts_table(tmp_path):
    ch = FakeCH()
    await Tagger(engine(tmp_path), ch, "20.1").ready()
    assert [table for table, _ in ch.asked] == ["mirage.actor_alerts"]


def test_every_read_is_final_and_none_touches_ground_truth():
    queries = {k: v for k, v in vars(tagging).items() if k.endswith("_SQL")}
    assert len(queries) >= 10
    for name, sql in queries.items():
        tables = re.findall(r"FROM\s+(mirage\.\w+)(\s+FINAL)?", sql)
        assert tables and all(final for _, final in tables), name
        assert "sim_" not in sql, name  # predictions and captured events only (register rule 1)


async def test_a_batch_writes_the_actor_alert_alongside_the_session_alert(tmp_path):
    ch = demo_2()
    ch._evidence = {"m1": evid("m1", start=60, end=75, ip="198.18.0.9", protocol="mysql",
                               inputs=4, attempts=1, success=1, tokens=["tok-db"])}  # fmt: skip
    t = Tagger(engine(tmp_path), ch, "20.1")
    _, n_alerts = await t.process([decision("select 1", session="m1", protocol="mysql")])
    assert n_alerts == 1  # process() still reports labels and session alerts, as before
    assert [a["session_id"] for a in ch.inserted["mirage.alerts"]] == ["m1"]
    (row,) = ch.inserted["mirage.actor_alerts"]
    assert row["actor_id"] == "actor-a" and row["session_ids"] == ["http-web", "m1"]

    # A redelivered batch recomputes the same row; nothing is added up.
    await t.process([decision("select 1", session="m1", protocol="mysql")])
    first, again = ch.inserted["mirage.actor_alerts"]
    assert again["version"] > first["version"]
    assert {**again, "version": 0} == {**first, "version": 0}


async def test_when_two_actors_are_linked_the_old_alert_is_retired(tmp_path):
    # m1 alone already had an alert (an artifact) under its own actor ...
    ch = FakeCH(
        summaries=by_id([summ("m1", "actor-m", protocol="mysql", artifacts=["ab" * 32])]),
    )
    t = Tagger(engine(tmp_path), ch, "20.1")
    ch.inserted["mirage.actor_alerts"] = await t.actor_alerts({"actor-m"}, version=10)
    assert ch.last("mirage.actor_alerts", "actor_id")["actor-m"]["reasons"] == ["artifact"]

    # ... then the sessioniser links it to the web session: one actor, with a new ID.
    ch.summaries = by_id(
        [
            summ("http-web", "actor-a", protocol="http", connections=["w1"]),
            summ("m1", "actor-a", protocol="mysql", artifacts=["ab" * 32], tokens=["tok-db"]),
        ]
    )
    ch.inserted["mirage.actor_alerts"] += await t.actor_alerts({"actor-a"}, version=20)
    table = ch.last("mirage.actor_alerts", "actor_id")
    assert table["actor-a"]["session_ids"] == ["http-web", "m1"]
    assert table["actor-a"]["reasons"] == ["artifact", "honeytoken"]
    # The old row is emptied, so `WHERE notEmpty(reasons)` leaves one alert naming both.
    assert table["actor-m"]["version"] == 20
    assert table["actor-m"]["reasons"] == [] and table["actor-m"]["session_ids"] == []
    assert [a for a, r in table.items() if r["reasons"]] == ["actor-a"]

    # Recomputing again does not keep retiring it.
    assert [r["actor_id"] for r in await t.actor_alerts({"actor-a"}, version=30)] == ["actor-a"]


# ------------------------------------------------------------------ R3: the reconciliation sweep


def ns(when: datetime) -> int:
    return int(when.timestamp() * 1_000_000) * 1000


async def test_a_token_written_after_the_batch_still_raises_the_alert(tmp_path):
    # The session's last event is the one that uses the honeytoken. The tagger handles the
    # batch first: no token.triggered row exists yet, so there is nothing to alert on.
    ch = FakeCH({"s1": evid("s1", inputs=1)})
    t = Tagger(engine(tmp_path), ch, "20.1")
    assert await t.process([decision("mysql -u app -p", session="s1")]) == (0, 0)
    assert await t.sweep() == (0, 0, 0) and ch.inserted["mirage.alerts"] == []

    # Then the sessioniser writes the finding, straight to ClickHouse. No event follows it,
    # so no batch will ever touch s1 again.
    now = datetime.now(UTC)
    ch._evidence["s1"]["tokens"] = ["tok-db"]
    ch.findings["s1"] = _ch_ts(now - timedelta(seconds=1))
    assert await t.sweep(now) == (1, 1, 0)
    (alert,) = ch.inserted["mirage.alerts"]
    assert (alert["session_id"], alert["reasons"], alert["tokens"]) == (
        "s1",
        ["honeytoken"],
        ["tok-db"],
    )

    # The same finding is not recomputed sweep after sweep.
    asked = len(ch.asked)
    assert await t.sweep(now + timedelta(seconds=15)) == (0, 0, 0)
    assert len(ch.inserted["mirage.alerts"]) == 1 and len(ch.asked) == asked + 4


async def test_the_sweep_picks_up_the_actor_link_the_sessioniser_wrote_later(tmp_path):
    # Demo 2, in the order it happens: the tagger sees the MySQL login before the sessioniser
    # has written the finding, the link or the summaries.
    ch = FakeCH(
        {"m1": evid("m1", start=60, ip="198.18.0.9", protocol="mysql", attempts=1, success=1)}
    )
    t = Tagger(engine(tmp_path), ch, "20.1")
    await t.process([decision("select 1", session="m1", protocol="mysql")])
    assert ch.inserted["mirage.alerts"] == [] and ch.inserted["mirage.actor_alerts"] == []

    now = datetime.now(UTC)
    ch._evidence["m1"]["tokens"] = ["tok-db"]
    ch.findings["m1"] = _ch_ts(now - timedelta(seconds=2))
    ch.summaries = by_id(
        [
            summ("http-web", "actor-a", ip="198.18.0.5", protocol="http", inputs=12,
                 connections=["w1", "w2"], version=ns(now) - 2_000_000_000),
            summ("m1", "actor-a", start=60, ip="198.18.0.9", protocol="mysql", inputs=4,
                 tokens=["tok-db"], version=ns(now) - 2_000_000_000),
        ]
    )  # fmt: skip
    _, n_alerts, n_actor = await t.sweep(now)
    assert (n_alerts, n_actor) == (1, 1)
    assert ch.inserted["mirage.alerts"][0]["session_id"] == "m1"
    (row,) = ch.inserted["mirage.actor_alerts"]
    assert row["session_ids"] == ["http-web", "m1"]
    assert row["src_ips"] == ["198.18.0.5", "198.18.0.9"] and row["reasons"] == ["honeytoken"]


async def test_a_prediction_written_later_reaches_the_actor_alert(tmp_path):
    # The classifier worker classifies a session after its summary is written, so the actor
    # alert is first built without a class. Nothing else about the actor changes afterwards.
    now = datetime.now(UTC)
    ch = demo_2()
    for row in ch.summaries.values():
        row["version"] = str(ns(now) - 10**9)
    predictions, ch.classes = ch.classes, {}
    t = Tagger(engine(tmp_path), ch, "20.1")
    await t.sweep(now)
    assert ch.last("mirage.actor_alerts", "actor_id")["actor-a"]["actor_classes"] == []

    ch.classes = predictions
    ch.classified = {sid: _ch_ts(now + timedelta(seconds=5)) for sid in predictions}
    asked = len(ch.asked)
    sessions, n_alerts, n_actor = await t.sweep(now + timedelta(seconds=15))
    assert (sessions, n_alerts, n_actor) == (3, 0, 1)  # actor-z has no reason for an alert
    row = ch.last("mirage.actor_alerts", "actor_id")["actor-a"]
    assert row["actor_classes"] == ["scanner", "scripted_bot"]
    # Only the actors were recomputed: no session's events were read again.
    assert not any(table == "mirage.events" and "ids" in p for table, p in ch.asked[asked:])
    assert await t.sweep(now + timedelta(seconds=30)) == (0, 0, 0)


async def test_a_change_older_than_the_window_is_left_alone(tmp_path):
    now = datetime.now(UTC)
    ch = FakeCH(
        {"s1": evid("s1", tokens=["tok-db"])},
        summaries=by_id([summ("s1", "actor-a", tokens=["tok-db"], version=ns(now) - 400 * 10**9)]),
    )
    ch.findings["s1"] = _ch_ts(now - timedelta(seconds=400))
    t = Tagger(engine(tmp_path), ch, "20.1", sweep_window_s=300)
    assert await t.sweep(now) == (0, 0, 0) and ch.inserted == {}


async def test_a_sweep_is_bounded(tmp_path, caplog):
    now = datetime.now(UTC)
    rows = [
        summ(f"s{i}", f"actor-{i}", artifacts=["ab" * 32], version=ns(now) - i * 10**9)
        for i in range(1, 8)  # s1 changed most recently
    ]
    ch = FakeCH(
        {r["session_id"]: evid(r["session_id"], artifacts=["ab" * 32]) for r in rows},
        summaries=by_id(rows),
    )
    t = Tagger(engine(tmp_path), ch, "20.1", sweep_limit=3)
    with caplog.at_level("WARNING"):
        assert await t.sweep(now) == (3, 3, 3)
    assert "3 or more changed summaries" in caplog.text
    assert sorted(a["session_id"] for a in ch.inserted["mirage.alerts"]) == ["s1", "s2", "s3"]
    assert all(len(p.get("ids", [])) <= 3 for _, p in ch.asked)


async def test_a_session_with_too_many_connections_gets_only_its_actor_recomputed(tmp_path):
    now = datetime.now(UTC)
    conns = [f"h{i}" for i in range(50)]
    ch = FakeCH(
        {c: evid(c, protocol="http", artifacts=["ab" * 32]) for c in conns},
        summaries=by_id(
            [summ("http-big", "actor-a", protocol="http", artifacts=["ab" * 32],
                  connections=conns, version=ns(now) - 10**9)]
        ),
    )  # fmt: skip
    t = Tagger(engine(tmp_path), ch, "20.1", sweep_limit=10)
    assert await t.sweep(now) == (1, 0, 1)
    assert not any(table == "mirage.events" and "ids" in p for table, p in ch.asked)
    assert ch.inserted["mirage.actor_alerts"][0]["session_ids"] == ["http-big"]


async def test_the_sweep_does_not_trigger_itself(tmp_path):
    # A sweep writes session-rule labels. They must not read back as "a label changed",
    # or every sweep would recompute the session again, for ever.
    now = datetime.now(UTC)
    ch = FakeCH(
        {"c3": evid("c3", attempts=5, success=1)},
        summaries=by_id([summ("c3", "actor-a", attempts=5, success=1, version=ns(now) - 10**9)]),
    )
    t = Tagger(session_engine(tmp_path), ch, "20.1")
    assert (await t.sweep(now))[0] == 1
    assert [r["kind"] for r in ch.inserted["mirage.labels"]] == ["session"]
    assert await t.sweep(now + timedelta(seconds=15)) == (0, 0, 0)
    assert len(ch.inserted["mirage.labels"]) == 1
    # The fake leaves session labels out because the query does; hold the query to it.
    assert "kind != 'session'" in tagging.CHANGED_LABELS_SQL


async def test_a_batch_s_own_labels_do_not_bring_the_sweep_back(tmp_path):
    ch = FakeCH({"s1": evid("s1", inputs=1)})
    t = Tagger(engine(tmp_path), ch, "20.1")
    assert await t.process([decision("uname -a", session="s1")]) == (1, 0)
    assert await t.sweep() == (0, 0, 0)
    # A label some other writer adds later does.
    ch.inserted["mirage.labels"].append(
        {**ch.inserted["mirage.labels"][0], "event_id": "x", "tactic": "TA0040",
         "version": ch.inserted["mirage.labels"][0]["version"] + 5}
    )  # fmt: skip
    assert await t.sweep() == (1, 1, 0)
    assert ch.inserted["mirage.alerts"][0]["reasons"] == ["impact"]


async def test_a_sweep_that_fails_is_repeated_in_full(tmp_path):
    now = datetime.now(UTC)
    ch = FakeCH({"s1": evid("s1", tokens=["tok-db"])})
    ch.findings["s1"] = _ch_ts(now - timedelta(seconds=1))
    ch.fail_inserts = 1
    t = Tagger(engine(tmp_path), ch, "20.1")
    with pytest.raises(RuntimeError):
        await t.sweep(now)
    assert await t.sweep(now + timedelta(seconds=15)) == (1, 1, 0)
