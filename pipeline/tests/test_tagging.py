"""The tagger worker: labelling decisions and raising alerts. Fake ClickHouse, synthetic events."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import yaml

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
    """Records inserts; answers the two aggregate queries from canned data keyed by session."""

    def __init__(self, evidence=None, labels=None) -> None:
        self.inserted: dict[str, list] = {}
        self._evidence = evidence or {}
        self._labels = labels or {}

    async def insert(self, rows, table):
        self.inserted.setdefault(table, []).extend(rows)

    async def select(self, sql, **params):
        ids = params["ids"]
        src = self._labels if "mirage.labels" in sql else self._evidence
        return [src[i] for i in ids if i in src]


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
