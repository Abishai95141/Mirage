import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from mirage_schema import (
    SCHEMA_VERSION,
    EventClass,
    GroundTruth,
    Label,
    MirageEvent,
    SessionTruth,
    Source,
    input_hash,
    parse_record,
)
from mirage_schema.export import schemas

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)


def _event(**kw) -> MirageEvent:
    base = dict(
        event_id="e1",
        ts=NOW,
        ingest_ts=NOW,
        source=Source.COWRIE,
        event_class=EventClass.PROCESS_ACTIVITY,
        action="command",
    )
    base.update(kw)
    return MirageEvent(**base)


def test_serialises_class_by_alias_with_ocsf_uid():
    data = _event().model_dump(by_alias=True, mode="json")
    assert data["class"] == "process_activity"
    assert data["class_uid"] == 1007
    assert data["schema_version"] == SCHEMA_VERSION


def test_round_trip():
    ev = _event(payload={"command": "uname -a"})
    assert MirageEvent.model_validate_json(ev.to_json()) == ev


def test_mismatched_class_uid_rejected():
    bad = _event().to_json().replace('"class_uid":1007', '"class_uid":4001')
    with pytest.raises(ValidationError, match="class_uid"):
        MirageEvent.model_validate_json(bad)


def test_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        _event(colour="red")


def test_requires_timezone():
    with pytest.raises(ValidationError):
        _event(ts=datetime(2026, 11, 11, 12, 0))


def test_rejects_event_far_after_ingest():
    with pytest.raises(ValidationError):
        _event(ts=NOW + timedelta(minutes=5))


@pytest.mark.parametrize("kind", ["tactic", "technique"])
def test_attack_labels_need_version(kind):
    with pytest.raises(ValidationError, match="attack_version"):
        Label(kind=kind, value="TA0007", model_version="logprecis-0")
    Label(kind=kind, value="TA0007", model_version="logprecis-0", attack_version="20.1")


def test_actor_label_needs_no_attack_version():
    Label(kind="actor", value="scripted_bot", model_version="rules-0")


def _gt(**kw):
    base = dict(
        run_id="r1",
        scenario_id="s1",
        session_ref="s1/0",
        protocol="ssh",
        step_id="1",
        procedure_id="p-cron-persist",
        technique_id="T1053.003",
        tactic="TA0003",
        attack_version="20.1",
        src={"ip": "198.18.0.5", "port": 40001},
        dst={"ip": "10.10.0.2", "port": 2222},
        input_sha256=input_hash("crontab -l"),
        start_ts=NOW,
        end_ts=NOW + timedelta(seconds=2),
        status="ran",
    )
    base.update(kw)
    return GroundTruth(**base)


def _session(**kw):
    base = dict(
        run_id="r1",
        scenario_id="s1",
        session_ref="s1/0",
        protocol="ssh",
        actor_ref="a1",
        actor_class="scripted_bot",
        timing_profile="bot-fast",
        mode="capture",
        connections=[
            {
                "src": {"ip": "198.18.0.5", "port": 40001},
                "dst": {"ip": "10.10.0.2", "port": 2222},
                "opened_ts": NOW,
            }
        ],
        start_ts=NOW,
        end_ts=NOW + timedelta(seconds=9),
    )
    base.update(kw)
    return SessionTruth(**base)


def test_step_without_a_technique_is_an_explicit_negative():
    assert _gt(technique_id=None, tactic=None).technique_id is None
    with pytest.raises(ValidationError):
        _gt(tactic=None)  # a technique without its tactic


def test_session_truth_needs_an_addressed_connection():
    assert _session().connections[0].src.port == 40001
    with pytest.raises(ValidationError):
        _session(connections=[])
    with pytest.raises(ValidationError):
        _session(connections=[{"src": {"ip": "198.18.0.5"}, "dst": {"port": 22}, "opened_ts": NOW}])
    with pytest.raises(ValidationError):
        _session(actor_class="robot")


def test_parse_record_dispatches_on_kind():
    step = json.loads(_gt().model_dump_json())
    assert isinstance(parse_record(step), GroundTruth)
    step.pop("kind")
    assert isinstance(parse_record(step), GroundTruth)  # phase 0 records had no kind
    assert isinstance(parse_record(json.loads(_session().model_dump_json())), SessionTruth)


def test_ground_truth_valid():
    assert _gt().technique_id == "T1053.003"


@pytest.mark.parametrize("bad", [{"technique_id": "1053"}, {"tactic": "Persistence"}])
def test_ground_truth_ids_are_checked(bad):
    with pytest.raises(ValidationError):
        _gt(**bad)


def test_ground_truth_times_ordered():
    with pytest.raises(ValidationError):
        _gt(end_ts=NOW - timedelta(seconds=1))


def test_json_schema_export():
    out = schemas()
    ev = out["mirage-event.schema.json"]
    assert "class" in ev["properties"]
    assert "class_uid" in ev["properties"]
    assert "technique_id" in out["ground-truth.schema.json"]["properties"]
    assert "connections" in out["session-truth.schema.json"]["properties"]
    assert "catalogue_sha256" in out["run-record.schema.json"]["properties"]
