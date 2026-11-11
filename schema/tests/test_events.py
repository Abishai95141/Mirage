from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from mirage_schema import (
    SCHEMA_VERSION,
    EventClass,
    GroundTruth,
    Label,
    MirageEvent,
    Source,
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
        scenario_id="s1",
        step_id="1",
        procedure_id="p-cron-persist",
        technique_id="T1053.003",
        tactic="TA0003",
        attack_version="20.1",
        src={"ip": "10.10.0.5"},
        dst={"ip": "10.10.0.2", "port": 2222},
        start_ts=NOW,
        end_ts=NOW + timedelta(seconds=2),
        status="ran",
    )
    base.update(kw)
    return GroundTruth(**base)


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
