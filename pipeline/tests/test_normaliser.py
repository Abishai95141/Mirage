import json

from mirage_pipeline.normaliser import normalise_batch
from mirage_pipeline.rows import to_row
from mirage_schema import MirageEvent

GOOD = {
    "eventid": "cowrie.command.input",
    "timestamp": "2026-11-11T12:00:01.5Z",
    "session": "abc123",
    "sensor": "s1",
    "src_ip": "10.10.0.5",
    "src_port": 50000,
    "dst_ip": "10.10.0.2",
    "dst_port": 2222,
    "protocol": "ssh",
    "input": "cat /etc/passwd",
    "message": "CMD: cat /etc/passwd",
}


def test_batch_splits_good_and_dead():
    res = normalise_batch(
        [
            ("raw.honeypot.cowrie", json.dumps(GOOD).encode()),
            ("raw.honeypot.cowrie", b"not json"),
            ("raw.honeypot.cowrie", json.dumps({"_unparsed": "x"}).encode()),
            ("raw.honeypot.nosuch", b"{}"),
        ]
    )
    assert len(res.events) == 1 and isinstance(res.events[0], MirageEvent)
    reasons = [d["reason"] for d in res.dead]
    assert len(reasons) == 3
    assert reasons[0].startswith("JSONDecodeError")
    assert reasons[1].startswith("KeyError")
    assert reasons[2] == "no mapper for subject"


def test_row_is_flat_and_clickhouse_ready():
    ev = normalise_batch([("raw.honeypot.cowrie", json.dumps(GOOD).encode())]).events[0]
    row = to_row(ev)
    assert row["ts"] == "2026-11-11 12:00:01.500000"
    assert row["class"] == "process_activity" and row["class_uid"] == 1007
    assert row["src_ip"] == "10.10.0.5" and row["dst_port"] == 2222
    assert json.loads(row["payload"]) == {"command": "cat /etc/passwd"}
    assert json.loads(row["raw"])["eventid"] == "cowrie.command.input"
    assert row["policy"] == "" and json.loads(row["labels"]) == []
    assert all(isinstance(v, str | int) for v in row.values())
