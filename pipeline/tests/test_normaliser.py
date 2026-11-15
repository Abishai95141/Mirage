import json
import re
from pathlib import Path

import yaml

from mirage_pipeline.normaliser import STREAMS, normalise_batch
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


def test_stream_caps_fit_the_broker_budget():
    """Every stream reserves its max_bytes against JetStream's file-store limit, and a stream
    that does not fit is refused when the pipeline starts. The limit is fixed in
    compose/nats/nats.conf. A stream added or enlarged without raising it would stop every
    worker with "insufficient storage resources available", which is how CI found this."""
    compose = Path(__file__).parents[2] / "compose"
    conf = (compose / "nats" / "nats.conf").read_text()
    limit = re.search(r"^\s*max_file_store:\s*(\d+)GB\s*$", conf, re.MULTILINE)
    assert limit, "max_file_store must be set, in whole GB"
    assert all(s.max_bytes and s.max_bytes > 0 for s in STREAMS), "every stream needs a cap"
    assert sum(s.max_bytes for s in STREAMS) <= int(limit.group(1)) * 1024**3

    # The file only counts if the server is started from it.
    nats = yaml.safe_load((compose / "docker-compose.yml").read_text())["services"]["nats"]
    assert nats["command"] == ["-c", "/etc/nats/nats.conf"]
    assert "./nats/nats.conf:/etc/nats/nats.conf:ro" in nats["volumes"]
