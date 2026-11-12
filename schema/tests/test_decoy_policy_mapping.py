import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mirage_policy.app import RULES_DIR, Settings, create_app
from mirage_schema.events import EventClass, Outcome, Source
from mirage_schema.mappings import decoy, policy


def _http_records(tmp_path: Path) -> list[dict]:
    """Run the real HTTP decoy for two requests and return what it logged."""
    import asyncio

    from mirage_decoy_common.gate import GateClient
    from mirage_decoy_common.proxyproto import build_header
    from mirage_decoy_common.server import connection_handler
    from mirage_decoy_common.session import ArtifactStore, Decoy, EventLog
    from mirage_http_decoy.handler import Handler
    from mirage_http_decoy.nginx import Profile
    from mirage_profiles.generator import render
    from mirage_schema.policy import Protocol

    out = render(Path("decoys/profiles/web-db.yaml"), 3, tmp_path / "p")
    d = Decoy(Protocol.HTTP, GateClient(None), EventLog(None), ArtifactStore(None), "dep-t")
    handler = Handler(Profile.load(out / "http.json"))

    async def go() -> None:
        srv = await asyncio.start_server(connection_handler(d, handler), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        async with srv:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(build_header("203.0.113.4", 5000, "127.0.0.1", port))
            w.write(b"GET /.env HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            await w.drain()
            await r.read()
            w.close()
            await asyncio.sleep(0.05)

    asyncio.run(go())
    return d.log.records


def test_http_decoy_records_map(tmp_path):
    recs = _http_records(tmp_path)
    events = [decoy.map_record(r) for r in recs]
    by_action = {e.action: e for e in events}
    assert {"connect", "decide", "request", "disconnect"} <= set(by_action)
    req = by_action["request"]
    assert req.source is Source.HTTP_DECOY and req.event_class is EventClass.HTTP_ACTIVITY
    assert req.class_uid == 4002 and req.outcome is Outcome.SUCCESS
    assert str(req.src.ip) == "203.0.113.4" and req.payload["path"] == "/.env"
    dec = by_action["decide"]
    assert dec.policy is not None and dec.policy.decision_id.startswith("fallback:")
    assert dec.outcome is Outcome.FAILURE  # gate disabled -> recorded fallback
    assert len({e.session_id for e in events}) == 1


def test_unknown_decoy_protocol_rejected():
    with pytest.raises(ValueError):
        decoy.map_record({"eventid": "smtp.request", "timestamp": "2026-11-12T00:00:00Z"})


def test_policy_log_record_maps(tmp_path):
    log = tmp_path / "d.json"
    app = create_app(
        Settings(token="t" * 32, log_path=log, rule_files=[RULES_DIR / "default.yaml"])
    )
    TestClient(app).post(
        "/v1/decide",
        headers={"Authorization": "Bearer " + "t" * 32},
        json={
            "request_id": "r9",
            "session_id": "s9",
            "deployment_id": "dep",
            "seq": 4,
            "protocol": "ssh",
            "argv": ["id"],
            "src": {"ip": "198.51.100.2", "port": 1},
        },
    )
    ev = policy.map_record(json.loads(log.read_text().splitlines()[0]))
    assert ev.source is Source.POLICY and ev.event_class is EventClass.POLICY_DECISION
    assert ev.session_id == "s9" and ev.sensor == "dep" and str(ev.src.ip) == "198.51.100.2"
    assert ev.payload["request_id"] == "r9" and ev.payload["seq"] == 4
    assert ev.payload["rule_id"] == "default-allow" and ev.policy.action == "allow"
