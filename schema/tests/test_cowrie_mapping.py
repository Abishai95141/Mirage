import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mirage_schema import EventClass, Outcome
from mirage_schema.mappings.cowrie import TABLE, map_record

INGEST = datetime(2026, 11, 11, 12, 0, 5, tzinfo=UTC)
UPSTREAM_DOC = Path(__file__).parents[2] / "spikes/s1-cowrie-gate/upstream/docs/OUTPUT.rst"


def rec(eventid, **kw):
    base = {
        "eventid": eventid,
        "timestamp": "2026-11-11T12:00:01.123456Z",
        "session": "a1b2c3d4e5f6",
        "sensor": "svr04",
        "src_ip": "10.10.0.5",
        "src_port": 51514,
        "dst_ip": "10.10.0.2",
        "dst_port": 2222,
        "protocol": "ssh",
        "message": "...",
    }
    base.update(kw)
    return base


def test_connect():
    ev = map_record(rec("cowrie.session.connect"), ingest_ts=INGEST)
    assert ev.event_class is EventClass.SSH_ACTIVITY  # as Cowrie's own OCSF module classes it
    assert ev.action == "connect"
    assert str(ev.src.ip) == "10.10.0.5" and ev.src.port == 51514
    assert ev.dst.port == 2222
    assert ev.session_id == "a1b2c3d4e5f6"
    assert ev.ts == datetime(2026, 11, 11, 12, 0, 1, 123456, tzinfo=UTC)
    assert "message" not in ev.payload and "eventid" not in ev.payload


def test_telnet_connect_is_network_activity():
    ev = map_record(rec("cowrie.session.connect", protocol="telnet"), ingest_ts=INGEST)
    assert ev.event_class is EventClass.NETWORK_ACTIVITY


def test_policy_decision():
    ev = map_record(
        rec(
            "cowrie.policy.decision",
            input="frobnicate",
            action="fake_success",
            fallback=False,
            known=False,
            decision_id="d-1",
            propensity=0.25,
            latency_ms=0.9,
            request_id="r-1",
        ),
        ingest_ts=INGEST,
    )
    assert ev.event_class is EventClass.POLICY_DECISION
    assert ev.outcome is Outcome.SUCCESS
    assert ev.policy is not None
    assert (ev.policy.decision_id, ev.policy.action, ev.policy.propensity) == (
        "d-1",
        "fake_success",
        0.25,
    )
    assert ev.payload["command"] == "frobnicate"
    assert ev.payload["known"] is False


def test_policy_fallback_is_failure_with_synthetic_id():
    ev = map_record(
        rec(
            "cowrie.policy.decision",
            input="ls",
            action="allow",
            fallback=True,
            known=True,
            decision_id=None,
            propensity=None,
            latency_ms=200.4,
            request_id="r-2",
        ),
        ingest_ts=INGEST,
    )
    assert ev.outcome is Outcome.FAILURE
    assert ev.policy.decision_id == "fallback:r-2"


@pytest.mark.parametrize(
    ("eventid", "outcome"),
    [("cowrie.login.success", Outcome.SUCCESS), ("cowrie.login.failed", Outcome.FAILURE)],
)
def test_login(eventid, outcome):
    ev = map_record(rec(eventid, username="root", password="hunter2"), ingest_ts=INGEST)
    assert ev.event_class is EventClass.AUTHENTICATION
    assert ev.outcome is outcome
    assert ev.payload == {"username": "root", "password": "hunter2"}


def test_command_input_renamed():
    ev = map_record(rec("cowrie.command.input", input="uname -a"), ingest_ts=INGEST)
    assert (ev.event_class, ev.action, ev.payload) == (
        EventClass.PROCESS_ACTIVITY,
        "command",
        {"command": "uname -a"},
    )


def test_command_input_outcome_is_unknown():
    # Cowrie logs input before it knows whether the command exists.
    ev = map_record(rec("cowrie.command.input", input="frobnicate"), ingest_ts=INGEST)
    assert ev.outcome is Outcome.UNKNOWN


def test_command_input_with_realm_is_stdin():
    ev = map_record(rec("cowrie.command.input", input="y", realm="apt-get"), ingest_ts=INGEST)
    assert ev.action == "stdin_input"


def test_unknown_command_is_failure():
    ev = map_record(rec("cowrie.command.failed", input="frobnicate"), ingest_ts=INGEST)
    assert ev.outcome is Outcome.FAILURE and ev.payload["command"] == "frobnicate"


def test_kex_fields_canonical():
    ev = map_record(
        rec(
            "cowrie.client.kex",
            hassh="abc",
            hasshAlgorithms="x;y;z;w",
            kexAlgs=["curve25519-sha256"],
        ),
        ingest_ts=INGEST,
    )
    assert ev.payload["hassh"] == "abc"
    assert ev.payload["hassh_algorithms"] == "x;y;z;w"
    assert ev.payload["kex_algs"] == ["curve25519-sha256"]


def test_download():
    ev = map_record(
        rec("cowrie.session.file_download", url="http://x/m", shasum="ff" * 32, outfile="dl/ff"),
        ingest_ts=INGEST,
    )
    assert ev.event_class is EventClass.FILE_ACTIVITY
    assert ev.payload["sha256"] == "ff" * 32


def test_tunnel_request_does_not_overwrite_honeypot_dst():
    ev = map_record(
        rec(
            "cowrie.direct-tcpip.request", dst_ip="93.184.216.34", dst_port=443, orig_ip="127.0.0.1"
        ),
        ingest_ts=INGEST,
    )
    assert ev.dst.ip is None
    assert ev.payload["requested_dst_ip"] == "93.184.216.34"
    assert ev.payload["requested_dst_port"] == 443


def test_unknown_eventid_kept():
    ev = map_record(rec("cowrie.brand.new", foo=1), ingest_ts=INGEST)
    assert ev.event_class is EventClass.UNKNOWN
    assert ev.action == "brand.new"
    assert ev.raw["foo"] == 1


def test_event_id_is_deterministic():
    r = rec("cowrie.command.input", input="id")
    assert (
        map_record(r, ingest_ts=INGEST).event_id == map_record(dict(r), ingest_ts=INGEST).event_id
    )
    assert (
        map_record(r, ingest_ts=INGEST).event_id
        != map_record(rec("cowrie.command.input", input="ls"), ingest_ts=INGEST).event_id
    )


def test_missing_eventid_raises():
    with pytest.raises(KeyError):
        map_record({"timestamp": "2026-11-11T12:00:00Z"})


@pytest.mark.skipif(not UPSTREAM_DOC.exists(), reason="upstream Cowrie checkout not present")
def test_every_documented_session_event_is_mapped():
    documented = set(re.findall(r"^(cowrie\.[a-z0-9_.-]+)\n=+$", UPSTREAM_DOC.read_text(), re.M))
    # Operational and enrichment events (third-party lookups, proxy-mode plumbing) are not
    # attacker activity; they fall through to class "unknown" by design.
    operational = (
        "cowrie.abuseipdb.",
        "cowrie.greynoise.",
        "cowrie.reversedns.",
        "cowrie.urlhaus.",
        "cowrie.malwarebazaar.",
        "cowrie.virustotal.",
        "cowrie.proxy.",
    )
    expected = {e for e in documented if not e.startswith(operational)}
    assert expected - TABLE.keys() == set()
