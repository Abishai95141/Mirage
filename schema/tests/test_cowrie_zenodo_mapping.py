from datetime import UTC, datetime

from mirage_schema import EventClass, Outcome
from mirage_schema.mappings.cowrie_zenodo import DATASET, map_record

INGEST = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)

# Shape of a row in the corpus (abridged; unused columns are null).
ROW = {
    "ts": "2025-06-27 23:09:31.604633",
    "ts_indexed": "2025-06-27 23:09:31",
    "id": 12345,
    "eventid": "cowrie.login.success",
    "session": "e500e363a13b",
    "sensor": "e9f16d233101",
    "group": 1,
    "username": "root",
    "password": "yhtcAdmin",
    "input": None,
    "message": "login attempt [root/yhtcAdmin] succeeded",
    "protocol": None,
    "src_ip": "203.0.113.7",
    "src_port": None,
    "dst_ip": None,
    "dst_port": None,
    "honeypot_ip": "198.51.100.20",
    "src_ip_geoip_asn_number": "64500",
    "src_ip_geoip_country_iso_code": "NL",
    "src_ip_geoip_city_name": None,
    "honeypot_ip_geoip_country_iso_code": "DE",
}


def test_corpus_row_maps():
    ev = map_record(ROW, ingest_ts=INGEST)
    assert ev.event_class is EventClass.AUTHENTICATION and ev.outcome is Outcome.SUCCESS
    assert ev.ts == datetime(2025, 6, 27, 23, 9, 31, 604633, tzinfo=UTC)
    assert ev.protocol == "ssh"
    assert str(ev.src.ip) == "203.0.113.7" and ev.src.asn == 64500 and ev.src.country == "NL"
    assert str(ev.dst.ip) == "198.51.100.20"
    assert ev.payload == {
        "username": "root",
        "password": "yhtcAdmin",
        "dataset": DATASET,
        "deployment_group": 1,
    }
    assert ev.raw == ROW


def test_null_columns_do_not_reach_payload():
    ev = map_record(
        ROW | {"eventid": "cowrie.command.input", "input": "uname -a"}, ingest_ts=INGEST
    )
    assert ev.payload["command"] == "uname -a"
    assert None not in ev.payload.values()
    assert not any(k.startswith("src_ip_geoip") for k in ev.payload)


def test_pseudonymised_addresses():
    ev = map_record(ROW | {"src_ip": "2d8e5953", "honeypot_ip": "9a1b"}, ingest_ts=INGEST)
    assert ev.src.ip is None and ev.src.pseudonym == "2d8e5953"
    assert ev.dst.ip is None and ev.dst.pseudonym == "9a1b"
    # The model must still be valid once serialised and read back.
    assert type(ev).model_validate_json(ev.to_json()).src.pseudonym == "2d8e5953"


def test_bad_asn_ignored():
    ev = map_record(ROW | {"src_ip_geoip_asn_number": "n/a"}, ingest_ts=INGEST)
    assert ev.src.asn is None
