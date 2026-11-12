"""Sessioniser logic: HTTP session boundaries, honeytoken findings and links, actor IDs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from mirage_pipeline.analyst import Analyst, Components
from mirage_pipeline.artifacts import detect, index_file, parse_dirs
from mirage_pipeline.sessioniser import fingerprints
from mirage_schema.mappings import cowrie, decoy
from mirage_tokens import Token

T0 = datetime(2026, 11, 1, 10, 0, 0, tzinfo=UTC)  # in the past: events cannot postdate ingest
PW = "Prod6227!yQxWU"
TOKENS = [
    Token(
        "tok-cred",
        "credential",
        PW,
        "dep",
        "ssh:/var/www/html/.env, http:/.env",
        "2026-06-01T00:00:00Z",
        username="wp_user",
    ),
    Token("tok-url", "url", "/backup-o3tmfojm7s", "dep", "http:/robots.txt", "2026-06-01"),
]


def ts(s: float) -> str:
    return (T0 + timedelta(seconds=s)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ssh(eventid: str, session: str, at: float, src: str = "198.51.100.7", **kw):
    return cowrie.map_record(
        {
            "eventid": eventid,
            "timestamp": ts(at),
            "session": session,
            "sensor": "dep",
            "src_ip": src,
            "src_port": 40000,
            "dst_ip": "10.0.0.2",
            "dst_port": 2222,
            "protocol": "ssh",
            **kw,
        }
    )


def http(event: str, conn: str, at: float, src: str = "203.0.113.9", **kw):
    return decoy.map_record(
        {
            "eventid": f"http.{event}",
            "timestamp": ts(at),
            "session": conn,
            "sensor": "dep",
            "protocol": "http",
            "src_ip": src,
            "src_port": 50000,
            "dst_ip": "10.0.0.3",
            "dst_port": 8080,
            **kw,
        }
    )


def request(conn: str, at: float, path: str, ua: str = "curl/8.5", src: str = "203.0.113.9"):
    return http(
        "request",
        conn,
        at,
        src,
        method="GET",
        path=path,
        target=path,
        headers=[["Host", "x"], ["User-Agent", ua]],
        user_agent=ua,
        body={"size": 0, "sha256": "e3b0", "text": ""},
    )


def test_http_connections_group_by_source_and_user_agent_until_idle():
    a = Analyst([])
    # Before any request a connection is not a session yet.
    assert a.process(http("session.connect", "c1", 0)).touched == set()
    first = a.process(request("c1", 1, "/")).touched
    same = a.process(request("c2", 60, "/robots.txt")).touched
    other_ua = a.process(request("c3", 61, "/", ua="Mozilla/5.0")).touched
    later = a.process(request("c4", 61 + 31 * 60, "/")).touched
    assert first == same
    assert first != other_ua
    assert later != first
    assert a.conn_map["c1"] == a.conn_map["c2"] != a.conn_map["c4"]
    # Events after the first request follow the connection into the session.
    assert a.process(http("session.closed", "c1", 2)).touched == first


def test_token_read_over_ssh_then_used_over_http_links_the_sessions():
    a = Analyst(TOKENS)
    a.process(ssh("cowrie.session.connect", "s1", 0))
    ch = a.process(ssh("cowrie.command.input", "s1", 5, input="cat /var/www/html/.env"))
    assert [e.token_id for e in ch.exposures] == ["tok-cred"]
    login = http("login.failed", "c9", 30, username="wp_user", password=PW, form="/wp-login.php")
    a.process(request("c9", 29, "/wp-login.php"))
    ch = a.process(login)
    assert [f.payload["token_id"] for f in ch.findings] == ["tok-cred"]
    finding = ch.findings[0]
    assert finding.action == "token_triggered"
    assert finding.payload["exposed_in"] == ["s1"]
    hs = a.conn_map["c9"]
    assert [(lk.reason, {lk.a, lk.b}) for lk in ch.links if lk.reason == "honeytoken"] == [
        ("honeytoken", {"s1", hs})
    ]
    assert a.components.actor_id("s1") == a.components.actor_id(hs)


def test_use_seen_before_exposure_still_links():
    # Vector tails each decoy's log separately, so the use can arrive first.
    a = Analyst(TOKENS)
    a.process(request("c1", 29, "/wp-login.php"))
    used = a.process(
        http("login.failed", "c1", 30, username="wp_user", password=PW, form="/wp-login.php")
    )
    assert used.findings and not [lk for lk in used.links if lk.reason == "honeytoken"]
    late = a.process(ssh("cowrie.command.input", "s1", 5, input="cd /var/www/html; cat .env"))
    assert [lk.reason for lk in late.links if lk.reason == "honeytoken"] == ["honeytoken"]


def test_exposure_after_use_does_not_link():
    a = Analyst(TOKENS)
    a.process(ssh("cowrie.login.failed", "s1", 1, username="wp_user", password=PW))
    ch = a.process(ssh("cowrie.command.input", "s2", 9, src="192.0.2.1", input="cat .env"))
    assert not [lk for lk in ch.links if lk.reason == "honeytoken"]


def test_use_in_the_exposing_session_is_a_finding_without_a_link():
    a = Analyst(TOKENS)
    a.process(ssh("cowrie.command.input", "s1", 1, input="cat /var/www/html/.env"))
    ch = a.process(ssh("cowrie.command.input", "s1", 2, input=f"mysql -u wp_user -p{PW}"))
    assert len(ch.findings) == 1 and not ch.links


def test_url_token_and_policy_echo_counted_once():
    a = Analyst(TOKENS)
    decision = http(
        "policy.decision",
        "c1",
        0,
        seq=1,
        request_id="r",
        input="GET /backup-o3tmfojm7s",
        action="allow",
        fallback=False,
    )
    assert a.process(decision).findings == []
    ch = a.process(request("c1", 1, "/backup-o3tmfojm7s"))
    assert [f.payload["token_id"] for f in ch.findings] == ["tok-url"]
    # The same event again (a redelivered batch) gives no second finding.
    assert a.process(request("c1", 1, "/backup-o3tmfojm7s")).findings == []


def test_same_source_and_fingerprint_links():
    a = Analyst([])
    for sid, at in (("s1", 0), ("s2", 100)):
        a.process(ssh("cowrie.session.connect", sid, at))
        a.process(ssh("cowrie.client.version", sid, at + 1, version="SSH-2.0-Go"))
        a.process(ssh("cowrie.client.kex", sid, at + 2, hassh="abc"))
        ch = a.process(ssh("cowrie.login.failed", sid, at + 3, username="root", password="x"))
    reasons = {r for *_, r in a.linked}
    assert reasons == {"same_source_24h", "ssh_fingerprint_credential"}
    assert ch.links[0].evidence["hassh"] == "abc"
    a.process(ssh("cowrie.session.connect", "s3", 100 + 25 * 3600))
    assert a.components.actor_id("s3") != a.components.actor_id("s1")


def test_actor_id_is_independent_of_link_order():
    one, two = Components(), Components()
    for x, y in (("b", "c"), ("a", "b"), ("d", "e")):
        one.union(x, y)
    for x, y in (("d", "e"), ("a", "b"), ("c", "b")):
        two.union(x, y)
    assert one.actor_id("c") == two.actor_id("c") == two.actor_id("a")
    assert one.actor_id("d") != one.actor_id("a")


def test_fingerprints():
    fp = fingerprints(
        {"hassh": "h", "client_version": "SSH-2.0-x", "headers": '[["Host","x"],["Accept","*"]]'}
    )
    assert fp["hassh"] == "h" and len(fp["header_order"]) == 16


def test_artifact_indexer_hashes_and_types(tmp_path):
    import hashlib

    data = b"\x7fELF\x02\x01\x01" + b"\0" * 100
    digest = hashlib.sha256(data).hexdigest()
    (tmp_path / digest).write_bytes(data)
    (tmp_path / ".partial").write_bytes(b"x")
    row = index_file("http", tmp_path / digest)
    assert row is not None
    assert row["sha256"] == digest and row["size"] == len(data) and row["name_matches"] == 1
    assert index_file("http", tmp_path / ".partial") is None
    assert detect(b"hello\n") == "text/plain"
    assert detect(b"") == "application/x-empty"
    assert parse_dirs("cowrie=/a,http=/b") == [("cowrie", Path("/a")), ("http", Path("/b"))]
