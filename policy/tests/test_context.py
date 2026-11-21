"""The context map, the verb classes and the decision record's new fields (spec 2.5, R6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mirage_policy import verbs
from mirage_policy.app import RULES_DIR, Settings, create_app
from mirage_policy.explore import CONTEXT_VERSION, IDLE_RESET_S, Context
from mirage_policy.fake_errors import FakeErrors
from mirage_policy.verbs import VERB_CLASSES, verb_class, verb_key
from mirage_schema.mappings.policy import map_record
from mirage_schema.policy import DecideRequest, Protocol

TOKEN = "t" * 32
EXPLORE_IP = "198.19.0.7"


def req(session: str | None = "s1", protocol: str = "ssh", **over) -> DecideRequest:
    base = {"request_id": "r", "session_id": session, "protocol": protocol}
    if protocol in ("ssh", "redis"):
        base["argv"] = ["uname", "-a"]
    return DecideRequest.model_validate({**base, **over})


# ------------------------------------------------------------------ eviction (R6)


def test_the_session_map_evicts_the_least_recently_used_not_the_oldest():
    ctx = Context(max_sessions=3)
    ctx.observe(req("long"), None)  # the oldest session, and the one that keeps talking
    for i in range(10):
        ctx.observe(req(f"short{i}"), None)
        f = ctx.observe(req("long"), "TA0007" if i == 0 else None)
        # creation-order eviction would have dropped "long" here and restarted it at 0
        assert f["inputs_so_far"] == i + 1
    assert f["last_tactic"] == "TA0007"
    assert len(ctx._sessions) == 3 and "long" in ctx._sessions


def test_an_idle_session_is_the_one_evicted():
    ctx = Context(max_sessions=2)
    ctx.observe(req("idle"), None)
    ctx.observe(req("busy"), None)
    ctx.observe(req("busy"), None)
    ctx.observe(req("new"), None)  # over the bound: "idle" was used longest ago
    assert set(ctx._sessions) == {"busy", "new"}
    assert ctx.observe(req("busy"), None)["inputs_so_far"] == 2  # kept, and now the freshest
    assert ctx.observe(req("idle"), None)["inputs_so_far"] == 0  # it starts again
    assert set(ctx._sessions) == {"busy", "idle"}  # "new" was the least recently used


def test_a_session_idle_for_too_long_starts_again():
    clock = {"t": 0.0}
    ctx = Context(now=lambda: clock["t"])
    ctx.observe(req("a"), "TA0007")
    clock["t"] = IDLE_RESET_S + 1.0
    f = ctx.observe(req("a"), None)
    assert (f["inputs_so_far"], f["last_tactic"], f["seconds_since_last"]) == (0, None, None)


# ------------------------------------------------------------------ seen before (R6)


def test_seen_before_is_per_process_and_the_session_one_has_its_own_name():
    ctx = Context()
    a1 = ctx.observe(req("a"), None)
    assert (a1["seen_before"], a1["seen_before_in_session"]) == (False, False)
    b1 = ctx.observe(req("b"), None)  # another session sends the same input
    assert (b1["seen_before"], b1["seen_before_in_session"]) == (True, False)
    a2 = ctx.observe(req("a"), None)
    assert (a2["seen_before"], a2["seen_before_in_session"]) == (True, True)
    other = ctx.observe(req("a", argv=["id"]), None)
    assert (other["seen_before"], other["seen_before_in_session"]) == (False, False)


def test_requests_without_a_session_still_count_for_the_process():
    ctx = Context()
    assert ctx.observe(req(None), None)["seen_before"] is False
    f = ctx.observe(req(None), None)
    assert (f["seen_before"], f["seen_before_in_session"], f["inputs_so_far"]) == (True, False, 0)


def test_the_same_text_on_another_protocol_is_a_different_input():
    ctx = Context()
    ctx.observe(req("a", protocol="redis", argv=["GET", "/"]), None)
    http = ctx.observe(req("b", protocol="http", method="GET", path="/"), None)
    assert http["seen_before"] is False
    assert ctx.observe(req("c", protocol="redis", argv=["GET", "/"]), None)["seen_before"] is True


def test_the_process_memory_is_bounded_and_forgets_the_least_recently_seen():
    ctx = Context(process_seen_cap=3)
    for word in ("a", "b", "c"):
        ctx.observe(req(word, argv=[word]), None)
    assert ctx.observe(req("x", argv=["a"]), None)["seen_before"] is True  # "a" is fresh again
    ctx.observe(req("y", argv=["d"]), None)  # a fourth input: "b" is the one forgotten
    assert len(ctx._seen_in_process) == 3
    assert ctx.observe(req("z", argv=["a"]), None)["seen_before"] is True
    assert ctx.observe(req("z", argv=["b"]), None)["seen_before"] is False
    for i in range(1000):
        ctx.observe(req(None, argv=[f"cmd{i}"]), None)
    assert len(ctx._seen_in_process) == 3


# ------------------------------------------------------------------ verb classes


@pytest.mark.parametrize(
    ("body", "key", "cls"),
    [
        ({"protocol": "ssh", "argv": ["cat", "/etc/passwd"]}, "cat", "file_read"),
        ({"protocol": "ssh", "argv": ["/usr/bin/wget", "http://x/"]}, "wget", "network"),
        ({"protocol": "ssh", "argv": ["A=1", "B=2", "apt-get", "update"]}, "apt-get", "package"),
        ({"protocol": "ssh", "argv": ["chmod", "+x", "m"]}, "chmod", "file_write"),
        ({"protocol": "ssh", "argv": ["ps", "aux"]}, "ps", "process"),
        ({"protocol": "ssh", "argv": ["uname", "-a"]}, "uname", "system_info"),
        ({"protocol": "ssh", "argv": ["sudo", "id"]}, "sudo", "privilege"),
        ({"protocol": "ssh", "argv": ["python3", "-c", "1"]}, "python3", "interpreter"),
        ({"protocol": "ssh", "argv": ["cd", "/tmp"]}, "cd", "shell_builtin"),
        ({"protocol": "ssh", "argv": ["CAT", "x"]}, "CAT", "other"),  # a shell is case-sensitive
        ({"protocol": "ssh", "argv": ["frobnicate"]}, "frobnicate", "other"),
        ({"protocol": "ssh", "argv": ["X=1"]}, "", "other"),
        ({"protocol": "ssh"}, "", "other"),
        ({"protocol": "http", "method": "GET", "path": "/"}, "GET", "read"),
        ({"protocol": "http", "method": "post", "path": "/"}, "POST", "write"),
        ({"protocol": "http", "method": "PROPFIND", "path": "/"}, "PROPFIND", "other"),
        ({"protocol": "http"}, "", "other"),
        ({"protocol": "redis", "argv": ["keys", "*"]}, "KEYS", "read"),
        ({"protocol": "redis", "argv": ["SET", "k", "v"]}, "SET", "write"),
        ({"protocol": "redis", "argv": ["config", "set", "dir", "/"]}, "CONFIG", "admin"),
        ({"protocol": "redis", "argv": ["EVAL", "return 1", "0"]}, "EVAL", "script"),
        ({"protocol": "redis", "argv": ["AUTH", "x"]}, "AUTH", "session"),
        ({"protocol": "redis", "argv": ["Host:", "x"]}, "HOST:", "other"),
        ({"protocol": "mysql", "sql": "select 1"}, "SELECT", "read"),
        ({"protocol": "mysql", "sql": " INSERT INTO t VALUES (1)"}, "INSERT", "write"),
        ({"protocol": "mysql", "sql": "DROP TABLE t"}, "DROP", "schema"),
        ({"protocol": "mysql", "sql": "SET NAMES utf8"}, "SET", "admin"),
        ({"protocol": "mysql", "command": "COM_PING"}, "COM_PING", "session"),
        ({"protocol": "mysql", "sql": "/*!40101 SET x=1 */"}, "/*!40101", "other"),
        ({"protocol": "mysql", "command": "COM_0x1F"}, "COM_0X1F", "other"),
    ],
)
def test_a_verb_maps_to_its_class_and_an_unknown_one_to_other(body, key, cls):
    r = DecideRequest.model_validate({"request_id": "r", **body})
    assert (verb_key(r), verb_class(r)) == (key, cls)


def test_the_class_vocabulary_is_fixed():
    # A model is trained on these names: changing them needs a new verbs.VERSION.
    assert verbs.VERSION == "1"
    assert VERB_CLASSES == {
        Protocol.SSH: (
            "file_read",
            "file_write",
            "network",
            "package",
            "process",
            "system_info",
            "privilege",
            "interpreter",
            "shell_builtin",
            "other",
        ),
        Protocol.HTTP: ("read", "write", "other"),
        Protocol.REDIS: ("read", "write", "admin", "script", "session", "other"),
        Protocol.MYSQL: ("read", "write", "schema", "admin", "session", "other"),
    }


def test_the_context_carries_the_class_beside_the_raw_verb():
    f = Context().observe(req(argv=["LANG=C", "/bin/cat", "/etc/passwd"]), None)
    assert (f["verb"], f["verb_class"]) == ("LANG=C", "file_read")  # the raw verb is unchanged
    f = Context().observe(req(protocol="redis", argv=["flushall"]), None)
    assert (f["verb"], f["verb_class"]) == ("FLUSHALL", "write")


# ------------------------------------------------------------------ the decision record


def service(tmp_path: Path, monkeypatch) -> tuple[TestClient, Path]:
    monkeypatch.setenv("POLICY_EXPLORE", "lab")
    monkeypatch.delenv("POLICY_TECHNIQUE_RULES", raising=False)
    log = tmp_path / "decisions.json"
    settings = Settings(token=TOKEN, log_path=log, rule_files=[RULES_DIR / "default.yaml"])
    return TestClient(create_app(settings)), log


def decide(c: TestClient, ip: str, **over) -> dict:
    body = {
        "request_id": "req-1",
        "session_id": "s1",
        "deployment_id": "dep-1",
        "protocol": "ssh",
        "argv": ["cat", "/etc/passwd"],
        "seq": 2,
        "src": {"ip": ip, "port": 40000},
        **over,
    }
    r = c.post("/v1/decide", json=body, headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.parametrize("ip", [EXPLORE_IP, "203.0.113.9"])
def test_every_decision_logs_policies_versions_and_the_verb_class(tmp_path, monkeypatch, ip):
    c, log = service(tmp_path, monkeypatch)
    sent = decide(c, ip)
    (r,) = (json.loads(line) for line in log.read_text().splitlines())
    explored = ip == EXPLORE_IP
    assert r["explore"] is explored
    # the rule set's version, in the record and in the response as before
    assert r["rules_version"] == sent["rules_version"] and len(r["rules_version"]) == 12
    # the acting policy: name and version
    acting = r["acting"]
    if explored:
        assert (acting["name"], acting["version"]) == ("epsilon-greedy-v0(eps=0.3)", "0")
        assert acting["rules_version"] == r["rules_version"]
        assert (
            acting["fake_errors_version"] == FakeErrors.load(RULES_DIR / "fake_errors.yaml").version
        )
        assert list(acting["probs"]) == r["allowed"]
    else:
        assert (acting["name"], acting["version"]) == ("rules", r["rules_version"])
    assert acting["action"] == r["action"] == sent["action"]
    assert acting["propensity"] == r["propensity"] == sent["propensity"]
    # the shadow policy: name, version, and a probability for every allowed action
    shadow = r["shadow"]
    assert shadow["name"] and shadow["version"] and list(shadow["probs"]) == r["allowed"]
    # the context: the class beside the raw verb, and which feature set this is
    assert (r["context"]["verb"], r["context"]["verb_class"]) == ("cat", "file_read")
    assert r["context"]["rule_action"] == "allow"
    assert r["context_version"] == f"{CONTEXT_VERSION}.{verbs.VERSION}" == "3.1"
    # every field the record had before is still there
    for old in ("eventid", "timestamp", "request", "input", "action", "decision_id", "latency_us"):
        assert old in r
    for old in ("protocol", "verb", "known", "inputs_so_far", "seconds_since_last", "last_tactic"):
        assert old in r["context"]
    assert "seen_before" in r["context"]


def test_the_pipeline_mapping_still_reads_the_record(tmp_path, monkeypatch):
    c, log = service(tmp_path, monkeypatch)
    decide(c, EXPLORE_IP)
    decide(c, "203.0.113.9", request_id="req-2")
    for line in log.read_text().splitlines():
        record = json.loads(line)
        event = map_record(record)
        p = event.payload
        assert p["rules_version"] == record["rules_version"] and p["rule_id"] == "default-allow"
        assert p["context"]["verb_class"] == "file_read" and p["allowed"] == record["allowed"]
        assert p["acting"]["version"] and p["shadow"]["version"] and p["shadow"]["probs"]
        assert p["explore"] is record["explore"]
        assert event.policy.action == record["action"]
        assert event.policy.propensity == record["propensity"]
        assert event.raw["context_version"] == "3.1"  # not in the payload: see the mapping
