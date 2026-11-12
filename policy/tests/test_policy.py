import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from mirage_policy.app import RULES_DIR, Settings, create_app
from mirage_policy.rules import RuleSet
from mirage_schema.policy import MAX_OUTPUT_BYTES, DecideRequest

TOKEN = "t" * 32


def client(tmp_path: Path, selftest: bool = True) -> tuple[TestClient, Path]:
    files = ([RULES_DIR / "selftest.yaml"] if selftest else []) + [RULES_DIR / "default.yaml"]
    log = tmp_path / "decisions.json"
    app = create_app(Settings(token=TOKEN, log_path=log, rule_files=files))
    return TestClient(app), log


def post(c: TestClient, body: dict, token: str = TOKEN):
    return c.post("/v1/decide", json=body, headers={"Authorization": f"Bearer {token}"})


SSH = {
    "request_id": "r1",
    "session_id": "s1",
    "protocol": "ssh",
    "argv": ["uname", "-a"],
    "known": True,
}


def test_default_allows_every_protocol(tmp_path):
    c, _ = client(tmp_path, selftest=False)
    bodies = [
        SSH,
        {"request_id": "r2", "protocol": "http", "method": "GET", "path": "/.env"},
        {"request_id": "r3", "protocol": "redis", "argv": ["CONFIG", "SET", "dir", "/root/.ssh"]},
        {"request_id": "r4", "protocol": "mysql", "command": "COM_QUERY", "sql": "SHOW DATABASES"},
    ]
    for b in bodies:
        r = post(c, b)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["action"] == "allow" and d["rule_id"] == "default-allow"
        assert d["propensity"] == 1.0 and len(d["rules_version"]) == 12 and d["decision_id"]


@pytest.mark.parametrize(
    ("argv", "action", "extra"),
    [
        (["mirage-selftest-fake-success"], "fake_success", {"output": "selftest ok\n"}),
        (["mirage-selftest-fake-error"], "fake_error", {"exit_code": 2}),
        (["mirage-selftest-delay"], "delay", {"delay_ms": 300}),
        (["mirage-selftest-terminate"], "terminate", {}),
    ],
)
def test_selftest_rule_per_action(tmp_path, argv, action, extra):
    c, _ = client(tmp_path)
    d = post(c, {**SSH, "argv": argv, "known": False}).json()
    assert d["action"] == action
    for k, v in extra.items():
        assert d[k] == v


def test_http_path_rule_and_status(tmp_path):
    c, _ = client(tmp_path)
    d = post(
        c,
        {
            "request_id": "h",
            "protocol": "http",
            "method": "GET",
            "path": "/mirage-selftest-http-error",
        },
    ).json()
    assert d["action"] == "fake_error" and d["exit_code"] == 418


def test_auth_required(tmp_path):
    c, log = client(tmp_path)
    assert post(c, SSH, token="wrong" * 8).status_code == 401
    assert c.post("/v1/decide", json=SSH).status_code == 401
    assert log.read_text() == ""


def test_malformed_requests_rejected(tmp_path):
    c, _ = client(tmp_path)
    assert post(c, {"protocol": "ssh"}).status_code == 422  # no request_id
    assert post(c, {"request_id": "x", "protocol": "smtp"}).status_code == 422
    r = c.post("/v1/decide", content=b"{not json", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 422


def test_unknown_fields_ignored(tmp_path):
    c, _ = client(tmp_path)
    assert post(c, {**SSH, "future_field": 1}).status_code == 200


def test_decision_log_records_request_rule_and_latency(tmp_path):
    c, log = client(tmp_path)
    post(c, {**SSH, "src": {"ip": "203.0.113.9", "port": 51000}, "seq": 3})
    rec = json.loads(log.read_text().splitlines()[0])
    assert rec["eventid"] == "policy.decision"
    assert rec["request"]["request_id"] == "r1" and rec["request"]["seq"] == 3
    assert rec["input"] == "uname -a" and rec["rule_id"] == "default-allow"
    assert rec["latency_us"] >= 0 and rec["timestamp"].endswith("Z")


def _write(tmp_path: Path, rules: list[dict]) -> Path:
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump({"version": 1, "rules": rules}))
    return p


CATCH_ALL = {"id": "all", "action": "allow"}


@pytest.mark.parametrize(
    "bad",
    [
        [{"id": "x", "action": "fake_success", "output": "a" * (MAX_OUTPUT_BYTES + 1)}, CATCH_ALL],
        [{"id": "x", "action": "delay", "delay_ms": 10_001}, CATCH_ALL],
        [{"id": "x", "action": "allow", "output": "nope"}, CATCH_ALL],
        [{"id": "x", "action": "plant_token"}, CATCH_ALL],  # not in the phase 1 action set
        [{"id": "x", "action": "allow", "when": {"input_regex": "("}}, CATCH_ALL],
        [{"id": "x", "action": "allow", "when": {"protocol": "ssh"}}],  # no catch-all
        [CATCH_ALL, CATCH_ALL],  # duplicate id
        [{"id": "x", "action": "allow", "when": {"colour": "red"}}, CATCH_ALL],
    ],
)
def test_invalid_rule_files_refused_at_load(tmp_path, bad):
    with pytest.raises(ValueError):
        RuleSet.load(_write(tmp_path, bad))


def test_matching_semantics(tmp_path):
    rs = RuleSet.load(
        _write(
            tmp_path,
            [
                {
                    "id": "redis-config",
                    "when": {"protocol": "redis", "verb": "config"},
                    "action": "fake_error",
                    "output": "ERR",
                },
                {
                    "id": "sql-drop",
                    "when": {"protocol": "mysql", "verb": "DROP"},
                    "action": "terminate",
                },
                {
                    "id": "unknown-ssh",
                    "when": {"protocol": "ssh", "known": False},
                    "action": "fake_error",
                },
                CATCH_ALL,
            ],
        )
    )
    r = lambda **kw: rs.decide(DecideRequest(request_id="x", **kw)).id  # noqa: E731
    assert r(protocol="redis", argv=["CONFIG", "GET", "dir"]) == "redis-config"
    assert r(protocol="redis", argv=["config", "get", "dir"]) == "redis-config"
    assert r(protocol="mysql", sql="  drop table users") == "sql-drop"
    assert r(protocol="ssh", argv=["nmap"], known=False) == "unknown-ssh"
    assert r(protocol="ssh", argv=["ls"], known=True) == "all"
    assert r(protocol="ssh", argv=["CONFIG"]) == "all"  # verb rule was redis-only


def test_rules_version_changes_with_content(tmp_path):
    a = RuleSet.load(_write(tmp_path, [CATCH_ALL])).version
    b = RuleSet.load(_write(tmp_path, [{"id": "other", "action": "allow"}])).version
    assert a != b
