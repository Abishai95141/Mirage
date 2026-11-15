"""The action mask (spec 2.5): what each protocol can express, and the first input."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mirage_policy.app import RULES_DIR, Settings, create_app
from mirage_policy.explore import EXPRESSIBLE, allowed_actions, expressible, is_first_input
from mirage_schema.policy import Action, DecideRequest, Protocol

TOKEN = "t" * 32
EXPLORE_IP = "198.19.0.7"
ALL = ["allow", "delay", "fake_success", "fake_error", "terminate"]

# One ordinary input per protocol, as its decoy sends it.
INPUTS = {
    "ssh": {"argv": ["uname", "-a"]},
    "http": {"method": "GET", "path": "/.env"},
    "redis": {"argv": ["CONFIG", "GET", "dir"]},
    "mysql": {"command": "COM_QUERY", "sql": "SHOW DATABASES"},
}


def req(protocol: str = "ssh", seq: int | None = 2, **over) -> DecideRequest:
    base = {"request_id": "r", "session_id": "s1", "protocol": protocol, "seq": seq}
    return DecideRequest.model_validate({**base, **INPUTS[protocol], **over})


# ------------------------------------------------------------------ per protocol


@pytest.mark.parametrize("protocol", sorted(INPUTS))
def test_the_allowed_set_of_each_protocol_is_pinned(protocol):
    # Every decoy honours all five actions (see the handler citations beside EXPRESSIBLE), so
    # the only thing the mask removes from an ordinary input is terminate on the first one.
    # If a decoy stops honouring an action, EXPRESSIBLE changes and this test says where.
    assert [a.value for a in allowed_actions(req(protocol, seq=2))] == ALL
    assert [a.value for a in allowed_actions(req(protocol, seq=1))] == ALL[:-1]


def test_every_protocol_has_an_entry_and_allow_is_always_expressible():
    assert set(EXPRESSIBLE) == set(Protocol)
    assert all(Action.ALLOW in actions for actions in EXPRESSIBLE.values())


@pytest.mark.parametrize("word", ["Host:", "host:", "HOST:"])
def test_the_redis_gopher_line_can_only_be_allowed(word):
    # redis/handler.py:223-241 asks the gate and then ignores the answer for this input.
    gopher = req("redis", seq=3, argv=[word, "example.org"])
    assert expressible(gopher) == {Action.ALLOW}
    assert allowed_actions(gopher) == [Action.ALLOW]
    # the same word is an ordinary input anywhere else, and an ordinary Redis command is too
    assert allowed_actions(req("ssh", seq=3, argv=[word, "example.org"])) == list(Action)
    assert allowed_actions(req("redis", seq=3, argv=["HOSTS", "x"])) == list(Action)


# ------------------------------------------------------------------ the first input


def test_seq_decides_the_first_input_when_the_decoy_sends_it():
    assert is_first_input(req(seq=0)) and is_first_input(req(seq=1))
    assert not is_first_input(req(seq=2))
    # the decoy's number wins over the service's count (a service restarted mid-session)
    assert not is_first_input(req(seq=7), inputs_so_far=0)
    assert is_first_input(req(seq=1), inputs_so_far=5)


def test_a_missing_seq_falls_back_to_the_services_count():
    assert is_first_input(req(seq=None), inputs_so_far=0)
    assert not is_first_input(req(seq=None), inputs_so_far=1)
    assert Action.TERMINATE not in allowed_actions(req(seq=None), inputs_so_far=0)
    assert Action.TERMINATE in allowed_actions(req(seq=None), inputs_so_far=1)


# ------------------------------------------------------------------ the service


def service(tmp_path: Path, monkeypatch) -> tuple[TestClient, Path]:
    monkeypatch.setenv("POLICY_EXPLORE", "lab")
    monkeypatch.delenv("POLICY_TECHNIQUE_RULES", raising=False)
    log = tmp_path / "decisions.json"
    settings = Settings(token=TOKEN, log_path=log, rule_files=[RULES_DIR / "default.yaml"])
    return TestClient(create_app(settings, rng=random.Random(3))), log


def post(c: TestClient, **body):
    body = {"request_id": "r", "protocol": "ssh", "argv": ["id"], "src": {"ip": EXPLORE_IP}, **body}
    r = c.post("/v1/decide", json=body, headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200, r.text
    return r.json()


def records(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text().splitlines()]


def test_a_session_without_seq_is_masked_once_not_for_ever(tmp_path, monkeypatch):
    c, log = service(tmp_path, monkeypatch)
    for _ in range(3):
        post(c, session_id="no-seq")
    first, second, third = records(log)
    assert "terminate" not in first["allowed"]
    assert "terminate" in second["allowed"] and "terminate" in third["allowed"]
    assert [r["context"]["inputs_so_far"] for r in (first, second, third)] == [0, 1, 2]


def test_without_seq_or_session_every_request_is_a_first_input(tmp_path, monkeypatch):
    c, log = service(tmp_path, monkeypatch)
    for _ in range(3):
        post(c)
    assert all("terminate" not in r["allowed"] for r in records(log))


def test_terminate_can_be_explored_after_the_first_input_without_seq(tmp_path, monkeypatch):
    c, log = service(tmp_path, monkeypatch)
    for i in range(400):
        post(c, session_id=f"s{i % 4}")  # four long sessions, none sending seq
    rows = records(log)
    assert any(r["action"] == "terminate" for r in rows)
    assert all(r["action"] in r["allowed"] for r in rows)
    assert all(r["action"] != "terminate" for r in rows if r["context"]["inputs_so_far"] == 0)


def test_the_exploring_policy_never_picks_what_the_gopher_line_cannot_express(
    tmp_path, monkeypatch
):
    c, log = service(tmp_path, monkeypatch)
    for i in range(200):
        d = post(c, protocol="redis", argv=["Host:", "example.org"], session_id="g", seq=i + 2)
        assert d["action"] == "allow" and d["propensity"] == 1.0
    for r in records(log):
        assert r["explore"] is True and r["allowed"] == ["allow"]
        assert r["acting"]["probs"] == {"allow": 1.0} and r["shadow"]["probs"] == {"allow": 1.0}
