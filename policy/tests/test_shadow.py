"""The pluggable shadow policy: the interface, the loader and its fallback (spec 2.5, V13)."""

from __future__ import annotations

import json
import logging
import random
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mirage_policy import shadow as shadow_module
from mirage_policy.app import RULES_DIR, Settings, create_app
from mirage_policy.explore import ACTIONS, BanditPolicy
from mirage_policy.shadow import (
    FALLBACK_NAME,
    FallbackShadow,
    ShadowPolicy,
    distribution,
    file_version,
    load_shadow,
    register_loader,
)
from mirage_policy.verbs import VERB_CLASSES
from mirage_schema.policy import Action, Protocol

TOKEN = "t" * 32
EXPLORE_IP = "198.19.0.7"
CAPTURE_IP = "198.18.0.7"
ALL = list(ACTIONS)  # the five of contract v1: what the shadow policies know


class Toy:
    """A stand-in for a trained model: it prefers delay, more so later in a session."""

    name = "toy-model"

    def __init__(self, path: Path) -> None:
        self.version = file_version(path)
        self.weight = float(path.read_text())
        self.contexts: list[dict] = []

    def probabilities(self, context: Mapping, allowed: Sequence[Action]) -> Mapping[Action, float]:
        self.contexts.append(dict(context))
        if Action.DELAY not in allowed:
            return {a: 1.0 / len(allowed) for a in allowed}
        rest = (1.0 - self.weight) / (len(allowed) - 1)
        return {a: self.weight if a is Action.DELAY else rest for a in allowed}


@pytest.fixture
def toy_file(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setitem(shadow_module._LOADERS, ".toy", Toy)
    path = tmp_path / "shadow.toy"
    path.write_text("0.6")
    path.chmod(0o444)  # the service only ever reads it
    return path


def warnings(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


# ------------------------------------------------------------------ the interface


def test_the_fallback_and_a_loaded_model_both_satisfy_the_interface(toy_file):
    assert isinstance(FallbackShadow(BanditPolicy(), "why"), ShadowPolicy)
    assert isinstance(Toy(toy_file), ShadowPolicy)
    assert not isinstance(object(), ShadowPolicy)


def test_the_fallback_is_epsilon_greedy_around_the_rules_action():
    policy = BanditPolicy(epsilon=0.3)
    fallback = FallbackShadow(policy, "why")
    assert fallback.name == FALLBACK_NAME == "shadow-fallback(epsilon-greedy)"
    assert fallback.version == policy.name  # which epsilon-greedy it is
    probs = fallback.probabilities({"rule_action": "fake_error"}, ALL)
    assert probs == policy.probs(ALL, Action.FAKE_ERROR)
    assert max(probs, key=probs.get) is Action.FAKE_ERROR


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {},
        {a: 0.25 for a in ALL[:4]},  # an allowed action is missing
        {**{a: 0.2 for a in ALL}, "plant_token": 0.0},  # something that is not allowed
        {a: 0.3 for a in ALL},  # does not sum to 1
        {**{a: 0.25 for a in ALL[:4]}, Action.TERMINATE: float("nan")},
        {**{a: 0.5 for a in ALL[:2]}, **{a: 0.5 for a in ALL[2:4]}, Action.TERMINATE: -1.0},
        {a: "0.2" for a in ALL},
    ],
)
def test_only_a_distribution_over_the_allowed_actions_is_accepted(answer):
    assert distribution(answer, ALL) is None


def test_a_distribution_is_stored_by_action_name_in_mask_order():
    answer = {"terminate": 0.5, Action.ALLOW: 0.5, "delay": 0, "fake_success": 0, "fake_error": 0}
    assert distribution(answer, ALL) == {
        "allow": 0.5,
        "delay": 0.0,
        "fake_success": 0.0,
        "fake_error": 0.0,
        "terminate": 0.5,
    }
    assert list(distribution(answer, ALL)) == [a.value for a in ALL]


# ------------------------------------------------------------------ the loader


def test_no_model_configured_means_the_named_fallback_logged_once(caplog):
    got = load_shadow(None, BanditPolicy())
    assert isinstance(got, FallbackShadow) and got.name == FALLBACK_NAME
    assert "POLICY_SHADOW_MODEL is not set" in got.reason
    assert len(warnings(caplog)) == 1 and FALLBACK_NAME in warnings(caplog)[0]


def _missing(tmp_path: Path) -> Path:
    return tmp_path / "nothing-here.toy"


def _directory(tmp_path: Path) -> Path:
    (tmp_path / "model.toy").mkdir()
    return tmp_path / "model.toy"


def _unknown_format(tmp_path: Path) -> Path:
    (tmp_path / "model.onnx").write_bytes(b"\x00")
    return tmp_path / "model.onnx"


def _corrupt(tmp_path: Path) -> Path:
    (tmp_path / "model.toy").write_text("not a number")
    return tmp_path / "model.toy"


def _wrong_object(tmp_path: Path) -> Path:
    (tmp_path / "model.junk").write_text("1")
    return tmp_path / "model.junk"


def _impostor(tmp_path: Path) -> Path:
    (tmp_path / "model.liar").write_text("0.5")
    return tmp_path / "model.liar"


class Liar(Toy):
    name = FALLBACK_NAME  # a model may not take the fallback's name, or the reverse


@pytest.mark.parametrize(
    ("make", "says"),
    [
        (_missing, "cannot read"),
        (_directory, "cannot read"),
        (_unknown_format, "no loader is registered for '.onnx'"),
        (_corrupt, "the loader failed on model.toy: ValueError"),
        (_wrong_object, "did not return a shadow policy"),
        (_impostor, "did not return a shadow policy"),
    ],
)
def test_a_model_that_cannot_be_loaded_means_the_named_fallback_logged_once(
    tmp_path, caplog, make, says
):
    loaders = {".toy": Toy, ".junk": lambda path: object(), ".liar": Liar}
    got = load_shadow(make(tmp_path), BanditPolicy(), loaders)
    assert isinstance(got, FallbackShadow) and got.name == FALLBACK_NAME
    assert says in got.reason
    assert len(warnings(caplog)) == 1 and says in warnings(caplog)[0]


def test_a_readable_model_with_a_loader_is_loaded_and_left_untouched(toy_file, caplog):
    before = (toy_file.read_bytes(), toy_file.stat().st_mtime_ns)
    got = load_shadow(toy_file, BanditPolicy())
    assert isinstance(got, Toy) and got.name == "toy-model"
    assert got.version == file_version(toy_file) and len(got.version) == 12
    assert (toy_file.read_bytes(), toy_file.stat().st_mtime_ns) == before
    assert warnings(caplog) == []


def test_register_loader_takes_a_suffix(monkeypatch):
    monkeypatch.setattr(shadow_module, "_LOADERS", {})
    register_loader(".VW", Toy)
    assert list(shadow_module._LOADERS.items()) == [(".vw", Toy)]
    with pytest.raises(ValueError):
        register_loader("vw", Toy)


# ------------------------------------------------------------------ the service


def service(tmp_path: Path, monkeypatch, model: Path | None = None, seed: int = 7):
    monkeypatch.setenv("POLICY_EXPLORE", "lab")
    monkeypatch.setenv(
        "POLICY_TECHNIQUE_RULES", str(Path(__file__).resolve().parents[2] / "intel" / "rules")
    )
    log = tmp_path / "decisions.json"
    settings = Settings(
        token=TOKEN, log_path=log, rule_files=[RULES_DIR / "default.yaml"], shadow_model=model
    )
    app = create_app(settings, rng=random.Random(seed))
    return TestClient(app), log, app


def post(c: TestClient, i: int, ip: str, session: str | None = None, **over) -> dict:
    body = {
        "request_id": f"r{i}",
        "session_id": session or f"s{i}",
        "protocol": "ssh",
        "argv": ["uname", "-a"],
        "seq": 2,
        "src": {"ip": ip},
        **over,
    }
    r = c.post("/v1/decide", json=body, headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200, r.text
    return r.json()


def records(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text().splitlines()]


def test_settings_read_the_model_path_from_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("POLICY_TOKEN", TOKEN)
    monkeypatch.setenv("POLICY_LOG", str(tmp_path / "d.json"))
    monkeypatch.delenv("POLICY_SHADOW_MODEL", raising=False)
    assert Settings.from_env().shadow_model is None
    monkeypatch.setenv("POLICY_SHADOW_MODEL", "/models/shadow.vw")
    assert Settings.from_env().shadow_model == Path("/models/shadow.vw")


def test_without_a_model_every_decision_logs_the_fallback_shadow(tmp_path, monkeypatch, caplog):
    c, log, _ = service(tmp_path, monkeypatch)
    for i in range(40):
        post(c, i, EXPLORE_IP if i % 2 else CAPTURE_IP)
    rows = records(log)
    assert {r["explore"] for r in rows} == {True, False}
    for r in rows:  # explored decisions log a shadow too, which they did not before
        s = r["shadow"]
        assert s["name"] == FALLBACK_NAME and s["version"] == "epsilon-greedy-v0(eps=0.3)"
        assert "POLICY_SHADOW_MODEL is not set" in s["reason"]
        assert list(s["probs"]) == r["allowed"] and abs(sum(s["probs"].values()) - 1) < 1e-5
    assert len(warnings(caplog)) == 1  # at start-up, not once per decision


def test_a_configured_but_missing_model_is_never_claimed(tmp_path, monkeypatch, caplog):
    c, log, _ = service(tmp_path, monkeypatch, model=tmp_path / "gone.vw")
    for i in range(5):
        post(c, i, CAPTURE_IP)
    assert {r["shadow"]["name"] for r in records(log)} == {FALLBACK_NAME}
    assert all("cannot read" in r["shadow"]["reason"] for r in records(log))
    assert len(warnings(caplog)) == 1


def test_a_loaded_model_shadows_every_decision_with_its_own_distribution(
    tmp_path, monkeypatch, toy_file
):
    c, log, _ = service(tmp_path, monkeypatch, model=toy_file)
    for i in range(60):
        post(c, i, EXPLORE_IP if i % 2 else CAPTURE_IP, seq=1 if i % 3 == 0 else 2)
    rows = records(log)
    assert {r["explore"] for r in rows} == {True, False}
    for r in rows:
        s = r["shadow"]
        assert (s["name"], s["version"]) == ("toy-model", file_version(toy_file))
        assert "reason" not in s and "error" not in s
        # a probability for every allowed action, and only for those
        assert list(s["probs"]) == r["allowed"] and abs(sum(s["probs"].values()) - 1) < 1e-5
        assert s["probs"]["delay"] == 0.6
        # a second, different distribution: not the acting policy's
        acting = r["acting"].get("probs") or {r["acting"]["action"]: 1.0}
        assert s["probs"] != acting


def test_the_shadow_never_changes_what_is_done(tmp_path, monkeypatch, toy_file):
    def run(directory: Path, model: Path | None) -> list[tuple]:
        directory.mkdir()
        c, _, _ = service(directory, monkeypatch, model=model, seed=5)
        sent = [post(c, i, EXPLORE_IP) for i in range(300)]
        return [(d["action"], d["propensity"], d["output"], d.get("exit_code")) for d in sent]

    assert run(tmp_path / "with", toy_file) == run(tmp_path / "without", None)


def test_the_model_is_given_the_documented_context(tmp_path, monkeypatch, toy_file):
    c, log, app = service(tmp_path, monkeypatch, model=toy_file)
    post(c, 0, CAPTURE_IP, session="a", seq=1)
    post(c, 1, CAPTURE_IP, session="a", seq=2)
    first, second = app.state.shadow.contexts
    # exactly what the decision record stores as "context"
    assert [first, second] == [r["context"] for r in records(log)]
    types = {
        "protocol": str,
        "verb": str,
        "verb_class": str,
        "known": bool,
        "inputs_so_far": int,
        "seconds_since_last": (float, type(None)),
        "last_tactic": (str, type(None)),
        "seen_before": bool,
        "seen_before_in_session": bool,
        "rule_action": str,
        # context version 3 (phase 3 spec 3.3)
        "rule_action_v2": (str, type(None)),
        "tier": (str, type(None)),
        "actor_class": (str, type(None)),
        "actor_confidence": (float, type(None)),
        "respond_budget_left": str,
        "token_planted": bool,
        "previous_action": (str, type(None)),
        "had_non_allow": bool,
    }
    for context in (first, second):
        assert set(context) == set(types)
        for name, kind in types.items():
            assert isinstance(context[name], kind), (name, context[name])
        assert context["verb_class"] in VERB_CLASSES[Protocol(context["protocol"])]
        assert context["rule_action"] in {a.value for a in ACTIONS}
        assert context["respond_budget_left"] == "full" and context["token_planted"] is False
    assert (first["seconds_since_last"], first["last_tactic"]) == (None, None)
    assert (first["previous_action"], second["previous_action"]) == (None, "allow")
    assert isinstance(second["seconds_since_last"], float) and second["last_tactic"] == "TA0007"


class Flaky(Toy):
    """Fails on some inputs, the three ways a model can."""

    def probabilities(self, context: Mapping, allowed: Sequence[Action]) -> Mapping[Action, float]:
        if context["verb"] == "raise":
            raise RuntimeError("model exploded")
        if context["verb"] == "short":
            return {Action.ALLOW: 1.0}
        if context["verb"] == "heavy":
            return {a: 1.0 for a in allowed}
        return super().probabilities(context, allowed)


@pytest.mark.parametrize("verb", ["raise", "short", "heavy"])
def test_a_model_that_fails_on_a_decision_is_not_credited_with_it(
    tmp_path, monkeypatch, caplog, verb
):
    monkeypatch.setitem(shadow_module._LOADERS, ".flaky", Flaky)
    model = tmp_path / "m.flaky"
    model.write_text("0.6")
    c, log, _ = service(tmp_path, monkeypatch, model=model)
    caplog.clear()
    assert post(c, 0, CAPTURE_IP, argv=["id"])["action"] == "allow"
    for i in range(1, 4):  # the decision itself is unaffected, every time
        assert post(c, i, CAPTURE_IP, argv=[verb])["action"] == "allow"
    good, *bad = records(log)
    assert good["shadow"]["name"] == "toy-model"
    for r in bad:
        s = r["shadow"]
        assert s["name"] == FALLBACK_NAME and s["version"].startswith("epsilon-greedy")
        assert s["error"] and list(s["probs"]) == r["allowed"]
    assert len(warnings(caplog)) == 1  # reported once, not three times
