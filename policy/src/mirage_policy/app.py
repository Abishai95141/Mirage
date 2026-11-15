"""Policy service v0: ``POST /v1/decide`` (gate contract v1, spec section 3).

Every decision is written as one JSON line to the decision log, which Vector tails and
publishes to ``raw.policy.decision``. The decoy's own event records what it actually applied;
this record says why. The two join on ``request_id``.

Beside the request and the decision the decoy was sent, a record carries (phase 2 spec 2.5):

``context``          the features the policies saw (documented in :mod:`mirage_policy.shadow`),
                     the raw ``verb`` and its ``verb_class`` among them
``context_version``  the feature set's version and the verb-class mapping's, as ``"2.1"``
``allowed``          the actions left by the mask, in the service's fixed order
``acting``           the policy that decided: ``name``, ``version``, ``action``, ``propensity``;
                     for the exploring policy also ``probs`` for every allowed action, the
                     ``rules_version`` it explored around and the ``fake_errors_version`` an
                     explored fake error was rendered with. When the rules act, ``version`` is
                     the rule set's
``shadow``           the policy that only watched: ``name``, ``version`` and ``probs`` for
                     every allowed action, on every decision. Without a trained model the name
                     is ``shadow-fallback(epsilon-greedy)`` and ``reason`` says why
``explore``          whether the exploring policy acted (lab explore range only)
``rules_version``    the rule set's version (also in the response, as before)
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import random
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import ValidationError

from mirage_policy import (
    shadow_json,  # noqa: F401 - importing it registers the loader for saved .json policies
    verbs,
)
from mirage_policy.explore import (
    CONTEXT_VERSION,
    BanditPolicy,
    Context,
    TacticRules,
    allowed_actions,
    explore_enabled,
    is_explore,
)
from mirage_policy.fake_errors import FakeErrors
from mirage_policy.rules import Rule, RuleSet
from mirage_policy.shadow import FALLBACK_NAME, FallbackShadow, distribution, load_shadow
from mirage_schema.policy import Action, DecideRequest, Decision, as_dict

log = logging.getLogger("mirage.policy")

# Defaults for an action the exploring policy picks that the matched rule did not specify.
_DELAY_MS = 250


def _decision_for(
    action: Action,
    rule: Rule,
    decision_id: str,
    propensity: float,
    rules_version: str,
    fake_error: tuple[str, int | None] = ("", 1),
) -> Decision:
    """Build the decision for the acting action: the rule's own fields when the action is the
    rule's, otherwise sane defaults so an explored action is still a valid, safe response.
    ``fake_error`` is the ``(output, exit_code)`` an explored fake error is rendered with: the
    fake-error table's entry for this input's protocol and verb."""
    if action is rule.action:
        output, exit_code, delay_ms = rule.output, rule.exit_code, rule.delay_ms
    else:
        output, exit_code, delay_ms = "", None, 0
        if action is Action.FAKE_ERROR:
            output, exit_code = fake_error
        elif action is Action.DELAY:
            delay_ms = _DELAY_MS
    return Decision(
        action=action,
        output=output,
        exit_code=exit_code,
        delay_ms=delay_ms,
        decision_id=decision_id,
        propensity=propensity,
        rule_id=rule.id,
        rules_version=rules_version,
    )


RULES_DIR = Path(__file__).parent / "rulesets"


@dataclass
class Settings:
    token: str
    log_path: Path
    rule_files: list[Path]
    # How an explored fake_error is rendered, per protocol and verb (spec 2.5).
    fake_errors: Path = RULES_DIR / "fake_errors.yaml"
    # A trained shadow policy's model file, opened read-only. None: the fallback shadows.
    shadow_model: Path | None = None

    @classmethod
    def from_env(cls) -> Settings:
        token = os.environ.get("POLICY_TOKEN", "")
        if len(token) < 16:
            raise SystemExit("POLICY_TOKEN must be set (at least 16 characters); run make env")
        files: list[Path] = []
        if os.environ.get("POLICY_SELFTEST") == "1":
            files.append(RULES_DIR / "selftest.yaml")
        extra = os.environ.get("POLICY_RULES")
        files.append(Path(extra) if extra else RULES_DIR / "default.yaml")
        log_path = Path(os.environ.get("POLICY_LOG", "/var/log/mirage-policy/decisions.json"))
        fake_errors = os.environ.get("POLICY_FAKE_ERRORS")
        shadow_model = os.environ.get("POLICY_SHADOW_MODEL")
        return cls(
            token=token,
            log_path=log_path,
            rule_files=files,
            fake_errors=Path(fake_errors) if fake_errors else RULES_DIR / "fake_errors.yaml",
            shadow_model=Path(shadow_model) if shadow_model else None,
        )


class DecisionLog:
    """Append-only JSON lines. One write per line, so a line is never interleaved."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._f = path.open("a", buffering=1, encoding="utf-8")
        self._lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n"
        with self._lock:
            self._f.write(line)

    def close(self) -> None:
        self._f.close()


def create_app(settings: Settings, rng: random.Random | None = None) -> FastAPI:
    # Without this the service's own INFO lines go nowhere (the web server configures only
    # its own loggers), and which shadow policy loaded could not be read from the log.
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=os.environ.get("LOG_LEVEL", "INFO"), format="%(levelname)s %(name)s %(message)s"
        )
    rules = RuleSet.load(*settings.rule_files)
    fake_errors = FakeErrors.load(settings.fake_errors)
    log_file = DecisionLog(settings.log_path)
    expected = f"Bearer {settings.token}".encode()
    context = Context()
    policy = BanditPolicy()
    # The shadow is a trained model when one loads; otherwise the same epsilon-greedy policy
    # under a name that says so. ``fallback`` also answers for a model that fails at run time.
    shadow = load_shadow(settings.shadow_model, policy)
    fallback = (
        shadow
        if isinstance(shadow, FallbackShadow)
        else FallbackShadow(policy, "the shadow model failed on this decision")
    )
    shadow_failed = False  # a failing model is reported once, not once per decision
    tactics = TacticRules.from_env()
    explore_on = explore_enabled()
    rng = rng or random.Random()  # noqa: S311 - exploration sampling, not cryptography

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.rules = rules
    app.state.context = context
    app.state.shadow = shadow

    def shadow_record(features: dict[str, Any], allowed: list[Action]) -> dict[str, Any]:
        """The shadow policy's name, version and probability for every allowed action. A model
        that raises or answers with something that is not a distribution over ``allowed`` is
        replaced, for this decision, by the fallback under the fallback's own name."""
        nonlocal shadow_failed
        if shadow is not fallback:
            error = None
            try:
                # Copies: the model reads the context and the mask, it does not get to edit
                # what is logged or what the acting policy chose from.
                answer = shadow.probabilities(dict(features), tuple(allowed))
                probs = distribution(answer, allowed)
            except Exception as exc:  # the model is foreign code; a decision must not fail on it
                probs, error = None, f"{type(exc).__name__}: {exc}"[:200]
            if probs is not None:
                return {"name": shadow.name, "version": shadow.version, "probs": probs}
            error = error or "not a probability for every allowed action, summing to 1"
            if not shadow_failed:
                shadow_failed = True
                log.warning("shadow policy %s failed (%s); using the fallback", shadow.name, error)
        else:
            error = None
        record = {
            "name": FALLBACK_NAME,
            "version": fallback.version,
            "probs": distribution(fallback.probabilities(features, allowed), allowed),
            "reason": fallback.reason,
        }
        if error is not None:
            record["error"] = error
        return record

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz() -> str:
        return "ok"

    @app.post("/v1/decide")
    async def decide(request: Request, authorization: str = Header(default="")) -> JSONResponse:
        started = time.perf_counter()
        if not hmac.compare_digest(authorization.encode(), expected):
            raise HTTPException(status_code=401)
        try:
            req = DecideRequest.model_validate(await request.json())
        except (ValidationError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)[:500]) from exc

        rule = rules.decide(req)
        tactic = tactics.tactic(req.protocol.value, req.input_text())
        features = context.observe(req, tactic)
        features["rule_action"] = rule.action.value
        # The mask needs the service's own count of the session's inputs: a request without a
        # ``seq`` is a first input only until the session has had one.
        allowed = allowed_actions(req, features["inputs_so_far"])
        decision_id = str(uuid.uuid4())

        exploring = is_explore(req, explore_on)
        if exploring:
            # In the lab explore range the bandit acts and logs the probability of its choice.
            choice = policy.sample(allowed, rule.action, rng)
            decision = _decision_for(
                choice.action,
                rule,
                decision_id,
                choice.propensity,
                rules.version,
                fake_errors.render(req, features["verb_class"]),
            )
            acting = {
                "name": policy.name,
                "version": policy.version,
                "action": choice.action.value,
                "propensity": choice.propensity,
                "probs": choice.probs,
                # What this policy's choice depends on besides its own version: the rule set
                # whose action it explores around, and the table that renders a fake error.
                "rules_version": rules.version,
                "fake_errors_version": fake_errors.version,
            }
        else:
            # Elsewhere the rules decide; the shadow policy only says what it would have done.
            decision = _decision_for(rule.action, rule, decision_id, 1.0, rules.version)
            acting = {
                "name": "rules",
                "version": rules.version,
                "action": rule.action.value,
                "propensity": 1.0,
            }
        # Asked on every decision, explored or not: the shadow never acts.
        shadowed = shadow_record(features, allowed)

        body = decision.model_dump(mode="json", exclude_none=True)
        latency_us = round((time.perf_counter() - started) * 1e6)
        log_file.write(
            {
                "eventid": "policy.decision",
                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "request": as_dict(req),
                "input": req.input_text(),
                **body,
                "context": features,
                "context_version": f"{CONTEXT_VERSION}.{verbs.VERSION}",
                "allowed": [a.value for a in allowed],
                "acting": acting,
                "shadow": shadowed,
                "explore": exploring,
                "latency_us": latency_us,
            }
        )
        return JSONResponse(body)

    return app
