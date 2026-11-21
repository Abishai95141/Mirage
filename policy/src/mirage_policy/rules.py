"""The rule engine: an ordered list of rules, first match wins.

A rule file that does not validate stops the service from starting (spec 1.2): configuration
errors fail closed here, while the decoys fail open to ``allow`` when the service is absent.
The action mask is enforced at load time, so a bad rule can never reach a decision.

**Version 2** (phase 3 spec, 3.3, decision R11) adds conditions on the session's context (the
decoy's ``tier`` for the input, how far into the session it is, the tactic of the input and
of the one before, the actor class, whether a token has been planted) and the three actions
of gate contract v2. A version 1 file may use none of them. A rule whose action the mask does
not allow for this request does not match, and the next rule is tried: a v2 rule set is thus
a v1 rule set towards a decoy that supports nothing new.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mirage_schema.policy import (
    MAX_DELAY_MS,
    MAX_OUTPUT_BYTES,
    MAX_OUTPUT_TOKENS,
    MAX_RESPOND_DEADLINE_MS,
    V2_ACTIONS,
    Action,
    DecideRequest,
    Protocol,
    Tier,
)

# What a version 2 rule may condition on beside the request: the context the service keeps
# for the session, as :meth:`mirage_policy.explore.Context.observe` gives it, and the tactic
# of the input being decided.
V2_CONDITIONS = (
    "tier",
    "inputs_min",
    "inputs_max",
    "tactic",
    "last_tactic",
    "actor_class",
    "not_actor_class",
    "token_planted",
)


class When(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: list[Protocol] | None = None
    known: bool | None = None
    verb: list[str] | None = None  # argv[0] (ssh), command (redis, upper-cased), SQL verb, method
    input_regex: str | None = None  # over DecideRequest.input_text()
    path_regex: str | None = None  # http only
    # version 2: the context
    tier: list[Tier] | None = None  # what the decoy has for this input
    inputs_min: int | None = Field(default=None, ge=1)  # this is at least the Nth input
    inputs_max: int | None = Field(default=None, ge=1)  # and at most the Nth
    tactic: list[str] | None = None  # ATT&CK tactic of this input; "unknown" for none
    last_tactic: list[str] | None = None  # of the latest earlier input that had one
    actor_class: list[str] | None = None  # the classifier's answer; "unknown" before it has one
    not_actor_class: list[str] | None = None
    token_planted: bool | None = None  # in this session, by the policy

    @field_validator(
        "protocol",
        "verb",
        "tier",
        "tactic",
        "last_tactic",
        "actor_class",
        "not_actor_class",
        mode="before",
    )
    @classmethod
    def _listify(cls, v: Any) -> Any:
        return [v] if isinstance(v, str) else v

    def uses_context(self) -> list[str]:
        return [name for name in V2_CONDITIONS if getattr(self, name) is not None]

    @field_validator("input_regex", "path_regex")
    @classmethod
    def _compiles(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                re.compile(v)
            except re.error as exc:
                raise ValueError(f"bad regex {v!r}: {exc}") from exc
        return v

    def matches(
        self, req: DecideRequest, features: dict[str, Any] | None = None, tactic: str | None = None
    ) -> bool:
        """Whether the rule's conditions hold. ``features`` is the session's context and
        ``tactic`` the tactic of this input; a rule that conditions on either does not match
        where the caller has none to give."""
        if self.uses_context() and not self._context_matches(req, features, tactic):
            return False
        if self.protocol is not None and req.protocol not in self.protocol:
            return False
        if self.known is not None and req.known != self.known:
            return False
        if self.verb is not None:
            verb = req.verb()
            if verb is None:
                return False
            if req.protocol is Protocol.SSH:  # shell commands are case-sensitive
                if verb not in self.verb:
                    return False
            elif verb.upper() not in {v.upper() for v in self.verb}:
                return False
        if self.input_regex is not None and not re.search(self.input_regex, req.input_text()):
            return False
        return not (
            self.path_regex is not None
            and (
                req.protocol is not Protocol.HTTP or not re.search(self.path_regex, req.path or "")
            )
        )

    def _context_matches(
        self, req: DecideRequest, features: dict[str, Any] | None, tactic: str | None
    ) -> bool:
        if features is None:
            return False
        if self.tier is not None and req.tier not in self.tier:
            return False
        nth = int(features.get("inputs_so_far") or 0) + 1
        if self.inputs_min is not None and nth < self.inputs_min:
            return False
        if self.inputs_max is not None and nth > self.inputs_max:
            return False
        if self.tactic is not None and (tactic or "unknown") not in self.tactic:
            return False
        earlier = features.get("last_tactic") or "unknown"
        if self.last_tactic is not None and earlier not in self.last_tactic:
            return False
        actor = features.get("actor_class") or "unknown"
        if self.actor_class is not None and actor not in self.actor_class:
            return False
        if self.not_actor_class is not None and actor in self.not_actor_class:
            return False
        return not (
            self.token_planted is not None
            and bool(features.get("token_planted")) != self.token_planted
        )


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    when: When = Field(default_factory=When)
    action: Action
    output: str = ""
    exit_code: int | None = None
    delay_ms: int = 0
    # respond: what the answer may spend (defaults of spec 3.2b)
    max_tokens: int | None = Field(default=None, ge=1, le=MAX_OUTPUT_TOKENS)
    deadline_ms: int | None = Field(default=None, ge=1, le=MAX_RESPOND_DEADLINE_MS)

    @model_validator(mode="after")
    def _mask(self) -> Rule:
        if self.action is not Action.RESPOND and (self.max_tokens or self.deadline_ms):
            raise ValueError(f"rule {self.id}: max_tokens and deadline_ms only apply to respond")
        if len(self.output.encode()) > MAX_OUTPUT_BYTES:
            raise ValueError(f"rule {self.id}: output over {MAX_OUTPUT_BYTES} bytes")
        if not 0 <= self.delay_ms <= MAX_DELAY_MS:
            raise ValueError(f"rule {self.id}: delay_ms outside 0..{MAX_DELAY_MS}")
        if self.action is not Action.DELAY and self.delay_ms:
            raise ValueError(f"rule {self.id}: delay_ms only applies to delay")
        if self.output and self.action not in (Action.FAKE_SUCCESS, Action.FAKE_ERROR):
            raise ValueError(f"rule {self.id}: output only applies to fake_success/fake_error")
        if self.exit_code is not None and self.action is not Action.FAKE_ERROR:
            raise ValueError(f"rule {self.id}: exit_code only applies to fake_error")
        return self


class RuleFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(ge=1, le=2)
    rules: list[Rule]

    @model_validator(mode="after")
    def _version_1_is_what_it_was(self) -> RuleFile:
        if self.version == 1:
            for rule in self.rules:
                if rule.action in V2_ACTIONS:
                    raise ValueError(f"rule {rule.id}: {rule.action.value} needs a version 2 file")
                used = rule.when.uses_context()
                if used:
                    raise ValueError(f"rule {rule.id}: {used} need a version 2 file")
        return self


class RuleSet:
    def __init__(self, rules: list[Rule], version: str) -> None:
        ids = [r.id for r in rules]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"duplicate rule ids: {sorted(dupes)}")
        if not rules or rules[-1].when != When():
            raise ValueError("the last rule must match everything (an empty 'when')")
        if rules[-1].action in V2_ACTIONS:
            # A v2 action can be masked for a request, and then nothing would be left.
            raise ValueError("the last rule's action must be one every decoy can carry out")
        self.rules = rules
        self.version = version

    @classmethod
    def load(cls, *paths: Path) -> RuleSet:
        """Load rule files in order; earlier files' rules come first. The last file must end
        with a catch-all rule."""
        rules: list[Rule] = []
        digest = hashlib.sha256()
        for p in paths:
            text = p.read_bytes()
            digest.update(text)
            rules.extend(RuleFile.model_validate(yaml.safe_load(text)).rules)
        return cls(rules, digest.hexdigest()[:12])

    def decide(
        self,
        req: DecideRequest,
        features: dict[str, Any] | None = None,
        tactic: str | None = None,
        v2_allowed: frozenset[Action] = frozenset(),
    ) -> Rule:
        """The first rule that matches. A rule with a v2 action matches only where the mask
        allows that action for this request (``v2_allowed``)."""
        for rule in self.rules:
            if rule.action in V2_ACTIONS and rule.action not in v2_allowed:
                continue
            if rule.when.matches(req, features, tactic):
                return rule
        raise AssertionError("unreachable: the last rule matches everything")
