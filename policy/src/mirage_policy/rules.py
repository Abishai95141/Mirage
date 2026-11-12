"""Rule engine v0: an ordered list of rules, first match wins.

A rule file that does not validate stops the service from starting (spec 1.2): configuration
errors fail closed here, while the decoys fail open to ``allow`` when the service is absent.
The action mask is enforced at load time, so a bad rule can never reach a decision.
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
    Action,
    DecideRequest,
    Protocol,
)


class When(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: list[Protocol] | None = None
    known: bool | None = None
    verb: list[str] | None = None  # argv[0] (ssh), command (redis, upper-cased), SQL verb, method
    input_regex: str | None = None  # over DecideRequest.input_text()
    path_regex: str | None = None  # http only

    @field_validator("protocol", "verb", mode="before")
    @classmethod
    def _listify(cls, v: Any) -> Any:
        return [v] if isinstance(v, str) else v

    @field_validator("input_regex", "path_regex")
    @classmethod
    def _compiles(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                re.compile(v)
            except re.error as exc:
                raise ValueError(f"bad regex {v!r}: {exc}") from exc
        return v

    def matches(self, req: DecideRequest) -> bool:
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


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    when: When = Field(default_factory=When)
    action: Action
    output: str = ""
    exit_code: int | None = None
    delay_ms: int = 0

    @model_validator(mode="after")
    def _mask(self) -> Rule:
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

    version: int = Field(ge=1, le=1)
    rules: list[Rule]


class RuleSet:
    def __init__(self, rules: list[Rule], version: str) -> None:
        ids = [r.id for r in rules]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"duplicate rule ids: {sorted(dupes)}")
        if not rules or rules[-1].when != When():
            raise ValueError("the last rule must match everything (an empty 'when')")
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

    def decide(self, req: DecideRequest) -> Rule:
        for rule in self.rules:
            if rule.when.matches(req):
                return rule
        raise AssertionError("unreachable: the last rule matches everything")
