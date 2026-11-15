"""Technique rule engine (phase 2 spec, 2.4, layer 1).

Rules are data, in ``intel/rules/*.yaml``: each names a technique and tactic and a set of
regexes over the input. The engine compiles and applies them; it holds no patterns of its own,
so the offensive rules can be written and reviewed as data (and, where a safety classifier
refuses to draft them, handed to the tool that wrote the catalogue) without touching this code.

The same compiled engine serves two callers: the offline tagger (``tagger.py``), which labels
captured inputs, and the policy service, which needs the last tactic seen as a decision feature
and must compute it in-process without a network call (spec Q12). So the engine depends on
nothing but the rules file and the standard library.

Every input is normalised before a pattern sees it (:func:`normalise`): runs of whitespace
become one space and the ends are stripped. Rules are written against that form.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from mirage_schema.groundtruth import TACTIC_ID, TECHNIQUE_ID

PROTOCOLS = ("ssh", "http", "redis", "mysql", "any")

# How an input is prepared for matching. Part of the engine's version, so labels written
# under different matching carry different ``model_version`` values.
MATCHING = "ws1"
_WHITESPACE = re.compile(r"\s+")


def normalise(text: str) -> str:
    """The form every rule is matched against (spec 2.4, "regexes on a normalised input").

    Runs of whitespace (spaces, tabs, newlines) collapse to one space, and leading and
    trailing whitespace goes. Nothing more: case is the patterns' business (they compile with
    IGNORECASE), and quoting, paths and arguments stay as typed, so a rule sees what was sent
    and ``a  b`` cannot slip past a pattern written for ``a b``. Idempotent."""
    return _WHITESPACE.sub(" ", text).strip()


@dataclass(frozen=True)
class Hit:
    technique: str
    tactic: str
    confidence: float
    rule_id: str


@dataclass
class Rule:
    id: str
    technique: str
    tactic: str
    confidence: float
    protocol: str
    any_of: list[re.Pattern[str]] = field(default_factory=list)
    all_of: list[re.Pattern[str]] = field(default_factory=list)

    def matches(self, protocol: str, text: str) -> bool:
        """Whether this rule fires on ``text``, which the caller has normalised."""
        if self.protocol != "any" and self.protocol != protocol:
            return False
        if self.any_of and not any(p.search(text) for p in self.any_of):
            return False
        return all(p.search(text) for p in self.all_of)


@dataclass
class SessionRule:
    """A rule over a whole session's shape, for what no single input shows (spec 2.4). The
    fields are the structural session summary, never command text."""

    id: str
    technique: str
    tactic: str
    confidence: float
    when: dict  # a small predicate language: {field: {">=": n}} over session features

    def matches(self, summary: dict) -> bool:
        for field_name, cond in self.when.items():
            value = summary.get(field_name, 0)
            for op, target in cond.items():
                if op == ">=" and not value >= target:
                    return False
                if op == "<=" and not value <= target:
                    return False
                if op == "==" and value != target:
                    return False
        return True


def _compile(patterns: str | list[str] | None) -> list[re.Pattern[str]]:
    if patterns is None:
        return []
    if isinstance(patterns, str):
        patterns = [patterns]
    return [re.compile(p, re.IGNORECASE) for p in patterns]


class Engine:
    def __init__(
        self, rules: list[Rule], session_rules: list[SessionRule], version: str = "rules-0"
    ) -> None:
        self.rules = rules
        self.session_rules = session_rules
        self.version = version  # a hash of the rule set, logged with every label

    @classmethod
    def load(cls, directory: Path) -> Engine:
        rules: list[Rule] = []
        session_rules: list[SessionRule] = []
        seen: set[str] = set()
        digest = hashlib.sha256(MATCHING.encode())
        for path in sorted(directory.glob("*.yaml")):
            raw = path.read_bytes()
            digest.update(path.name.encode() + b"\0" + raw)
            doc = yaml.safe_load(raw) or {}
            for item in doc.get("rules", []):
                rule = cls._rule(item, path.name)
                if rule.id in seen:
                    raise ValueError(f"{path.name}: duplicate rule id {rule.id}")
                seen.add(rule.id)
                rules.append(rule)
            for item in doc.get("session_rules", []):
                session_rules.append(
                    SessionRule(
                        id=item["id"],
                        technique=item["technique"],
                        tactic=item["tactic"],
                        confidence=float(item.get("confidence", 0.8)),
                        when=item["when"],
                    )
                )
        return cls(rules, session_rules, f"rules-{digest.hexdigest()[:12]}")

    @staticmethod
    def _rule(item: dict, where: str) -> Rule:
        for key, pattern in (("technique", TECHNIQUE_ID), ("tactic", TACTIC_ID)):
            if not re.fullmatch(pattern, str(item.get(key, ""))):
                raise ValueError(f"{where}: rule {item.get('id')!r} has a bad {key}")
        protocol = item.get("protocol", "any")
        if protocol not in PROTOCOLS:
            raise ValueError(f"{where}: rule {item.get('id')!r} has an unknown protocol")
        any_of, all_of = _compile(item.get("any_of")), _compile(item.get("all_of"))
        if not any_of and not all_of:
            raise ValueError(f"{where}: rule {item.get('id')!r} has no patterns")
        return Rule(
            id=item["id"],
            technique=item["technique"],
            tactic=item["tactic"],
            confidence=float(item.get("confidence", 0.8)),
            protocol=protocol,
            any_of=any_of,
            all_of=all_of,
        )

    def tag_input(self, protocol: str, text: str) -> list[Hit]:
        """Every rule that fires on one input, strongest confidence first. The input is
        normalised here, once, so every caller (tagger, policy service) matches alike."""
        text = normalise(text)
        hits = [
            Hit(r.technique, r.tactic, r.confidence, r.id)
            for r in self.rules
            if r.matches(protocol, text)
        ]
        return sorted(hits, key=lambda h: -h.confidence)

    def best(self, protocol: str, text: str) -> Hit | None:
        hits = self.tag_input(protocol, text)
        return hits[0] if hits else None

    def tag_session(self, summary: dict) -> list[Hit]:
        return [
            Hit(r.technique, r.tactic, r.confidence, r.id)
            for r in self.session_rules
            if r.matches(summary)
        ]

    def last_tactic(self, protocol: str, text: str) -> str | None:
        """The tactic the policy service shows as a context feature (spec Q12)."""
        hit = self.best(protocol, text)
        return hit.tactic if hit else None
