"""The bandit's context, action mask and exploring policy (phase 2 spec, 2.5 and Q6).

On ordinary traffic the rules decide and the bandit only shadows: it logs the action
probabilities it would have chosen, so a policy can be evaluated off-policy later. In the lab's
explore address range it acts: it samples an action and logs the exact probability of what it
took. Both need the same two things -- a context computed from the requests the service sees
(Q12: in-process, no network call), and an action mask that removes what is not allowed.

The policy here is epsilon-greedy over the rule's action: a well-defined default whose
propensities make off-policy evaluation possible before any model is trained. A Vowpal Wabbit
model trained from the explore logs replaces it later, behind the same interface.

Per-session context lives in a bounded in-memory map. A single service process owns it; lab
runs are low volume, and nothing here is durable state.
"""

from __future__ import annotations

import ipaddress
import os
import random
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from mirage_schema.policy import Action, DecideRequest

# RFC 2544, never routed; the runner's explore runs dial from here (spec Q6, lab net section).
EXPLORE_NET = ipaddress.ip_network("198.19.0.0/16")
EPSILON = 0.3
MAX_SESSIONS = 4096  # bound the context map
IDLE_RESET_S = 1800  # a session untouched this long is treated as new

ACTIONS = (Action.ALLOW, Action.DELAY, Action.FAKE_SUCCESS, Action.FAKE_ERROR, Action.TERMINATE)


def allowed_actions(req: DecideRequest) -> list[Action]:
    """The mask: never terminate on the first input of a session (spec 2.5)."""
    first = req.seq is None or req.seq <= 1
    return [a for a in ACTIONS if not (a is Action.TERMINATE and first)]


@dataclass
class SessionState:
    count: int = 0
    last_ts: float = 0.0
    last_tactic: str | None = None
    seen: set[str] = field(default_factory=set)


class Context:
    """Per-session features for the policy, updated as requests arrive."""

    def __init__(self, now: callable = time.monotonic) -> None:
        self._sessions: OrderedDict[str, SessionState] = OrderedDict()
        self._now = now

    def _state(self, session_id: str | None) -> SessionState:
        if not session_id:
            return SessionState()
        st = self._sessions.get(session_id)
        if st is None or self._now() - st.last_ts > IDLE_RESET_S:
            st = SessionState()
            self._sessions[session_id] = st
            self._sessions.move_to_end(session_id)
            while len(self._sessions) > MAX_SESSIONS:
                self._sessions.popitem(last=False)
        return st

    def observe(self, req: DecideRequest, tactic: str | None) -> dict:
        """Compute the context for this request and fold it into the session's state."""
        now = self._now()
        st = self._state(req.session_id)
        text = req.input_text()
        features = {
            "protocol": req.protocol.value,
            "verb": req.verb() or "",
            "known": bool(req.known),
            "inputs_so_far": st.count,
            "seconds_since_last": round(now - st.last_ts, 3) if st.count else None,
            "last_tactic": st.last_tactic,
            "seen_before": text in st.seen,
        }
        st.count += 1
        st.last_ts = now
        st.seen.add(text)
        if tactic:
            st.last_tactic = tactic
        return features


def is_explore(req: DecideRequest, enabled: bool) -> bool:
    """True only when exploration is switched on and the source is in the lab explore range."""
    if not enabled:
        return False
    ip = req.src.ip
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip) in EXPLORE_NET
    except ValueError:
        return False


@dataclass
class Choice:
    action: Action
    propensity: float  # probability the acting policy gave the chosen action
    probs: dict[str, float]  # probability of every allowed action


class BanditPolicy:
    """Epsilon-greedy over the rule's action (v0). A trained model replaces ``probs`` later."""

    def __init__(self, epsilon: float = EPSILON) -> None:
        self.epsilon = epsilon
        self.name = f"epsilon-greedy-v0(eps={epsilon})"

    def probs(self, allowed: list[Action], rule_action: Action) -> dict[Action, float]:
        base = rule_action if rule_action in allowed else allowed[0]
        n = len(allowed)
        p = {a: self.epsilon / n for a in allowed}
        p[base] += 1.0 - self.epsilon
        return p

    def sample(self, allowed: list[Action], rule_action: Action, rng: random.Random) -> Choice:
        p = self.probs(allowed, rule_action)
        r, cumulative = rng.random(), 0.0
        chosen = allowed[-1]
        for action, prob in p.items():
            cumulative += prob
            if r <= cumulative:
                chosen = action
                break
        return Choice(chosen, p[chosen], {a.value: round(pr, 6) for a, pr in p.items()})

    def shadow(self, allowed: list[Action], rule_action: Action) -> dict[str, float]:
        return {a.value: round(pr, 6) for a, pr in self.probs(allowed, rule_action).items()}


def explore_enabled() -> bool:
    return os.environ.get("POLICY_EXPLORE", "").lower() == "lab"


@dataclass
class _TacticRule:
    protocol: str
    patterns: list[re.Pattern[str]]
    tactic: str
    confidence: float


class TacticRules:
    """The ``last_tactic`` context feature (spec Q12), read in-process from the tagger's rule
    files. A minimal reader of the same YAML -- no dependency on the intel package, whose
    libraries are heavy and do not belong in the policy image."""

    def __init__(self, rules: list[_TacticRule]) -> None:
        self._rules = rules

    @classmethod
    def load(cls, directory: Path | None) -> TacticRules:
        rules: list[_TacticRule] = []
        if directory and directory.is_dir():
            for path in sorted(directory.glob("*.yaml")):
                doc = yaml.safe_load(path.read_text()) or {}
                for item in doc.get("rules", []):
                    patterns = item.get("any_of") or item.get("all_of") or []
                    if isinstance(patterns, str):
                        patterns = [patterns]
                    rules.append(
                        _TacticRule(
                            protocol=item.get("protocol", "any"),
                            patterns=[re.compile(p, re.IGNORECASE) for p in patterns],
                            tactic=item["tactic"],
                            confidence=float(item.get("confidence", 0.8)),
                        )
                    )
        return cls(rules)

    def tactic(self, protocol: str, text: str) -> str | None:
        best: _TacticRule | None = None
        for rule in self._rules:
            if rule.protocol not in (protocol, "any"):
                continue
            if any(p.search(text) for p in rule.patterns) and (
                best is None or rule.confidence > best.confidence
            ):
                best = rule
        return best.tactic if best else None

    @classmethod
    def from_env(cls) -> TacticRules:
        path = os.environ.get("POLICY_TECHNIQUE_RULES")
        return cls.load(Path(path) if path else None)
