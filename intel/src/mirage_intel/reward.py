"""The bandit's reward (phase 2 spec, 2.5), computed offline from a session's events.

The reward pays for intelligence, not for time: a session that stalls earns nothing. It is
attributed to each decision over the remainder of its session, so a decision that opened the
way to a new technique or a captured artifact is credited. The weights are versioned, because
changing them changes every policy comparison.

This is a pure function of a session's ordered decisions and what followed them; it does not
touch the network or the store. The sessioniser's own tagger rules supply the techniques, so
the same reward can be computed on real traffic, not only in the lab.
"""

from __future__ import annotations

from dataclasses import dataclass, field

REWARD_VERSION = "reward-v1"

W_NEW_TECHNIQUE = 1.0
W_ARTIFACT = 2.0
W_TOKEN = 3.0
W_EARLY_EXIT = -2.0  # the session ended right after a non-allow action: a likely tell


@dataclass
class Decision:
    """One gated input and what it led to, in session order."""

    seq: int
    action: str  # allow | delay | fake_success | fake_error | terminate
    techniques: frozenset[str] = frozenset()  # techniques seen at or after this input
    artifacts: frozenset[str] = frozenset()  # artifact hashes captured at or after it
    tokens: frozenset[str] = frozenset()  # honeytokens reached or used at or after it
    ended_after: bool = False  # the session's last input, with no further input after it


@dataclass
class Rewarded:
    seq: int
    reward: float
    parts: dict[str, float] = field(default_factory=dict)


def session_rewards(decisions: list[Decision]) -> list[Rewarded]:
    """Reward each decision by what was *first* seen at or after it, so a thing is paid once,
    to the decision that first reached it."""
    seen_tech: set[str] = set()
    seen_art: set[str] = set()
    seen_tok: set[str] = set()
    out = []
    for d in sorted(decisions, key=lambda x: x.seq):
        new_tech = d.techniques - seen_tech
        new_art = d.artifacts - seen_art
        new_tok = d.tokens - seen_tok
        seen_tech |= d.techniques
        seen_art |= d.artifacts
        seen_tok |= d.tokens
        parts = {
            "technique": W_NEW_TECHNIQUE * len(new_tech),
            "artifact": W_ARTIFACT * len(new_art),
            "token": W_TOKEN * len(new_tok),
        }
        if d.ended_after and d.action != "allow":
            parts["early_exit"] = W_EARLY_EXIT
        out.append(
            Rewarded(d.seq, round(sum(parts.values()), 6), {k: v for k, v in parts.items() if v})
        )
    return out


def total(decisions: list[Decision]) -> float:
    return round(sum(r.reward for r in session_rewards(decisions)), 6)
