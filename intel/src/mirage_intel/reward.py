"""The bandit's reward (phase 2 spec, 2.5), computed offline from a session's events.

The spec's sentence: *for each decision, over the rest of its session: +1 per new distinct
technique, +2 per new captured artifact, +3 per honeytoken reached or used, -2 if the session
ends before the next input after a non-allow action. Nothing is paid for time or for input
count.*

So a decision is credited with everything that first appears **after** it. A response cannot
have caused the input it was a response to, so the technique of a decision's own input is not
part of its reward; it belongs to the decisions before it. Two decisions that both precede a
new technique are both credited: each could have ended the session and did not. This is
reward-to-go, and it is what makes an early ``terminate`` cost something.

(The first implementation paid each item once, to the first decision at or after which it
appeared, and counted a decision's own input. It was never run on stored data. This is the
reward the spec describes, under the same version name.)

Pure functions: no network, no store. ``decisions.py`` builds the inputs from the store, from
the tagger's labels and, in the lab, from ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field

REWARD_VERSION = "reward-v1"

WEIGHTS = {"technique": 1.0, "artifact": 2.0, "token": 3.0}
W_EARLY_EXIT = -2.0  # the session ended right after a non-allow action: a likely tell


@dataclass(frozen=True)
class Decision:
    """One gated input, in session order."""

    seq: int
    action: str  # allow | delay | fake_success | fake_error | terminate, as applied


@dataclass(frozen=True)
class Observation:
    """Something worth paying for, and the last decision it came after.

    ``after_seq`` is the ``seq`` of the latest decision that preceded it. A technique seen in
    the input of decision 4 came after decision 3. An artifact captured between decisions 4
    and 5 came after decision 4. Something that preceded every decision has ``after_seq`` 0.
    """

    kind: str  # technique | artifact | token
    value: str
    after_seq: int


@dataclass
class Rewarded:
    seq: int
    reward: float
    parts: dict[str, float] = field(default_factory=dict)


def session_rewards(decisions: list[Decision], observations: list[Observation]) -> list[Rewarded]:
    """Each decision's reward: what first appeared after it, and the early-exit penalty."""
    ordered = sorted(decisions, key=lambda d: d.seq)
    last_seq = ordered[-1].seq if ordered else 0
    first_after: dict[tuple[str, str], int] = {}
    for o in observations:
        key = (o.kind, o.value)
        first_after[key] = min(first_after.get(key, o.after_seq), o.after_seq)
    out = []
    for d in ordered:
        parts: dict[str, float] = {}
        for (kind, _value), after in first_after.items():
            # New after this decision: its first appearance follows this decision.
            if after >= d.seq:
                parts[kind] = parts.get(kind, 0.0) + WEIGHTS[kind]
        if d.seq == last_seq and d.action != "allow":
            parts["early_exit"] = W_EARLY_EXIT
        out.append(Rewarded(d.seq, round(sum(parts.values()), 6), parts))
    return out


def after_seq(decision_times: list[tuple[float, int]], ts: float) -> int:
    """The ``seq`` of the latest decision at or before ``ts`` (0 if none): where an event with
    only a timestamp sits on a session's decision timeline."""
    best = 0
    for when, seq in decision_times:
        if when <= ts and seq > best:
            best = seq
    return best
