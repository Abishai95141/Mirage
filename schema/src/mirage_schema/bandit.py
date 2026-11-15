"""The learned response policy's shared logic (phase 2 spec, 2.5).

Two programs must agree exactly on what a learned policy does: the code that trains and
evaluates it offline (``mirage_intel.policylearn``) and the policy service that loads it and
logs what it would have chosen. If each had its own copy of "how a context becomes buckets"
or "how a saved table picks an action", a difference between them would make every offline
number describe a policy that is not the one running. So both import this module, which has
no dependency beyond the standard library.

A saved policy is plain JSON, one of two kinds:

- ``table``: per bucket and action, a mean reward and an effective sample size, at several
  grains from fine to coarse. The choice is the best supported action at the finest grain that
  knows enough, and the rule's action otherwise.
- ``linear``: per action, a weight for each one-hot context feature and an intercept. The
  choice is the allowed action with the highest predicted reward.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

SMOOTH = 0.1  # the share of exploration a learned policy keeps when it acts or shadows

INPUT_EDGES, INPUT_NAMES = (0, 2, 5, 10), ("0", "1-2", "3-5", "6-10", "11+")
SINCE_EDGES, SINCE_NAMES = (0.5, 2, 10), ("<0.5s", "<2s", "<10s", "10s+")


def _bucket(value: float, edges: Sequence[float], names: Sequence[str]) -> str:
    """The name of the first bucket whose upper edge the value does not exceed."""
    for edge, name in zip(edges, names, strict=False):
        if value <= edge:
            return name
    return names[-1]


def buckets(context: Mapping[str, Any]) -> dict[str, str]:
    """A decision's context as categories. Accepts the policy service's context object and a
    row of the decision table alike: a missing gap is ``None`` in one and negative in the
    other, a missing tactic ``None`` or an empty string."""
    since = context.get("seconds_since_last")
    first = since is None or float(since) < 0
    return {
        "protocol": str(context.get("protocol") or ""),
        "verb_class": str(context.get("verb_class") or "other"),
        "known": "known" if context.get("known") else "unknown",
        "inputs": _bucket(int(context.get("inputs_so_far") or 0), INPUT_EDGES, INPUT_NAMES),
        "since": "first" if first else _bucket(float(since), SINCE_EDGES, SINCE_NAMES),
        "tactic": str(context.get("last_tactic") or "none"),
        "seen": "seen" if context.get("seen_before") else "new",
    }


def _table_choice(
    model: Mapping[str, Any], cats: Mapping[str, str], allowed: Sequence[str], rule: str
) -> str:
    support, margin = float(model["min_support"]), float(model.get("margin", 0.0))
    judged: set[str] = set()  # actions a finer bucket knew, and found no better than the rule
    for level, cells in zip(model["levels"], model["cells"], strict=True):
        acts = cells.get("|".join(cats[k] for k in level))
        if not acts or rule not in acts or acts[rule][1] < support:
            continue  # too little is known about the rule's own action here: back off
        baseline = acts[rule][0]
        # Only actions no finer bucket has judged. A coarse bucket averages over contexts the
        # fine one tells apart, so it must not bring back an action the fine one ruled out.
        fresh = {
            a: v[0]
            for a, v in acts.items()
            if v[1] >= support and a in allowed and a != rule and a not in judged
        }
        if fresh:
            best = max(sorted(fresh), key=lambda a: fresh[a])
            if fresh[best] > baseline + margin:
                return best
            judged |= set(fresh)
        if all(a == rule or a in judged for a in allowed):
            return rule  # every allowed action has been judged, and none beats the rule
        # some action is still unknown at this grain: a coarser bucket may know it
    return rule


def linear_scores(model: Mapping[str, Any], cats: Mapping[str, str]) -> dict[str, float]:
    index = model.get("_index")
    if index is None:
        index = {name: i for i, name in enumerate(model["features"])}
    active = [index[k] for k in (f"{name}={value}" for name, value in cats.items()) if k in index]
    return {a: sum(w[j] for j in active) + w[-1] for a, w in model["weights"].items()}


def choose(
    model: Mapping[str, Any], context: Mapping[str, Any], allowed: Sequence[str], rule: str
) -> str:
    """The saved policy's action for this context: always one of ``allowed``."""
    fallback = rule if rule in allowed else allowed[0]
    cats = buckets(context)
    if model["kind"] == "table":
        choice = _table_choice(model, cats, allowed, fallback)
    elif model["kind"] == "linear":
        scores = {a: s for a, s in linear_scores(model, cats).items() if a in allowed}
        choice = max(sorted(scores), key=lambda a: scores[a]) if scores else fallback
    else:
        raise ValueError(f"unknown policy kind {model['kind']!r}")
    return choice if choice in allowed else fallback


def probabilities(
    model: Mapping[str, Any],
    context: Mapping[str, Any],
    allowed: Sequence[str],
    rule: str,
    smooth: float = SMOOTH,
) -> dict[str, float]:
    """The policy's distribution over the allowed actions: its choice, with ``smooth`` spread
    evenly over everything allowed."""
    choice = choose(model, context, allowed, rule)
    return {a: smooth / len(allowed) + (1.0 - smooth) * (a == choice) for a in allowed}


def validate(model: Mapping[str, Any]) -> None:
    """Refuse a file that is not a policy this module can run."""
    kind = model.get("kind")
    if kind == "table":
        levels, cells = model.get("levels"), model.get("cells")
        if not isinstance(levels, list) or not isinstance(cells, list) or len(levels) != len(cells):
            raise ValueError("a table policy needs one cell map per level")
        float(model["min_support"])
    elif kind == "linear":
        width = len(model.get("features", [])) + 1
        weights = model.get("weights")
        if not isinstance(weights, dict) or not weights:
            raise ValueError("a linear policy needs weights")
        for action, w in weights.items():
            if len(w) != width:
                raise ValueError(f"weights for {action} do not match the feature list")
    else:
        raise ValueError(f"unknown policy kind {kind!r}")
