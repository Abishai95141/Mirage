"""Gate 2 test 8: are the bandit's logged probabilities the true ones?

Every later policy comparison reweights logged decisions by the probability the acting policy
recorded for them. If that number is not the probability the action was really drawn with, every
estimate is wrong and nothing fails. This reads the policy service's decisions from ClickHouse
and checks the log against itself:

- **size**: enough explore sessions and decisions to be worth evaluating on;
- **range**: nothing explored outside the lab explore range, and only the rules acted elsewhere;
- **mask**: no action outside the allowed set, and no ``terminate`` on a session's first input;
- **consistency**: the logged propensity is the logged probability of the chosen action, and
  each logged distribution sums to one;
- **calibration**: within each bucket (protocol and logged distribution) the observed action
  counts agree with the logged probabilities, by a chi-square test;
- **weights**: the mean importance weight of a uniform target policy is 1 within its interval.

    uv run python -m mirage_intel.explore_check [--since 2026-11-14T17:00:00] [--min-sessions 300]

It prints a JSON report and exits non-zero if any check fails. No input text is read.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any

import numpy as np
from scipy.stats import chisquare

from mirage_intel.dataset import ClickHouse, _env_file

EXPLORE_NET = ipaddress.ip_network("198.19.0.0/16")  # the lab explore range (spec Q6)
ALPHA = 0.01  # family-wise, Bonferroni-corrected over the buckets tested
MIN_EXPECTED = 5.0  # chi-square needs every expected count at least this large
TOL = 1e-5  # logged probabilities are rounded to six places

# One row per decision the policy service logged. Structural fields only: no command text.
DECISIONS_SQL = """
SELECT
    session_id,
    src_ip,
    protocol,
    JSONExtractBool(payload, 'explore')            AS explore,
    JSONExtractRaw(payload, 'acting')              AS acting,
    JSONExtractRaw(payload, 'allowed')             AS allowed,
    JSONExtractInt(payload, 'seq')                 AS seq
FROM mirage.events FINAL
WHERE source = 'policy' AND class = 'policy_decision' {since}
"""


@dataclass
class Decision:
    session_id: str
    src_ip: str
    protocol: str
    explore: bool
    policy: str  # name of the policy that acted
    action: str
    propensity: float
    probs: dict[str, float]  # the acting policy's probability for every allowed action
    allowed: list[str]
    seq: int

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> Decision:
        acting = row["acting"]
        acting = json.loads(acting) if isinstance(acting, str) and acting else (acting or {})
        allowed = row["allowed"]
        allowed = json.loads(allowed) if isinstance(allowed, str) and allowed else (allowed or [])
        return cls(
            session_id=row.get("session_id") or "",
            src_ip=row.get("src_ip") or "",
            protocol=row.get("protocol") or "",
            explore=bool(row.get("explore")),
            policy=acting.get("name", ""),
            action=acting.get("action", ""),
            propensity=float(acting.get("propensity") or 0.0),
            probs={k: float(v) for k, v in (acting.get("probs") or {}).items()},
            allowed=list(allowed),
            seq=int(row.get("seq") or 0),
        )


@dataclass
class Check:
    name: str
    ok: bool
    detail: dict[str, Any] = field(default_factory=dict)


def _in_explore_range(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in EXPLORE_NET
    except ValueError:
        return False


def check_size(explore: list[Decision], min_sessions: int, min_decisions: int) -> Check:
    sessions = len({d.session_id for d in explore})
    return Check(
        "size",
        sessions >= min_sessions and len(explore) >= min_decisions,
        {
            "explore_sessions": sessions,
            "explore_decisions": len(explore),
            "min_sessions": min_sessions,
            "min_decisions": min_decisions,
        },
    )


def check_range(decisions: list[Decision]) -> Check:
    outside = sum(1 for d in decisions if d.explore and not _in_explore_range(d.src_ip))
    not_rules = sum(1 for d in decisions if not d.explore and d.policy != "rules")
    return Check(
        "range",
        outside == 0 and not_rules == 0,
        {"explored_outside_lab_range": outside, "non_rule_policy_acted_elsewhere": not_rules},
    )


def check_mask(explore: list[Decision]) -> Check:
    masked = sum(1 for d in explore if d.action not in d.allowed)
    first_terminate = sum(1 for d in explore if d.seq <= 1 and d.action == "terminate")
    return Check(
        "mask",
        masked == 0 and first_terminate == 0,
        {"action_outside_allowed": masked, "terminate_on_first_input": first_terminate},
    )


def check_consistency(explore: list[Decision]) -> Check:
    wrong_propensity = sum(
        1 for d in explore if abs(d.probs.get(d.action, -1.0) - d.propensity) > TOL
    )
    bad_sum = sum(1 for d in explore if abs(sum(d.probs.values()) - 1.0) > 10 * TOL)
    wrong_support = sum(1 for d in explore if set(d.probs) != set(d.allowed))
    return Check(
        "consistency",
        wrong_propensity == 0 and bad_sum == 0 and wrong_support == 0,
        {
            "propensity_not_prob_of_action": wrong_propensity,
            "distribution_does_not_sum_to_one": bad_sum,
            "distribution_not_over_allowed_set": wrong_support,
        },
    )


def check_calibration(explore: list[Decision], alpha: float = ALPHA) -> Check:
    """Chi-square goodness of fit, one test per (protocol, logged distribution) bucket."""
    buckets: dict[tuple, list[str]] = defaultdict(list)
    for d in explore:
        key = (d.protocol, tuple(sorted((a, round(p, 6)) for a, p in d.probs.items())))
        buckets[key].append(d.action)
    tested, skipped, results = 0, 0, []
    for (protocol, dist), actions in buckets.items():
        n = len(actions)
        expected = np.array([p * n for _, p in dist])
        if n == 0 or expected.min() < MIN_EXPECTED:
            skipped += n  # too few decisions for the approximation to hold
            continue
        counts = Counter(actions)
        observed = np.array([counts.get(a, 0) for a, _ in dist])
        if observed.sum() != n:  # an action outside the logged distribution: the mask check's job
            results.append({"protocol": protocol, "n": n, "p_value": 0.0})
            tested += 1
            continue
        stat = chisquare(observed, expected * (n / expected.sum()))
        results.append({"protocol": protocol, "n": n, "p_value": float(stat.pvalue)})
        tested += 1
    threshold = alpha / tested if tested else alpha
    rejected = [r for r in results if r["p_value"] < threshold]
    return Check(
        "calibration",
        tested > 0 and not rejected,
        {
            "buckets_tested": tested,
            "decisions_in_buckets_too_small_to_test": skipped,
            "bonferroni_threshold": threshold,
            "min_p_value": min((r["p_value"] for r in results), default=None),
            "rejected": rejected,
        },
    )


def check_weights(explore: list[Decision], draws: int = 2000, seed: int = 0) -> Check:
    """A uniform target policy's importance weights must average 1 if the propensities are true."""
    usable = [d for d in explore if d.propensity > 0 and d.allowed]
    if not usable:
        return Check("weights", False, {"reason": "no usable decisions"})
    w = np.array([(1.0 / len(d.allowed)) / d.propensity for d in usable])
    rng = np.random.default_rng(seed)
    means = [float(np.mean(w[rng.integers(0, len(w), len(w))])) for _ in range(draws)]
    lo, hi = (float(x) for x in np.percentile(means, [2.5, 97.5]))
    return Check(
        "weights",
        lo <= 1.0 <= hi,
        {"mean_weight": float(np.mean(w)), "ci_low": lo, "ci_high": hi, "n": len(w)},
    )


def run_checks(
    decisions: list[Decision], min_sessions: int = 300, min_decisions: int = 3000
) -> list[Check]:
    explore = [d for d in decisions if d.explore]
    return [
        check_size(explore, min_sessions, min_decisions),
        check_range(decisions),
        check_mask(explore),
        check_consistency(explore),
        check_calibration(explore),
        check_weights(explore),
    ]


def fetch(ch: ClickHouse, since: str | None) -> list[Decision]:
    clause = ""
    if since:
        # Validated as a timestamp before it goes into the query text.
        from datetime import datetime

        stamp = datetime.fromisoformat(since).strftime("%Y-%m-%d %H:%M:%S")
        clause = f"AND ts >= toDateTime64('{stamp}', 6, 'UTC')"
    return [Decision.from_row(r) for r in ch.rows(DECISIONS_SQL.format(since=clause))]


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage-explore-check")
    ap.add_argument("--since", help="only decisions at or after this UTC time (ISO 8601)")
    ap.add_argument("--min-sessions", type=int, default=300)
    ap.add_argument("--min-decisions", type=int, default=3000)
    args = ap.parse_args(argv)
    os.environ.update({k: v for k, v in _env_file().items() if k not in os.environ})
    decisions = fetch(ClickHouse.from_env(), args.since)
    checks = run_checks(decisions, args.min_sessions, args.min_decisions)
    report = {
        "decisions": len(decisions),
        "passed": all(c.ok for c in checks),
        "checks": [asdict(c) for c in checks],
    }
    print(json.dumps(report, indent=2))
    sys.exit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
