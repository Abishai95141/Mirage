"""Four checks on phase 2's frozen decisions, before phase 3's learned policy is built
(phase 3 spec, 3.3 "First"; the survey that asked for them: docs/research/deception-rl.md).

1. **Closed loop.** The explorer chose each action at random with a logged probability, so
   every logged decision is a small randomised experiment. Does what the decoy answered change
   what the attacker did next: whether the session went on, how many inputs followed, whether
   the next input repeated this one? And does any action raise what the session was worth?
   If nothing depends on the answer, no policy can gain anything on this traffic.
2. **Imitation.** With its dial at the careful end, a learner must be the rule.
3. **Conservative learners.** Learners that leave the rule only where the data support it,
   at several settings of that dial, each scored on sessions it did not see (cross-fitted by
   scenario group) by the doubly robust difference to the rules.
4. **The reward's loopholes.** How much of the penalty for a session that ends after a
   non-allow action is coincidence, and what never leaving ``allow`` is worth.

Only train and dev sessions are read: the test sessions were read once, for phase 2's shadow.

Every interval is computed twice, resampling sessions and resampling scenario groups. Sessions
of one scenario are repeats of one script, so the group interval is the honest one for "would
this hold on a new scenario"; the wider of the two is the one reported as ``ci``. The exact
interval the offline screen will add (3.3) is not built here.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np

from mirage_intel import policylearn as pl

ROOT = Path(__file__).resolve().parents[4]
OUT = ROOT / "build" / "experiments" / "phase-3"
READ = ("train", "dev")
NON_ALLOW = ("delay", "fake_success", "fake_error", "terminate")
OUTCOMES = ("continues", "remaining", "repeats", "reward_truth", "reward_no_exit")
FOLDS = 5
EXIT_PENALTY = -2.0  # reward.W_EARLY_EXIT: paid by a session's last decision if it was not allow


# ---------------------------------------------------------------- data


def load(data: Path) -> list[dict[str, Any]]:
    import pyarrow.parquet as pq

    return pq.read_table(data / "decisions.parquet").to_pylist()


def prepare(rows: list[dict[str, Any]], splits: tuple[str, ...] = READ) -> list[dict[str, Any]]:
    """The usable decisions of the splits that may be read, each with what followed it.

    What followed is taken from every logged decision of the session, usable or not: a
    decision the decoy fell back on is still an input the attacker sent."""
    by_session: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_session[r["session"]].append(r)
    out = []
    for members in by_session.values():
        members.sort(key=lambda r: r["pos"])
        last = members[-1]["pos"]
        for i, r in enumerate(members):
            if not r["usable"] or r["split"] not in splits:
                continue
            nxt = members[i + 1] if i + 1 < len(members) else None
            ended_on_non_allow = r["pos"] == last and r["applied"] != "allow"
            out.append(
                {
                    **r,
                    "continues": float(nxt is not None),
                    "remaining": float(len(members) - 1 - i),
                    "repeats": float(nxt is not None and nxt["verb"] == r["verb"]),
                    "reward_no_exit": r["reward_truth"] - EXIT_PENALTY * ended_on_non_allow,
                }
            )
    return out


# ---------------------------------------------------------------- resampling


def unit_index(rows: list[dict[str, Any]], by: str) -> tuple[np.ndarray, int]:
    """Each row's unit (a session, or a scenario group) as an integer, and how many units."""
    names = sorted({r[by] for r in rows})
    index = {n: i for i, n in enumerate(names)}
    return np.array([index[r[by]] for r in rows]), len(names)


def unit_sums(columns: np.ndarray, units: np.ndarray, n_units: int) -> np.ndarray:
    """Per-unit column sums: (rows, C) to (units, C)."""
    out = np.zeros((n_units, columns.shape[1]))
    np.add.at(out, units, columns)
    return out


def resampled_totals(sums: np.ndarray, draws: int, seed: int) -> np.ndarray:
    """Column totals of ``draws`` bootstrap samples of the units: (draws, C). Drawing how many
    times each unit appears and multiplying is the same resampling as concatenating rows."""
    rng = np.random.default_rng(seed)
    n = sums.shape[0]
    counts = rng.multinomial(n, np.full(n, 1.0 / n), size=draws)
    return counts @ sums


def interval(
    columns: np.ndarray,
    stat: Callable[[np.ndarray], np.ndarray],
    rows: list[dict[str, Any]],
    draws: int,
    seed: int = 0,
) -> dict[str, Any]:
    """``stat`` maps column totals (.., C) to a number. Returns its value on the data and a
    95% interval under each resampling unit, with the wider one as ``ci``."""
    point = float(stat(columns.sum(axis=0)[None, :])[0])
    out: dict[str, Any] = {"value": round(point, 4)}
    for name, by in (("ci_sessions", "session"), ("ci_groups", "group")):
        units, n_units = unit_index(rows, by)
        samples = stat(resampled_totals(unit_sums(columns, units, n_units), draws, seed))
        lo, hi = np.nanpercentile(samples, [2.5, 97.5])
        out[name] = [round(float(lo), 4), round(float(hi), 4)]
    wider = max(("ci_sessions", "ci_groups"), key=lambda k: out[k][1] - out[k][0])
    out["ci"] = out[wider]
    return out


def _ratio(num: np.ndarray, den: np.ndarray) -> np.ndarray:
    return np.divide(num, den, out=np.full_like(num, np.nan, dtype=float), where=den > 0)


# ---------------------------------------------------------------- 1. closed loop


def action_effect(
    rows: list[dict[str, Any]], action: str, outcome: str, draws: int
) -> dict[str, Any]:
    """E[outcome | the decoy answers ``action``] minus E[outcome | it answers ``allow``],
    over the decisions where ``action`` was allowed. Each side is a self-normalised
    inverse-propensity mean, so the comparison is between the same population of decisions."""
    where = [r for r in rows if action in pl.allowed_of(r) and "allow" in pl.allowed_of(r)]
    if not where:
        return {"value": None, "taken": 0}
    y = np.array([r[outcome] for r in where], dtype=float)
    cols = np.zeros((len(where), 4))
    taken = 0
    for i, r in enumerate(where):
        probs = pl.logged_probs(r)
        if r["action"] == action:
            cols[i, 0], cols[i, 1] = y[i] / probs[action], 1.0 / probs[action]
            taken += 1
        elif r["action"] == "allow":
            cols[i, 2], cols[i, 3] = y[i] / probs["allow"], 1.0 / probs["allow"]

    def stat(t: np.ndarray) -> np.ndarray:
        return _ratio(t[:, 0], t[:, 1]) - _ratio(t[:, 2], t[:, 3])

    total = cols.sum(axis=0)
    if taken == 0 or total[3] == 0:  # one side was never observed here: nothing to compare
        return {"value": None, "taken": taken}
    out = interval(cols, stat, where, draws)
    out["under_action"] = round(float(total[0] / total[1]), 4) if total[1] else None
    out["under_allow"] = round(float(total[2] / total[3]), 4) if total[3] else None
    out["taken"] = taken
    out["decisions"] = len(where)
    return out


def closed_loop(rows: list[dict[str, Any]], draws: int) -> dict[str, Any]:
    overall = {a: {o: action_effect(rows, a, o, draws) for o in OUTCOMES} for a in NON_ALLOW}
    strata: list[dict[str, Any]] = []
    for key in ("protocol", "verb_class"):
        for value in sorted({r[key] for r in rows}):
            part = [r for r in rows if r[key] == value]
            for a in NON_ALLOW:
                e = action_effect(part, a, "reward_no_exit", draws)
                if e.get("taken", 0) >= 20:
                    strata.append({"by": key, "stratum": value, "action": a, **e})
    return {"overall": overall, "strata": strata}


def excludes_zero(e: dict[str, Any]) -> bool:
    return e.get("value") is not None and (e["ci"][0] > 0 or e["ci"][1] < 0)


# ---------------------------------------------------------------- learners


class CautiousLinear:
    """A linear reward model that leaves the rule only where it is sure.

    ``members`` models are fitted on resamples of the training sessions. An action replaces
    the rule's when its predicted advantage over the rule's action, averaged over the members
    and less ``z`` standard deviations across them, is above zero. ``z`` is the dial: at 0 it
    is the bagged greedy choice, and a large ``z`` never leaves the rule."""

    def __init__(self, z: float, members: int = 25, ridge: float = 1.0, seed: int = 0) -> None:
        self.z, self.members, self.ridge, self.seed = z, members, ridge, seed
        self.name = f"cautious-linear(z={z:g})"
        self.models: list[pl.LinearPolicy] = []
        self._cache: dict[tuple, str] = {}

    def fit(self, rows: list[dict[str, Any]], reward: str) -> CautiousLinear:
        self._cache = {}
        by_session: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in rows:
            by_session[r["session"]].append(r)
        sessions = sorted(by_session)
        rng = np.random.default_rng(self.seed)
        self.models = []
        for _ in range(self.members):
            draw = rng.integers(0, len(sessions), len(sessions))
            sample = [r for i in draw for r in by_session[sessions[i]]]
            self.models.append(pl.LinearPolicy(ridge=self.ridge, weighted=True).fit(sample, reward))
        return self

    def choose(self, row: dict[str, Any]) -> str:
        allowed, rule = pl.allowed_of(row), row["rule_action"]
        key = (tuple(sorted(pl.context(row).items())), tuple(allowed), rule)
        if key not in self._cache:
            self._cache[key] = self._decide(row, allowed, rule)
        return self._cache[key]

    def _decide(self, row: dict[str, Any], allowed: list[str], rule: str) -> str:
        scores = [{a: float(v[0]) for a, v in m.predict([row]).items()} for m in self.models]
        best, best_bound = rule, 0.0
        for a in allowed:
            if a == rule:
                continue
            gains = [s[a] - s[rule] for s in scores if a in s and rule in s]
            if len(gains) < max(2, len(self.models) // 2):
                continue  # too few members ever saw this action: no support
            bound = float(np.mean(gains) - self.z * np.std(gains))
            if bound > best_bound:
                best, best_bound = a, bound
        return best


def candidates() -> list[tuple[str, Callable[[], Any]]]:
    out: list[tuple[str, Callable[[], Any]]] = []
    for s in (15.0, 30.0, 60.0, 120.0):
        out.append((f"table(support>={s:g})", lambda s=s: pl.TablePolicy(min_support=s)))
    for z in (0.0, 1.0, 2.0, 3.0):
        out.append((f"cautious-linear(z={z:g})", lambda z=z: CautiousLinear(z)))
    out.append(("linear(ridge=1,ipw)", lambda: pl.LinearPolicy(ridge=1.0, weighted=True)))
    return out


def most_careful() -> list[tuple[str, Callable[[], Any]]]:
    """Each learner family with its dial at the careful end, for the imitation check."""
    return [
        ("table(support>=1e9)", lambda: pl.TablePolicy(min_support=1e9)),
        ("cautious-linear(z=1e6)", lambda: CautiousLinear(1e6)),
    ]


# ---------------------------------------------------------------- 2 and 3. cross-fitting


def folds_of(rows: list[dict[str, Any]], k: int = FOLDS, seed: int = 0) -> dict[str, int]:
    """Scenario group to fold. A group is never split, so no session is scored by a model
    that saw another session of its scenario."""
    groups = sorted({r["group"] for r in rows})
    order = np.random.default_rng(seed).permutation(len(groups))
    return {groups[g]: i % k for i, g in enumerate(order)}


def cross_fit(
    rows: list[dict[str, Any]],
    make: Callable[[], Any],
    reward: str,
    fold_of: dict[str, int],
    rules_smooth: float = pl.SMOOTH,
) -> dict[str, np.ndarray]:
    """Score every decision with a policy and a reward model fitted on the other folds.
    Returns per-decision arrays aligned with ``rows``.

    The candidate and the rules are scored with the same exploration share (``pl.SMOOTH``,
    what a learned policy keeps when it acts), so a learner that is the rule differs from it
    by exactly nothing. Phase 2 scored the rules without that share (``rules_smooth=0``),
    which charges the candidate for its exploration as well as for its choices."""
    n = len(rows)
    out = {k: np.zeros(n) for k in ("d_dr", "ips_c", "ips_r", "w_c", "w_r", "changed")}
    rules = pl.RulesPolicy()
    for fold in sorted(set(fold_of.values())):
        held = [i for i, r in enumerate(rows) if fold_of[r["group"]] == fold]
        if not held:
            continue
        fit_on = [r for r in rows if fold_of[r["group"]] != fold]
        score_on = [rows[i] for i in held]
        model = pl.LinearPolicy(ridge=1.0).fit(fit_on, reward)  # the reward model for DR
        policy = make().fit(fit_on, reward)
        c = pl.terms(policy, score_on, reward, model, smooth=pl.SMOOTH)
        b = pl.terms(rules, score_on, reward, model, smooth=rules_smooth)
        dr_c = c["q_target"] + c["weight"] * (c["reward"] - c["q_logged"])
        dr_b = b["q_target"] + b["weight"] * (b["reward"] - b["q_logged"])
        out["d_dr"][held] = dr_c - dr_b
        out["ips_c"][held] = c["weight"] * c["reward"]
        out["ips_r"][held] = b["weight"] * b["reward"]
        out["w_c"][held] = c["weight"]
        out["w_r"][held] = b["weight"]
        out["changed"][held] = [policy.choose(r) != r["rule_action"] for r in score_on]
    return out


def judge(rows: list[dict[str, Any]], parts: dict[str, np.ndarray], draws: int) -> dict[str, Any]:
    """The offline screen's reading of one cross-fitted candidate against the rules."""
    ones = np.ones(len(rows))
    cols = np.column_stack(
        [parts["d_dr"], ones, parts["ips_c"], parts["ips_r"], parts["w_c"], parts["w_r"]]
    )
    dr = interval(cols, lambda t: _ratio(t[:, 0], t[:, 1]), rows, draws)
    ips = interval(cols, lambda t: _ratio(t[:, 2] - t[:, 3], t[:, 1]), rows, draws)
    snips = interval(
        cols, lambda t: _ratio(t[:, 2], t[:, 4]) - _ratio(t[:, 3], t[:, 5]), rows, draws
    )
    w = parts["w_c"]
    units, n_units = unit_index(rows, "session")
    per_session = unit_sums(w[:, None], units, n_units)[:, 0]
    signs = {np.sign(round(e["value"], 6)) for e in (dr, ips, snips)}
    return {
        "dr": dr,
        "ips": ips,
        "snips": snips,
        "same_sign": len(signs) == 1,
        "changed": round(float(parts["changed"].mean()), 4),
        "ess_decisions": round(float(w.sum() ** 2 / max((w**2).sum(), 1e-12)), 1),
        "ess_sessions": round(
            float(per_session.sum() ** 2 / max((per_session**2).sum(), 1e-12)), 1
        ),
        "top10_session_weight_share": round(
            float(np.sort(per_session)[-10:].sum() / max(per_session.sum(), 1e-12)), 4
        ),
        "passes_screen": bool(len(signs) == 1 and dr["ci"][0] > 0),
    }


def exploration_share_cost(
    rows: list[dict[str, Any]], fold_of: dict[str, int], draws: int
) -> dict[str, Any]:
    """The rules with the exploration share minus the rules without it: what phase 2's way
    of scoring charged every learned policy before its choices were looked at."""
    parts = cross_fit(
        rows, lambda: pl.TablePolicy(min_support=1e9), "reward_truth", fold_of, rules_smooth=0.0
    )
    return judge(rows, parts, draws)["dr"]


def imitation(rows: list[dict[str, Any]], fold_of: dict[str, int]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "rule_actions": dict(
            sorted(
                {a: sum(r["rule_action"] == a for r in rows) for a in pl.ACTIONS}.items(),
                key=lambda kv: -kv[1],
            )
        ),
        "learners": {},
    }
    for name, make in most_careful():
        parts = cross_fit(rows, make, "reward_truth", fold_of)
        out["learners"][name] = {"agrees_with_rule": round(1.0 - float(parts["changed"].mean()), 4)}
    return out


def conservative(
    rows: list[dict[str, Any]], fold_of: dict[str, int], draws: int
) -> list[dict[str, Any]]:
    out = []
    for name, make in candidates():
        row: dict[str, Any] = {"name": name}
        for reward in ("reward_truth", "reward_no_exit"):
            row[reward] = judge(rows, cross_fit(rows, make, reward, fold_of), draws)
        out.append(row)
    return out


# ---------------------------------------------------------------- 4. the reward


def loopholes(rows: list[dict[str, Any]], effects: dict[str, Any]) -> dict[str, Any]:
    fired = [r for r in rows if r["reward_no_exit"] != r["reward_truth"]]
    paid = sum(r["reward_no_exit"] for r in rows)
    out: dict[str, Any] = {
        "decisions": len(rows),
        "exit_penalty_fired": len(fired),
        "exit_penalty_total": round(EXIT_PENALTY * len(fired), 1),
        "reward_paid_without_it": round(paid, 1),
        "by_action": {},
    }
    for a in NON_ALLOW:
        e = effects[a]["continues"]
        if e.get("value") is None:
            continue
        ends_action = 1.0 - e["under_action"]
        ends_allow = 1.0 - e["under_allow"]
        out["by_action"][a] = {
            "session_ends_after_it": round(ends_action, 4),
            "session_ends_after_allow": round(ends_allow, 4),
            # of the times the penalty fires for this action, the share in which the session
            # would have ended there anyway
            "share_coincidence": round(min(1.0, ends_allow / ends_action), 4)
            if ends_action > 0
            else None,
            "effect_on_reward": effects[a]["reward_truth"]["value"],
            "effect_on_reward_without_penalty": effects[a]["reward_no_exit"]["value"],
        }
    return out


# ---------------------------------------------------------------- run


def run(data: Path, draws: int) -> dict[str, Any]:
    rows = prepare(load(data))
    fold_of = folds_of(rows)
    loop = closed_loop(rows, draws)
    return {
        "data": str(data),
        "splits_read": list(READ),
        "decisions": len(rows),
        "sessions": len({r["session"] for r in rows}),
        "groups": len({r["group"] for r in rows}),
        "draws": draws,
        "closed_loop": loop,
        "imitation": imitation(rows, fold_of),
        "conservative": conservative(rows, fold_of, draws),
        "exploration_share_cost": exploration_share_cost(rows, fold_of, draws),
        "loopholes": loopholes(rows, loop["overall"]),
    }


def _fmt(e: dict[str, Any]) -> str:
    if e.get("value") is None:
        return "n/a"
    star = " *" if excludes_zero(e) else ""
    return f"{e['value']:+.3f} [{e['ci'][0]:+.3f}, {e['ci'][1]:+.3f}]{star}"


def report(result: dict[str, Any]) -> str:
    lines = [
        f"{result['decisions']} decisions, {result['sessions']} sessions, "
        f"{result['groups']} scenario groups ({', '.join(result['splits_read'])})",
        "",
        "1. closed loop: effect of each answer against allow (* = interval excludes zero)",
    ]
    for a, by_outcome in result["closed_loop"]["overall"].items():
        lines.append(f"   {a} (taken {by_outcome['continues'].get('taken', 0)} times)")
        lines += [f"     {o:<15} {_fmt(e)}" for o, e in by_outcome.items()]
    gains = [s for s in result["closed_loop"]["strata"] if s["value"] is not None]
    positive = [s for s in gains if s["ci"][0] > 0]
    lines.append(
        f"   strata tested for a gain in reward without the penalty: {len(gains)}; "
        f"with an interval above zero: {len(positive)}"
    )
    for s in positive:
        lines.append(f"     {s['by']}={s['stratum']} {s['action']}: {_fmt(s)} (taken {s['taken']})")
    lines += ["", "2. imitation: agreement with the rule at the careful end of the dial"]
    lines.append(f"   rule actions in the log: {result['imitation']['rule_actions']}")
    for name, v in result["imitation"]["learners"].items():
        lines.append(f"   {name:<26} {v['agrees_with_rule']:.4f}")
    lines += ["", "3. conservative learners: doubly robust difference to the rules, cross-fitted"]
    for c in result["conservative"]:
        t, x = c["reward_truth"], c["reward_no_exit"]
        lines.append(
            f"   {c['name']:<26} {_fmt(t['dr'])}  changed {t['changed']:.2f}  "
            f"ess {t['ess_decisions']:.0f}/{t['ess_sessions']:.0f}  "
            f"without penalty {_fmt(x['dr'])}"
        )
    lines.append(
        "   the rules with the 10% exploration share, minus the rules without it: "
        + _fmt(result["exploration_share_cost"])
    )
    lo = result["loopholes"]
    lines += [
        "",
        "4. the reward",
        f"   the exit penalty fired on {lo['exit_penalty_fired']} of {lo['decisions']} decisions "
        f"({lo['exit_penalty_total']} against {lo['reward_paid_without_it']} paid)",
    ]
    for a, v in lo["by_action"].items():
        lines.append(
            f"   {a:<13} session ends after it {v['session_ends_after_it']:.2f}, after allow "
            f"{v['session_ends_after_allow']:.2f}, coincidence {v['share_coincidence']}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--data", type=Path, default=ROOT / "eval" / "datasets" / "gate2")
    ap.add_argument("--draws", type=int, default=1000)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)
    result = run(args.data, args.draws)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "rl-checks.json").write_text(json.dumps(result, indent=1) + "\n")
    print(report(result))
    print(f"\nwritten to {args.out / 'rl-checks.json'}")


if __name__ == "__main__":
    main()
