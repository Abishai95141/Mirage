"""Which policy learner, and does it beat the rules? (phase 2 spec, 2.5; Gate 2 test 9)

Learners are fitted on the explore sessions of train-split scenarios and compared with the
rules on those of dev-split scenarios, by the difference of their off-policy estimates over
the same decisions. A learner is *eligible* if all three estimators agree in sign and the
doubly robust difference has an interval above zero. The pick is the simplest eligible one
(a readable table, then a linear model, then Vowpal Wabbit). If none is eligible the rules
stay, and that is the result.

Whether or not a learner is fit to act, one of them shadows: the policy service logs what it
would have done beside every decision, which is how the next comparison gets its data (Gate 2
test 9 asks for its value against the rules', not for it to win). The shadow is the eligible
pick when there is one. Otherwise it is the learner most worth watching: among those that can
be saved as a file and differ from the rules on at least ``MIN_CHANGED`` of the decisions (a
copy of the rules shows nothing), the one whose doubly robust interval has the highest lower
end.

Each learned policy is scored as it would act in the lab: its choice, with a tenth of the
probability spread over every allowed action. The rules are scored as they act: without.

    uv run python -m mirage_intel.experiments.bandit_bench [--reward reward_truth]
    uv run python -m mirage_intel.experiments.bandit_bench --final --choice "<name>"
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq

from mirage_intel import policylearn as pl
from mirage_intel.experiments.tagger_bench import log_mlflow

ROOT = Path(__file__).resolve().parents[4]
OUT = ROOT / "build" / "experiments" / "bandit"
MIN_CHANGED = 0.05  # a shadow that differs from the rules on fewer decisions shows nothing


def learners() -> list[tuple[int, Any]]:
    """(simplicity rank, learner): lower is simpler."""
    out: list[tuple[int, Any]] = []
    out += [(0, pl.TablePolicy(min_support=s)) for s in (15.0, 30.0, 60.0)]
    out += [
        (1, pl.LinearPolicy(ridge=r, weighted=w)) for r in (0.3, 1.0, 3.0) for w in (True, False)
    ]
    try:
        import vowpalwabbit  # noqa: F401

        out += [(2, pl.VWPolicy(t)) for t in ("ips", "dr", "mtr")]
    except ImportError:
        pass
    return out


def run(
    fit_on: list[dict], score_on: list[dict], reward: str, draws: int, only: str | None = None
) -> list[dict[str, Any]]:
    rules = pl.RulesPolicy()
    model = pl.LinearPolicy(ridge=1.0).fit(fit_on, reward)  # the reward model for DR
    rows = []
    for rank, learner in learners():
        if only and learner.name != only:
            continue
        policy = learner.fit(fit_on, reward)
        plain = pl.compare(policy, rules, score_on, reward, model, smooth_a=pl.SMOOTH, draws=draws)
        even = pl.compare(
            policy, rules, score_on, reward, model, smooth_a=pl.SMOOTH, balanced=True, draws=draws
        )
        value = pl.evaluate(policy, score_on, reward, model, smooth=pl.SMOOTH)
        rows.append(
            {
                "name": policy.name,
                "rank": rank,
                "value": {
                    "ips": round(value.ips, 4),
                    "snips": round(value.snips, 4),
                    "dr": round(value.dr, 4),
                },
                "ess": round(value.ess, 1),
                "vs_rules": plain,
                "vs_rules_session_balanced": even,
                "eligible": bool(plain["same_sign"] and plain["dr"]["ci"][0] > 0),
                "policy": policy,
            }
        )
    return rows


def pick(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    eligible = [r for r in rows if r["eligible"]]
    if not eligible:
        return None
    simplest = min(r["rank"] for r in eligible)
    return max(
        (r for r in eligible if r["rank"] == simplest), key=lambda r: r["vs_rules"]["dr"]["ci"][0]
    )


def shadow(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The learner that shadows: the eligible pick, or else the one most worth watching."""
    chosen = pick(rows)
    if chosen is not None and hasattr(chosen["policy"], "to_json"):
        return chosen
    watchable = [
        r
        for r in rows
        if hasattr(r["policy"], "to_json") and r["vs_rules"]["changed"] >= MIN_CHANGED
    ]
    if not watchable:
        return None
    return max(watchable, key=lambda r: (r["vs_rules"]["dr"]["ci"][0], -r["rank"], r["name"]))


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="bandit_bench")
    ap.add_argument("--data", type=Path, default=ROOT / "build" / "dataset")
    ap.add_argument("--reward", default="reward_truth", choices=["reward_truth", "reward_tagged"])
    ap.add_argument(
        "--final", action="store_true", help="score the chosen learner on test sessions"
    )
    ap.add_argument("--choice", help="learner name, with --final")
    ap.add_argument("--save", type=Path, help="write the shadow policy here as JSON")
    ap.add_argument("--draws", type=int, default=1000)
    args = ap.parse_args(argv)

    table = pq.read_table(args.data / "decisions.parquet").to_pylist()
    usable = [r for r in table if r["usable"]]
    by_split = {s: [r for r in usable if r["split"] == s] for s in ("train", "dev", "test")}
    if args.final:
        if not args.choice:
            # The learner the dev run settled on, as recorded with the other choices.
            import yaml

            doc = yaml.safe_load((ROOT / "eval" / "choices.yaml").read_text()) or {}
            args.choice = (doc.get("policy") or {}).get("shadow")
        if not args.choice:
            ap.error("--final needs --choice, or a policy.shadow in eval/choices.yaml")
        fit_on, score_on, split = by_split["train"] + by_split["dev"], by_split["test"], "test"
    else:
        fit_on, score_on, split = by_split["train"], by_split["dev"], "dev"
    if not fit_on or not score_on:
        raise SystemExit(f"no usable decisions to fit on or to score ({split})")

    rows = run(fit_on, score_on, args.reward, args.draws, args.choice if args.final else None)
    if args.final and not rows:
        raise SystemExit(f"no learner is called {args.choice!r}")
    # Who acts was decided on dev. The final run scores the learner named in advance on test
    # and saves it, whatever it scored: picking again here would be choosing on test.
    chosen = None if args.final else pick(rows)
    watching = rows[0] if args.final else shadow(rows)
    rules_value = pl.evaluate(pl.RulesPolicy(), score_on, args.reward)
    summary = {
        "split": split,
        "reward": args.reward,
        "decisions": {
            "all": len(table),
            "usable": len(usable),
            "fit": len(fit_on),
            "scored": len(score_on),
        },
        "sessions_scored": len({r["session"] for r in score_on}),
        "rules_value": {"ips": round(rules_value.ips, 4), "snips": round(rules_value.snips, 4)},
        "choice": "decided on dev (eval/choices.yaml)"
        if args.final
        else (chosen["name"] if chosen else "rules (no learner was eligible)"),
        "shadow": watching["name"] if watching else None,
        "candidates": [{k: v for k, v in r.items() if k != "policy"} for r in rows],
    }
    OUT.mkdir(parents=True, exist_ok=True)
    path = (
        OUT
        / f"{'final' if args.final else 'dev'}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
    )
    path.write_text(json.dumps(summary, indent=1) + "\n")
    if args.save:
        if watching is None:
            raise SystemExit("no learner can shadow: none differs from the rules enough")
        pl.save(
            watching["policy"],
            args.save,
            {"reward": args.reward, "fitted_on": len(fit_on), "scored_on": split},
        )
    logged = log_mlflow(
        f"phase2-bandit-{split}",
        [
            {
                "name": r["name"],
                "unit": "decision",
                "split": split,
                "threshold": 0.0,
                "metrics": {
                    "dr_diff": r["vs_rules"]["dr"]["diff"],
                    "dr_low": r["vs_rules"]["dr"]["ci"][0],
                    "dr_high": r["vs_rules"]["dr"]["ci"][1],
                    "snips_diff": r["vs_rules"]["snips"]["diff"],
                    "ips_diff": r["vs_rules"]["ips"]["diff"],
                    "balanced_dr_diff": r["vs_rules_session_balanced"]["dr"]["diff"],
                    "changed": r["vs_rules"]["changed"],
                    "ess": r["ess"],
                },
            }
            for r in rows
        ],
    )
    print(
        f"{split}: {len(score_on)} usable decisions in {summary['sessions_scored']} sessions scored; "
        f"fitted on {len(fit_on)}; reward {args.reward}; rules value (SNIPS) {rules_value.snips:.3f}; "
        f"MLflow {'logged' if logged else 'not installed'}"
    )
    print(
        f"{'learner':26} {'DR diff':>8} {'95% interval':>18} {'SNIPS':>7} {'IPS':>7} {'balanced':>9} {'changed':>8} {'ESS':>7} ok"
    )
    for r in sorted(rows, key=lambda r: -r["vs_rules"]["dr"]["ci"][0]):
        v, b = r["vs_rules"], r["vs_rules_session_balanced"]
        print(
            f"{r['name'][:26]:26} {v['dr']['diff']:+8.3f} [{v['dr']['ci'][0]:+7.3f}, {v['dr']['ci'][1]:+7.3f}] "
            f"{v['snips']['diff']:+7.3f} {v['ips']['diff']:+7.3f} {b['dr']['diff']:+9.3f} {v['changed']:8.2f} "
            f"{r['ess']:7.0f} {'yes' if r['eligible'] else 'no'}"
        )
    print(f"to act: {summary['choice']}; to shadow: {summary['shadow']}")
    print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
