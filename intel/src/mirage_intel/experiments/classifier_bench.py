"""Which classifier? (phase 2 spec, 2.3; completion plan, section 3)

Every model family on every feature set, scored by holding out whole scenarios. The number
that decides is macro-F1 over the sessions the scanner rule leaves to the model. The fold
assignment is itself a source of variance, so each candidate is run under several fold seeds
and the mean over seeds is what is compared.

**How the pick is made.** Candidates run with one fold seed predict the same sessions, so two
candidates are compared as pairs: scenarios are resampled, and each resample gives the
difference between their macro-F1 on exactly the same sessions. That interval is far tighter
than either candidate's own, because most of the variation (which scenarios happen to be
drawn) is shared.

The pick is the simplest candidate shown to be *no worse than the best by more than*
``MARGIN``: the upper end of the 95% interval on (best - candidate) is at most ``MARGIN``.
Failing to tell two candidates apart is not evidence that they are equal, so a simpler model
is preferred only when the data shows it gives up next to nothing; otherwise the best one is
taken. (The first version of this script took the simplest candidate whose mean was inside the
best one's own interval. On 50 scenarios that interval is 0.3 wide, and the rule chose a model
0.17 below the best.)

**What is chosen.** The spec fixes the two variants that are served (2.3): one over the
event-level features, which any Cowrie data has, and the full one with the keystroke features
as well. The experiment chooses the model family for each, simplest first: logistic
regression, then random forest, then gradient boosting. The feature sets themselves are an
ablation, reported as the paired difference the keystroke features and the event features
each make to the chosen family; a keystroke-only model is measured, not served, because a
session on a protocol with no terminal has no keystrokes to read.

The choice made here is fixed in ``eval/choices.yaml`` and then measured again on the frozen
dataset, which is a separate collection: the figure the gate reads is not the one that won a
nine-way comparison.

    uv run python -m mirage_intel.experiments.classifier_bench [--data build/dataset]
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path

import numpy as np

from mirage_intel import classifier
from mirage_intel.classifier import Folded, encode, macro_f1_codes
from mirage_intel.experiments.tagger_bench import log_mlflow

ROOT = Path(__file__).resolve().parents[4]
OUT = ROOT / "build" / "experiments" / "classifier"
FEATURE_ORDER = ("event", "tty", "both")
MARGIN = 0.02  # macro-F1 a simpler model may give up and still be preferred


def fold_all(rows: list[dict], seeds: list[int]) -> dict[str, list[Folded]]:
    """Out-of-fold predictions for every candidate under every fold seed."""
    out: dict[str, list[Folded]] = {}
    for family in classifier.FAMILIES:
        for fs in FEATURE_ORDER:
            runs = [
                classifier.out_of_fold(
                    rows, seed=s, features=classifier.FEATURE_SETS[fs], family=family
                )
                for s in seeds
            ]
            if all(r is not None for r in runs):
                out[f"{family}/{fs}"] = runs  # type: ignore[assignment]
    return out


def _open(f: Folded, column: np.ndarray) -> np.ndarray:
    return column[f.is_open]


def interval(
    a: list[Folded],
    b: list[np.ndarray] | None,
    labels: list[str],
    draws: int,
    seed: int = 0,
) -> list[float]:
    """A 95% interval on the mean over fold seeds of macro-F1(a) - macro-F1(b), on the sessions
    the rule leaves, resampling scenario groups. ``b`` holds, per seed, the other predictions
    for the same sessions; without it the interval is on macro-F1(a) itself."""
    coded = []
    for i, f in enumerate(a):
        group = _open(f, f.group)
        other = b[i] if b is not None else _open(f, f.pred)
        k, over, (t, pa, pb) = encode(labels, _open(f, f.truth), _open(f, f.pred), other)
        index = {name: np.flatnonzero(group == name) for name in sorted(set(group.tolist()))}
        coded.append((k, over, t, pa, pb, index))
    names = sorted(coded[0][5])
    if any(sorted(c[5]) != names for c in coded):
        raise ValueError("fold seeds disagree on which scenario groups were scored")
    rng = np.random.default_rng(seed)
    values = []
    for _ in range(draws):
        drawn = [names[i] for i in rng.integers(0, len(names), len(names))]
        total = 0.0
        for k, over, t, pa, pb, index in coded:
            pick = np.concatenate([index[name] for name in drawn])
            total += macro_f1_codes(t[pick], pa[pick], k, over)
            if b is not None:
                total -= macro_f1_codes(t[pick], pb[pick], k, over)
        values.append(total / len(coded))
    return [round(float(x), 4) for x in np.percentile(values, [2.5, 97.5])]


def summarise(name: str, runs: list[Folded], labels: list[str], draws: int) -> dict:
    family, fs = name.split("/")
    points, everything, per_class = [], [], []
    for f in runs:
        k, over, (t, p) = encode(labels, _open(f, f.truth), _open(f, f.pred))
        points.append(macro_f1_codes(t, p, k, over))
        per_class.append([macro_f1_codes(t, p, k, over[i : i + 1]) for i in range(len(labels))])
        every = sorted(set(f.truth.tolist()) | set(classifier.CLASSES))
        k, over, (t, p) = encode(every, f.truth, f.pred)
        everything.append(macro_f1_codes(t, p, k, over))
    first = runs[0]
    truth, pred = _open(first, first.truth), _open(first, first.pred)
    k, over, (t, m) = encode(labels, truth, _open(first, first.majority_open))
    return {
        "name": name,
        "family": family,
        "features": fs,
        "rank": (classifier.FAMILIES.index(family), FEATURE_ORDER.index(fs)),
        "model_only_macro_f1": round(float(np.mean(points)), 4),
        "seed_spread": round(float(np.std(points)), 4),
        "macro_f1_ci": interval(runs, None, labels, draws),
        "vs_majority_ci": interval(runs, [_open(f, f.majority_open) for f in runs], labels, draws),
        "majority_f1": round(macro_f1_codes(t, m, k, over), 4),
        "all_sessions_macro_f1": round(float(np.mean(everything)), 4),
        "per_class_f1": {
            lab: round(float(v), 3)
            for lab, v in zip(labels, np.mean(per_class, axis=0), strict=True)
        },
        "confusion": {
            f"{a}->{b}": n for (a, b), n in sorted(Counter(zip(truth, pred, strict=True)).items())
        },
        "support": dict(sorted(Counter(truth.tolist()).items())),
        "n": int(first.is_open.sum()),
        "groups": len(set(_open(first, first.group).tolist())),
        "rule_settled": int((~first.is_open).sum()),
    }


def mistakes(runs: list[Folded]) -> dict[str, float]:
    """Where a candidate is wrong: per scenario and (true -> predicted), the mean number of
    sessions over fold seeds. Scenario IDs only; nothing a session contained."""
    counts: Counter = Counter()
    for f in runs:
        wrong = f.is_open & (f.truth != f.pred)
        for scenario, truth, pred in zip(
            f.scenario[wrong], f.truth[wrong], f.pred[wrong], strict=True
        ):
            counts[f"{scenario}: {truth}->{pred}"] += 1
    return {key: round(n / len(runs), 2) for key, n in counts.most_common()}


def pick(results: list[dict]) -> dict:
    """The simplest candidate shown to be within ``MARGIN`` of the best one. Give it the
    candidates of one feature set, each compared with the best of that set."""
    eligible = [r for r in results if r["best_minus_this_ci"][1] <= MARGIN]
    return min(eligible, key=lambda r: r["rank"])


def run(rows: list[dict], seeds: list[int], draws: int) -> tuple[list[dict], dict[str, dict]]:
    """Every candidate's summary, and the chosen candidate per served variant."""
    folded = fold_all(rows, seeds)
    if not folded:
        raise SystemExit("too few scenario groups to hold any out")
    first = next(iter(folded.values()))[0]
    labels = sorted(set(first.truth[first.is_open].tolist()))
    results = [summarise(name, runs, labels, draws) for name, runs in folded.items()]

    def others(name: str) -> list[np.ndarray]:
        return [f.pred[f.is_open] for f in folded[name]]

    chosen: dict[str, dict] = {}
    for fs in FEATURE_ORDER:
        group = [r for r in results if r["features"] == fs]
        best = max(group, key=lambda r: (r["model_only_macro_f1"], -r["rank"][0]))
        for r in group:
            r["best_of_set"] = best["name"]
            r["best_minus_this_ci"] = (
                [0.0, 0.0]
                if r is best
                else interval(folded[best["name"]], others(r["name"]), labels, draws)
            )
        chosen[fs] = pick(group)
    full = chosen["both"]
    # The ablation: what the full model gains over each feature group alone, same family.
    full["gain_over"] = {
        fs: interval(folded[full["name"]], others(f"{full['family']}/{fs}"), labels, draws)
        for fs in ("event", "tty")
    }
    full["mistakes"] = mistakes(folded[full["name"]])
    return results, {"full": full, "event": chosen["event"]}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="classifier_bench")
    ap.add_argument("--data", type=Path, default=ROOT / "build" / "dataset")
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--draws", type=int, default=1000)
    args = ap.parse_args(argv)
    rows = classifier.load_rows(args.data / "sessions.parquet")
    results, chosen = run(rows, list(range(args.seeds)), args.draws)
    full = chosen["full"]

    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"cv-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
    path.write_text(
        json.dumps(
            {
                "sessions": len(rows),
                "seeds": args.seeds,
                "draws": args.draws,
                "margin": MARGIN,
                "choice": {variant: r["name"] for variant, r in chosen.items()},
                "candidates": results,
            },
            indent=1,
        )
        + "\n"
    )
    logged = log_mlflow(
        "phase2-classifier",
        [
            {
                "name": r["name"],
                "unit": r["features"],
                "split": "scenario-cv",
                "threshold": 0.0,
                "metrics": {
                    "model_only_macro_f1": r["model_only_macro_f1"],
                    "seed_spread": r["seed_spread"],
                    "ci_low": r["macro_f1_ci"][0],
                    "ci_high": r["macro_f1_ci"][1],
                    "best_minus_this_high": r["best_minus_this_ci"][1],
                    "all_sessions_macro_f1": r["all_sessions_macro_f1"],
                },
            }
            for r in results
        ],
    )
    first = results[0]
    print(
        f"{len(rows)} sessions; {first['rule_settled']} settled by the rule; "
        f"{first['n']} left to the model in {first['groups']} scenario groups; "
        f"support {first['support']}; MLflow {'logged' if logged else 'not installed'}"
    )
    print(
        f"{'candidate':14} {'macro-F1':>8} {'95% interval':>16} {'seed sd':>7} "
        f"{'vs majority':>18} {'best of set - this':>18}  per class"
    )
    for r in sorted(results, key=lambda r: (r["rank"][1], -r["model_only_macro_f1"])):
        ci, vs, gap = r["macro_f1_ci"], r["vs_majority_ci"], r["best_minus_this_ci"]
        per = " ".join(f"{k[:5]} {v:.2f}" for k, v in r["per_class_f1"].items())
        print(
            f"{r['name']:14} {r['model_only_macro_f1']:8.3f} [{ci[0]:6.3f}, {ci[1]:6.3f}] "
            f"{r['seed_spread']:7.3f} [{vs[0]:+6.3f}, {vs[1]:+6.3f}] "
            f"[{gap[0]:+6.3f}, {gap[1]:+6.3f}]  {per}"
        )
    print(
        f"chosen (simplest family within {MARGIN} of the best of its feature set): "
        f"full {full['name']}, event-level {chosen['event']['name']}"
    )
    gain = full["gain_over"]
    print(
        f"what the full model gains: over event-level alone [{gain['event'][0]:+.3f}, "
        f"{gain['event'][1]:+.3f}], over keystrokes alone [{gain['tty'][0]:+.3f}, {gain['tty'][1]:+.3f}]"
    )
    print(f"full model, confusion (first seed): {full['confusion']}")
    for key, n in list(full["mistakes"].items())[:12]:
        print(f"  wrong {n:5.2f} per seed  {key}")
    print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
