"""Which tagger? (phase 2 spec, 2.4; completion plan, section 3)

Candidates are fitted on the training split and compared on dev. For each one the report gives
technique micro-F1 over the headline population with an interval that resamples procedures, and
its difference to the most-frequent baseline over the same procedures. A learned model's
abstention threshold is tuned on dev, which is what dev is for; that makes dev numbers a little
optimistic, and the only unbiased number is the final one on test.

    # selection (never reads test)
    uv run --group research python -m mirage_intel.experiments.tagger_bench \
        --embedders bge-small,minilm,securebert2,shellbert --attack data/attack/enterprise-attack-20.1.json

    # the final report for a chosen candidate, fitted on train + dev, scored once on test
    uv run --group research python -m mirage_intel.experiments.tagger_bench --final --choice <name>

Nothing printed or written here contains input text: names, counts and scores only.
"""

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq

from mirage_intel import tagmodels as tm
from mirage_intel import tagscore as ts
from mirage_intel import tagserve
from mirage_intel.embedders import EMBEDDERS, neural_embedder
from mirage_intel.techniques import Engine

ROOT = Path(__file__).resolve().parents[4]
OUT = ROOT / "build" / "experiments" / "tagger"


def load(data: Path) -> dict[str, list[ts.Step]]:
    steps = ts.steps_from_rows(pq.read_table(data / "steps.parquet").to_pylist())
    out: dict[str, list[ts.Step]] = {"train": [], "dev": [], "test": []}
    for s in steps:
        out[s.split].append(s)
    return out


context = tagserve.scoring_context


def candidates(
    embedders: dict[str, Callable],
    attack_text: dict[str, str],
    engine: Engine,
    atomic: dict[str, list[tuple[str, str]]] | None = None,
) -> list[tuple[str, Callable[[], Any], str, bool]]:
    """(name, factory, unit, has a threshold to tune). ``atomic`` holds, per unit, the extra
    labelled text from Atomic Red Team; candidates that use it carry ``+atomic`` in the name."""
    atomic = atomic or {}
    out: list[tuple[str, Callable[[], Any], str, bool]] = [
        ("most-frequent", tm.MostFrequent, "line", False),
        ("rules", lambda: tm.RuleModel(engine), "pieces", False),
    ]
    for unit in ("line", "pieces"):
        extra = atomic.get(unit) or []
        if extra:
            for ngram in ((1, 4), (2, 5)):
                for c in (1.0, 10.0):
                    out.append(
                        (
                            f"linear-char{ngram[0]}-{ngram[1]}-C{c:g}+atomic/{unit}",
                            lambda n=ngram, c=c, e=extra: tm.LinearNgram(n, c, extra=e),
                            unit,
                            True,
                        )
                    )
            for k in (1, 3):
                out.append(
                    (
                        f"retrieval-tfidf-k{k}+atomic/{unit}",
                        lambda k=k, e=extra: tm.Retrieval(k=k, extra=e),
                        unit,
                        True,
                    )
                )
                for label, make in embedders.items():
                    out.append(
                        (
                            f"retrieval-{label}-k{k}+atomic/{unit}",
                            lambda k=k, label=label, make=make, e=extra: tm.Retrieval(
                                make, label=label, k=k, extra=e
                            ),
                            unit,
                            True,
                        )
                    )
        for ngram in ((1, 4), (2, 5), (3, 6)):
            for c in (1.0, 10.0, 100.0):
                name = f"linear-char{ngram[0]}-{ngram[1]}-C{c:g}/{unit}"
                out.append((name, lambda n=ngram, c=c: tm.LinearNgram(n, c), unit, True))
        for k in (1, 3):
            out.append((f"retrieval-tfidf-k{k}/{unit}", lambda k=k: tm.Retrieval(k=k), unit, True))
            if attack_text:
                out.append(
                    (
                        f"retrieval-tfidf-k{k}+attack/{unit}",
                        lambda k=k: tm.Retrieval(k=k, attack_text=attack_text),
                        unit,
                        True,
                    )
                )
            for label, make in embedders.items():
                out.append(
                    (
                        f"retrieval-{label}-k{k}/{unit}",
                        lambda k=k, label=label, make=make: tm.Retrieval(make, label=label, k=k),
                        unit,
                        True,
                    )
                )
                if attack_text:
                    out.append(
                        (
                            f"retrieval-{label}-k{k}+attack/{unit}",
                            lambda k=k, label=label, make=make: tm.Retrieval(
                                make, label=label, k=k, attack_text=attack_text
                            ),
                            unit,
                            True,
                        )
                    )
    return out


def run_one(
    name: str,
    model: Any,
    unit: str,
    tune: bool,
    fit_on: list[ts.Step],
    eval_on: list[ts.Step],
    split: str,
    threshold: float | None = None,
    draws: int = 1000,
    also_seen: set[tuple[str, str]] | None = None,
) -> tuple[ts.Report, list[ts.Unit], float]:
    model.fit(fit_on, unit)
    ctx = context(fit_on, unit)
    # Text from outside the lab is training data too: a scored input equal to it is a leak.
    ctx["seen_skeletons"] = ctx["seen_skeletons"] | (also_seen or set())
    # Predict once with no threshold. A step's prediction is its most confident text, so
    # applying a threshold afterwards gives exactly what the model would have answered with it.
    model.threshold = 0.0
    raw = ts.predict_steps(model, eval_on, unit)

    def at(th: float) -> tuple[ts.Report, list[ts.Unit]]:
        preds = [p if p.confidence >= th else ts.Pred() for p in raw]
        return ts.score(name, eval_on, preds, unit=unit, split=split, draws=draws, **ctx)

    if not tune:
        return (*at(0.0), 0.0)
    if threshold is None:
        quick = {"draws": 1}
        threshold, _ = tm.tune_threshold(
            lambda th: ts.score(
                name,
                eval_on,
                [p if p.confidence >= th else ts.Pred() for p in raw],
                unit=unit,
                split=split,
                **{**ctx, **quick},
            )[0].headline["micro_f1"]
        )
    return (*at(threshold), float(threshold))


def log_mlflow(experiment: str, rows: list[dict[str, Any]]) -> bool:
    """Record the candidates in the local MLflow store. Tracking is a convenience: the result
    file each script writes is the record, so a store that is missing, locked by another run
    or broken is reported and never stops an experiment."""
    try:
        import mlflow
    except ImportError:
        return False
    try:
        (ROOT / "build").mkdir(exist_ok=True)
        mlflow.set_tracking_uri(f"sqlite:///{ROOT / 'build' / 'mlflow.db'}")
        mlflow.set_experiment(experiment)
        for row in rows:
            with mlflow.start_run(run_name=row["name"]):
                mlflow.log_params({k: row[k] for k in ("unit", "split", "threshold")})
                mlflow.log_metrics({k: float(v) for k, v in row["metrics"].items()})
    except Exception as exc:  # any failure of the tracking store, whatever its type
        print(f"MLflow tracking skipped: {type(exc).__name__}: {str(exc)[:120]}")
        return False
    return True


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="tagger_bench")
    ap.add_argument("--data", type=Path, default=ROOT / "build" / "dataset")
    ap.add_argument("--embedders", default="", help="comma-separated: " + ", ".join(EMBEDDERS))
    ap.add_argument("--attack", type=Path, help="ATT&CK STIX bundle, for technique descriptions")
    ap.add_argument("--atomic", type=Path, help="Atomic Red Team linux-index.yaml")
    ap.add_argument("--final", action="store_true", help="score the chosen candidate on test")
    ap.add_argument("--choice", help="candidate name, with --final")
    ap.add_argument("--threshold", type=float, help="the threshold dev chose, with --final")
    ap.add_argument("--draws", type=int, default=1000)
    ap.add_argument("--only", default="", help="comma-separated candidate names to run")
    ap.add_argument(
        "--together",
        type=int,
        default=0,
        metavar="N",
        help="also score the rules in front of each of the best N candidates (spec 2.4)",
    )
    ap.add_argument(
        "--logprecis",
        action="store_true",
        help="also report LogPrécis alone, and the best candidate, at tactic level on SSH",
    )
    args = ap.parse_args(argv)

    data = load(args.data)
    engine = Engine.load(ROOT / "intel" / "rules")
    labels = sorted({s.technique for split in data.values() for s in split if s.technique})
    attack_text: dict[str, str] = {}
    if args.attack:
        from mirage_intel.attack import Attack

        attack = Attack.from_stix(args.attack)
        attack_text = {t: attack.text(t) for t in labels if t in attack.techniques}
    embedders = {
        label: neural_embedder(EMBEDDERS[label])
        for label in filter(None, args.embedders.split(","))
    }
    fit_splits = ("train", "dev") if args.final else ("train",)
    atomic_pairs: dict[str, list[tuple[str, str]]] = {}
    atomic_seen: set[tuple[str, str]] = set()
    if args.atomic:
        # Every Atomic test a held-out procedure quotes is kept out of what is fitted.
        atomic_pairs = tagserve.atomic_pairs(args.atomic, fit_splits)
        atomic_seen = tagserve.seen_in(atomic_pairs)
        print(
            f"atomic: {len(atomic_pairs['line'])} lines and {len(atomic_pairs['pieces'])} "
            "pieces indexed, held-out tests excluded by GUID"
        )
    grid = candidates(embedders, attack_text, engine, atomic_pairs)

    if args.final:
        if not args.choice or args.threshold is None:
            ap.error("--final needs --choice and --threshold (both from the dev run)")
        fit_on, eval_on, split = data["train"] + data["dev"], data["test"], "test"
        grid = [g for g in grid if g[0] in (args.choice, "most-frequent")]
        if len(grid) != 2:
            ap.error(f"unknown candidate {args.choice!r}")
    else:
        fit_on, eval_on, split = data["train"], data["dev"], "dev"
        only = set(filter(None, args.only.split(",")))
        if only:
            missing = only - {g[0] for g in grid}
            if missing:
                ap.error(f"unknown candidates: {sorted(missing)}")
            grid = [g for g in grid if g[0] in only or g[0] == "most-frequent"]

    baseline_units: list[ts.Unit] = []
    rows = []
    started = time.time()
    for name, factory, unit, tune in grid:
        fixed = args.threshold if args.final and name == args.choice else None
        report, units, threshold = run_one(
            name,
            factory(),
            unit,
            tune,
            fit_on,
            eval_on,
            split,
            fixed,
            args.draws,
            atomic_seen if "+atomic" in name else None,
        )
        if name == "most-frequent":
            baseline_units = units
        diff = (
            ts.paired_difference(units, baseline_units, args.draws) if baseline_units else (0, 0, 0)
        )
        h = report.headline
        rows.append(
            {
                "name": name,
                "unit": unit,
                "split": split,
                "threshold": threshold,
                "metrics": {
                    "micro_f1": h["micro_f1"],
                    "ci_low": h["micro_f1_ci"][0],
                    "ci_high": h["micro_f1_ci"][1],
                    "macro_f1": h["macro_f1"],
                    "precision": h["precision"],
                    "recall": h["recall"],
                    "abstention": h["abstention"],
                    "vs_baseline": round(diff[0], 4),
                    "vs_baseline_low": round(diff[1], 4),
                    "vs_baseline_high": round(diff[2], 4),
                    "unseen_recall": report.unseen["recall"],
                    "negative_fp_rate": report.negatives["false_positive_rate"],
                    "session_tactic_f1": report.sessions["f1"],
                },
                "report": report.to_dict(),
            }
        )
    rows.sort(key=lambda r: -r["metrics"]["micro_f1"])
    by_name = {g[0]: g for g in grid}
    tuned = [r for r in rows if by_name[r["name"]][3]]

    # The layers together (spec 2.4): the rules answer first, the learned layer where they
    # abstain, at the threshold it was given alone. A layer that does not help is dropped.
    together = []
    for r in tuned[: args.together]:
        _, factory, unit, _ = by_name[r["name"]]
        name = f"rules > {r['name']}"
        model = tm.Cascade([(tm.RuleModel(engine), 0.0), (factory(), r["threshold"])])
        seen = atomic_seen if "+atomic" in r["name"] else None
        report, _, _ = run_one(
            name, model, unit, False, fit_on, eval_on, split, None, args.draws, seen
        )
        together.append(
            {
                "name": name,
                "alone": r["metrics"]["micro_f1"],
                "micro_f1": report.headline["micro_f1"],
                "micro_f1_ci": report.headline["micro_f1_ci"],
                "precision": report.headline["precision"],
                "recall": report.headline["recall"],
                "negative_fp_rate": report.negatives["false_positive_rate"],
                "session_tactic_f1": report.sessions["f1"],
            }
        )

    # The published baseline (spec 2.4): LogPrécis alone at tactic level, on SSH steps, beside
    # the best candidate's predictions read at the same level.
    tactic_level = []
    if args.logprecis and tuned:
        from mirage_intel import logprecis

        best = tuned[0]
        _, factory, unit, _ = by_name[best["name"]]
        model = factory()
        model.fit(fit_on, unit)
        model.threshold = best["threshold"]
        ours = logprecis.as_tactics(
            ts.predict_steps(model, eval_on, unit), context(fit_on)["tactic_of"]
        )
        theirs = logprecis.predict(eval_on, logprecis.load())
        for name, preds in ((best["name"], ours), ("logprecis", theirs)):
            report, _ = logprecis.score_tactics(
                name, eval_on, preds, unit=unit, split=split, draws=args.draws
            )
            h = report.headline
            tactic_level.append(
                {
                    "name": name,
                    "procedures": h["procedures"],
                    "micro_f1": h["micro_f1"],
                    "micro_f1_ci": h["micro_f1_ci"],
                    "precision": h["precision"],
                    "recall": h["recall"],
                    "abstention": h["abstention"],
                    "session_tactic_f1": report.sessions["f1"],
                }
            )

    OUT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(started))
    path = OUT / f"{'final' if args.final else 'dev'}-{stamp}.json"
    summary = {
        "split": split,
        "fit_on": {"steps": len(fit_on), "procedures": len({s.procedure for s in fit_on})},
        "scored": {"steps": len(eval_on), "procedures": len({s.procedure for s in eval_on})},
        "techniques_in_training": len({s.technique for s in fit_on if s.technique}),
        "attack_text": len(attack_text),
        "atomic_indexed": {unit: len(pairs) for unit, pairs in atomic_pairs.items()},
        "candidates": rows,
        "together": together,
        "tactic_level_ssh": tactic_level,
    }
    path.write_text(json.dumps(summary, indent=1) + "\n")
    logged = log_mlflow(f"phase2-tagger-{split}", rows)

    print(f"{split}: {summary['scored']['procedures']} procedures scored, fitted on "
          f"{summary['fit_on']['procedures']}; MLflow {'logged' if logged else 'not installed'}")  # fmt: skip
    print(
        f"{'candidate':46} {'F1':>6} {'95% interval':>15} {'vs baseline':>22} {'abst':>5} {'thr':>5}"
    )
    for r in rows[: 40 if not args.final else None]:
        m = r["metrics"]
        print(
            f"{r['name'][:46]:46} {m['micro_f1']:6.3f} [{m['ci_low']:5.3f}, {m['ci_high']:5.3f}] "
            f"{m['vs_baseline']:+6.3f} [{m['vs_baseline_low']:+5.3f}, {m['vs_baseline_high']:+5.3f}] "
            f"{m['abstention']:5.2f} {r['threshold']:5.2f}"
        )
    for t in together:
        print(
            f"{t['name'][:60]:60} {t['micro_f1']:6.3f} [{t['micro_f1_ci'][0]:5.3f}, "
            f"{t['micro_f1_ci'][1]:5.3f}]  alone {t['alone']:.3f}"
        )
    for t in tactic_level:
        print(
            f"tactic level, SSH: {t['name'][:40]:40} F1 {t['micro_f1']:.3f} "
            f"[{t['micro_f1_ci'][0]:.3f}, {t['micro_f1_ci'][1]:.3f}] P {t['precision']:.2f} "
            f"R {t['recall']:.2f} abstains {t['abstention']:.2f} session F1 {t['session_tactic_f1']:.3f}"
        )
    print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
