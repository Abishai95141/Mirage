"""Evaluation harness (phase 2 spec, 2.6; Gate 2 tests 5, 6, 7, 9 and 10).

One program answers "do the models still do what was measured?" for one dataset:

1. it runs the integrity checks of spec section 5 and refuses to report if one fails;
2. it builds the models ``eval/choices.yaml`` names, the same way the trainers and the live
   workers do, and scores each on data it was not fitted on, with an interval that resamples
   the independent unit (scenarios, procedures, sessions);
3. it decides the gates, and **exits non-zero if any check or gate is not met**. A metric that
   could not be computed is a failed gate, never a skipped one;
4. ``check`` compares the result with the committed baseline of the same dataset: a tracked
   metric below the baseline's own interval, a metric missing on either side, a gate that no
   longer holds or a different choice of models fails it.

No absolute threshold is used anywhere. Gate 2 asks a model to beat a trivial baseline by more
than its interval, not to reach a number chosen before there was data.

    mirage-eval freeze --data build/dataset --name gate2   # lab host: a healthy lab-seed export
    mirage-eval run    --data eval/datasets/gate2 --write-baseline
    mirage-eval check  --data eval/datasets/gate2          # CI: needs no model and no store
    mirage-eval publish --data eval/datasets/gate2         # to mirage.eval_metrics
    mirage-eval served --data build/dataset                # lab host: live labels vs offline

The frozen dataset carries the tagger's index and the vectors the embedding model produced for
every text it reads, so ``check`` recomputes each number in CI without the model. On a host
that has the model and the Atomic Red Team file, ``run --verify`` rebuilds both from scratch
and fails if they differ from what was frozen.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq
import yaml

from mirage_intel import classifier, tagserve
from mirage_intel import dataset as ds_mod
from mirage_intel import policylearn as pl
from mirage_intel import tagmodels as tm
from mirage_intel import tagscore as ts
from mirage_intel.embedders import EMBEDDERS, Cache, neural_embedder

ROOT = Path(__file__).resolve().parents[3]
DATASETS = ROOT / "eval" / "datasets"
BASELINES = ROOT / "eval" / "baselines"
_EVENT_ID = re.compile(r"^[A-Za-z0-9_.:@/+=-]{1,128}$")
FILES = ("sessions.parquet", "sessions.manifest.json", "steps.parquet")
DECISION_FILES = ("decisions.parquet", "decisions.manifest.json")
# Metrics the regression check holds to the baseline's interval. Higher is better for all.
TRACKED = (
    "classifier.macro_f1",
    "classifier_event.macro_f1",
    "tagger.micro_f1",
)


class HarnessError(RuntimeError):
    """The dataset cannot be evaluated at all; the message says why."""


def _rows(path: Path) -> list[dict[str, Any]]:
    return pq.read_table(path).to_pylist()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass
class Dataset:
    directory: Path
    name: str
    sessions: list[dict[str, Any]]
    steps: list[dict[str, Any]]
    decisions: list[dict[str, Any]]
    manifest: dict[str, Any]

    @classmethod
    def load(cls, directory: Path) -> Dataset:
        for name in FILES:
            if not (directory / name).exists():
                raise HarnessError(f"{directory} has no {name}; export or freeze a dataset first")
        decisions = directory / "decisions.parquet"
        return cls(
            directory=directory,
            name=directory.name,
            sessions=_rows(directory / "sessions.parquet"),
            steps=_rows(directory / "steps.parquet"),
            decisions=_rows(decisions) if decisions.exists() else [],
            manifest=json.loads((directory / "sessions.manifest.json").read_text()),
        )

    def identity(self) -> dict[str, str]:
        """What a baseline is tied to: the content of every table."""
        out = {name: _sha(self.directory / name) for name in ("sessions.parquet", "steps.parquet")}
        if (self.directory / "decisions.parquet").exists():
            out["decisions.parquet"] = _sha(self.directory / "decisions.parquet")
        return out


@dataclass
class Result:
    dataset: str
    identity: dict[str, str]
    choices: dict[str, Any]
    checks: dict[str, dict[str, Any]] = field(default_factory=dict)
    metrics: dict[str, dict[str, Any]] = field(default_factory=dict)
    gates: dict[str, dict[str, Any]] = field(default_factory=dict)
    reports: dict[str, Any] = field(default_factory=dict)

    def check(self, name: str, ok: bool, detail: str) -> None:
        self.checks[name] = {"ok": bool(ok), "detail": detail}

    def metric(self, name: str, value: float, ci: list[float] | None, detail: str = "") -> None:
        self.metrics[name] = {"value": round(float(value), 4), "ci": ci, "detail": detail}

    def gate(self, name: str, ok: bool, detail: str) -> None:
        self.gates[name] = {"ok": bool(ok), "detail": detail}

    def failures(self) -> list[str]:
        out = [f"check {k}: {v['detail']}" for k, v in self.checks.items() if not v["ok"]]
        out += [f"gate {k}: {v['detail']}" for k, v in self.gates.items() if not v["ok"]]
        if not self.gates:
            out.append("no gate was evaluated")
        return out

    def to_json(self) -> dict[str, Any]:
        return {
            "dataset": self.dataset,
            "identity": self.identity,
            "choices": self.choices,
            "checks": self.checks,
            "metrics": self.metrics,
            "gates": self.gates,
            "reports": self.reports,
        }


def load_choices(path: Path = tagserve.CHOICES) -> dict[str, Any]:
    doc = (yaml.safe_load(path.read_text()) or {}) if path.exists() else {}
    for key in ("classifier", "classifier_event", "tagger", "policy"):
        if not isinstance(doc.get(key), dict):
            raise HarnessError(f"{path.name} has no '{key}' section")
    return doc


# ------------------------------------------------------------------ section 5: integrity


def integrity(ds: Dataset, result: Result, allow_unhealthy: bool = False) -> None:
    """The checks of spec section 5 that a dataset on disk can be held to."""
    from mirage_lab.models import Catalogue, Scenario

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))  # the split module lives at the repository root
    import eval.split as split_mod

    catalogue = Catalogue.load(ROOT / "lab" / "catalogue")
    scenarios = [Scenario.load(p) for p in sorted((ROOT / "lab" / "scenarios").rglob("*.yaml"))]
    split = split_mod.Split.load(ROOT / "eval" / "split.yaml")

    # Checks 2 and 3 on the catalogue: no scenario mixes splits, no near-identical command
    # spans the split.
    frozen = split_mod.check(split, catalogue, scenarios)
    result.check(
        "split_integrity",
        frozen.ok,
        "; ".join(frozen.problems) or f"{len(split.of_procedure)} procedures, one split each",
    )
    same = ds.manifest.get("catalogue_sha256") == catalogue.sha256
    result.check(
        "dataset_matches_catalogue",
        same,
        "the dataset was exported against the catalogue on disk"
        if same
        else "the dataset was exported against a different catalogue than the one on disk",
    )

    # Check 2 on the data: no session holds steps of two splits.
    by_session: dict[tuple[str, str], set[str]] = {}
    for s in ds.steps:
        by_session.setdefault((s["run_id"], s["session_ref"]), set()).add(s["split"])
    mixed = sum(1 for v in by_session.values() if len(v) > 1)
    result.check(
        "sessions_one_split", mixed == 0, f"{mixed} of {len(by_session)} sessions mix splits"
    )
    # ... and no procedure sits on both sides.
    where: dict[str, set[str]] = {}
    for s in ds.steps:
        where.setdefault(s["procedure_id"], set()).add(s["split"])
    crossing = sorted(p for p, v in where.items() if len(v) > 1)
    result.check(
        "procedures_one_split",
        not crossing,
        f"{len(crossing)} procedure(s) appear under two splits"
        + (f": {crossing[:5]}" if crossing else ""),
    )

    # ... and every row is filed under the split the frozen file gives its procedure or its
    # scenario. Without this the checks above would pass on a dataset split some other way.
    misfiled = sum(1 for s in ds.steps if split.of_procedure.get(s["procedure_id"]) != s["split"])
    misfiled_sessions = sum(
        1
        for r in ds.sessions
        if not r.get("real") and split.of_scenario.get(r["scenario_id"]) != r["split"]
    )
    result.check(
        "splits_match_frozen",
        misfiled == 0 and misfiled_sessions == 0,
        f"{misfiled} step row(s) and {misfiled_sessions} session(s) are not filed under the "
        "split eval/split.yaml gives them",
    )

    # Rule 4 of the completion plan: the held-out half of the catalogue is actually there,
    # filed as held out.
    wanted = {p for p, s in split.of_procedure.items() if s == "test"}
    absent = sorted(wanted - {p for p, v in where.items() if "test" in v})
    result.check(
        "held_out_coverage",
        not absent,
        f"{len(wanted) - len(absent)} of {len(wanted)} test procedures have captured steps"
        + (f"; missing: {absent[:8]}" if absent else ""),
    )

    # Check 8: nothing only the lab knows is visible to a model.
    columns = set(pq.read_schema(ds.directory / "sessions.parquet").names)
    extra = sorted(columns - set(ds_mod.META) - set(ds_mod.FEATURES))
    result.check(
        "session_columns_allowlisted",
        not extra,
        f"columns outside the allowlist: {extra}"
        if extra
        else f"{len(columns)} columns, all allowlisted",
    )
    ids = set(catalogue.procedures) | {s.id for s in scenarios}
    hits = ds_mod.leak_scan(ds.steps, ids)
    result.check(
        "no_lab_marker_in_inputs",
        not hits,
        f"{len(hits)} input(s) carry a lab address, ID or marker" if hits else "none found",
    )

    problems = list(ds.manifest.get("problems") or [])
    if not ds.manifest.get("lab_seed"):
        problems.append("not rendered from the lab seed")
    result.check(
        "collection_healthy",
        not problems or allow_unhealthy,
        ("allowed for development: " if problems and allow_unhealthy else "")
        + ("; ".join(problems)[:300] or "every run joined cleanly, from the lab seed"),
    )


# ------------------------------------------------------------------ the three models


def score_classifier(ds: Dataset, choices: dict[str, Any], result: Result, draws: int) -> None:
    for key in ("classifier", "classifier_event"):
        family, feature_set = choices[key]["family"], choices[key]["features"]
        report = classifier.cross_validate(
            ds.sessions,
            draws=draws,
            features=classifier.FEATURE_SETS[feature_set],
            family=family,
        )
        if report is None or not report.model_only.get("n"):
            if key == "classifier":
                result.gate("classifier_beats_majority", False, "too few scenario groups to score")
            continue
        m = report.model_only
        result.metric(
            f"{key}.macro_f1",
            m["macro_f1"],
            m["macro_f1_ci"],
            f"{family}/{feature_set}; {m['n']} sessions the rule leaves, "
            f"{m['groups']} scenario groups",
        )
        result.reports[key] = {
            "family": family,
            "features": feature_set,
            "model_only": m,
            "all_sessions_macro_f1": round(report.macro_f1, 4),
            "rules_only_f1": round(report.rules_only_f1, 4),
            "majority_f1": round(report.majority_f1, 4),
            "vs_rules_ci": report.vs_rules_ci,
            "per_class_f1": report.per_class_f1,
            "confusion": report.confusion,
            "labels": report.labels,
            "rule_settled": report.rule_settled,
            "support": report.support,
        }
        if key != "classifier":
            continue
        result.metric(
            "classifier.above_majority", m["macro_f1"] - m["majority_f1"], m["vs_majority_ci"]
        )
        result.metric(
            "classifier.above_rules_only",
            report.macro_f1 - report.rules_only_f1,
            report.vs_rules_ci,
            "all sessions: the rule alone, with the majority class where it does not decide",
        )
        result.gate(
            "classifier_beats_majority",
            report.beats_majority(),
            f"on the sessions the rule leaves, above the majority class by {m['vs_majority_ci']}",
        )
        result.gate(
            "classifier_beats_rules",
            report.beats_rules(),
            f"on all sessions, above the rule alone by {report.vs_rules_ci}",
        )


def _frozen_index(directory: Path) -> dict[str, Any] | None:
    path = directory / "tagger.index.json"
    return json.loads(path.read_text()) if path.exists() else None


def build_tagger(
    ds: Dataset,
    chosen: dict[str, Any],
    fit_on: list[ts.Step],
    make_embed: Any = None,
    atomic_file: Path | None = None,
) -> tuple[tm.Retrieval, set[tuple[str, str]], str]:
    """The chosen tagger for this dataset, the extra texts its leak guard must know, and how
    it was built: from scratch (the Atomic file and the model are here) or from what the
    dataset froze."""
    frozen = _frozen_index(ds.directory)
    if make_embed is None:
        if (ds.directory / "embeddings.json").exists():
            cache = Cache.load(ds.directory)
            if cache.embedder != chosen["embedder"]:
                raise HarnessError(
                    f"the frozen vectors are {cache.embedder}'s and the chosen tagger embeds "
                    f"with {chosen['embedder']}: refreeze the dataset"
                )
            make_embed = cache.make
        else:
            make_embed = neural_embedder(EMBEDDERS[chosen["embedder"]])
    wants_atomic = bool(chosen.get("atomic"))
    if atomic_file is not None and (atomic_file.exists() or not wants_atomic):
        pairs = tagserve.atomic_pairs(atomic_file, ("train", "dev")) if wants_atomic else {}
        model = tagserve.fit(chosen, fit_on, make_embed, pairs.get(chosen["unit"]))
        return model, tagserve.seen_in(pairs), "built from the steps and the Atomic Red Team file"
    if frozen is None:
        raise HarnessError(
            "the chosen tagger indexes Atomic Red Team text: give --atomic, or evaluate a "
            "frozen dataset, which carries its index"
        )
    if frozen.get("choice") != tagserve.choice_identity(chosen):
        raise HarnessError(
            f"the frozen index was built for {frozen.get('choice')} and eval/choices.yaml now "
            "names another model: refreeze the dataset"
        )
    model = tm.Retrieval.from_saved(
        {**frozen["model"], "threshold": chosen["threshold"]}, make_embed
    )
    seen = {(p, t) for p, t in frozen["also_seen"]}
    return model, seen, "the index frozen with the dataset"


def score_tagger(
    ds: Dataset,
    choices: dict[str, Any],
    result: Result,
    draws: int,
    make_embed: Any = None,
    atomic_file: Path | None = None,
) -> None:
    chosen = choices["tagger"]
    steps = ts.steps_from_rows(ds.steps)
    fit_on = [s for s in steps if s.split in ("train", "dev")]
    held = [s for s in steps if s.split == "test"]
    if not fit_on or not held:
        result.gate(
            "tagger_beats_most_frequent", False, "the dataset has no train or no test steps"
        )
        return
    model, also_seen, how = build_tagger(ds, chosen, fit_on, make_embed, atomic_file)
    unit = chosen["unit"]
    ctx = tagserve.scoring_context(fit_on, unit)
    ctx["seen_skeletons"] = ctx["seen_skeletons"] | also_seen
    # A label is written with the tactic the served model would write (tagserve.tactic_map).
    ctx["tactic_of"] = tagserve.tactic_map(fit_on, {e.technique for e in model.entries})

    # Check 5, index hygiene: nothing fitted comes from a held-out procedure, and every
    # scored input whose own text is in the index anyway was dropped by the scorer.
    crossing = {s.procedure for s in fit_on} & {s.procedure for s in held}
    indexed = {e.key for e in model.entries}
    scored = [s for s in held if s.skeleton not in ctx["seen_skeletons"]]
    slipped = sum(1 for s in scored if tm._key(s.protocol, s.line) in indexed)
    # A scored input can still contain one gated command that is in the index word for word
    # (a shared `cat` in two different pipelines). That is counted, and scored both ways.
    partial = [s for s in scored if any(tm._key(s.protocol, t) in indexed for t in s.texts(unit))]
    result.check(
        "index_hygiene",
        not crossing and slipped == 0,
        f"{len(model.entries)} index entries; {len(crossing)} from held-out procedures; "
        f"{slipped} scored inputs present in the index; {len(partial)} scored inputs share "
        "one gated command with it",
    )

    preds = ts.predict_steps(model, held, unit)
    report, units = ts.score(
        chosen["name"], held, preds, unit=unit, split="test", draws=draws, **ctx
    )
    base = tm.MostFrequent()
    base.fit(fit_on, "line")
    _, base_units = ts.score(
        "most-frequent", held, ts.predict_steps(base, held, "line"), unit="line", split="test",
        draws=draws, **ctx,
    )  # fmt: skip
    diff = ts.paired_difference(units, base_units, draws)
    h = report.headline
    result.metric(
        "tagger.micro_f1",
        h["micro_f1"],
        h["micro_f1_ci"],
        f"{chosen['name']} at {chosen['threshold']}; {h['procedures']} held-out procedures over "
        f"{h['techniques']} techniques; {how}",
    )
    result.metric("tagger.above_most_frequent", diff[0], [round(diff[1], 4), round(diff[2], 4)])
    result.metric(
        "tagger.session_tactic_f1",
        report.sessions["f1"],
        None,
        f"{report.sessions['sessions']} sessions",
    )
    if partial:
        strict = {**ctx, "seen_skeletons": ctx["seen_skeletons"] | {s.skeleton for s in partial}}
        apart, _ = ts.score(
            chosen["name"], held, preds, unit=unit, split="test", draws=draws, **strict
        )
        result.metric(
            "tagger.micro_f1_no_shared_command",
            apart.headline["micro_f1"],
            apart.headline["micro_f1_ci"],
            f"the same, leaving out the {len(partial)} inputs that share a gated command "
            f"with the index; {apart.headline['procedures']} procedures",
        )
    result.metric("tagger.abstention", h["abstention"], None)
    result.metric(
        "tagger.unseen_technique_recall",
        report.unseen["recall"],
        None,
        f"{report.unseen['procedures']} held-out procedures of {report.unseen['techniques']} "
        "technique(s) with no lab training procedure",
    )
    # A rate over nothing is not a zero. The held-out split may hold no explicit negative.
    if report.negatives["procedures"]:
        result.metric(
            "tagger.negative_false_positive_rate",
            report.negatives["false_positive_rate"],
            None,
            f"{report.negatives['procedures']} explicit negative procedures",
        )
    result.reports["tagger"] = report.to_dict()
    result.gate(
        "tagger_beats_most_frequent",
        diff[1] > 0,
        f"technique micro-F1 above the most frequent technique by [{diff[1]:.3f}, {diff[2]:.3f}]",
    )


def score_policy(ds: Dataset, choices: dict[str, Any], result: Result, draws: int) -> None:
    """Gate 2 test 9, the live half: the shadow policy's value against the rules', with an
    interval. It is reported, not required to win (that is Gate 3)."""
    from mirage_intel.experiments.bandit_bench import learners

    chosen = choices["policy"]
    reward = chosen.get("reward", "reward_truth")
    usable = [r for r in ds.decisions if r.get("usable")]
    fit_on = [r for r in usable if r["split"] in ("train", "dev")]
    held = [r for r in usable if r["split"] == "test"]
    if not fit_on or not held:
        result.gate(
            "shadow_value_reported", False, "no usable explore decisions to fit on or to score"
        )
        return
    learner = next((x for _, x in learners() if x.name == chosen["shadow"]), None)
    if learner is None:
        result.gate("shadow_value_reported", False, f"unknown learner {chosen['shadow']!r}")
        return
    reward_model = pl.LinearPolicy(ridge=1.0).fit(fit_on, reward)
    policy = learner.fit(fit_on, reward)
    cmp = pl.compare(
        policy, pl.RulesPolicy(), held, reward, reward_model, smooth_a=pl.SMOOTH, draws=draws
    )
    value = pl.evaluate(policy, held, reward, reward_model, smooth=pl.SMOOTH)
    dr = cmp["dr"]
    sessions = len({r["session"] for r in held})
    result.metric(
        "policy.shadow_minus_rules",
        dr["diff"],
        dr["ci"],
        f"{chosen['shadow']}, doubly robust, {len(held)} decisions in {sessions} test sessions; "
        f"effective sample {value.ess:.0f}; differs from the rules on {cmp['changed']:.0%}",
    )
    result.reports["policy"] = {
        "shadow": chosen["shadow"],
        "reward": reward,
        "decisions": {"fit": len(fit_on), "scored": len(held), "sessions": sessions},
        "vs_rules": cmp,
        "ess": round(value.ess, 1),
    }
    finite = all(math.isfinite(x) for x in (dr["diff"], *dr["ci"])) and value.ess > 0
    result.gate(
        "shadow_value_reported",
        finite,
        f"shadow minus rules {dr['diff']:+.3f} {dr['ci']}; it need not win before Gate 3",
    )


def evaluate(
    ds: Dataset,
    choices: dict[str, Any],
    *,
    draws: int = 1000,
    allow_unhealthy: bool = False,
    make_embed: Any = None,
    atomic_file: Path | None = None,
) -> Result:
    result = Result(ds.name, ds.identity(), choices)
    integrity(ds, result, allow_unhealthy)
    blocking = [k for k, v in result.checks.items() if not v["ok"]]
    if blocking:
        # Spec section 5: no metric is reported from a dataset that fails its checks.
        result.gate("integrity", False, f"failed: {blocking}; no metric is reported")
        return result
    result.gate("integrity", True, f"{len(result.checks)} checks passed")
    score_classifier(ds, choices, result, draws)
    score_tagger(ds, choices, result, draws, make_embed, atomic_file)
    score_policy(ds, choices, result, draws)
    return result


# ------------------------------------------------------------------ regression


def regress(current: Result, baseline: dict[str, Any]) -> list[str]:
    """Why the regression job should fail, if it should."""
    problems = current.failures()
    if baseline.get("identity") != current.identity:
        problems.append("the committed baseline is for a different dataset: rewrite it on purpose")
    if baseline.get("choices") != current.choices:
        problems.append("the committed baseline is for a different choice of models")
    was_metrics = baseline.get("metrics") or {}
    for name in TRACKED:
        was, now = was_metrics.get(name), current.metrics.get(name)
        if was is None or now is None:
            missing = "the baseline" if was is None else "this run"
            problems.append(f"{name} is missing from {missing}")
            continue
        floor = was["ci"][0] if was.get("ci") else was["value"]
        if not math.isfinite(now["value"]):
            problems.append(f"{name} is not a number in this run")
        elif now["value"] < floor:
            problems.append(
                f"{name} fell to {now['value']:.3f}, below the baseline's interval "
                f"({was['value']:.3f}, from {floor:.3f})"
            )
    for name, was in (baseline.get("gates") or {}).items():
        if was.get("ok") and not current.gates.get(name, {}).get("ok"):
            problems.append(f"gate {name} was met in the baseline and is not now")
    return sorted(set(problems))


def baseline_path(name: str) -> Path:
    return BASELINES / f"{name}.json"


# ------------------------------------------------------------------ freeze


def freeze(source: Path, name: str, atomic_file: Path, force: bool = False) -> Path:
    """Copy a healthy lab-seed export into ``eval/datasets/<name>`` with everything the
    regression job needs to recompute the tagger's numbers without the model."""
    ds = Dataset.load(source)
    problems = list(ds.manifest.get("problems") or [])
    if not ds.manifest.get("lab_seed"):
        problems.append("it was not rendered from the lab seed (make lab-seed)")
    for name_ in DECISION_FILES:
        if not (source / name_).exists():
            problems.append(f"it has no {name_} (mirage-decisions)")
    if problems:
        raise HarnessError("this dataset cannot be frozen: " + "; ".join(problems))
    final = DATASETS / name
    if final.exists() and not force:
        raise HarnessError(f"{final.relative_to(ROOT)} exists; --force replaces it")
    # Built beside its final place and moved there whole: a step that fails (the model, the
    # Atomic file) leaves no half-frozen dataset, and --force never mixes old files with new.
    target = DATASETS / f".{name}.partial"
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    for name_ in (*FILES, *DECISION_FILES):
        shutil.copyfile(source / name_, target / name_)

    chosen = load_choices()["tagger"]
    steps = ts.steps_from_rows(ds.steps)
    fit_on = [s for s in steps if s.split in ("train", "dev")]
    make = neural_embedder(EMBEDDERS[chosen["embedder"]])
    pairs = tagserve.atomic_pairs(atomic_file, ("train", "dev")) if chosen.get("atomic") else {}
    model = tagserve.fit(chosen, fit_on, make, pairs.get(chosen["unit"]))
    index = {
        "choice": tagserve.choice_identity(chosen),
        "model": model.to_saved(),
        "also_seen": sorted([p, t] for p, t in tagserve.seen_in(pairs)),
        "note": "Atomic-origin entries derive from Atomic Red Team (Red Canary, MIT licence).",
    }
    (target / "tagger.index.json").write_text(json.dumps(index, ensure_ascii=False) + "\n")
    # Every text the harness will embed: the index, and each step's texts in the chosen unit.
    texts = [e.key for e in model.entries]
    texts += [tm._key(s.protocol, t) for s in steps for t in s.texts(chosen["unit"])]
    Cache.build(chosen["embedder"], texts, make(texts)).save(target)
    listing = {p.name: _sha(p) for p in sorted(target.iterdir()) if p.name != "FROZEN.json"}
    (target / "FROZEN.json").write_text(
        json.dumps(
            {
                "name": name,
                "frozen_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "files": listing,
            },
            indent=1,
        )
        + "\n"
    )
    if final.exists():
        shutil.rmtree(final)
    target.rename(final)
    return final


def verify_frozen(directory: Path, atomic_file: Path) -> list[str]:
    """On a host with the model and the Atomic file: is what was frozen what a fresh build
    gives? Catches a stale index, a different model revision, a changed file."""
    problems = []
    listing = json.loads((directory / "FROZEN.json").read_text())["files"]
    for name, digest in listing.items():
        if not (directory / name).exists() or _sha(directory / name) != digest:
            problems.append(f"{name} is not the file that was frozen")
    ds = Dataset.load(directory)
    chosen = load_choices()["tagger"]
    steps = ts.steps_from_rows(ds.steps)
    fit_on = [s for s in steps if s.split in ("train", "dev")]
    make = neural_embedder(EMBEDDERS[chosen["embedder"]])
    pairs = tagserve.atomic_pairs(atomic_file, ("train", "dev")) if chosen.get("atomic") else {}
    fresh = tagserve.fit(chosen, fit_on, make, pairs.get(chosen["unit"])).to_saved()
    frozen = _frozen_index(directory)
    if frozen is None or frozen["model"]["entries"] != fresh["entries"]:
        problems.append("the frozen tagger index is not what the steps and the Atomic file give")
    try:
        Cache.load(directory).verify(make([]))
    except ValueError as exc:
        problems.append(str(exc))
    return problems


# ------------------------------------------------------------------ as served


def served_check(ds: Dataset, ch: Any, served: Any, draws: int = 1000) -> dict[str, Any]:
    """Does the number the harness reports describe what the live system writes?

    The harness scores a model offline, on steps grouped by the lab's ground truth. The live
    worker groups events itself, embeds them itself and writes ``mirage.labels``. This reads
    the labels that worker wrote, under the model version now loaded, for the held-out steps
    of this dataset's run, and sets them beside what the same model predicts offline: step by
    step (they should be the same answer) and as a score against ground truth.

    Needs the store the dataset was exported from, and the worker to have labelled that run
    with this model (``TAGGER_LOOKBACK_S`` reaches back when it starts)."""
    steps = ts.steps_from_rows(ds.steps)
    events: dict[tuple[str, str, str], list[str]] = {}
    for r in ds.steps:
        events.setdefault((r["run_id"], r["session_ref"], r["step_id"]), []).append(r["event_id"])
    held = [s for s in steps if s.split == "test"]
    fit_on = [s for s in steps if s.split in ("train", "dev")]
    wanted = sorted({e for s in held for e in events[(s.run, s.session_ref, s.step_id)]})
    found: dict[str, tuple[str, float]] = {}
    for start in range(0, len(wanted), 400):
        listed = ", ".join(f"'{e}'" for e in wanted[start : start + 400] if _EVENT_ID.match(e))
        if not listed:
            continue
        for row in ch.rows(
            "SELECT event_id, technique, confidence FROM mirage.labels FINAL "  # noqa: S608
            f"WHERE kind = 'input' AND technique != '' AND model_version = '{served.version}' "
            f"AND event_id IN ({listed})"
        ):
            found[row["event_id"]] = (row["technique"], float(row["confidence"]))
    live: list[ts.Pred] = []
    doubled = 0
    for s in held:
        hits = [found[e] for e in events[(s.run, s.session_ref, s.step_id)] if e in found]
        doubled += len(hits) > 1  # the worker split one input in two: its grouping differs
        best = max(hits, key=lambda h: h[1]) if hits else None
        live.append(ts.Pred(best[0], best[1], "live") if best else ts.Pred())
    offline = ts.predict_steps(served.model, held, served.unit)
    same = sum(a.technique == b.technique for a, b in zip(live, offline, strict=True))
    only_offline = sum(
        bool(b.technique) and not a.technique for a, b in zip(live, offline, strict=True)
    )
    only_live = sum(
        bool(a.technique) and not b.technique for a, b in zip(live, offline, strict=True)
    )
    ctx = tagserve.scoring_context(fit_on, served.unit)
    ctx["tactic_of"] = served.tactic_of
    out: dict[str, Any] = {
        "model": served.version,
        "held_out_steps": len(held),
        "same_answer": same,
        "agreement": round(same / len(held), 4) if held else None,
        "labelled_offline_only": only_offline,
        "labelled_live_only": only_live,
        "different_technique": len(held) - same - only_offline - only_live,
        "inputs_with_two_live_labels": doubled,
    }
    for name, preds in (("live", live), ("offline", offline)):
        report, _ = ts.score(name, held, preds, unit=served.unit, split="test", draws=draws, **ctx)
        out[f"{name}_micro_f1"] = report.headline["micro_f1"]
        out[f"{name}_micro_f1_ci"] = report.headline["micro_f1_ci"]
    return out


# ------------------------------------------------------------------ publish and print


def publish_rows(
    result: Result, baseline: dict[str, Any] | None, now_us: int
) -> list[dict[str, Any]]:
    """Rows for ``mirage.eval_metrics`` (the Lab dashboard reads them)."""
    stamp = (
        time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now_us / 1e6)) + f".{now_us % 1_000_000:06d}"
    )
    was = (baseline or {}).get("metrics") or {}
    rows = []
    for name, m in sorted(result.metrics.items()):
        ci = m["ci"] or [m["value"], m["value"]]
        rows.append(
            {
                "dataset": result.dataset, "metric": name, "value": m["value"], "ci_low": ci[0],
                "ci_high": ci[1], "baseline": (was.get(name) or {}).get("value", m["value"]),
                "gate": 255, "detail": m["detail"][:300], "published_at": stamp, "version": now_us,
            }
        )  # fmt: skip
    for name, g in sorted({**result.checks, **result.gates}.items()):
        rows.append(
            {
                "dataset": result.dataset, "metric": f"gate.{name}", "value": float(g["ok"]),
                "ci_low": float(g["ok"]), "ci_high": float(g["ok"]), "baseline": 1.0,
                "gate": int(g["ok"]), "detail": g["detail"][:300], "published_at": stamp,
                "version": now_us,
            }
        )  # fmt: skip
    return rows


def show(result: Result) -> None:
    print(f"dataset {result.dataset}")
    for name, c in result.checks.items():
        print(f"  check {'ok  ' if c['ok'] else 'FAIL'} {name}: {c['detail']}")
    for name, m in result.metrics.items():
        ci = f" [{m['ci'][0]:.3f}, {m['ci'][1]:.3f}]" if m["ci"] else ""
        print(f"  {name} = {m['value']:.3f}{ci}  {m['detail']}")
    for name, g in result.gates.items():
        print(f"  gate {'met ' if g['ok'] else 'NOT MET'} {name}: {g['detail']}")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage-eval")
    ap.add_argument("cmd", choices=["run", "check", "freeze", "publish", "served"])
    ap.add_argument("--model", type=Path, default=tagserve.MODEL_DIR, help="served: the tagger")
    ap.add_argument("--data", type=Path, default=ROOT / "build" / "dataset")
    ap.add_argument("--name", default="gate2", help="freeze: the frozen dataset's name")
    ap.add_argument("--atomic", type=Path, default=tagserve.ATOMIC_FILE)
    ap.add_argument("--draws", type=int, default=1000)
    ap.add_argument("--write-baseline", action="store_true", help="run: record the result")
    ap.add_argument(
        "--verify", action="store_true", help="run: rebuild what was frozen and compare"
    )
    ap.add_argument("--allow-unhealthy", action="store_true", help="development data only")
    ap.add_argument("--force", action="store_true", help="freeze: replace an existing dataset")
    args = ap.parse_args(argv)
    stale: list[str] = []
    try:
        if args.cmd == "freeze":
            target = freeze(args.data, args.name, args.atomic, args.force)
            print(f"froze {target.relative_to(ROOT)}")
            return
        ds = Dataset.load(args.data)
        if args.cmd == "served":
            os.environ.update({k: v for k, v in ds_mod._env_file().items() if k not in os.environ})
            report = served_check(
                ds, ds_mod.ClickHouse.from_env(), tagserve.load(args.model), args.draws
            )
            print(json.dumps(report, indent=1))
            # One answer per input, and the same one: anything else means the live path and
            # the scored path are not the same model.
            bad = report["held_out_steps"] - report["same_answer"]
            if bad or report["inputs_with_two_live_labels"] or not report["held_out_steps"]:
                raise SystemExit(f"the live labels differ from the offline answer on {bad} step(s)")
            print("ok")
            return
        choices = load_choices()
        frozen = (args.data / "FROZEN.json").exists()
        # A frozen dataset is evaluated from what it froze unless asked to rebuild.
        atomic_file = args.atomic if (args.verify or not frozen) else None
        result = evaluate(
            ds,
            choices,
            draws=args.draws,
            allow_unhealthy=args.allow_unhealthy,
            atomic_file=atomic_file,
        )
        problems = result.failures()
        stale = verify_frozen(args.data, args.atomic) if args.verify and frozen else []
    except HarnessError as exc:
        raise SystemExit(f"mirage-eval: {exc}") from exc
    show(result)
    path = baseline_path(ds.name)
    if args.cmd == "run":
        if args.write_baseline:
            if problems:
                print("the baseline is not written while a check or gate fails")
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(result.to_json(), indent=1) + "\n")
                print(f"wrote {path.relative_to(ROOT)}")
    elif args.cmd == "check":
        if not path.exists():
            raise SystemExit(f"no committed baseline at {path.relative_to(ROOT)}")
        problems = regress(result, json.loads(path.read_text()))
    elif args.cmd == "publish":
        os.environ.update({k: v for k, v in ds_mod._env_file().items() if k not in os.environ})
        ch = ds_mod.ClickHouse.from_env()
        baseline = json.loads(path.read_text()) if path.exists() else None
        ch.insert("mirage.eval_metrics", publish_rows(result, baseline, time.time_ns() // 1000))
        print(
            f"published {len(result.metrics)} metrics, "
            f"{len(result.checks) + len(result.gates)} checks and gates"
        )
    problems = [*problems, *stale]  # whatever the subcommand, a stale freeze is a failure
    for p in problems:
        print("FAIL", p)
    print("ok" if not problems else f"{len(problems)} problem(s)")
    raise SystemExit(1 if problems else 0)


if __name__ == "__main__":
    main()
