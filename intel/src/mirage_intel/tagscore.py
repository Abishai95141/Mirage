"""Scoring a technique tagger against the lab's ground truth (phase 2 spec, 2.4 and section 5).

The unit that is scored is the **step**: one line a simulated attacker sent. A line can expand
to several gated commands (a pipeline); the step's prediction is the most confident one among
them, or an abstention. The unit that is independent is the **procedure**: a lab run repeats
each procedure with different slot values, and those repeats are not new evidence. So every
procedure contributes one unit of weight, shared equally among its distinct renderings, and
every interval resamples procedures.

Three populations are kept apart, because mixing them makes a number mean nothing:

- **headline**: procedures whose technique has at least one training procedure, plus the
  explicit negatives (procedures with no technique, where the right answer is to abstain);
- **unseen**: procedures whose technique no training procedure has. A learned model cannot
  name them; retrieval over ATT&CK text might. Reported, never averaged in;
- **leaked**: renderings whose normalised text also occurs in train or dev. Dropped from the
  headline and counted (section 5, item 3, at the unit that is actually scored).

Nothing here prints or returns input text: reports hold counts, IDs and scores.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

import numpy as np

from mirage_intel.text import normalise, parent


@dataclass(frozen=True)
class Step:
    run: str
    session_ref: str
    step_id: str
    split: str
    protocol: str
    procedure: str
    technique: str  # "" for an explicit negative
    tactic: str
    source: str
    line: str  # the content-bearing input: for SSH the whole line as typed
    pieces: tuple[str, ...]  # the gated commands the line expanded to

    @property
    def session(self) -> tuple[str, str]:
        return (self.run, self.session_ref)

    @property
    def skeleton(self) -> tuple[str, str]:
        return (self.protocol, normalise(self.line))

    def texts(self, unit: str) -> tuple[str, ...]:
        """What a model is shown: the whole line, or each gated command."""
        return (self.line,) if unit == "line" or not self.pieces else self.pieces


def steps_from_rows(rows: list[dict[str, Any]]) -> list[Step]:
    """Group the export's per-event rows into steps."""
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        grouped[(r["run_id"], r["session_ref"], r["step_id"])].append(r)
    out = []
    for (run, ref, sid), events in sorted(grouped.items()):
        events.sort(key=lambda e: (e["ts_ms"], e["event_id"]))
        first = events[0]
        pieces = tuple(e["input"] for e in events if e["role"] == "decision")
        line = next((e["input"] for e in events if e["role"] == "input"), "") or " | ".join(pieces)
        out.append(
            Step(
                run=run,
                session_ref=ref,
                step_id=sid,
                split=first["split"],
                protocol=first["protocol"],
                procedure=first["procedure_id"],
                technique=first["technique_id"] or "",
                tactic=first.get("tactic") or "",
                source=first["source"],
                line=line,
                pieces=pieces,
            )
        )
    return out


@dataclass
class Pred:
    technique: str = ""  # "" abstains
    confidence: float = 0.0
    evidence: str = ""


class Tagger(Protocol):
    name: str

    def predict(self, protocol: str, texts: list[str]) -> list[Pred]: ...


def predict_steps(model: Tagger, steps: list[Step], unit: str = "line") -> list[Pred]:
    """One prediction per step: the most confident non-abstaining one among its texts."""
    flat: list[tuple[int, str, str]] = [
        (i, s.protocol, t) for i, s in enumerate(steps) for t in s.texts(unit)
    ]
    by_protocol: dict[str, list[int]] = defaultdict(list)
    for j, (_, protocol, _text) in enumerate(flat):
        by_protocol[protocol].append(j)
    preds: list[Pred] = [Pred()] * len(flat)
    for protocol, idx in by_protocol.items():
        for j, p in zip(idx, model.predict(protocol, [flat[j][2] for j in idx]), strict=True):
            preds[j] = p
    best = [Pred() for _ in steps]
    for (i, _, _), p in zip(flat, preds, strict=True):
        if p.technique and p.confidence >= best[i].confidence:
            best[i] = p
    return best


def _f1(tp: float, fp: float, fn: float) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


@dataclass
class Unit:
    """One procedure's share of the counts, averaged over its distinct renderings."""

    procedure: str
    technique: str
    source: str
    tp: float = 0.0
    fn: float = 0.0
    abstained: float = 0.0
    wrong: dict[str, float] = field(default_factory=dict)  # predicted technique -> weight
    tp_parent: float = 0.0
    fp_parent: float = 0.0
    fn_parent: float = 0.0

    @property
    def fp(self) -> float:
        return sum(self.wrong.values())


def units(steps: list[Step], preds: list[Pred]) -> list[Unit]:
    by_proc: dict[str, dict[tuple[str, str], tuple[Step, Pred]]] = defaultdict(dict)
    for s, p in zip(steps, preds, strict=True):
        by_proc[s.procedure].setdefault(s.skeleton, (s, p))  # one per distinct rendering
    out = []
    for proc, renderings in sorted(by_proc.items()):
        any_step = next(iter(renderings.values()))[0]
        u = Unit(proc, any_step.technique, any_step.source)
        weight = 1.0 / len(renderings)
        for s, p in renderings.values():
            if not p.technique:
                u.abstained += weight
            if s.technique and p.technique == s.technique:
                u.tp += weight
            else:
                if p.technique:
                    u.wrong[p.technique] = u.wrong.get(p.technique, 0.0) + weight
                if s.technique:
                    u.fn += weight
            folded_ok = bool(s.technique) and parent(p.technique) == parent(s.technique)
            if folded_ok and p.technique:
                u.tp_parent += weight
            else:
                u.fp_parent += weight * bool(p.technique)
                u.fn_parent += weight * bool(s.technique)
        out.append(u)
    return out


def _micro(us: list[Unit]) -> tuple[float, float, float]:
    return _f1(sum(u.tp for u in us), sum(u.fp for u in us), sum(u.fn for u in us))


def _macro(us: list[Unit]) -> float:
    tp: Counter = Counter()
    fp: Counter = Counter()
    fn: Counter = Counter()
    for u in us:
        if u.technique:
            tp[u.technique] += u.tp
            fn[u.technique] += u.fn
        for t, w in u.wrong.items():
            fp[t] += w
    techniques = sorted({u.technique for u in us if u.technique})
    if not techniques:
        return 0.0
    return float(np.mean([_f1(tp[t], fp[t], fn[t])[2] for t in techniques]))


def bootstrap(us: list[Unit], draws: int = 2000, seed: int = 0) -> tuple[float, float]:
    """A 95% interval for micro-F1, resampling procedures."""
    if not us:
        return 0.0, 0.0
    rng = np.random.default_rng(seed)
    tp, fp, fn = (np.array([getattr(u, k) for u in us]) for k in ("tp", "fp", "fn"))
    values = []
    for _ in range(draws):
        i = rng.integers(0, len(us), len(us))
        values.append(_f1(tp[i].sum(), fp[i].sum(), fn[i].sum())[2])
    lo, hi = np.percentile(values, [2.5, 97.5])
    return float(lo), float(hi)


def paired_difference(
    a: list[Unit], b: list[Unit], draws: int = 2000, seed: int = 0
) -> tuple[float, float, float]:
    """Micro-F1 of ``a`` minus ``b`` over the same procedures, with a 95% interval."""
    by_b = {u.procedure: u for u in b}
    pairs = [(u, by_b[u.procedure]) for u in a if u.procedure in by_b]
    if not pairs:
        return 0.0, 0.0, 0.0
    rng = np.random.default_rng(seed)

    def arr(side: int, k: str) -> np.ndarray:
        return np.array([getattr(p[side], k) for p in pairs])

    cols = {(s, k): arr(s, k) for s in (0, 1) for k in ("tp", "fp", "fn")}

    def f1(side: int, i: np.ndarray) -> float:
        return _f1(*(cols[(side, k)][i].sum() for k in ("tp", "fp", "fn")))[2]

    everything = np.arange(len(pairs))
    point = f1(0, everything) - f1(1, everything)
    diffs = []
    for _ in range(draws):
        i = rng.integers(0, len(pairs), len(pairs))
        diffs.append(f1(0, i) - f1(1, i))
    lo, hi = np.percentile(diffs, [2.5, 97.5])
    return float(point), float(lo), float(hi)


def session_tactics(
    steps: list[Step], preds: list[Pred], tactic_of: dict[str, str]
) -> dict[str, float]:
    """Precision and recall of each session's predicted tactic set against its true one."""
    truth: dict[tuple[str, str], set[str]] = defaultdict(set)
    guess: dict[tuple[str, str], set[str]] = defaultdict(set)
    for s, p in zip(steps, preds, strict=True):
        truth[s.session]  # a session with no tactic still counts as a session
        if s.tactic:
            truth[s.session].add(s.tactic)
        if p.technique and tactic_of.get(p.technique):
            guess[s.session].add(tactic_of[p.technique])
    hit = sum(len(truth[k] & guess[k]) for k in truth)
    predicted = sum(len(guess[k]) for k in truth)
    actual = sum(len(truth[k]) for k in truth)
    precision, recall, f1 = _f1(hit, predicted - hit, actual - hit)
    return {
        "sessions": len(truth),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


@dataclass
class Report:
    model: str
    unit: str
    split: str
    n_steps: int
    n_procedures: int
    n_leaked_renderings: int  # dropped: same normalised text occurs in train or dev
    headline: dict[str, Any] = field(default_factory=dict)
    unseen: dict[str, Any] = field(default_factory=dict)
    negatives: dict[str, Any] = field(default_factory=dict)
    by_source: dict[str, dict[str, Any]] = field(default_factory=dict)
    sessions: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _block(us: list[Unit], draws: int, seed: int) -> dict[str, Any]:
    precision, recall, f1 = _micro(us)
    lo, hi = bootstrap(us, draws, seed)
    folded = _f1(
        sum(u.tp_parent for u in us), sum(u.fp_parent for u in us), sum(u.fn_parent for u in us)
    )
    return {
        "procedures": len(us),
        "techniques": len({u.technique for u in us if u.technique}),
        "micro_f1": round(f1, 4),
        "micro_f1_ci": [round(lo, 4), round(hi, 4)],
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "macro_f1": round(_macro(us), 4),
        "micro_f1_parent_folded": round(folded[2], 4),
        "abstention": round(float(np.mean([u.abstained for u in us])), 4) if us else 0.0,
    }


def score(
    model_name: str,
    steps: list[Step],
    preds: list[Pred],
    *,
    train_techniques: set[str],
    seen_skeletons: set[tuple[str, str]],
    tactic_of: dict[str, str],
    unit: str = "line",
    split: str = "dev",
    draws: int = 2000,
    seed: int = 0,
) -> tuple[Report, list[Unit]]:
    """Score one model's step predictions. Returns the report and the headline units (for a
    paired comparison with another model)."""
    kept = [(s, p) for s, p in zip(steps, preds, strict=True) if s.skeleton not in seen_skeletons]
    leaked = len(steps) - len(kept)
    k_steps = [s for s, _ in kept]
    k_preds = [p for _, p in kept]
    all_units = units(k_steps, k_preds)
    headline = [u for u in all_units if not u.technique or u.technique in train_techniques]
    unseen = [u for u in all_units if u.technique and u.technique not in train_techniques]
    negatives = [u for u in all_units if not u.technique]
    report = Report(
        model=model_name,
        unit=unit,
        split=split,
        n_steps=len(steps),
        n_procedures=len(all_units),
        n_leaked_renderings=leaked,
        headline=_block(headline, draws, seed),
        unseen={
            "procedures": len(unseen),
            "techniques": len({u.technique for u in unseen}),
            "recall": round(_micro(unseen)[1], 4),
            "abstention": round(float(np.mean([u.abstained for u in unseen])), 4)
            if unseen
            else 0.0,
        },
        negatives={
            "procedures": len(negatives),
            "false_positive_rate": round(float(np.mean([u.fp for u in negatives])), 4)
            if negatives
            else 0.0,
        },
        by_source={
            src: _block([u for u in headline if u.source == src], draws, seed)
            for src in sorted({u.source for u in headline})
        },
        sessions=session_tactics(k_steps, k_preds, tactic_of),
    )
    return report, headline
