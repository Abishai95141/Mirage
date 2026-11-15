"""LogPrécis as the tactic-level baseline (phase 2 spec, 2.4 layer 3 and Q13).

LogPrécis (``SmartDataPolito/logprecis``, Apache-2.0) labels each part of a Unix shell session
with one of seven labels: five ATT&CK tactics, Harmless and Other. It was trained on 360
sessions and knows nothing of Credential Access, Command and Control or Collection, so it is
not the tagger. It is the published baseline a tagger for shell sessions should be measured
against, and the spec asks for that measurement at tactic level.

Two things make the comparison fair to it:

- its Defense Evasion predates ATT&CK v19, which split that tactic into Stealth (TA0005) and
  Defense Impairment (TA0112). Both are folded into one before comparing (Q14);
- it is scored on SSH steps only, the one protocol it was trained for.

A step whose true tactic is outside its five still counts against it: that gap is the reason
it is a baseline and not the answer.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import replace

from mirage_intel import tagscore as ts

REPO = "SmartDataPolito/logprecis"
TACTIC = {
    "execution": "TA0002",
    "persistence": "TA0003",
    "discovery": "TA0007",
    "impact": "TA0040",
    "defense evasion": "TA0005",
}
FOLD = {"TA0112": "TA0005"}  # v19's split of Defense Evasion, compared at the merged level
SEPARATOR = " ; "
LINES_PER_CHUNK = 8  # a session is fed in pieces well under the model's 512-token window

Classify = Callable[[str], list[dict]]  # text -> [{"entity_group", "start", "end"}, ...]


def fold(tactic: str) -> str:
    return FOLD.get(tactic, tactic)


def _label(group: str) -> str:
    """A model label as a tactic ID, or '' for Harmless, Other and anything unrecognised."""
    name = group.split("-", 1)[1] if group[:2] in ("B-", "I-") else group
    return TACTIC.get(name.replace("_", " ").strip().lower(), "")


def session_tactics(lines: list[str], classify: Classify) -> list[str]:
    """One tactic (or '') per line of a session, in order. A line gets the label that covers
    most of its characters."""
    out: list[str] = []
    for start in range(0, len(lines), LINES_PER_CHUNK):
        chunk = lines[start : start + LINES_PER_CHUNK]
        spans, pos = [], 0
        for line in chunk:
            spans.append((pos, pos + len(line)))
            pos += len(line) + len(SEPARATOR)
        entities = classify(SEPARATOR.join(chunk))
        for lo, hi in spans:
            cover: Counter = Counter()
            for e in entities:
                overlap = min(hi, int(e["end"])) - max(lo, int(e["start"]))
                if overlap > 0:
                    cover[_label(str(e.get("entity_group") or e.get("entity") or ""))] += overlap
            out.append(cover.most_common(1)[0][0] if cover else "")
    return out


def load(device: str = "cpu") -> Classify:
    """The real model. Needs the ``research`` dependency group and the weights."""
    from transformers import pipeline

    pipe = pipeline(
        "token-classification", model=REPO, aggregation_strategy="simple", device=device
    )
    return lambda text: pipe(text)


def predict(steps: list[ts.Step], classify: Classify) -> list[ts.Pred]:
    """A tactic for each step, read from its whole session in order. Non-SSH steps abstain."""
    by_session: dict[tuple[str, str], list[int]] = {}
    for i, s in enumerate(steps):
        if s.protocol == "ssh":
            by_session.setdefault(s.session, []).append(i)
    preds = [ts.Pred() for _ in steps]
    for indices in by_session.values():
        indices.sort(key=lambda i: steps[i].step_id)
        for i, tactic in zip(
            indices, session_tactics([steps[i].line for i in indices], classify), strict=True
        ):
            if tactic:
                preds[i] = ts.Pred(tactic, 1.0, "logprecis")
    return preds


def tactic_view(steps: list[ts.Step]) -> list[ts.Step]:
    """The same steps with the folded tactic in the technique's place, so the technique
    scorer measures tactics."""
    return [replace(s, technique=fold(s.tactic), tactic=fold(s.tactic)) for s in steps]


def as_tactics(preds: list[ts.Pred], tactic_of: dict[str, str]) -> list[ts.Pred]:
    """A technique tagger's predictions at tactic level."""
    return [
        ts.Pred(fold(tactic_of.get(p.technique, "")), p.confidence, p.evidence)
        if p.technique
        else ts.Pred()
        for p in preds
    ]


def score_tactics(name: str, steps: list[ts.Step], preds: list[ts.Pred], **kwargs):
    """Tactic-level report over SSH steps."""
    keep = [i for i, s in enumerate(steps) if s.protocol == "ssh"]
    view = tactic_view([steps[i] for i in keep])
    tactics = {s.technique for s in view if s.technique}
    return ts.score(
        name,
        view,
        [preds[i] for i in keep],
        train_techniques=tactics,
        seen_skeletons=set(),
        tactic_of={t: t for t in tactics | set(TACTIC.values())},
        **kwargs,
    )
