"""Real-traffic sanity checks (phase 2 spec 2.3 and section 5; gap register M3).

Lab scores are an upper bound: the scenario authors chose the procedures and the timing
profiles are generators. So each report carries two checks on traffic nobody here wrote, the
replayed sample of the public Cowrie corpus (Zenodo record 21260400, CC BY 4.0):

- **Classifier against heuristic labels.** The event-level model (the corpus has no keystroke
  logs) is trained on the frozen lab dataset and asked about every sample session. Its answer
  is compared with two heuristics the spec names: a session with no successful login or no
  command is a scanner; a session whose commands repeat exactly across several sources is a
  bot. The heuristics are not ground truth. Agreement says the model is not doing something
  absurd on real traffic; disagreement says where to look. Sessions the classifier's own rule
  settles are left out of the figure: there the heuristic and the rule say the same thing.
- **Tagger abstention and tactic mix.** How often the served tagger answers on real commands,
  and which tactics it names. There is no truth to score against; a tagger that labels every
  real command, or none, is the thing this would show.

Neither is a gate. Both need the running store, and the second the embedding model.

    uv run --group research python -m mirage_intel.realcheck --data eval/datasets/gate2

Nothing printed or written here contains a command: counts and shares only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

from mirage_intel import classifier
from mirage_intel.dataset import ClickHouse, _env_file, feature_query, features_of
from mirage_intel.text import normalise

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "build" / "experiments" / "real"
SAMPLE = "zenodo:21260400"
MIN_SOURCES = 3  # "repeats across many sources": the same command sequence from this many

_LINE = (
    "source = 'cowrie' AND class = 'process_activity' AND action = 'command' "
    "AND outcome = 'unknown'"
)
_IN_SAMPLE = (
    "session_id IN (SELECT DISTINCT session_id FROM mirage.events "  # noqa: S608
    f"WHERE JSONExtractString(payload, 'dataset') = '{SAMPLE}' AND session_id != '')"
)
SESSIONS_SQL = (
    "SELECT session_id, any(if(src_pseudonym != '', src_pseudonym, src_ip)) AS src, "  # noqa: S608
    "arrayMap(x -> x.2, arraySort(x -> x.1, groupArrayIf("
    f"(toUnixTimestamp64Micro(ts), JSONExtractString(payload, 'command')), {_LINE}))) AS commands "
    f"FROM mirage.events FINAL WHERE {_IN_SAMPLE} GROUP BY session_id"
)


def sequence_key(commands: list[str]) -> str:
    """One key per command sequence, exact up to the parts a bot varies (addresses, numbers)."""
    joined = "\n".join(normalise(c) for c in commands)
    return hashlib.sha256(joined.encode()).hexdigest()


def heuristic_labels(sessions: list[dict[str, Any]], min_sources: int = MIN_SOURCES) -> list[str]:
    """``scanner``, ``scripted_bot`` or ``""`` (the heuristics say nothing) per session. Each
    session needs ``auth_success``, ``inputs``, ``src`` and ``commands``."""
    sources: dict[str, set[str]] = {}
    for s in sessions:
        if s["commands"]:
            sources.setdefault(sequence_key(s["commands"]), set()).add(s["src"])
    out = []
    for s in sessions:
        if int(s["auth_success"]) == 0 or not s["commands"] or int(s["inputs"]) == 0:
            out.append("scanner")
        elif len(sources[sequence_key(s["commands"])]) >= min_sources:
            out.append("scripted_bot")
        else:
            out.append("")
    return out


def agreement(
    heuristic: list[str],
    predicted: list[str],
    sources: list[str],
    decided: list[str] | None = None,
    draws: int = 1000,
    seed: int = 0,
) -> dict[str, Any]:
    """Agreement between the model and the heuristics, over the sessions the **model**
    decided. Where the classifier's rule decided (no access means scanner), the "no login"
    heuristic and the rule are one statement, and a classifier agreeing with itself is not
    evidence: those sessions are counted and kept out of the figure. What is left is where
    the model can be wrong: a session that logged in and typed nothing (a scanner by the
    heuristic) and a command sequence many sources repeat (a bot by the heuristic).

    The interval resamples sources: one source's sessions are not independent."""
    decided = decided or ["model"] * len(heuristic)
    by_rule = [d == "rule" for d in decided]
    open_ = [i for i, r in enumerate(by_rule) if not r]
    labelled = [i for i in open_ if heuristic[i]]
    by_class: dict[str, dict[str, Any]] = {}
    for label in ("scanner", "scripted_bot"):
        idx = [i for i in labelled if heuristic[i] == label]
        said = Counter(predicted[i] for i in idx)
        by_class[label] = {
            "sessions": len(idx),
            "agree": round(said[label] / len(idx), 4) if idx else None,
            "model_said": dict(sorted(said.items())),
        }
    unlabelled = Counter(predicted[i] for i in open_ if not heuristic[i])
    hit = np.array([heuristic[i] == predicted[i] for i in labelled], dtype=float)
    result: dict[str, Any] = {
        "sessions": len(heuristic),
        "settled_by_the_rule": {
            "sessions": sum(by_rule),
            "note": "no access: scanner by the rule and by the heuristic alike; not counted",
        },
        "decided_by_the_model": len(open_),
        "labelled_by_a_heuristic": len(labelled),
        "agreement": round(float(hit.mean()), 4) if len(hit) else None,
        "by_heuristic": by_class,
        "no_heuristic": {
            "sessions": sum(unlabelled.values()),
            "model_said": dict(sorted(unlabelled.items())),
        },
    }
    if len(hit):
        groups: dict[str, list[int]] = {}
        for pos, i in enumerate(labelled):
            groups.setdefault(sources[i], []).append(pos)
        names = sorted(groups)
        rng = np.random.default_rng(seed)
        values = []
        for _ in range(draws):
            pick = np.concatenate(
                [groups[names[j]] for j in rng.integers(0, len(names), len(names))]
            )
            values.append(float(hit[pick].mean()))
        result["agreement_ci"] = [round(float(x), 4) for x in np.percentile(values, [2.5, 97.5])]
        result["sources"] = len(names)
    return result


def classifier_check(ch: ClickHouse, data: Path, family: str, draws: int) -> dict[str, Any]:
    sample = {r["session_id"]: r for r in ch.rows(SESSIONS_SQL)}
    if not sample:
        return {"sessions": 0, "note": "the sample has not been replayed into this store"}
    ids = sorted(sample)
    feats: dict[str, dict[str, Any]] = {}
    for start in range(0, len(ids), 500):
        for r in ch.rows(feature_query(ids[start : start + 500])):
            feats[r["session_id"]] = {**features_of(r), "protocol": r.get("protocol") or "ssh"}
    sessions = [{**sample[i], **feats[i]} for i in ids if i in feats]
    train_rows = [r for r in classifier.load_rows(data / "sessions.parquet") if not r.get("real")]
    model = classifier.train(train_rows, classifier.FEATURE_SETS["event"], family)
    decisions = model.decide(sessions)
    heuristic = heuristic_labels(sessions)
    out = agreement(
        heuristic,
        [c for c, _, _ in decisions],
        [s["src"] for s in sessions],
        [who for _, _, who in decisions],
        draws,
    )
    out["without_a_session_summary"] = len(ids) - len(sessions)
    out["model"] = f"{family}/event, trained on {len(train_rows)} lab sessions"
    return out


def tagger_check(ch: ClickHouse, model_dir: Path) -> dict[str, Any]:
    from mirage_intel import tagserve

    served = tagserve.load(model_dir)
    counts: Counter = Counter()
    for r in ch.rows(SESSIONS_SQL):
        counts.update(r["commands"])
    lines = sorted(counts)
    if not lines:
        return {"commands": 0, "note": "the sample has no commands in this store"}
    tactics: Counter = Counter()
    answered = answered_weighted = 0
    for start in range(0, len(lines), 256):
        chunk = lines[start : start + 256]
        for line, pred in zip(chunk, served.model.predict("ssh", chunk), strict=True):
            if pred.technique:
                answered += 1
                answered_weighted += counts[line]
                tactics[served.tactic_of.get(pred.technique, "unmapped")] += counts[line]
    total = sum(counts.values())
    return {
        "model": served.version,
        "distinct_commands": len(lines),
        "commands": total,
        "abstention_distinct": round(1 - answered / len(lines), 4),
        "abstention_weighted": round(1 - answered_weighted / total, 4),
        "tactic_mix": {
            t: round(n / max(answered_weighted, 1), 4) for t, n in tactics.most_common()
        },
    }


def main(argv: list[str] | None = None) -> None:
    import yaml

    ap = argparse.ArgumentParser(prog="mirage_intel.realcheck")
    ap.add_argument("--data", type=Path, default=ROOT / "eval" / "datasets" / "gate2")
    ap.add_argument("--tagger", type=Path, default=ROOT / "build" / "models" / "tagger")
    ap.add_argument("--no-tagger", action="store_true", help="skip the part that needs the model")
    ap.add_argument("--draws", type=int, default=1000)
    args = ap.parse_args(argv)
    os.environ.update({k: v for k, v in _env_file().items() if k not in os.environ})
    ch = ClickHouse.from_env()
    choices = yaml.safe_load((ROOT / "eval" / "choices.yaml").read_text())
    report: dict[str, Any] = {
        "sample": SAMPLE,
        "min_sources": MIN_SOURCES,
        "classifier": classifier_check(
            ch, args.data, choices["classifier_event"]["family"], args.draws
        ),
    }
    if not args.no_tagger:
        report["tagger"] = tagger_check(ch, args.tagger)
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"real-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
    path.write_text(json.dumps(report, indent=1) + "\n")
    print(json.dumps(report, indent=1))
    print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
