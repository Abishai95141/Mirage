"""The chosen tagger, built one way for every user (phase 2 spec, 2.4).

Three programs need "the tagger the experiment chose": the evaluation harness that scores it,
the trainer that writes the file the live worker loads, and the worker itself. Each building
it in its own way would let the scored model and the running model drift apart, so all three
come here. What was chosen is read from ``eval/choices.yaml``; nothing in this module decides
it.

A served model is one JSON file: the index entries (normalised text, technique, where the
entry came from), the neighbour count, the threshold, the unit and the tactic each technique
maps to. The vectors are recomputed from the entries on load, by the same embedding model, so
the file has nothing executable and nothing that could disagree with its entries.

    uv run --group research mirage-tagger-train --data eval/datasets/gate2
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from mirage_intel import atomic
from mirage_intel import tagmodels as tm
from mirage_intel import tagscore as ts
from mirage_intel.attack import Attack
from mirage_intel.embedders import EMBEDDERS, Embed, neural_embedder
from mirage_intel.text import normalise

ROOT = Path(__file__).resolve().parents[3]
CHOICES = ROOT / "eval" / "choices.yaml"
MODEL_DIR = ROOT / "build" / "models" / "tagger"
# Atomic Red Team's Linux index (Red Canary, MIT licence), fetched to the lab host and not
# kept in the repository. Pinned by hash: another version would index different text.
ATOMIC_FILE = ROOT / "data" / "atomic" / "linux-index.yaml"
ATOMIC_SHA256 = "4848189d53fda69640fc79819fa24b243463affcb0df7ed3db79ab305ec7a6d8"

MakeEmbed = Callable[[list[str]], Embed]


class ChoiceError(RuntimeError):
    """``eval/choices.yaml`` does not describe a tagger this module can build."""


def choice(path: Path = CHOICES) -> dict[str, Any]:
    """The tagger the experiment settled on."""
    doc = (yaml.safe_load(path.read_text()) or {}) if path.exists() else {}
    chosen = doc.get("tagger")
    if not isinstance(chosen, dict):
        raise ChoiceError(f"{path.name} names no tagger; run the experiment and record its pick")
    if chosen.get("kind") != "retrieval":
        raise ChoiceError(f"tagger kind {chosen.get('kind')!r} is not one this build can serve")
    if chosen.get("embedder") not in EMBEDDERS:
        raise ChoiceError(f"unknown embedding model {chosen.get('embedder')!r}")
    if chosen.get("unit") not in ("line", "pieces"):
        raise ChoiceError("the tagger's unit is 'line' or 'pieces'")
    return chosen


def choice_identity(chosen: dict[str, Any]) -> dict[str, Any]:
    """What an index is built from. A frozen index is only the chosen model's if this is the
    same; the threshold is applied at prediction time and is not part of it."""
    return {k: chosen.get(k) for k in ("name", "kind", "embedder", "k", "unit", "atomic")}


def atomic_pairs(
    path: Path, fit_splits: tuple[str, ...], check_hash: bool = True
) -> dict[str, list[tuple[str, str]]]:
    """Per unit, the (text, technique) pairs from Atomic Red Team that may be indexed when
    fitting on ``fit_splits``: every test a procedure outside those splits quotes is left
    out by its GUID, technique IDs the pinned ATT&CK version replaced are translated, and
    only the catalogue's techniques are kept."""
    from mirage_lab.models import Catalogue

    if check_hash and hashlib.sha256(path.read_bytes()).hexdigest() != ATOMIC_SHA256:
        raise ChoiceError(f"{path} is not the pinned Atomic Red Team index")
    catalogue = Catalogue.load(ROOT / "lab" / "catalogue")
    split = yaml.safe_load((ROOT / "eval" / "split.yaml").read_text())
    of_proc = {pid: s for s, ids in split["procedures"].items() for pid in ids}
    held_out = atomic.guids_in(
        [p.ref for p in catalogue.procedures.values() if of_proc[p.id] not in fit_splits]
    )
    tests = atomic.load(path)
    current = Attack.from_index().replaced_by
    label_space = {p.technique for p in catalogue.procedures.values() if p.technique}
    return {
        unit: atomic.pairs(tests, unit, label_space, held_out, current)
        for unit in ("line", "pieces")
    }


def seen_in(pairs: dict[str, list[tuple[str, str]]]) -> set[tuple[str, str]]:
    """The leak guard for a model that indexed this text: a scored step whose whole input
    equals an indexed line or piece is dropped and counted, whichever unit was indexed."""
    return {("ssh", normalise(text)) for unit in pairs for text, _ in pairs[unit]}


def scoring_context(fit_on: list[ts.Step], unit: str = "line") -> dict[str, Any]:
    """What scoring needs to know about the data a model was fitted on. The leak guard holds
    every text the model was fitted on in the unit it reads: a scored input that is, as a
    whole, one of the fitted lines or one of the fitted gated commands is dropped and
    counted, not scored."""
    tactics: dict[str, Counter] = {}
    for s in fit_on:
        if s.technique and s.tactic:
            tactics.setdefault(s.technique, Counter())[s.tactic] += 1
    seen = {s.skeleton for s in fit_on}
    if unit != "line":
        seen |= {(s.protocol, normalise(t)) for s in fit_on for t in s.texts(unit)}
    return {
        "train_techniques": {s.technique for s in fit_on if s.technique},
        "seen_skeletons": seen,
        "tactic_of": {t: c.most_common(1)[0][0] for t, c in tactics.items()},
    }


def tactic_map(fit_on: list[ts.Step], techniques: set[str]) -> dict[str, str]:
    """Technique -> the tactic a label is written with: the one the training procedures use
    it for most, or, for a technique only the public corpus covers, its first in ATT&CK."""
    counts: dict[str, Counter] = {}
    for s in fit_on:
        if s.technique and s.tactic:
            counts.setdefault(s.technique, Counter())[s.tactic] += 1
    out = {t: c.most_common(1)[0][0] for t, c in counts.items()}
    attack = Attack.from_index()
    for t in sorted(techniques - set(out)):
        known = attack.techniques.get(t)
        if known and known.tactics:
            out[t] = known.tactics[0]
    return out


def fit(
    chosen: dict[str, Any],
    fit_on: list[ts.Step],
    make_embed: MakeEmbed,
    extra: list[tuple[str, str]] | None = None,
) -> tm.Retrieval:
    """The chosen model, fitted on these steps and, when the choice says so, on ``extra``."""
    model = tm.Retrieval(
        make_embed,
        label=chosen["embedder"],
        k=int(chosen.get("k", 1)),
        threshold=float(chosen["threshold"]),
        extra=extra if chosen.get("atomic") else None,
    )
    return model.fit(fit_on, chosen["unit"])


def index_texts(model: tm.Retrieval) -> list[str]:
    return [e.key for e in model.entries]


@dataclass
class Served:
    """A loaded model and what the worker needs beside it."""

    model: tm.Retrieval
    unit: str
    tactic_of: dict[str, str]
    version: str
    attack_version: str

    def tag(self, protocol: str, texts: list[str]) -> tuple[int, ts.Pred] | None:
        """The label for one input, given the texts it is made of (a line's gated commands,
        or the line): the most confident answer at or above the threshold, and which text
        gave it. This is ``tagscore.predict_steps`` for a single step."""
        best: tuple[int, ts.Pred] | None = None
        for i, pred in enumerate(self.model.predict(protocol, texts)):
            if pred.technique and (best is None or pred.confidence >= best[1].confidence):
                best = (i, pred)
        return best


def save(
    model: tm.Retrieval | dict[str, Any],
    chosen: dict[str, Any],
    tactic_of: dict[str, str],
    meta: dict[str, Any],
    directory: Path = MODEL_DIR,
) -> Path:
    """Write the served model: a fitted one, or an index already in its saved form."""
    body = {
        **(model.to_saved() if isinstance(model, tm.Retrieval) else dict(model)),
        "embedder": chosen["embedder"],
        "unit": chosen["unit"],
        "tactic_of": dict(sorted(tactic_of.items())),
        "attack_version": Attack.from_index().version,
    }
    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:12]
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "model.json"
    path.write_text(
        json.dumps({**body, "version": f"tagger-{chosen['embedder']}-{digest}", **meta}) + "\n"
    )
    return path


def load(directory: Path = MODEL_DIR, make_embed: MakeEmbed | None = None) -> Served:
    body = json.loads((directory / "model.json").read_text())
    if make_embed is None:
        if body.get("embedder") not in EMBEDDERS:
            raise ValueError(f"unknown embedding model {body.get('embedder')!r}")
        # The worker runs with the model hub offline; the licence was checked at fetch.
        make_embed = neural_embedder(EMBEDDERS[body["embedder"]], check_licence=False)
    return Served(
        model=tm.Retrieval.from_saved(body, make_embed),
        unit=str(body["unit"]),
        tactic_of={str(k): str(v) for k, v in body["tactic_of"].items()},
        version=str(body["version"]),
        attack_version=str(body["attack_version"]),
    )


def main(argv: list[str] | None = None) -> None:
    import pyarrow.parquet as pq

    ap = argparse.ArgumentParser(prog="mirage-tagger-train")
    ap.add_argument("--data", type=Path, default=ROOT / "build" / "dataset")
    ap.add_argument("--atomic", type=Path, default=ATOMIC_FILE)
    ap.add_argument("--out", type=Path, default=MODEL_DIR)
    ap.add_argument(
        "--rebuild",
        action="store_true",
        help="fit from the steps and the Atomic file even when the dataset froze an index",
    )
    args = ap.parse_args(argv)
    chosen = choice()
    steps = ts.steps_from_rows(pq.read_table(args.data / "steps.parquet").to_pylist())
    # The served model is the one the harness scores: fitted on train and dev, never on test.
    fit_splits = ("train", "dev")
    fit_on = [s for s in steps if s.split in fit_splits]
    frozen = args.data / "tagger.index.json"
    if frozen.exists() and not args.rebuild:
        # A frozen dataset carries the index the harness scores. Serving that same index
        # needs neither the Atomic file nor the embedding model here: the worker embeds it.
        index = json.loads(frozen.read_text())
        if index.get("choice") != choice_identity(chosen):
            raise ChoiceError(
                f"the index frozen in {args.data} was built for {index.get('choice')}, and "
                "eval/choices.yaml now names another model: refreeze, or pass --rebuild"
            )
        saved = {**index["model"], "threshold": float(chosen["threshold"])}
        how = "the index frozen with the dataset"
    else:
        extra = (
            atomic_pairs(args.atomic, fit_splits)[chosen["unit"]] if chosen.get("atomic") else []
        )
        saved = fit(
            chosen, fit_on, neural_embedder(EMBEDDERS[chosen["embedder"]]), extra
        ).to_saved()
        how = "fitted from the steps" + (" and the Atomic Red Team file" if extra else "")
    techniques = {str(e[1]) for e in saved["entries"]}
    origins = Counter(str(e[2]) for e in saved["entries"])
    path = save(
        saved,
        chosen,
        tactic_map(fit_on, techniques),
        {"fitted_on": {"splits": list(fit_splits), "entries": dict(sorted(origins.items()))}},
        args.out,
    )
    served = json.loads(path.read_text())
    print(
        json.dumps(
            {
                "model": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
                "version": served["version"],
                "built": how,
                "entries": served["fitted_on"]["entries"],
                "techniques": len(techniques),
                "threshold": served["threshold"],
                "unit": chosen["unit"],
            },
            indent=1,
        )
    )


if __name__ == "__main__":
    main()
