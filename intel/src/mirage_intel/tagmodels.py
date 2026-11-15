"""Technique taggers that can be compared on the same steps (phase 2 spec, 2.4).

Every model has one job: given a protocol and a text, name an ATT&CK technique with a
confidence, or abstain. They differ in where the knowledge comes from:

- ``MostFrequent``: the baseline every other model has to beat. It always answers the most
  common technique of the *training* split.
- ``RuleModel``: the hand-written regex rules (layer 1).
- ``LinearNgram``: a linear classifier on character n-grams, learned from the training split.
- ``Retrieval``: nearest neighbours among training inputs and, optionally, ATT&CK technique
  descriptions, under any embedding function. It can name a technique no training procedure
  has, which a classifier cannot.
- ``Cascade``: the first of several models that answers above its own threshold.

A learned model sees only the training split. Its abstention threshold is tuned on dev by
``tune_threshold``; the test split is never passed to anything in this module.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from mirage_intel.tagscore import Pred, Step
from mirage_intel.text import normalise

NONE = ""  # the label of an explicit negative: nothing to tag


def _key(protocol: str, text: str) -> str:
    """What a learned model reads: the protocol, then the normalised text."""
    return f"[{protocol}] {normalise(text)}"


def training_pairs(steps: list[Step], unit: str) -> list[tuple[str, str]]:
    """Distinct (key, technique) pairs from the steps' texts."""
    seen: dict[tuple[str, str], None] = {}
    for s in steps:
        for text in s.texts(unit):
            seen.setdefault((_key(s.protocol, text), s.technique), None)
    return list(seen)


class MostFrequent:
    name = "most-frequent"

    def __init__(self) -> None:
        self.technique = NONE

    def fit(self, steps: list[Step], unit: str = "line") -> MostFrequent:
        by_procedure = {s.procedure: s.technique for s in steps if s.technique}
        counts = Counter(by_procedure.values())
        self.technique = sorted(counts, key=lambda t: (-counts[t], t))[0] if counts else NONE
        return self

    def predict(self, protocol: str, texts: list[str]) -> list[Pred]:
        return [Pred(self.technique, 1e-6, "most frequent in training") for _ in texts]


class RuleModel:
    name = "rules"

    def __init__(self, engine) -> None:
        self.engine = engine

    def fit(self, steps: list[Step], unit: str = "line") -> RuleModel:
        return self  # rules are written, not learned

    def predict(self, protocol: str, texts: list[str]) -> list[Pred]:
        out = []
        for text in texts:
            hit = self.engine.best(protocol, text)
            out.append(Pred(hit.technique, hit.confidence, hit.rule_id) if hit else Pred())
        return out


class LinearNgram:
    """Logistic regression over TF-IDF character n-grams. Negatives are a class of their own,
    so the model can learn that a harmless command has no technique."""

    def __init__(
        self,
        ngram: tuple[int, int] = (2, 5),
        c: float = 10.0,
        threshold: float = 0.0,
        extra: list[tuple[str, str]] | None = None,
    ) -> None:
        self.ngram, self.c, self.threshold = ngram, c, threshold
        # Labelled text from outside the lab (Atomic Red Team), as (text, technique) for SSH.
        self.extra = extra or []
        self.name = f"linear-char{ngram[0]}-{ngram[1]}" + ("+atomic" if self.extra else "")
        self.vectorizer: TfidfVectorizer | None = None
        self.model: LogisticRegression | None = None
        self.only: str | None = None  # the single class, when training has just one

    def fit(self, steps: list[Step], unit: str = "line") -> LinearNgram:
        pairs = training_pairs(steps, unit)
        pairs += [(_key("ssh", text), technique) for text, technique in self.extra]
        labels = [t for _, t in pairs]
        if len(set(labels)) < 2:
            self.only = labels[0] if labels else NONE
            return self
        self.vectorizer = TfidfVectorizer(
            analyzer="char_wb", ngram_range=self.ngram, sublinear_tf=True, lowercase=False
        )
        x = self.vectorizer.fit_transform([k for k, _ in pairs])
        self.model = LogisticRegression(C=self.c, max_iter=2000, class_weight="balanced")
        self.model.fit(x, labels)
        return self

    def predict(self, protocol: str, texts: list[str]) -> list[Pred]:
        if self.model is None or self.vectorizer is None:
            return [Pred(self.only or NONE, 1.0 if self.only else 0.0, self.name) for _ in texts]
        probs = self.model.predict_proba(
            self.vectorizer.transform([_key(protocol, t) for t in texts])
        )
        out = []
        for row in probs:
            i = int(np.argmax(row))
            technique, confidence = str(self.model.classes_[i]), float(row[i])
            if technique == NONE or confidence < self.threshold:
                out.append(Pred())
            else:
                out.append(Pred(technique, confidence, self.name))
        return out


Embed = Callable[[list[str]], np.ndarray]  # texts -> unit-length row vectors


def tfidf_embedder(corpus: list[str], ngram: tuple[int, int] = (2, 5)) -> Embed:
    """A non-neural embedding: TF-IDF character n-grams fitted on the index's own texts."""
    vectorizer = TfidfVectorizer(
        analyzer="char_wb", ngram_range=ngram, sublinear_tf=True, lowercase=False
    ).fit(corpus)

    def embed(texts: list[str]) -> np.ndarray:
        return vectorizer.transform(texts).toarray().astype(np.float32)  # rows are l2-normalised

    return embed


@dataclass
class Entry:
    key: str
    technique: str
    origin: str  # "train", "attack" or "atomic"


# Similarities are compared to this many decimals. The same vectors multiplied on two machines
# differ in the last bits, and the index holds a few commands under more than one technique,
# so without this an exact tie was settled by rounding noise: differently on a Mac and on
# Linux, on the CPU and on the GPU (found 15 November 2026: 2 of 144 held-out texts).
SIMILARITY_DECIMALS = 6
# Between entries equally near, the lab's own procedures come before the public corpus and
# that before a technique's description; then technique ID, then text. A fixed rule, written
# before looking at which answer it favours.
ORIGIN_ORDER = {"train": 0, "atomic": 1, "attack": 2}


def _tie_rank(entries: list[Entry]) -> np.ndarray:
    """For each entry, its place in the fixed order that settles ties."""
    order = sorted(
        range(len(entries)),
        key=lambda i: (
            ORIGIN_ORDER.get(entries[i].origin, 9),
            entries[i].technique,
            entries[i].key,
        ),
    )
    rank = np.empty(len(entries), dtype=np.int64)
    rank[order] = np.arange(len(entries))
    return rank


class Retrieval:
    """Nearest neighbours by cosine similarity. The answer is the technique with the largest
    summed similarity among the ``k`` nearest entries; its confidence is the top similarity.
    Ties are settled by a fixed rule (``ORIGIN_ORDER``), never by floating-point noise, so the
    same index gives the same answer on every machine."""

    def __init__(
        self,
        make_embed: Callable[[list[str]], Embed] | None = None,
        *,
        label: str = "tfidf",
        k: int = 1,
        threshold: float = 0.0,
        attack_text: dict[str, str] | None = None,
        extra: list[tuple[str, str]] | None = None,
    ) -> None:
        self.make_embed = make_embed or tfidf_embedder
        self.k, self.threshold = k, threshold
        self.attack_text = attack_text or {}
        self.extra = extra or []  # (text, technique) from Atomic Red Team, SSH
        self.name = (
            f"retrieval-{label}-k{k}"
            + ("+attack" if self.attack_text else "")
            + ("+atomic" if self.extra else "")
        )
        self.entries: list[Entry] = []
        self.matrix: np.ndarray | None = None
        self.embed: Embed | None = None
        self.rank: np.ndarray | None = None  # the tie order of the entries

    def fit(self, steps: list[Step], unit: str = "line") -> Retrieval:
        self.entries = [
            Entry(key, technique, "train")
            for key, technique in training_pairs(steps, unit)
            if technique != NONE  # a negative is nothing to retrieve
        ]
        # A technique's own description, so a technique with no training procedure can still
        # be named. Index hygiene (section 5, item 5): only the training split and public
        # ATT&CK text ever enter the index.
        self.entries += [Entry(text, t, "attack") for t, text in sorted(self.attack_text.items())]
        known = {(e.key, e.technique) for e in self.entries}
        for text, technique in self.extra:
            key = _key("ssh", text)
            if (key, technique) not in known:
                known.add((key, technique))
                self.entries.append(Entry(key, technique, "atomic"))
        if not self.entries:
            return self
        self.embed = self.make_embed([e.key for e in self.entries])
        self.matrix = self.embed([e.key for e in self.entries])
        self.rank = _tie_rank(self.entries)
        return self

    def to_saved(self) -> dict:
        """The fitted index as plain data. The vectors are not saved: they are recomputed
        from the entries when the model is loaded, by the embedding function it is given."""
        return {
            "kind": "retrieval",
            "name": self.name,
            "k": self.k,
            "threshold": self.threshold,
            "entries": [[e.key, e.technique, e.origin] for e in self.entries],
        }

    @classmethod
    def from_saved(cls, saved: dict, make_embed: Callable[[list[str]], Embed]) -> Retrieval:
        if saved.get("kind") != "retrieval":
            raise ValueError(f"not a saved retrieval model: {saved.get('kind')!r}")
        model = cls(make_embed, k=int(saved["k"]), threshold=float(saved["threshold"]))
        model.name = str(saved["name"])
        model.entries = [Entry(str(k), str(t), str(o)) for k, t, o in saved["entries"]]
        if model.entries:
            keys = [e.key for e in model.entries]
            model.embed = make_embed(keys)
            model.matrix = model.embed(keys)
            model.rank = _tie_rank(model.entries)
        return model

    def predict(self, protocol: str, texts: list[str]) -> list[Pred]:
        if self.matrix is None or self.embed is None or not texts:
            return [Pred() for _ in texts]
        sims = np.round(
            self.embed([_key(protocol, t) for t in texts]) @ self.matrix.T, SIMILARITY_DECIMALS
        )
        out = []
        for row in sims:
            # nearest first; among the equally near, the fixed tie order
            top = np.lexsort((self.rank, -row))[: self.k]
            votes: dict[str, float] = {}
            for j in top:
                votes[self.entries[j].technique] = votes.get(
                    self.entries[j].technique, 0.0
                ) + float(row[j])
            technique = max(sorted(votes), key=lambda t: votes[t])
            confidence = float(row[top[0]])
            if confidence < self.threshold:
                out.append(Pred())
            else:
                nearest = self.entries[int(top[0])]
                out.append(Pred(technique, confidence, f"{self.name}:{nearest.origin}"))
        return out


class Cascade:
    """Ask each model in turn; the first that answers at or above its threshold wins."""

    def __init__(self, layers: list[tuple[object, float]]) -> None:
        self.layers = layers
        self.name = " > ".join(m.name for m, _ in layers)

    def fit(self, steps: list[Step], unit: str = "line") -> Cascade:
        for model, _ in self.layers:
            model.fit(steps, unit)
        return self

    def predict(self, protocol: str, texts: list[str]) -> list[Pred]:
        out = [Pred() for _ in texts]
        open_ = list(range(len(texts)))
        for model, threshold in self.layers:
            if not open_:
                break
            answers = model.predict(protocol, [texts[i] for i in open_])
            still = []
            for i, p in zip(open_, answers, strict=True):
                if p.technique and p.confidence >= threshold:
                    out[i] = p
                else:
                    still.append(i)
            open_ = still
        return out


def tune_threshold(
    score_at: Callable[[float], float], grid: list[float] | None = None
) -> tuple[float, float]:
    """The threshold on the grid with the best score (ties go to the lower threshold, which
    abstains less). ``score_at`` must score on dev: this is model selection."""
    grid = grid or [round(x, 2) for x in np.arange(0.0, 0.96, 0.05)]
    scored = [(score_at(t), -t) for t in grid]
    best, neg_t = max(scored)
    return -neg_t, best
