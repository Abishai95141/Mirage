"""Embedding functions for the tagger's retrieval layer (phase 2 spec, 2.4).

Two kinds, with one interface (texts in, one unit-length row per text out):

- the real model, through sentence-transformers. It needs the ``research`` dependency group
  and the weights, and is what the experiments, the model's training and the live worker use;
- a **cache** of vectors the real model produced for a fixed set of texts. The frozen dataset
  carries one, so the regression job recomputes every tagger number in CI with no model, no
  download and no GPU. A text that is not in the cache is an error, never a guess: a change
  to normalisation that alters what is embedded fails loudly. ``verify`` recomputes the cache
  with the real model, which is how the cache itself is kept honest (run on the lab host).

Licences are checked when a model is fetched, and a model whose card does not state a
permissive one is refused. CmdCaliper, the one published command-line embedding model, is not
listed: its weights are gated, its card states no licence, and it was trained on Windows
command lines.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path

import numpy as np

Embed = Callable[[list[str]], np.ndarray]

EMBEDDERS = {
    "bge-small": "BAAI/bge-small-en-v1.5",
    "minilm": "sentence-transformers/all-MiniLM-L6-v2",
    "securebert2": "cisco-ai/SecureBERT2.0-biencoder",
    "shellbert": "SmartDataPolito/SecureShellBert",
}
PERMISSIVE = {"mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "bsd"}


def device() -> str:
    """Where the embedding model runs. ``MIRAGE_EMBED_DEVICE`` says ``cpu``, ``cuda`` or
    ``auto`` (the default): the GPU when this PyTorch build can see one, the CPU otherwise.
    The default research environment has the CPU build, so there ``auto`` is the CPU; the GPU
    environment (``make gpu-env``) is what makes it the GPU. Asking for ``cuda`` where there is
    none is an error, not a silent fallback: a run should not be slower than it was told to be
    without saying so."""
    import torch

    wanted = os.environ.get("MIRAGE_EMBED_DEVICE", "auto").lower()
    if wanted not in ("auto", "cpu", "cuda"):
        raise ValueError(f"MIRAGE_EMBED_DEVICE is 'auto', 'cpu' or 'cuda', not {wanted!r}")
    if wanted == "cpu":
        return "cpu"
    if torch.cuda.is_available():
        return "cuda"
    if wanted == "cuda":
        raise RuntimeError(
            "MIRAGE_EMBED_DEVICE=cuda, but this PyTorch build sees no GPU (make gpu-env)"
        )
    return "cpu"


def neural_embedder(repo: str, check_licence: bool = True) -> Callable[[list[str]], Embed]:
    """An embedding function backed by a sentence-transformers model. The licence check asks
    the model hub, so a worker that must start offline from weights already on disk skips it:
    the check ran when those weights were fetched."""
    from sentence_transformers import SentenceTransformer

    if check_licence:
        from huggingface_hub import model_info

        card = model_info(repo).card_data
        licence = str(getattr(card, "license", "") or "").lower()
        if licence not in PERMISSIVE:
            raise RuntimeError(
                f"{repo}: licence {licence or 'not stated'!r} is not on the allowlist"
            )
    where = device()
    model = SentenceTransformer(repo, device=where)
    print(f"embedding model {repo} on {where}", flush=True)

    def make(_corpus: list[str]) -> Embed:
        def embed(texts: list[str]) -> np.ndarray:
            return model.encode(
                texts, batch_size=64, normalize_embeddings=True, show_progress_bar=False
            ).astype(np.float32)

        return embed

    return make


class Cache:
    """Vectors the real model produced, looked up by text."""

    def __init__(self, embedder: str, texts: list[str], vectors: np.ndarray) -> None:
        if len(texts) != len(vectors) or len(set(texts)) != len(texts):
            raise ValueError("an embedding cache needs one vector per distinct text")
        self.embedder = embedder
        self.texts = texts
        self.vectors = np.asarray(vectors, dtype=np.float32)
        self._index = {t: i for i, t in enumerate(texts)}

    def __call__(self, texts: list[str]) -> np.ndarray:
        missing = [t for t in texts if t not in self._index]
        if missing:
            raise LookupError(
                f"{len(missing)} text(s) are not in the frozen embedding cache. What the tagger "
                "embeds has changed (normalisation, the index, or the dataset): refreeze it"
            )
        return self.vectors[[self._index[t] for t in texts]]

    def make(self, _corpus: list[str]) -> Embed:
        return self

    def save(self, directory: Path) -> None:
        """Two files: the vectors as a plain array and the texts with the array's hash.
        Neither is a pickle. The vectors are kept at the model's own precision: at half
        precision a few similarities sitting on the abstention threshold changed side, and
        the frozen dataset scored 0.211 where the model scored 0.212 (15 November 2026). The
        frozen numbers must be the model's numbers."""
        directory.mkdir(parents=True, exist_ok=True)
        array = directory / "embeddings.npy"
        np.save(array, self.vectors.astype(np.float32), allow_pickle=False)
        meta = {
            "embedder": self.embedder,
            "dimensions": int(self.vectors.shape[1]) if len(self.vectors) else 0,
            "sha256": hashlib.sha256(array.read_bytes()).hexdigest(),
            "texts": self.texts,
        }
        (directory / "embeddings.json").write_text(json.dumps(meta, ensure_ascii=False) + "\n")

    @classmethod
    def load(cls, directory: Path) -> Cache:
        meta = json.loads((directory / "embeddings.json").read_text())
        array = directory / "embeddings.npy"
        if hashlib.sha256(array.read_bytes()).hexdigest() != meta["sha256"]:
            raise ValueError("embeddings.npy does not match the hash recorded beside it")
        vectors = np.load(array, allow_pickle=False).astype(np.float32)
        return cls(meta["embedder"], meta["texts"], vectors)

    @classmethod
    def build(cls, embedder: str, texts: list[str], embed: Embed) -> Cache:
        distinct = sorted(set(texts))
        vectors = embed(distinct) if distinct else np.zeros((0, 0), dtype=np.float32)
        return cls(embedder, distinct, vectors)

    def verify(self, embed: Embed, tolerance: float = 1e-4) -> float:
        """The largest difference between a cached vector and the real model's, over every
        cached text. Raises when it is more than the same model on another device explains
        (CPU and GPU arithmetic differ in the last digits)."""
        if not self.texts:
            return 0.0
        worst = float(np.abs(embed(self.texts) - self.vectors).max())
        if worst > tolerance:
            raise ValueError(
                f"the embedding cache differs from the model by {worst:.4f}: a different model "
                "or revision produced it"
            )
        return worst
