"""Timing profiles: how a simulated actor paces its input (spec section 3).

Each actor draws its own parameters from its profile's ranges, so two bots are not identical
and the classifier's test actors use draws its training actors never had (spec section 5,
check 6). These are generators, not recordings: a model that scores well on them has learned
to recognise the generator (spec section 8).
"""

from __future__ import annotations

import math
import random
from collections.abc import Iterator
from dataclasses import dataclass

BACKSPACE = "\x7f"
NEIGHBOURS = "asdfghjklqwertyuiopzxcvbnm"


@dataclass
class Timing:
    name: str
    rng: random.Random
    scale: float  # 1.0 for datasets; tests shorten every pause
    keys: bool  # type key by key, or send whole lines
    gap_median: float  # seconds between receiving output and starting the next input
    gap_sigma: float  # log-normal spread of that gap
    key_median: float = 0.0  # seconds between keys
    key_sigma: float = 0.0
    typo_rate: float = 0.0
    read_rate: float = 0.0  # extra seconds per character of the previous output

    def describe(self) -> str:
        return self.name if self.scale == 1.0 else f"{self.name}@{self.scale:g}"

    def _lognormal(self, median: float, sigma: float) -> float:
        if median <= 0:
            return 0.0
        return self.rng.lognormvariate(math.log(median), sigma) * self.scale

    def gap(self, previous_output_len: int = 0) -> float:
        """Pause before the next input: think time, plus time to read what came back."""
        reading = min(previous_output_len, 2000) * self.read_rate * self.scale
        return self._lognormal(self.gap_median, self.gap_sigma) + reading

    def strokes(self, line: str) -> Iterator[tuple[str, float]]:
        """(text to send, pause before it). Whole-line senders yield once."""
        if not self.keys:
            yield line, 0.0
            return
        for ch in line:
            if self.typo_rate and ch.isalpha() and self.rng.random() < self.typo_rate:
                yield self.rng.choice(NEIGHBOURS), self._lognormal(self.key_median, self.key_sigma)
                yield BACKSPACE, self._lognormal(self.key_median * 2.5, self.key_sigma)
            yield ch, self._lognormal(self.key_median, self.key_sigma)


def make(name: str, rng: random.Random, scale: float = 1.0) -> Timing:
    u = rng.uniform
    if name == "scan":
        return Timing(name, rng, scale, keys=False, gap_median=u(0.01, 0.1), gap_sigma=0.1)
    if name == "bot-fast":
        return Timing(name, rng, scale, keys=False, gap_median=u(0.05, 0.4), gap_sigma=u(0.02, 0.1))
    if name == "bot-slow":
        return Timing(name, rng, scale, keys=False, gap_median=u(1.0, 3.0), gap_sigma=u(0.05, 0.2))
    if name == "human":
        return Timing(
            name,
            rng,
            scale,
            keys=True,
            gap_median=u(2.0, 6.0),
            gap_sigma=u(0.5, 0.9),
            key_median=u(0.11, 0.24),
            key_sigma=u(0.35, 0.6),
            typo_rate=u(0.01, 0.05),
            read_rate=u(0.004, 0.012),
        )
    raise ValueError(f"unknown timing profile {name!r}")
