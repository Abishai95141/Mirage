"""The output filter (docs/06-phase-3-spec.md, 3.2b): what a generated line may not contain.

Every line of an answer passes here before the attacker can see it. A line that fails ends
the answer: an abort is safe, and the decoy falls back to what the emulator would have
printed. The rule that fired is logged, never the line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_LINE_BYTES = 4096
# Words that would name this project, the lab or the emulator to whoever reads the answer:
# the lab lint's list for inputs (mirage_lab.models.MARKER_WORDS), held to outputs too.
MARKER_WORDS = ("mirage", "atomic", "scenario", "selftest", "gate1", "honeypot", "cowrie")
# How a model talks when it stops being the machine.
OUT_OF_CHARACTER = (
    "as an ai",
    "language model",
    "i cannot",
    "i can't",
    "i'm sorry",
    "i am sorry",
    "i apologize",
    "as a helpful",
    "simulat",
    "roleplay",
    "role-play",
    "fictional",
    "```",
)
# Tab and newline are the only control characters a line of terminal output may carry here:
# an escape sequence from a model is a way to rewrite what the attacker's terminal shows.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_WORD = re.compile(r"[a-z0-9_']+")
PROMPT_WINDOW = 6  # this many consecutive words of the prompt in a line is the prompt leaking


@dataclass(frozen=True)
class Hit:
    rule: str  # control, length, marker, character, prompt


class Filter:
    """Built once for a prompt: the fixed text the model was given, which no line of an
    answer may repeat a run of."""

    def __init__(self, prompt_text: str = "", allowed: tuple[str, ...] = ()) -> None:
        words = _WORD.findall(prompt_text.lower())
        self._runs = {
            " ".join(words[i : i + PROMPT_WINDOW]) for i in range(len(words) - PROMPT_WINDOW + 1)
        }
        # Facts of the host are in the prompt and belong in answers: a run made only of the
        # host's own values (its name, its kernel string) is not the prompt leaking.
        self._allowed = tuple(" ".join(_WORD.findall(a.lower())) for a in allowed if a)

    def check(self, line: str) -> Hit | None:
        """What is wrong with one line of output, or None."""
        if len(line.encode("utf8", errors="replace")) > MAX_LINE_BYTES:
            return Hit("length")
        if _CONTROL.search(line):
            return Hit("control")
        lowered = line.lower()
        if any(word in lowered for word in MARKER_WORDS):
            return Hit("marker")
        if any(phrase in lowered for phrase in OUT_OF_CHARACTER):
            return Hit("character")
        if self._runs:
            words = _WORD.findall(lowered)
            for i in range(len(words) - PROMPT_WINDOW + 1):
                run = " ".join(words[i : i + PROMPT_WINDOW])
                if run in self._runs and not any(run in fact for fact in self._allowed):
                    return Hit("prompt")
        return None

    def check_text(self, text: str) -> Hit | None:
        for line in text.split("\n"):
            hit = self.check(line)
            if hit:
                return hit
        return None
