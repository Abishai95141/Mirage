"""The fidelity check (phase 3 spec, section 5): does a candidate answer to a command have the
shape of what a real Debian 12 host printed for the same command?

One tool, used three times: on render-library entries, on the emulator, and on a sample of
live answers. It compares a candidate with the reference's output:

1. the exit codes are equal;
2. the same streams are used (stdout, stderr, both or neither);
3. after masking the fields that vary, the outputs have the same shape: for ``key: value``
   output the same keys in the same order, for a table the same header and column counts,
   for an error the same text, for free text the same line count within a tolerance;
4. the facts the caller fixes agree: where the reference shows its own value of a fact (its
   host name, its CPU), the candidate shows the profile's or the hardware class's.

It compares structure, not text. It can say an answer has the wrong shape; it cannot say a
well-shaped answer is true. Rule 4 covers the facts we know and nothing covers the rest, which
is why a person reviews every library entry.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

# The mask. The split's content check (eval/split.py) normalises addresses, hex strings and
# numbers this way; dates and sizes are added here. Order matters: the specific forms go
# first, so that a date is not left as a row of masked numbers.
_MONTH = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
_DAY = r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"
_MASKS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?"
        ),
        "<date>",
    ),
    (
        re.compile(
            rf"\b(?:{_DAY},? +)?{_MONTH} +\d{{1,2}}(?:,? +\d{{4}})?(?: +\d{{1,2}}:\d{{2}}(?::\d{{2}})?)?(?: +[A-Z]{{2,5}})?(?: +\d{{4}})?"
        ),
        "<date>",
    ),
    (re.compile(rf"\b{_DAY} +\d{{1,2}} +{_MONTH} +\d{{4}}"), "<date>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}\b"), "<date>"),
    # Hardware and network addresses before the time of day: both are groups joined by
    # colons. An IPv6 address is told from a time by having four groups or a "::".
    (re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.I), "<mac>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"), "<ip>"),
    (
        re.compile(
            r"(?<![0-9a-z:])(?:[0-9a-f]{1,4}:){0,6}:(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}(?:/\d{1,3})?\b",
            re.I,
        ),
        "<ip>",
    ),
    (re.compile(r"\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}(?:/\d{1,3})?\b", re.I), "<ip>"),
    (re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?(?:[.,]\d+)?\b"), "<time>"),
    (
        re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),
        "<hex>",
    ),
    (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<hex>"),
    (re.compile(r"\b(?=[0-9a-f]*[a-f])(?=[0-9a-f]*\d)[0-9a-f]{6,}\b"), "<hex>"),
    (re.compile(r"\b\d+(?:[.,]\d+)?\s?(?:[KMGTP]i?B?|kB|bytes|B)\b"), "<size>"),
    (re.compile(r"\b\d+(?:[.,]\d+)?%"), "<n>%"),
    (re.compile(r"\b\d+(?:[.,]\d+)?\b"), "<n>"),
)
_SPACE = re.compile(r"[ \t]+")
# A ``key: value`` or ``KEY=value`` line: a short key that starts with a letter.
_KEY = re.compile(r"^\s*([A-Za-z_][^:=\n]{0,47}?)\s*([:=])(?:\s|$|(?<==)\S)")
_HEADER_WORD = re.compile(r"^[A-Za-z%#/_][A-Za-z0-9%#/_.()-]*$")
TOLERANCE = 0.2  # free text: line counts may differ by a fifth, and always by one


@dataclass(frozen=True)
class Observed:
    """What a command printed and returned."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0

    def streams(self) -> str:
        used = [
            name
            for name, text in (("stdout", self.stdout), ("stderr", self.stderr))
            if text.strip()
        ]
        return "+".join(used) or "neither"


@dataclass(frozen=True)
class Fact:
    """A fact with a known value on both sides: wherever the reference shows ``reference``,
    the candidate must show ``expected`` (the profile's or the hardware class's value)."""

    name: str
    reference: str
    expected: str


@dataclass
class Verdict:
    ok: bool
    shape: str  # empty | error | keyvalue | table | text
    problems: list[str] = field(default_factory=list)


def mask(text: str) -> str:
    """``text`` with the fields that vary between hosts and moments replaced by placeholders,
    and runs of blanks made one."""
    for pattern, placeholder in _MASKS:
        text = pattern.sub(placeholder, text)
    return "\n".join(_SPACE.sub(" ", line).rstrip() for line in text.splitlines())


def _lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip()]


def _keys(text: str) -> tuple[list[tuple[str, ...]], str] | None:
    """For ``key: value`` output: the distinct blocks' key sequences, in order of first
    appearance, and the delimiter. A block is a run of lines between blank lines, so a file
    that repeats one block per processor has one signature however many processors there
    are. None when the output is not of that kind."""
    lines = _lines(text)
    found = [_KEY.match(line) for line in lines]
    hits = [m for m in found if m]
    if len(lines) < 2 or len(hits) < 0.7 * len(lines):
        return None
    delims = [m.group(2) for m in hits]
    delim = max(set(delims), key=delims.count)
    blocks: list[tuple[str, ...]] = []
    for chunk in re.split(r"\n\s*\n", text.strip()):
        keys = tuple(
            _SPACE.sub(" ", m.group(1).strip())
            for m in (_KEY.match(line) for line in _lines(chunk))
            if m and m.group(2) == delim
        )
        if keys and keys not in blocks:
            blocks.append(keys)
    return blocks, delim


def _table(text: str) -> tuple[list[str], set[int]] | None:
    """For a table: the header's words and the set of field counts its rows have. None when
    the output is not a table."""
    lines = _lines(text)
    if len(lines) < 2 or ":" in lines[0] or "=" in lines[0]:
        return None
    header = lines[0].split()
    if len(header) < 2 or not all(_HEADER_WORD.match(word) for word in header):
        return None
    counts = {len(line.split()) for line in lines[1:]}
    if min(counts) < 2 and len(counts) == 1:
        return None
    return header, counts


def _shape(reference: Observed) -> str:
    if reference.streams() == "neither":
        return "empty"
    if not reference.stdout.strip():
        # A message on stderr alone, whatever the exit code (`nginx -v` exits 0): the text
        # itself is the answer, and is compared after masking.
        return "error"
    if _table(reference.stdout):
        return "table"
    if _keys(reference.stdout):
        return "keyvalue"
    return "text"


def check(candidate: Observed, reference: Observed, facts: Sequence[Fact] = ()) -> Verdict:
    """Compare ``candidate`` with the ``reference`` host's output for the same command."""
    shape = _shape(reference)
    problems: list[str] = []
    if candidate.exit_code != reference.exit_code:
        problems.append(
            f"exit code {candidate.exit_code}, the reference's is {reference.exit_code}"
        )
    if candidate.streams() != reference.streams():
        problems.append(
            f"output on {candidate.streams()}, the reference's is on {reference.streams()}"
        )

    if shape == "error":
        if mask(candidate.stderr).strip() != mask(reference.stderr).strip():
            problems.append("the error text differs from the reference's")
    elif shape == "keyvalue":
        want, have = _keys(reference.stdout), _keys(candidate.stdout)
        if have is None:
            problems.append("not key and value lines, as the reference's output is")
        elif have[1] != want[1]:
            problems.append(f"keys end in {have[1]!r}, the reference's in {want[1]!r}")
        elif have[0] != want[0]:
            problems.append(_key_difference(want[0], have[0]))
    elif shape == "table":
        want_t, have_t = _table(reference.stdout), _table(candidate.stdout)
        if have_t is None:
            problems.append("not a table, as the reference's output is")
        elif have_t[0] != want_t[0]:
            problems.append(
                f"header {' '.join(have_t[0])!r}, the reference's is {' '.join(want_t[0])!r}"
            )
        else:
            # A table whose last column is free text (a command line) has rows longer than
            # its header. Any length from the header's own up is then a row: the free text
            # may be one word, whether or not the reference happens to have such a row (a
            # kernel thread in `ps`, which a container does not show).
            loose = max(want_t[1]) > len(want_t[0])
            odd = sorted(
                n for n in have_t[1] if n not in want_t[1] and not (loose and n >= len(want_t[0]))
            )
            if odd:
                problems.append(
                    f"rows of {odd} fields; the reference's rows have {sorted(want_t[1])}"
                )
    elif shape == "text":
        want_n, have_n = len(_lines(reference.stdout)), len(_lines(candidate.stdout))
        if abs(want_n - have_n) > max(1, round(TOLERANCE * want_n)):
            problems.append(f"{have_n} lines, the reference has {want_n}")
        if want_n == 1 and have_n == 1:
            want_w, have_w = len(reference.stdout.split()), len(candidate.stdout.split())
            if abs(want_w - have_w) > max(1, round(TOLERANCE * want_w)):
                problems.append(f"{have_w} words on its line, the reference has {want_w}")

    both = candidate.stdout + "\n" + candidate.stderr
    ref_both = reference.stdout + "\n" + reference.stderr
    for fact in facts:
        if not fact.reference or fact.reference not in ref_both:
            continue  # the reference does not show this fact for this command
        if fact.expected not in both:
            problems.append(
                f"{fact.name}: {fact.expected!r} is missing where the reference shows its own"
            )
        elif fact.reference != fact.expected and _shows(both, fact.reference, fact.expected):
            problems.append(
                f"{fact.name}: the reference host's own value {fact.reference!r} is still there"
            )
    return Verdict(not problems, shape, problems)


def _shows(text: str, value: str, expected: str) -> bool:
    """``value`` appears in ``text`` other than as a part of ``expected``."""
    return value in text.replace(expected, "")


def _key_difference(want: list[tuple[str, ...]], have: list[tuple[str, ...]]) -> str:
    wanted = [k for block in want for k in block]
    had = [k for block in have for k in block]
    missing = [k for k in wanted if k not in had]
    extra = [k for k in had if k not in wanted]
    if missing or extra:
        parts = []
        if missing:
            parts.append(f"missing keys {missing[:6]}")
        if extra:
            parts.append(f"keys the reference lacks {extra[:6]}")
        return "; ".join(parts)
    return "the same keys in a different order or grouping"
