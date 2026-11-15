"""Keystroke statistics from Cowrie's TTY logs (phase 2 spec, 2.0).

A person at a keyboard and a program sending whole lines look alike in the event stream: both
produce commands with gaps between them. They differ in how the bytes arrive. Typing reaches the
decoy one key at a time, with corrections; a program's line arrives in one write. Cowrie records
every write with its direction and time in a TTY log, so this reads that log and counts: how many
input writes there were, how many carried a single byte, how many backspaces, how many long
writes (a paste, or a program), and the gaps between writes.

The format is Cowrie's own (``cowrie/core/ttylog.py``): a sequence of records, each a header
``<iLiiLL`` (op, tty, length, direction, seconds, microseconds) followed by ``length`` bytes.
The parser reads bytes it is given and nothing else; a truncated or malformed log yields the
records before the damage and is marked ``truncated``.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from itertools import pairwise

HEADER = struct.Struct("<iLiiLL")
OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC = 1, 2, 3, 4
TYPE_INPUT, TYPE_OUTPUT, TYPE_INTERACT = 1, 2, 3

MAX_LOG_BYTES = 8 * 1024 * 1024  # read at most this much of one log
PASTE_MIN_BYTES = 8  # an input write this long is a paste or a program, not a keystroke
BACKSPACES = (0x7F, 0x08)


@dataclass
class Record:
    op: int
    direction: int
    ts: float
    data: bytes


def records(blob: bytes) -> Iterator[Record]:
    """The log's records, in order. Stops at the first header or body that does not fit."""
    pos, end = 0, len(blob)
    while pos + HEADER.size <= end:
        op, _tty, length, direction, sec, usec = HEADER.unpack_from(blob, pos)
        pos += HEADER.size
        if op not in (OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC) or length < 0 or pos + length > end:
            return
        yield Record(op, direction, sec + usec / 1_000_000, blob[pos : pos + length])
        pos += length


def _complete(blob: bytes) -> bool:
    """True when the records account for every byte of the log."""
    pos, end = 0, len(blob)
    while pos + HEADER.size <= end:
        op, _tty, length, _direction, _sec, _usec = HEADER.unpack_from(blob, pos)
        pos += HEADER.size
        if op not in (OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC) or length < 0 or pos + length > end:
            return False
        pos += length
    return pos == end


def _quantile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    index = q * (len(sorted_values) - 1)
    low = int(index)
    high = min(low + 1, len(sorted_values) - 1)
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * (index - low)


@dataclass
class Stats:
    input_chunks: int = 0  # writes from the client
    input_bytes: int = 0
    single_byte_chunks: int = 0  # writes carrying exactly one byte: a keystroke
    backspaces: int = 0
    paste_bursts: int = 0  # writes of PASTE_MIN_BYTES or more
    lines: int = 0  # carriage returns or newlines in the input
    key_gap_p10_s: float = 0.0  # gaps between consecutive input writes
    key_gap_p50_s: float = 0.0
    key_gap_p90_s: float = 0.0
    duration_s: float = 0.0
    truncated: int = 0

    def row(self) -> dict:
        return asdict(self)


def stats(blob: bytes) -> Stats:
    """Count what a TTY log shows about how its input was produced."""
    limited = blob[:MAX_LOG_BYTES]
    out = Stats(truncated=int(len(blob) > MAX_LOG_BYTES or not _complete(limited)))
    stamps: list[float] = []
    first = last = None
    for rec in records(limited):
        first = rec.ts if first is None else first
        last = rec.ts
        if rec.op != OP_WRITE or rec.direction != TYPE_INPUT or not rec.data:
            continue
        out.input_chunks += 1
        out.input_bytes += len(rec.data)
        out.single_byte_chunks += len(rec.data) == 1
        out.paste_bursts += len(rec.data) >= PASTE_MIN_BYTES
        out.backspaces += sum(rec.data.count(bytes([b])) for b in BACKSPACES)
        out.lines += rec.data.count(b"\r") + rec.data.count(b"\n")
        stamps.append(rec.ts)
    gaps = sorted(max(b - a, 0.0) for a, b in pairwise(stamps))
    out.key_gap_p10_s = round(_quantile(gaps, 0.10), 6)
    out.key_gap_p50_s = round(_quantile(gaps, 0.50), 6)
    out.key_gap_p90_s = round(_quantile(gaps, 0.90), 6)
    if first is not None and last is not None:
        out.duration_s = round(max(last - first, 0.0), 6)
    return out
