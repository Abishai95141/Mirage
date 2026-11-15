"""Tagger model worker (phase 2 spec, 2.4): the learned layer, live.

It reads gated inputs from ClickHouse, asks the model the experiment chose for a technique,
and writes one row per labelled input to ``mirage.labels``. The pipeline's tagger worker turns
those labels into session and actor alerts on its next sweep, as it does for any label.

**One label per input, as scored.** An SSH line can run several gated commands (a pipeline, a
list). The model was scored on the line: the most confident answer among its commands. So the
worker groups a line with the gate decisions that follow it, up to the session's next line
(the lab's join uses the same rule), and writes the group's one label on the line's first
gate decision. An HTTP request, a Redis command or a MySQL query is one decision and one
group, and its label sits on that decision. An input's label has one place, so reading the
input again replaces its row and cannot leave a second one behind.

A line's commands are gated as they run: usually within milliseconds, sometimes seconds
apart. A group is labelled once it is *closed*: a later line exists in its session, or nothing
has been added for ``SETTLE_S``. If a command still arrives after that, the group is read
again and its label rewritten, or withdrawn (a newer row with an empty technique) when the
model no longer answers.

The worker keeps no state that matters. It polls by ingest time, so after a stop it carries on
from ``TAGGER_LOOKBACK_S`` ago and writes the same labels again under a newer version, which
replaces the old rows. Text never leaves the process: logs carry counts.
"""

from __future__ import annotations

import logging
import os
import re
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from mirage_intel.dataset import ClickHouse, QueryError, _env_file
from mirage_intel.tagserve import MODEL_DIR, Served, load

log = logging.getLogger("mirage.tagger-model")
HEALTH = Path("/tmp/mirage-tagger-model.alive")  # noqa: S108 container-private
SETTLE_S = 5.0
LIMIT = 500  # sessions read per round: a round stays short, so progress shows and health holds
STAMP = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(\.\d{1,6})?$")
SESSION = re.compile(r"^[A-Za-z0-9_.:@/+=-]{1,128}$")

# What this worker reads: gate decisions the decoys logged, and the SSH lines they belong to.
_GATED = (
    "source != 'policy' AND (class = 'policy_decision' OR (source = 'cowrie' "
    "AND class = 'process_activity' AND action = 'command' AND outcome = 'unknown'))"
)
CHANGED_SQL = (
    "SELECT session_id, toString(max(ingest_ts)) AS changed FROM mirage.events "  # noqa: S608
    "WHERE ingest_ts >= parseDateTime64BestEffort('{after}', 6, 'UTC') AND session_id != '' "
    f"AND {_GATED} GROUP BY session_id ORDER BY changed LIMIT {LIMIT}"
)
EVENTS_SQL = (
    "SELECT event_id, session_id, source, protocol, class, toString(ts) AS ts, "  # noqa: S608
    "dateDiff('millisecond', ingest_ts, now64(6)) AS age_ms, "
    "JSONExtractString(payload, 'command') AS command, "
    "JSONExtractString(payload, 'input') AS input "
    f"FROM mirage.events FINAL WHERE session_id IN ({{ids}}) AND {_GATED} "
    "ORDER BY session_id, ts, event_id"
)
NOW_SQL = "SELECT toString(now64(6, 'UTC') - INTERVAL {seconds} SECOND) AS t"


@dataclass
class Group:
    """One input: the event it is known by, and the gated commands it ran."""

    session_id: str
    protocol: str
    anchor: dict[str, Any]  # the SSH line, or the one decision of an input that has no line
    pieces: list[dict[str, Any]] = field(default_factory=list)  # a line's gate decisions
    closed: bool = False

    @property
    def key(self) -> str:
        """What the input is remembered by: fixed from the moment its line is seen."""
        return str(self.anchor["event_id"])

    @property
    def place(self) -> dict[str, Any]:
        """The event the input's label is written on: its first gate decision, which is where
        everything downstream looks for the label of a gated input (the reward joins on it,
        the Session page shows it beside the command), or the line itself while it has none.
        A line's first decision never changes once it exists, so the place moves at most
        once, from the line to that decision."""
        return self.pieces[0] if self.pieces else self.anchor

    @property
    def signature(self) -> tuple[int, str]:
        """Changes whenever the group gains a command, so a group that grew is read again."""
        return (len(self.pieces), str(self.pieces[-1]["event_id"]) if self.pieces else "")

    def texts(self, unit: str) -> list[str]:
        """What the model is shown, as ``tagscore.Step.texts`` gives it for a scored step."""
        if unit == "line" or not self.pieces:
            return [_text(self.anchor)]
        return [_text(ev) for ev in self.pieces]


def _text(ev: dict[str, Any]) -> str:
    return str(ev.get("command") or ev.get("input") or "")


def _is_decision(ev: dict[str, Any]) -> bool:
    return ev["class"] == "policy_decision"


def groups(events: list[dict[str, Any]], settle_ms: float = SETTLE_S * 1000) -> list[Group]:
    """Group the gated events of one or more sessions. Within a session they are taken in
    time order, a line before a decision logged at the same instant (the lab's join counts a
    decision at the line's own time as that line's)."""
    ordered = sorted(
        events, key=lambda e: (e["session_id"], e["ts"], _is_decision(e), e["event_id"])
    )
    out: list[Group] = []
    line: Group | None = None  # the SSH line being filled
    newest_ms = float("inf")

    def close_line(by_next_line: bool) -> None:
        nonlocal line
        if line is not None:
            line.closed = by_next_line or newest_ms >= settle_ms
            out.append(line)
            line = None

    current = None
    for ev in ordered:
        if ev["session_id"] != current:
            close_line(False)
            current, newest_ms = ev["session_id"], float("inf")
        age = float(ev.get("age_ms") or 0)
        if not _is_decision(ev):  # an SSH line
            close_line(True)
            line = Group(ev["session_id"], ev.get("protocol") or "ssh", ev)
            newest_ms = age
        elif ev.get("source") == "cowrie" and line is not None:
            line.pieces.append(ev)
            newest_ms = min(newest_ms, age)
        else:
            # one gated input on its own: HTTP, Redis, MySQL, or an SSH command with no line
            out.append(Group(ev["session_id"], ev.get("protocol") or "", ev, closed=True))
    close_line(False)
    return out


def _row(served: Served, g: Group, event_id: str, version: int, pred: Any) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "version": version,
        "session_id": g.session_id,
        "protocol": g.protocol,
        "kind": "input",
        "technique": pred.technique if pred else "",
        "tactic": served.tactic_of.get(pred.technique, "") if pred else "",
        "confidence": round(float(pred.confidence), 4) if pred else 0.0,
        # the evidence: which index the nearest neighbour came from
        "rule_id": pred.evidence if pred else "withdrawn",
        "model_version": served.version,
        "attack_version": served.attack_version,
        "ts": g.place["ts"],
    }


def answers(served: Served, todo: list[Group]) -> list[tuple[int, Any] | None]:
    """Each group's answer: the most confident one among its texts, a tie going to the later
    text (``Served.tag``, which is ``tagscore.predict_steps`` for one step). The model is asked
    once per protocol for every text of every group together. Asked one input at a time, a
    worker reading back over a run made thousands of one-line calls and kept nine CPU cores
    busy beside the policy service (15 November 2026)."""
    flat: list[tuple[int, int, str]] = []
    by_protocol: dict[str, list[int]] = {}
    for gi, g in enumerate(todo):
        for ti, text in enumerate(g.texts(served.unit)):
            if text:
                by_protocol.setdefault(g.protocol, []).append(len(flat))
                flat.append((gi, ti, text))
    best: list[tuple[int, Any] | None] = [None] * len(todo)
    for protocol, idx in by_protocol.items():
        preds = served.model.predict(protocol, [flat[j][2] for j in idx])
        for j, pred in zip(idx, preds, strict=True):
            gi, ti, _ = flat[j]
            held = best[gi]
            if pred.technique and (held is None or pred.confidence >= held[1].confidence):
                best[gi] = (ti, pred)
    return best


def label_rows(
    served: Served, todo: list[Group], version: int, previous: dict[str, str] | None = None
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Rows for ``mirage.labels`` and, per group, the event that now carries its label
    (``""`` for none). An input has one label in one place. ``previous`` says where each
    group's label was written the last time it was read: if the model no longer answers, or
    the place has moved, the old row is withdrawn with a newer row whose technique is empty,
    which every reader of the table leaves out."""
    previous = previous or {}
    rows: list[dict[str, Any]] = []
    placed: dict[str, str] = {}
    for g, answer in zip(todo, answers(served, todo), strict=True):
        target = str(g.place["event_id"])
        before = previous.get(g.key, "")
        if before and (answer is None or before != target):
            rows.append(_row(served, g, before, version, None))
        if answer is not None:
            rows.append(_row(served, g, target, version, answer[1]))
        placed[g.key] = target if answer is not None else ""
    return rows, placed


@dataclass
class State:
    after: str  # ingest time read from; moves forward as sessions are settled
    handled: dict[str, str] = field(default_factory=dict)  # session -> the change dealt with
    # group key -> (what it was made of when it was read, the event its label is on or "")
    done: dict[str, tuple[tuple[int, str], str]] = field(default_factory=dict)


def step(ch: ClickHouse, served: Served, state: State) -> tuple[int, int]:
    """One round: (groups read, label rows written)."""
    if not STAMP.match(state.after):
        raise ValueError(f"not a timestamp: {state.after!r}")
    changed = ch.rows(CHANGED_SQL.format(after=state.after))
    fresh = [r for r in changed if state.handled.get(r["session_id"]) != r["changed"]]
    ids = [r["session_id"] for r in fresh if SESSION.match(r["session_id"])]
    if not ids:
        if changed:
            state.after = max(r["changed"] for r in changed)
        return 0, 0
    listed = ", ".join(f"'{i}'" for i in ids)
    found = groups(ch.rows(EVENTS_SQL.format(ids=listed)))
    # A closed group is read once, and again only if it has gained a command since: a line's
    # commands are gated as they run, which can be seconds apart.
    todo = [g for g in found if g.closed and state.done.get(g.key, (None,))[0] != g.signature]
    previous = {g.key: state.done[g.key][1] for g in todo if g.key in state.done}
    rows, placed = label_rows(served, todo, time.time_ns() // 1000, previous)
    ch.insert("mirage.labels", rows)
    for g in todo:
        state.done[g.key] = (g.signature, placed[g.key])
    # A session with a group still open is read again next round; the rest are settled.
    waiting = {g.session_id for g in found if not g.closed}
    for r in fresh:
        if r["session_id"] not in waiting:
            state.handled[r["session_id"]] = r["changed"]
    # Read on from the earliest session still waiting, or from the newest change seen. The
    # query takes changes at or after this time, and `handled` drops the ones dealt with, so
    # sessions that share a timestamp are neither lost nor read twice.
    pending = [r["changed"] for r in changed if r["session_id"] in waiting]
    state.after = min(pending) if pending else max(r["changed"] for r in changed)
    return len(todo), sum(1 for where in placed.values() if where)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    os.environ.update({k: v for k, v in _env_file().items() if k not in os.environ})
    ch = ClickHouse.from_env()
    directory = Path(os.environ.get("TAGGER_MODEL", str(MODEL_DIR)))
    interval = float(os.environ.get("POLL_S", "2"))
    lookback = int(os.environ.get("TAGGER_LOOKBACK_S", "900"))
    running = True

    def stop(*_: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    served: Served | None = None
    state: State | None = None
    while running:
        HEALTH.touch()
        if served is None:
            try:
                served = load(directory)
                log.info(
                    "tagger model %s loaded: %d index entries",
                    served.version,
                    len(served.model.entries),
                )
            except (OSError, ValueError, KeyError) as exc:
                # No model yet (`make models` writes it): wait for one rather than exit.
                log.warning("no usable tagger model in %s: %s", directory, str(exc)[:200])
                time.sleep(30)
                continue
        try:
            if state is None:
                state = State(ch.rows(NOW_SQL.format(seconds=lookback))[0]["t"])
            seen, written = step(ch, served, state)
        except (QueryError, OSError, httpx.HTTPError) as exc:
            # The store is restarting or unreachable: keep the model and the state, and retry.
            log.warning("could not tag this round: %s", str(exc)[:200])
            seen, written = 0, 0
        if seen:
            log.info("read %d inputs, labelled %d", seen, written)
        else:
            time.sleep(interval)
        if len(state.done if state else ()) > 200_000:
            state.done.clear()
            state.handled.clear()


def healthcheck() -> None:
    raise SystemExit(0 if HEALTH.exists() and time.time() - HEALTH.stat().st_mtime < 120 else 1)


if __name__ == "__main__":
    main()
