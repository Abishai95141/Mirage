"""Classifier worker (phase 2 spec, 2.3 and 2.7): a predicted actor class for every session.

Until now the classifier existed only offline, so no dashboard, alert or demo could show a
class that was not copied from the lab's own labels. This worker closes that: it reads the
sessions whose summary has changed since they were last classified, computes their features
with the same query the training export uses (``dataset.feature_query``), and writes
``mirage.actor_class``. A session is classified again whenever it grows, so a long session's
class follows the evidence.

It polls ClickHouse; it needs no bus. It reads predictions' inputs only from pipeline tables,
never from a ``sim_*`` table. Without a model file it still applies the scanner rule, and
writes nothing for the sessions that rule does not settle: an absent class is honest, a
majority-class guess presented as a prediction is not.
"""

from __future__ import annotations

import logging
import os
import signal
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from mirage_intel.classifier import MODEL_DIR, Model
from mirage_intel.dataset import ClickHouse, QueryError, _env_file, feature_query, features_of

log = logging.getLogger("mirage.classifier")
HEALTH = Path("/tmp/mirage-classifier.alive")  # noqa: S108 container-private
BATCH = 200

# Sessions whose summary is newer than their classification (0 when never classified).
PENDING_SQL = f"""
SELECT s.session_id AS session_id
FROM (SELECT session_id, version FROM mirage.session_summary FINAL) AS s
LEFT JOIN (SELECT session_id, version FROM mirage.actor_class FINAL) AS a
    ON s.session_id = a.session_id
WHERE a.version < s.version
ORDER BY s.version
LIMIT {BATCH}
"""  # noqa: S608 - constants only


def load_model(directory: Path) -> Model | None:
    try:
        model = Model.load(directory)
    except (OSError, ValueError, KeyError) as exc:
        log.warning(
            "no usable model in %s (%s): only the scanner rule will be applied", directory, exc
        )
        return None
    log.info("model %s over %d features", model.version, len(model.features))
    return model


def classify(model: Model | None, feature_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rows for ``mirage.actor_class``. A session nothing can decide gets no row."""
    rule_only = Model("rule-only", [], [], majority="")
    out = []
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")
    for raw in feature_rows:
        # The rule reads the protocol; the model reads only its feature columns.
        features = {**features_of(raw), "protocol": raw.get("protocol") or ""}
        actor_class, confidence, who = (model or rule_only).decide([features])[0]
        if who == "majority" or not actor_class:
            continue
        out.append(
            {
                "session_id": raw["session_id"],
                "version": int(raw["summary_version"]),
                "actor_class": actor_class,
                "confidence": round(float(confidence), 4),
                "decided_by": who,
                "model_version": (model.version if model and who == "model" else "rule"),
                "ts": now,
            }
        )
    return out


def step(ch: ClickHouse, model: Model | None, skipped: dict[str, int]) -> int:
    """Classify one batch of pending sessions. ``skipped`` remembers, by summary version, the
    sessions nothing could decide, so they are not fetched again until they change."""
    pending = [r["session_id"] for r in ch.rows(PENDING_SQL)]
    feature_rows = ch.rows(feature_query(pending)) if pending else []
    wanted = set(pending)
    todo = [
        r
        for r in feature_rows
        if r["session_id"] in wanted and skipped.get(r["session_id"]) != int(r["summary_version"])
    ]
    rows = classify(model, todo)
    done = {r["session_id"] for r in rows}
    for r in todo:
        if r["session_id"] not in done:
            skipped[r["session_id"]] = int(r["summary_version"])
    ch.insert("mirage.actor_class", rows)
    return len(rows)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    os.environ.update({k: v for k, v in _env_file().items() if k not in os.environ})
    ch = ClickHouse.from_env()
    model = load_model(Path(os.environ.get("CLASSIFIER_MODEL", str(MODEL_DIR))))
    interval = float(os.environ.get("POLL_S", "5"))
    running = True

    def stop(*_: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    skipped: dict[str, int] = {}
    log.info("classifier worker running")
    while running:
        HEALTH.touch()
        try:
            n = step(ch, model, skipped)
        except (QueryError, OSError, httpx.HTTPError) as exc:  # the store is away: retry
            log.warning("could not classify this round: %s", str(exc)[:200])
            n = 0
        if n:
            log.info("classified %d sessions", n)
        if n < BATCH // 2:
            time.sleep(interval)
        if len(skipped) > 50_000:
            skipped.clear()


def healthcheck() -> None:
    raise SystemExit(0 if HEALTH.exists() and time.time() - HEALTH.stat().st_mtime < 60 else 1)


if __name__ == "__main__":
    main()
