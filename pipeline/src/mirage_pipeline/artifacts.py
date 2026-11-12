"""Artifact indexer (spec 1.8): hash and type every stored artifact into ``mirage.artifact_files``.

The decoys write artifacts named by SHA-256 to volumes this service mounts read-only. The
indexer reads each new file once, to hash it and to let ``puremagic`` (MIT) look at its first
bytes. It never runs, unpacks or parses an artifact beyond that. ``mirage.artifacts`` (a view)
joins these rows with the events that mention each hash: first and last seen, and sessions.

``ARTIFACT_DIRS`` lists the directories as ``source=path`` pairs separated by commas.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import re
import signal
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import puremagic

from mirage_pipeline.normaliser import ClickHouse, Settings, _retry
from mirage_pipeline.rows import _ch_ts

log = logging.getLogger("mirage.artifacts")
HEALTH = Path("/tmp/mirage-artifacts.alive")  # noqa: S108 container-private
SHA256_NAME = re.compile(r"[0-9a-f]{64}")
HEAD = 8192
DEFAULT_DIRS = "cowrie=/cowrie-var/lib/cowrie/downloads,http=/http-artifacts"


def parse_dirs(spec: str) -> list[tuple[str, Path]]:
    out = []
    for part in spec.split(","):
        source, _, path = part.strip().partition("=")
        if source and path:
            out.append((source, Path(path)))
    return out


def detect(head: bytes) -> str:
    if not head:
        return "application/x-empty"
    try:
        return puremagic.from_string(head, mime=True) or "application/octet-stream"
    except puremagic.PureError:
        pass
    try:
        head.decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        return "application/octet-stream"


def index_file(source: str, path: Path) -> dict[str, Any] | None:
    """Hash and type one file. Returns None for names that are not artifacts (temp files)."""
    if not SHA256_NAME.fullmatch(path.name) or not path.is_file():
        return None
    h = hashlib.sha256()
    size = 0
    head = b""
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            if not head:
                head = chunk[:HEAD]
            h.update(chunk)
            size += len(chunk)
    digest = h.hexdigest()
    if digest != path.name:
        log.warning("artifact %s/%s hashes to %s", source, path.name, digest)
    st = path.stat()
    return {
        "sha256": digest,
        "size": size,
        "mime": detect(head),
        "source": source,
        "stored_at": _ch_ts(datetime.fromtimestamp(st.st_mtime, UTC)),
        "name_matches": 1 if digest == path.name else 0,
        "indexed_at": _ch_ts(datetime.now(UTC)),
    }


def scan(dirs: list[tuple[str, Path]], known: set[tuple[str, str]]) -> list[dict[str, Any]]:
    rows = []
    for source, root in dirs:
        if not root.is_dir():
            continue
        for p in sorted(root.iterdir()):
            if (source, p.name) in known:
                continue
            try:
                row = index_file(source, p)
            except OSError as exc:
                log.warning("cannot read %s: %s", p, exc)
                continue
            if row is not None:
                rows.append(row)
                known.add((source, p.name))
    return rows


async def run(stop: asyncio.Event) -> None:
    s = Settings.from_env()
    dirs = parse_dirs(os.environ.get("ARTIFACT_DIRS", DEFAULT_DIRS))
    interval = float(os.environ.get("SCAN_INTERVAL_S", "5"))
    ch = ClickHouse(s)
    await _retry("ClickHouse", ch.ping)
    known = {
        (r["source"], r["sha256"])
        for r in await _retry(
            "ClickHouse tables",
            lambda: ch.select("SELECT source, sha256 FROM mirage.artifact_files FINAL"),
        )
    }
    log.info("indexing %s (%d already indexed)", dirs, len(known))
    while not stop.is_set():
        HEALTH.touch()
        rows = await asyncio.to_thread(scan, dirs, known)
        if rows:
            await ch.insert(rows, "mirage.artifact_files")
            log.info("indexed %d artifacts", len(rows))
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=interval)
    await ch.close()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.Formatter.converter = time.gmtime
    stop = asyncio.Event()

    async def _main() -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        await run(stop)

    asyncio.run(_main())


def healthcheck() -> None:
    raise SystemExit(0 if HEALTH.exists() and time.time() - HEALTH.stat().st_mtime < 30 else 1)


if __name__ == "__main__":
    main()
