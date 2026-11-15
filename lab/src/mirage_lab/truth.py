"""The ground-truth log: JSON lines on the runner's volume, which Vector tails to
``sim.groundtruth``. The runner sends nothing over the network but its attack traffic.

Each run writes its own file, ``groundtruth.json.<run_id>``, so no file grows past one run.
Vector's source already reads ``groundtruth.json*``, so the name needs nothing changed there.
Vector mounts the volume read-only and cannot remove what it has shipped, so the runner prunes:
a file no run has written to for ``keep_days`` is deleted when the next run starts. By then its
records are long in ``mirage.sim_truth``, which is where a join is repeated from.
"""

from __future__ import annotations

import contextlib
import threading
import time
from pathlib import Path

from pydantic import BaseModel

TRUTH_NAME = "groundtruth.json"  # the prefix Vector's file source globs for
KEEP_DAYS = 14.0  # Vector ships a line within seconds; two weeks covers a long outage


def run_file(out_dir: Path, run_id: str) -> Path:
    return out_dir / f"{TRUTH_NAME}.{run_id}"


def prune(out_dir: Path, keep_days: float = KEEP_DAYS) -> list[Path]:
    """Delete ground-truth files last written more than ``keep_days`` ago, and say which.
    Zero or less keeps everything. A file in use is never old enough to qualify."""
    if keep_days <= 0:
        return []
    cutoff = time.time() - keep_days * 86400
    removed = []
    for path in sorted(out_dir.glob(TRUTH_NAME + "*")):
        with contextlib.suppress(OSError):  # another runner may have pruned it first
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink()
                removed.append(path)
    return removed


class TruthWriter:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(path, "a", buffering=1)  # noqa: SIM115 - held for the whole run
        self._lock = threading.Lock()
        self.counts: dict[str, int] = {}

    def write(self, record: BaseModel) -> None:
        # A session record names its ``error`` only when it has one. A healthy record is then
        # byte for byte what it was before the field existed, so a join built without the
        # field (it forbids unknown keys) still reads every healthy session.
        # The same holds for a step's ``attempts``, which only a login step carries.
        quiet = {k for k in ("error", "attempts") if getattr(record, k, False) is None} or None
        line = record.model_dump_json(exclude=quiet)
        kind = getattr(record, "kind", "step")
        with self._lock:
            self._file.write(line + "\n")
            self.counts[kind] = self.counts.get(kind, 0) + 1

    def close(self) -> None:
        with self._lock:
            self._file.flush()
            self._file.close()
