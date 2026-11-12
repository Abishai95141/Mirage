"""The ground-truth log: JSON lines on the runner's volume, which Vector tails to
``sim.groundtruth``. The runner sends nothing over the network but its attack traffic."""

from __future__ import annotations

import threading
from pathlib import Path

from pydantic import BaseModel


class TruthWriter:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(path, "a", buffering=1)  # noqa: SIM115 - held for the whole run
        self._lock = threading.Lock()
        self.counts: dict[str, int] = {}

    def write(self, record: BaseModel) -> None:
        line = record.model_dump_json()
        kind = getattr(record, "kind", "step")
        with self._lock:
            self._file.write(line + "\n")
            self.counts[kind] = self.counts.get(kind, 0) + 1

    def close(self) -> None:
        with self._lock:
            self._file.flush()
            self._file.close()
