"""Export JSON Schema files for the event envelope and the ground-truth record."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mirage_schema.events import SCHEMA_VERSION, MirageEvent
from mirage_schema.groundtruth import GroundTruth, RunRecord, SessionTruth


def schemas() -> dict[str, dict]:
    return {
        "mirage-event.schema.json": MirageEvent.model_json_schema(
            by_alias=True, mode="serialization"
        ),
        "ground-truth.schema.json": GroundTruth.model_json_schema(mode="serialization"),
        "session-truth.schema.json": SessionTruth.model_json_schema(mode="serialization"),
        "run-record.schema.json": RunRecord.model_json_schema(mode="serialization"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out_dir", type=Path, nargs="?", default=Path("schema/json"))
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for name, body in schemas().items():
        body["$id"] = f"https://mirage.invalid/schema/{SCHEMA_VERSION}/{name}"
        (args.out_dir / name).write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        print(args.out_dir / name)


if __name__ == "__main__":
    main()
