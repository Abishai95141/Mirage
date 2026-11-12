"""``mirage-lab``: lint scenarios, check the lab, run scenarios."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from mirage_lab import runner, safety
from mirage_lab.models import Catalogue, Scenario, lint
from mirage_lab.slots import Slots


def _paths(args: list[str]) -> list[Path]:
    out: list[Path] = []
    for a in args:
        p = Path(a)
        out += sorted(p.rglob("*.yaml")) if p.is_dir() else [p]
    if not out:
        raise SystemExit("no scenario files given")
    return out


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage-lab")
    ap.add_argument(
        "--catalogue", type=Path, default=os.environ.get("LAB_CATALOGUE", "lab/catalogue")
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_lint = sub.add_parser("lint", help="check scenario files; sends nothing")
    p_lint.add_argument("scenarios", nargs="+")
    sub.add_parser("check", help="verify this container is isolated and the target is the lab's")
    p_run = sub.add_parser("run", help="run scenarios against the lab edge")
    p_run.add_argument("scenarios", nargs="+")
    p_run.add_argument("--mode", choices=["capture", "explore"], default="capture")
    p_run.add_argument("--seed", type=int, default=0)
    p_run.add_argument("--repeat", type=int, default=1)
    p_run.add_argument("--workers", type=int, default=8)
    p_run.add_argument("--time-scale", type=float, default=1.0)
    args = ap.parse_args(argv)

    target = os.environ.get("LAB_TARGET", "lab-edge")
    if args.cmd == "check":
        try:
            print(f"ok: {target} is {safety.require_lab(target)}, inside the lab network")
        except safety.SafetyError as exc:
            raise SystemExit(f"refusing to run: {exc}") from exc
        return

    catalogue = Catalogue.load(Path(args.catalogue))
    paths = _paths(args.scenarios)
    if args.cmd == "lint":
        problems = [
            p for path in paths for p in lint(Scenario.load(path), catalogue, Slots.names())
        ]
        for p in problems:
            print(p)
        print(f"{len(paths)} scenario(s), {len(problems)} problem(s)")
        sys.exit(1 if problems else 0)

    try:
        target_ip = safety.require_lab(target)  # before anything is opened
    except safety.SafetyError as exc:
        raise SystemExit(f"refusing to run: {exc}") from exc
    settings = runner.Settings(
        target_ip=target_ip,
        out_dir=Path(os.environ.get("LAB_OUT", "/var/lib/mirage-lab")),
        profile_dir=Path(os.environ.get("PROFILE_DIR", "/profile")),
        mode=args.mode,
        seed=args.seed,
        repeat=args.repeat,
        workers=args.workers,
        time_scale=args.time_scale,
        code_version=os.environ.get("MIRAGE_CODE_VERSION", "dev"),
    )
    try:
        summary = runner.run(paths, catalogue, settings)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print(
        json.dumps(
            {
                "run_id": summary.run_id,
                "sessions": summary.sessions,
                "steps": summary.steps,
                "errors": summary.errors,
            }
        )
    )
    sys.exit(1 if summary.errors else 0)


if __name__ == "__main__":
    main()
