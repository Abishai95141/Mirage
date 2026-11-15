"""``mirage-lab``: lint scenarios, check the lab, run scenarios, record a human session."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from mirage_lab import record, runner, safety
from mirage_lab.models import DEFAULT_SPLIT, Catalogue, Scenario, Split, lint, load_split
from mirage_lab.net import AddressesExhausted
from mirage_lab.slots import Slots
from mirage_lab.truth import KEEP_DAYS

REPO_SPLIT = Path("eval/split.yaml")  # where the split lives in a checkout


def _paths(args: list[str]) -> list[Path]:
    out: list[Path] = []
    for a in args:
        p = Path(a)
        out += sorted(p.rglob("*.yaml")) if p.is_dir() else [p]
    if not out:
        raise SystemExit("no scenario files given")
    return out


def _split_file(given: Path | None) -> Path:
    """Where the frozen split is: ``--split``, else ``LAB_SPLIT``, else the runner container's
    mount; in a checkout, where that mount does not exist, the repository's own copy."""
    if given is not None:
        return given
    if os.environ.get("LAB_SPLIT"):
        return Path(os.environ["LAB_SPLIT"])
    mounted = Path(DEFAULT_SPLIT)
    return REPO_SPLIT if REPO_SPLIT.exists() and not mounted.exists() else mounted


def _lint(paths: list[Path], catalogue: Catalogue, split_file: Path) -> int:
    split: Split | None = None
    try:
        split = load_split(split_file)
    except OSError:
        # Lint is also an editing aid, so it goes on without the split and says what it did
        # not check. The runner does not: it refuses to run.
        print(
            f"warning: no split file at {split_file}; the one-split rule was not checked",
            file=sys.stderr,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    scenarios = [Scenario.load(path) for path in paths]
    ids = sorted({s.id for s in scenarios} | set(split.scenarios if split else ()))
    of_procedure = split.procedures if split else None
    problems = [p for s in scenarios for p in lint(s, catalogue, Slots.names(), of_procedure, ids)]
    for p in problems:
        print(p)
    print(f"{len(paths)} scenario(s), {len(problems)} problem(s)")
    return 1 if problems else 0


def _probe(targets: list[str], timeout: float) -> None:
    try:
        parsed = [safety.parse_probe(t) for t in targets]
    except ValueError as exc:
        raise SystemExit(f"refusing to probe: {exc}") from exc
    print(json.dumps(safety.probe(parsed, timeout)))


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage-lab")
    ap.add_argument(
        "--catalogue", type=Path, default=os.environ.get("LAB_CATALOGUE", "lab/catalogue")
    )
    ap.add_argument(
        "--split",
        type=Path,
        default=None,
        help=f"the frozen split; default $LAB_SPLIT, else {DEFAULT_SPLIT}, else {REPO_SPLIT}",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_lint = sub.add_parser("lint", help="check scenario files; sends nothing")
    p_lint.add_argument("scenarios", nargs="+")
    p_check = sub.add_parser(
        "check", help="verify this container is isolated and the target is the lab's"
    )
    p_check.add_argument(
        "--probe",
        action="append",
        default=[],
        metavar="ADDRESS:PORT",
        help="instead of the check: try a TCP connection to this literal private address and "
        "print how each attempt ended, as JSON (repeatable)",
    )
    p_check.add_argument("--timeout", type=float, default=3.0, help="seconds per probe")
    p_run = sub.add_parser("run", help="run scenarios against the lab edge")
    p_run.add_argument("scenarios", nargs="+")
    p_run.add_argument("--mode", choices=["capture", "explore"], default="capture")
    p_run.add_argument("--seed", type=int, default=0)
    p_run.add_argument("--repeat", type=int, default=1)
    p_run.add_argument("--workers", type=int, default=8)
    p_run.add_argument("--time-scale", type=float, default=1.0)
    p_record = sub.add_parser(
        "record", help="type a real SSH session into the decoy through the lab edge (spec Q8)"
    )
    p_record.add_argument("--user", default="root", help="the account to log in as")
    args = ap.parse_args(argv)

    target = os.environ.get("LAB_TARGET", "lab-edge")
    if args.cmd == "check":
        if args.probe:
            _probe(args.probe, args.timeout)
            return
        try:
            print(f"ok: {target} is {safety.require_lab(target)}, inside the lab network")
        except safety.SafetyError as exc:
            raise SystemExit(f"refusing to run: {exc}") from exc
        return

    catalogue = Catalogue.load(Path(args.catalogue))
    split_file = _split_file(args.split)
    if args.cmd == "lint":
        sys.exit(_lint(_paths(args.scenarios), catalogue, split_file))

    paths = _paths(args.scenarios) if args.cmd == "run" else []
    try:
        target_ip = safety.require_lab(target)  # before anything is opened
    except safety.SafetyError as exc:
        raise SystemExit(f"refusing to run: {exc}") from exc
    settings = runner.Settings(
        target_ip=target_ip,
        out_dir=Path(os.environ.get("LAB_OUT", "/var/lib/mirage-lab")),
        profile_dir=Path(os.environ.get("PROFILE_DIR", "/profile")),
        mode=getattr(args, "mode", "capture"),  # a recording is always a capture session
        seed=getattr(args, "seed", 0),
        repeat=getattr(args, "repeat", 1),
        workers=getattr(args, "workers", 1),
        time_scale=getattr(args, "time_scale", 1.0),
        code_version=os.environ.get("MIRAGE_CODE_VERSION", "dev"),
        split_file=split_file,
        truth_keep_days=float(os.environ.get("LAB_TRUTH_KEEP_DAYS") or KEEP_DAYS),
    )
    if args.cmd == "record":
        try:
            print(json.dumps(record.run(settings, catalogue, args.user)))
        except (record.RecordError, AddressesExhausted, ValueError) as exc:
            raise SystemExit(f"not recorded: {exc}") from exc
        return
    try:
        summary = runner.run(paths, catalogue, settings)
    except AddressesExhausted as exc:
        raise SystemExit(f"refusing to run: {exc}") from exc
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
