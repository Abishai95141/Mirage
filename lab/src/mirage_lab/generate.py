"""Generated scenarios: files made from the catalogue's IDs, never from its command text.

Two kinds, both deterministic and both checked in beside the hand-written scenarios:

- **Human twins** (``lab/scenarios/human/``). An existing SSH shell scenario's steps under a
  human-paced actor. Only the actor differs, so a classifier has to tell the two apart by how
  the input arrives, not by what it is. ``variant_of`` names the original; the two are held out
  together when the classifier is scored.
- **Coverage** (``lab/scenarios/coverage/``). The first live run showed that hand-written
  scenarios exercise 139 of the catalogue's 205 procedures, and under half of the held-out
  ones, so a held-out score described the part of the test set scenarios happened to use.
  These scenarios walk every procedure no hand-written scenario uses, one split and one
  protocol at a time. A scenario never mixes splits.

    uv run python -m mirage_lab.generate            # write the files
    uv run python -m mirage_lab.generate --check    # fail if the checked-in files have drifted
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from mirage_lab.models import Catalogue, Scenario

ROOT = Path(__file__).resolve().parents[3]
SCENARIOS = ROOT / "lab" / "scenarios"
GENERATED = ("human", "coverage")  # directories this module owns
STEPS_PER_SCENARIO = 8

# SSH shell scenarios that get a human-paced twin. Shell only: an exec request is one line sent
# by a program, and has no typing to observe.
HUMAN_BASES = (
    "bot-hunt-secrets",
    "bot-probe-files",
    "bot-stage-and-run",
    "bot-impact-miner",
    "bot-persist-access",
    "bot-persist-cron",
    "smoke-shell-recon",
    "bot-cover-tracks",
)
MYSQL_USER = "wp_user"  # the profile's application account, as the hand-written scenarios use


def hand_written(scenarios_dir: Path = SCENARIOS) -> dict[str, Path]:
    """Scenario ID -> file, for every scenario outside the generated directories."""
    out = {}
    for path in sorted(scenarios_dir.rglob("*.yaml")):
        if path.relative_to(scenarios_dir).parts[0] in GENERATED:
            continue
        out[Scenario.load(path).id] = path
    return out


def human_twins(scenarios_dir: Path = SCENARIOS) -> dict[Path, str]:
    """Each base scenario's text with its ID and actor replaced; the steps are copied as they
    are, without being parsed or printed."""
    sources = hand_written(scenarios_dir)
    out = {}
    for base in HUMAN_BASES:
        new_id = "human-" + base.split("-", 1)[1]
        lines = [
            f"# Human-paced twin of {base}: the same steps, typed key by key with pauses.",
            "# Only the actor differs, so the classifier has to tell the two apart by timing.",
        ]
        seen = set()
        for line in sources[base].read_text().splitlines():
            if line.startswith("#"):
                continue
            if line.startswith("id:"):
                lines.append(f"id: {new_id}")
                seen.add("id")
            elif line.startswith("actor:"):
                lines.append("actor: {class: human, timing: human, patience: 3}")
                lines.append(f"variant_of: {base}")
                seen.add("actor")
            else:
                lines.append(line)
        if seen != {"id", "actor"}:
            raise ValueError(f"{base}: expected one id line and one actor line")
        out[scenarios_dir / "human" / f"{new_id}.yaml"] = "\n".join(lines) + "\n"
    return out


def _used(scenarios_dir: Path) -> set[str]:
    used: set[str] = set()
    for path in hand_written(scenarios_dir).values():
        sc = Scenario.load(path)
        for session in sc.sessions:
            if session.login.procedure:
                used.add(session.login.procedure)
            used.update(step.procedure for step in session.steps)
    return used


def _session_head(protocol: str, index: int) -> list[str]:
    head = [f"  - protocol: {protocol}"]
    if protocol == "ssh":
        # alternate the channel so both request forms are exercised
        head.append(f"    channel: {'exec' if index % 2 else 'shell'}")
        head.append("    login: {user: root}")
    elif protocol == "mysql":
        head.append(f"    login: {{user: {MYSQL_USER}}}")
    return head


def coverage(
    catalogue: Catalogue, of_procedure: dict[str, str], scenarios_dir: Path = SCENARIOS
) -> dict[Path, str]:
    used = _used(scenarios_dir)
    buckets: dict[tuple[str, str], list[str]] = {}
    for pid in sorted(catalogue.procedures):
        proc = catalogue.procedures[pid]
        if pid in used or proc.kind == "auth":
            continue  # an auth procedure labels a login, not a step
        buckets.setdefault((of_procedure[pid], proc.protocol), []).append(pid)
    out = {}
    for (split, protocol), pids in sorted(buckets.items()):
        chunks = [pids[i : i + STEPS_PER_SCENARIO] for i in range(0, len(pids), STEPS_PER_SCENARIO)]
        for n, chunk in enumerate(chunks, start=1):
            sid = f"cover-{split}-{protocol}-{n:02d}"
            timing = "bot-slow" if n % 2 == 0 else "bot-fast"
            lines = [
                "# Generated by `python -m mirage_lab.generate`; do not edit.",
                f"# Exercises {split}-split procedures that no hand-written scenario uses.",
                f"id: {sid}",
                f"actor: {{class: scripted_bot, timing: {timing}, patience: 8}}",
                "sessions:",
                *_session_head(protocol, n),
                "    steps:",
                *(
                    f"      - {{id: s{i}, procedure: {pid}}}"
                    for i, pid in enumerate(chunk, start=1)
                ),
            ]
            out[scenarios_dir / "coverage" / f"{sid}.yaml"] = "\n".join(lines) + "\n"
    return out


def generate(scenarios_dir: Path = SCENARIOS, split_file: Path | None = None) -> dict[Path, str]:
    split_file = split_file or ROOT / "eval" / "split.yaml"
    doc = yaml.safe_load(split_file.read_text())
    of_procedure = {pid: s for s, ids in doc["procedures"].items() for pid in ids}
    catalogue = Catalogue.load(ROOT / "lab" / "catalogue")
    return {**human_twins(scenarios_dir), **coverage(catalogue, of_procedure, scenarios_dir)}


def drift(files: dict[Path, str], scenarios_dir: Path = SCENARIOS) -> list[str]:
    """Differences between what would be generated and what is checked in."""
    problems = []
    for path, text in sorted(files.items()):
        if not path.exists():
            problems.append(f"missing: {path.relative_to(ROOT)}")
        elif path.read_text() != text:
            problems.append(f"differs: {path.relative_to(ROOT)}")
    wanted = set(files)
    for name in GENERATED:
        for path in sorted((scenarios_dir / name).glob("*.yaml")):
            if path not in wanted:
                problems.append(f"stale: {path.relative_to(ROOT)}")
    return problems


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage_lab.generate")
    ap.add_argument("--check", action="store_true", help="verify the checked-in files; write none")
    args = ap.parse_args(argv)
    files = generate()
    if args.check:
        problems = drift(files)
        for p in problems:
            print(p)
        print(f"{len(files)} generated scenario(s), {len(problems)} problem(s)")
        sys.exit(1 if problems else 0)
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for name in GENERATED:
        for path in sorted((SCENARIOS / name).glob("*.yaml")):
            if path not in files:
                path.unlink()
    print(f"wrote {len(files)} scenario(s)")


if __name__ == "__main__":
    main()
