"""The fingerprint regression suite (phase 3 spec 3.4; Gate 3 test 7).

    python -m eval.probes.suite [--groups tells,transport,...] [--json report.json]

Run inside the lab network (``make probe``), where the decoy and the real reference host are
both one proxy away: the decoy behind ``lab-edge``, the reference host behind ``arm-r-edge``.
Run from the machine's own shell it reaches the decoy on loopback and has no reference host;
the groups that need one are then skipped, and said to be.

Groups:

    tells      the default-tell checks (``default_tells``)
    transport  spike S3's probes as checks, decoy against reference (``transport``)
    emulator   a fixed list of ordinary commands, compared by the fidelity check (``emulator``)
    timing     the same requests timed on both hosts (``emulator``)
    library    the render library's entries on the running decoy (``render_library``)
    fleet      a second deployment, from another seed: what must differ and agree (``fleet``)
    consistency  the decoy held to itself: asked twice it answers the same, and what a
               command reported agrees with what is then seen (``consistency``)

**Known gaps** are in ``known_gaps.yaml``: a check ID, the reason, and the decision that owns
it. A failing check that is not listed fails the run. A listed check that passes fails the run
too, until its entry is removed, and so does an entry that names no check of a group that ran:
the list cannot go stale.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from eval.probes import (
    consistency,
    default_tells,
    emulator,
    fleet,
    render_library,
    ssh_probes,
    transport,
)
from eval.probes.default_tells import Result
from eval.probes.net import Target, probe_source

HERE = Path(__file__).parent
GAPS = HERE / "known_gaps.yaml"
GROUPS = ("tells", "transport", "emulator", "timing", "library", "fleet", "consistency")
NEEDS_REFERENCE = {"transport", "emulator", "timing"}


@dataclass
class Check:
    id: str
    group: str
    text: str
    ok: bool
    detail: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)  # group -> why it did not run
    extra: dict[str, Any] = field(default_factory=dict)  # measurements, for the JSON report

    @property
    def ran(self) -> set[str]:
        return {c.group for c in self.checks}


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def from_results(group: str, results: list[Result]) -> list[Check]:
    """Checks from a probe's own results, each ID built from the protocol and the text."""
    return [
        Check(f"{group}.{r.protocol}.{slug(r.check)}", group, r.check, r.status == "pass", r.detail)
        for r in results
    ]


def from_pairs(group: str, pairs: list[tuple[str, Result]]) -> list[Check]:
    """Checks whose IDs the probe names itself (a command's ID, a transport item)."""
    return [
        Check(f"{group}.{suffix}", group, r.check, r.status == "pass", r.detail)
        for suffix, r in pairs
    ]


def load_gaps(path: Path = GAPS) -> dict[str, dict[str, str]]:
    """The known gaps by check ID. Every entry gives a reason and the decision that owns it."""
    doc = yaml.safe_load(path.read_text()) or {}
    gaps: dict[str, dict[str, str]] = {}
    for item in doc.get("gaps") or []:
        missing = [k for k in ("id", "reason", "owner") if not str(item.get(k) or "").strip()]
        if missing:
            raise ValueError(f"{path.name}: an entry lacks {missing}: {item}")
        if item["id"] in gaps:
            raise ValueError(f"{path.name}: {item['id']} is listed twice")
        gaps[item["id"]] = {"reason": str(item["reason"]), "owner": str(item["owner"])}
    return gaps


@dataclass
class Verdict:
    failed: list[Check]  # failing, and not a known gap
    known: list[Check]  # failing, and listed
    stale: list[Check]  # listed, and passing
    missing: list[str]  # listed, in a group that ran, and no such check exists

    @property
    def ok(self) -> bool:
        return not (self.failed or self.stale or self.missing)


def judge(report: Report, gaps: dict[str, dict[str, str]]) -> Verdict:
    by_id = {c.id: c for c in report.checks}
    if len(by_id) != len(report.checks):
        twice = sorted(
            {c.id for c in report.checks if sum(x.id == c.id for x in report.checks) > 1}
        )
        raise ValueError(f"two checks share an ID: {twice}")
    ran = report.ran
    return Verdict(
        failed=[c for c in report.checks if not c.ok and c.id not in gaps],
        known=[c for c in report.checks if not c.ok and c.id in gaps],
        stale=[c for c in report.checks if c.ok and c.id in gaps],
        missing=sorted(g for g in gaps if g.split(".", 1)[0] in ran and g not in by_id),
    )


@dataclass
class Where:
    """The hosts of one run. ``reference`` is None outside the lab network."""

    ssh: Target
    http: Target | None
    redis: Target | None
    mysql: Target | None
    reference: Target | None
    profile: Path
    samples: int = 30
    fleet: Target | None = None  # a second deployment's SSH decoy
    fleet_profile: Path | None = None

    def password(self, profile: Path | None = None) -> str:
        lines = ((profile or self.profile) / "cowrie/userdb.txt").read_text().splitlines()
        return next(ln.split(":", 2)[2] for ln in lines if ln.startswith("root:"))


def run(where: Where, groups: tuple[str, ...] = GROUPS) -> Report:
    report = Report()
    password = where.password()
    for group in groups:
        if group in NEEDS_REFERENCE and where.reference is None:
            report.skipped[group] = "it needs the reference host, which only the lab network has"
    wanted = [g for g in groups if g not in report.skipped]

    if "tells" in wanted:
        results = default_tells.run(
            where.ssh, where.http, password, where.profile, where.redis, where.mysql
        )
        report.checks += from_results("tells", results)
    if "transport" in wanted:
        reference, decoy = ssh_probes.probe(where.reference), ssh_probes.probe(where.ssh)
        report.checks += from_pairs("transport", transport.compare(reference, decoy))
        report.extra["transport"] = {"reference": reference, "decoy": decoy}
    if {"emulator", "timing"} & set(wanted):
        commands = emulator.load_commands()
        decoy = emulator.Exec(where.ssh, "root", password)
        reference = emulator.Exec(where.reference, "root", password)
        try:
            if "emulator" in wanted:
                pairs, seen = emulator.check_fidelity(decoy, reference, commands)
                report.checks += from_pairs("emulator", pairs)
                report.extra["emulator"] = seen
            if "timing" in wanted:
                pairs, timings = emulator.check_timing(decoy, reference, commands, where.samples)
                report.checks += from_pairs("timing", pairs)
                report.extra["timing"] = [
                    {
                        "id": t.id,
                        "class": t.cls,
                        "decoy_ms": round(t.medians[0], 2),
                        "reference_ms": round(t.medians[1], 2),
                        "samples": len(t.decoy_ms),
                    }
                    for t in timings
                ]
        finally:
            decoy.close()
            reference.close()
    if "library" in wanted:
        if (where.profile / "cowrie/rendered.json").exists():
            report.checks += from_results("library", render_library.run(where.ssh, where.profile))
        else:
            report.skipped["library"] = "this deployment has no render library"
    if "consistency" in wanted:
        first = emulator.Exec(where.ssh, "root", password)
        second = emulator.Exec(where.ssh, "root", password)
        try:
            report.checks += from_pairs("consistency", consistency.run(first, second))
        finally:
            first.close()
            second.close()
    if "fleet" in wanted:
        there = where.fleet_profile is not None and (where.fleet_profile / "host.json").exists()
        if where.fleet is None or not there:
            report.skipped["fleet"] = "it needs a second deployment (make probe starts one)"
        else:
            first = emulator.Exec(where.ssh, "root", password)
            second = emulator.Exec(where.fleet, "root", where.password(where.fleet_profile))
            try:
                classes = (
                    fleet.hardware_class(where.profile),
                    fleet.hardware_class(where.fleet_profile),
                )
                same = None if None in classes else classes[0] == classes[1]
                report.checks += from_pairs("fleet", fleet.compare(first, second, same))
                report.extra["fleet"] = {"hardware_classes": classes}
            finally:
                first.close()
                second.close()
    return report


def show(report: Report, verdict: Verdict, gaps: dict[str, dict[str, str]]) -> str:
    lines = []
    stale = {c.id for c in verdict.stale}
    for c in report.checks:
        if c.id in stale:
            word = "STALE"
        elif c.ok:
            word = "PASS"
        else:
            word = "GAP" if c.id in gaps else "FAIL"
        tail = f"  [{c.detail}]" if c.detail and word != "PASS" else ""
        lines.append(f"{word:5} {c.id}  {c.text}{tail}")
    for group, why in report.skipped.items():
        lines.append(f"SKIP  {group}: {why}")
    for gap in verdict.missing:
        lines.append(f"STALE {gap}  the known-gaps file names it and no check has that ID")
    passed = sum(c.ok for c in report.checks) - len(verdict.stale)
    lines.append(
        f"\n{passed} pass, {len(verdict.failed)} fail, {len(verdict.known)} known gap, "
        f"{len(verdict.stale) + len(verdict.missing)} stale gap entries"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    env = os.environ
    ap = argparse.ArgumentParser(prog="python -m eval.probes.suite")
    ap.add_argument("--ssh", default=env.get("PROBE_SSH", "127.0.0.1:2222"))
    ap.add_argument("--http", default=env.get("PROBE_HTTP", "127.0.0.1:8081"))
    ap.add_argument("--redis", default=env.get("PROBE_REDIS", "127.0.0.1:6380"))
    ap.add_argument("--mysql", default=env.get("PROBE_MYSQL", "127.0.0.1:3307"))
    ap.add_argument(
        "--reference",
        default=env.get("PROBE_REFERENCE"),
        help="the reference host's SSH, HOST:PORT (inside the lab network: arm-r-edge:2222)",
    )
    ap.add_argument(
        "--proxy",
        action="store_true",
        default=env.get("PROBE_PROXY") == "1",
        help="announce a documentation-range source with a PROXY header (the lab edges want one)",
    )
    ap.add_argument("--profile", type=Path, default=Path(env.get("PROFILE_DIR", "build/profile")))
    ap.add_argument("--fleet", default=env.get("PROBE_FLEET"), help="a second deployment's SSH")
    ap.add_argument(
        "--fleet-profile",
        type=Path,
        default=Path(env["PROBE_FLEET_PROFILE"]) if env.get("PROBE_FLEET_PROFILE") else None,
    )
    ap.add_argument("--groups", default=",".join(GROUPS))
    ap.add_argument("--samples", type=int, default=30, help="timed runs of each timed command")
    ap.add_argument("--gaps", type=Path, default=GAPS)
    ap.add_argument("--json", type=Path, help="write the full report here")
    args = ap.parse_args(argv)
    groups = tuple(g for g in args.groups.split(",") if g)
    unknown = sorted(set(groups) - set(GROUPS))
    if unknown:
        raise SystemExit(f"no such group: {unknown}; the groups are {', '.join(GROUPS)}")
    source = probe_source() if args.proxy else None

    def target(text: str | None) -> Target | None:
        return Target.parse(text, source) if text else None

    where = Where(
        ssh=Target.parse(args.ssh, source),
        http=target(args.http),
        redis=target(args.redis),
        mysql=target(args.mysql),
        reference=target(args.reference),
        profile=args.profile,
        samples=args.samples,
        fleet=target(args.fleet),
        fleet_profile=args.fleet_profile,
    )
    gaps = load_gaps(args.gaps)
    report = run(where, groups)
    verdict = judge(report, gaps)
    print(show(report, verdict, gaps))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(
                {
                    "source": source,
                    "groups": sorted(report.ran),
                    "skipped": report.skipped,
                    "checks": [asdict(c) | {"known_gap": c.id in gaps} for c in report.checks],
                    "measurements": report.extra,
                },
                indent=1,
            )
            + "\n"
        )
    sys.exit(0 if verdict.ok else 1)


if __name__ == "__main__":
    main()
