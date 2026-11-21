"""Hardware classes (phase 3 spec 3.2a, decision R6): the few machines a deployment can claim
to be.

A class is recorded, not written. ``hardware/capture/capture.sh`` boots Debian 12 on the
class's virtual hardware and records the kernel's own files, the trees under /dev, /proc and
/sys, and what the reporting commands print. This module turns such a record into the
committed class (:func:`import_capture`) and gives the profile generator what it needs from
one (:class:`HardwareClass`).

The record is of one machine, and a deployment is another machine of the same class. So the
values that belong to the recorded machine alone (its host name, its machine and boot IDs, its
network card's address, its IP addresses, the IDs of its file systems) are replaced by named
slots on import, and filled from the deployment's own values when a profile is rendered.
Nothing else in a record is changed: what the class says about its CPU, memory, disk and
devices is what the kernel said.
"""

from __future__ import annotations

import gzip
import io
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parents[2]
HARDWARE = HERE / "hardware"
SLOT = re.compile(r"\{\{([a-z0-9_]+)\}\}")
# What the capture machine was given (hardware/capture/run.py), and QEMU's user network.
CAPTURE_HOSTNAME = "mirage-capture-host"
CAPTURE_MAC = "52:54:00:6d:69:72"
CAPTURE_NET = {
    "10.0.2.15": "private_ip",
    "10.0.2.255": "broadcast",
    "10.0.2.2": "gateway",
    "10.0.2.3": "dns",
    "10.0.2.0": "network",
}
# Commands whose output is true only for the moment it was printed (the time of day, what is
# running, how long the machine has been up). They are kept in the record, marked, and are
# not library entries: the emulator or a later rung has to answer them.
VOLATILE = frozenset(["uptime", "free", "vmstat", "top", "ps", "w", "who", "last", "timedatectl"])
# Lines the recording left in its own record.
_OWN_TRACES = re.compile(r"guest\.sh|describe\.service|/root/capture|commands\.txt|sleep 25")
# The kernel's files a class provides under /proc. The rest of /proc is per process or
# changes by the second, and is not served from a file.
PROC_FILES = (
    "cpuinfo", "meminfo", "cmdline", "partitions", "swaps", "mounts", "filesystems", "modules",
    "devices", "misc", "consoles", "cgroups", "crypto", "interrupts", "iomem", "ioports",
    "diskstats", "stat", "loadavg", "uptime", "net/dev", "sys/kernel/osrelease",
    "sys/kernel/ostype", "sys/kernel/version", "sys/kernel/pid_max", "sys/vm/swappiness",
)  # fmt: skip


def _identity(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def _eui64(mac: str) -> str:
    """The IPv6 link-local address a kernel derives from a MAC address."""
    b = [int(x, 16) for x in mac.split(":")]
    b[0] ^= 0x02
    groups = [(b[0] << 8) | b[1], (b[2] << 8) | 0xFF, 0xFE00 | b[3], (b[4] << 8) | b[5]]
    return "fe80::" + ":".join(f"{g:x}" for g in groups)


def slot_map(identity: dict[str, str], blkid: str) -> list[tuple[str, str]]:
    """(the recorded machine's value, the slot that replaces it), longest value first so that
    a value that is part of another is not replaced inside it."""
    pairs = [
        (identity["hostname"], "hostname"),
        (identity["machine_id"], "machine_id"),
        (identity["boot_id"], "boot_id"),
        (identity["boot_id"].replace("-", ""), "boot_id_hex"),
        (CAPTURE_MAC, "mac"),
        (_eui64(CAPTURE_MAC), "ipv6_link"),
        *CAPTURE_NET.items(),
    ]
    # File-system and partition IDs, named after the partition they belong to.
    for line in blkid.splitlines():
        device = line.split(":", 1)[0].rsplit("/", 1)[-1]
        part = re.sub(r"^\D+", "", device) or "0"
        for key, value in re.findall(r'\b(UUID|PARTUUID)="([^"]+)"', line):
            pairs.append((value, f"{key.lower()}_{part}"))
    return sorted({p for p in pairs if p[0]}, key=lambda p: (-len(p[0]), p[0]))


def to_slots(text: str, pairs: list[tuple[str, str]]) -> str:
    for value, name in pairs:
        text = text.replace(value, "{{" + name + "}}")
        if value != value.upper() and re.fullmatch(r"[0-9a-f:-]+", value):
            text = text.replace(value.upper(), "{{" + name + "_upper}}")
    return text


def fill(text: str, values: dict[str, str]) -> str:
    """``text`` with its slots filled. A slot with no value is an error: a half-filled answer
    must never reach a decoy."""

    def one(m: re.Match[str]) -> str:
        name = m.group(1)
        if name.endswith("_upper") and name[:-6] in values:
            return values[name[:-6]].upper()
        if name not in values:
            raise KeyError(f"no value for the slot {name!r}")
        return values[name]

    return SLOT.sub(one, text)


def _listing(text: str, pairs: list[tuple[str, str]], keep: re.Pattern[str] | None = None) -> str:
    """A tree listing as it is committed: type, mode, owner, group, size, path, link target,
    sorted by path. The change time is dropped (the deployment's boot decides it) and the
    recording's own files are left out."""
    rows = []
    for line in text.splitlines():
        cols = line.split("\t")
        if len(cols) < 8 or _OWN_TRACES.search(cols[6]):
            continue
        kind, mode, uid, gid, size, _when, path, target = cols[:8]
        if keep is not None and not keep.search(path):
            continue
        rows.append(
            "\t".join((kind, mode, uid, gid, size, to_slots(path, pairs), to_slots(target, pairs)))
        )
    return "\n".join(sorted(rows, key=lambda r: r.split("\t")[5])) + "\n"


def _facts(cap: Path, cls: dict[str, Any], identity: dict[str, str], commands: list[dict]) -> dict:
    cpuinfo = (cap / "proc/cpuinfo").read_text()
    meminfo = (cap / "proc/meminfo").read_text()
    out = {c["argv"]: c["stdout"] for c in commands}
    root = next(line.split() for line in out["df"].splitlines() if line.split()[-1:] == ["/"])
    links = re.findall(r"^\d+: ([a-z0-9]+):", out["ip link"], re.M)
    disk = next(line.split() for line in out["lsblk"].splitlines() if " disk" in line)
    vendor = re.search(r"Hardware Vendor: (.+)", out["hostnamectl"])
    model = re.search(r"Hardware Model: (.+)", out["hostnamectl"])
    return {
        "id": cls["id"],
        "about": cls["about"],
        "vm": cls["vm"],
        "cpu_model": re.search(r"model name\s*: (.+)", cpuinfo).group(1),
        "cpus": len(re.findall(r"^processor\s*:", cpuinfo, re.M)),
        "memory_kb": int(re.search(r"MemTotal:\s+(\d+) kB", meminfo).group(1)),
        "disk": {"name": disk[0], "size": disk[3]},
        "root_device": root[0],
        "interface": next(n for n in links if n != "lo"),
        "virtualisation": out["systemd-detect-virt"].strip(),
        "hardware_vendor": vendor.group(1).strip() if vendor else "",
        "hardware_model": model.group(1).strip() if model else "",
        "kernel_release": identity["kernel_release"],
        "kernel_version": identity["kernel_version"],
        "recorded_uptime_s": float(identity["uptime_s"]),
    }


def import_capture(capture: Path, class_file: Path, dest: Path) -> dict[str, Any]:
    """Turn the record in ``capture`` into the committed class under ``dest``. Returns its
    facts. The same record always gives the same files."""
    cls = yaml.safe_load(class_file.read_text())
    identity = _identity((capture / "identity.txt").read_text())
    commands = []
    for cmd_file in sorted((capture / "commands").glob("*.cmd")):
        stem = cmd_file.with_suffix("")
        code, ms = stem.with_suffix(".meta").read_text().split()
        commands.append(
            {
                "argv": cmd_file.read_text().strip(),
                "exit_code": int(code),
                "ms": int(ms),
                "stdout": stem.with_suffix(".out").read_text(errors="replace"),
                "stderr": stem.with_suffix(".err").read_text(errors="replace"),
            }
        )
    raw = {c["argv"]: c["stdout"] for c in commands}
    pairs = slot_map(identity, raw.get("blkid", ""))
    facts = _facts(capture, cls, identity, commands)
    # Each slot and the kind of value it takes: a FAT file system's ID is eight hex digits,
    # every other file-system or partition ID is a UUID, the rest are the deployment's facts.
    facts["slots"] = {
        name: (
            "fat_id"
            if re.fullmatch(r"[0-9A-F]{4}-[0-9A-F]{4}", value)
            else "uuid"
            if name.startswith(("uuid_", "partuuid_"))
            else "fact"
        )
        for value, name in sorted(pairs, key=lambda p: p[1])
    }
    facts["image_sha512"] = (capture / "source.sha512").read_text().split()[0]

    if dest.exists():
        for old in sorted(dest.rglob("*"), reverse=True):
            old.unlink() if old.is_file() else old.rmdir()
    (dest / "proc").mkdir(parents=True)
    for name in PROC_FILES:
        src = capture / "proc" / name
        if src.exists():
            target = dest / "proc" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(to_slots(src.read_text(errors="replace"), pairs))
    (dest / "dev.tsv").write_text(_listing((capture / "dev.tsv").read_text(), pairs))
    (dest / "proc.tsv").write_text(
        _listing(
            (capture / "proc.tsv").read_text(), pairs, re.compile(r"^/proc(/[a-z][^/]*){0,2}$")
        )
    )
    (dest / "boot.tsv").write_text(_listing((capture / "boot.tsv").read_text(), pairs))
    sys_rows = _listing(gzip.decompress((capture / "sys.tsv.gz").read_bytes()).decode(), pairs)
    packed = io.BytesIO()
    with gzip.GzipFile(fileobj=packed, mode="wb", mtime=0) as z:  # the same bytes every time
        z.write(sys_rows.encode())
    (dest / "sys.tsv.gz").write_bytes(packed.getvalue())
    (dest / "sysfiles.tsv").write_text(to_slots((capture / "sysfiles.tsv").read_text(), pairs))

    kept = []
    for c in commands:
        verb = c["argv"].split()[0]
        if c["exit_code"] == 127:  # the image has no such command: it says nothing of the class
            continue
        entry = dict(c)
        for stream in ("stdout", "stderr"):
            lines = [ln for ln in c[stream].splitlines() if not _OWN_TRACES.search(ln)]
            entry[stream] = to_slots("\n".join(lines) + ("\n" if lines else ""), pairs)
        entry["volatile"] = verb in VOLATILE
        kept.append(entry)
    (dest / "commands.yaml").write_text(
        "# What the class's reporting commands printed, with the recorded machine's own values\n"
        "# as slots. Written by `mirage-profile hardware`; do not edit.\n"
        + yaml.safe_dump(kept, sort_keys=False, width=1000, allow_unicode=True)
    )
    absent = sorted(c["argv"].split()[0] for c in commands if c["exit_code"] == 127)
    facts["commands_absent"] = absent
    (dest / "facts.yaml").write_text(
        "# What this class is, read off its record. Written by `mirage-profile hardware`.\n"
        + yaml.safe_dump(facts, sort_keys=False, width=100)
    )
    return facts


@dataclass
class HardwareClass:
    """A committed class, as the profile generator uses it."""

    id: str
    facts: dict[str, Any]
    root: Path

    @classmethod
    def load(cls, class_id: str, base: Path = HARDWARE) -> HardwareClass:
        root = base / class_id
        return cls(class_id, yaml.safe_load((root / "facts.yaml").read_text()), root)

    @staticmethod
    def available(base: Path = HARDWARE) -> list[str]:
        return sorted(p.parent.name for p in base.glob("*/facts.yaml"))

    def proc_files(self) -> dict[str, str]:
        """{path under /proc: text with slots}."""
        base = self.root / "proc"
        return {
            str(p.relative_to(base)): p.read_text() for p in sorted(base.rglob("*")) if p.is_file()
        }

    def commands(self) -> list[dict[str, Any]]:
        return yaml.safe_load((self.root / "commands.yaml").read_text())

    def listing(self, name: str) -> str:
        path = self.root / name
        if name.endswith(".gz"):
            return gzip.decompress(path.read_bytes()).decode()
        return path.read_text()

    def sysfiles(self) -> dict[str, str]:
        rows = (
            line.split("\t", 1) for line in (self.root / "sysfiles.tsv").read_text().splitlines()
        )
        return {r[0]: r[1].rstrip() for r in rows if len(r) == 2}


def slot_values(host: dict[str, Any], rng: Any, facts: dict[str, Any]) -> dict[str, str]:
    """A deployment's own values for a class's slots, from its profile and its seed."""
    import uuid

    def hexes(n: int) -> str:
        return "".join(rng.choice("0123456789abcdef") for _ in range(n))

    def new_uuid() -> str:
        return str(uuid.UUID(hexes(32), version=4))

    ip = host["private_ip"]
    net = ip.rsplit(".", 1)[0]
    mac = "52:54:00:" + ":".join(hexes(2) for _ in range(3))
    boot = new_uuid()
    values = {
        "hostname": host["hostname"],
        "machine_id": host["machine_id"],
        "boot_id": boot,
        "boot_id_hex": boot.replace("-", ""),
        "mac": mac,
        "ipv6_link": _eui64(mac),
        "private_ip": ip,
        "gateway": f"{net}.1",
        "dns": f"{net}.2",
        "broadcast": f"{net}.255",
        "network": f"{net}.0",
    }
    for name, kind in sorted(facts["slots"].items()):
        if kind == "fat_id":
            values[name] = f"{hexes(4).upper()}-{hexes(4).upper()}"
        elif kind == "uuid":
            values[name] = new_uuid()
    return values
