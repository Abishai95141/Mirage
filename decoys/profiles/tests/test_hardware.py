"""Hardware classes (phase 3 spec 3.2a, R6): importing a recorded machine as a class, and
rendering a deployment that claims to be one."""

from __future__ import annotations

import gzip
import json
import random
import re
from pathlib import Path

import pytest
import yaml

from mirage_profiles import generator, hardware

ROOT = Path(__file__).resolve().parents[3]
PROFILE = ROOT / "decoys/profiles/web-db.yaml"
CLASSES = hardware.HardwareClass.available()
IDENTITY = {
    "hostname": hardware.CAPTURE_HOSTNAME,
    "machine_id": "e775be25e0c540e79b220d570d6ecbf5",
    "boot_id": "2d667301-88eb-4cb9-ba31-48216c36d049",
    "kernel_release": "6.1.0-54-amd64",
    "kernel_version": "#1 SMP PREEMPT_DYNAMIC Debian 6.1.190-1 (2026-10-16)",
    "uptime_s": "30.5",
}
BLKID = (
    '/dev/vda15: SEC_TYPE="msdos" UUID="EEF4-1F19" TYPE="vfat" PARTUUID="22bd1d88-1039-4dfa-b688-b3c344c5b123"\n'
    '/dev/vda1: UUID="501540a8-c8a5-49b6-bafa-78be9b0d36fb" TYPE="ext4" PARTUUID="b7255bda-17d6-4556-9acc-f54211365058"\n'
)


def test_the_recorded_machine_s_own_values_become_slots():
    pairs = hardware.slot_map(IDENTITY, BLKID)
    text = (
        "Static hostname: mirage-capture-host\n"
        "Machine ID: e775be25e0c540e79b220d570d6ecbf5\n"
        "Boot ID: 2d66730188eb4cb9ba3148216c36d049\n"
        "link/ether 52:54:00:6d:69:72 brd ff:ff:ff:ff:ff:ff\n"
        "inet 10.0.2.15/24 brd 10.0.2.255 scope global ens3\n"
        "default via 10.0.2.2 dev ens3\n"
        "inet6 fe80::5054:ff:fe6d:6972/64 scope link\n"
        "root=PARTUUID=b7255bda-17d6-4556-9acc-f54211365058 ro\n"
        "/dev/disk/by-uuid/EEF4-1F19 -> ../../vda15\n"
        "model name : AMD EPYC Processor\n"
    )
    assert hardware.to_slots(text, pairs) == (
        "Static hostname: {{hostname}}\n"
        "Machine ID: {{machine_id}}\n"
        "Boot ID: {{boot_id_hex}}\n"
        "link/ether {{mac}} brd ff:ff:ff:ff:ff:ff\n"
        "inet {{private_ip}}/24 brd {{broadcast}} scope global ens3\n"
        "default via {{gateway}} dev ens3\n"
        "inet6 {{ipv6_link}}/64 scope link\n"
        "root=PARTUUID={{partuuid_1}} ro\n"
        "/dev/disk/by-uuid/{{uuid_15}} -> ../../vda15\n"
        "model name : AMD EPYC Processor\n"  # what the class fixes is left as the kernel said it
    )


def test_filling_needs_every_slot():
    assert hardware.fill(
        "{{hostname}} {{mac_upper}}", {"hostname": "web01", "mac": "52:54:00:ab:cd:ef"}
    ) == ("web01 52:54:00:AB:CD:EF")
    with pytest.raises(KeyError, match="no value for the slot 'gateway'"):
        hardware.fill("via {{gateway}}", {"hostname": "web01"})


def test_a_deployment_s_values_are_its_own_and_of_the_right_kind():
    facts = {
        "slots": {"uuid_1": "uuid", "uuid_15": "fat_id", "partuuid_1": "uuid", "hostname": "fact"}
    }
    host = {"hostname": "web01", "machine_id": "ab" * 16, "private_ip": "10.7.3.44"}
    a = hardware.slot_values(host, random.Random(1), facts)
    b = hardware.slot_values(host, random.Random(2), facts)
    assert a == hardware.slot_values(host, random.Random(1), facts) and a["mac"] != b["mac"]
    assert re.fullmatch(r"52:54:00(:[0-9a-f]{2}){3}", a["mac"])
    assert a["ipv6_link"] == hardware._eui64(a["mac"]) and a["ipv6_link"].startswith("fe80::50")
    assert (a["gateway"], a["broadcast"], a["network"]) == ("10.7.3.1", "10.7.3.255", "10.7.3.0")
    assert re.fullmatch(r"[0-9A-F]{4}-[0-9A-F]{4}", a["uuid_15"])
    assert re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", a["uuid_1"]
    )
    assert a["uuid_1"] != a["partuuid_1"] and a["boot_id_hex"] == a["boot_id"].replace("-", "")


def test_the_link_local_address_is_the_one_a_kernel_derives():
    assert hardware._eui64("52:54:00:6d:69:72") == "fe80::5054:ff:fe6d:6972"


def write_capture(base: Path) -> Path:
    cap = base / "kvm-test"
    (cap / "proc").mkdir(parents=True)
    (cap / "commands").mkdir()
    (cap / "identity.txt").write_text("".join(f"{k}={v}\n" for k, v in IDENTITY.items()))
    (cap / "source.sha512").write_text("abc123  debian-12-generic-amd64.qcow2\n")
    (cap / "proc/cpuinfo").write_text(
        "processor\t: 0\nmodel name\t: AMD EPYC Processor\n\nprocessor\t: 1\nmodel name\t: AMD EPYC Processor\n"
    )
    (cap / "proc/meminfo").write_text("MemTotal:        2014672 kB\nMemFree:         1800000 kB\n")
    (cap / "proc/cmdline").write_text("root=PARTUUID=b7255bda-17d6-4556-9acc-f54211365058 ro\n")
    (cap / "proc/uptime").write_text("30.52 20.11\n")
    rows = [
        "d\t755\t0\t0\t3200\t1794845281.1\t/dev\t",
        "c\t666\t0\t0\t0\t1794845281.1\t/dev/null\t",
        "l\t777\t0\t0\t10\t1794845281.1\t/dev/disk/by-uuid/EEF4-1F19\t../../vda15",
        "f\t644\t0\t0\t12\t1794845281.1\t/dev/shm/guest.sh.tmp\t",
    ]
    (cap / "dev.tsv").write_text("\n".join(rows) + "\n")
    (cap / "proc.tsv").write_text(
        "d\t555\t0\t0\t0\t1.0\t/proc\t\nf\t444\t0\t0\t0\t1.0\t/proc/cpuinfo\t\nf\t444\t0\t0\t0\t1.0\t/proc/sys/kernel/a/b/c\t\n"
    )
    (cap / "boot.tsv").write_text("f\t644\t0\t0\t8000000\t1.0\t/boot/vmlinuz-6.1.0-54-amd64\t\n")
    (cap / "sys.tsv.gz").write_bytes(
        gzip.compress(
            b"d\t555\t0\t0\t0\t1.0\t/sys\t\nf\t444\t0\t0\t4096\t1.0\t/sys/class/net/ens3/address\t\n"
        )
    )
    (cap / "sysfiles.tsv").write_text("/sys/class/net/ens3/address\t52:54:00:6d:69:72\n")
    outputs = {
        "lscpu": ("Model name: AMD EPYC Processor\n", 0),
        "df": (
            "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/vda1 41000000 1000000 38000000 3% /\n",
            0,
        ),
        "lsblk": ("NAME MAJ:MIN RM SIZE RO TYPE MOUNTPOINTS\nvda 254:0 0 40G 0 disk \n", 0),
        "ip link": (
            "1: lo: <LOOPBACK>\n2: ens3: <BROADCAST>\n    link/ether 52:54:00:6d:69:72\n",
            0,
        ),
        "hostnamectl": (
            " Static hostname: mirage-capture-host\n Hardware Vendor: QEMU\n  Hardware Model: Standard PC\n",
            0,
        ),
        "systemd-detect-virt": ("kvm\n", 0),
        "blkid": (BLKID, 0),
        "ps aux": ("root 1 /sbin/init\nroot 612 /bin/sh /root/guest.sh\nroot 700 ps aux\n", 0),
        "lsusb": ("", 127),
    }
    for i, (argv, (text, code)) in enumerate(outputs.items(), 1):
        stem = cap / "commands" / f"{i:03d}"
        stem.with_suffix(".cmd").write_text(argv + "\n")
        stem.with_suffix(".out").write_text(text)
        stem.with_suffix(".err").write_text("sh: 1: lsusb: not found\n" if code else "")
        stem.with_suffix(".meta").write_text(f"{code} {3 + i}\n")
    return cap


def test_a_record_is_imported_the_same_way_every_time_with_nothing_of_the_recorder_left(tmp_path):
    cap = write_capture(tmp_path)
    class_file = tmp_path / "kvm-test.yaml"
    class_file.write_text(
        yaml.safe_dump({"id": "kvm-test", "about": "a test class", "vm": {"cpus": 2}})
    )
    facts = hardware.import_capture(cap, class_file, tmp_path / "out/kvm-test")
    first = {
        p.relative_to(tmp_path / "out"): p.read_bytes()
        for p in (tmp_path / "out").rglob("*")
        if p.is_file()
    }
    hardware.import_capture(cap, class_file, tmp_path / "out/kvm-test")
    again = {
        p.relative_to(tmp_path / "out"): p.read_bytes()
        for p in (tmp_path / "out").rglob("*")
        if p.is_file()
    }
    assert first == again

    assert (facts["cpu_model"], facts["cpus"], facts["memory_kb"]) == (
        "AMD EPYC Processor",
        2,
        2014672,
    )
    assert facts["disk"] == {"name": "vda", "size": "40G"} and facts["root_device"] == "/dev/vda1"
    assert (facts["interface"], facts["virtualisation"]) == ("ens3", "kvm")
    assert facts["slots"]["uuid_15"] == "fat_id" and facts["slots"]["uuid_1"] == "uuid"
    assert facts["commands_absent"] == ["lsusb"] and facts["image_sha512"] == "abc123"

    cls = hardware.HardwareClass.load("kvm-test", tmp_path / "out")
    everything = b"\n".join(first.values()).decode(errors="replace") + cls.listing("sys.tsv.gz")
    for own in (
        hardware.CAPTURE_HOSTNAME,
        hardware.CAPTURE_MAC,
        "EEF4-1F19",
        "guest.sh",
        IDENTITY["machine_id"],
    ):
        assert own not in everything, own
    assert cls.proc_files()["cmdline"] == "root=PARTUUID={{partuuid_1}} ro\n"
    assert "/dev/disk/by-uuid/{{uuid_15}}\t../../vda15" in cls.listing("dev.tsv")
    assert "guest" not in cls.listing("dev.tsv")  # the recording's own file is not a device
    # The listing of /proc stops two levels down; the change time is not kept.
    assert cls.listing("proc.tsv").splitlines() == [
        "d\t555\t0\t0\t0\t/proc\t",
        "f\t444\t0\t0\t0\t/proc/cpuinfo\t",
    ]
    assert cls.sysfiles() == {"/sys/class/net/ens3/address": "{{mac}}"}
    cmds = {c["argv"]: c for c in cls.commands()}
    assert "lsusb" not in cmds and cmds["ps aux"]["volatile"] and not cmds["lscpu"]["volatile"]
    assert cmds["ps aux"]["stdout"] == "root 1 /sbin/init\nroot 700 ps aux\n"
    assert cmds["hostnamectl"]["stdout"].startswith(" Static hostname: {{hostname}}\n")
    assert cmds["lscpu"]["ms"] == 4 and cmds["lscpu"]["exit_code"] == 0


# ------------------------------------------------------------------ the committed classes


@pytest.mark.parametrize("class_id", CLASSES)
def test_a_committed_class_is_whole_and_holds_nothing_of_its_recorder(class_id):
    cls = hardware.HardwareClass.load(class_id)
    vm = cls.facts["vm"]
    assert cls.facts["cpus"] == vm["cpus"] and cls.facts["virtualisation"] == "kvm"
    # The kernel keeps a little memory for itself: the total is just under what was given.
    assert 0.9 * vm["memory_mb"] * 1024 < cls.facts["memory_kb"] < vm["memory_mb"] * 1024
    assert cls.facts["disk"]["size"] == f"{vm['disk_gb']}G"
    proc = cls.proc_files()
    assert proc["cpuinfo"].count("processor\t:") == vm["cpus"]
    assert cls.facts["cpu_model"] in proc["cpuinfo"] and "hypervisor" in proc["cpuinfo"]
    text = "\n".join(proc.values()) + cls.listing("dev.tsv") + cls.listing("sys.tsv.gz")
    text += yaml.safe_dump(cls.commands())
    for own in (
        hardware.CAPTURE_HOSTNAME,
        hardware.CAPTURE_MAC,
        "10.0.2.",
        "guest.sh",
        "describe.service",
    ):
        assert own not in text, own
    assert set(hardware.SLOT.findall(text)) <= set(cls.facts["slots"]) | {"mac_upper"}
    dev = cls.listing("dev.tsv")
    disk = cls.facts["disk"]["name"]
    for node in ("null", "zero", "urandom", "tty", "ptmx", disk, f"{disk}1", "ttyS0"):
        assert re.search(rf"\t/dev/{node}\t", dev), node
    assert not re.search(r"\t/dev/(fd0|sr0)\t", dev)  # no drive a hosted machine lacks
    said = {c["argv"]: c for c in cls.commands()}
    assert said["nproc"]["stdout"].strip() == str(vm["cpus"])
    assert (
        f"/dev/{disk}1" in said["df -h"]["stdout"]
        and cls.facts["interface"] in said["ip a"]["stdout"]
    )


def test_there_are_three_classes_and_they_differ_in_their_hardware():
    assert len(CLASSES) >= 3
    facts = [hardware.HardwareClass.load(c).facts for c in CLASSES]
    assert len({f["cpu_model"] for f in facts}) == len(facts)
    assert len({f["memory_kb"] for f in facts}) == len(facts)
    # One kernel: the one the reference image has, so a profile and its class agree.
    ref = json.loads(generator.REFERENCE.read_text())["os"]["kernel"]
    assert {f["kernel_release"] for f in facts} == {f"{ref['abi']}-amd64"}


# ------------------------------------------------------------------ a deployment of a class


def rendered(tmp_path: Path, seed: int) -> tuple[dict, Path]:
    out = tmp_path / f"p{seed}"
    generator.render(PROFILE, seed, out)
    return json.loads((out / "host.json").read_text()), out / "cowrie"


def test_a_deployment_claims_one_class_and_says_so_everywhere(tmp_path):
    host, cowrie = rendered(tmp_path, 4242)
    cls = hardware.HardwareClass.load(host["hardware_class"])
    assert host["hardware"]["cpu_model"] == cls.facts["cpu_model"]
    proc = cowrie / "honeyfs/proc"
    assert (proc / "cpuinfo").read_text().count("processor\t:") == cls.facts["cpus"]
    assert f"MemTotal:{cls.facts['memory_kb']:>15} kB" in (proc / "meminfo").read_text()
    assert (proc / "version").read_text().strip() == host[
        "proc_version"
    ]  # the profile's, as before
    # What changes by the second is not served from a file.
    assert not (proc / "uptime").exists() and not (proc / "loadavg").exists()
    # Not one slot is left open, and this deployment's values are in.
    texts = [p.read_text(errors="replace") for p in cowrie.rglob("*") if p.is_file()]
    assert not any("{{" in t for t in texts)
    assert host["mac"] in (cowrie / "tree/sys.tsv").read_text() or host["mac"] in "".join(texts)
    iface = cls.facts["interface"]
    assert (cowrie / f"honeyfs/sys/class/net/{iface}/address").read_text().strip() == host["mac"]
    assert host["hostname"] in (cowrie / "txtcmds/usr/bin/dmesg").read_text()
    assert (cowrie / "txtcmds/usr/bin/nproc").read_text().strip() == str(cls.facts["cpus"])
    assert cls.facts["cpu_model"] in (cowrie / "txtcmds/usr/bin/lscpu").read_text()
    assert "txtcmds_path = /cowrie/deployment/txtcmds" in (cowrie / "cowrie.cfg").read_text()
    for tree in ("dev.tsv", "proc.tsv", "sys.tsv", "boot.tsv"):
        assert (cowrie / "tree" / tree).read_text().count("\n") > 10
    overlay = json.loads((cowrie / "fs-overlay.json").read_text())
    assert overlay["boot_epoch"] == host["boot_epoch"]


def test_one_seed_one_deployment_and_two_seeds_two_machines(tmp_path):
    a, a_dir = rendered(tmp_path, 7)
    again, again_dir = rendered(tmp_path / "again", 7)
    same = lambda d: {p.relative_to(d): p.read_bytes() for p in d.rglob("*") if p.is_file()}
    assert a == again and same(a_dir) == same(again_dir)
    seen = {}
    for seed in range(1, 40):
        host, _ = rendered(tmp_path, 1000 + seed)
        seen.setdefault(host["hardware_class"], host)
    assert set(seen) == set(CLASSES)  # every class is some deployment's
    macs = {h["mac"] for h in seen.values()}
    assert len(macs) == len(seen)


def test_a_profile_that_lists_no_classes_renders_as_it_always_did(tmp_path):
    profile = yaml.safe_load(PROFILE.read_text())
    del profile["hardware_classes"]
    plain = tmp_path / "plain.yaml"
    plain.write_text(yaml.safe_dump(profile))
    generator.render(plain, 4242, tmp_path / "plain")
    host = json.loads((tmp_path / "plain/host.json").read_text())
    with_class, _ = rendered(tmp_path, 4242)
    assert "hardware_class" not in host
    # The class is drawn apart from everything else: the same seed is the same host.
    for key in ("hostname", "private_ip", "machine_id", "boot_epoch", "deployment_id"):
        assert host[key] == with_class[key], key
    cowrie = tmp_path / "plain/cowrie"
    assert not (cowrie / "tree").exists() and not (cowrie / "txtcmds").exists()
    # Under /proc only what the profile itself knows: the kernel's version line, and the few
    # files of /proc/sys that repeat the host's name and kernel. No boot ID without a class.
    proc = cowrie / "honeyfs/proc"
    assert sorted(p.name for p in proc.iterdir()) == ["sys", "version"]
    assert sorted(str(p.relative_to(proc)) for p in proc.rglob("*") if p.is_file()) == [
        "sys/kernel/hostname",
        "sys/kernel/osrelease",
        "sys/kernel/ostype",
        "sys/kernel/version",
        "version",
    ]
