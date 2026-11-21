#!/usr/bin/env python3
"""Boot one hardware class as a throwaway virtual machine and record what it says about itself.

    run.py <class.yaml> <debian-12-generic-amd64.qcow2> <out-dir>

Runs inside the capture image (Dockerfile here), with /dev/kvm. Debian's own cloud image is
booted twice on the class's virtual hardware, from a copy-on-write layer that is thrown away:

1. with a seed disc, so the system sets itself up as on any hosting company's machine (it
   grows its disk, takes its host name) and installs guest.sh to run at the next boot;
2. with nothing attached but the class's own hardware, so what guest.sh records is that
   hardware and nothing of ours. The record leaves through the serial console.

The machine has a network card and no network: QEMU's user-mode network with ``restrict=on``
gives it an address and reaches nothing.
"""

from __future__ import annotations

import base64
import io
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
BEGIN, END = "=====MIRAGE-CAPTURE-BEGIN=====", "=====MIRAGE-CAPTURE-END====="
# A name no real file or message holds, so it can be found and replaced in what is recorded.
HOSTNAME = "mirage-capture-host"
MAC = "52:54:00:6d:69:72"
USER_DATA = f"""#cloud-config
hostname: {HOSTNAME}
manage_etc_hosts: true
write_files:
  - path: /etc/systemd/system/describe.service
    content: |
      [Unit]
      After=multi-user.target
      [Service]
      Type=oneshot
      ExecStart=/bin/sh /root/guest.sh
      StandardOutput=null
      StandardError=null
      [Install]
      WantedBy=multi-user.target
runcmd:
  - mount -o ro /dev/sr0 /mnt
  - cp /mnt/guest.sh /mnt/commands.txt /root/
  - umount /mnt
  - systemctl enable describe.service
  - touch /etc/cloud/cloud-init.disabled
power_state:
  mode: poweroff
  delay: now
  timeout: 30
"""


def qemu(vm: dict, disk: Path, serial: Path, cdrom: Path | None, seconds: int) -> None:
    args = [
        "qemu-system-x86_64", "-enable-kvm", "-cpu", str(vm["cpu"]), "-smp", str(vm["cpus"]),
        "-m", str(vm["memory_mb"]), "-machine", str(vm["machine"]), "-display", "none",
        "-no-reboot", "-serial", f"file:{serial}",
        # Only the hardware named here: without this QEMU adds a floppy drive, an empty CD
        # drive and a parallel port, which no hosting company's machine has.
        "-nodefaults", "-vga", "std",
        "-nic", f"user,restrict=on,ipv6=off,model=virtio-net-pci,mac={MAC}",
    ]  # fmt: skip
    if vm["disk_bus"] == "scsi":
        args += [
            "-device", "virtio-scsi-pci,id=scsi0",
            "-drive", f"file={disk},if=none,id=d0,format=qcow2",
            "-device", "scsi-hd,drive=d0,bus=scsi0.0",
        ]  # fmt: skip
    else:
        args += ["-drive", f"file={disk},if=virtio,format=qcow2"]
    if cdrom is not None:
        args += ["-cdrom", str(cdrom)]
    done = subprocess.run(args, timeout=seconds, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise SystemExit(f"qemu ended with {done.returncode}: {done.stderr.strip()[-400:]}")


def main(class_file: str, image: str, out_dir: str) -> None:
    cls = yaml.safe_load(Path(class_file).read_text())
    vm, target = cls["vm"], Path(out_dir) / cls["id"]
    with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
        work = Path(tmp)
        disk = work / "disk.qcow2"
        subprocess.run(
            ["qemu-img", "create", "-q", "-f", "qcow2", "-b", image, "-F", "qcow2", str(disk),
             f"{vm['disk_gb']}G"],
            check=True,
        )  # fmt: skip
        seed = work / "seed"
        seed.mkdir()
        (seed / "user-data").write_text(USER_DATA)
        (seed / "meta-data").write_text(f"instance-id: {cls['id']}\nlocal-hostname: {HOSTNAME}\n")
        for name in ("guest.sh", "commands.txt"):
            shutil.copy(HERE / name, seed / name)
        iso = work / "seed.iso"
        subprocess.run(
            ["genisoimage", "-quiet", "-output", str(iso), "-volid", "cidata", "-joliet", "-rock",
             *(str(p) for p in sorted(seed.iterdir()))],
            check=True,
        )  # fmt: skip
        print(f"{cls['id']}: first boot (set-up)", flush=True)
        qemu(vm, disk, work / "serial1.log", iso, 420)
        print(f"{cls['id']}: second boot (the record)", flush=True)
        qemu(vm, disk, work / "serial2.log", None, 420)
        log = (work / "serial2.log").read_text(errors="replace")
        if BEGIN not in log or END not in log:
            tail = "\n".join(log.splitlines()[-15:])
            raise SystemExit(f"{cls['id']}: no record came out of the second boot:\n{tail}")
        payload = log.split(BEGIN, 1)[1].split(END, 1)[0]
        data = base64.b64decode("".join(payload.split()))
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for member in tar.getmembers():
                # Only plain files and directories under capture/, wherever the archive says.
                parts = Path(member.name).parts
                if (
                    parts[:1] != ("capture",)
                    or ".." in parts
                    or not (member.isfile() or member.isdir())
                ):
                    continue
                dest = target.joinpath(*parts[1:])
                if member.isdir():
                    dest.mkdir(parents=True, exist_ok=True)
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(tar.extractfile(member).read())
    count = sum(1 for p in target.rglob("*") if p.is_file())
    print(f"{cls['id']}: {count} files in {target}", flush=True)


if __name__ == "__main__":
    main(*sys.argv[1:4])
