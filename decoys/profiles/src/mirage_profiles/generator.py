"""Profile generator (spec 1.3): one profile + one seed -> every file a deployment needs.

``mirage-profile render decoys/profiles/web-db.yaml --seed 7 --out build/profile``

writes::

    host.json      identity shared by every service (hostname, OS, kernel, deployment ID)
    http.json      routes, headers and error pages for the HTTP decoy
    redis.json     version, INFO, CONFIG, keyspace and reference replies for the Redis decoy
    mysql.json     handshake, variables, users, schema, rows and error texts for MariaDB
    tokens.json    every honeytoken planted below (spec 1.6)
    cowrie/        cowrie.cfg overrides, userdb.txt, honeyfs/ files and fs-overlay/ tree

Distribution facts come only from ``reference/debian-12.json`` (decision P9); this module
chooses per-deployment values (hostname, users, passwords, data) from the seed. The same
profile and seed give byte-identical output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import shutil
import string
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from faker import Faker

from mirage_profiles import hardware, hostkeys, library, processes
from mirage_profiles.website import Site
from mirage_tokens import Minter

HERE = Path(__file__).resolve().parents[2]
REFERENCE = HERE / "reference" / "debian-12.json"
ROOT = HERE.parents[1]  # the repository, in a checkout
RENDERED = HERE / "rendered"  # the render library and its inventory (phase 3 spec 3.2a)
# Reporting programs Cowrie answers from a fixed text or lacks, and the recorded command whose
# output a hardware class gives them instead.
CLASS_TEXT_COMMANDS = {
    "lscpu": "lscpu",
    "nproc": "nproc",
    "arch": "arch",
    "df": "df",
    "mount": "mount",
    "dmesg": "dmesg",
    "lsblk": "lsblk",
    "blkid": "blkid",
    "findmnt": "findmnt",
}

# Not extractable from a container. Debian 12's kernel is built with its own gcc-12; keep this
# in step with the reference image's gcc package if it moves.
KERNEL_COMPILER = "gcc-12 (Debian 12.2.0-14+deb12u1) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40"

# OpenSSH 9.2p1's algorithms that Twisted also implements; Cowrie may offer only these.
_SSH_CIPHERS_TWISTED = {"aes128-ctr", "aes192-ctr", "aes256-ctr"}
_SSH_MACS_TWISTED = {"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"}


def _dump(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False) + "\n")


def parse_resp_array(text: str) -> list[str]:
    """Parse a flat RESP2 array of bulk strings (CONFIG GET output)."""
    lines = text.split("\r\n")
    out, i = [], 1
    while i < len(lines) - 1:
        if lines[i].startswith("$"):
            out.append(lines[i + 1])
            i += 2
        else:
            i += 1
    return out


def parse_info(text: str) -> list[dict[str, Any]]:
    """INFO bulk reply -> [{"section": name, "fields": [[k, v], ...]}] in server order."""
    body = text.split("\r\n", 1)[1] if text.startswith("$") else text
    sections: list[dict[str, Any]] = []
    for line in body.split("\r\n"):
        if line.startswith("# "):
            sections.append({"section": line[2:], "fields": []})
        elif ":" in line and sections:
            k, v = line.split(":", 1)
            sections[-1]["fields"].append([k, v])
    return sections


class Render:
    def __init__(self, profile: dict[str, Any], seed: int, ref: dict[str, Any]) -> None:
        self.p = profile
        self.seed = seed
        self.ref = ref
        self.rng = random.Random(f"{profile['profile_id']}:{seed}")
        self.fake = Faker("en_US")
        self.fake.seed_instance(seed)
        self.deployment_id = (
            f"{profile['profile_id']}-{hashlib.sha256(str(seed).encode()).hexdigest()[:8]}"
        )
        self.tokens = Minter(self.deployment_id, random.Random(f"tokens:{seed}"))
        # A fixed epoch per seed keeps output reproducible: "now" is the render date's midnight.
        self.epoch = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=self.rng.randint(0, 300))

    # ------------------------------------------------------------------ identity
    def host(self) -> dict[str, Any]:
        k = self.ref["os"]["kernel"]
        machine = self.p.get("machine", "x86_64")
        arch = {"x86_64": "amd64", "aarch64": "arm64"}[machine]
        release = f"{k['abi']}-{arch}"
        build = f"#1 SMP PREEMPT_DYNAMIC Debian {k['package_version']} ({k['build_date']})"
        hostname = self.rng.choice(self.p["hostnames"])
        octets = [10, self.rng.randint(0, 31), self.rng.randint(0, 255), self.rng.randint(10, 250)]
        self.h = {
            "deployment_id": self.deployment_id,
            "profile_id": self.p["profile_id"],
            "seed": self.seed,
            "hostname": hostname,
            "private_ip": ".".join(map(str, octets)),
            "machine": machine,
            "arch": arch,
            "kernel_release": release,
            "kernel_build": build,
            "proc_version": f"Linux version {release} (debian-kernel@lists.debian.org) ({KERNEL_COMPILER}) {build}",
            "os_release": self.ref["os"]["files"]["/etc/os-release"],
            "boot_epoch": int(
                (
                    self.epoch
                    - timedelta(days=self.rng.randint(3, 120), seconds=self.rng.randint(0, 86399))
                ).timestamp()
            ),
            "machine_id": "".join(self.rng.choice("0123456789abcdef") for _ in range(32)),
            "timezone": "Etc/UTC",
        }
        self._hardware()
        self._library()
        return self.h

    def _hardware(self) -> None:
        """Pick the machine this deployment claims to be (phase 3 spec 3.2a, R6), where the
        profile lists hardware classes. The choice and the deployment's own values for the
        class's slots are drawn from a generator of their own, so that a seed gives the same
        host name, users and site as before classes existed."""
        self.hw: hardware.HardwareClass | None = None
        self.hw_values: dict[str, str] = {}
        choices = self.p.get("hardware_classes") or []
        if not choices:
            return
        rng = random.Random(f"hardware:{self.p['profile_id']}:{self.seed}")
        self.hw = hardware.HardwareClass.load(rng.choice(sorted(choices)))
        facts = self.hw.facts
        if facts["kernel_release"] != self.h["kernel_release"]:
            raise ValueError(
                f"hardware class {self.hw.id} was recorded on kernel {facts['kernel_release']}; "
                f"the profile claims {self.h['kernel_release']}. Record the class again."
            )
        self.hw_values = hardware.slot_values(self.h, rng, facts)
        self.h["hardware_class"] = self.hw.id
        self.h["hardware"] = {
            k: facts[k]
            for k in ("cpu_model", "cpus", "memory_kb", "disk", "root_device", "interface",
                      "virtualisation", "hardware_vendor", "hardware_model")
        }  # fmt: skip
        self.h["mac"] = self.hw_values["mac"]
        self.h["boot_id"] = self.hw_values["boot_id"]

    def _processes(self) -> dict[str, Any] | None:
        """This deployment's process list (``mirage_profiles.processes``), or None where the
        profile has no hardware class or its class recorded none: the decoy then keeps what
        it printed before."""
        if self.hw is None:
            return None
        said = {c["argv"]: c for c in self.hw.commands()}
        if not {"ps -ef", "ps aux"} <= set(said):
            return None
        return processes.table(
            said["ps -ef"]["stdout"],
            said["ps aux"]["stdout"],
            self.hw.facts["cpus"],
            self.hw.facts["memory_kb"],
            str(self.seed),
            private_ip=str(self.h.get("private_ip", "")),
            interface=str(self.hw.facts.get("interface", "")),
        )

    def _library(self) -> None:
        """This deployment's render library (phase 3 spec 3.2a): the entries of its class and
        the ones every class shares, with its own values in their slots, each checked against
        its record. Also what the decoy needs to answer for the files under /proc that change
        by the second: the class's own record of them and how long that machine had been up."""
        values = {
            "hostname": self.h["hostname"],
            "machine_id": self.h["machine_id"],
            "private_ip": self.h["private_ip"],
            **self.hw_values,
        }
        known = {"nginx version": self.ref["nginx"]["version"].rsplit("/", 1)[-1]}
        entries = library.load(self.hw.id if self.hw else None)
        self.rendered = library.render_for(entries, values, self.hw, known)
        self.rendered["hardware_class"] = self.hw.id if self.hw else None
        if self.hw is not None:
            proc = self.hw.proc_files()
            self.rendered["proc"] = {
                "recorded_uptime_s": self.hw.facts["recorded_uptime_s"],
                "loadavg": proc.get("loadavg", ""),
                "stat": hardware.fill(proc.get("stat", ""), self.hw_values),
            }
        self.h["render_library"] = {
            "version": self.rendered["version"],
            "entries": len(self.rendered["entries"]),
        }

    def hardware_files(self) -> dict[str, str]:
        """What the class puts under /proc and /sys, with this deployment's values. Left out:
        the files that change by the second (uptime, load, the tick counters), which a file
        cannot serve truthfully."""
        if self.hw is None:
            return {}
        skip = {"uptime", "loadavg", "stat"}
        files = {
            f"/proc/{name}": hardware.fill(text, self.hw_values)
            for name, text in self.hw.proc_files().items()
            if name not in skip
        }
        for path, text in self.hw.sysfiles().items():
            files[path] = hardware.fill(text, self.hw_values) + "\n"
        return files

    def token_paths(self) -> list[str]:
        """The SSH decoy's files that hold a planted token."""
        return sorted(
            {
                place.strip()[len("ssh:") :]
                for token in self.tokens.tokens
                for place in str(token.planted_at).split(",")
                if place.strip().startswith("ssh:/")
            }
        )

    def responder(self, tokens: list[dict[str, Any]]) -> dict[str, Any]:
        """What the responder may know of this host (phase 3 spec 3.2b): only what a user
        logged in to it could read for themselves, and no secret. It goes into the model's
        prompt. The planted tokens appear as the paths that hold them, never as values: the
        responder must not let an answer's operations touch those files."""
        h = self.h
        pretty = re.search(r'PRETTY_NAME="([^"]+)"', h["os_release"])
        token_paths = sorted(
            {
                place.strip()[len("ssh:") :]
                for token in tokens
                for place in str(token.get("planted_at", "")).split(",")
                if place.strip().startswith("ssh:/")
            }
        )
        hardware_facts = h.get("hardware") or {}
        maria = re.search(r"(\d+\.\d+\.\d+)-MariaDB", self._mysql["server_version"])
        redis = re.search(r"v=(\S+)", self.ref["redis"]["version"])
        return {
            "version": 1,
            "deployment_id": self.deployment_id,
            "hostname": h["hostname"],
            "os": pretty.group(1) if pretty else "Debian GNU/Linux 12 (bookworm)",
            "kernel": f"Linux {h['kernel_release']} {h['kernel_build']} {h['machine']}",
            "kernel_release": h["kernel_release"],
            "arch": h["arch"],
            "address": h["private_ip"],
            "timezone": h["timezone"],
            "hardware": {
                k: hardware_facts[k]
                for k in ("cpu_model", "cpus", "memory_kb", "virtualization")
                if k in hardware_facts
            },
            "users": [{"name": "root", "uid": 0, "home": "/root"}]
            + [
                {"name": u["name"], "uid": u["uid"], "home": f"/home/{u['name']}"}
                for u in self.regular
            ],
            "services": [
                {
                    "name": "sshd",
                    "version": self.ref["ssh"]["ssh_dash_v"].split(",")[0],
                    "port": 22,
                },
                {
                    "name": "nginx",
                    "version": self.ref["nginx"]["version"].rsplit("/", 1)[-1],
                    "port": 80,
                },
                {"name": "mariadb", "version": maria.group(1) if maria else "", "port": 3306},
                {"name": "redis-server", "version": redis.group(1) if redis else "", "port": 6379},
            ],
            "token_paths": token_paths,
        }

    def kernel_files(self) -> dict[str, str]:
        """The few files under /proc/sys that say who this host is, from what the profile
        already holds. The hardware classes did not record /proc/sys, so the rest of it is
        absent; these are the ones people read, and every one is a fact stated elsewhere."""
        files = {
            "/proc/sys/kernel/hostname": self.h["hostname"],
            "/proc/sys/kernel/osrelease": self.h["kernel_release"],
            "/proc/sys/kernel/ostype": "Linux",
            "/proc/sys/kernel/version": self.h["kernel_build"],
        }
        if self.h.get("boot_id"):
            files["/proc/sys/kernel/random/boot_id"] = self.h["boot_id"]
        return {path: text + "\n" for path, text in files.items()}

    def users(self) -> None:
        n = self.rng.randint(self.p["regular_users"]["min"], self.p["regular_users"]["max"])
        names: list[str] = []
        while len(names) < n:
            u = re.sub(r"[^a-z]", "", self.fake.first_name().lower())[:12]
            if u and u not in names and u not in {"root", "admin", "test", "phil"}:
                names.append(u)
        self.regular = [
            {
                "name": u,
                "uid": 1000 + i,
                "gecos": f"{u.capitalize()},,,",
                "password": self.tokens.password(12),
            }
            for i, u in enumerate(names)
        ]
        self.root_passwords = self.rng.sample(self.p["root_passwords"], self.rng.randint(1, 3))
        # Web application database credentials: the honeytoken chain of Gate 1 test 5.
        self.db_user = self.rng.choice(["wp_user", "wordpress", "wpadmin", "webapp"])
        self.db_cred = self.tokens.credential(
            self.db_user,
            "ssh:/var/www/html/.env, ssh:/var/www/html/wp-config.php, http:/.env, redis:app:config",
        )
        self.db_name = "wordpress"

    # ------------------------------------------------------------------ cowrie
    def cowrie(self, out: Path) -> None:
        d = out / "cowrie"
        ssh = self.ref["ssh"]
        algos = ssh["algorithms"]
        ciphers = [c for c in algos["encryption_s2c"] if c in _SSH_CIPHERS_TWISTED]
        macs = [m for m in algos["mac_s2c"] if m in _SSH_MACS_TWISTED]
        comp = [c for c in algos["compression_s2c"] if c in {"none", "zlib@openssh.com"}]
        version = ssh["banner"]  # SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10
        cfg = f"""# Rendered by mirage-profile for {self.deployment_id}. Do not edit; re-render.
# Read as /etc/cowrie/cowrie.cfg; compose/cowrie/cowrie.cfg (etc/cowrie.cfg) layers on top.
[honeypot]
hostname = {self.h["hostname"]}
# The address this host says it has, wherever a command shows one (SSH_CONNECTION among
# them). Left out, Cowrie asks the kernel for a route to the internet, finds none in a
# container with no way out, and falls back to 192.168.0.1 on every deployment.
internet_facing_ip = {self.h["private_ip"]}
sensor_name = {self.deployment_id}
# Built into the image by decoys/ssh/build_fs.py from the reference root and this profile.
contents_path = /cowrie/deployment/honeyfs
# The stock image declares /cowrie/cowrie-git/etc a VOLUME, and an old anonymous volume would
# hide anything the build puts there; userdb.txt lives with the rest of the deployment.
etc_path = /cowrie/deployment/etc
# Fixed-text commands of this deployment's hardware class; looked up before Cowrie's own.
txtcmds_path = /cowrie/deployment/txtcmds
download_limit_size = 52428800

[shell]
filesystem = /cowrie/deployment/fs.pickle
# The builder gives every symbolic link the text it has on the reference host (`bin ->
# usr/bin`), where Cowrie's own tool records the place it ends up. The fork resolves such a
# tree's relative links from the directory that holds them.
link_targets = verbatim
kernel_version = {self.h["kernel_release"]}
kernel_build_string = {self.h["kernel_build"]}
hardware_platform = {self.h["machine"]}
operating_system = GNU/Linux
ssh_version = {ssh["ssh_dash_v"]}

[ssh]
version = {version}
ciphers = {",".join(ciphers)}
macs = {",".join(macs)}
compression = {",".join(comp)}
# The host keys this deployment was given (mirage_profiles.hostkeys). The server presents
# them from the very files `cat /etc/ssh/ssh_host_*_key.pub` shows, so the two cannot differ.
rsa_public_key = /cowrie/deployment/honeyfs/etc/ssh/ssh_host_rsa_key.pub
rsa_private_key = /cowrie/deployment/honeyfs/etc/ssh/ssh_host_rsa_key
ecdsa_public_key = /cowrie/deployment/honeyfs/etc/ssh/ssh_host_ecdsa_key.pub
ecdsa_private_key = /cowrie/deployment/honeyfs/etc/ssh/ssh_host_ecdsa_key
ed25519_public_key = /cowrie/deployment/honeyfs/etc/ssh/ssh_host_ed25519_key.pub
ed25519_private_key = /cowrie/deployment/honeyfs/etc/ssh/ssh_host_ed25519_key

[mirage]
# This deployment's render library: answers to commands the emulator lacks, from real hosts.
render_library = /cowrie/deployment/rendered.json
# What `ps` shows here: the hardware class's own processes and the profile's services.
processes = /cowrie/deployment/processes.json
# The real checksums of the image's own programs (decoys/ssh/build_fs.py), for md5sum and
# the like: the emulated tree holds their names and sizes, not their bytes.
file_hashes = /cowrie/deployment/hashes.db
# Files that hold a planted token. No answer from the responder may change them, and their
# contents are never sent to it.
token_paths = {",".join(self.token_paths())}
"""
        d.mkdir(parents=True, exist_ok=True)
        (d / "cowrie.cfg").write_text(cfg)

        userdb = ["# user:x:password  (rendered; no wildcard entries)"]
        userdb += [f"root:x:{p}" for p in self.root_passwords]
        userdb += [f"{u['name']}:x:{u['password']}" for u in self.regular]
        (d / "userdb.txt").write_text("\n".join(userdb) + "\n")

        fs = d / "honeyfs"
        files = self.etc_files()
        files.update(self.web_files())
        files.update(self.hardware_files())
        files.update(self.kernel_files())
        for key in hostkeys.mint(str(self.seed), self.h["hostname"]):
            files[f"/etc/ssh/ssh_host_{key.kind}_key"] = key.private
            files[f"/etc/ssh/ssh_host_{key.kind}_key.pub"] = key.public
        for rel, text in files.items():
            p = fs / rel.lstrip("/")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        _dump(d / "rendered.json", self.rendered)
        table = self._processes()
        if table is not None:
            _dump(d / "processes.json", table)
        elif (d / "processes.json").exists():
            (d / "processes.json").unlink()
        # Cowrie answers a few reporting commands from a fixed text, the same on every
        # honeypot: an Intel CPU, a disk no profile has. Where the class recorded the command,
        # its text replaces Cowrie's. A text file cannot tell `df` from `df -h`: it is what
        # the command prints with no option, and the render library above answers the exact
        # forms the inventory names.
        texts = d / "txtcmds"
        if texts.exists():
            shutil.rmtree(texts)
        if self.hw is not None:
            said = {c["argv"]: c for c in self.hw.commands()}
            for program, argv in CLASS_TEXT_COMMANDS.items():
                if argv in said and said[argv]["exit_code"] == 0:
                    for prefix in ("usr/bin", "bin", "usr/sbin", "sbin"):
                        target = texts / prefix / program
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_text(hardware.fill(said[argv]["stdout"], self.hw_values))
        # The class's trees under /dev, /proc, /sys and /boot, for the filesystem builder
        # (decoys/ssh/build_fs.py): one line a node, this deployment's values in the names.
        tree = d / "tree"
        if tree.exists():
            shutil.rmtree(tree)
        if self.hw is not None:
            tree.mkdir()
            for name in ("dev.tsv", "proc.tsv", "boot.tsv", "sys.tsv.gz"):
                text = hardware.fill(self.hw.listing(name), self.hw_values)
                (tree / name.removesuffix(".gz")).write_text(text)
        # Directories to add to the reference tree when the fs pickle is built inside the
        # Cowrie image (decoys/ssh/build-fs.sh), with owner and mode.
        overlay = [
            {
                "path": f"/home/{u['name']}",
                "uid": u["uid"],
                "gid": u["uid"],
                "mode": 0o750,
                "dir": True,
            }
            for u in self.regular
        ]
        overlay += [
            {"path": p, "uid": 33, "gid": 33, "mode": 0o640, "dir": False} for p in self.web_files()
        ]
        overlay += [
            {"path": p, "uid": 0, "gid": 0, "mode": 0o644, "dir": False}
            for p in self.etc_files()
            if not p.startswith("/var/www")
        ]
        install_epoch = self.h["boot_epoch"] - 86400 * self.rng.randint(120, 600)
        _dump(
            d / "fs-overlay.json",
            {
                "remove": ["/home/phil"],
                "add": overlay,
                "install_epoch": install_epoch,
                # When the kernel's own nodes in /dev were made (decoys/ssh/build_fs.py).
                "boot_epoch": self.h["boot_epoch"],
            },
        )

    def etc_files(self) -> dict[str, str]:
        h, ref = self.h, self.ref["os"]
        passwd = ref["passwd"]
        group = ref["group"]
        for u in self.regular:
            passwd += (
                f"{u['name']}:x:{u['uid']}:{u['uid']}:{u['gecos']}:/home/{u['name']}:/bin/bash\n"
            )
            group += f"{u['name']}:x:{u['uid']}:\n"
        shadow_lines = []
        days = (self.epoch - datetime(1970, 1, 1, tzinfo=UTC)).days - self.rng.randint(30, 400)
        for line in passwd.splitlines():
            name = line.split(":", 1)[0]
            if name == "root" or any(u["name"] == name for u in self.regular):
                salt = "".join(
                    self.rng.choice(string.ascii_letters + string.digits + "./") for _ in range(22)
                )
                hsh = "".join(
                    self.rng.choice(string.ascii_letters + string.digits + "./") for _ in range(43)
                )
                shadow_lines.append(f"{name}:$y$j9T${salt}${hsh}:{days}:0:99999:7:::")
            else:
                shadow_lines.append(f"{name}:*:{days}:0:99999:7:::")
        return {
            "/etc/hostname": h["hostname"] + "\n",
            "/etc/hosts": f"127.0.0.1\tlocalhost\n127.0.1.1\t{h['hostname']}\n\n# The following lines are desirable for IPv6 capable hosts\n::1     localhost ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n",
            "/etc/passwd": passwd,
            "/etc/group": group,
            "/etc/shadow": "\n".join(shadow_lines) + "\n",
            "/etc/machine-id": h["machine_id"] + "\n",
            "/etc/os-release": ref["files"]["/etc/os-release"],
            "/etc/issue": ref["files"]["/etc/issue"],
            "/etc/issue.net": ref["files"]["/etc/issue.net"],
            "/etc/debian_version": ref["files"]["/etc/debian_version"],
            "/proc/version": h["proc_version"] + "\n",
        }

    def web_files(self) -> dict[str, str]:
        if not hasattr(self, "_web"):
            c = self.db_cred
            salt = "".join(self.rng.choice(string.ascii_letters + string.digits) for _ in range(64))
            self.site_title = f"{self.rng.choice(self.p['site']['title_words'])} {self.rng.choice(self.p['site']['title_suffix'])}"
            # One public domain for the site, its database rows and its cache keys.
            self.site_domain = self.fake.domain_name()
            env = (
                "APP_ENV=production\nAPP_DEBUG=false\n"
                f"DB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE={self.db_name}\n"
                f"DB_USERNAME={c.username}\nDB_PASSWORD={c.value}\n"
                "REDIS_HOST=127.0.0.1\nREDIS_PORT=6379\n"
            )
            wpconfig = (
                "<?php\n/** The base configuration for WordPress */\n"
                f"define( 'DB_NAME', '{self.db_name}' );\n"
                f"define( 'DB_USER', '{c.username}' );\n"
                f"define( 'DB_PASSWORD', '{c.value}' );\n"
                "define( 'DB_HOST', 'localhost' );\n"
                "define( 'DB_CHARSET', 'utf8mb4' );\n"
                "define( 'DB_COLLATE', '' );\n\n"
                f"define( 'AUTH_KEY',         '{salt}' );\n\n"
                "$table_prefix = 'wp_';\n\n"
                "define( 'WP_DEBUG', false );\n\n"
                "if ( ! defined( 'ABSPATH' ) ) {\n\tdefine( 'ABSPATH', __DIR__ . '/' );\n}\n\n"
                "require_once ABSPATH . 'wp-settings.php';\n"
            )
            self._web = {"/var/www/html/.env": env, "/var/www/html/wp-config.php": wpconfig}
        return self._web

    # ------------------------------------------------------------------ http
    def http(self) -> dict[str, Any]:
        ng = self.ref["nginx"]
        server = ng["404"]["headers"]["Server"]
        backup_url = self.tokens.url("http:/robots.txt", prefix="/backup-")
        title = self.site_title
        users = self._mysql["databases"][self.db_name]["wp_users"]["rows"]
        site = Site(
            self.seed,
            self.epoch,
            title,
            [{"id": r[0], "login": r[1], "email": r[3], "display_name": r[5]} for r in users],
            self.p["site"]["wordpress_version"],
            self.site_domain,
        )
        routes = [
            *site.routes(),
            {
                "path": "/robots.txt",
                "methods": ["GET", "HEAD"],
                "status": 200,
                "content_type": "text/plain",
                "body": f"User-agent: *\nDisallow: /wp-admin/\nDisallow: {backup_url.value}/\nAllow: /wp-admin/admin-ajax.php\n",
            },
            {
                "path": "/.env",
                "methods": ["GET", "HEAD"],
                "status": 200,
                "content_type": "application/octet-stream",
                "body": self.web_files()["/var/www/html/.env"],
            },
            {
                "path": "/.git/config",
                "methods": ["GET", "HEAD"],
                "status": 200,
                "content_type": "application/octet-stream",
                "body": "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
                f'[remote "origin"]\n\turl = git@{self.fake.domain_name()}:web/site.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n'
                '[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n',
            },
            {"path": "/server-status", "methods": ["GET", "HEAD"], "status": 403},
            {"path": "/backup.sql", "methods": ["GET", "HEAD"], "status": 403},
            {"path": backup_url.value + "/", "methods": ["GET", "HEAD"], "status": 403},
        ]
        errors = {}
        for code in ("400_garbage", "403", "404", "405", "413", "301_dir"):
            r = ng[code]
            errors[code.split("_")[0]] = {
                "status_line": r["status_line"],
                "header_order": r["header_order"],
                "headers": r["headers"],
                "body": r["body"],
            }
        idx = ng["index"]
        return {
            "deployment_id": self.deployment_id,
            "server": server,
            "routes": routes,
            "errors": errors,
            "ok_header_order": idx["header_order"],
            "max_body_bytes": 1048576,
            "last_modified_epoch": int(
                (self.epoch - timedelta(days=self.rng.randint(10, 200))).timestamp()
            ),
        }

    # ------------------------------------------------------------------ redis
    def redis(self) -> dict[str, Any]:
        rr = self.ref["redis"]["replies"]
        cfg_list = parse_resp_array(rr["config_get_all"])
        config = dict(zip(cfg_list[::2], cfg_list[1::2], strict=False))
        config.update(
            {
                "dir": "/var/lib/redis",
                "requirepass": "",
                "pidfile": "/run/redis/redis-server.pid",
                "logfile": "/var/log/redis/redis-server.log",
                "bind": "0.0.0.0",
                "protected-mode": "no",
            }
        )
        run_id = "".join(self.rng.choice("0123456789abcdef") for _ in range(40))
        pid = self.rng.randint(400, 1800)
        overrides = {
            "os": f"Linux {self.h['kernel_release']} {self.h['machine']}",
            "process_id": str(pid),
            "run_id": run_id,
            "executable": "/usr/bin/redis-server",
            "config_file": "/etc/redis/redis.conf",
        }
        info = parse_info(rr["info"])
        for sec in info:
            sec["fields"] = [[k, overrides.get(k, v)] for k, v in sec["fields"]]
        c = self.db_cred
        keyspace = {
            "0": {
                "app:config": {
                    "type": "hash",
                    "value": {
                        "db_host": "127.0.0.1",
                        "db_name": self.db_name,
                        "db_user": c.username,
                        "db_pass": c.value,
                    },
                },
                "wp:options:siteurl": {
                    "type": "string",
                    "value": f"https://{self.site_domain}",
                },
                "wp:options:blogname": {"type": "string", "value": self.site_title},
                **{
                    f"session:{self.fake.sha1()[:24]}": {
                        "type": "string",
                        "value": json.dumps(
                            {"uid": self.rng.randint(2, 90), "ip": self.fake.ipv4_public()}
                        ),
                    }
                    for _ in range(5)
                },
                "queue:mail": {
                    "type": "list",
                    "value": [
                        json.dumps({"to": self.fake.email(), "tpl": "reset"}) for _ in range(3)
                    ],
                },
            }
        }
        canned = {
            k: rr[k]
            for k in (
                "command_count",
                "module_load",
                "hello_3",
                "eval_cve_2022_0543",
                "auth_no_password",
                "select_out_of_range",
                "unknown",
                "unknown_noargs",
                "wrong_arity",
                "config_set_bad",
                "config_set_dir",
                "config_set_dbfilename",
                "config_bad_subcommand",
                "config_get_all",
                "bgsave",
                "bulk_too_big",
                "inline_unknown",
                "info_replication_after_slaveof",
            )
        }
        return {
            "deployment_id": self.deployment_id,
            "version": rr["info_server"].split("redis_version:", 1)[1].split("\r\n", 1)[0],
            "start_epoch": self.h["boot_epoch"] + self.rng.randint(20, 90),
            "requirepass": None,
            "config": config,
            "info": info,
            "info_dynamic": [
                "server_time_usec",
                "uptime_in_seconds",
                "uptime_in_days",
                "lru_clock",
                "connected_clients",
                "used_memory",
                "used_memory_human",
                "keyspace",
            ],
            "keyspace": keyspace,
            "reference_replies": canned,
            "max_bulk_bytes": 1048576,
        }

    # ------------------------------------------------------------------ mysql
    def mysql(self) -> dict[str, Any]:
        m = self.ref["mysql"]
        q = m["queries"]
        variables = {r[0]: r[1] for r in q["SHOW VARIABLES"]["rows"]}
        variables.update(
            {
                "hostname": self.h["hostname"],
                "max_allowed_packet": "1048576",
                "version_compile_machine": self.h["machine"],
                "pid_file": "/run/mysqld/mysqld.pid",
            }
        )
        c = self.db_cred
        reg = self.fake.date_time_between(
            start_date=self.epoch - timedelta(days=3 * 365),
            end_date=self.epoch - timedelta(days=365),
        )
        admin_email = self.fake.company_email()
        wp_users = {
            "create": "CREATE TABLE `wp_users` (\n  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,\n  `user_login` varchar(60) NOT NULL DEFAULT '',\n  `user_pass` varchar(255) NOT NULL DEFAULT '',\n  `user_email` varchar(100) NOT NULL DEFAULT '',\n  `user_registered` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',\n  `display_name` varchar(250) NOT NULL DEFAULT '',\n  PRIMARY KEY (`ID`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci",
            "columns": [
                ["ID", "bigint(20) unsigned", "NO", "PRI", None, "auto_increment"],
                ["user_login", "varchar(60)", "NO", "", "", ""],
                ["user_pass", "varchar(255)", "NO", "", "", ""],
                ["user_email", "varchar(100)", "NO", "", "", ""],
                ["user_registered", "datetime", "NO", "", "0000-00-00 00:00:00", ""],
                ["display_name", "varchar(250)", "NO", "", "", ""],
            ],
            "rows": [],
        }
        record_email = self.tokens.record(
            f"{self.fake.user_name()}.{self.rng.randint(10, 99)}@{self.fake.free_email_domain()}",
            "mysql:wordpress.wp_users",
        ).value
        for i, (login, email) in enumerate(
            [
                ("admin", admin_email),
                (self.fake.user_name(), record_email),
                (self.fake.user_name(), self.fake.email()),
            ],
            start=1,
        ):
            phpass = "$P$B" + "".join(
                self.rng.choice(string.ascii_letters + string.digits + "./") for _ in range(30)
            )
            wp_users["rows"].append(
                [
                    i,
                    login,
                    phpass,
                    email,
                    (reg + timedelta(days=40 * i)).strftime("%Y-%m-%d %H:%M:%S"),
                    login.capitalize(),
                ]
            )
        wp_options = {
            "create": "CREATE TABLE `wp_options` (\n  `option_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,\n  `option_name` varchar(191) NOT NULL DEFAULT '',\n  `option_value` longtext NOT NULL,\n  `autoload` varchar(20) NOT NULL DEFAULT 'yes',\n  PRIMARY KEY (`option_id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci",
            "columns": [
                ["option_id", "bigint(20) unsigned", "NO", "PRI", None, "auto_increment"],
                ["option_name", "varchar(191)", "NO", "", "", ""],
                ["option_value", "longtext", "NO", "", None, ""],
                ["autoload", "varchar(20)", "NO", "", "yes", ""],
            ],
            "rows": [
                [1, "siteurl", f"https://{self.site_domain}", "yes"],
                [2, "blogname", self.site_title, "yes"],
                [3, "admin_email", admin_email, "yes"],
                [4, "users_can_register", "0", "yes"],
            ],
        }
        customers = {
            "create": "CREATE TABLE `customers` (\n  `id` int(11) NOT NULL AUTO_INCREMENT,\n  `first_name` varchar(64) DEFAULT NULL,\n  `last_name` varchar(64) DEFAULT NULL,\n  `email` varchar(128) DEFAULT NULL,\n  `phone` varchar(32) DEFAULT NULL,\n  `city` varchar(64) DEFAULT NULL,\n  `created_at` datetime DEFAULT NULL,\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci",
            "columns": [
                ["id", "int(11)", "NO", "PRI", None, "auto_increment"],
                ["first_name", "varchar(64)", "YES", "", None, ""],
                ["last_name", "varchar(64)", "YES", "", None, ""],
                ["email", "varchar(128)", "YES", "", None, ""],
                ["phone", "varchar(32)", "YES", "", None, ""],
                ["city", "varchar(64)", "YES", "", None, ""],
                ["created_at", "datetime", "YES", "", None, ""],
            ],
            "rows": [
                [
                    i,
                    self.fake.first_name(),
                    self.fake.last_name(),
                    self.fake.email(),
                    self.fake.phone_number(),
                    self.fake.city(),
                    self.fake.date_time_between(
                        start_date=self.epoch - timedelta(days=2 * 365),
                        end_date=self.epoch - timedelta(days=1),
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                ]
                for i in range(1, self.p["crm_rows"] + 1)
            ],
        }
        # MariaDB's own grant format, from the reference SHOW GRANTS.
        native = lambda pw: (
            "*" + hashlib.sha1(hashlib.sha1(pw.encode()).digest()).hexdigest().upper()
        )
        users = [
            {
                "user": c.username,
                "host": "%",
                "password": c.value,
                "grants": [
                    f"GRANT USAGE ON *.* TO `{c.username}`@`%` IDENTIFIED BY PASSWORD '{native(c.value)}'",
                    f"GRANT ALL PRIVILEGES ON `{self.db_name}`.* TO `{c.username}`@`%`",
                    f"GRANT ALL PRIVILEGES ON `crm`.* TO `{c.username}`@`%`",
                ],
                "databases": [self.db_name, "crm"],
            },
        ]
        return {
            "deployment_id": self.deployment_id,
            "handshake": m["handshake"],
            "server_version": m["handshake"]["server_version"],
            "version": variables["version"],
            "version_comment": variables["version_comment"],
            "variables": variables,
            "users": users,
            "denied_root_over_tcp": True,  # Debian's root@localhost uses unix_socket
            "databases": {
                "information_schema": {},
                "mysql": {},
                "performance_schema": {},
                "sys": {},
                self.db_name: {"wp_users": wp_users, "wp_options": wp_options},
                "crm": {"customers": customers},
            },
            "errors": m["errors"],
            "reference_queries": {k: v for k, v in q.items() if k != "SHOW VARIABLES"},
            "max_allowed_packet": 1048576,
        }

    def render(self, out: Path) -> None:
        # Empty the directory rather than replace it: running containers bind-mount it, and a
        # mount of a deleted directory keeps showing the old files.
        out.mkdir(parents=True, exist_ok=True)
        for child in out.iterdir():
            shutil.rmtree(child) if child.is_dir() and not child.is_symlink() else child.unlink()
        _dump(out / "host.json", self.host())
        self.users()
        self.web_files()  # fixes the site title and domain, used by http, redis and mysql
        self._mysql = self.mysql()  # the site's WordPress users are its wp_users rows
        _dump(out / "http.json", self.http())
        self.cowrie(out)
        _dump(out / "redis.json", self.redis())
        _dump(out / "mysql.json", self._mysql)
        # minted_at is wall-clock; pin it to the epoch so renders stay byte-identical.
        toks = [
            t.to_row() | {"minted_at": self.epoch.strftime("%Y-%m-%dT%H:%M:%SZ")}
            for t in self.tokens.tokens
        ]
        _dump(out / "tokens.json", toks)
        # In a directory of its own: the responder is given this directory and nothing else
        # of the profile, which holds the decoys' passwords and the tokens' values.
        (out / "responder").mkdir(exist_ok=True)
        _dump(out / "responder" / "responder.json", self.responder(toks))


def render(profile_path: Path, seed: int, out: Path, reference: Path = REFERENCE) -> Path:
    profile = yaml.safe_load(profile_path.read_text())
    ref = json.loads(reference.read_text())
    Render(profile, seed, ref).render(out)
    return out


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage-profile")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("render", help="render a profile for one deployment")
    r.add_argument("profile", type=Path)
    r.add_argument("--seed", type=int, required=True)
    r.add_argument("--out", type=Path, required=True)
    r.add_argument("--reference", type=Path, default=REFERENCE)
    inv = sub.add_parser(
        "inventory", help="rank the commands the SSH decoy answers wrongly (phase 3 spec 3.2a)"
    )
    inv.add_argument("--corpus", type=Path, nargs="+", required=True, help="Cowrie JSON logs")
    inv.add_argument("--catalogue", type=Path, default=ROOT / "lab/catalogue")
    inv.add_argument("--scenarios", type=Path, default=ROOT / "lab/scenarios")
    inv.add_argument(
        "--split",
        type=Path,
        nargs="+",
        default=[ROOT / "eval/split.yaml", ROOT / "eval/split-depth.yaml"],
    )
    inv.add_argument("--sources", type=Path, default=RENDERED / "sources")
    inv.add_argument("--out", type=Path, default=RENDERED / "inventory.yaml")
    hw = sub.add_parser(
        "hardware", help="turn recorded hardware (build/hardware/<class>) into committed classes"
    )
    hw.add_argument("captures", type=Path, nargs="+", help="what capture.sh recorded, a class each")
    lib = sub.add_parser(
        "render-library", help="build the render library from its records (phase 3 spec 3.2a)"
    )
    lib.add_argument("--commands", action="store_true", help="list the commands to record")
    lib.add_argument("--coverage", action="store_true", help="report coverage; change nothing")
    lib.add_argument(
        "--candidates", type=Path, help="the responder's cached commands (JSON): promote them"
    )
    lib.add_argument(
        "--cached",
        type=Path,
        default=ROOT / "build/rendered/candidates.json",
        help="the same file, when building: cached answers are held to the records",
    )
    lib.add_argument("--records", type=Path, default=ROOT / "build/rendered/reference")
    lib.add_argument("--inventory", type=Path, default=RENDERED / "inventory.yaml")
    lib.add_argument("--catalogue", type=Path, default=ROOT / "lab/catalogue")
    lib.add_argument("--scenarios", type=Path, default=ROOT / "lab/scenarios")
    lib.add_argument("--held-out", type=Path, default=ROOT / "eval/split-depth.yaml")
    args = ap.parse_args(argv)
    if args.cmd == "render-library":
        raise SystemExit(write_library(args))
    if args.cmd == "inventory":
        print(write_inventory(args))
        return
    if args.cmd == "hardware":
        from mirage_profiles import hardware

        for capture in args.captures:
            class_file = hardware.HARDWARE / f"{capture.name}.yaml"
            facts = hardware.import_capture(capture, class_file, hardware.HARDWARE / capture.name)
            print(
                f"{facts['id']}: {facts['cpu_model']} x{facts['cpus']}, "
                f"{facts['memory_kb'] // 1024} MB, {facts['disk']['name']} {facts['disk']['size']}, "
                f"{facts['interface']}, {facts['virtualisation']}"
            )
        return
    out = render(args.profile, args.seed, args.out, args.reference)
    print(f"rendered {out}")


def write_inventory(args: argparse.Namespace) -> str:
    """Build the render inventory and write it; returns a one-line summary."""
    from mirage_profiles import inventory

    tables = inventory.Tables.load(
        args.sources / "emulator-commands.json", args.sources / "reference-commands.txt"
    )
    lab, used = inventory.lab_lines(args.catalogue, args.scenarios, args.split)
    corpus = [line for path in args.corpus for line in inventory.corpus_lines(path)]
    notes = {
        "corpus": {
            "what": "the public Cowrie corpus sample",
            "files": [p.name for p in args.corpus],
        },
        "lab": {
            "what": "lab procedures outside every test split, once for each step sending them",
            "steps_by_split": used,
        },
    }
    built = inventory.build({"corpus": corpus, "lab": lab}, tables, notes)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(built.dump())
    wrong = {name: note["wrongly_answered"] for name, note in built.sources.items()}
    return f"wrote {args.out}: {len(built.entries)} entries; wrongly answered {wrong}"


def write_library(args: argparse.Namespace) -> int:
    """Build the render library, or report on the committed one. Returns the exit status."""
    from mirage_profiles import inventory

    doc = yaml.safe_load(args.inventory.read_text())
    promoted = library.load_promoted()
    if args.commands:
        print("\n".join(e["argv"] for e in library.renderable(doc, promoted)))
        return 0
    if args.candidates is not None:
        # Promotion (spec 3.2b): what the responder's cache holds, added to promoted.yaml.
        cached = json.loads(args.candidates.read_text())
        excluded = library.load_excluded(RENDERED / "excluded.yaml")
        promoted, left = library.candidates(cached, doc, promoted, excluded)
        library.PROMOTED.write_text(library.dump_promoted(promoted))
        print(f"{library.PROMOTED}: {len(promoted)} commands promoted")
        for argv, why in sorted(left.items()):
            print(f"left: {argv[:80]}: {why}")
        return 0
    classes = [hardware.HardwareClass.load(c) for c in hardware.HardwareClass.available()]
    excluded = library.load_excluded(RENDERED / "excluded.yaml")
    status = 0
    if not args.coverage:
        records, identity = library.load_records(args.records)
        available = args.records / "available.txt"
        if available.exists():
            # What the reference host can run, for the inventory's next ranking.
            (RENDERED / "sources/reference-commands.txt").write_text(
                "# The commands a Debian 12 server of the reference image has: its shell's "
                "builtins and the\n# programs on root's PATH. Recorded by `make render-record`, "
                "written by `make render-library`;\n# one name a line.\n"
                + "\n".join(sorted(set(available.read_text().split())))
                + "\n"
            )
        built, problems = library.build(doc, records, identity, classes, excluded, promoted)
        # A promoted command the reference host gave no fixed answer to is no fault of the
        # library's: the list says why it was left, and it is not asked for again.
        names = sorted((p["argv"] for p in promoted), key=len, reverse=True)
        kept = []
        for problem in problems:
            argv = next((a for a in names if problem.startswith(a + ": ")), None)
            if argv is None:
                kept.append(problem)
                continue
            for entry in promoted:
                if entry["argv"] == argv:
                    entry["left"] = problem[len(argv) + 2 :]
        if len(kept) != len(problems):
            library.PROMOTED.write_text(library.dump_promoted(promoted))
        problems = kept
        if args.cached is not None and args.cached.exists():
            # Cached answers the reference host has now answered too: which are to go.
            verdicts = library.cache_verdicts(json.loads(args.cached.read_text()), records)
            evict = [v for v in verdicts if not v["same"]]
            out = args.records.parent / "evict.json"
            out.write_text(json.dumps(evict, indent=1))
            print(
                f"{len(verdicts)} cached answers held to the reference host: "
                f"{sum(1 for v in verdicts if v['same'])} the same, {len(evict)} to evict ({out})"
            )
        written = library.write(built, RENDERED / library.DISTRIBUTION)
        (RENDERED / "REVIEW.md").write_text(library.review(built, excluded, problems, identity))
        print(f"wrote {len(written)} entries and {RENDERED / 'REVIEW.md'}")
        for problem in problems:
            print(f"not built: {problem}")
        status = 1 if problems else 0
    answered: set[str] = set()
    for c in [None, *classes]:
        entries = library.load(c.id if c else None)
        answered |= {e.argv for e in entries}
        if c is not None:
            print(f"{c.id}: {len(entries)} entries, version {library.version(entries)}")
    tables = inventory.Tables.load(
        RENDERED / "sources/emulator-commands.json", RENDERED / "sources/reference-commands.txt"
    )
    held_out = library.held_out_lines(args.catalogue, args.scenarios, args.held_out)
    for name, c in library.coverage(doc, answered, held_out, tables).items():
        could = f"; a library could answer {c['a_library_could']}" if "a_library_could" in c else ""
        print(f"coverage, {name}: {c['answered']} of {c['of']} ({c['share']:.1%}){could}")
    return status


if __name__ == "__main__":
    main()
