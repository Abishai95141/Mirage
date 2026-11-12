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

from mirage_profiles.website import Site
from mirage_tokens import Minter

HERE = Path(__file__).resolve().parents[2]
REFERENCE = HERE / "reference" / "debian-12.json"

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
        return self.h

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
sensor_name = {self.deployment_id}
# Built into the image by decoys/ssh/build_fs.py from the reference root and this profile.
contents_path = /cowrie/deployment/honeyfs
# The stock image declares /cowrie/cowrie-git/etc a VOLUME, and an old anonymous volume would
# hide anything the build puts there; userdb.txt lives with the rest of the deployment.
etc_path = /cowrie/deployment/etc
download_limit_size = 52428800

[shell]
filesystem = /cowrie/deployment/fs.pickle
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
        for rel, text in files.items():
            p = fs / rel.lstrip("/")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
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
            {"remove": ["/home/phil"], "add": overlay, "install_epoch": install_epoch},
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
    args = ap.parse_args(argv)
    out = render(args.profile, args.seed, args.out, args.reference)
    print(f"rendered {out}")


if __name__ == "__main__":
    main()
