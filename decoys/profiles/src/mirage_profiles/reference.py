"""Extract reference facts from a real Debian 12 host (spec 1.3, decision P9).

``make profile-ref`` builds ``mirage/reference:debian-12`` (decoys/profiles/reference), runs it
with its ports on 127.0.0.1, probes the real OpenSSH, nginx, Redis and MariaDB, and writes
``decoys/profiles/reference/debian-12.json``. The decoys and the profile generator read every
version string, banner, error text and reply framing from that file; nothing is typed by hand.

Values that are per-host on a real machine (container hostname, Redis run_id, start times) are
recorded too, but the generator replaces them per deployment.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

IMAGE = "mirage/reference:debian-12"
OUT = Path(__file__).resolve().parents[2] / "reference" / "debian-12.json"


def sh(*args: str, check: bool = True) -> str:
    return subprocess.run(args, check=check, capture_output=True, text=True).stdout


class Container:
    def __init__(self) -> None:
        self.cid = sh(
            "docker", "run", "-d", "--rm",
            "-p", "127.0.0.1::22", "-p", "127.0.0.1::80", "-p", "127.0.0.1::3306", "-p", "127.0.0.1::6379",
            IMAGE,
        ).strip()  # fmt: skip

    def port(self, p: int) -> int:
        return int(sh("docker", "port", self.cid, f"{p}/tcp").splitlines()[0].rsplit(":", 1)[1])

    def exec(self, *cmd: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["docker", "exec", self.cid, *cmd], capture_output=True, text=True)

    def wait_ready(self, timeout: float = 120) -> None:
        end = time.time() + timeout
        while time.time() < end:
            if self.exec("test", "-f", "/ready").returncode == 0:
                return
            time.sleep(1)
        raise RuntimeError("reference container did not become ready")

    def stop(self) -> None:
        sh("docker", "stop", "-t", "2", self.cid, check=False)


# ---------------------------------------------------------------- raw TCP helpers


def exchange(port: int, data: bytes, wait: float = 1.0, read_first: bool = False) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        if read_first:
            s.recv(4096)
        if data:
            s.sendall(data)
        s.settimeout(wait)
        out = b""
        with contextlib.suppress(TimeoutError, ConnectionResetError):
            while chunk := s.recv(65536):
                out += chunk
        return out


def http(port: int, raw: bytes) -> dict[str, Any]:
    resp = exchange(port, raw, wait=1.0)
    head, _, body = resp.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    headers = [line.split(":", 1) for line in lines[1:] if ":" in line]
    return {
        "status_line": lines[0],
        "header_order": [h[0] for h in headers],
        "headers": {h[0]: h[1].strip() for h in headers if h[0].lower() != "date"},
        "body": body.decode(errors="replace"),
    }


def resp_cmd(*args: str) -> bytes:
    out = f"*{len(args)}\r\n".encode()
    for a in args:
        b = a.encode()
        out += f"${len(b)}\r\n".encode() + b + b"\r\n"
    return out


# ---------------------------------------------------------------- probes


def probe_os(c: Container) -> dict[str, Any]:
    files = {}
    for f in ("/etc/os-release", "/etc/issue", "/etc/issue.net", "/etc/debian_version"):
        files[f] = c.exec("cat", f).stdout
    kernel = c.exec("cat", "/ref-kernel.txt").stdout
    m = re.search(r"Depends: linux-image-(6\.\d+\.\d+-\d+)-(arm64|amd64)", kernel)
    v = re.search(r"Package: linux-image-(?:arm64|amd64)\nVersion: (\S+)", kernel)
    changelog = c.exec("cat", "/ref-kernel-changelog.txt").stdout
    d = re.search(r"^ -- .*>  (.+)$", changelog, re.M)
    build_date = None
    if d:
        from email.utils import parsedate_to_datetime

        build_date = parsedate_to_datetime(d.group(1)).strftime("%Y-%m-%d")
    return {
        "files": files,
        "kernel": {
            "abi": m.group(1) if m else None,  # e.g. 6.1.0-54
            "package_version": v.group(1).split("+")[0] if v else None,  # e.g. 6.1.190-1
            "build_date": build_date,  # uname: "#1 SMP PREEMPT_DYNAMIC Debian <ver> (<date>)"
        },
        "passwd": c.exec("cat", "/etc/passwd").stdout,
        "group": c.exec("cat", "/etc/group").stdout,
    }


def probe_ssh(c: Container, port: int) -> dict[str, Any]:
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
    from eval.probes.ssh_probes import probe_kexinit

    kex = probe_kexinit("127.0.0.1", port, samples=1)
    t = c.exec("sshd", "-T").stdout
    eff = dict(line.split(" ", 1) for line in t.splitlines() if " " in line)
    return {
        "banner": kex["banner"],
        "ssh_dash_v": c.exec("ssh", "-V").stderr.strip(),
        "hassh_server": kex["hassh_server"],
        "algorithms": kex["algorithms"],
        "sshd_effective": {
            k: eff.get(k)
            for k in ("ciphers", "macs", "kexalgorithms", "hostkeyalgorithms", "compression")
        },
    }


def probe_nginx(c: Container, port: int) -> dict[str, Any]:
    c.exec("mkdir", "-p", "/var/www/html/private")
    h = b"Host: localhost\r\nUser-Agent: probe\r\nConnection: close\r\n"
    return {
        "version": c.exec("nginx", "-v").stderr.strip(),
        "index": http(port, b"GET / HTTP/1.1\r\n" + h + b"\r\n"),
        "head": http(port, b"HEAD / HTTP/1.1\r\n" + h + b"\r\n"),
        "404": http(port, b"GET /.env HTTP/1.1\r\n" + h + b"\r\n"),
        "404_http10": http(port, b"GET /nope HTTP/1.0\r\n\r\n"),
        "403": http(port, b"GET /private/ HTTP/1.1\r\n" + h + b"\r\n"),
        "405": http(
            port,
            b"POST /index.nginx-debian.html HTTP/1.1\r\n" + h + b"Content-Length: 3\r\n\r\nabc",
        ),
        "413": http(port, b"POST / HTTP/1.1\r\n" + h + b"Content-Length: 1048577\r\n\r\n"),
        "400_garbage": http(port, b"GARBAGE\r\n\r\n"),
        "400_no_host": http(port, b"GET / HTTP/1.1\r\n\r\n"),
        "301_dir": http(port, b"GET /private HTTP/1.1\r\n" + h + b"\r\n"),
    }


REDIS_PROBES: dict[str, bytes] = {
    "ping": resp_cmd("PING"),
    "ping_inline": b"PING\r\n",
    "unknown": resp_cmd("FOO", "bar", "baz"),
    "unknown_noargs": resp_cmd("FOO"),
    "wrong_arity": resp_cmd("GET"),
    "auth_no_password": resp_cmd("AUTH", "hunter2"),
    "select_out_of_range": resp_cmd("SELECT", "16"),
    "select_1": resp_cmd("SELECT", "1"),
    "dbsize": resp_cmd("DBSIZE"),
    "keys_empty": resp_cmd("KEYS", "*"),
    "type_missing": resp_cmd("TYPE", "nokey"),
    "ttl_missing": resp_cmd("TTL", "nokey"),
    "get_missing": resp_cmd("GET", "nokey"),
    "set": resp_cmd("SET", "k", "v"),
    "get": resp_cmd("GET", "k"),
    "del": resp_cmd("DEL", "k"),
    "exists": resp_cmd("EXISTS", "k"),
    "config_get_dir": resp_cmd("CONFIG", "GET", "dir"),
    "config_get_dbfilename": resp_cmd("CONFIG", "GET", "dbfilename"),
    "config_get_all": resp_cmd("CONFIG", "GET", "*"),
    "config_set_bad": resp_cmd("CONFIG", "SET", "nosuch", "1"),
    "config_set_dir": resp_cmd("CONFIG", "SET", "dir", "/tmp"),
    "config_set_dbfilename": resp_cmd("CONFIG", "SET", "dbfilename", "x.rdb"),
    "config_set_maxclients": resp_cmd("CONFIG", "SET", "maxclients", "10000"),
    "config_bad_subcommand": resp_cmd("CONFIG", "FOO"),
    "client_list": resp_cmd("CLIENT", "LIST"),
    "scan_empty": resp_cmd("SCAN", "0"),
    "echo": resp_cmd("ECHO", "hello"),
    "eval_os": resp_cmd("EVAL", "os.execute('id')", "0"),
    "eval_return_string": resp_cmd("EVAL", "return 'x'", "0"),
    "bgsave": resp_cmd("BGSAVE"),
    "flushdb": resp_cmd("FLUSHDB"),
    "quit": resp_cmd("QUIT"),
    "module_load": resp_cmd("MODULE", "LOAD", "/tmp/exp.so"),
    "eval_cve_2022_0543": resp_cmd(
        "EVAL",
        'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); '
        'local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res',
        "0",
    ),
    "eval_simple": resp_cmd("EVAL", "return 1", "0"),
    "hello_2": resp_cmd("HELLO", "2"),
    "hello_3": resp_cmd("HELLO", "3"),
    "command_count": resp_cmd("COMMAND", "COUNT"),
    "client_setname": resp_cmd("CLIENT", "SETNAME", "probe"),
    "client_getname": resp_cmd("CLIENT", "GETNAME"),
    "flushall": resp_cmd("FLUSHALL"),
    "save": resp_cmd("SAVE"),
    "info": resp_cmd("INFO"),
    "info_server": resp_cmd("INFO", "server"),
    "bulk_too_big": b"*1\r\n$600000000\r\n",
    "inline_unknown": b"hello world\r\n",
    "http_on_redis": b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
}


def probe_redis(c: Container, port: int) -> dict[str, Any]:
    out: dict[str, Any] = {"version": c.exec("redis-server", "--version").stdout.strip()}
    replies = {}
    for name, payload in REDIS_PROBES.items():
        replies[name] = exchange(port, payload, wait=0.6).decode(errors="replace")
    # Replication probe last: SLAVEOF points at TEST-NET (nothing answers), then INFO shows it.
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(resp_cmd("SLAVEOF", "192.0.2.10", "6379"))
    time.sleep(0.3)
    replies["slaveof"] = s.recv(4096).decode(errors="replace")
    s.sendall(resp_cmd("INFO", "replication"))
    time.sleep(0.3)
    replies["info_replication_after_slaveof"] = s.recv(65536).decode(errors="replace")
    s.sendall(resp_cmd("SLAVEOF", "NO", "ONE"))
    time.sleep(0.2)
    replies["slaveof_no_one"] = s.recv(4096).decode(errors="replace")
    s.close()
    out["replies"] = replies
    return out


def mysql_handshake(port: int) -> dict[str, Any]:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        hdr = s.recv(4)
        n = hdr[0] | hdr[1] << 8 | hdr[2] << 16
        pkt = b""
        while len(pkt) < n:
            pkt += s.recv(n - len(pkt))
    proto = pkt[0]
    ver_end = pkt.index(b"\0", 1)
    version = pkt[1:ver_end].decode()
    p = ver_end + 1
    (thread_id,) = struct.unpack("<I", pkt[p : p + 4])
    p += 4 + 8 + 1  # scramble part 1 + filler
    cap_lo, charset, status, cap_hi, auth_len = struct.unpack("<HBHHB", pkt[p : p + 8])
    p += 8
    reserved = pkt[p : p + 10]
    p += 10
    scramble2_len = max(13, auth_len - 8)
    p += scramble2_len
    plugin = pkt[p:].rstrip(b"\0").decode()
    return {
        "protocol": proto,
        "server_version": version,
        "thread_id_sample": thread_id,
        "capabilities": cap_lo | cap_hi << 16,
        "charset": charset,
        "status": status,
        "auth_data_len": auth_len,
        "reserved_hex": reserved.hex(),  # MariaDB puts extended capabilities in the last 4
        "auth_plugin": plugin,
        "packet_hex_len": len(pkt),
    }


MYSQL_QUERIES = [
    "SELECT @@version_comment LIMIT 1",
    "SELECT VERSION()",
    "SELECT @@version",
    "SELECT DATABASE()",
    "SELECT USER()",
    "SELECT CURRENT_USER()",
    "SELECT @@hostname",
    "SELECT @@datadir",
    "SELECT @@basedir",
    "SELECT @@secure_file_priv",
    "SELECT @@max_allowed_packet",
    "SELECT @@version_compile_os, @@version_compile_machine",
    "SHOW DATABASES",
    "SHOW GRANTS",
    "SHOW VARIABLES",
    "SHOW TABLES FROM probe",
    "DESCRIBE probe.t",
    "SHOW CREATE TABLE probe.t",
    "SELECT * FROM probe.nosuch",
    "SELECT nocol FROM probe.t",
    "SELEC 1",
    "SELECT 1 INTO OUTFILE '/tmp/mirage_probe.txt'",
    "SELECT 1 INTO DUMPFILE '/var/lib/mysql/mirage_probe.so'",
    "SELECT LOAD_FILE('/etc/passwd')",
    "CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so'",
    "SELECT COUNT(*) FROM probe.t",
    "USE nosuchdb",
    "SHOW TABLES",  # before any USE: no database selected
    "SELECT 1",
    "SELECT NOW()",
    "PREPARE s FROM 'SELECT 1'",
    "DROP DATABASE probe_nosuch",
    "INSERT INTO probe.nosuch VALUES (1)",
]


def probe_mysql(port: int) -> dict[str, Any]:
    import pymysql

    out: dict[str, Any] = {"handshake": mysql_handshake(port), "errors": {}, "queries": {}}
    for name, (user, pw) in {
        "denied_password": ("root", "wrong"),
        "denied_nopassword": ("admin", ""),
        "denied_unknown_user": ("nosuchuser", "x"),
    }.items():
        try:
            pymysql.connect(
                host="127.0.0.1", port=port, user=user, password=pw, connect_timeout=5
            ).close()
        except pymysql.err.OperationalError as e:
            out["errors"][name] = {"code": e.args[0], "message": e.args[1]}
    # Which error wins when the password is right but the database is wrong or not granted.
    for name, db in {"connect_unknown_db": "nosuchdb", "connect_denied_db": "mysql"}.items():
        try:
            pymysql.connect(
                host="127.0.0.1", port=port, user="probe", password="probe", database=db
            ).close()
        except pymysql.err.OperationalError as e:
            out["errors"][name] = {"code": e.args[0], "message": e.args[1]}
    conn = pymysql.connect(
        host="127.0.0.1", port=port, user="probe", password="probe", autocommit=True
    )
    cur = conn.cursor()
    for q in MYSQL_QUERIES:
        try:
            cur.execute(q)
            out["queries"][q] = {
                "columns": [d[0] for d in cur.description] if cur.description else [],
                "column_types": [d[1] for d in cur.description] if cur.description else [],
                "rows": [
                    list(
                        map(lambda v: v.decode(errors="replace") if isinstance(v, bytes) else v, r)
                    )
                    for r in cur.fetchall()
                ],
            }
        except pymysql.err.MySQLError as e:
            out["queries"][q] = {"error": {"code": e.args[0], "message": e.args[1]}}
    try:
        cur.execute("SELECT %s", ("x" * (17 * 1024 * 1024),))
    except pymysql.err.MySQLError as e:
        out["errors"]["max_allowed_packet"] = {"code": e.args[0], "message": str(e.args[1])}
    with contextlib.suppress(Exception):
        conn.close()
    return out


def extract() -> dict[str, Any]:
    c = Container()
    try:
        c.wait_ready()
        return {
            "image": IMAGE,
            "image_id": sh("docker", "image", "inspect", IMAGE, "--format", "{{.Id}}").strip(),
            "extracted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "container_hostname": c.exec("hostname").stdout.strip(),
            "os": probe_os(c),
            "ssh": probe_ssh(c, c.port(22)),
            "nginx": probe_nginx(c, c.port(80)),
            "redis": probe_redis(c, c.port(6379)),
            "mysql": probe_mysql(c.port(3306)),
        }
    finally:
        c.stop()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()
    ref = extract()
    args.out.write_text(json.dumps(ref, indent=1, sort_keys=True, default=str) + "\n")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
