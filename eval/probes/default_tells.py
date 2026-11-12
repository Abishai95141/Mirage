"""Default-tell checks (spec 1.3): does a decoy still look like an out-of-the-box honeypot?

    uv run python -m eval.probes.default_tells [--ssh 127.0.0.1:2222] [--http 127.0.0.1:8081]
        [--redis 127.0.0.1:6380] [--mysql 127.0.0.1:3307] [--password PW] [--profile build/profile]

Each check compares the running decoy with the Debian 12 reference
(decoys/profiles/reference/debian-12.json) and reports pass, fail, or gap. A gap is a known
difference that no profile can fix (spec section 8); it does not fail the run. Phase 3's
fingerprint regression suite (3.4) extends this file.
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from eval.probes.ssh_probes import probe_kexinit

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "decoys/profiles/reference/debian-12.json"
COWRIE_DEFAULT_HOSTNAMES = {"svr04"}
FRAMEWORK_STRINGS = ("uvicorn", "starlette", "fastapi", "h11", "python", "werkzeug")


@dataclass
class Result:
    protocol: str
    check: str
    status: str  # pass | fail | gap
    detail: str = ""


class Shell:
    def __init__(self, host: str, port: int, user: str, password: str) -> None:
        import paramiko

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            host, port, user, password, look_for_keys=False, allow_agent=False, timeout=10
        )
        self.chan = self.client.invoke_shell(width=250)
        time.sleep(1)
        self._drain()

    def _drain(self) -> bytes:
        out = b""
        while self.chan.recv_ready():
            out += self.chan.recv(65536)
        return out

    def run(self, cmd: str, wait: float = 0.7) -> str:
        self.chan.send((cmd + "\n").encode())
        time.sleep(wait)
        text = self._drain().decode(errors="replace")
        text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text).replace("\r", "")
        lines = text.split("\n")[1:-1]  # drop the echoed command and the next prompt
        return "\n".join(lines).strip()

    def close(self) -> None:
        self.client.close()


def ssh_login_works(host: str, port: int, user: str, password: str) -> bool:
    import paramiko

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(host, port, user, password, look_for_keys=False, allow_agent=False, timeout=10)
        return True
    except paramiko.AuthenticationException:
        return False
    finally:
        c.close()


def check_ssh(
    target: str, password: str, ref: dict[str, Any], host_profile: dict[str, Any] | None
) -> list[Result]:
    host, port_s = target.rsplit(":", 1)
    port = int(port_s)
    r: list[Result] = []

    def add(check: str, ok: bool, detail: str = "", gap: bool = False) -> None:
        r.append(Result("ssh", check, "pass" if ok else ("gap" if gap else "fail"), detail))

    kex = probe_kexinit(host, port, samples=1)
    add("banner is the reference OpenSSH", kex["banner"] == ref["ssh"]["banner"], kex["banner"])
    for name, offered in kex["algorithms"].items():
        if name.startswith("languages"):
            continue
        extra = [a for a in offered if a not in ref["ssh"]["algorithms"][name]]
        add(f"{name} offers nothing OpenSSH 9.2p1 does not", not extra, ",".join(extra))
    add(
        "HASSH-server equals OpenSSH 9.2p1",
        kex["hassh_server"] == ref["ssh"]["hassh_server"],
        f"{kex['hassh_server']} (Twisted lacks chacha20, GCM, ETM MACs, sntrup761, strict KEX)",
        gap=True,
    )

    rejected = [not ssh_login_works(host, port, "root", secrets.token_hex(6)) for _ in range(5)]
    add("random root passwords rejected", all(rejected), f"{sum(rejected)}/5 rejected")
    add(
        "random user rejected",
        not ssh_login_works(host, port, f"u{secrets.token_hex(3)}", secrets.token_hex(6)),
    )

    sh = Shell(host, port, "root", password)
    try:
        hostname = sh.run("hostname")
        add("hostname is not a Cowrie default", hostname not in COWRIE_DEFAULT_HOSTNAMES, hostname)
        if host_profile:
            add("hostname is the profile's", hostname == host_profile["hostname"], hostname)
        passwd = sh.run("cat /etc/passwd", wait=1.0)
        add("no user phil", "phil:" not in passwd)
        add("no /home/phil", "phil" not in sh.run("ls /home"))
        ssh_v = sh.run("ssh -V")
        add("ssh -V agrees with the banner", ssh_v == ref["ssh"]["ssh_dash_v"], ssh_v)
        uname = sh.run("uname -a")
        k = ref["os"]["kernel"]
        add("kernel ABI is the reference's", f" {k['abi']}-" in uname, uname)
        add(
            "kernel build date matches the kernel version",
            f"Debian {k['package_version']} ({k['build_date']})" in uname,
            uname,
        )
        osr = sh.run("cat /etc/os-release")
        add(
            "/etc/os-release is the reference's",
            osr.splitlines()[:1] == ref["os"]["files"]["/etc/os-release"].splitlines()[:1],
            osr[:60],
        )
    finally:
        sh.close()
    return r


def http_raw(target: str, raw: bytes) -> dict[str, Any]:
    host, port = target.rsplit(":", 1)
    s = socket.create_connection((host, int(port)), timeout=5)
    s.sendall(raw)
    data = b""
    s.settimeout(3)
    try:
        while chunk := s.recv(65536):
            data += chunk
    except TimeoutError:
        pass
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    hdrs = [ln.split(":", 1) for ln in lines[1:] if ":" in ln]
    return {
        "raw": data.decode(errors="replace"),
        "status_line": lines[0],
        "header_order": [h[0] for h in hdrs],
        "headers": {h[0]: h[1].strip() for h in hdrs if h[0].lower() != "date"},
        "body": body.decode(errors="replace"),
    }


def check_http(target: str, ref: dict[str, Any]) -> list[Result]:
    ng = ref["nginx"]
    r: list[Result] = []
    h = b"Host: localhost\r\nUser-Agent: probe\r\nConnection: close\r\n"
    probes = {
        "404": b"GET /.env-does-not-exist HTTP/1.1\r\n" + h + b"\r\n",
        "413": b"POST / HTTP/1.1\r\n" + h + b"Content-Length: 1048577\r\n\r\n",
        "400_garbage": b"GARBAGE\r\n\r\n",
        "400_no_host": b"GET / HTTP/1.1\r\n\r\n",
    }
    seen = []
    for name, raw in probes.items():
        got, want = http_raw(target, raw), ng[name]
        seen.append(got["raw"])
        ok = (got["status_line"], got["header_order"], got["body"]) == (
            want["status_line"],
            want["header_order"],
            want["body"],
        )
        r.append(
            Result(
                "http",
                f"{name} page is nginx's byte for byte",
                "pass" if ok else "fail",
                got["status_line"],
            )
        )
    idx = http_raw(target, b"GET / HTTP/1.1\r\n" + h + b"\r\n")
    seen.append(idx["raw"])
    r.append(
        Result(
            "http",
            "200 header order is nginx's",
            "pass" if idx["header_order"] == ng["index"]["header_order"] else "fail",
            ",".join(idx["header_order"]),
        )
    )
    server = idx["headers"].get("Server")
    r.append(
        Result(
            "http",
            "Server header is the reference's",
            "pass" if server == ng["index"]["headers"]["Server"] else "fail",
            str(server),
        )
    )
    leaked = [s for s in FRAMEWORK_STRINGS if any(s in x.lower() for x in seen)]
    r.append(
        Result(
            "http",
            "no framework names in any response",
            "pass" if not leaked else "fail",
            ",".join(leaked),
        )
    )
    return r


def _hostport(target: str) -> tuple[str, int]:
    host, _, port = target.rpartition(":")
    return host, int(port)


def _resp_cmd(sock: socket.socket, *args: str) -> bytes:
    """Send one RESP command and return its reply bytes (simple, error, integer or bulk)."""
    wire = f"*{len(args)}\r\n".encode()
    for a in args:
        wire += f"${len(a)}\r\n{a}\r\n".encode()
    sock.sendall(wire)
    buf = b""
    while b"\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    if buf.startswith(b"$") and b"\r\n" in buf:
        n = int(buf[1 : buf.index(b"\r\n")])
        need = buf.index(b"\r\n") + 2 + max(n, 0) + 2
        while len(buf) < need:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    return buf


def check_redis(target: str, ref: dict[str, Any]) -> list[Result]:
    replies = ref["redis"]["replies"]
    version = re.search(r"v=(\S+)", ref["redis"]["version"])
    want_version = version.group(1) if version else ""
    r: list[Result] = []
    with socket.create_connection(_hostport(target), timeout=5) as sock:
        info = _resp_cmd(sock, "INFO", "server").decode(errors="replace")
        got = re.search(r"redis_version:(\S+)", info)
        r.append(
            Result(
                "redis",
                "redis_version is the reference's",
                "pass" if got and got.group(1) == want_version else "fail",
                got.group(1) if got else "no redis_version",
            )
        )
        bad = []
        for _ in range(5):
            word = "x" + secrets.token_hex(4)
            reply = _resp_cmd(sock, word, "a").decode(errors="replace")
            want = f"-ERR unknown command '{word}', with args beginning with: 'a' \r\n"
            if reply != want:
                bad.append(reply.strip())
        r.append(
            Result(
                "redis",
                "unknown commands get Redis 7.0's error, byte for byte",
                "pass" if not bad else "fail",
                "; ".join(bad[:2]),
            )
        )
        count = _resp_cmd(sock, "COMMAND", "COUNT")
        r.append(
            Result(
                "redis",
                "COMMAND COUNT is the reference's",
                "pass" if count == replies["command_count"].encode() else "fail",
                count.decode(errors="replace").strip(),
            )
        )
    return r


def check_mysql(target: str, ref: dict[str, Any]) -> list[Result]:
    import pymysql

    hs = ref["mysql"]["handshake"]
    r: list[Result] = []
    with socket.create_connection(_hostport(target), timeout=5) as sock:
        header = b""
        while len(header) < 4:
            header += sock.recv(4 - len(header))
        n = header[0] | header[1] << 8 | header[2] << 16
        payload = b""
        while len(payload) < n:
            payload += sock.recv(n - len(payload))
    end = payload.index(b"\0", 1)
    version = payload[1:end].decode(errors="replace")
    i = end + 1 + 4 + 8 + 1
    cap_lo = int.from_bytes(payload[i : i + 2], "little")
    cap_hi = int.from_bytes(payload[i + 5 : i + 7], "little")
    caps = cap_lo | cap_hi << 16
    r.append(
        Result(
            "mysql",
            "handshake version is the reference's",
            "pass" if version == hs["server_version"] else "fail",
            version,
        )
    )
    r.append(
        Result(
            "mysql",
            "handshake capabilities are the reference's",
            "pass" if caps == hs["capabilities"] else "fail",
            hex(caps),
        )
    )
    host, port = _hostport(target)
    try:
        pymysql.connect(
            host=host, port=port, user="root", password=secrets.token_hex(8), connect_timeout=5
        ).close()
        status, detail = "fail", "a random root password was accepted"
    except pymysql.MySQLError as e:
        ok = e.args[0] == 1045 and re.fullmatch(
            r"Access denied for user 'root'@'[^']+' \(using password: YES\)", str(e.args[1])
        )
        status, detail = ("pass" if ok else "fail"), f"{e.args[0]} {e.args[1]}"
    r.append(Result("mysql", "wrong password gets MariaDB's 1045 text", status, detail))
    return r


def run(
    ssh: str | None,
    http: str | None,
    password: str | None,
    profile: Path | None,
    redis: str | None = None,
    mysql: str | None = None,
) -> list[Result]:
    ref = json.loads(REFERENCE.read_text())
    host_profile = (
        json.loads((profile / "host.json").read_text())
        if profile and (profile / "host.json").exists()
        else None
    )
    out: list[Result] = []
    if ssh and password:
        out += check_ssh(ssh, password, ref, host_profile)
    if http:
        out += check_http(http, ref)
    if redis:
        out += check_redis(redis, ref)
    if mysql:
        out += check_mysql(mysql, ref)
    return out


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="default_tells")
    ap.add_argument("--ssh", default="127.0.0.1:2222")
    ap.add_argument("--http", default="127.0.0.1:8081")
    ap.add_argument("--redis", default="127.0.0.1:6380")
    ap.add_argument("--mysql", default="127.0.0.1:3307")
    ap.add_argument("--profile", type=Path, default=ROOT / "build/profile")
    ap.add_argument(
        "--password", help="a root password the decoy accepts (default: from the profile)"
    )
    args = ap.parse_args(argv)
    password = args.password
    if password is None and (args.profile / "cowrie/userdb.txt").exists():
        lines = (args.profile / "cowrie/userdb.txt").read_text().splitlines()
        password = next(ln.split(":", 2)[2] for ln in lines if ln.startswith("root:"))
    results = run(args.ssh, args.http, password, args.profile, args.redis, args.mysql)
    for res in results:
        print(
            f"{res.status.upper():4}  {res.protocol:<6} {res.check}"
            + (f"  [{res.detail}]" if res.detail and res.status != "pass" else "")
        )
    fails = sum(r.status == "fail" for r in results)
    passed = sum(r.status == "pass" for r in results)
    gaps = sum(r.status == "gap" for r in results)
    print(f"\n{passed} pass, {fails} fail, {gaps} known gap")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
