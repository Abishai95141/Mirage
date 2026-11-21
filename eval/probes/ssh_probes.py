"""SSH transport fingerprint probes (spike S3; seed of the phase 3 probe suite).

Stdlib only, so it runs in any container that can reach a decoy. Each probe records what a
server does at the transport layer, below anything a Cowrie profile can change. Comparing a
decoy against a real OpenSSH build of the version the decoy claims shows its transport tells.

Probes follow Vetterl & Clayton, "Bitter Harvest" (WOOT '18): KEXINIT padding (OpenSSH zeroes
padding before encryption; Twisted fills it with random bytes) and replies to malformed or
unexpected client identification strings.

    python -m eval.probes.ssh_probes HOST:PORT [HOST:PORT ...]
"""

from __future__ import annotations

import hashlib
import json
import socket
import struct
import sys
import time
from typing import Any

from eval.probes.net import Target

CLIENT_ID = b"SSH-2.0-OpenSSH_9.6\r\n"
NAME_LISTS = [
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_c2s",
    "encryption_s2c",
    "mac_c2s",
    "mac_s2c",
    "compression_c2s",
    "compression_s2c",
    "languages_c2s",
    "languages_s2c",
]

# Client identification strings a real sshd and an emulator may treat differently.
BANNER_PROBES = {
    "version_2.2": b"SSH-2.2-OpenSSH_9.6\r\n",
    "version_1.5": b"SSH-1.5-OpenSSH_9.6\r\n",
    "version_1.99": b"SSH-1.99-OpenSSH_9.6\r\n",
    "no_cr": b"SSH-2.0-OpenSSH_9.6\n",
    "http_get": b"GET / HTTP/1.0\r\n\r\n",
    "garbage": b"\x00\xff\x00\xff" * 8 + b"\r\n",
    "overlong": b"SSH-2.0-" + b"A" * 300 + b"\r\n",
}


def _connect(target: Target, timeout: float = 5.0) -> socket.socket:
    return target.connect(timeout)


def _read_line(s: socket.socket) -> bytes:
    buf = b""
    while not buf.endswith(b"\n") and len(buf) < 512:
        ch = s.recv(1)
        if not ch:
            break
        buf += ch
    return buf


def _read_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"closed after {len(buf)} of {n} bytes")
        buf += chunk
    return buf


def _read_until_close(s: socket.socket, timeout: float) -> tuple[bytes, bool, float]:
    """Read until the server closes or ``timeout``. Returns (data, closed, seconds)."""
    s.settimeout(0.2)
    t0 = time.monotonic()
    data = b""
    while time.monotonic() - t0 < timeout:
        try:
            chunk = s.recv(4096)
        except TimeoutError:
            continue
        except OSError:
            return data, True, time.monotonic() - t0
        if not chunk:
            return data, True, time.monotonic() - t0
        data += chunk
    return data, False, time.monotonic() - t0


def _printable(b: bytes, limit: int = 160) -> str:
    return "".join(chr(c) if 32 <= c < 127 else f"\\x{c:02x}" for c in b[:limit])


def _parse_kexinit(packet: bytes, padding_len: int) -> dict[str, Any]:
    payload = packet[: len(packet) - padding_len]
    padding = packet[len(packet) - padding_len :]
    assert payload[0] == 20, f"expected SSH_MSG_KEXINIT (20), got {payload[0]}"
    off = 17  # msg byte + 16-byte cookie
    lists: dict[str, list[str]] = {}
    for name in NAME_LISTS:
        (n,) = struct.unpack(">I", payload[off : off + 4])
        lists[name] = payload[off + 4 : off + 4 + n].decode().split(",") if n else []
        off += 4 + n
    first_kex_follows = payload[off]
    (reserved,) = struct.unpack(">I", payload[off + 1 : off + 5])
    hassh_server_src = ";".join(
        ",".join(lists[k])
        for k in ("kex_algorithms", "encryption_s2c", "mac_s2c", "compression_s2c")
    )
    return {
        "padding_length": padding_len,
        "padding_all_zero": padding == b"\x00" * padding_len,
        "padding_hex": padding.hex(),
        "first_kex_packet_follows": first_kex_follows,
        "reserved": reserved,
        "hassh_server": hashlib.md5(hassh_server_src.encode(), usedforsecurity=False).hexdigest(),
        "algorithms": lists,
    }


def probe_kexinit(target: Target | str, samples: int = 3) -> dict[str, Any]:
    """Banner, KEXINIT timing and contents, over ``samples`` fresh connections."""
    target = Target.parse(target)
    runs = []
    for _ in range(samples):
        s = _connect(target)
        banner = _read_line(s)
        # Does the server send KEXINIT before it has seen our identification string?
        s.settimeout(1.5)
        try:
            early = s.recv(5)
        except TimeoutError:
            early = b""
        s.settimeout(5)
        s.sendall(CLIENT_ID)
        header = early + _read_exact(s, 5 - len(early)) if len(early) < 5 else early[:5]
        packet_len, padding_len = struct.unpack(">IB", header)
        packet = _read_exact(s, packet_len - 1)
        s.close()
        runs.append(
            {
                "banner": banner,
                "kexinit_before_client_id": bool(early),
                "packet_length": packet_len,
                **_parse_kexinit(packet, padding_len),
            }
        )
    first = runs[0]
    return {
        "banner": first["banner"].decode(errors="replace").rstrip("\r\n"),
        "banner_line_ending": "CRLF" if first["banner"].endswith(b"\r\n") else "LF",
        "kexinit_before_client_id": first["kexinit_before_client_id"],
        "padding_lengths": [r["padding_length"] for r in runs],
        "padding_all_zero": all(r["padding_all_zero"] for r in runs),
        "padding_sample_hex": first["padding_hex"],
        "packet_length_stable": len({r["packet_length"] for r in runs}) == 1,
        "first_kex_packet_follows": first["first_kex_packet_follows"],
        "hassh_server": first["hassh_server"],
        "algorithms": first["algorithms"],
    }


def probe_banners(target: Target | str) -> dict[str, Any]:
    target = Target.parse(target)
    out = {}
    for name, line in BANNER_PROBES.items():
        s = _connect(target)
        _read_line(s)
        s.sendall(line)
        data, closed, secs = _read_until_close(s, timeout=4.0)
        s.close()
        # Strip a following binary KEXINIT so only the textual reaction is compared.
        text = data.split(b"\x00\x00", 1)[0] if data[:1] != b"\x00" else b""
        out[name] = {
            "reply_text": _printable(text),
            "reply_bytes": len(data),
            "kexinit_sent": b"\x14" in data[:16] or (len(data) > 5 and data[5:6] == b"\x14"),
            "closed": closed,
            "close_after_s": round(secs, 2) if closed else None,
        }
    return out


def probe(target: Target | str) -> dict[str, Any]:
    target = Target.parse(target)
    return {
        "target": str(target),
        "kexinit": probe_kexinit(target),
        "banners": probe_banners(target),
    }


def compare(reference: dict[str, Any], candidate: dict[str, Any]) -> list[str]:
    """Differences between a candidate (decoy) and a reference (real sshd): its tells."""
    tells = []
    rk, ck = reference["kexinit"], candidate["kexinit"]
    for key in (
        "banner_line_ending",
        "kexinit_before_client_id",
        "padding_all_zero",
        "first_kex_packet_follows",
        "hassh_server",
    ):
        if rk[key] != ck[key]:
            tells.append(f"kexinit.{key}: reference={rk[key]!r} decoy={ck[key]!r}")
    for name in NAME_LISTS:
        if rk["algorithms"][name] != ck["algorithms"][name]:
            extra = sorted(set(ck["algorithms"][name]) - set(rk["algorithms"][name]))
            missing = sorted(set(rk["algorithms"][name]) - set(ck["algorithms"][name]))
            order = not extra and not missing
            tells.append(
                f"algorithms.{name}: extra={extra} missing={missing}"
                + (" (same set, different order)" if order else "")
            )
    for name in BANNER_PROBES:
        r, c = reference["banners"][name], candidate["banners"][name]
        if (r["reply_text"], r["closed"], r["kexinit_sent"]) != (
            c["reply_text"],
            c["closed"],
            c["kexinit_sent"],
        ):
            tells.append(
                f"banner.{name}: reference={r['reply_text']!r} closed={r['closed']} "
                f"kex={r['kexinit_sent']} | decoy={c['reply_text']!r} closed={c['closed']} "
                f"kex={c['kexinit_sent']}"
            )
    return tells


def main(argv: list[str]) -> None:
    if not argv:
        raise SystemExit(__doc__)
    results = [probe(t) for t in argv]
    report: dict[str, Any] = {"results": results}
    if len(results) > 1:
        report["tells"] = {r["target"]: compare(results[0], r) for r in results[1:]}
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main(sys.argv[1:])
