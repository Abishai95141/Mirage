"""Connections to the lab edge, each announcing a simulated source address.

lab-edge accepts a PROXY v2 header and passes the source on to the decoy, so the decoy logs
the address and port chosen here. That pair is what the label join matches on (spec section 3),
so every connection's pair is recorded and never reused within a run.
"""

from __future__ import annotations

import fcntl
import ipaddress
import random
import socket
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
# Reserved for benchmarking (RFC 2544) and never routed on the internet, so a simulated actor
# can never share an address with a real one. One half per mode (spec Q6).
RANGES = {
    "capture": ipaddress.IPv4Network("198.18.0.0/16"),
    "explore": ipaddress.IPv4Network("198.19.0.0/16"),
}
PORT_LO, PORT_HI = 32768, 60999


def proxy_v2(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> bytes:
    """A PROXY protocol v2 header: PROXY command, TCP over IPv4."""
    body = (
        socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!HH", src_port, dst_port)
    )
    return SIGNATURE + bytes([0x21, 0x11]) + struct.pack("!H", len(body)) + body


class AddressPool:
    """Hands out simulated addresses in order, from a counter kept on the runner's volume, so
    two runs never give two actors the same address."""

    def __init__(self, state_file: Path, mode: str) -> None:
        self.state_file, self.net = state_file, RANGES[mode]

    def take(self, count: int) -> list[str]:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        usable = self.net.num_addresses - 2
        with open(self.state_file, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            start = int(f.read().strip() or 0)
            f.seek(0)
            f.truncate()
            f.write(str(start + count))
        return [str(self.net.network_address + 1 + (start + i) % usable) for i in range(count)]


@dataclass
class Conn:
    sock: socket.socket
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    opened: datetime
    closed: datetime | None = None


class Dialer:
    """Opens connections for one simulated actor. Source ports count up from a random start,
    so each connection of the actor has a pair no other connection has."""

    def __init__(self, target_ip: str, src_ip: str, rng: random.Random) -> None:
        self.target_ip, self.src_ip = target_ip, src_ip
        self._next_port = rng.randint(PORT_LO, PORT_HI - 2000)
        self.opened: list[Conn] = []

    def connect(self, dst_port: int, timeout: float = 10.0) -> Conn:
        port = self._next_port
        self._next_port = port + 1 if port < PORT_HI else PORT_LO
        sock = socket.create_connection((self.target_ip, dst_port), timeout=timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(proxy_v2(self.src_ip, port, self.target_ip, dst_port))
        conn = Conn(sock, self.src_ip, port, self.target_ip, dst_port, datetime.now(UTC))
        self.opened.append(conn)
        return conn
