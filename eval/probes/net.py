"""Where a probe connects, and how.

A probe run from the machine's own shell reaches a decoy through the published edge on
loopback. The fingerprint suite (phase 3 spec 3.4) runs inside the lab network instead, so
that the decoy and the real reference host are measured from one place, and both of those
edges want a PROXY v2 header naming a source address. A ``Target`` carries that choice, so
every probe opens its connections one way.

The source a probe announces is from the documentation ranges (RFC 5737). The lab's own
ranges (198.18.0.0/15) are left alone: a connection from one of those is a simulated actor to
the label join, and a probe is not one.
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
from dataclasses import dataclass
from typing import Any

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
PROBE_NETWORKS = tuple(
    ipaddress.IPv4Network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
PORT_LO, PORT_HI = 32768, 60999


def proxy_v2(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> bytes:
    """A PROXY protocol v2 header: PROXY command, TCP over IPv4."""
    body = (
        socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!HH", src_port, dst_port)
    )
    return SIGNATURE + bytes([0x21, 0x11]) + struct.pack("!H", len(body)) + body


def probe_source(rng: random.Random | None = None) -> str:
    """A source address for one probe run, from the documentation ranges."""
    rng = rng or random.Random()
    net = rng.choice(PROBE_NETWORKS)
    return str(net.network_address + rng.randint(1, net.num_addresses - 2))


def is_probe_source(address: str) -> bool:
    ip = ipaddress.IPv4Address(address)
    return any(ip in net for net in PROBE_NETWORKS)


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    source: str | None = None  # announced in a PROXY v2 header, where the far end wants one

    @classmethod
    def parse(cls, text: str | Target, source: str | None = None) -> Target:
        if isinstance(text, Target):
            return text
        host, _, port = text.rpartition(":")
        if not host or not port.isdigit():
            raise ValueError(f"a target is HOST:PORT, not {text!r}")
        if source is not None and not is_probe_source(source):
            raise ValueError(f"{source} is not a documentation address; a probe announces no other")
        return cls(host, int(port), source)

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"

    def connect(self, timeout: float = 5.0) -> socket.socket:
        """A connected socket, with the PROXY header already sent when this target takes one."""
        sock = socket.create_connection((self.host, self.port), timeout=timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.source is not None:
            dst_ip, dst_port = sock.getpeername()[:2]
            sock.sendall(proxy_v2(self.source, random.randint(PORT_LO, PORT_HI), dst_ip, dst_port))
        return sock

    def ssh(self, user: str, password: str, timeout: float = 15.0) -> Any:
        """A logged-in paramiko client. Raises paramiko's own errors."""
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            self.host,
            self.port,
            user,
            password,
            look_for_keys=False,
            allow_agent=False,
            timeout=timeout,
            sock=self.connect(timeout),
        )
        return client
