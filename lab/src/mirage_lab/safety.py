"""The runner's own containment check (build plan section 7, spec section 2).

The runner refuses to start unless it can show, from the kernel's routing tables, that it sits
on an isolated network: no default route (so no path to the internet or to anything we own),
and a target that resolves only to addresses on a directly attached private network. It has no
option to name a target elsewhere. Off Linux there are no tables to read, so it refuses.

``probe`` is the same claim tested from the other side, for the integration tests: given the
real addresses of the services the runner must not reach, it tries each and says how the
attempt ended. It takes literal addresses only, so it cannot fail at name resolution and pass
for isolation.
"""

from __future__ import annotations

import errno
import ipaddress
import socket
from pathlib import Path

ROUTE4 = Path("/proc/net/route")
ROUTE6 = Path("/proc/net/ipv6_route")


class SafetyError(RuntimeError):
    pass


def _hex_le_ip(text: str) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(bytes.fromhex(text)[::-1])


def attached_networks(route4: str) -> tuple[list[ipaddress.IPv4Network], bool, bool]:
    """(directly attached IPv4 networks, a default route exists, a non-default routed path
    exists) from /proc/net/route. A gatewayed non-default route is a path off the attached
    network and breaks isolation just as a default route does."""
    nets: list[ipaddress.IPv4Network] = []
    default = False
    routed = False
    for line in route4.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 8:
            continue
        iface, dest, gateway, mask = cols[0], cols[1], cols[2], cols[7]
        if iface == "lo":
            continue
        if dest == "00000000" and mask == "00000000":
            default = True
            continue
        if gateway == "00000000":
            nets.append(ipaddress.IPv4Network(f"{_hex_le_ip(dest)}/{_hex_le_ip(mask)}"))
        else:
            routed = True  # a non-default route through a gateway: an off-link path
    return nets, default, routed


def has_default_route6(route6: str) -> bool:
    """A ::/0 route through a real interface, from /proc/net/ipv6_route."""
    for line in route6.splitlines():
        cols = line.split()
        if len(cols) < 10:
            continue
        dest, prefix, iface = cols[0], cols[1], cols[9]
        if dest == "0" * 32 and prefix == "00" and iface != "lo":
            return True
    return False


def check_target(addresses: list[str], route4: str, route6: str) -> list[str]:
    """Why the runner may not start; an empty list means it may."""
    problems: list[str] = []
    nets, default4, routed4 = attached_networks(route4)
    if default4:
        problems.append("this container has an IPv4 default route, so it is not isolated")
    if routed4:
        problems.append("this container has a gatewayed (off-link) route, so it is not isolated")
    if has_default_route6(route6):
        problems.append("this container has an IPv6 default route, so it is not isolated")
    private = [n for n in nets if n.is_private and n.prefixlen >= 12]
    if len(nets) != 1 or len(private) != 1:
        shown = [str(n) for n in nets]
        problems.append(f"expected exactly one attached private network, found {shown}")
    if not addresses:
        problems.append("the target does not resolve")
    for addr in addresses:
        ip = ipaddress.ip_address(addr)
        if not any(ip in n for n in private):
            problems.append(f"target address {addr} is outside the lab network")
    return problems


def resolve(target: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


def require_lab(target: str) -> str:
    """The target's address, or SafetyError. Called before any connection is opened."""
    if not ROUTE4.exists():
        raise SafetyError("no /proc/net/route: the runner only runs in its lab container")
    addresses = resolve(target)
    route6 = ROUTE6.read_text() if ROUTE6.exists() else ""
    problems = check_target(addresses, ROUTE4.read_text(), route6)
    if problems:
        raise SafetyError("; ".join(problems))
    return addresses[0]


# ------------------------------------------------------------------ probe by address

# How a refused attempt ended, by errno. ``no_route`` is the one isolation predicts: the kernel
# had no path to the address and sent nothing. ``refused`` means a packet got there and back.
STATES = {
    "ECONNREFUSED": "refused",
    "ENETUNREACH": "no_route",
    "EHOSTUNREACH": "host_unreachable",
}


def parse_probe(text: str) -> tuple[str, int]:
    """``ADDRESS:PORT`` (``[ADDRESS]:PORT`` for IPv6) as a literal address and a port.

    A name is refused: resolving it is exactly the failure a probe by address exists to rule
    out. A public address is refused as well: the runner's image never opens a connection to a
    host outside private and reserved space, whoever asks. To test the path to the internet,
    probe an address reserved for documentation (192.0.2.1): it is routed like any public one.
    """
    host, _, port = text.rpartition(":")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        number = int(port)
    except ValueError as exc:
        raise ValueError(f"{text!r} is not a literal ADDRESS:PORT") from exc
    if not 0 < number < 65536:
        raise ValueError(f"{text!r}: no such port")
    if ip.is_global:
        raise ValueError(f"{ip} is a public address; probe private or reserved addresses only")
    return str(ip), number


def probe(targets: list[tuple[str, int]], timeout: float = 3.0) -> dict[str, dict[str, str | None]]:
    """Try a TCP connection to each address and report how it ended: ``open``, ``refused``,
    ``no_route``, ``host_unreachable``, ``timeout`` or ``error``, with the errno's name where
    there was one. A connection that opens is closed at once; nothing is ever sent on it."""
    out: dict[str, dict[str, str | None]] = {}
    for host, port in targets:
        key = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        try:
            socket.create_connection((host, port), timeout=timeout).close()
            out[key] = {"state": "open", "errno": None}
        except TimeoutError:
            out[key] = {"state": "timeout", "errno": None}
        except OSError as exc:
            name = errno.errorcode.get(exc.errno or 0, type(exc).__name__)
            out[key] = {"state": STATES.get(name, "error"), "errno": name}
    return out
