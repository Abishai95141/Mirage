"""The runner's own containment check (build plan section 7, spec section 2).

The runner refuses to start unless it can show, from the kernel's routing tables, that it sits
on an isolated network: no default route (so no path to the internet or to anything we own),
and a target that resolves only to addresses on a directly attached private network. It has no
option to name a target elsewhere. Off Linux there are no tables to read, so it refuses.
"""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path

ROUTE4 = Path("/proc/net/route")
ROUTE6 = Path("/proc/net/ipv6_route")


class SafetyError(RuntimeError):
    pass


def _hex_le_ip(text: str) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(bytes.fromhex(text)[::-1])


def attached_networks(route4: str) -> tuple[list[ipaddress.IPv4Network], bool]:
    """(directly attached IPv4 networks, whether a default route exists) from /proc/net/route."""
    nets: list[ipaddress.IPv4Network] = []
    default = False
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
    return nets, default


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
    nets, default4 = attached_networks(route4)
    if default4:
        problems.append("this container has an IPv4 default route, so it is not isolated")
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
