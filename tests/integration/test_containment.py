"""Containment baseline (work package 0.4).

A decoy must not be able to reach the internet, the pipeline, or the host. The probe runs with
Cowrie's own Python both inside the running Cowrie container and in a throwaway container on
the decoy network, so the check covers the network, not just one container's configuration.
A positive control from the edge network proves the probe can detect egress when it exists.
"""

from __future__ import annotations

import json
import socket

import pytest

from .conftest import container_ip, docker, read_env

pytestmark = pytest.mark.integration

COWRIE_IMAGE = "cowrie/cowrie:3.1.6"
COWRIE_PY = "/cowrie/cowrie-env/bin/python3"

PROBE = r"""
import json, socket, sys
targets = json.loads(sys.argv[1])
out = {}
def tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=3).close()
        return "connected"
    except Exception as e:
        return type(e).__name__
def dns(name):
    try:
        return "resolved:" + socket.gethostbyname(name)
    except Exception as e:
        return type(e).__name__
def udp_dns(server):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    try:
        s.sendto(q, (server, 53)); s.recvfrom(512); return "answered"
    except Exception as e:
        return type(e).__name__
for h, p in targets["tcp"]:
    out[f"tcp {h}:{p}"] = tcp(h, p)
for n in targets["dns"]:
    out[f"dns {n}"] = dns(n)
for s in targets["udp_dns"]:
    out[f"udp-dns {s}"] = udp_dns(s)
print(json.dumps(out))
"""

INTERNET_TCP = [
    ["1.1.1.1", 443],
    ["8.8.8.8", 53],
    ["9.9.9.9", 443],
    # Docker Desktop networks are dual-stack, so IPv6 egress must be checked too.
    ["2606:4700:4700::1111", 443],
    ["2001:4860:4860::8888", 53],
]
INTERNET_DNS = ["example.com", "github.com"]
CORE_NAMES = ["nats", "clickhouse", "grafana", "vector", "normaliser"]
HOST_NAMES = ["host.docker.internal", "gateway.docker.internal"]


def _targets() -> dict:
    env = read_env()
    core_ips = [container_ip(s, "mirage_core") for s in ("nats", "clickhouse", "grafana")]
    tcp = INTERNET_TCP + [[ip, p] for ip in core_ips for p in (4222, 8123, 3000)]
    # Host services must not be reachable either: the native llama-server above all, and the
    # ports the stack publishes on the host's loopback.
    host_ports = {22, int(env.get("LLM_PORT", 8090))}
    host_ports |= {
        int(env.get(k, d))
        for k, d in (("GRAFANA_PORT", 3300), ("CLICKHOUSE_PORT", 8123), ("NATS_PORT", 4222))
    }
    tcp += [[h, p] for h in HOST_NAMES for p in sorted(host_ports)]
    return {"tcp": tcp, "dns": INTERNET_DNS + CORE_NAMES, "udp_dns": ["8.8.8.8", "1.1.1.1"]}


def _run_in(args: list[str], targets: dict) -> dict[str, str]:
    res = docker(*args, "-c", PROBE, json.dumps(targets), timeout=180)
    return json.loads(res.stdout.strip().splitlines()[-1])


def _assert_blocked(results: dict[str, str]) -> None:
    leaks = {k: v for k, v in results.items() if v == "connected" or v == "answered"}
    # Docker's embedded DNS may answer host.docker.internal; resolution is acceptable only if
    # connecting to it then fails, which the tcp entries check. Any other name resolving is a leak.
    leaks |= {
        k: v
        for k, v in results.items()
        if v.startswith("resolved:") and k.split(" ", 1)[1] not in HOST_NAMES
    }
    assert leaks == {}, f"decoy network leaks: {leaks}"


def test_running_cowrie_has_no_egress():
    targets = _targets()
    results = _run_in(["exec", "mirage-cowrie-1", COWRIE_PY], targets)
    _assert_blocked(results)


def test_any_container_on_decoy_network_has_no_egress():
    targets = _targets()
    results = _run_in(["run", "--rm", "--network", "mirage_decoy", COWRIE_IMAGE], targets)
    _assert_blocked(results)


def test_positive_control_probe_detects_egress():
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=3).close()
    except OSError:
        pytest.skip("host has no internet; positive control not meaningful")
    results = _run_in(
        ["run", "--rm", "--network", "mirage_edge", COWRIE_IMAGE],
        {"tcp": [["1.1.1.1", 443]], "dns": ["example.com"], "udp_dns": []},
    )
    assert results["tcp 1.1.1.1:443"] == "connected"
    assert results["dns example.com"].startswith("resolved:")


def test_cowrie_is_only_on_decoy_network():
    nets = json.loads(docker("inspect", "mirage-cowrie-1").stdout)[0]["NetworkSettings"]["Networks"]
    assert set(nets) == {"mirage_decoy"}


def test_decoy_network_is_internal():
    info = json.loads(docker("network", "inspect", "mirage_decoy").stdout)[0]
    assert info["Internal"] is True


def test_published_ports_bind_localhost_only():
    out = docker(
        "ps", "--filter", "label=com.docker.compose.project=mirage", "--format", "{{.Ports}}"
    )
    bindings = [b.strip() for line in out.stdout.splitlines() for b in line.split(",") if "->" in b]
    assert bindings, "no published ports found; is the stack up?"
    exposed = [b for b in bindings if not b.startswith("127.0.0.1:")]
    assert exposed == [], f"ports published beyond localhost: {exposed}"
