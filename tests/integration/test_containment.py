"""Containment (work package 0.4, extended for phase 1: spec section 2 and Gate 1 test 7).

A decoy must not be able to reach the internet, the pipeline, or the host. Its only permitted
destination is the policy service's port on the gate network, which only decoys share. The probe runs with
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


DECOYS = {
    "cowrie": COWRIE_PY,
    "http-decoy": "/usr/local/bin/python",
    "redis-decoy": "/usr/local/bin/python",
    "mysql-decoy": "/usr/local/bin/python",
}


def _networks(service: str) -> set[str]:
    out = docker("inspect", f"mirage-{service}-1").stdout
    return set(json.loads(out)[0]["NetworkSettings"]["Networks"])


def test_network_membership():
    for decoy in DECOYS:
        assert _networks(decoy) == {"mirage_decoy", "mirage_gate"}, decoy
    assert _networks("policy") == {"mirage_gate"}
    assert _networks("edge") == {"mirage_decoy", "mirage_edge"}


def test_decoy_and_gate_networks_are_internal():
    for net in ("mirage_decoy", "mirage_gate"):
        info = json.loads(docker("network", "inspect", net).stdout)[0]
        assert info["Internal"] is True, net


def test_running_decoys_have_no_egress():
    targets = _targets()
    for decoy, py in DECOYS.items():
        _assert_blocked(_run_in(["exec", f"mirage-{decoy}-1", py], targets))


def test_decoys_reach_only_the_policy_port_on_the_gate():
    policy_ip = container_ip("policy", "mirage_gate")
    others = [container_ip(d, "mirage_gate") for d in DECOYS]
    targets = {
        "tcp": [[policy_ip, 8000], [policy_ip, 22], [policy_ip, 8080], [policy_ip, 4222]]
        + [[ip, p] for ip in others for p in (2222, 8080)],
        "dns": [],
        "udp_dns": [policy_ip],
    }
    for decoy, py in DECOYS.items():
        res = _run_in(["exec", f"mirage-{decoy}-1", py], targets)
        assert res[f"tcp {policy_ip}:8000"] == "connected", (decoy, res)
        leaks = {k: v for k, v in res.items() if v in ("connected", "answered")}
        leaks.pop(f"tcp {policy_ip}:8000")
        # Decoys share the decoy network, so they may reach each other's service ports there
        # (one profile is one host). On the gate they reach only the policy port.
        leaks = {k: v for k, v in leaks.items() if not any(ip in k for ip in others)}
        assert leaks == {}, (decoy, leaks)


def test_policy_service_has_no_egress():
    _assert_blocked(_run_in(["exec", "mirage-policy-1", "python"], _targets()))


def test_edge_side_cannot_reach_the_policy_service():
    policy_ip = container_ip("policy", "mirage_gate")
    res = _run_in(
        ["run", "--rm", "--network", "mirage_decoy", COWRIE_IMAGE],
        {"tcp": [[policy_ip, 8000], ["policy", 8000]], "dns": ["policy"], "udp_dns": []},
    )
    assert not any(
        v in ("connected", "answered") or v.startswith("resolved:") for v in res.values()
    ), res


POLICY_POST = r"""
import json, sys, urllib.request, urllib.error
req = urllib.request.Request("http://policy:8000/v1/decide", data=json.dumps(
    {"request_id": "containment", "protocol": "ssh", "argv": ["id"]}).encode(),
    headers={"Content-Type": "application/json", "Authorization": sys.argv[1]})
try:
    print(urllib.request.urlopen(req, timeout=3).status)
except urllib.error.HTTPError as e:
    print(e.code)
"""


def test_policy_refuses_a_wrong_or_missing_token():
    for auth in ("Bearer wrong-token-0000000000000000", ""):
        out = docker("exec", "mirage-cowrie-1", COWRIE_PY, "-c", POLICY_POST, auth).stdout.strip()
        assert out == "401", (auth[:6], out)


def test_emulated_shell_cannot_reach_the_policy_service(env):
    import time

    import paramiko

    from .conftest import ROOT

    password = next(
        line.split(":", 2)[2]
        for line in (ROOT / "build/profile/cowrie/userdb.txt").read_text().splitlines()
        if line.startswith("root:")
    )
    policy_ip = container_ip("policy", "mirage_gate")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "127.0.0.1",
        int(env.get("SSH_PORT", 2222)),
        "root",
        password,
        look_for_keys=False,
        allow_agent=False,
        timeout=10,
    )
    chan = client.invoke_shell()
    time.sleep(1)
    chan.recv(65536)
    out = b""
    for cmd in (
        f"curl -s http://{policy_ip}:8000/healthz",
        f"wget -O - http://{policy_ip}:8000/healthz",
    ):
        chan.send((cmd + "\n").encode())
        time.sleep(4)
        while chan.recv_ready():
            out += chan.recv(65536)
    client.close()
    text = out.decode(errors="replace")
    # The service answers /healthz with "ok"; the emulated tools must never get that far.
    assert "\nok" not in text and "200 OK" not in text, text


def test_published_ports_bind_localhost_only():
    out = docker(
        "ps", "--filter", "label=com.docker.compose.project=mirage", "--format", "{{.Ports}}"
    )
    bindings = [b.strip() for line in out.stdout.splitlines() for b in line.split(",") if "->" in b]
    assert bindings, "no published ports found; is the stack up?"
    exposed = [b for b in bindings if not b.startswith("127.0.0.1:")]
    assert exposed == [], f"ports published beyond localhost: {exposed}"
