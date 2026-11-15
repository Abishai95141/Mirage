"""The runner's probe by literal address (gap register F6, the lab's part).

The integration test of the runner's isolation tried service names, so every attempt failed at
name resolution and the test passed without saying anything about routing. A probe that takes
addresses cannot fail that way. No socket is opened here: the connection attempt is replaced.
"""

from __future__ import annotations

import errno
import json

import pytest
from test_lab import ROOT

from mirage_lab import cli, safety


def test_a_probe_target_is_a_literal_private_address_and_a_port():
    assert safety.parse_probe("172.26.0.2:2222") == ("172.26.0.2", 2222)
    assert safety.parse_probe("[fd00::2]:8123") == ("fd00::2", 8123)
    # reserved for documentation: routed like a public address, and nobody's host
    assert safety.parse_probe("192.0.2.1:443") == ("192.0.2.1", 443)


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("cowrie:2222", "not a literal"),  # a name would be resolved: the old test's mistake
        ("lab-edge:2222", "not a literal"),
        ("172.26.0.2", "not a literal"),  # no port
        ("172.26.0.2:ssh", "not a literal"),
        ("172.26.0.2:0", "no such port"),
        ("172.26.0.2:70000", "no such port"),
        ("1.1.1.1:443", "public address"),  # never a real host on the internet
        ("[2606:4700:4700::1111]:443", "public address"),
    ],
)
def test_a_probe_refuses_names_and_public_addresses(text, why):
    with pytest.raises(ValueError, match=why):
        safety.parse_probe(text)


class Opened:
    closed = False

    def close(self):
        self.closed = True


def test_a_probe_says_how_each_attempt_ended(monkeypatch):
    opened = Opened()
    tried = []
    ends = {
        "172.26.0.2": opened,
        "172.25.0.3": OSError(errno.ENETUNREACH, "Network is unreachable"),
        "172.25.0.4": ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"),
        "172.25.0.5": TimeoutError("timed out"),
        "172.25.0.6": OSError(errno.EHOSTUNREACH, "No route to host"),
        "172.25.0.7": OSError(errno.EPERM, "Operation not permitted"),
    }

    def connect(address, timeout):
        tried.append((address, timeout))
        end = ends[address[0]]
        if isinstance(end, Exception):
            raise end
        return end

    monkeypatch.setattr(safety.socket, "create_connection", connect)
    got = safety.probe([(ip, 2222) for ip in ends], timeout=1.5)
    assert got == {
        "172.26.0.2:2222": {"state": "open", "errno": None},
        "172.25.0.3:2222": {"state": "no_route", "errno": "ENETUNREACH"},
        "172.25.0.4:2222": {"state": "refused", "errno": "ECONNREFUSED"},
        "172.25.0.5:2222": {"state": "timeout", "errno": None},
        "172.25.0.6:2222": {"state": "host_unreachable", "errno": "EHOSTUNREACH"},
        "172.25.0.7:2222": {"state": "error", "errno": "EPERM"},
    }
    assert opened.closed  # opened, closed, nothing sent
    assert tried[0] == (("172.26.0.2", 2222), 1.5) and len(tried) == len(ends)


def test_check_probe_prints_one_json_object(monkeypatch, capsys):
    def connect(address, timeout):
        if address[0] == "172.26.0.2":
            return Opened()
        raise OSError(errno.ENETUNREACH, "Network is unreachable")

    monkeypatch.setattr(safety.socket, "create_connection", connect)
    # no catalogue, no lab container, no target check: the probe is only a report
    monkeypatch.setattr(safety, "require_lab", lambda target: pytest.fail("the check ran"))
    cli.main(
        ["check", "--probe", "172.26.0.2:2222", "--probe", "172.25.0.3:8123", "--timeout", "1"]
    )
    (line,) = capsys.readouterr().out.splitlines()
    assert json.loads(line) == {
        "172.26.0.2:2222": {"state": "open", "errno": None},
        "172.25.0.3:8123": {"state": "no_route", "errno": "ENETUNREACH"},
    }


def test_check_probe_refuses_a_name_before_trying_anything(monkeypatch):
    monkeypatch.setattr(
        safety.socket, "create_connection", lambda *a, **k: pytest.fail("a connection was tried")
    )
    with pytest.raises(SystemExit, match="refusing to probe: 'cowrie:2222' is not a literal"):
        cli.main(["check", "--probe", "172.26.0.2:2222", "--probe", "cowrie:2222"])
    with pytest.raises(SystemExit, match=r"refusing to probe: 1\.1\.1\.1 is a public address"):
        cli.main(["check", "--probe", "1.1.1.1:443"])


def test_check_without_a_probe_is_still_the_isolation_check(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(safety, "require_lab", lambda target: "172.26.0.2")
    cli.main(["--catalogue", str(ROOT / "lab/catalogue"), "check"])
    assert capsys.readouterr().out.strip() == "ok: lab-edge is 172.26.0.2, inside the lab network"
    monkeypatch.undo()
    monkeypatch.setattr(safety, "ROUTE4", tmp_path / "no-proc")
    with pytest.raises(SystemExit, match="refusing to run: no /proc/net/route"):
        cli.main(["check"])
