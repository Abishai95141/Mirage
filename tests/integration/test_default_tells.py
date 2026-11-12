"""Gate 1 test 8: the default-tell checks pass on the stack, and fail on stock Cowrie."""

from __future__ import annotations

import socket
import time

import pytest

from eval.probes import default_tells

from .conftest import ROOT, docker

pytestmark = pytest.mark.integration


def _root_password() -> str:
    lines = (ROOT / "build/profile/cowrie/userdb.txt").read_text().splitlines()
    return next(ln.split(":", 2)[2] for ln in lines if ln.startswith("root:"))


def test_stack_passes_default_tell_checks(env):
    results = default_tells.run(
        f"127.0.0.1:{env.get('SSH_PORT', '2222')}",
        f"127.0.0.1:{env.get('HTTP_PORT', '8081')}",
        _root_password(),
        ROOT / "build/profile",
        redis=f"127.0.0.1:{env.get('REDIS_PORT', '6380')}",
        mysql=f"127.0.0.1:{env.get('MYSQL_PORT', '3307')}",
    )
    assert {"redis", "mysql"} <= {r.protocol for r in results}
    fails = [r for r in results if r.status == "fail"]
    assert fails == [], fails
    assert {r.check for r in results if r.status == "gap"} == {"HASSH-server equals OpenSSH 9.2p1"}


@pytest.fixture
def stock_cowrie():
    # Stock Cowrie on loopback only, for a few seconds, as the negative control.
    name = f"mirage-tells-stock-{int(time.time())}"
    docker("run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::2222", "cowrie/cowrie:3.1.6")
    try:
        port = int(docker("port", name, "2222/tcp").stdout.splitlines()[0].rsplit(":", 1)[1])
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1) as s:
                    if s.recv(64).startswith(b"SSH-"):
                        break
            except OSError:
                time.sleep(0.5)
        yield f"127.0.0.1:{port}"
    finally:
        docker("stop", "-t", "1", name, check=False)


def test_stock_cowrie_fails_the_ssh_checks(stock_cowrie):
    # Stock Cowrie accepts root with almost any password.
    results = default_tells.run(stock_cowrie, None, "mirage-probe", None)
    failed = {r.check for r in results if r.status == "fail"}
    for expected in (
        "hostname is not a Cowrie default",
        "no user phil",
        "ssh -V agrees with the banner",
        "random root passwords rejected",
        "kex_algorithms offers nothing OpenSSH 9.2p1 does not",
        "server_host_key_algorithms offers nothing OpenSSH 9.2p1 does not",
    ):
        assert expected in failed, (expected, sorted(failed))
