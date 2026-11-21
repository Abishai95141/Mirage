"""Gate 3 test 3, the live half: the running SSH decoy answers the render library's commands
as the real hosts did, and goes on doing so with the policy service stopped."""

from __future__ import annotations

import json
import time

import pytest

from eval.probes import render_library

from .conftest import ROOT, docker, unavailable

pytestmark = pytest.mark.integration
PROFILE = ROOT / "build/profile"


@pytest.fixture(scope="module")
def target(env) -> str:
    if not (PROFILE / "cowrie/rendered.json").exists():
        unavailable("the profile has no render library; run make up")
    return f"127.0.0.1:{env.get('SSH_PORT', '2222')}"


def test_the_decoy_answers_every_library_entry_as_recorded(target):
    library = json.loads((PROFILE / "cowrie/rendered.json").read_text())
    results = render_library.run(target, PROFILE)
    fails = [r for r in results if r.status == "fail"]
    assert fails == [], fails
    # Three checks an entry, the edges, and the files under /proc.
    assert len(results) >= 3 * len(library["entries"]) + 4
    assert len(library["entries"]) >= 7


@pytest.fixture
def policy_stopped():
    docker("stop", "-t", "2", "mirage-policy-1", timeout=60)
    try:
        yield
    finally:
        docker("start", "mirage-policy-1", timeout=60)
        deadline = time.time() + 60
        while time.time() < deadline:
            st = docker("inspect", "-f", "{{.State.Health.Status}}", "mirage-policy-1").stdout
            if st.strip() == "healthy":
                break
            time.sleep(1)


def test_the_library_answers_with_the_policy_service_stopped(target, policy_stopped):
    library = json.loads((PROFILE / "cowrie/rendered.json").read_text())
    password, _ = render_library.accounts(PROFILE)
    shell = render_library.Session(target, "root", password)
    try:
        results = render_library.check_entries(shell, library)
    finally:
        shell.close()
    fails = [r for r in results if r.status == "fail"]
    assert fails == [], fails
