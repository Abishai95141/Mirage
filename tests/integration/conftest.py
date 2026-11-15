import json
import os
import subprocess
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).parents[2]
# In a gate run a missing stack is a failure, not a skip: a skipped test is green, and a gate
# that is green because nothing ran proves nothing (completion plan, F2). CI and `make gate2`
# set this.
REQUIRE_STACK = os.environ.get("MIRAGE_REQUIRE_STACK") == "1"


def unavailable(reason: str) -> None:
    """Skip a test whose stack is not up; in a gate run, fail it."""
    if REQUIRE_STACK:
        pytest.fail(f"{reason} (MIRAGE_REQUIRE_STACK=1: this is a gate run)")
    pytest.skip(reason)


class Env(dict):
    """The .env values. Its repr shows key names only, so a failing test's traceback (pytest
    prints fixture arguments) never puts secrets in a log."""

    def __repr__(self) -> str:
        return f"Env(keys={sorted(self)})"


def read_env() -> Env:
    env = Env()
    for line in (ROOT / ".env").read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def docker(*args: str, check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=timeout
    )


def container_ip(service: str, network: str) -> str:
    out = docker("inspect", f"mirage-{service}-1").stdout
    return json.loads(out)[0]["NetworkSettings"]["Networks"][network]["IPAddress"]


def container_ips(service: str) -> dict[str, str]:
    """Every address a service has, by network."""
    out = docker("inspect", f"mirage-{service}-1").stdout
    networks = json.loads(out)[0]["NetworkSettings"]["Networks"]
    return {name: net["IPAddress"] for name, net in networks.items() if net.get("IPAddress")}


@pytest.fixture(scope="session")
def env() -> Env:
    if not (ROOT / ".env").exists():
        unavailable("no .env; run make up")
    return read_env()


@pytest.fixture(scope="session")
def clickhouse(env):
    client = httpx.Client(
        base_url=f"http://127.0.0.1:{env.get('CLICKHOUSE_PORT', '8123')}",
        headers={
            "X-ClickHouse-User": env["CLICKHOUSE_USER"],
            "X-ClickHouse-Key": env["CLICKHOUSE_PASSWORD"],
        },
        timeout=10,
    )

    def query(sql: str) -> list[dict]:
        r = client.post("/", params={"query": sql + " FORMAT JSON"})
        r.raise_for_status()
        return r.json()["data"]

    try:
        query("SELECT 1")
    except httpx.HTTPError:
        unavailable("ClickHouse not reachable; run make up")
    return query


def pytest_collection_modifyitems(items):
    """The dashboard checks read what the other tests produce, so they run after them. (On a
    fresh stack they would otherwise find no sessions, which a gate run counts as a failure.)"""
    items.sort(key=lambda item: "test_dashboards" in item.nodeid)
