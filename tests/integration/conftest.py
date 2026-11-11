import json
import subprocess
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).parents[2]


def read_env() -> dict[str, str]:
    env = {}
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


@pytest.fixture(scope="session")
def env() -> dict[str, str]:
    if not (ROOT / ".env").exists():
        pytest.skip("no .env; run make up")
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
        pytest.skip("ClickHouse not reachable; run make up")
    return query
