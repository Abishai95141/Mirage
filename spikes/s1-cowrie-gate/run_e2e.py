"""Spike S1 end-to-end check: gated Cowrie over real SSH, real HTTP to the policy stub.

Run from the repo root after `docker compose -f spikes/s1-cowrie-gate/compose.yml up -d --build`:
    uv run python spikes/s1-cowrie-gate/run_e2e.py
"""

from __future__ import annotations

import json
import secrets
import statistics
import subprocess
import time

import paramiko

GATED, STOCK = 2224, 2225
PROMPT = b"# "
COMPOSE = ["docker", "compose", "-f", "spikes/s1-cowrie-gate/compose.yml"]


class Shell:
    def __init__(self, port: int) -> None:
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            "127.0.0.1",
            port,
            username="root",
            password=secrets.token_hex(6),
            look_for_keys=False,
            allow_agent=False,
            timeout=15,
        )
        self.chan = self.client.invoke_shell()
        self.chan.settimeout(10)
        self.read_until_prompt()

    def read_until_prompt(self, timeout: float = 10) -> bytes:
        buf = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.chan.recv_ready():
                buf += self.chan.recv(65536)
                if buf.rstrip().endswith(b"#"):
                    return buf
            elif self.chan.closed or self.chan.exit_status_ready():
                return buf
            else:
                time.sleep(0.002)
        return buf

    def run(self, line: str) -> tuple[float, str]:
        t0 = time.monotonic()
        self.chan.send((line + "\n").encode())
        out = self.read_until_prompt()
        return (time.monotonic() - t0) * 1000, out.decode(errors="replace")

    def close(self) -> None:
        self.client.close()


def pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(p * len(xs)))], 1)


def latency(port: int, reps: int = 20) -> list[float]:
    sh = Shell(port)
    cmds = ["echo hi", "uname -a", "whoami", "ls /", "cat /etc/passwd"]
    times = [sh.run(c)[0] for _ in range(reps) for c in cmds]
    sh.close()
    return times


def main() -> None:
    result: dict = {}
    stock, gated = latency(STOCK), latency(GATED)
    result["latency_ms"] = {
        "stock": {"p50": pct(stock, 0.5), "p95": pct(stock, 0.95), "n": len(stock)},
        "gated": {"p50": pct(gated, 0.5), "p95": pct(gated, 0.95), "n": len(gated)},
        "added_p50": round(statistics.median(gated) - statistics.median(stock), 1),
    }

    sh = Shell(GATED)
    _, out = sh.run("frobnicate --now")
    result["unknown_answered_by_policy"] = "ok" in out and "not found" not in out
    _, out = sh.run("echo a | grep a; x=$(frobnicate); echo [$x]")
    result["pipeline_and_substitution"] = "[ok]" in out
    ms, out = sh.run("mirage-slow")
    result["slow_policy"] = {"elapsed_ms": round(ms, 1), "fell_back_to_stock": "not found" in out}
    sh.close()

    result["policy_requests_before_restart"] = len(policy_log())

    subprocess.run([*COMPOSE, "stop", "policy"], check=True, capture_output=True)
    try:
        sh = Shell(GATED)
        ms, out = sh.run("echo still-here")
        result["policy_down"] = {"elapsed_ms": round(ms, 1), "shell_works": "still-here" in out}
        sh.close()
    finally:
        subprocess.run([*COMPOSE, "start", "policy"], check=True, capture_output=True)
    time.sleep(1)

    sh = Shell(GATED)
    sh.chan.send(b"mirage-kill\n")
    time.sleep(1.5)
    result["terminate_closed_session"] = sh.chan.closed or sh.chan.exit_status_ready()
    sh.close()

    result["decisions"] = decision_summary()
    print(json.dumps(result, indent=2))


def policy_log() -> list[dict]:
    out = subprocess.run(
        [
            *COMPOSE,
            "exec",
            "-T",
            "policy",
            "python",
            "-c",
            "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/log').read().decode())",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return json.loads(out)


def decision_summary() -> dict:
    """Read cowrie.policy.decision events from the gated Cowrie's own JSON log."""
    script = (
        "import json,collections;"
        "d=[json.loads(l) for l in open('var/log/cowrie/cowrie.json')];"
        "d=[r for r in d if r['eventid']=='cowrie.policy.decision'];"
        "print(json.dumps({'n':len(d),"
        "'by_action':collections.Counter(f\"{r['action']}{'(fallback)' if r['fallback'] else ''}\" for r in d),"
        "'latency_ms':sorted(r['latency_ms'] for r in d if not r['fallback'])}))"
    )
    out = subprocess.run(
        [*COMPOSE, "exec", "-T", "cowrie-gated", "/cowrie/cowrie-env/bin/python3", "-c", script],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    d = json.loads(out)
    lat = d.pop("latency_ms")
    d["gate_latency_ms"] = (
        {"p50": pct(lat, 0.5), "p95": pct(lat, 0.95), "max": max(lat)} if lat else None
    )
    return d


if __name__ == "__main__":
    main()
