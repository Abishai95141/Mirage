"""Create or complete .env (used by `make env`). Never prints a secret.

* Copies .env.example when .env is missing.
* Adds any key a newer .env.example introduced, with the example's default.
* Fills empty secrets with random hex, and an empty MIRAGE_SEED with a random integer.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRETS = ("CLICKHOUSE_PASSWORD", "GRAFANA_ADMIN_PASSWORD", "POLICY_TOKEN")


def parse(text: str) -> list[tuple[str | None, str]]:
    out = []
    for line in text.splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out.append((k.strip(), v))
        else:
            out.append((None, line))
    return out


def main() -> None:
    example = parse((ROOT / ".env.example").read_text())
    env_path = ROOT / ".env"
    lines = parse(env_path.read_text()) if env_path.exists() else list(example)
    have = {k for k, _ in lines if k}
    changed = not env_path.exists()
    for k, v in example:
        if k and k not in have:
            lines.append((k, v))
            print(f"added {k}")
            changed = True
    for i, (k, v) in enumerate(lines):
        if k in SECRETS and not v:
            lines[i] = (k, secrets.token_hex(16))
            print(f"set {k}")
            changed = True
        elif k == "MIRAGE_SEED" and not v:
            lines[i] = (k, str(secrets.randbelow(10**6)))
            print("set MIRAGE_SEED")
            changed = True
    if changed:
        env_path.write_text("\n".join(f"{k}={v}" if k else v for k, v in lines) + "\n")
        os.chmod(env_path, 0o600)


if __name__ == "__main__":
    main()
