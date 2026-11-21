"""Create or complete .env (used by `make env`). Never prints a secret.

* Copies .env.example when .env is missing.
* Adds any key a newer .env.example introduced, with the example's default.
* Fills empty secrets with random hex, and an empty MIRAGE_SEED with a random integer.
* ``--renew NAME`` replaces one secret that is given to other people (the showcase console's
  password). The services that use it must be restarted to take the new value.
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRETS = (
    "CLICKHOUSE_PASSWORD",
    "CLICKHOUSE_GRAFANA_PASSWORD",
    "GRAFANA_ADMIN_PASSWORD",
    "CLICKHOUSE_SHOWCASE_PASSWORD",
    "GRAFANA_PUBLIC_ADMIN_PASSWORD",
    "SHOWCASE_CONSOLE_PASSWORD",
    "POLICY_TOKEN",
    "RESPONDER_TOKEN",
)
# Only a secret nothing else is derived from may be replaced: changing a store password here
# would lock the services out of a store that still has the old one.
RENEWABLE = ("SHOWCASE_CONSOLE_PASSWORD",)


def parse(text: str) -> list[tuple[str | None, str]]:
    out = []
    for line in text.splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out.append((k.strip(), v))
        else:
            out.append((None, line))
    return out


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    renew = set(args[1:]) if args[:1] == ["--renew"] else set()
    if (args and not renew) or renew - set(RENEWABLE):
        raise SystemExit(f"usage: env_fill.py [--renew {'|'.join(RENEWABLE)}]")
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
        if k in SECRETS and (not v or k in renew):
            lines[i] = (k, secrets.token_hex(16))
            print(f"replaced {k}" if v else f"set {k}")
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
