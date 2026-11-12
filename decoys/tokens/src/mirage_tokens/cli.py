"""``mirage-tokens list <tokens.json>`` and ``mirage-tokens match <tokens.json> <text>``.

Minting happens in the profile generator (``mirage-profile render``); this CLI inspects a
rendered deployment's tokens and checks a string against them.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mirage_tokens import Matcher, load


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="mirage-tokens")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list")
    ls.add_argument("tokens", type=Path)
    m = sub.add_parser("match")
    m.add_argument("tokens", type=Path)
    m.add_argument("text")
    args = ap.parse_args(argv)
    tokens = load(args.tokens)
    if args.cmd == "list":
        for t in tokens:
            print(f"{t.token_id}  {t.type:<10}  {t.planted_at}")
        return
    hits = Matcher(tokens).find(args.text)
    for t in hits:
        print(f"{t.token_id}  {t.type:<10}  planted at {t.planted_at}")
    sys.exit(0 if hits else 1)


if __name__ == "__main__":
    main()
