"""Score the model behind this responder on held-out rows of the tuning set (phase 3, 5b).

    python -m mirage_responder.score < test_programs.jsonl

Run inside the responder's container (it is what may reach the model server). Each row is a
request as the responder would put it and the answer a real host gave (eval/tune/build.py).
The row is put to the model exactly as in service: the same JSON schema, temperature and
token limit. Counted: answers that are the real host's (stdout, stderr and exit status all
equal), answers whose stdout alone is, and replies that are not an answer at all. The
summary goes to standard output as JSON; it holds no row's text unless ``--samples`` asks.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections import Counter
from typing import Any

import httpx

from mirage_responder import prompt


async def ask(
    client: httpx.AsyncClient,
    url: str,
    row: dict[str, Any],
    seed: int,
    temperature: float = prompt.TEMPERATURE,
) -> str | None:
    body = {
        "messages": row["messages"],
        "max_tokens": 400,
        "temperature": temperature,
        "seed": seed,
        "stream": False,
        "cache_prompt": True,
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "answer", "strict": True, "schema": prompt.SCHEMA},
        },
    }
    try:
        reply = await client.post(f"{url}/v1/chat/completions", json=body)
        reply.raise_for_status()
        return str(reply.json()["choices"][0]["message"]["content"])
    except (httpx.HTTPError, KeyError, ValueError):
        return None


def judge(said: str | None, real: str) -> str:
    """``same``, ``stdout`` (stdout right, something else not), ``wrong`` or ``broken``."""
    if said is None:
        return "broken"
    try:
        mine, theirs = json.loads(said), json.loads(real)
    except ValueError:
        return "broken"
    if not isinstance(mine, dict):
        return "broken"
    if all(mine.get(k) == theirs.get(k) for k in ("stdout", "stderr", "exit_code")):
        return "same"
    return (
        "stdout" if mine.get("stdout") == theirs.get("stdout") and theirs.get("stdout") else "wrong"
    )


async def score(
    rows: list[dict[str, Any]],
    url: str,
    parallel: int,
    samples: int,
    temperature: float = prompt.TEMPERATURE,
    twice: bool = False,
) -> dict[str, Any]:
    """Put every row to the model and judge the answers. With ``twice`` every row is put a
    second time, with the same seed, after all the first answers are in: a session that
    sends a command again must be told the same, and the count says how often it would be."""
    gate = asyncio.Semaphore(parallel)
    verdicts: list[tuple[dict[str, Any], str, str | None]] = []
    first: dict[int, str | None] = {}
    agreed: list[bool] = []

    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=5.0)) as client:

        async def one(index: int, row: dict[str, Any]) -> None:
            async with gate:
                said = await ask(client, url, row, index, temperature)
            first[index] = said
            verdicts.append((row, judge(said, row["answer"]), said))

        async def again(index: int, row: dict[str, Any]) -> None:
            async with gate:
                said = await ask(client, url, row, index, temperature)
            agreed.append(said is not None and said == first[index])

        await asyncio.gather(*(one(i, row) for i, row in enumerate(rows)))
        if twice:
            await asyncio.gather(*(again(i, row) for i, row in enumerate(rows)))

    total = Counter(v for _, v, _ in verdicts)
    by_source: dict[str, Counter] = {}
    for row, verdict, _ in verdicts:
        by_source.setdefault(row.get("source", "?"), Counter())[verdict] += 1
    out: dict[str, Any] = {
        "rows": len(rows),
        "same": total["same"],
        "stdout_only": total["stdout"],
        "wrong": total["wrong"],
        "broken": total["broken"],
        "by_source": {
            source: {"rows": sum(c.values()), "same": c["same"]}
            for source, c in sorted(by_source.items())
        },
    }
    out["temperature"] = temperature
    if twice:
        out["repeats_the_same"] = sum(agreed)
    if samples:
        missed = [(r, s) for r, v, s in verdicts if v != "same"][:samples]
        out["samples"] = [
            {"cmd": r["cmd"], "said": (s or "")[:240], "real": r["answer"][:240]} for r, s in missed
        ]
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m mirage_responder.score")
    ap.add_argument("--url", default=os.environ.get("RESPONDER_LLM_URL", ""))
    ap.add_argument("--parallel", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--samples", type=int, default=0, help="show this many missed answers")
    ap.add_argument("--temperature", type=float, default=prompt.TEMPERATURE)
    ap.add_argument("--twice", action="store_true", help="ask again and count equal answers")
    args = ap.parse_args(argv)
    if not args.url:
        raise SystemExit(
            "no model server: RESPONDER_LLM_URL is not set (the replay backend has none)"
        )
    rows = [json.loads(line) for line in sys.stdin.read().splitlines() if line.strip()]
    if args.limit:
        rows = rows[: args.limit]
    summary = asyncio.run(
        score(rows, args.url.rstrip("/"), args.parallel, args.samples, args.temperature, args.twice)
    )
    summary["model"] = os.environ.get("RESPONDER_MODEL", "")
    json.dump(summary, sys.stdout, indent=1)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
