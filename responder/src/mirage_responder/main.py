"""Entry point: the responder on one dual-stack socket, as the policy service is (spike S1).

Configuration, all from the environment:

    RESPONDER_TOKEN       the bearer token the SSH decoy sends (at least 16 characters)
    RESPONDER_PROFILE     the deployment's responder.json (default /profile/responder.json)
    RESPONDER_BACKEND     replay (the default), llama or llama-dev
    RESPONDER_RECORDINGS  where replay reads recordings (default /recordings)
    RESPONDER_RECORD      with a live backend: also write every answer there, for replay
    RESPONDER_LLM_URL     the model server, for llama and llama-dev
    RESPONDER_MODEL       the model's name and build, kept with every cached answer
    RESPONDER_CACHE       the SQLite cache file (default /var/lib/mirage-responder/cache.db)
    RESPONDER_LOG         the record log (default /var/log/mirage-responder/answers.json)
    RESPONDER_CONCURRENCY answers in the making at once (default 1)
    RESPONDER_REFUSAL_S   how long a program that could not be answered stays refused for
                          the deployment (default 604800, a week; 0: not kept)
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
from pathlib import Path

import uvicorn

from mirage_responder import prompt
from mirage_responder.app import Settings, create_app
from mirage_responder.backends import Backend, Llama, Recording, Replay


def backend_from_env() -> Backend:
    name = os.environ.get("RESPONDER_BACKEND", "replay")
    recordings = Path(os.environ.get("RESPONDER_RECORDINGS", "/recordings"))
    if name == "replay":
        return Replay(recordings)
    if name not in ("llama", "llama-dev"):
        raise SystemExit(f"RESPONDER_BACKEND: no backend called {name!r}")
    url = os.environ.get("RESPONDER_LLM_URL", "")
    if not url:
        raise SystemExit(f"RESPONDER_LLM_URL must be set for the {name} backend")
    live: Backend = Llama(url, name, prompt.SCHEMA, os.environ.get("RESPONDER_MODEL", ""))
    if os.environ.get("RESPONDER_RECORD") == "1":
        live = Recording(live, recordings)
    return live


WEEK_S = "604800"


def settings_from_env() -> Settings:
    token = os.environ.get("RESPONDER_TOKEN", "")
    if len(token) < 16:
        raise SystemExit("RESPONDER_TOKEN must be set (at least 16 characters); run make env")
    profile_path = Path(os.environ.get("RESPONDER_PROFILE", "/profile/responder.json"))
    try:
        profile = json.loads(profile_path.read_text())
    except (OSError, ValueError) as exc:
        raise SystemExit(f"RESPONDER_PROFILE: cannot read {profile_path}: {exc}") from exc
    return Settings(
        token=token,
        profile=profile,
        backend=backend_from_env(),
        cache_path=Path(os.environ.get("RESPONDER_CACHE", "/var/lib/mirage-responder/cache.db")),
        log_path=Path(os.environ.get("RESPONDER_LOG", "/var/log/mirage-responder/answers.json")),
        concurrency=int(os.environ.get("RESPONDER_CONCURRENCY", "1")),
        refusal_s=float(os.environ.get("RESPONDER_REFUSAL_S") or WEEK_S),
    )


def dual_stack_socket(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("::", port))
    sock.listen(128)
    sock.setblocking(False)
    return sock


def main() -> None:
    app = create_app(settings_from_env())
    config = uvicorn.Config(
        app,
        timeout_keep_alive=75,
        access_log=False,
        server_header=False,
        log_level=os.environ.get("LOG_LEVEL", "info").lower(),
    )
    sock = dual_stack_socket(int(os.environ.get("RESPONDER_PORT", "8100")))
    asyncio.run(uvicorn.Server(config).serve(sockets=[sock]))


def healthcheck() -> None:
    import urllib.request

    port = os.environ.get("RESPONDER_PORT", "8100")
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as r:
            raise SystemExit(0 if r.status == 200 else 1)
    except OSError:
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
