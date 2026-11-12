"""Entry point: uvicorn on one dual-stack socket.

Requirements measured in spike S1 (spec 1.2): dual-stack (Docker resolves names to IPv6 first,
and an IPv4-only service costs 300 ms per connection), HTTP/1.1 keep-alive above the gate's 2 s
idle timeout, and TCP_NODELAY (asyncio sets it on every TCP transport).

uvicorn's ``host="::"`` is not enough: asyncio sets IPV6_V6ONLY on the IPv6 socket it creates,
so IPv4 clients are refused. The socket is made here with IPV6_V6ONLY off and handed over.
"""

from __future__ import annotations

import asyncio
import os
import socket

import uvicorn

from mirage_policy.app import Settings, create_app


def dual_stack_socket(port: int) -> socket.socket:
    # proto must be IPPROTO_TCP, not 0: asyncio sets TCP_NODELAY on a transport only when the
    # socket says it is TCP. With proto 0 the service answered with Nagle on, and every reused
    # keep-alive connection waited ~40 ms for the client's delayed ACK (measured, Gate 1).
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("::", port))
    sock.listen(512)
    sock.setblocking(False)
    return sock


def main() -> None:
    app = create_app(Settings.from_env())
    config = uvicorn.Config(
        app,
        timeout_keep_alive=5,
        access_log=False,
        server_header=False,
        log_level=os.environ.get("LOG_LEVEL", "info").lower(),
    )
    sock = dual_stack_socket(int(os.environ.get("POLICY_PORT", "8000")))
    asyncio.run(uvicorn.Server(config).serve(sockets=[sock]))


def healthcheck() -> None:
    import urllib.request

    port = os.environ.get("POLICY_PORT", "8000")
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as r:
        raise SystemExit(0 if r.status == 200 else 1)


if __name__ == "__main__":
    main()
