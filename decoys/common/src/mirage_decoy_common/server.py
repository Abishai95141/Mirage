"""TCP server for the decoys we write: PROXY v2 first, then the protocol handler."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from collections.abc import Awaitable, Callable

from mirage_decoy_common.proxyproto import ProxyError, read_proxy_header
from mirage_decoy_common.session import Decoy, Session

log = logging.getLogger("mirage.decoy")

Handler = Callable[[Session, asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


def connection_handler(
    decoy: Decoy, handler: Handler, require_proxy: bool = True
) -> Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]:
    async def on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            if require_proxy:
                try:
                    peer = await read_proxy_header(reader)
                except (ProxyError, asyncio.IncompleteReadError, TimeoutError):
                    return  # not from the edge: drop without a word
                if peer.local:
                    return  # health check
            else:
                from mirage_decoy_common.proxyproto import ProxyInfo

                host, port = writer.get_extra_info("peername")[:2]
                peer = ProxyInfo(host, port, None, None)
            session = Session(decoy, peer)
            session.connect()
            try:
                await handler(session, reader, writer)
            except (ConnectionError, asyncio.IncompleteReadError, TimeoutError):
                pass
            except Exception:
                log.exception("handler error in session %s", session.id)
            finally:
                session.close()
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    return on_connect


async def serve(decoy: Decoy, handler: Handler, port: int, require_proxy: bool = True) -> None:
    server = await asyncio.start_server(
        connection_handler(decoy, handler, require_proxy), host=["0.0.0.0", "::"], port=port
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    log.info("%s decoy listening on %d", decoy.protocol.value, port)
    async with server:
        await stop.wait()
    await decoy.gate.close()
