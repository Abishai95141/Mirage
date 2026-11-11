"""Stub policy service for spike S1 (stdlib only; runs on the decoy network).

Rules:
  argv[0] == "mirage-slow"  -> sleep 1 s, then allow (tests the gate's timeout fallback)
  argv[0] == "mirage-kill"  -> terminate
  unknown command           -> fake_success "ok"
  anything else             -> allow
GET /log returns every request received.
"""

import json
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG: list[dict] = []
LOCK = threading.Lock()


def decide(req: dict) -> dict:
    argv = req.get("argv") or [""]
    if argv[0] == "mirage-slow":
        time.sleep(1.0)
        return {"action": "allow"}
    if argv[0] == "mirage-kill":
        return {"action": "terminate"}
    if not req.get("known", True):
        return {"action": "fake_success", "output": "ok\n"}
    return {"action": "allow"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, as a real service (uvicorn) does
    # http.server writes headers and body separately; with Nagle on, the body waits for the
    # client's delayed ACK and every decision costs ~40 ms (measured in spike S1).
    disable_nagle_algorithm = True

    def _send(self, code: int, body: object) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        with LOCK:
            LOG.append(req)
        decision = decide(req) | {"decision_id": str(uuid.uuid4()), "propensity": 1.0}
        self._send(200, decision)

    def do_GET(self) -> None:
        with LOCK:
            self._send(200, LOG)

    def log_message(self, *args) -> None:
        pass


class DualStackServer(ThreadingHTTPServer):
    # Docker resolves the service name to IPv6 first; listen on both families.
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


if __name__ == "__main__":
    DualStackServer(("::", 8000), Handler).serve_forever()
