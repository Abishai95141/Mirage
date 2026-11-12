"""Entry point: ``mirage-http-decoy``, configured from the environment."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

from mirage_decoy_common.server import serve
from mirage_decoy_common.session import Decoy
from mirage_http_decoy.handler import Handler
from mirage_http_decoy.nginx import Profile
from mirage_schema.policy import Protocol


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    profile = Profile.load(Path(os.environ.get("PROFILE_DIR", "/profile")) / "http.json")
    decoy = Decoy.from_env(Protocol.HTTP, "/var/log/mirage/http.json")
    if not os.environ.get("DEPLOYMENT_ID") and profile.deployment_id:
        decoy.deployment_id = profile.deployment_id
    port = int(os.environ.get("PORT", "8080"))
    require_proxy = os.environ.get("REQUIRE_PROXY", "1").lower() not in ("0", "false", "no", "")
    asyncio.run(serve(decoy, Handler(profile), port, require_proxy))


if __name__ == "__main__":
    main()
