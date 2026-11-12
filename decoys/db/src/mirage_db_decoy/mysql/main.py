"""Entry point: ``mirage-mysql-decoy``, configured from the environment."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

from mirage_db_decoy.mysql.handler import Handler
from mirage_db_decoy.mysql.sql import Engine
from mirage_db_decoy.mysql.state import Profile, Registry
from mirage_decoy_common.server import serve
from mirage_decoy_common.session import Decoy
from mirage_schema.policy import Protocol


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    profile = Profile.load(Path(os.environ.get("PROFILE_DIR", "/profile")))
    decoy = Decoy.from_env(Protocol.MYSQL, "/var/log/mirage/mysql.json")
    if not os.environ.get("DEPLOYMENT_ID") and profile.deployment_id:
        decoy.deployment_id = profile.deployment_id
    port = int(os.environ.get("PORT", "3306"))
    require_proxy = os.environ.get("REQUIRE_PROXY", "1").lower() not in ("0", "false", "no", "")
    asyncio.run(
        serve(decoy, Handler(profile, Registry(profile), Engine(profile)), port, require_proxy)
    )


if __name__ == "__main__":
    main()
