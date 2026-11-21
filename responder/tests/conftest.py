from __future__ import annotations

import json
from typing import Any

import pytest
from responder_kit import PROFILE


@pytest.fixture
def profile() -> dict[str, Any]:
    return json.loads(json.dumps(PROFILE))
