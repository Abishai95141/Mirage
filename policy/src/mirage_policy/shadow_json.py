"""Loader for a learned response policy saved as JSON (phase 2 spec, 2.5).

The offline learners (``mirage_intel.policylearn``) save a policy as plain JSON: a table of
per-bucket action values, or per-action linear weights. This turns such a file into a shadow
policy. It contains no decision logic of its own: bucketing a context and picking an action
are done by ``mirage_schema.bandit``, the same code training and evaluation used, so the
distribution logged here is the one the offline numbers describe.

Importing this module registers the loader for ``.json`` files.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from mirage_policy.shadow import file_version, register_loader
from mirage_schema import bandit
from mirage_schema.policy import Action

MAX_BYTES = 8 * 1024 * 1024  # a policy file is small; refuse to read something that is not one


class LearnedShadow:
    """A saved table or linear policy, answering with its choice smoothed over what is allowed."""

    def __init__(self, model: dict[str, Any], version: str) -> None:
        self.model = model
        self.name = f"learned({model.get('name') or model['kind']})"
        self.version = version

    def probabilities(
        self, context: Mapping[str, Any], allowed: Sequence[Action]
    ) -> Mapping[Action, float]:
        names = [a.value for a in allowed]
        rule = str(context.get("rule_action") or names[0])
        probs = bandit.probabilities(self.model, context, names, rule)
        return {a: probs[a.value] for a in allowed}


def load(path: Path) -> LearnedShadow:
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"{path.name} is too large to be a policy file")
    model = json.loads(path.read_text())
    if not isinstance(model, dict):
        raise ValueError("a policy file holds one JSON object")
    bandit.validate(model)
    if model["kind"] == "linear":
        model["_index"] = {name: i for i, name in enumerate(model["features"])}
    return LearnedShadow(model, file_version(path))


register_loader(".json", load)
