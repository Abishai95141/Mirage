"""The technique rule engine lives in ``mirage_schema.techniques`` so the pipeline's tagger
worker and the policy service can share it without the intel package's heavy libraries."""

from mirage_schema.techniques import PROTOCOLS, Engine, Hit, Rule, SessionRule

__all__ = ["PROTOCOLS", "Engine", "Hit", "Rule", "SessionRule"]
