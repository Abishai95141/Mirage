"""Input normalisation shared by the tagger's de-duplication and its learned layers.

Every rendering of one command should reduce to one skeleton: the parts a slot generator or an
attacker varies freely (addresses, hosts, long hex strings, numbers) become placeholders, and
whitespace collapses. Case is kept, because a flag's case changes its meaning. This is the
unit the content check compares, so two inputs that differ only in such parts count as one.
"""

from __future__ import annotations

import re

URL = re.compile(r"\b((?:https?|ftp|tftp|sftp)://)[^\s/'\"|;&<>]+", re.IGNORECASE)
IP4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
HOST = re.compile(
    r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:example|test|invalid|localhost)\b", re.IGNORECASE
)
HEX = re.compile(r"\b[0-9a-fA-F]{8,}\b")
NUM = re.compile(r"\b\d+\b")
WS = re.compile(r"\s+")


def normalise(text: str) -> str:
    out = URL.sub(r"\1<host>", text)
    out = IP4.sub("<ip>", out)
    out = HOST.sub("<host>", out)
    out = HEX.sub("<hex>", out)
    out = NUM.sub("<n>", out)
    return WS.sub(" ", out).strip()


def parent(technique: str) -> str:
    """A sub-technique folded into its technique: ``T1059.004`` -> ``T1059``."""
    return technique.split(".", 1)[0]
