"""Profile, glob matching and the keyspace kept per source address (decision P10)."""

from __future__ import annotations

import copy
import json
import secrets
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

RESET_AFTER_S = 24 * 3600
SOURCE_BUDGET = 8 * 1024 * 1024  # bytes of keyspace one source may write before OOM
TOTAL_BUDGET = 48 * 1024 * 1024  # the container has 128 MB
MAX_SOURCES = 4096
MAX_SCRIPTS = 256


@dataclass
class Profile:
    deployment_id: str
    version: str
    start_epoch: int
    config: dict[str, str]
    info: list[dict[str, Any]]
    keyspace: dict[int, dict[bytes, Entry]]
    replies: dict[str, str]
    max_bulk: int
    private_ip: str = "127.0.0.1"

    @classmethod
    def load(cls, profile_dir: Path) -> Profile:
        p = json.loads((profile_dir / "redis.json").read_text())
        host_file = profile_dir / "host.json"
        host = json.loads(host_file.read_text()) if host_file.exists() else {}
        config = dict(p["config"])
        if p.get("requirepass"):
            config["requirepass"] = p["requirepass"]
        ks = {
            int(db): {k.encode(): Entry.from_profile(v) for k, v in keys.items()}
            for db, keys in p["keyspace"].items()
        }
        return cls(
            p["deployment_id"],
            p["version"],
            int(p["start_epoch"]),
            config,
            p["info"],
            ks,
            p["reference_replies"],
            int(p["max_bulk_bytes"]),
            host.get("private_ip", "127.0.0.1"),
        )

    def info_field(self, section: str, name: str, default: str = "") -> str:
        for sec in self.info:
            if sec["section"] == section:
                return next((v for k, v in sec["fields"] if k == name), default)
        return default


@dataclass
class Entry:
    kind: str  # string | hash | list
    data: Any  # bytes | dict[bytes, bytes] | list[bytes]
    expire_ms: int | None = None

    @classmethod
    def from_profile(cls, v: dict[str, Any]) -> Entry:
        val = v["value"]
        if v["type"] == "hash":
            return cls("hash", {k.encode(): x.encode() for k, x in val.items()})
        if v["type"] == "list":
            return cls("list", [x.encode() for x in val])
        return cls("string", str(val).encode())

    def size(self) -> int:
        if self.kind == "hash":
            return sum(len(k) + len(v) + 24 for k, v in self.data.items())
        if self.kind == "list":
            return sum(len(x) + 16 for x in self.data)
        return len(self.data)


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class SourceState:
    """Everything one source address can change. Created from the seed, never shared."""

    dbs: dict[int, dict[bytes, Entry]]
    config: dict[str, str]
    last_save: int
    replid: str
    master: tuple[str, int] | None = None
    replid2: str = "0" * 40
    second_offset: int = -1
    first_write: float | None = None
    dirty: int = 0
    saves: int = 0
    scripts: dict[str, bytes] = field(default_factory=dict)

    def db(self, i: int) -> dict[bytes, Entry]:
        d = self.dbs.setdefault(i, {})
        now = now_ms()
        for k in [k for k, e in d.items() if e.expire_ms is not None and e.expire_ms <= now]:
            del d[k]
        return d

    def get(self, i: int, key: bytes) -> Entry | None:
        e = self.dbs.get(i, {}).get(key)
        if e is not None and e.expire_ms is not None and e.expire_ms <= now_ms():
            del self.dbs[i][key]
            return None
        return e

    def wrote(self, n: int = 1) -> None:
        if self.first_write is None:
            self.first_write = time.time()
        self.dirty += n

    def nbytes(self) -> int:
        return sum(len(k) + e.size() for d in self.dbs.values() for k, e in d.items())

    def remember_script(self, sha: str, script: bytes) -> None:
        if len(self.scripts) >= MAX_SCRIPTS:
            self.scripts.pop(next(iter(self.scripts)))
        self.scripts[sha] = script


class Registry:
    """Source address -> state, plus the open clients of each source."""

    def __init__(self, profile: Profile) -> None:
        self.profile = profile
        self.states: dict[str, SourceState] = {}
        self.clients: dict[str, list[Any]] = {}

    def fresh(self) -> SourceState:
        p = self.profile
        return SourceState(
            copy.deepcopy(p.keyspace),
            dict(p.config),
            p.start_epoch,
            p.info_field("Replication", "master_replid", secrets.token_hex(20)),
        )

    def get(self, ip: str) -> SourceState:
        st = self.states.get(ip)
        if st is None or (st.first_write and time.time() - st.first_write >= RESET_AFTER_S):
            if st is None and len(self.states) >= MAX_SOURCES:
                self._evict()
            st = self.states[ip] = self.fresh()
        return st

    def _evict(self) -> None:
        idle = [ip for ip in self.states if not self.clients.get(ip)]
        victim = min(idle or self.states, key=lambda ip: self.states[ip].first_write or 0)
        del self.states[victim]

    def attach(self, ip: str, client: Any) -> None:
        self.clients.setdefault(ip, []).append(client)

    def detach(self, ip: str, client: Any) -> None:
        peers = self.clients.get(ip, [])
        if client in peers:
            peers.remove(client)
        if not peers:
            self.clients.pop(ip, None)
            # A source that only read keeps nothing worth remembering.
            st = self.states.get(ip)
            if st is not None and st.first_write is None:
                del self.states[ip]

    def total_bytes(self) -> int:
        return sum(s.nbytes() for s in self.states.values())


# ---------------------------------------------------------------- glob (stringmatchlen)

_STAR, _ANY = "*", "?"


@lru_cache(maxsize=256)
def _compile(pattern: bytes) -> tuple[Any, ...]:
    toks: list[Any] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == 0x2A:
            if not toks or toks[-1] != _STAR:
                toks.append(_STAR)
        elif c == 0x3F:
            toks.append(_ANY)
        elif c == 0x5B:
            i += 1
            neg = i < n and pattern[i] == 0x5E
            i += neg
            chars: set[int] = set()
            while i < n and pattern[i] != 0x5D:
                if pattern[i] == 0x5C and i + 1 < n:
                    i += 1
                    chars.add(pattern[i])
                elif i + 2 < n and pattern[i + 1] == 0x2D:
                    lo, hi = sorted((pattern[i], pattern[i + 2]))
                    chars.update(range(lo, hi + 1))
                    i += 2
                else:
                    chars.add(pattern[i])
                i += 1
            toks.append((neg, frozenset(chars)))
        elif c == 0x5C and i + 1 < n:
            i += 1
            toks.append(pattern[i])
        else:
            toks.append(c)
        i += 1
    return tuple(toks)


def _one(tok: Any, c: int) -> bool:
    if tok == _ANY:
        return True
    if isinstance(tok, tuple):
        return (c in tok[1]) != tok[0]
    return tok == c


def glob_match(pattern: bytes, s: bytes, nocase: bool = False) -> bool:
    """Redis glob semantics with star backtracking, so hostile patterns stay O(n*m)."""
    if nocase:
        pattern, s = pattern.lower(), s.lower()
    toks = _compile(pattern)
    i = j = 0
    star, mark = -1, 0
    while i < len(s):
        if j < len(toks) and toks[j] != _STAR and _one(toks[j], s[i]):
            i += 1
            j += 1
        elif j < len(toks) and toks[j] == _STAR:
            star, mark = j, i
            j += 1
        elif star >= 0:
            j, mark = star + 1, mark + 1
            i = mark
        else:
            return False
    while j < len(toks) and toks[j] == _STAR:
        j += 1
    return j == len(toks)
