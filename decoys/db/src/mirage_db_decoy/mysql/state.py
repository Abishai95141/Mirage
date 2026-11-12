"""Profile and per-source state for the MySQL decoy (spec 1.5, decision P10).

Every source address gets its own in-memory SQLite copy of the profile's tables, seeded once
and reset 24 hours after that source's first write. Nothing is ever written to disk.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

RESET_AFTER_S = 24 * 3600
MAX_SOURCES = 256  # each source's schema is tiny; this bounds the container's memory
STATEMENT_BUDGET_S = 0.25  # SQLite runs on the event loop; no statement may hold it longer
MAX_VALUE_BYTES = 4 * 1024 * 1024  # SQLITE_LIMIT_LENGTH: no string or blob larger than this

# Statements a client can reach SQLite with must never touch anything but the attached
# in-memory copies: no ATTACH (a path would create a file), no PRAGMA, and none of the file or
# extension functions an SQLite build may carry. (SQLite's own tables are kept out by the
# engine, which answers 1146 for any table the profile does not have: DDL itself has to read
# sqlite_master, so the authorizer cannot refuse that.)
_DENIED_ACTIONS = {sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_PRAGMA}
_DENIED_FUNCTIONS = {"load_extension", "readfile", "writefile", "edit", "fts3_tokenizer"}


def _authorizer(action: int, arg1: str | None, arg2: str | None, *_: object) -> int:
    if action in _DENIED_ACTIONS:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and (arg2 or "").lower() in _DENIED_FUNCTIONS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


# MariaDB column types that SQLite stores as integers/floats; everything else is TEXT.
_INT_TYPES = ("int", "bit", "bool", "boolean", "year", "serial")
_REAL_TYPES = ("decimal", "numeric", "dec", "fixed", "float", "double", "real")


def affinity(mariadb_type: str) -> str:
    t = mariadb_type.lower()
    if any(t.startswith(k) for k in _INT_TYPES):
        return "INTEGER"
    if any(t.startswith(k) for k in _REAL_TYPES):
        return "REAL"
    return "TEXT"


def column_type_code(mariadb_type: str) -> int:
    """The MySQL protocol type code PyMySQL sees in ``cursor.description``."""
    t = mariadb_type.lower()
    if t.startswith("bigint"):
        return 8  # LONGLONG
    if any(t.startswith(k) for k in _INT_TYPES):
        return 3  # LONG
    if t.startswith("datetime"):
        return 12
    if t.startswith("timestamp"):
        return 7
    if t.startswith("date"):
        return 10
    if t.startswith("time"):
        return 11
    if t.startswith(("double", "float")):
        return 5
    if any(t.startswith(k) for k in _REAL_TYPES):
        return 246  # NEWDECIMAL
    if t.startswith("longtext"):
        return 251  # LONG_BLOB
    if t.startswith(("mediumtext", "text", "tinytext", "blob", "json")):
        return 252  # BLOB
    return 253  # VAR_STRING


@dataclass
class TableMeta:
    """What DESCRIBE, SHOW CREATE TABLE and result-set typing need about one table."""

    name: str
    create: str
    columns: list[list[Any]]  # [name, type, null, key, default, extra]

    def column(self, name: str) -> list[Any] | None:
        low = name.lower()
        return next((c for c in self.columns if c[0].lower() == low), None)

    @classmethod
    def from_profile(cls, name: str, meta: dict[str, Any]) -> TableMeta:
        return cls(name, meta["create"], [list(c) for c in meta["columns"]])


@dataclass
class Profile:
    deployment_id: str
    handshake: dict[str, Any]
    server_version: str
    version: str
    version_comment: str
    variables: dict[str, str]
    users: list[dict[str, Any]]
    databases: dict[str, dict[str, TableMeta]]
    rows: dict[str, dict[str, list[list[Any]]]]
    errors: dict[str, dict[str, Any]]
    reference_queries: dict[str, dict[str, Any]]
    max_allowed_packet: int
    denied_root_over_tcp: bool = True

    @classmethod
    def load(cls, profile_dir: Path) -> Profile:
        p = json.loads((profile_dir / "mysql.json").read_text())
        return cls(
            deployment_id=p["deployment_id"],
            handshake=p["handshake"],
            server_version=p["server_version"],
            version=p["version"],
            version_comment=p["version_comment"],
            variables={k.lower(): str(v) for k, v in p["variables"].items()},
            users=p["users"],
            databases={
                db: {t: TableMeta.from_profile(t, meta) for t, meta in tables.items()}
                for db, tables in p["databases"].items()
            },
            rows={
                db: {t: meta["rows"] for t, meta in tables.items() if meta.get("rows")}
                for db, tables in p["databases"].items()
            },
            errors=p["errors"],
            reference_queries=p["reference_queries"],
            max_allowed_packet=int(p["max_allowed_packet"]),
            denied_root_over_tcp=p.get("denied_root_over_tcp", True),
        )

    def user(self, username: str) -> dict[str, Any] | None:
        return next((u for u in self.users if u["user"] == username), None)

    def tables_of(self, db: str, st: SourceState) -> dict[str, TableMeta]:
        return {**self.databases.get(db, {}), **st.created.get(db, {})}


def _ddl(db: str, meta: TableMeta) -> str:
    """SQLite DDL for one table, built from the profile's column metadata."""
    cols, pk = [], []
    for c in meta.columns:
        piece = f'"{c[0]}" {affinity(c[1])}'
        if c[2] == "NO":
            piece += " NOT NULL"
        if c[4] is not None and c[2] != "NO":
            piece += f" DEFAULT '{c[4]}'" if isinstance(c[4], str) else f" DEFAULT {c[4]}"
        if c[3] == "PRI":
            pk.append(c[0])
        cols.append(piece)
    ddl = f'CREATE TABLE "{db}"."{meta.name}" ({", ".join(cols)}'
    if pk:
        ddl += ", PRIMARY KEY (" + ", ".join(f'"{c}"' for c in pk) + ")"
    return ddl + ")"


@dataclass
class SourceState:
    """Everything one source address can change: its SQLite copy and its current database."""

    conn: sqlite3.Connection
    current_db: str | None = None
    created: dict[str, dict[str, TableMeta]] = field(default_factory=dict)
    dropped: set[str] = field(default_factory=set)  # databases the source dropped
    first_write: float | None = None
    deadline: float = 0.0  # monotonic time the running statement must finish by

    def start_statement(self) -> None:
        self.deadline = time.monotonic() + STATEMENT_BUDGET_S

    def _over_budget(self) -> int:
        return 1 if time.monotonic() > self.deadline else 0  # non-zero aborts the statement

    def wrote(self) -> None:
        if self.first_write is None:
            self.first_write = time.time()

    def remember(self, db: str, meta: TableMeta) -> None:
        self.created.setdefault(db, {})[meta.name] = meta

    def metadata(self, db: str, table: str, profile: Profile) -> TableMeta | None:
        return profile.tables_of(db, self).get(table)

    def table_names(self, db: str, profile: Profile) -> list[str]:
        return sorted(profile.tables_of(db, self))


class Registry:
    """Source address -> state, created on first sight, reset 24h after the first write."""

    def __init__(self, profile: Profile) -> None:
        self.profile = profile
        self.states: dict[str, SourceState] = {}
        self._ids = 0

    def next_id(self) -> int:
        """Connection ids (the handshake's thread id column)."""
        self._ids += 1
        return self._ids

    def get(self, ip: str) -> SourceState:
        st = self.states.get(ip)
        if st is None or (st.first_write and time.time() - st.first_write >= RESET_AFTER_S):
            if st is None and len(self.states) >= MAX_SOURCES:
                self._evict()
            st = self.states[ip] = self.fresh()
        return st

    # P10 reads better at the call site spelled out.
    state_for = get

    def fresh(self) -> SourceState:
        p = self.profile
        conn = sqlite3.connect(":memory:")
        for db, tables in p.databases.items():
            if not tables:
                continue
            conn.execute(f'ATTACH ":memory:" AS "{db}"')
            for name, meta in tables.items():
                conn.execute(_ddl(db, meta))
                rows = p.rows.get(db, {}).get(name) or []
                if rows:
                    marks = ",".join("?" * len(rows[0]))
                    # db and table names come from the deployment profile, values are bound
                    sql = f'INSERT INTO "{db}"."{name}" VALUES ({marks})'  # noqa: S608
                    conn.executemany(sql, rows)
        conn.commit()
        st = SourceState(conn)
        # Guards go on after seeding: from here on every statement is a client's.
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_VALUE_BYTES)
        conn.set_authorizer(_authorizer)
        conn.set_progress_handler(st._over_budget, 1000)
        return st

    def _evict(self) -> None:
        victim = min(self.states, key=lambda ip: self.states[ip].first_write or 0)
        del self.states[victim]
