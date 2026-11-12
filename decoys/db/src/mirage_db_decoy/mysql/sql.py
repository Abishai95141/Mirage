"""The MySQL query subset (spec 1.5): sqlglot parse, in-memory SQLite, MariaDB errors.

Every statement is one of the profile's measured shapes or part of the subset (single-table
SELECT with WHERE/ORDER BY/LIMIT/COUNT(*), INSERT, UPDATE, DELETE, CREATE/DROP TABLE, USE,
SET, SHOW and DESCRIBE of metadata). Anything else gets MariaDB's 1064. SQLite errors are
mapped to MariaDB codes: 1146 missing table, 1054 unknown column, 1064 syntax. The classic
probes are answered from the profile's measured texts: INTO OUTFILE/DUMPFILE (1227),
CREATE FUNCTION ... SONAME (1126), LOAD_FILE (NULL).
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import sqlglot
import sqlglot.errors
import sqlglot.expressions as exp

from mirage_db_decoy.mysql.proto import Column
from mirage_db_decoy.mysql.state import Profile, SourceState, TableMeta, column_type_code

LIKE_RE = re.compile(r"%|_|[^%_]+")
INT_RE = re.compile(r"-?\d+$")
OUTFILE_RE = re.compile(r"\bINTO\s+(OUTFILE|DUMPFILE)\b", re.I)
SONAME_RE = re.compile(r"\bCREATE\s+(?:AGGREGATE\s+)?FUNCTION\b.*\bSONAME\s+'([^']+)'", re.I | re.S)

SQLSTATE = {
    1008: "HY000",
    1044: "42000",
    1045: "28000",
    1698: "28000",
    1046: "3D000",
    1047: "08S01",
    1049: "42000",
    1050: "42S01",
    1051: "42S02",
    1054: "42S22",
    1062: "23000",
    1064: "42000",
    1126: "HY000",
    1136: "21S01",
    1146: "42S02",
    1153: "08S01",
    1193: "HY000",
    1227: "42000",
    1317: "70100",
}


@dataclass
class Result:
    """One statement's reply: an OK packet, a result set, or an error."""

    affected: int = 0
    columns: list[Column] = field(default_factory=list)
    rows: list[list[Any]] = field(default_factory=list)
    error: tuple[int, str] | None = None
    more: bool = False  # SERVER_MORE_RESULTS_EXISTS (multi-statement queries)
    changes: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class Ctx:
    """Who is asking, and from where; collects the results of a multi-statement query."""

    user: str
    ip: str
    results: list[Result] = field(default_factory=list)


class Engine:
    def __init__(self, profile: Profile) -> None:
        self.p = profile
        # Measured texts for the classic probes (data-driven; never typed from memory).
        q = profile.reference_queries
        self.outfile_msg = self._probe_error(
            q, lambda key: "INTO OUTFILE" in key or "INTO DUMPFILE" in key
        )
        self.udf_key = next((k for k in q if "CREATE FUNCTION" in k and q[k].get("error")), "")
        self.udf_template = q[self.udf_key]["error"]["message"] if self.udf_key else ""
        self.udf_lib = _quoted(self.udf_key, "SONAME")
        # @@vars the reference reports as NULL when the configured value is the empty string.
        self.null_when_empty = {
            col[2:].lower()
            for v in q.values()
            if v.get("rows") and v["rows"][0] == [None]
            for col in v.get("columns", [])
            if col.startswith("@@")
        }

    @staticmethod
    def _probe_error(queries: dict[str, Any], pick: Callable[[str], bool]) -> str:
        return next(
            (v["error"]["message"] for k, v in queries.items() if v.get("error") and pick(k)), ""
        )

    # ------------------------------------------------------------------ entry point

    def execute(self, st: SourceState, sql: str, user: str, src_ip: str) -> list[Result]:
        """One result per statement of a (multi-)statement query, stopping at the first error
        as MariaDB does; every result but the last carries SERVER_MORE_RESULTS_EXISTS."""
        ctx = Ctx(user, src_ip)
        for statement in self._statements(sql):
            st.start_statement()
            result = self._one(st, statement, ctx)
            if ctx.results:
                ctx.results[-1].more = True
            ctx.results.append(result)
            if not result.ok:
                break
        return ctx.results

    def _statements(self, sql: str) -> list[str]:
        """Split on top-level semicolons, keeping each statement's original text (the column
        names of a SELECT are echoed from it)."""
        out: list[str] = []
        piece: list[str] = []
        depth, quote = 0, ""
        for c in sql:
            piece.append(c)
            if quote:
                quote = "" if c == quote else quote
            elif c in "'\"`":
                quote = c
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif c == ";" and depth == 0:
                # the separator is not part of the statement (nor of its echoed column names)
                if stmt := "".join(piece[:-1]).strip():
                    out.append(stmt)
                piece = []
        if tail := "".join(piece).strip():
            out.append(tail)
        return out or [sql]

    def _one(self, st: SourceState, sql: str, ctx: Ctx) -> Result:
        if OUTFILE_RE.search(sql):
            return Result(error=(1227, self.outfile_msg))
        if m := SONAME_RE.search(sql):
            return Result(error=(1126, self.udf_template.replace(self.udf_lib, m.group(1))))
        try:
            node = sqlglot.parse_one(sql, dialect="mysql")
        except sqlglot.errors.ParseError:
            return Result(error=(1064, _syntax_msg(sql)))
        return self._dispatch(node, sql, st, ctx)

    # ------------------------------------------------------------------ dispatch

    def _dispatch(self, node: exp.Expression, sql: str, st: SourceState, ctx: Ctx) -> Result:
        if isinstance(node, exp.Select):
            return self._select(node, sql, st, ctx)
        if isinstance(node, exp.Show):
            return self._show(node, st, ctx)
        if isinstance(node, exp.Describe):
            return self._describe(node, st)
        if isinstance(node, exp.Use):
            return self._use(node, st)
        if isinstance(node, exp.Set):
            return Result()
        if isinstance(node, exp.Command) and str(node.this).upper() == "PREPARE":
            return Result()
        if isinstance(node, exp.Insert):
            return self._write(node, sql, st, "insert")
        if isinstance(node, exp.Update):
            return self._write(node, sql, st, "update")
        if isinstance(node, exp.Delete):
            return self._write(node, sql, st, "delete")
        if isinstance(node, exp.Create) and str(node.args.get("kind", "")).upper() == "TABLE":
            return self._create(node, sql, st)
        if isinstance(node, exp.Drop):
            kind = str(node.args.get("kind", "")).upper()
            if kind == "TABLE":
                return self._drop_table(node, sql, st)
            if kind in ("DATABASE", "SCHEMA"):
                return self._drop_database(node, st)
        return Result(error=(1064, _syntax_msg(sql)))

    # ------------------------------------------------------------------ SELECT

    def _select(self, node: exp.Select, sql: str, st: SourceState, ctx: Ctx) -> Result:
        from_ = _from_of(node)
        if from_ is None or _is_dual(from_.this):
            return self._select_exprs(node, sql, st, ctx)
        if not _subset_select(node):
            return Result(error=(1064, _syntax_msg(sql)))
        table = from_.this
        db = _db_name(table) or st.current_db
        if db is None:
            return Result(error=(1046, "No database selected"))
        if db in st.dropped or db not in self.p.databases:
            return Result(error=(1049, f"Unknown database '{db}'"))
        meta = st.metadata(db, table.name, self.p)
        if meta is None:
            return Result(error=(1146, f"Table '{db}.{table.name}' doesn't exist"))
        query = self._prepare(node, st).sql(dialect="sqlite")
        try:
            cur = st.conn.execute(query)
            rows = [list(r) for r in cur.fetchall()]
        except sqlite3.Error as exc:
            return _sqlite_error(str(exc), node)
        return Result(columns=self._columns(node, sql, meta, st), rows=rows)

    def _prepare(self, node: exp.Select, st: SourceState) -> exp.Expression:
        """Rewrite what SQLite cannot run: LOAD_FILE(x) -> NULL, @@vars -> literals."""

        def repl(n: exp.Expression) -> exp.Expression:
            if isinstance(n, exp.Anonymous) and str(n.this).upper() == "LOAD_FILE":
                return exp.Null()
            if isinstance(n, exp.SessionParameter):
                value = self.p.variables.get(str(n.this).lower())
                return exp.Literal.string(value) if value is not None else exp.Null()
            return n

        return node.transform(repl)

    def _select_exprs(self, node: exp.Select, sql: str, st: SourceState, ctx: Ctx) -> Result:
        """SELECT without FROM: @@variables and the session functions, as MariaDB answers."""
        names, values, types = [], [], []
        pieces = _select_pieces(sql)
        for i, e in enumerate(node.expressions):
            raw = pieces[i] if i < len(pieces) else e.sql(dialect="mysql")
            got = self._expr_value(e, raw, st, ctx)
            if isinstance(got, Result):
                return got
            names.append(got[0])
            values.append(got[1])
            types.append(got[2])
        return Result(
            columns=[Column(n, t) for n, t in zip(names, types, strict=True)], rows=[values]
        )

    def _expr_value(
        self, e: exp.Expression, raw: str, st: SourceState, ctx: Ctx
    ) -> tuple[str, Any, int] | Result:
        alias = e.alias if isinstance(e, exp.Alias) else ""
        inner = e.this if isinstance(e, exp.Alias) else e
        if isinstance(inner, exp.SessionParameter):
            return self._variable(str(inner.this), alias or raw, st)
        if isinstance(inner, exp.Null):
            return alias or raw, None, 6
        if isinstance(inner, exp.Literal):
            value = int(inner.this) if not inner.is_string else inner.this
            return alias or raw, value, 3 if not inner.is_string else 253
        if isinstance(inner, exp.Count):
            return alias or raw, 1, 8  # COUNT(*) with no FROM: one row over zero tables
        if isinstance(inner, exp.Anonymous) and str(inner.this).upper() == "LOAD_FILE":
            return alias or raw, None, 251  # measured: LOAD_FILE is always NULL here
        name = _func_name(inner)
        if name in FUNC_TYPES:
            code, fn = FUNC_TYPES[name]
            value = fn(self, st, ctx)
            if name in self.null_when_empty and value == "":
                value = None
            return alias or raw, value, code
        return Result(error=(1064, _syntax_msg(raw)))

    def _variable(self, name: str, raw: str, st: SourceState) -> tuple[str, Any, int] | Result:
        low = name.lower()
        if low not in self.p.variables:
            return Result(error=(1193, f"Unknown system variable '{name}'"))
        value: Any = self.p.variables[low]
        if low in self.null_when_empty and value == "":
            value = None
        return raw, value, 8 if isinstance(value, str) and INT_RE.fullmatch(value) else 253

    def _columns(
        self, node: exp.Select, sql: str, meta: TableMeta, st: SourceState
    ) -> list[Column]:
        pieces = _select_pieces(sql)
        out: list[Column] = []
        for i, e in enumerate(node.expressions):
            raw = pieces[i] if i < len(pieces) else e.sql(dialect="mysql")
            if isinstance(e, exp.Star) or (
                isinstance(e, exp.Column) and isinstance(e.this, exp.Star)
            ):
                out += [
                    Column(c[0], column_type_code(c[1]), table=meta.name, org_name=c[0])
                    for c in meta.columns
                ]
                continue
            name = e.alias or raw
            out.append(Column(name, self._type_of(e, meta), table=meta.name))
        return out

    def _type_of(self, e: exp.Expression, meta: TableMeta) -> int:
        inner = e.this if isinstance(e, exp.Alias) else e
        if isinstance(inner, exp.Count):
            return 8
        if isinstance(inner, exp.Column) and meta is not None:
            c = meta.column(inner.name)
            if c is not None:
                return column_type_code(c[1])
        if isinstance(inner, exp.Literal):
            return 3 if not inner.is_string else 253
        if isinstance(inner, exp.Null):
            return 6
        return 253

    # ------------------------------------------------------------------ metadata

    def _show(self, node: exp.Show, st: SourceState, ctx: Ctx) -> Result:
        what = str(node.this).upper()
        like = node.args.get("like")
        pattern = _like_regex(like.this) if like is not None else None
        if what == "DATABASES":
            rows = [
                [n]
                for n in sorted(set(self.p.databases) - st.dropped)
                if pattern is None or pattern.match(n)
            ]
            return Result(columns=[Column("Database", 253)], rows=rows)
        if what == "TABLES":
            db_arg = node.args.get("db")
            db = _ident_name(db_arg) or st.current_db
            if db is None:
                return Result(error=(1046, "No database selected"))
            if db in st.dropped or db not in self.p.databases:
                return Result(error=(1049, f"Unknown database '{db}'"))
            rows = [[t] for t in st.table_names(db, self.p) if pattern is None or pattern.match(t)]
            return Result(columns=[Column(f"Tables_in_{db}", 253)], rows=rows)
        if what == "VARIABLES":
            rows = [
                [k, v]
                for k, v in sorted(self.p.variables.items())
                if pattern is None or pattern.match(k)
            ]
            return Result(columns=[Column("Variable_name", 253), Column("Value", 253)], rows=rows)
        if what == "GRANTS":
            user = self.p.user(ctx.user) or {}
            name = f"Grants for {ctx.user}@{user.get('host', '%')}"
            return Result(
                columns=[Column(name, 253)],
                rows=[[g] for g in user.get("grants", [])],
            )
        if what == "CREATE TABLE":
            return self._show_create(node, st)
        return Result(error=(1064, "Unsupported SHOW statement"))

    def _show_create(self, node: exp.Show, st: SourceState) -> Result:
        target, db_arg = node.args.get("target"), node.args.get("db")
        if target is None:
            return Result(error=(1064, "Unsupported SHOW statement"))
        db = _ident_name(db_arg) or st.current_db
        name = _ident_name(target)
        if db is None:
            return Result(error=(1046, "No database selected"))
        if db in st.dropped or db not in self.p.databases:
            return Result(error=(1049, f"Unknown database '{db}'"))
        meta = st.metadata(db, name, self.p)
        if meta is None:
            return Result(error=(1146, f"Table '{db}.{name}' doesn't exist"))
        return Result(
            columns=[Column("Table", 253), Column("Create Table", 253)],
            rows=[[meta.name, meta.create]],
        )

    def _describe(self, node: exp.Describe, st: SourceState) -> Result:
        table = node.this
        if not isinstance(table, exp.Table):
            return Result(error=(1064, "Unsupported DESCRIBE statement"))
        db = _db_name(table) or st.current_db
        if db is None:
            return Result(error=(1046, "No database selected"))
        if db in st.dropped or db not in self.p.databases:
            return Result(error=(1049, f"Unknown database '{db}'"))
        meta = st.metadata(db, table.name, self.p)
        if meta is None:
            return Result(error=(1146, f"Table '{db}.{table.name}' doesn't exist"))
        cols = [
            Column(n, t)
            for n, t in zip(
                ("Field", "Type", "Null", "Key", "Default", "Extra"),
                (253, 252, 253, 253, 252, 253),
                strict=True,
            )
        ]
        return Result(columns=cols, rows=[list(c) for c in meta.columns])

    def _use(self, node: exp.Use, st: SourceState) -> Result:
        db = _ident_name(node.this)
        if db is None or db in st.dropped or db not in self.p.databases:
            return Result(error=(1049, f"Unknown database '{db}'"))
        st.current_db = db
        return Result()

    # ------------------------------------------------------------------ writes

    def _write(self, node: exp.Expression, sql: str, st: SourceState, op: str) -> Result:
        table = node.this
        if isinstance(table, exp.Schema):
            table = table.this
        if not isinstance(table, exp.Table):
            return Result(error=(1064, _syntax_msg(sql)))
        db = _db_name(table) or st.current_db
        if db is None:
            return Result(error=(1046, "No database selected"))
        if db in st.dropped or db not in self.p.databases:
            return Result(error=(1049, f"Unknown database '{db}'"))
        if st.metadata(db, table.name, self.p) is None:
            return Result(error=(1146, f"Table '{db}.{table.name}' doesn't exist"))
        if missing := self._unknown_table(node, st):
            return missing
        try:
            cur = st.conn.execute(node.sql(dialect="sqlite"))
            st.conn.commit()
        except sqlite3.Error as exc:
            return _sqlite_error(str(exc), node)
        st.wrote()
        affected = max(cur.rowcount, 0)
        result = Result(affected=affected)
        result.changes.append(
            {"op": op, "db": db, "table": table.name, "rows": affected, "sql": sql}
        )
        return result

    def _unknown_table(self, node: exp.Expression, st: SourceState) -> Result | None:
        """1146 for the first table a statement reads that this source does not have - which
        also keeps SQLite's own tables (sqlite_master, ...) out of reach."""
        ctes = {c.alias_or_name.lower() for c in node.find_all(exp.CTE)}
        for t in node.find_all(exp.Table):
            db = _db_name(t) or st.current_db
            if not t.db and t.name.lower() in ctes:
                continue
            if db is None:
                return Result(error=(1046, "No database selected"))
            if st.metadata(db, t.name, self.p) is None:
                return Result(error=(1146, f"Table '{db}.{t.name}' doesn't exist"))
        return None

    def _create(self, node: exp.Create, sql: str, st: SourceState) -> Result:
        schema = node.this
        table = schema.this if isinstance(schema, exp.Schema) else schema
        if not isinstance(table, exp.Table):
            return Result(error=(1064, _syntax_msg(sql)))
        db = _db_name(table) or st.current_db
        if db is None:
            return Result(error=(1046, "No database selected"))
        if db in st.dropped or db not in self.p.databases:
            return Result(error=(1049, f"Unknown database '{db}'"))
        if st.metadata(db, table.name, self.p) is not None:
            return Result(error=(1050, f"Table '{db}.{table.name}' already exists"))
        meta = _table_from_create(table.name, schema)
        try:
            st.conn.execute(_sqlite_ddl(db, meta))
            st.conn.commit()
        except sqlite3.Error as exc:
            return _sqlite_error(str(exc), node)
        st.wrote()
        st.remember(db, meta)
        result = Result()
        result.changes.append({"op": "create", "db": db, "table": meta.name, "sql": sql})
        return result

    def _drop_table(self, node: exp.Drop, sql: str, st: SourceState) -> Result:
        tables = node.args.get("tables") or []
        if len(tables) != 1 or not isinstance(tables[0], exp.Table):
            return Result(error=(1064, _syntax_msg(sql)))
        table = tables[0]
        db = _db_name(table) or st.current_db
        if db is None:
            return Result(error=(1046, "No database selected"))
        meta = st.metadata(db, table.name, self.p)
        if meta is None:
            if db in st.dropped or db not in self.p.databases:
                return Result(error=(1049, f"Unknown database '{db}'"))
            return Result(error=(1051, f"Unknown table '{db}.{table.name}'"))
        try:
            st.conn.execute(f'DROP TABLE "{db}"."{table.name}"')
            st.conn.commit()
        except sqlite3.Error as exc:
            return _sqlite_error(str(exc), node)
        st.wrote()
        st.created.get(db, {}).pop(meta.name, None)
        result = Result()
        result.changes.append({"op": "drop", "db": db, "table": meta.name, "sql": sql})
        return result

    def _drop_database(self, node: exp.Drop, st: SourceState) -> Result:
        tables = node.args.get("tables") or []
        db = tables[0].name if len(tables) == 1 and isinstance(tables[0], exp.Table) else None
        if db is None or db not in self.p.databases or db in st.dropped:
            return Result(error=(1008, f"Can't drop database '{db}'; database doesn't exist"))
        for name in st.table_names(db, self.p):
            st.conn.execute(f'DROP TABLE "{db}"."{name}"')
        st.conn.commit()
        st.wrote()
        st.created.pop(db, None)
        st.dropped.add(db)
        result = Result()
        result.changes.append({"op": "drop_database", "db": db})
        return result


FUNC_TYPES: dict[str, tuple[int, Callable[[Engine, SourceState, Ctx], Any]]] = {
    "VERSION": (253, lambda eng, st, ctx: eng.p.version),
    "DATABASE": (253, lambda eng, st, ctx: st.current_db),
    "USER": (253, lambda eng, st, ctx: f"{ctx.user}@{ctx.ip}"),
    "CURRENT_USER": (253, lambda eng, st, ctx: f"{ctx.user}@%"),
    "NOW": (
        12,
        lambda eng, st, ctx: datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"),
    ),
}


# ------------------------------------------------------------------ helpers


def _func_name(inner: exp.Expression) -> str:
    named = {
        "CurrentVersion": "VERSION",
        "CurrentSchema": "DATABASE",
        "CurrentUser": "CURRENT_USER",
    }
    if type(inner).__name__ in named:
        return named[type(inner).__name__]
    if isinstance(inner, exp.Anonymous):
        return str(inner.this).upper()
    return ""


def _syntax_msg(near: str) -> str:
    near = near.strip().rstrip(";").strip()
    return (
        "You have an error in your SQL syntax; check the manual that corresponds to your "
        f"MariaDB server version for the right syntax to use near '{near}' at line 1"
    )


def _swap_quoted(template: str, value: str) -> str:
    """The measured 1126 text names the library; put the client's library in it."""
    if not template:
        return template
    return re.sub(r"'([^']+)'", f"'{value}'", template, count=1)


def _quoted(text: str, keyword: str) -> str:
    """The quoted word after ``keyword`` (e.g. the SONAME library of the measured probe)."""
    if m := re.search(keyword + r"\s+'([^']+)'", text, re.I):
        return m.group(1)
    return ""


def _sqlite_error(msg: str, node: exp.Expression) -> Result:
    if msg == "interrupted":  # the statement budget ran out
        return Result(error=(1317, "Query execution was interrupted"))
    if m := re.match(r"no such table: (.+)", msg):
        return Result(error=(1146, f"Table '{m.group(1)}' doesn't exist"))
    if m := re.match(r"no such column: (.+)", msg):
        context = _column_context(m.group(1), node)
        return Result(error=(1054, f"Unknown column '{m.group(1)}' in '{context}'"))
    if m := re.search(r"has no column named (.+)", msg):
        return Result(error=(1054, f"Unknown column '{m.group(1)}' in 'field list'"))
    if re.search(r"\d+ columns? but \d+ values? (were|was) supplied", msg):
        return Result(error=(1136, "Column count doesn't match value count at row 1"))
    if "UNIQUE constraint failed" in msg:
        return Result(error=(1062, "Duplicate entry for key 'PRIMARY'"))
    return Result(error=(1064, _syntax_msg(node.sql(dialect="mysql"))))


def _column_context(column: str, node: exp.Expression) -> str:
    """Where MariaDB says an unknown column lives; the measured SELECT-list probe says 'SELECT'."""
    low = column.lower().strip("'\"`")

    def has(where: exp.Expression | None) -> bool:
        return where is not None and any(
            isinstance(x, exp.Column) and x.name.lower() == low for x in where.walk()
        )

    if isinstance(node, exp.Select):
        if any(
            isinstance(e, (exp.Column, exp.Alias)) and _col_name(e) == low for e in node.expressions
        ):
            return "SELECT"
        if has(node.args.get("where")):
            return "where clause"
        if has(node.args.get("order")):
            return "order clause"
    return "field list"


def _col_name(e: exp.Expression) -> str:
    inner = e.this if isinstance(e, exp.Alias) else e
    return inner.name.lower() if isinstance(inner, exp.Column) else ""


def _like_regex(pattern: str) -> re.Pattern[str]:
    out = []
    for m in LIKE_RE.finditer(pattern):
        token = m.group(0)
        out.append(".*" if token == "%" else "." if token == "_" else re.escape(token))  # noqa: S105
    return re.compile("^" + "".join(out) + "$", re.I)


def _is_dual(table: exp.Expression) -> bool:
    return isinstance(table, exp.Table) and not table.db and table.name.lower() == "dual"


def _db_name(table: exp.Table) -> str | None:
    """A table's database qualifier; sqlglot hands back an Identifier or a bare str."""
    db = table.db
    if db is None:
        return None
    return db if isinstance(db, str) else db.name


def _ident_name(x: Any) -> str | None:
    if x is None:
        return None
    return x if isinstance(x, str) else x.name


def _subset_select(node: exp.Select) -> bool:
    """The spec's subset: one table, no joins, subqueries, windows, groups or CTEs."""
    if (
        node.args.get("joins")
        or node.args.get("laterals")
        or node.args.get("with_")
        or node.args.get("group")
        or node.args.get("having")
        or node.args.get("windows")
    ):
        return False
    if not isinstance(_from_of(node), exp.From):
        return False
    return not any(isinstance(x, exp.Select) for x in node.walk() if x is not node)


def _from_of(node: exp.Select) -> exp.From | None:
    return node.args.get("from_") or node.args.get("from")


def _select_pieces(sql: str) -> list[str]:
    """The select list as the client wrote it (MariaDB echoes it as the column names)."""
    m = re.match(r"\s*SELECT\s+(.*)", sql, re.I | re.S)
    if m is None:
        return []
    body = m.group(1)
    pieces: list[str] = []
    piece: list[str] = []
    depth, quote, i = 0, "", 0
    while i < len(body):
        c = body[i]
        if quote:
            if c == quote:
                quote = ""
        elif c in "'\"`":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif depth == 0:
            if c == ",":
                pieces.append("".join(piece).strip())
                piece = []
                i += 1
                continue
            if re.match(r"FROM\s|LIMIT\s|UNION\s", body[i:], re.I):
                break
        piece.append(c)
        i += 1
    pieces.append("".join(piece).strip())
    return [p for p in pieces if p]


def _table_from_create(name: str, schema: exp.Schema) -> TableMeta:
    pk: str | None = None
    for item in schema.expressions:  # the PRIMARY KEY clause may precede no column
        if isinstance(item, exp.PrimaryKey):
            pk = ", ".join(x.name for x in item.expressions)
    columns: list[list[Any]] = []
    for item in schema.expressions:
        if not isinstance(item, exp.ColumnDef):
            continue
        kind = getattr(item, "kind", None)
        dtype = kind.sql(dialect="mysql").lower() if kind is not None else "text"
        null = "NO" if item.find(exp.NotNullColumnConstraint) else "YES"
        key = "PRI" if item.find(exp.PrimaryKeyColumnConstraint) else ""
        extra = "auto_increment" if item.find(exp.AutoIncrementColumnConstraint) else ""
        default = None
        if d := item.find(exp.DefaultColumnConstraint):
            default = (
                d.this.this if isinstance(d.this, exp.Literal) else d.this.sql(dialect="mysql")
            )
        columns.append(
            [
                item.name,
                dtype,
                null,
                key or ("PRI" if _is_pk(pk, item.name) else ""),
                default,
                extra,
            ]
        )
    create = (
        f"CREATE TABLE `{name}` (\n  "
        + ",\n  ".join(
            f"`{c[0]}` {c[1]}"
            + (" NOT NULL" if c[2] == "NO" else "")
            + (f" DEFAULT '{c[4]}'" if c[4] is not None else "")
            for c in columns
        )
        + (f",\n  PRIMARY KEY ({pk})" if pk else "")
        + "\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    )
    return TableMeta(name, create, columns)


def _is_pk(pk: str | None, name: str) -> bool:
    return pk is not None and name in [x.strip().strip("`") for x in pk.split(",")]


def _sqlite_ddl(db: str, meta: TableMeta) -> str:
    from mirage_db_decoy.mysql.state import affinity

    cols = []
    for c in meta.columns:
        piece = f'"{c[0]}" {affinity(c[1])}'
        if c[2] == "NO":
            piece += " NOT NULL"
        if c[3] == "PRI":
            piece += " PRIMARY KEY"
        cols.append(piece)
    return f'CREATE TABLE "{db}"."{meta.name}" ({", ".join(cols)})'
