"""MySQL decoy: handshake bytes, auth, the query subset, per-source state, gating, limits.

PyMySQL (synchronous) runs in a worker thread and reaches the asyncio server through the
conftest Relay, which adds the PROXY v2 header the edge would. Measured texts come from the
rendered profile (``mysql.json``: handshake, errors, reference_queries).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import time

import pymysql
import pytest
from conftest import SRC_IP, FakeGate, Relay, decoy, handshake_of

from mirage_db_decoy.mysql import state as state_mod
from mirage_db_decoy.mysql.handler import Handler
from mirage_db_decoy.mysql.sql import Engine
from mirage_db_decoy.mysql.state import RESET_AFTER_S, Profile, Registry
from mirage_decoy_common.gate import Applied
from mirage_decoy_common.server import connection_handler
from mirage_schema.policy import Action, Protocol

COM_FIELD_LIST, COM_STMT_PREPARE = 0x05, 0x16


class Srv:
    def __init__(self, d, port: int, profile: Profile, raw: dict) -> None:
        self.decoy, self.port, self.profile, self.raw = d, port, profile, raw
        self.relays: dict[str, Relay] = {}
        self.conns: list[pymysql.connections.Connection] = []
        self.user = profile.users[0]

    def of(self, eventid: str) -> list[dict]:
        return [e for e in self.decoy.log.records if e["eventid"] == eventid]

    async def relay(self, src: str = SRC_IP) -> Relay:
        if src not in self.relays:
            self.relays[src] = await Relay(self.port, src_ip=src).start()
        return self.relays[src]

    async def connect(self, src: str = SRC_IP, **kw) -> pymysql.connections.Connection:
        relay = await self.relay(src)
        args = {
            "host": "127.0.0.1",
            "port": relay.port,
            "user": self.user["user"],
            "password": self.user["password"],
            "connect_timeout": 5,
            "read_timeout": 5,
            "autocommit": True,
            **kw,
        }
        conn = await asyncio.to_thread(pymysql.connect, **args)
        self.conns.append(conn)
        return conn

    async def refused(self, src: str = SRC_IP, **kw) -> pymysql.MySQLError:
        with pytest.raises(pymysql.MySQLError) as info:
            await self.connect(src, **kw)
        return info.value

    async def closed(self, sessions: int) -> list[dict]:
        for _ in range(300):
            if len(self.of("mysql.session.closed")) >= sessions:
                break
            await asyncio.sleep(0.01)
        return self.decoy.log.records


async def q(conn, sql: str, args=None):
    """(column (name, type) pairs or None, rows or affected count) for one statement."""

    def run():
        with conn.cursor() as cur:
            cur.execute(sql, args)
            if cur.description is None:
                return None, cur.rowcount
            return [d[:2] for d in cur.description], [list(r) for r in cur.fetchall()]

    return await asyncio.to_thread(run)


async def q_err(conn, sql: str, args=None) -> tuple[int, str]:
    with pytest.raises(pymysql.MySQLError) as info:
        await q(conn, sql, args)
    return info.value.args[0], info.value.args[1]


@pytest.fixture
async def srv(profile_dir, tmp_path):
    profile = Profile.load(profile_dir)
    raw = json.loads((profile_dir / "mysql.json").read_text())
    d = decoy(Protocol.MYSQL, artifacts=tmp_path / "art")
    handler = Handler(profile, Registry(profile), Engine(profile))
    server = await asyncio.start_server(connection_handler(d, handler, True), "127.0.0.1", 0)
    s = Srv(d, server.sockets[0].getsockname()[1], profile, raw)
    yield s
    for conn in s.conns:
        with contextlib.suppress(Exception):
            await asyncio.to_thread(conn.close)
    for relay in s.relays.values():
        await asyncio.wait_for(relay.stop(), 5)
    server.close()
    await asyncio.wait_for(server.wait_closed(), 5)


def ref(srv: Srv, sql: str) -> dict:
    return srv.raw["reference_queries"][sql]


# ------------------------------------------------------------------ handshake and auth


async def test_handshake_matches_profile_byte_for_byte(srv):
    relay = await srv.relay()
    r, w = await asyncio.open_connection("127.0.0.1", relay.port)
    header = await r.readexactly(4)
    n, seq = header[0] | header[1] << 8 | header[2] << 16, header[3]
    got = handshake_of(await r.readexactly(n))
    w.close()
    hs = srv.raw["handshake"]
    assert seq == 0
    for key in ("protocol", "server_version", "capabilities", "charset", "status"):
        assert got[key] == hs[key], key
    assert got["auth_data_len"] == hs["auth_data_len"]
    assert got["reserved_hex"] == hs["reserved_hex"]
    assert got["auth_plugin"] == hs["auth_plugin"]
    assert got["len"] == hs["packet_hex_len"]


async def test_login_success_logs_the_password(srv):
    conn = await srv.connect()
    assert await q(conn, "SELECT 1") == ([("1", 3)], [[1]])
    (ok,) = srv.of("mysql.login.success")
    assert (ok["username"], ok["password"]) == (srv.user["user"], srv.user["password"])


async def test_login_failures_use_the_profile_texts(srv):
    errors = srv.profile.errors

    def expect(key: str, user: str) -> tuple[int, str]:
        e = errors[key]
        return int(e["code"]), re.sub(r"'[^']*'@'[^']*'", f"'{user}'@'{SRC_IP}'", e["message"])

    e = await srv.refused(password="wrong")
    assert e.args == expect("denied_password", srv.user["user"])
    assert e.args[1].endswith("(using password: YES)")
    e = await srv.refused(user="nosuchuser", password="x")
    assert e.args == expect("denied_unknown_user", "nosuchuser")
    e = await srv.refused(user="admin", password="")
    assert e.args == expect("denied_nopassword", "admin")
    assert "using password" not in e.args[1]

    fails = srv.of("mysql.login.failed")
    assert [f["username"] for f in fails] == [srv.user["user"], "nosuchuser", "admin"]
    assert all(f["password"] is None for f in fails)
    assert fails[0]["auth_response"] and fails[2]["auth_response"] == ""


async def test_connect_database_errors(srv):
    e = await srv.refused(database="nosuchdb")
    assert e.args == (1049, "Unknown database 'nosuchdb'")
    e = await srv.refused(database="mysql")  # exists, not granted
    assert e.args == (
        1044,
        f"Access denied for user '{srv.user['user']}'@'{SRC_IP}' to database 'mysql'",
    )
    conn = await srv.connect(database="crm")
    assert await q(conn, "SELECT DATABASE()") == ([("DATABASE()", 253)], [["crm"]])


# ------------------------------------------------------------------ query subset


async def test_reference_shaped_answers(srv):
    conn = await srv.connect()
    p = srv.profile
    for sql in ("SELECT 1", "SHOW TABLES"):
        r = ref(srv, sql)
        if "error" in r:
            assert await q_err(conn, sql) == (r["error"]["code"], r["error"]["message"])
        else:
            assert await q(conn, sql) == (
                list(zip(r["columns"], r["column_types"], strict=True)),
                r["rows"],
            )
    assert await q(conn, "SELECT @@version_comment LIMIT 1") == (
        [("@@version_comment", 253)],
        [[p.version_comment]],
    )
    assert await q(conn, "SELECT VERSION()") == ([("VERSION()", 253)], [[p.version]])
    cols, rows = await q(conn, "SELECT NOW()")
    assert cols == [("NOW()", 12)]
    assert re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", str(rows[0][0])) or rows[0][0]
    user = srv.user["user"]
    assert await q(conn, "SELECT USER()") == ([("USER()", 253)], [[f"{user}@{SRC_IP}"]])
    assert await q(conn, "SELECT CURRENT_USER()") == ([("CURRENT_USER()", 253)], [[f"{user}@%"]])
    assert await q(conn, "SELECT DATABASE()") == ([("DATABASE()", 253)], [[None]])
    assert await q(conn, "SHOW DATABASES") == (
        [("Database", 253)],
        [[d] for d in sorted(p.databases)],
    )
    cols, rows = await q(conn, "SHOW VARIABLES")
    assert len(rows) == len(p.variables)
    cols, rows = await q(conn, "SHOW GRANTS")
    assert [r[0] for r in rows] == srv.user["grants"]


async def test_metadata_of_profile_tables(srv):
    conn = await srv.connect()
    meta = srv.raw["databases"]["crm"]["customers"]
    _, rows = await q(conn, "SHOW TABLES FROM crm")
    assert rows == [[t] for t in sorted(srv.raw["databases"]["crm"])]
    _, rows = await q(conn, "DESCRIBE crm.customers")
    assert rows == [list(c) for c in meta["columns"]]
    _, rows = await q(conn, "SHOW CREATE TABLE crm.customers")
    assert rows == [["customers", meta["create"]]]
    assert await q(conn, "SELECT COUNT(*) FROM crm.customers") == (
        [("COUNT(*)", 8)],
        [[len(meta["rows"])]],
    )
    cols, rows = await q(
        conn, "SELECT id, email FROM crm.customers WHERE id > 2 ORDER BY id LIMIT 3"
    )
    assert [c[0] for c in cols] == ["id", "email"] and [r[0] for r in rows] == [3, 4, 5]
    assert rows[0][1] == meta["rows"][2][3]


async def test_writes_and_ddl_round_trip(srv):
    conn = await srv.connect()
    assert await q(conn, "USE crm") == (None, 0)
    assert await q(conn, "INSERT INTO customers (first_name, city) VALUES ('Ada', 'Leeds')") == (
        None,
        1,
    )
    _, rows = await q(conn, "SELECT first_name FROM customers WHERE city = 'Leeds'")
    assert rows == [["Ada"]]
    assert await q(conn, "UPDATE customers SET city = 'York' WHERE city = 'Leeds'") == (None, 1)
    assert await q(conn, "DELETE FROM customers WHERE city = 'York'") == (None, 1)

    assert await q(
        conn, "CREATE TABLE notes (id INT NOT NULL, body VARCHAR(64), PRIMARY KEY (id))"
    ) == (None, 0)
    await q(conn, "INSERT INTO notes VALUES (1, 'hello')")
    assert (await q(conn, "SELECT * FROM notes"))[1] == [[1, "hello"]]
    _, rows = await q(conn, "DESCRIBE notes")
    assert [r[:4] for r in rows] == [["id", "int", "NO", "PRI"], ["body", "varchar(64)", "YES", ""]]
    assert (await q(conn, "SHOW CREATE TABLE notes"))[1][0][1].startswith("CREATE TABLE `notes`")
    assert await q_err(conn, "INSERT INTO notes VALUES (1, 'again')") == (
        1062,
        "Duplicate entry for key 'PRIMARY'",
    )
    assert await q_err(conn, "INSERT INTO notes VALUES (2)") == (
        1136,
        "Column count doesn't match value count at row 1",
    )
    assert await q(conn, "DROP TABLE notes") == (None, 0)
    assert (await q_err(conn, "SELECT * FROM notes"))[0] == 1146

    ops = [c["op"] for c in srv.of("mysql.state.change")]
    assert ops == ["insert", "update", "delete", "create", "insert", "drop"]


async def test_error_codes_match_the_reference(srv):
    conn = await srv.connect()
    r = ref(srv, "SELEC 1")["error"]
    assert await q_err(conn, "SELEC 1") == (r["code"], r["message"])
    assert await q_err(conn, "SELECT * FROM crm.nosuch") == (
        1146,
        "Table 'crm.nosuch' doesn't exist",
    )
    assert await q_err(conn, "SELECT nocol FROM crm.customers") == (
        1054,
        "Unknown column 'nocol' in 'SELECT'",
    )
    for sql in ("SELECT 1 INTO OUTFILE '/tmp/x.txt'", "SELECT 1 INTO DUMPFILE '/tmp/x.so'"):
        r = ref(srv, "SELECT 1 INTO OUTFILE '/tmp/mirage_probe.txt'")["error"]
        assert await q_err(conn, sql) == (r["code"], r["message"])
    load = "SELECT LOAD_FILE('/etc/passwd')"
    assert await q(conn, load) == ([(load[7:], 251)], [[None]])
    key = next(k for k in srv.raw["reference_queries"] if k.startswith("CREATE FUNCTION"))
    template = srv.raw["reference_queries"][key]["error"]["message"]
    code, msg = await q_err(conn, "CREATE FUNCTION f RETURNS STRING SONAME 'evil.so'")
    assert code == 1126 and msg == template.replace("lib_mysqludf_sys.so", "evil.so")
    assert await q_err(conn, "USE nosuchdb") == (1049, "Unknown database 'nosuchdb'")
    assert await q_err(conn, "DROP DATABASE nosuch") == (
        1008,
        "Can't drop database 'nosuch'; database doesn't exist",
    )
    assert await q(conn, "PREPARE s FROM 'SELECT 1'") == (None, 0)
    assert await q_err(conn, "SELECT @@nosuchvar") == (1193, "Unknown system variable 'nosuchvar'")


async def test_multi_statement_returns_every_result(srv):
    conn = await srv.connect(client_flag=pymysql.constants.CLIENT.MULTI_STATEMENTS)

    def run():
        with conn.cursor() as cur:
            cur.execute("SELECT 1; SELECT 2")
            first = (cur.description[0][0], cur.fetchall())
            assert cur.nextset()
            second = (cur.description[0][0], cur.fetchall())
            return first, second, cur.nextset()

    first, second, more = await asyncio.to_thread(run)
    assert first == ("1", ((1,),)) and second == ("2", ((2,),)) and not more


async def test_ping_and_raw_commands(srv):
    conn = await srv.connect(database="crm")
    await asyncio.to_thread(conn.ping, False)

    def field_list(table: bytes) -> list[bytes]:
        conn._execute_command(COM_FIELD_LIST, table + b"\0")
        packets = []
        while True:
            pkt = conn._read_packet()
            if pkt.is_eof_packet():
                return packets
            packets.append(pkt.get_all_data())

    cols = await asyncio.to_thread(field_list, b"customers")
    names = [c[0] for c in srv.raw["databases"]["crm"]["customers"]["columns"]]
    assert len(cols) == len(names) and all(
        n.encode() in c for n, c in zip(names, cols, strict=False)
    )
    with pytest.raises(pymysql.MySQLError) as info:
        await asyncio.to_thread(field_list, b"nosuch")
    assert info.value.args[0] == 1146

    def prepare():
        conn._execute_command(COM_STMT_PREPARE, b"SELECT 1")
        conn._read_packet()

    with pytest.raises(pymysql.MySQLError) as info:
        await asyncio.to_thread(prepare)
    assert info.value.args[0] == 1047


# ------------------------------------------------------------------ state


async def test_state_is_per_source_and_db_per_connection(srv):
    a = await srv.connect("203.0.113.1")
    b = await srv.connect("203.0.113.2")
    a2 = await srv.connect("203.0.113.1")
    n = len(srv.raw["databases"]["crm"]["customers"]["rows"])
    await q(a, "INSERT INTO crm.customers (first_name) VALUES ('only-a')")
    assert (await q(b, "SELECT COUNT(*) FROM crm.customers"))[1] == [[n]]
    assert (await q(a2, "SELECT COUNT(*) FROM crm.customers"))[1] == [[n + 1]]
    # the default database is per connection, even from one source
    await q(a, "USE crm")
    assert (await q(a2, "SELECT DATABASE()"))[1] == [[None]]
    assert (await q(a, "SELECT DATABASE()"))[1] == [["crm"]]


def test_state_resets_24h_after_first_write(profile_dir):
    profile = Profile.load(profile_dir)
    reg = Registry(profile)
    st = reg.get("1.2.3.4")
    st.conn.execute('DELETE FROM "crm"."customers"')
    st.wrote()
    st.first_write = time.time() - RESET_AFTER_S - 5
    fresh = reg.get("1.2.3.4")
    (count,) = fresh.conn.execute('SELECT COUNT(*) FROM "crm"."customers"').fetchone()
    assert count == len(profile.rows["crm"]["customers"])


async def test_sqlite_is_fenced(srv, monkeypatch):
    conn = await srv.connect()
    # SQLite internals and file functions are out of reach
    code, _ = await q_err(
        conn, "INSERT INTO crm.customers (first_name) SELECT name FROM crm.sqlite_master"
    )
    assert code == 1146
    code, _ = await q_err(
        conn, "INSERT INTO crm.customers (first_name) VALUES (load_extension('/tmp/x.so'))"
    )
    assert code != 0
    # a runaway statement is interrupted instead of holding the event loop
    monkeypatch.setattr(state_mod, "STATEMENT_BUDGET_S", 0.05)
    started = time.monotonic()
    code, msg = await q_err(
        conn,
        "INSERT INTO crm.customers (first_name) WITH RECURSIVE c(x) AS "
        "(SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT x FROM c",
    )
    assert (code, msg) == (1317, "Query execution was interrupted")
    assert time.monotonic() - started < 2
    assert (await q(conn, "SELECT 1"))[1] == [[1]]  # the connection survives


# ------------------------------------------------------------------ gate


async def test_gate_actions(srv):
    conn = await srv.connect()
    gate = FakeGate()
    srv.decoy.gate = gate

    gate.applied = Applied(Action.FAKE_SUCCESS, output="ignored")
    assert await q(conn, "SELECT * FROM crm.customers") == (None, 0)

    gate.applied = Applied(Action.FAKE_ERROR, output="selftest failed", exit_code=2)
    assert await q_err(conn, "SELECT 1") == (2, "selftest failed")
    gate.applied = Applied(Action.FAKE_ERROR, output="boom")
    assert (await q_err(conn, "SELECT 1"))[0] == 1105

    gate.applied = Applied(Action.DELAY, delay_ms=250)
    started = time.monotonic()
    assert (await q(conn, "SELECT 1"))[1] == [[1]]
    assert time.monotonic() - started >= 0.25

    gate.applied = Applied(Action.TERMINATE)
    assert (await q_err(conn, "SELECT 1"))[0] in (2013, 2006)

    req = gate.reqs[0]
    assert (req.protocol, req.command, req.sql, req.user, req.known) == (
        Protocol.MYSQL,
        "COM_QUERY",
        "SELECT * FROM crm.customers",
        srv.user["user"],
        True,
    )


async def test_fallback_behaves_as_plain_emulation(srv):
    conn = await srv.connect()
    assert (await q(conn, "SELECT 1"))[1] == [[1]]
    decisions = srv.of("mysql.policy.decision")
    assert decisions and all(
        (d["action"], d["fallback"], d["fallback_reason"]) == ("allow", True, "disabled")
        for d in decisions
    )


# ------------------------------------------------------------------ limits and events


async def test_oversized_packet_is_refused(srv):
    conn = await srv.connect()
    big = "a" * (srv.profile.max_allowed_packet + 64)
    e = srv.profile.errors["max_allowed_packet"]
    assert await q_err(conn, "SELECT %s", (big,)) == (int(e["code"]), e["message"])


async def test_large_sql_and_replies_go_to_the_artifact_store(srv, tmp_path):
    conn = await srv.connect()
    text = "x" * 5000
    assert (await q(conn, f"SELECT '{text}'"))[1] == [[text]]
    arts = {a["kind"]: a for a in srv.of("mysql.artifact")}
    assert set(arts) == {"mysql.sql", "mysql.reply"}
    sql = (tmp_path / "art" / arts["mysql.sql"]["sha256"]).read_bytes()
    assert sql == f"SELECT '{text}'".encode()


async def test_events_follow_every_command(srv):
    conn = await srv.connect()
    await q(conn, "USE crm")
    await q(conn, "INSERT INTO customers (first_name) VALUES ('Bo')")
    await q_err(conn, "SELEC 1")
    await asyncio.to_thread(conn.close)
    records = await srv.closed(1)

    inputs = srv.of("mysql.input")
    assert [i["seq"] for i in inputs] == list(range(1, len(inputs) + 1))
    by_sql = {i["sql"]["text"]: i for i in inputs if i["sql"]}
    assert by_sql["USE crm"]["db"] is None  # where it ran
    assert by_sql["INSERT INTO customers (first_name) VALUES ('Bo')"]["db"] == "crm"
    assert by_sql["SELEC 1"]["outcome"] == "failure"
    assert inputs[-1]["command"] == "COM_QUIT"
    (change,) = srv.of("mysql.state.change")
    assert (change["op"], change["db"], change["table"], change["rows"]) == (
        "insert",
        "crm",
        "customers",
        1,
    )
    ids = [e["eventid"] for e in records]
    assert ids[0] == "mysql.session.connect" and ids[-1] == "mysql.session.closed"
