"""One MySQL connection: handshake, native auth against the profile's users, gated commands.

The handshake bytes, the error texts and the query answers come from the deployment profile
(spec 1.5). Auth uses mysql_native_password against the profile's plaintext passwords, so the
password itself never crosses the wire but can still be logged on success - that is what lets
the pipeline see a honeytoken credential being used. Every command packet is one gated input.
The decoy never offers TLS, never sends a LOCAL INFILE request and never runs a statement
outside the in-memory SQLite copy of the profile's schema.
"""

from __future__ import annotations

import asyncio
import re

from mirage_db_decoy.mysql import proto
from mirage_db_decoy.mysql.proto import (
    COM_FIELD_LIST,
    COM_INIT_DB,
    COM_PING,
    COM_QUERY,
    COM_QUIT,
    COMMAND_NAMES,
    HandshakeResponse,
    PacketTooBig,
    Wire,
    auth_switch_payload,
    eof_packet,
    err_packet,
    handshake_payload,
    make_scramble,
    native_password,
    ok_packet,
    parse_handshake_response,
    result_packets,
)
from mirage_db_decoy.mysql.sql import Engine
from mirage_db_decoy.mysql.state import Profile, Registry
from mirage_decoy_common.session import Session
from mirage_schema.policy import SQL_CAP, Action, truncate

READ_SIZE = 65536
DENIED_USER_RE = re.compile(r"'[^']*'@'[^']*'")
NO_REPLY: list[bytes] = []


class Handler:
    def __init__(self, profile: Profile, registry: Registry, engine: Engine) -> None:
        self.p = profile
        self.registry = registry
        self.engine = engine

    async def __call__(
        self, session: Session, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        conn = Connection(self, session, reader, writer)
        try:
            await conn.run()
        finally:
            pass


class Connection:
    def __init__(
        self,
        h: Handler,
        session: Session,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.h, self.s = h, session
        self.p = h.p
        self.registry = h.registry
        self.engine = h.engine
        self.wire = Wire(reader, writer, self.p.max_allowed_packet)
        self.ip = session.peer.src_ip or ""
        self.user: str | None = None
        self.caps = 0
        self.status = int(self.p.handshake["status"])
        self.thread_id = self.registry.next_id()
        # The default database belongs to the connection, not the source: two connections
        # from one address each have their own. The engine reads st.current_db, so it is
        # loaded before and saved after every command (all of this runs on one event loop).
        self.db: str | None = None

    # ------------------------------------------------------------------ handshake and auth

    async def run(self) -> None:
        p = self.p
        self.scramble = make_scramble()
        hs = p.handshake
        self.wire.seq = -1  # the handshake is the exchange's first packet: sequence 0
        self.wire.write(
            handshake_payload(
                int(hs["capabilities"]),
                hs["server_version"],
                self.thread_id,
                self.scramble,
                int(hs["charset"]),
                int(hs["status"]),
                int(hs["auth_data_len"]),
                bytes.fromhex(hs["reserved_hex"]),
                hs["auth_plugin"],
            )
        )
        await self.wire.drain()
        try:
            data = await self.wire.read()
            resp = parse_handshake_response(data)
            if resp.ssl_request:
                return  # TLS was never offered; a client insisting on it gets a closed socket
            if resp.plugin and resp.plugin != hs["auth_plugin"]:
                self.wire.write(auth_switch_payload(hs["auth_plugin"], self.scramble))
                await self.wire.drain()
                resp.auth_response = await self.wire.read()
            if not await self.authenticate(resp):
                return
            if resp.database and not await self.select_database(resp.database):
                return
            self.wire.write(ok_packet(self.caps, self.status))
            await self.wire.drain()
            if resp.attrs:
                self.s.emit("client.attrs", attrs=resp.attrs)
            await self.commands()
        except (PacketTooBig, asyncio.IncompleteReadError, ConnectionError):
            return

    async def authenticate(self, resp: HandshakeResponse) -> bool:
        user = self.p.user(resp.username)
        want = str(user["password"]) if user else ""
        ok = user is not None and resp.auth_response == native_password(want, self.scramble)
        if ok:
            self.user, self.caps = resp.username, resp.capabilities
            self.s.emit("login.success", username=resp.username, password=want)
            return True
        key = (
            "denied_nopassword"
            if not resp.auth_response
            else ("denied_password" if user else "denied_unknown_user")
        )
        e = self.p.errors[key]
        message = DENIED_USER_RE.sub(f"'{resp.username}'@'{self.ip}'", e["message"], count=1)
        self.s.emit(
            "login.failed",
            username=resp.username,
            password=None,
            auth_response=resp.auth_response.hex(),
        )
        self.wire.write(err_packet(self.caps, int(e["code"]), message, _sqlstate(int(e["code"]))))
        await self.wire.drain()
        return False

    async def select_database(self, db: str) -> bool:
        if db not in self.p.databases:
            e = self.p.errors["connect_unknown_db"]
            message = re.sub(r"'[^']*'", f"'{db}'", e["message"], count=1)
            self.wire.write(err_packet(self.caps, int(e["code"]), message, "42000"))
        else:
            user = self.p.user(self.user or "") or {}
            if db not in user.get("databases", []):
                # Not in the measured set (the reference probe account has global grants);
                # MariaDB's documented 1044 text (spec section 8).
                self.wire.write(
                    err_packet(
                        self.caps,
                        1044,
                        f"Access denied for user '{self.user}'@'{self.ip}' to database '{db}'",
                        "42000",
                    )
                )
            else:
                self.db = db
                return True
        await self.wire.drain()
        return False

    # ------------------------------------------------------------------ command loop

    async def commands(self) -> None:
        while True:
            try:
                data = await self.wire.read()
            except PacketTooBig as too_big:
                e = self.p.errors["max_allowed_packet"]
                self.wire.write(err_packet(self.caps, int(e["code"]), e["message"], "08S01"))
                await self.wire.drain()
                await self.wire.discard(too_big.args[0])
                return
            except (asyncio.IncompleteReadError, ConnectionError):
                return
            if not data:
                return
            cmd = data[0]
            name = COMMAND_NAMES.get(cmd, f"COM_0x{cmd:02X}")
            sql_text = data[1:].decode(errors="replace") if cmd == COM_QUERY else None
            st = self.registry.state_for(self.ip)
            st.current_db = ran_in = self.db
            seq, rid, applied = await self.s.gate(
                known=cmd in (COM_QUIT, COM_INIT_DB, COM_QUERY, COM_FIELD_LIST, COM_PING),
                command=name,
                sql=truncate(sql_text, SQL_CAP) if sql_text is not None else None,
                db=st.current_db,
                user=self.user,
            )
            close = False
            if applied.action is Action.DELAY:
                await asyncio.sleep(applied.delay_ms / 1000)
            if applied.action is Action.TERMINATE:
                reply, close = NO_REPLY, True
            elif applied.action is Action.FAKE_SUCCESS:
                reply = [ok_packet(self.caps, self.status)]
            elif applied.action is Action.FAKE_ERROR:
                code = applied.exit_code if applied.exit_code is not None else 1105
                reply = [err_packet(self.caps, code, applied.output)]
            else:
                st.current_db = self.db  # another connection may have run while we were gated
                reply, close = self.emulate(cmd, data, st)
                self.db = st.current_db
            self.wire.write_all(reply)
            self.s.emit(
                "input",
                seq=seq,
                request_id=rid,
                command=name,
                sql=self.s.content(data[1:], "mysql.sql") if cmd == COM_QUERY else None,
                db=ran_in,  # where the command ran; a USE shows the database it left
                outcome="failure" if self.was_error(reply) else "success",
                reply=self.s.content(b"".join(reply), "mysql.reply"),
            )
            await self.wire.drain()
            if close:
                return

    @staticmethod
    def was_error(reply: list[bytes]) -> bool:
        # a multi-statement query stops at its first error, so that is always the last packet
        return bool(reply) and reply[-1][:1] == b"\xff"

    # ------------------------------------------------------------------ emulation

    def emulate(self, cmd: int, data: bytes, st) -> tuple[list[bytes], bool]:
        """The reply to one command packet, as a list of packet payloads."""
        if cmd == COM_QUIT:
            return NO_REPLY, True
        if cmd == COM_PING:
            return [ok_packet(self.caps, self.status)], False
        if cmd == COM_INIT_DB:
            return self.init_db(data[1:].split(b"\x00", 1)[0].decode(errors="replace"), st)
        if cmd == COM_QUERY:
            return self.query(data[1:].decode(errors="replace"), st)
        if cmd == COM_FIELD_LIST:
            return self.field_list(data[1:], st)
        return [err_packet(self.caps, 1047, "Unknown command", "08S01")], False

    def init_db(self, db: str, st) -> tuple[list[bytes], bool]:
        if db not in self.p.databases:
            e = self.p.errors["connect_unknown_db"]
            message = re.sub(r"'[^']*'", f"'{db}'", e["message"], count=1)
            return [err_packet(self.caps, int(e["code"]), message, "42000")], False
        user = self.p.user(self.user or "") or {}
        if db not in user.get("databases", []):
            message = f"Access denied for user '{self.user}'@'{self.ip}' to database '{db}'"
            return [err_packet(self.caps, 1044, message, "42000")], False
        st.current_db = db
        return [ok_packet(self.caps, self.status)], False

    def query(self, sql: str, st) -> tuple[list[bytes], bool]:
        out: list[bytes] = []
        for result in self.engine.execute(st, sql, self.user or "", self.ip):
            for change in result.changes:
                fields = dict(change)
                if "sql" in fields:
                    fields["sql"] = self.s.content(fields["sql"].encode(), "mysql.sql")
                self.s.emit("state.change", **fields)
            status = self.status | (proto.SERVER_MORE_RESULTS_EXISTS if result.more else 0)
            if not result.ok:
                code, message = result.error
                out.append(err_packet(self.caps, code, message, _sqlstate(code)))
            elif result.columns:
                out += result_packets(self.caps, status, result.columns, result.rows, result.more)
            else:
                out.append(ok_packet(self.caps, status, result.affected))
        return out, False

    def field_list(self, payload: bytes, st) -> tuple[list[bytes], bool]:
        name = payload.split(b"\x00", 1)[0].decode(errors="replace")
        wildcard = payload.split(b"\x00", 1)[1] if b"\x00" in payload else b""
        db = st.current_db
        if db is None:
            return [err_packet(self.caps, 1046, "No database selected", "3D000")], False
        meta = st.metadata(db, name, self.p)
        if meta is None:
            if db in st.dropped or db not in self.p.databases:
                return [err_packet(self.caps, 1049, f"Unknown database '{db}'", "42000")], False
            message = f"Table '{db}.{name}' doesn't exist"
            return [err_packet(self.caps, 1146, message, "42S02")], False
        from mirage_db_decoy.mysql.sql import _like_regex

        pattern = _like_regex(wildcard.decode(errors="replace")) if wildcard else None
        from mirage_db_decoy.mysql.state import column_type_code

        cols = [
            proto.Column(
                c[0],
                column_type_code(c[1]),
                org_name=c[0],
                table=meta.name,
                org_table=meta.name,
                length=255,
                flags=_flags(c),
            )
            for c in meta.columns
            if pattern is None or pattern.match(c[0])
        ]
        return [c.packet(self.caps) for c in cols] + [eof_packet(self.caps, self.status)], False


def _flags(c: list) -> int:
    NOT_NULL, PRI_KEY, AUTO_INCREMENT = 1, 2, 512
    flags = 0
    if c[2] == "NO":
        flags |= NOT_NULL
    if c[3] == "PRI":
        flags |= PRI_KEY
    if c[5] == "auto_increment":
        flags |= AUTO_INCREMENT
    return flags


def _sqlstate(code: int) -> str:
    from mirage_db_decoy.mysql.sql import SQLSTATE

    return SQLSTATE.get(code, "HY000")
