"""One Redis connection: parse RESP2 (plus inline), gate every command, answer from the profile.

The command set, error texts and INFO/CONFIG data reproduce the measured Debian 12
``redis-server`` 7.0 (spec 1.5): every reply is either computed from this deployment's profile
or taken verbatim from its ``reference_replies``. Nothing is ever executed: Lua scripts are only
read statically (``lua.py``), replication targets are only recorded, modules are refused with the
measured error, and the state each source sees is its own (decision P10).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from mirage_db_decoy.redis import lua
from mirage_db_decoy.redis.resp import (
    Error,
    Map,
    Parser,
    ProtocolError,
    Simple,
    Verbatim,
    encode,
    err,
    string2ll,
)
from mirage_db_decoy.redis.state import (
    Entry,
    Profile,
    Registry,
    SourceState,
    glob_match,
    now_ms,
)
from mirage_decoy_common.session import INLINE_CAP, Session
from mirage_schema.policy import ARG_CAP, Action, truncate

READ_SIZE = 65536
CLIENT_OVERHEAD = 16384  # counted per connected client in used_memory

WRONGTYPE = "WRONGTYPE Operation against a key holding the wrong kind of value"
WRONGPASS = "WRONGPASS invalid username-password pair or user is disabled."
NOPROTO = "NOPROTO unsupported protocol version"
NOAUTH = "NOAUTH Authentication required."
OOM = "OOM command not allowed when used memory > 'maxmemory'."

# Arity from Redis 7.0's command table: positive is exact, negative is a minimum (in argc).
ARITY: dict[str, int] = {
    "PING": -1,
    "ECHO": 2,
    "AUTH": -2,
    "HELLO": -1,
    "SELECT": 2,
    "QUIT": 1,
    "INFO": -1,
    "CONFIG": -2,
    "DBSIZE": 1,
    "KEYS": 2,
    "SCAN": -2,
    "TYPE": 2,
    "TTL": 2,
    "EXISTS": -2,
    "GET": 2,
    "SET": -3,
    "DEL": -2,
    "FLUSHDB": -1,
    "FLUSHALL": -1,
    "SAVE": 1,
    "BGSAVE": -1,
    "COMMAND": -1,
    "CLIENT": -2,
    "EVAL": -3,
    "EVALSHA": -3,
    "MODULE": -2,
    "SLAVEOF": 3,
    "REPLICAOF": 3,
}

# INFO fields computed live; everything else comes from the profile unchanged.
DYNAMIC = (
    "server_time_usec",
    "uptime_in_seconds",
    "uptime_in_days",
    "lru_clock",
    "connected_clients",
    "used_memory",
    "used_memory_human",
)


def human_bytes(n: int) -> str:
    """Redis's bytesToHuman: two decimals above 1 KiB, plain bytes below."""
    if abs(n) < 1024:
        return f"{n}B"
    for e, unit in ((1, "K"), (2, "M"), (3, "G"), (4, "T")):
        x = n / 1024**e
        if abs(x) < 1024 or e == 4:
            return f"{x:.2f}{unit}"
    return f"{n}B"


class Handler:
    """The per-connection state machine; one instance per server, one Client per connection."""

    def __init__(self, profile: Profile, registry: Registry) -> None:
        self.p = profile
        self.registry = registry
        # The CONFIG GET * order is measured (redis.replies["config_get_all"]); anything the
        # deployment adds at runtime is appended in the source's own order.
        self.config_order = _resp_strings(profile.replies.get("config_get_all", ""))[::2]
        self.command_count = _resp_int(profile.replies.get("command_count", ""), 240)
        repl = _resp_body(profile.replies.get("info_replication_after_slaveof", ""))
        self.slaveof_fields = [
            ln.split(":", 1) for ln in repl.split("\r\n") if ":" in ln and not ln.startswith("#")
        ]

    async def __call__(
        self, session: Session, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        from mirage_db_decoy.redis.handler import Client

        client = Client(self, session, reader, writer)
        try:
            await client.run()
        finally:
            self.registry.detach(client.ip, client)


class Client:
    def __init__(
        self,
        h: Handler,
        session: Session,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.h, self.s, self.r, self.w = h, session, reader, writer
        self.p = h.p
        self.registry = h.registry
        self.ip = session.peer.src_ip or ""
        self.id = self.registry.next_id()
        self.fd = self.registry.next_id()
        self.connected_at = time.time()
        self.last_cmd_at = self.connected_at
        self.last_cmd = "NULL"
        self.gopher = False
        self.db = 0
        self.proto = 2
        self.name = b""
        # requirepass is per-source state (CONFIG SET changes it for that source only).
        self.authed = self.registry.get(self.ip).config.get("requirepass", "") == ""
        sock = writer.get_extra_info("sockname") or ("127.0.0.1", 6379)
        self.laddr = (
            f"[{session.peer.dst_ip}]:{session.peer.dst_port}"
            if session.peer.dst_ip and ":" in str(session.peer.dst_ip)
            else f"{session.peer.dst_ip or sock[0]}:{session.peer.dst_port or sock[1]}"
        )

    # ------------------------------------------------------------------ loop

    @staticmethod
    def _cmd_name(upper: str, args: list[bytes]) -> str:
        """The executed command as CLIENT LIST reports it: subcommands after a pipe."""
        if upper in ("CLIENT", "CONFIG", "COMMAND", "MODULE") and len(args) > 1:
            return f"{upper.lower()}|{args[1].decode(errors='replace').lower()}"
        return upper.lower()

    def client_list_line(self) -> str:
        """One CLIENT LIST record, in the measured field order; addresses are this client's."""
        now = time.time()
        addr = f"{self.ip}:{self.s.peer.src_port or 0}"
        name = self.name.decode(errors="replace")
        return (
            f"id={self.id} addr={addr} laddr={self.laddr} fd={self.fd} name={name} "
            f"age={int(now - self.connected_at)} idle={int(now - self.last_cmd_at)} flags=N "
            f"db={self.db} sub=0 psub=0 ssub=0 multi=-1 qbuf=26 qbuf-free=20448 argv-mem=10 "
            f"multi-mem=0 rbs=16384 rbp=16384 obl=0 oll=0 omem=0 tot-mem=37658 events=r "
            f"cmd={self.last_cmd} user=default redir=-1 resp={self.proto}\n"
        )

    async def run(self) -> None:
        self.registry.attach(self.ip, self)
        parser = Parser(self.p.max_bulk)
        while True:
            data = await self.r.read(READ_SIZE)
            if not data:
                return
            parser.feed(data)
            # Replies are buffered per read batch and flushed together, as Redis flushes at
            # the end of an event loop iteration - the gopher close below relies on that.
            out = bytearray()
            while True:
                try:
                    args = parser.next()
                except ProtocolError as e:
                    out += encode(err(f"Protocol error: {e}"))
                    await self.send(bytes(out))
                    return
                if args is None:
                    break
                if not args:
                    continue  # an empty inline line is not a command
                wire, close = await self.command(args)
                if wire:
                    out += wire
                if close:
                    await self.send(bytes(out))
                    return
                if self.gopher:
                    return  # measured: the gopher path closes, discarding the pending replies
            await self.send(bytes(out))

    async def send(self, wire: bytes) -> None:
        if wire:
            self.w.write(wire)
            await self.w.drain()

    async def command(self, args: list[bytes]) -> tuple[bytes, bool]:
        """Gate one command, apply the decision, answer, log. Returns (reply, close); the
        reply is buffered by the caller and flushed with its batch."""
        self.registry.state_for(self.ip)  # may reset a source that wrote 24h ago (P10)
        if args[0].decode(errors="replace").lower() == "host:":
            # Redis 7.0's gopher path (measured): "Host: <gopher host>" swallows every queued
            # reply and closes the connection without a word.
            seq, rid, applied = await self.s.gate(
                known=False,
                argv=[truncate(a, ARG_CAP) or "" for a in args],
                db=self.db,
            )
            self.s.emit(
                "input",
                seq=seq,
                request_id=rid,
                argv=[truncate(a, INLINE_CAP) or "" for a in args],
                db=self.db,
                outcome="success",
                reply=self.s.content(b"", "redis.reply"),
            )
            self.gopher = True
            return b"", False
        upper = args[0].decode(errors="replace").upper()
        self.last_cmd = self._cmd_name(upper, args)
        db = self.db  # SELECT changes self.db; the event records where the command ran
        seq, rid, applied = await self.s.gate(
            known=upper in ARITY,
            argv=[truncate(a, ARG_CAP) or "" for a in args],
            db=self.db,
        )
        close = False
        if applied.action is Action.DELAY:
            await asyncio.sleep(applied.delay_ms / 1000)
        reply: Any = None
        if applied.action is Action.TERMINATE:
            close = True
        elif applied.action is Action.FAKE_SUCCESS:
            reply = Simple(b"OK") if not applied.output else applied.output.encode()
        elif applied.action is Action.FAKE_ERROR:
            out = applied.output.encode().strip()
            reply = Error(b"ERR " + out) if out else Error(b"ERR")
        else:
            reply, close = self.emulate(args)
        wire = encode(reply, self.proto)
        self.s.emit(
            "input",
            seq=seq,
            request_id=rid,
            argv=[truncate(a, INLINE_CAP) or "" for a in args],
            db=db,
            outcome="failure" if isinstance(reply, Error) else "success",
            reply=self.s.content(wire, "redis.reply"),
        )
        self.last_cmd_at = time.time()
        return wire, close

    # ------------------------------------------------------------------ dispatch

    def emulate(self, args: list[bytes]) -> tuple[Any, bool]:
        upper = args[0].decode(errors="replace").upper()
        st = self.state()
        if upper not in ARITY:
            return err(unknown_text(args)), False
        if not self.authed and upper not in ("AUTH", "QUIT", "HELLO"):
            return Error(NOAUTH.encode()), False
        n, arity = len(args), ARITY[upper]
        if (arity >= 0 and n != arity) or (arity < 0 and n < -arity):
            return err(f"wrong number of arguments for '{upper.lower()}' command"), False
        return getattr(self, "cmd_" + upper.lower())(args[1:], st)

    def state(self) -> SourceState:
        return self.registry.get(self.ip)

    def change(self, **fields: Any) -> None:
        self.s.emit("state.change", db=self.db, **fields)

    def canned(self, name: str) -> Simple | Error | int:
        """A measured reply from the profile as a typed object (byte-identical once encoded)."""
        text = self.p.replies[name]
        body = text[1:].rstrip("\r\n")
        if text.startswith(":"):
            return int(body)
        if text.startswith("+"):
            return Simple(body.encode())
        return Error(body.encode())

    # ------------------------------------------------------------------ connection commands

    def cmd_ping(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        return (rest[0] if rest else Simple(b"PONG")), False

    def cmd_echo(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        return rest[0], False

    def cmd_quit(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        return Simple(b"OK"), True

    def cmd_select(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        idx = string2ll(rest[0])
        if idx is None or not 0 <= idx < int(st.config.get("databases", "16")):
            return self.canned("select_out_of_range"), False
        self.db = idx
        return Simple(b"OK"), False

    def cmd_hello(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        i, ver = 0, 2
        while i < len(rest):
            opt = rest[i].upper()
            if i == 0:
                parsed = string2ll(rest[0])
                if parsed is None:
                    return self.canned("inline_unknown"), False
                if parsed not in (2, 3):
                    return Error(NOPROTO.encode()), False
                ver = parsed
                i += 1
            elif opt == b"AUTH" and i + 2 < len(rest) + 1:
                if st.config.get("requirepass", "") and not self._auth(rest[i + 2]):
                    return Error(WRONGPASS.encode()), False
                i += 3
            elif opt == b"SETNAME" and i + 1 < len(rest):
                self.name, i = rest[i + 1], i + 2
            else:
                return err("syntax error"), False
        self.proto = ver
        pairs: list[Any] = [
            (b"server", b"redis"),
            (b"version", self.p.version.encode()),
            (b"proto", self.proto),
            (b"id", self.id),
            (b"mode", b"standalone"),
            (b"role", b"slave" if st.master else b"master"),
            (b"modules", []),
        ]
        return Map(pairs), False

    def _auth(self, password: bytes) -> bool:
        want = self.state().config.get("requirepass", "")
        ok = bool(want) and password.decode(errors="replace") == want
        self.s.emit(
            "login.success" if ok else "login.failed",
            username="default",
            password=truncate(password.decode(errors="replace"), INLINE_CAP) if ok else None,
        )
        if ok:
            self.authed = True
        return ok

    def cmd_auth(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        if not st.config.get("requirepass", ""):
            return self.canned("auth_no_password"), False
        if not self._auth(rest[-1]):
            return Error(WRONGPASS.encode()), False
        return Simple(b"OK"), False

    # ------------------------------------------------------------------ server information

    def used_memory(self, st: SourceState) -> int:
        startup = int(self.p.info_field("Memory", "used_memory_startup", "908944") or 0)
        return startup + st.nbytes() + CLIENT_OVERHEAD * self.registry.client_count()

    def info_fields(self, section: str, st: SourceState) -> list[tuple[str, str]] | None:
        # section is lowercased by the caller (INFO section names are case-insensitive).
        if section == "replication" and st.master:
            fields = []
            for k, v in self.h.slaveof_fields:
                if k == "master_host":
                    v = st.master[0]
                elif k == "master_port":
                    v = str(st.master[1])
                elif k == "master_replid":
                    v = st.replid
                fields.append((k, v))
            return fields
        for sec in self.p.info:
            if sec["section"].lower() == section:
                if section == "keyspace":
                    return [
                        (
                            f"db{i}",
                            f"keys={len(d)},expires={sum(1 for e in d.values() if e.expire_ms)},avg_ttl=0",
                        )
                        for i, d in sorted(st.dbs.items())
                        if d
                    ]
                return [
                    (k, self._dynamic(k, v, st)) if k in DYNAMIC else (k, v)
                    for k, v in sec["fields"]
                ]
        return None

    def _dynamic(self, key: str, value: str, st: SourceState) -> str:
        if key == "server_time_usec":
            return str(int(time.time() * 1_000_000))  # one clock for every time field
        if key == "lru_clock":
            return str(int(time.time()) & 0xFFFFFF)
        if key == "connected_clients":
            return str(self.registry.client_count())
        if key in ("used_memory", "used_memory_human"):
            n = self.used_memory(st)
            return human_bytes(n) if key.endswith("_human") else str(n)
        up = max(0, int(time.time()) - self.p.start_epoch)
        return str(up // 86400) if key == "uptime_in_days" else str(up)

    def cmd_info(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        want = rest[0].decode(errors="replace").lower() if rest else None
        out = []
        for sec in self.p.info:
            name = sec["section"]
            if want and name.lower() != want:
                continue
            fields = self.info_fields(name.lower(), st)
            if fields is None:
                continue
            out.append(f"# {name}\r\n" + "".join(f"{k}:{v}\r\n" for k, v in fields))
        # Redis puts a blank line between sections, not after the last one.
        return Verbatim("\r\n".join(out).encode()), False

    def cmd_command(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        sub = rest[0].decode(errors="replace").upper() if rest else ""
        if sub == "COUNT":
            return self.canned("command_count"), False
        return self._bad_subcommand("COMMAND", rest[0] if rest else b""), False

    def _bad_subcommand(self, command: str, sub: bytes) -> Error:
        """The measured ``unknown subcommand`` text, with the client's subcommand in it."""
        template = self.p.replies["config_bad_subcommand"]
        text = template.replace("'FOO'", f"'{sub.decode(errors='replace')}'")
        return err(text[1:].rstrip("\r\n").removeprefix("ERR "))

    # ------------------------------------------------------------------ config

    def cmd_config(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        sub = rest[0].decode(errors="replace").upper()
        if sub == "GET":
            patterns = rest[1:]
            names = [n for n in self.h.config_order if n in st.config]
            names += sorted(n for n in st.config if n not in self.h.config_order)
            out = []
            for name in names:
                if any(glob_match(p, name.encode(), nocase=True) for p in patterns):
                    out += [name, st.config[name]]
            return out, False
        if sub != "SET":
            return self._bad_subcommand("CONFIG", rest[0]), False
        pairs = rest[1:]
        changed: dict[str, str] = {}
        for i in range(0, len(pairs) - 1, 2):
            param = pairs[i].decode(errors="replace").lower()
            value = pairs[i + 1].decode(errors="replace")
            if param in ("dir", "dbfilename"):
                return self.canned(f"config_set_{param}"), False
            if param not in st.config:
                return self.canned_bad_config_set(pairs[i]), False
            st.config[param] = value
            changed[param] = value
        if changed:
            st.wrote()
            self.change(op="config", params=changed)
        return Simple(b"OK"), False

    def canned_bad_config_set(self, param: bytes) -> Error:
        template = self.p.replies["config_set_bad"]
        text = template.replace("'nosuch'", f"'{param.decode(errors='replace')}'")
        return err(text[1:].rstrip("\r\n").removeprefix("ERR "))

    # ------------------------------------------------------------------ keyspace

    def cmd_dbsize(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        return len(st.db(self.db)), False

    def cmd_keys(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        return [k for k in st.db(self.db) if glob_match(rest[0], k)], False

    def cmd_scan(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        if string2ll(rest[0]) is None:
            return err("invalid cursor"), False
        pattern, i = None, 1
        while i < len(rest):
            opt = rest[i].upper()
            if opt == b"MATCH" and i + 1 < len(rest):
                pattern, i = rest[i + 1], i + 2
            elif opt in (b"COUNT", b"TYPE") and i + 1 < len(rest):
                i += 2
            else:
                return err("syntax error"), False
        keys = st.db(self.db)
        return [
            b"0",
            [k for k in keys if pattern is None or glob_match(pattern, k)],
        ], False

    def cmd_type(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        e = st.get(self.db, rest[0])
        return Simple((e.kind if e else "none").encode()), False

    def cmd_ttl(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        e = st.get(self.db, rest[0])
        if e is None:
            return -2, False
        if e.expire_ms is None:
            return -1, False
        return max(1, (e.expire_ms - now_ms() + 999) // 1000), False

    def cmd_exists(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        return sum(1 for k in rest if st.get(self.db, k) is not None), False

    def cmd_get(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        e = st.get(self.db, rest[0])
        if e is None:
            return None, False
        if e.kind != "string":
            return Error(WRONGTYPE.encode()), False
        return e.data, False

    def cmd_set(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        key, value, opts = rest[0], rest[1], rest[2:]
        nx = xx = keepttl = want_old = False
        expire_ms: int | None = None
        i = 0
        while i < len(opts):
            opt = opts[i].upper()
            if opt == b"NX":
                nx = True
            elif opt == b"XX":
                xx = True
            elif opt == b"KEEPTTL":
                keepttl = True
            elif opt == b"GET":
                want_old = True
            elif opt in (b"EX", b"PX", b"EXAT", b"PXAT") and i + 1 < len(opts):
                n = string2ll(opts[i + 1])
                if n is None:
                    return err("value is not an integer or out of range"), False
                if opt == b"EX":
                    expire_ms = now_ms() + n * 1000
                elif opt == b"PX":
                    expire_ms = now_ms() + n
                elif opt == b"EXAT":
                    expire_ms = n * 1000
                else:
                    expire_ms = n
                i += 1
            else:
                return err("syntax error"), False
            i += 1
        old = st.get(self.db, key)
        if (nx and old is not None) or (xx and old is None):
            return (old.data if want_old and old and old.kind == "string" else None), False
        if not self.registry.ensure_capacity(st, len(key) + len(value) + 64):
            return err(OOM), False
        st.db(self.db)[key] = Entry(
            "string",
            value,
            old.expire_ms if keepttl and old else expire_ms,
        )
        st.wrote()
        self.change(
            op="set", key=key.decode(errors="replace"), value=self.s.content(value, "redis.value")
        )
        return (old.data if want_old and old and old.kind == "string" else Simple(b"OK")), False

    def cmd_del(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        keys, n = list(dict.fromkeys(rest)), 0
        for k in keys:
            if st.get(self.db, k) is not None:
                del st.db(self.db)[k]
                n += 1
        if n:
            st.wrote(n)
            self.change(op="del", keys=[k.decode(errors="replace") for k in keys])
        return n, False

    def cmd_flushdb(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        st.dbs[self.db] = {}
        st.wrote()
        self.change(op="flush", scope="db")
        return Simple(b"OK"), False

    def cmd_flushall(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        st.dbs.clear()
        st.wrote()
        self.change(op="flush", scope="all")
        return Simple(b"OK"), False

    def cmd_save(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        st.last_save, st.dirty, st.saves = int(time.time()), 0, st.saves + 1
        return Simple(b"OK"), False

    def cmd_bgsave(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        st.last_save, st.dirty, st.saves = int(time.time()), 0, st.saves + 1
        return self.canned("bgsave"), False

    # ------------------------------------------------------------------ client and scripts

    def cmd_client(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        sub = rest[0].decode(errors="replace").upper()
        if sub == "SETNAME":
            self.name = rest[1]
            self.s.emit("client.attrs", attrs={"name": self.name.decode(errors="replace")})
            return Simple(b"OK"), False
        if sub == "GETNAME":
            return (self.name or None), False
        if sub == "ID":
            return self.id, False
        if sub == "LIST":
            return Verbatim(self.registry.client_list().encode()), False
        return self._bad_subcommand("CLIENT", rest[0]), False

    def cmd_eval(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        script, num = rest[0], string2ll(rest[1])
        if num is None or num < 0:
            return err("value is not an integer or out of range"), False
        keys, args = rest[2 : 2 + num], rest[2 + num :]
        st.remember_script(lua.sha1_hex(script), script)
        return lua.evaluate(script, keys, args), False

    def cmd_evalsha(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        script = st.scripts.get(rest[0].decode(errors="replace").lower())
        if script is None:
            return Error(b"NOSCRIPT No matching script. Please use EVAL."), False
        num = string2ll(rest[1])
        if num is None or num < 0:
            return err("value is not an integer or out of range"), False
        return lua.evaluate(script, rest[2 : 2 + num], rest[2 + num :]), False

    def cmd_module(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        if rest and rest[0].upper() == b"LIST":
            return [], False
        return self.canned("module_load"), False

    # ------------------------------------------------------------------ replication

    def _slaveof(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        host = rest[0].decode(errors="replace")
        # Redis checks for NO ONE before it parses a port.
        no_one = host.upper() == "NO" and rest[1].upper() == b"ONE"
        port = None if no_one else string2ll(rest[1])
        if not no_one and port is None:
            return err("value is not an integer or out of range"), False
        st.master = None if no_one else (host, port)
        st.wrote()
        self.change(
            op="slaveof",
            host=None if st.master is None else host,
            port=None if st.master is None else port,
        )
        return Simple(b"OK"), False

    def cmd_slaveof(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        return self._slaveof(rest, st)

    def cmd_replicaof(self, rest: list[bytes], st: SourceState) -> tuple[Any, bool]:
        return self._slaveof(rest, st)


def unknown_text(args: list[bytes]) -> str:
    """Redis 7.0's unknown-command error, args quoted and space-terminated (measured format)."""
    cmd = args[0].decode(errors="replace")
    rest = "".join(f"'{a.decode(errors='replace')}' " for a in args[1:])
    return f"unknown command '{cmd}', with args beginning with: {rest}"


def _resp_body(text: str) -> str:
    return text.split("\r\n", 1)[1] if text.startswith("$") else text


def _resp_strings(text: str) -> list[str]:
    """Every bulk string of a flat RESP2 array reply, in order."""
    out, lines = [], _resp_body(text).split("\r\n")
    i = 0
    while i < len(lines) - 1:
        if lines[i].startswith("$"):
            out.append(lines[i + 1])
            i += 2
        else:
            i += 1
    return out


def _resp_int(text: str, default: int) -> int:
    body = text.rstrip("\r\n")
    return int(body[1:]) if body.startswith(":") else default
