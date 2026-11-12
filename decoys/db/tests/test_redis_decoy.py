"""Redis decoy: every measured reply byte for byte, gating, per-source state, limits.

The reference replies come from ``decoys/profiles/reference/debian-12.json`` (the measured
Debian 12 redis-server 7.0.15); deployment values (keyspace, CONFIG, run_id) come from the
rendered profile. Probes run one connection per command from one source, like the extractor
that produced the reference.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time

import pytest
from conftest import ROOT, SRC_IP, FakeGate, RedisConn, decoy

from mirage_db_decoy.redis.handler import Handler, human_bytes
from mirage_db_decoy.redis.state import RESET_AFTER_S, Entry, Profile, Registry
from mirage_decoy_common.gate import Applied
from mirage_decoy_common.server import connection_handler
from mirage_profiles.generator import parse_resp_array
from mirage_schema.policy import Action, Protocol

REF = {
    k: v.encode()
    for k, v in json.loads((ROOT / "decoys/profiles/reference/debian-12.json").read_text())[
        "redis"
    ]["replies"].items()
}
SRC = SRC_IP.encode()


class Srv:
    def __init__(self, d, port: int, profile: Profile) -> None:
        self.decoy, self.port, self.profile = d, port, profile

    def of(self, eventid: str) -> list[dict]:
        return [e for e in self.decoy.log.records if e["eventid"] == eventid]

    async def events(self, sessions: int = 1) -> list[dict]:
        for _ in range(300):
            if (
                sum(e["eventid"] == "redis.session.closed" for e in self.decoy.log.records)
                >= sessions
            ):
                break
            await asyncio.sleep(0.01)
        return self.decoy.log.records

    async def probe(self, *args: bytes, src: str = SRC_IP) -> bytes:
        """One command on one fresh connection, as the reference extractor probes."""
        c = await RedisConn.connect(self.port, src=src)
        try:
            return (await c.cmd(*args))[0]
        finally:
            await c.close()


@pytest.fixture
async def srv(profile_dir, tmp_path):
    profile = Profile.load(profile_dir)
    d = decoy(Protocol.REDIS, artifacts=tmp_path / "art")
    server = await asyncio.start_server(
        connection_handler(d, Handler(profile, Registry(profile)), True), "127.0.0.1", 0
    )
    s = Srv(d, server.sockets[0].getsockname()[1], profile)
    yield s
    server.close()
    await RedisConn.close_all()
    await asyncio.wait_for(server.wait_closed(), 5)


def bulk(b: bytes) -> bytes:
    return b"$%d\r\n%s\r\n" % (len(b), b)


def array(items) -> bytes:
    items = list(items)
    return b"*%d\r\n" % len(items) + b"".join(bulk(i) for i in items)


# ------------------------------------------------------------------ reference parity


async def test_reference_replies_byte_for_byte(srv, profile_dir):
    prof = json.loads((profile_dir / "redis.json").read_text())
    seeded = list(prof["keyspace"]["0"])
    probe = srv.probe

    assert await probe(b"DBSIZE") == b":%d\r\n" % len(seeded)  # deployment data, not the :0
    assert await probe(b"KEYS", b"*") == array(k.encode() for k in seeded)
    assert await probe(b"TYPE", b"nokey") == REF["type_missing"]
    assert await probe(b"TTL", b"nokey") == REF["ttl_missing"]
    assert await probe(b"GET", b"nokey") == REF["get_missing"]
    assert await probe(b"SET", b"k", b"v") == REF["set"]
    assert await probe(b"GET", b"k") == REF["get"]
    assert await probe(b"DEL", b"k") == REF["del"]
    assert await probe(b"EXISTS", b"k") == REF["exists"]
    assert await probe(b"CONFIG", b"GET", b"dir") == REF["config_get_dir"]
    assert await probe(b"CONFIG", b"GET", b"dbfilename") == REF["config_get_dbfilename"]

    got = await probe(b"CONFIG", b"GET", b"*")
    names = parse_resp_array(REF["config_get_all"].decode())[::2]
    expected = array(x for n in names for x in (n.encode(), prof["config"][n].encode()))
    assert got == expected

    assert await probe(b"CONFIG", b"SET", b"nosuch", b"1") == REF["config_set_bad"]
    assert await probe(b"CONFIG", b"SET", b"dir", b"/tmp") == REF["config_set_dir"]
    assert await probe(b"CONFIG", b"SET", b"dbfilename", b"x.rdb") == REF["config_set_dbfilename"]
    assert await probe(b"CONFIG", b"SET", b"maxclients", b"10000") == b"+OK\r\n"
    assert await probe(b"CONFIG", b"FOO") == REF["config_bad_subcommand"]
    assert await probe(b"SCAN", b"0") == b"*2\r\n" + bulk(b"0") + array(k.encode() for k in seeded)
    assert await probe(b"ECHO", b"hello") == REF["echo"]
    assert await probe(b"EVAL", b"os.execute('id')", b"0") == REF["eval_os"]
    assert await probe(b"EVAL", b"return 'x'", b"0") == REF["eval_return_string"]
    assert await probe(b"BGSAVE") == REF["bgsave"]
    assert await probe(b"FLUSHDB") == REF["flushdb"]
    assert await probe(b"MODULE", b"LOAD", b"/tmp/exp.so") == REF["module_load"]
    script = b"local io_l = package.loadlib('/x', 'y')"
    sha = hashlib.sha1(script).hexdigest()
    assert await probe(b"EVAL", script, b"0") == REF["eval_cve_2022_0543"].replace(
        b"script: 59383731574f8ef9c055b3f4cf9cca078446f86d", f"script: {sha}".encode()
    )
    assert await probe(b"EVAL", b"return 1", b"0") == REF["eval_simple"]
    assert await probe(b"COMMAND", b"COUNT") == REF["command_count"]
    assert await probe(b"CLIENT", b"SETNAME", b"probe") == REF["client_setname"]
    assert await probe(b"CLIENT", b"GETNAME") == REF["client_getname"]  # fresh connection
    assert await probe(b"FLUSHALL") == REF["flushall"]
    assert await probe(b"SAVE") == REF["save"]
    assert await probe(b"SELECT", b"16") == REF["select_out_of_range"]
    assert await probe(b"SELECT", b"1") == REF["select_1"]
    assert await probe(b"AUTH", b"hunter2") == REF["auth_no_password"]
    assert await probe(b"FOO", b"bar", b"baz") == REF["unknown"]
    assert await probe(b"FOO") == REF["unknown_noargs"]
    assert await probe(b"GET") == REF["wrong_arity"]
    assert await probe(b"SLAVEOF", b"192.0.2.10", b"6379") == REF["slaveof"]
    assert await probe(b"SLAVEOF", b"NO", b"ONE") == REF["slaveof_no_one"]
    assert await probe(b"INFO", b"nosuchsection") == b"$0\r\n\r\n"


async def test_reference_inline_and_protocol_errors(srv):
    c = await RedisConn.connect(srv.port)
    assert (await c.inline(b"PING"))[0] == REF["ping_inline"]
    assert (await c.inline(b"hello world"))[0] == REF["inline_unknown"]
    await c.close()
    c = await RedisConn.connect(srv.port)
    await c.send(b"*1\r\n$600000000\r\n")
    assert await c.r.read(-1) == REF["bulk_too_big"]  # answered, then the connection closed
    c2 = await RedisConn.connect(srv.port)
    # Redis 7.0's gopher path: a Host: line swallows every queued reply and closes.
    c2.w.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    await c2.w.drain()
    assert await c2.r.read(-1) == REF["http_on_redis"]
    c3 = await RedisConn.connect(srv.port)
    c3.w.write(b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1048577\r\n")
    await c3.w.drain()
    assert await c3.r.read(-1) == b"-ERR Protocol error: invalid bulk length\r\n"


async def test_replication_target_recorded_and_reported(srv):
    c = await RedisConn.connect(srv.port)
    assert (await c.cmd(b"SLAVEOF", b"192.0.2.10", b"6379"))[0] == REF["slaveof"]
    info = (await c.cmd(b"INFO", b"replication"))[0]
    body = info.split(b"\r\n", 1)[1]
    assert body == REF["info_replication_after_slaveof"].split(b"\r\n", 1)[1]
    (change,) = srv.of("redis.state.change")
    assert (change["op"], change["host"], change["port"]) == ("slaveof", "192.0.2.10", 6379)
    assert (await c.cmd(b"SLAVEOF", b"NO", b"ONE"))[0] == REF["slaveof_no_one"]
    back = (await c.cmd(b"INFO", b"replication"))[1]
    assert b"role:master\r\n" in back


async def test_hello_matches_reference_shape(srv, profile_dir):
    prof = json.loads((profile_dir / "redis.json").read_text())
    c = await RedisConn.connect(srv.port)
    for proto_ver in (b"2", b"3"):
        _, value = await c.cmd(b"HELLO", proto_ver)
        pairs = (
            value.items() if isinstance(value, dict) else zip(value[::2], value[1::2], strict=True)
        )
        got = {k.decode(): v.decode() if isinstance(v, bytes) else v for k, v in pairs}
        assert got["server"] == "redis" and got["version"] == prof["version"]
        assert got["proto"] == int(proto_ver) and got["mode"] == "standalone"
        assert got["role"] == "master" and got["modules"] == []
        assert isinstance(got["id"], int)
    assert (await c.cmd(b"HELLO", b"9"))[0] == b"-NOPROTO unsupported protocol version\r\n"
    # the id is per-connection state (the reference captured 39/40); everything else matches


async def test_info_assembled_from_profile(srv, profile_dir, monkeypatch):
    prof = json.loads((profile_dir / "redis.json").read_text())
    now = prof["start_epoch"] + 120
    monkeypatch.setattr("mirage_db_decoy.redis.handler.time.time", lambda: now)
    c = await RedisConn.connect(srv.port)
    raw, _ = await c.cmd(b"INFO")
    body = raw.split(b"\r\n", 1)[1]
    up = 120
    dynamic = {
        "server_time_usec": str(int(now * 1e6)),
        "uptime_in_seconds": str(up),
        "uptime_in_days": str(up // 86400),
        "lru_clock": str(now & 0xFFFFFF),
        "connected_clients": "1",
    }
    sections = []
    for sec in prof["info"]:
        if sec["section"] == "Keyspace":
            fields = [f"db0:keys={len(prof['keyspace']['0'])},expires=0,avg_ttl=0"]
        else:
            fields = [f"{k}:{dynamic.get(k, v)}" for k, v in sec["fields"]]
        sections.append(f"# {sec['section']}\r\n" + "".join(f"{f}\r\n" for f in fields) + "\r\n")
    want = "".join(sections).encode()
    # used_memory is a live estimate (startup + keyspace + clients), not the profile snapshot
    live = {}

    def masked(lines: list[bytes]) -> list[bytes]:
        out = []
        for ln in lines:
            k, _, v = ln.partition(b":")
            if k in (b"used_memory", b"used_memory_human"):
                live[k] = v
                out.append(k)
            else:
                out.append(ln)
        return out

    assert masked(want.split(b"\r\n")) == masked(body.split(b"\r\n"))  # body's values last
    startup = int(srv.profile.info_field("Memory", "used_memory_startup", "0"))
    assert int(live[b"used_memory"]) > startup
    assert live[b"used_memory_human"].decode() == human_bytes(int(live[b"used_memory"]))
    assert b"run_id:" + prof["info"][0]["fields"][13][1].encode() in body


# ------------------------------------------------------------------ state


async def test_state_is_per_source(srv, profile_dir):
    prof = json.loads((profile_dir / "redis.json").read_text())
    blogname = prof["keyspace"]["0"]["wp:options:blogname"]["value"].encode()
    a, b, a2 = await asyncio.gather(
        RedisConn.connect(srv.port, src="203.0.113.1"),
        RedisConn.connect(srv.port, src="203.0.113.2"),
        RedisConn.connect(srv.port, src="203.0.113.1"),
    )
    assert (await a.cmd(b"SET", b"only-a", b"1"))[0] == b"+OK\r\n"
    assert (await b.cmd(b"GET", b"only-a"))[0] == b"$-1\r\n"
    assert (await a2.cmd(b"GET", b"only-a"))[0] == b"$1\r\n1\r\n"
    # the seeded keyspace is there for everyone
    assert (await b.cmd(b"GET", b"wp:options:blogname"))[1] == blogname
    await a.cmd(b"DEL", b"only-a")
    for c in (a, b, a2):
        await c.close()


def test_state_resets_24h_after_first_write(profile_dir):
    profile = Profile.load(profile_dir)
    reg = Registry(profile)
    st = reg.get("1.2.3.4")
    st.wrote()
    st.dbs[0][b"k"] = Entry("string", b"v")
    st.first_write = time.time() - RESET_AFTER_S - 5
    fresh = reg.get("1.2.3.4")
    assert b"k" not in fresh.dbs.get(0, {})
    assert b"app:config" in fresh.dbs[0]  # re-seeded from the profile


def test_write_budget_is_bounded(profile_dir, monkeypatch):
    from mirage_db_decoy.redis import state as st_mod

    profile = Profile.load(profile_dir)
    reg = Registry(profile)
    st = reg.get("1.2.3.4")
    # the seeded keyspace counts against the budget; leave 128 bytes of headroom
    monkeypatch.setattr(st_mod, "SOURCE_BUDGET", st.nbytes() + 128)
    assert reg.ensure_capacity(st, 64)
    assert not reg.ensure_capacity(st, 256)


async def test_set_options(srv):
    c = await RedisConn.connect(srv.port)
    assert (await c.cmd(b"SET", b"nxk", b"1", b"NX"))[0] == b"+OK\r\n"
    assert (await c.cmd(b"SET", b"nxk", b"2", b"NX"))[0] == b"$-1\r\n"
    assert (await c.cmd(b"SET", b"nxk", b"3", b"XX", b"GET"))[0] == b"$1\r\n1\r\n"
    assert (await c.cmd(b"SET", b"new", b"9", b"XX"))[0] == b"$-1\r\n"
    assert (await c.cmd(b"SET", b"exk", b"v", b"EX", b"100"))[0] == b"+OK\r\n"
    assert 90 <= (await c.cmd(b"TTL", b"exk"))[1] <= 100
    assert (await c.cmd(b"GET", b"wp:options:siteurl"))[0].startswith(b"$")  # hash would fail
    assert (await c.cmd(b"GET", b"app:config"))[0] == (
        b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n"
    )
    await c.close()


# ------------------------------------------------------------------ gate


async def test_gate_actions(srv, tmp_path):
    gate = FakeGate()
    srv.decoy.gate = gate
    c = await RedisConn.connect(srv.port)

    gate.applied = Applied(Action.FAKE_SUCCESS, output="selftest ok\n")
    assert (await c.cmd(b"GET", b"mirage-selftest-fake-success"))[0] == b"$12\r\nselftest ok\n\r\n"
    gate.applied = Applied(Action.FAKE_SUCCESS, output="")
    assert (await c.cmd(b"PING"))[0] == b"+OK\r\n"

    gate.applied = Applied(Action.FAKE_ERROR, output="selftest failed\n", exit_code=2)
    assert (await c.cmd(b"PING"))[0] == b"-ERR selftest failed\r\n"

    gate.applied = Applied(Action.DELAY, delay_ms=250)
    started = time.monotonic()
    assert (await c.cmd(b"PING"))[0] == b"+PONG\r\n"
    assert time.monotonic() - started >= 0.25

    gate.applied = Applied(Action.TERMINATE)
    await c.cmd(b"PING")
    assert await c.r.read(-1) == b""  # closed without a reply

    req = gate.reqs[0]
    assert (req.protocol, req.argv, req.db, req.seq, req.known) == (
        Protocol.REDIS,
        ["GET", "mirage-selftest-fake-success"],
        0,
        1,
        True,
    )


async def test_fallback_behaves_as_plain_emulation(srv):
    c = await RedisConn.connect(srv.port)
    assert (await c.cmd(b"PING"))[0] == b"+PONG\r\n"
    await srv.events()
    (dec,) = srv.of("redis.policy.decision")
    assert (dec["action"], dec["fallback"], dec["fallback_reason"]) == ("allow", True, "disabled")
    (iput,) = srv.of("redis.input")
    assert iput["outcome"] == "success" and iput["seq"] == 1


async def test_unknown_commands_are_gated_as_unknown(srv):
    gate = FakeGate()
    srv.decoy.gate = gate
    c = await RedisConn.connect(srv.port)
    assert (await c.cmd(b"FOO", b"bar"))[0] == REF["unknown"].replace(b"'bar' 'baz' ", b"'bar' ")
    assert gate.reqs[0].known is False


# ------------------------------------------------------------------ events


async def test_events_capture_inputs_replies_and_changes(srv, tmp_path):
    c = await RedisConn.connect(srv.port)
    await c.cmd(b"SELECT", b"2")
    big = b"v" * 5000
    await c.cmd(b"SET", b"big", big)
    await c.cmd(b"GET", b"big")
    await c.cmd(b"CLIENT", b"SETNAME", b"probe")
    await c.cmd(b"CONFIG", b"SET", b"maxmemory", b"100mb")
    await c.cmd(b"DEL", b"big")
    await c.close()
    await srv.events()

    inputs = srv.of("redis.input")
    assert [i["seq"] for i in inputs] == [1, 2, 3, 4, 5, 6]
    assert inputs[0]["argv"] == ["SELECT", "2"] and inputs[0]["db"] == 0
    assert inputs[1]["db"] == 2
    assert inputs[1]["reply"]["size"] == len(b"+OK\r\n")
    get_reply = inputs[2]["reply"]
    assert get_reply["size"] > 4096 and "text" not in get_reply and "head" in get_reply
    # replies are recorded as wire bytes, like the +OK above
    assert get_reply["sha256"] == hashlib.sha256(bulk(big)).hexdigest()

    (attrs,) = srv.of("redis.client.attrs")
    assert attrs["attrs"] == {"name": "probe"}

    changes = srv.of("redis.state.change")
    by_op = {ch["op"]: ch for ch in changes}
    assert by_op["set"]["key"] == "big" and by_op["set"]["value"]["size"] == 5000
    assert "text" not in by_op["set"]["value"]  # over 4 KiB: artifact store
    # two over-cap blobs: the SET value and the GET reply carrying it
    arts = {a["kind"]: a for a in srv.of("redis.artifact")}
    assert set(arts) == {"redis.value", "redis.reply"}
    assert all(a["stored"] is True for a in arts.values())
    assert (tmp_path / "art" / arts["redis.value"]["sha256"]).read_bytes() == big
    assert (tmp_path / "art" / arts["redis.reply"]["sha256"]).read_bytes() == bulk(big)
    assert by_op["config"]["params"] == {"maxmemory": "100mb"}
    assert by_op["del"]["keys"] == ["big"]

    ids = [e["eventid"] for e in await srv.events()]
    assert ids[0] == "redis.session.connect" and ids[-1] == "redis.session.closed"
    assert len({e["session"] for e in srv.decoy.log.records}) == 1


async def test_client_list_reports_live_clients(srv):
    a = await RedisConn.connect(srv.port, src="203.0.113.1")
    b = await RedisConn.connect(srv.port, src="203.0.113.2")
    await a.cmd(b"CLIENT", b"SETNAME", b"first")
    raw, _ = await b.cmd(b"CLIENT", b"LIST")
    lines = raw.split(b"\r\n", 1)[1].decode().strip().split("\n")
    assert len(lines) == 2
    fields = dict(f.split("=", 1) for ln in lines for f in ln.split() if "=" in f)
    assert fields["name"] in ("first", "") and fields["resp"] == "2"
    assert any("203.0.113.1" in ln for ln in lines)
    assert any("cmd=client|setname" in ln for ln in lines)
    await a.close()
    await b.close()


async def test_auth_with_requirepass(srv):
    c = await RedisConn.connect(srv.port)
    await c.cmd(b"CONFIG", b"SET", b"requirepass", b"sekrit")
    c2 = await RedisConn.connect(srv.port, src=SRC_IP)
    assert (await c2.cmd(b"PING"))[0] == b"-NOAUTH Authentication required.\r\n"
    assert (await c2.cmd(b"AUTH", b"wrong"))[0].startswith(b"-WRONGPASS")
    assert (await c2.cmd(b"AUTH", b"sekrit"))[0] == b"+OK\r\n"
    assert (await c2.cmd(b"PING"))[0] == b"+PONG\r\n"
    await c.close()
    await c2.close()
    await srv.events()
    logins = srv.of("redis.login.failed") + srv.of("redis.login.success")
    assert [e["eventid"] for e in logins] == ["redis.login.failed", "redis.login.success"]
    assert logins[1]["username"] == "default" and logins[1]["password"] == "sekrit"


def test_human_bytes():
    assert human_bytes(1592336) == "1.52M"
    assert human_bytes(43008) == "42.00K"
    assert human_bytes(908944) == "887.64K"
    assert human_bytes(12528578560) == "11.67G"
    assert human_bytes(512) == "512B"
