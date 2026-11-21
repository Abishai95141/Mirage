"""The sessioniser against its store: long lists of session IDs, and a batch that fails
between writing its links and writing its summaries.

Both were found on the lab host on 17 November 2026. One planted credential had been read by
hundreds of lab sessions, each use of it tied its session to all of them, and the actor grew
to thousands of sessions. From then on every batch that touched that actor asked the store
about all of them in one URL, which no longer fitted; the batch failed after its links were
written, was delivered again with nothing left to link, and its sessions kept two actor IDs.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from mirage_pipeline.analyst import Analyst, Changes
from mirage_pipeline.normaliser import (
    CHUNK,
    MAX_PARAM_BYTES,
    ClickHouse,
    Settings,
    _param,
    chunks,
)
from mirage_pipeline.sessioniser import SUMMARY_SQL, Sessioniser

T0 = datetime(2026, 11, 1, 10, 0, 0, tzinfo=UTC)


# ------------------------------------------------------------------ the client


def store(handler) -> ClickHouse:
    ch = ClickHouse(Settings())
    ch._client = httpx.AsyncClient(
        base_url="http://store:8123", transport=httpx.MockTransport(handler)
    )
    return ch


async def test_a_query_and_its_parameters_travel_in_the_body():
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["type"] = request.headers["content-type"]
        seen["body"] = request.content.decode()
        return httpx.Response(200, text='{"n":2}\n')

    ids = [f"http-{i:020d}" for i in range(CHUNK)]
    rows = await store(handler).select("SELECT length({ids:Array(String)}) AS n", ids=ids, lo="x")
    assert rows == [{"n": 2}]
    assert seen["url"] == "http://store:8123/"  # nothing of the query is in the URL
    assert seen["type"].startswith("multipart/form-data")
    for field in ('name="query"', 'name="param_ids"', 'name="param_lo"'):
        assert field in seen["body"]
    assert "FORMAT JSONEachRow" in seen["body"] and ids[-1] in seen["body"]


async def test_a_list_too_long_for_one_parameter_is_refused_before_it_is_sent():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("nothing may be sent")

    ids = ["s" * 30] * (MAX_PARAM_BYTES // 30)
    with pytest.raises(ValueError, match="in parts"):
        await store(handler).select("SELECT 1 WHERE x IN {ids:Array(String)}", ids=ids)


def test_a_full_chunk_of_the_longest_ids_fits_one_parameter():
    longest = ["http-" + "f" * 20] * CHUNK  # an HTTP session ID, the longest kind
    assert len(_param(longest).encode()) < MAX_PARAM_BYTES / 2
    assert [len(c) for c in chunks(list(range(2500)))] == [1000, 1000, 500]
    assert chunks([]) == []


def test_parameter_values_are_escaped_as_the_store_reads_them():
    assert _param(["a'b", "c\\d", "e\tf"]) == "['a\\'b','c\\\\d','e\\tf']"
    assert _param("it's a\ttab\\") == "it's a\\ttab\\\\"  # a scalar is not quoted
    assert _param(7) == "7"


# ------------------------------------------------------------------ an in-memory store


class Store:
    """Just enough of the tables the sessioniser reads and writes. ``events`` maps a
    connection or session ID to its source address; a summary is made from that."""

    def __init__(self) -> None:
        self.tables: dict[str, list[dict[str, Any]]] = {}
        self.events: dict[str, str] = {}
        self.summary_queries: list[dict[str, Any]] = []
        self.fail_summaries = 0

    async def insert(self, rows: list[dict[str, Any]], table: str | None = None) -> None:
        self.tables.setdefault(table or "mirage.events", []).extend(rows)

    def latest(self, table: str, key: str) -> list[dict[str, Any]]:
        kept: dict[Any, dict[str, Any]] = {}
        for row in self.tables.get(table, []):
            kept[row[key] if isinstance(key, str) else tuple(row[k] for k in key)] = row
        return list(kept.values())

    async def select(self, sql: str, **params: Any) -> list[dict[str, Any]]:
        for value in params.values():
            if isinstance(value, list):
                assert len(_param(value).encode()) <= MAX_PARAM_BYTES
        if sql == SUMMARY_SQL:
            if self.fail_summaries:
                self.fail_summaries -= 1
                raise RuntimeError("ClickHouse query failed 500")
            self.summary_queries.append(params)
            logical = dict(zip(params["conns"], params["sids"], strict=True))
            grouped: dict[str, list[str]] = {}
            for i in params["ids"]:
                if i in self.events:
                    grouped.setdefault(logical.get(i, i), []).append(i)
            return [
                {
                    "sid": sid, "source": "decoy", "protocol": "http", "sensor": "dep",
                    "src_ip": self.events[conns[0]], "start_ts": "2026-11-01 10:00:00.000000",
                    "end_ts": "2026-11-01 10:00:01.000000", "inputs": len(conns), "decisions": 0,
                    "fallbacks": 0, "auth_attempts": 0, "auth_ok": 0, "credentials": [],
                    "hassh": "", "client_version": "", "user_agent": "", "headers": "",
                    "client_attrs": "", "tokens": [], "artifacts": [],
                    "connections": sorted(conns),
                }
                for sid, conns in grouped.items()
            ]  # fmt: skip
        if "FROM mirage.actor_links" in sql:
            return [
                {"a": r["a"], "b": r["b"], "reason": r["reason"]}
                for r in self.tables.get("mirage.actor_links", [])
            ]
        if "FROM mirage.session_map" in sql:
            return self.latest("mirage.session_map", "conn_id")
        if "FROM mirage.session_summary" in sql:
            rows = self.latest("mirage.session_summary", "session_id")
            return [{**r, "ua": "", "fingerprints": r.get("fingerprints", "{}")} for r in rows]
        if "FROM mirage.token_exposures" in sql or "token_triggered" in sql:
            return []
        raise AssertionError(f"a query the store does not know: {sql[:80]}")

    def actor(self, sid: str) -> str:
        return next(
            r["actor_id"] for r in self.latest("mirage.session_summary", "session_id")
            if r["session_id"] == sid
        )  # fmt: skip


def link(svc: Sessioniser, x: str, y: str) -> Changes:
    ch = Changes()
    svc.analyst._add_link(x, y, "honeytoken", {"n": f"{x}:{y}"}, T0 + timedelta(seconds=1), ch)
    return ch


def service(n: int = 0) -> tuple[Sessioniser, Store]:
    """A sessioniser whose store holds ``n`` sessions of one actor, ``big-0000`` on."""
    st = Store()
    svc = Sessioniser(st, [])  # type: ignore[arg-type]
    members = [f"big-{i:04d}" for i in range(n)]
    for m in members:
        st.events[m] = "198.51.100.7"
        svc.analyst.seen.add(m)
        svc.analyst.components.find(m)
    for m in members[1:]:
        svc.analyst.restore_link(members[0], m, "same_source_24h")
        st.tables.setdefault("mirage.actor_links", []).append(
            {"a": members[0], "b": m, "reason": "same_source_24h"}
        )
    return svc, st


# ------------------------------------------------------------------ what is recomputed


def test_an_actor_that_gains_a_session_is_not_rewritten_for_it():
    svc, _ = service(3000)
    before = svc.analyst.components.actor_id("big-0000")
    ch = link(svc, "big-1500", "zzz-new")  # the new session sorts after the actor's name
    assert ch.touched == {"big-1500", "zzz-new"}
    assert svc.analyst.components.actor_id("zzz-new") == before


def test_an_actor_that_is_renamed_is_rewritten_whole():
    svc, _ = service(3000)
    before = svc.analyst.components.actor_id("big-0000")
    ch = link(svc, "big-1500", "aaa-new")  # sorts before every member: the actor takes its name
    assert len(ch.touched) == 3001
    after = {svc.analyst.components.actor_id(s) for s in ch.touched}
    assert len(after) == 1 and after != {before}


def test_two_actors_joining_rewrite_the_one_that_is_renamed():
    svc, _ = service(50)
    for s in ("mmm-1", "mmm-2", "mmm-3"):
        svc.analyst.components.find(s)
    link(svc, "mmm-1", "mmm-2")
    link(svc, "mmm-2", "mmm-3")
    ch = link(svc, "mmm-3", "big-0007")
    assert ch.touched == {"mmm-1", "mmm-2", "mmm-3", "big-0007"}


async def test_a_long_list_is_sent_in_parts_and_no_session_is_cut_in_two():
    svc, st = service()
    sids = set()
    for i in range(700):  # 700 logical sessions of four connections each: 3,500 IDs
        sid = f"http-{i:04d}"
        sids.add(sid)
        for c in range(4):
            conn = f"conn-{i:04d}-{c}"
            st.events[conn] = "203.0.113.9"
            svc.analyst.conn_map[conn] = sid
    assert await svc.summarise(sids, 1) == 700
    assert len(st.summary_queries) >= 3
    for q in st.summary_queries:
        assert len(q["ids"]) <= CHUNK
        assert set(q["conns"]) <= set(q["ids"])  # every connection with its session's others
    written = st.latest("mirage.session_summary", "session_id")
    assert len(st.tables["mirage.session_summary"]) == 700  # one row each, none in halves
    assert all(len(r["connections"]) == 4 for r in written)


# ------------------------------------------------------------------ a batch that fails halfway


async def test_a_batch_that_fails_after_its_links_is_put_right_when_state_is_rebuilt():
    svc, st = service(40)
    for s in ("web-1", "db-1"):
        st.events[s] = "203.0.113.9"
    assert await svc.summarise({"web-1", "db-1", *[f"big-{i:04d}" for i in range(40)]}, 1)
    assert st.actor("web-1") != st.actor("db-1")

    # The batch that ties the two together: its links are written, its summaries are not.
    ch = link(svc, "web-1", "db-1")
    st.fail_summaries = 1
    with pytest.raises(RuntimeError):
        await svc.write(ch)
    assert [r for r in st.tables["mirage.actor_links"] if r["reason"] == "honeytoken"]
    assert st.actor("web-1") != st.actor("db-1")  # the store now disagrees with itself

    # What the service does next: rebuild from the store, then take the batch again.
    svc.analyst = Analyst([])
    await svc.restore()
    assert st.actor("web-1") == st.actor("db-1")
    again = link(svc, "web-1", "db-1")
    # The link is known, so the batch marks nothing: which is why the rebuild had to.
    assert again.links == [] and again.touched == set() and await svc.write(again) == 0
    assert await svc.reconcile() == 0  # and there is nothing left to put right


async def test_reconcile_rewrites_only_what_disagrees():
    svc, st = service(40)
    everyone = {f"big-{i:04d}" for i in range(40)}
    await svc.summarise(everyone, 1)
    rows = len(st.tables["mirage.session_summary"])
    assert await svc.reconcile() == 0 and len(st.tables["mirage.session_summary"]) == rows
    stale = json.loads(json.dumps(st.latest("mirage.session_summary", "session_id")[5]))
    st.tables["mirage.session_summary"].append({**stale, "actor_id": "actor-of-long-ago"})
    assert await svc.reconcile() == 1
    assert len({st.actor(s) for s in everyone}) == 1
