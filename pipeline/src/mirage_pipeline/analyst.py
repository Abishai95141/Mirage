"""Sessioniser logic (spec 1.6 detection, 1.7): pure state, no NATS or ClickHouse.

``Analyst.process(event)`` takes normalised events in arrival order and returns what changed:

* **HTTP sessions.** HTTP has no session of its own. Connections from one source address and
  user agent form one session until it has been idle for 30 minutes. ``conn_map`` maps each
  connection's session ID to the logical one; other protocols use their own session IDs.
* **Honeytokens.** A session *exposes* a token when it reaches a place the token was planted
  (``cat /var/www/html/.env`` over SSH, ``GET /.env`` over HTTP). A session *uses* a token when
  the token's value appears in its input: a login, a command, a request. Each use is a
  ``token.triggered`` event. Each exposure followed by a use in a different session is an
  ``honeytoken`` actor link, whichever of the two the pipeline sees first.
* **Actor links**, strongest first: ``honeytoken``; ``ssh_fingerprint_credential`` (same HASSH,
  client version and credential pair); ``same_source_24h``. Each session links to the latest
  earlier session with the same key, so the components are the same as with every pair.
* **Actor IDs.** The connected component of the links. The ID hashes the smallest session ID in
  the component, so it does not depend on arrival order.

Every output is deterministic in its inputs, so a redelivered batch writes the same rows.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from mirage_schema import MirageEvent
from mirage_schema.events import EventClass, Outcome, Source, utc_now
from mirage_tokens import Matcher, Token

HTTP_IDLE = timedelta(minutes=30)
SAME_SOURCE = timedelta(hours=24)
STRENGTH = {"honeytoken": 3, "ssh_fingerprint_credential": 2, "same_source_24h": 1}
_NS = uuid.UUID("0d7ad1f4-6b0e-4c55-8c1e-73657373696f")


@dataclass(frozen=True)
class Link:
    a: str
    b: str
    reason: str
    evidence: dict[str, Any]
    ts: datetime

    @classmethod
    def make(cls, x: str, y: str, reason: str, evidence: dict[str, Any], ts: datetime) -> Link:
        a, b = sorted((x, y))
        return cls(a, b, reason, evidence, ts)


@dataclass(frozen=True)
class Exposure:
    token_id: str
    session_id: str
    ts: datetime
    location: str
    event_id: str


@dataclass(frozen=True)
class Use:
    token_id: str
    session_id: str
    ts: datetime
    event_id: str


@dataclass
class Changes:
    touched: set[str] = field(default_factory=set)  # logical sessions whose summary changed
    links: list[Link] = field(default_factory=list)
    findings: list[MirageEvent] = field(default_factory=list)
    exposures: list[Exposure] = field(default_factory=list)
    conn_map: dict[str, str] = field(default_factory=dict)  # new connection -> session rows

    def merge(self, other: Changes) -> None:
        self.touched |= other.touched
        self.links += other.links
        self.findings += other.findings
        self.exposures += other.exposures
        self.conn_map |= other.conn_map


class Components:
    """Union-find over session IDs; the representative is the smallest ID."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, x: str, y: str) -> bool:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return False
        lo, hi = sorted((rx, ry))
        self.parent[hi] = lo
        return True

    def members(self, x: str) -> set[str]:
        root = self.find(x)
        return {s for s in list(self.parent) if self.find(s) == root}

    def actor_id(self, x: str) -> str:
        return "actor-" + hashlib.sha256(self.find(x).encode()).hexdigest()[:16]


def _locations(token: Token) -> list[tuple[str, str]]:
    out = []
    for part in token.planted_at.split(","):
        proto, _, where = part.strip().partition(":")
        if where:
            out.append((proto, where))
    return out


def input_texts(ev: MirageEvent) -> list[str]:
    """The attacker-supplied text of an event, where a token value would appear if used."""
    p = ev.payload
    if ev.source == Source.POLICY or ev.event_class == EventClass.POLICY_DECISION:
        return []  # the same input again; counting it would double every use
    if ev.event_class == EventClass.AUTHENTICATION:
        return [str(p.get("username") or ""), str(p.get("password") or "")]
    if ev.event_class == EventClass.PROCESS_ACTIVITY and ev.action in ("command", "stdin_input"):
        if ev.source == Source.COWRIE and ev.outcome != Outcome.UNKNOWN:
            return []  # command.success / command.failed repeat command.input
        return [str(p.get("command") or "")]
    if ev.event_class == EventClass.HTTP_ACTIVITY:
        body = p.get("body") or {}
        texts = [str(p.get("target") or p.get("path") or ""), str(p.get("query") or "")]
        texts.append(str(body.get("text") or body.get("head") or ""))
        texts += [str(v) for _, v in (p.get("headers") or [])]
        return texts
    if ev.event_class == EventClass.DATASTORE_ACTIVITY and ev.action == "query":
        argv = p.get("argv")
        return [" ".join(map(str, argv)) if isinstance(argv, list) else str(p.get("sql") or "")]
    return []


class Analyst:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = {t.token_id: t for t in tokens}
        self.matcher = Matcher(tokens)
        self.components = Components()
        self.conn_map: dict[str, str] = {}
        self.http_open: dict[tuple[str, str], tuple[str, datetime]] = {}
        self.seen: set[str] = set()
        self.last_by_src: dict[str, tuple[str, datetime]] = {}
        self.ssh_fp: dict[str, tuple[str, str]] = {}  # cowrie session -> (hassh, version)
        self.last_by_fp_cred: dict[tuple[str, str, str, str], str] = {}
        self.exposures: dict[str, list[Exposure]] = {}
        self.uses: dict[str, list[Use]] = {}
        self.linked: set[tuple[str, str, str]] = set()

    # ------------------------------------------------------------------ restore after restart

    def restore_link(self, a: str, b: str, reason: str) -> None:
        self.linked.add((a, b, reason))
        self.components.union(a, b)

    def restore_session(self, sid: str, src_ip: str, end_ts: datetime) -> None:
        self.seen.add(sid)
        self.components.find(sid)
        prev = self.last_by_src.get(src_ip)
        if src_ip and (prev is None or prev[1] <= end_ts):
            self.last_by_src[src_ip] = (sid, end_ts)

    def restore_conn(self, conn_id: str, sid: str) -> None:
        self.conn_map[conn_id] = sid

    def restore_http(self, src_ip: str, ua: str, sid: str, end_ts: datetime) -> None:
        cur = self.http_open.get((src_ip, ua))
        if cur is None or cur[1] <= end_ts:
            self.http_open[(src_ip, ua)] = (sid, end_ts)

    def restore_exposure(self, e: Exposure) -> None:
        self.exposures.setdefault(e.token_id, []).append(e)

    def restore_use(self, u: Use) -> None:
        self.uses.setdefault(u.token_id, []).append(u)

    # ------------------------------------------------------------------ processing

    def session_of(self, ev: MirageEvent) -> str | None:
        if not ev.session_id:
            return None
        return self.conn_map.get(ev.session_id, ev.session_id)

    def process(self, ev: MirageEvent) -> Changes:
        ch = Changes()
        if ev.source in (Source.POLICY, Source.PIPELINE) or not ev.session_id:
            return ch
        src = str(ev.src.ip) if ev.src.ip else ""
        if ev.source == Source.HTTP_DECOY:
            if ev.event_class == EventClass.HTTP_ACTIVITY:
                self._map_http(ev, src, ch)
            elif ev.session_id not in self.conn_map:
                # Before its first request a connection belongs to no session yet (the connect
                # and the decision precede the request event). The summary query picks these
                # events up through the connection map once the request arrives; a connection
                # that never sends a request is not an HTTP session.
                return ch
        sid = self.session_of(ev)
        assert sid is not None
        ch.touched.add(sid)
        if sid not in self.seen:
            self.seen.add(sid)
            self.components.find(sid)
            self._link_same_source(sid, src, ev.ts, ch)
        if src:
            self.last_by_src[src] = (sid, ev.ts)
        self._ssh_fingerprint(ev, sid, ch)
        self._exposures(ev, sid, ch)
        self._uses(ev, sid, ch)
        return ch

    def _map_http(self, ev: MirageEvent, src: str, ch: Changes) -> None:
        conn = ev.session_id or ""
        if conn in self.conn_map:
            sid = self.conn_map[conn]
            ua = str(ev.payload.get("user_agent") or "")
            self.http_open[(src, ua)] = (sid, ev.ts)
            return
        ua = str(ev.payload.get("user_agent") or "")
        cur = self.http_open.get((src, ua))
        if cur is not None and ev.ts - cur[1] <= HTTP_IDLE:
            sid = cur[0]
        else:
            sid = "http-" + hashlib.sha256(f"{src}|{ua}|{conn}".encode()).hexdigest()[:20]
        self.http_open[(src, ua)] = (sid, ev.ts)
        self.conn_map[conn] = sid
        ch.conn_map[conn] = sid

    def _add_link(
        self, x: str, y: str, reason: str, evidence: dict[str, Any], ts: datetime, ch: Changes
    ) -> None:
        if x == y:
            return
        link = Link.make(x, y, reason, evidence, ts)
        key = (link.a, link.b, reason)
        if key in self.linked:
            return
        self.linked.add(key)
        ch.links.append(link)
        before = self.components.find(x) == self.components.find(y)
        self.components.union(x, y)
        ch.touched |= {x, y}
        if not before:
            ch.touched |= self.components.members(x)

    def _link_same_source(self, sid: str, src: str, ts: datetime, ch: Changes) -> None:
        prev = self.last_by_src.get(src) if src else None
        if prev and prev[0] != sid and ts - prev[1] <= SAME_SOURCE:
            gap = round((ts - prev[1]).total_seconds(), 3)
            self._add_link(prev[0], sid, "same_source_24h", {"src_ip": src, "gap_s": gap}, ts, ch)

    def _ssh_fingerprint(self, ev: MirageEvent, sid: str, ch: Changes) -> None:
        if ev.source != Source.COWRIE:
            return
        hassh, version = self.ssh_fp.get(sid, ("", ""))
        if ev.action == "client_kex":
            hassh = str(ev.payload.get("hassh") or "")
        elif ev.action == "client_version":
            version = str(ev.payload.get("client_version") or "")
        self.ssh_fp[sid] = (hassh, version)
        if ev.event_class == EventClass.AUTHENTICATION and ev.action == "login" and hassh:
            user = str(ev.payload.get("username") or "")
            pw = str(ev.payload.get("password") or "")
            key = (hassh, version, user, pw)
            prev = self.last_by_fp_cred.get(key)
            if prev and prev != sid:
                evidence = {"hassh": hassh, "client_version": version, "username": user}
                self._add_link(prev, sid, "ssh_fingerprint_credential", evidence, ev.ts, ch)
            self.last_by_fp_cred[key] = sid

    def _exposures(self, ev: MirageEvent, sid: str, ch: Changes) -> None:
        for token in self.tokens.values():
            for proto, where in _locations(token):
                if self._reaches(ev, proto, where):
                    e = Exposure(token.token_id, sid, ev.ts, f"{proto}:{where}", ev.event_id)
                    self.exposures.setdefault(token.token_id, []).append(e)
                    ch.exposures.append(e)
                    for u in self.uses.get(token.token_id, []):
                        if u.session_id != sid and u.ts >= ev.ts:
                            self._token_link(e, u, ch)

    @staticmethod
    def _reaches(ev: MirageEvent, proto: str, where: str) -> bool:
        p = ev.payload
        if proto == "ssh" and ev.source == Source.COWRIE:
            if ev.event_class != EventClass.PROCESS_ACTIVITY or ev.outcome != Outcome.UNKNOWN:
                return False
            cmd = str(p.get("command") or "")
            base = where.rsplit("/", 1)[-1]
            return where in cmd or (len(base) >= 4 and base in cmd.split("/")[-1].split())
        if proto == "http" and ev.event_class == EventClass.HTTP_ACTIVITY:
            return p.get("path") == where
        if proto in ("redis", "mysql") and ev.event_class == EventClass.DATASTORE_ACTIVITY:
            if ev.protocol != proto or ev.action != "query":
                return False
            text = " ".join(input_texts(ev)).lower()
            return where.lower().rsplit(".", 1)[-1] in text
        return False

    def _uses(self, ev: MirageEvent, sid: str, ch: Changes) -> None:
        hits: dict[str, Token] = {}
        for text in input_texts(ev):
            for t in self.matcher.find(text):
                hits[t.token_id] = t
        for token in hits.values():
            u = Use(token.token_id, sid, ev.ts, ev.event_id)
            known = self.uses.setdefault(token.token_id, [])
            if any(x.event_id == u.event_id for x in known):
                continue
            known.append(u)
            exposed = [
                e
                for e in self.exposures.get(token.token_id, [])
                if e.session_id != sid and e.ts <= ev.ts
            ]
            ch.findings.append(self._finding(ev, sid, token, exposed))
            ch.touched.add(sid)
            for e in exposed:
                self._token_link(e, u, ch)

    def _token_link(self, e: Exposure, u: Use, ch: Changes) -> None:
        evidence = {
            "token_id": e.token_id,
            "exposed_in": e.session_id,
            "exposed_at": e.location,
            "exposed_ts": e.ts.isoformat(),
            "used_in": u.session_id,
            "used_ts": u.ts.isoformat(),
            "use_event_id": u.event_id,
        }
        self._add_link(e.session_id, u.session_id, "honeytoken", evidence, u.ts, ch)

    def _finding(
        self, ev: MirageEvent, sid: str, token: Token, exposed: list[Exposure]
    ) -> MirageEvent:
        return MirageEvent(
            event_id=str(uuid.uuid5(_NS, f"token:{ev.event_id}:{token.token_id}")),
            ts=ev.ts,
            ingest_ts=max(utc_now(), ev.ts),
            source=Source.PIPELINE,
            event_class=EventClass.DETECTION_FINDING,
            session_id=ev.session_id,
            sensor=ev.sensor,
            src=ev.src,
            dst=ev.dst,
            protocol=ev.protocol,
            action="token_triggered",
            outcome=Outcome.SUCCESS,
            payload={
                "eventid": "token.triggered",
                "token_id": token.token_id,
                "token_type": token.type,
                "planted_at": token.planted_at,
                "session": sid,
                "trigger_event_id": ev.event_id,
                "trigger_class": ev.event_class.value,
                "exposed_in": sorted({e.session_id for e in exposed}),
            },
        )
