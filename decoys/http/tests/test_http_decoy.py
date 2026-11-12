import asyncio
import hashlib
import json
import re
import time
from pathlib import Path

import pytest

from mirage_decoy_common.gate import Applied, GateClient
from mirage_decoy_common.proxyproto import build_header
from mirage_decoy_common.server import connection_handler
from mirage_decoy_common.session import ArtifactStore, Decoy, EventLog
from mirage_http_decoy.handler import Handler
from mirage_http_decoy.nginx import PADDING, Profile, http_date
from mirage_profiles.generator import render
from mirage_schema.policy import Action, Protocol

ROOT = Path(__file__).resolve().parents[3]
REF = json.loads((ROOT / "decoys/profiles/reference/debian-12.json").read_text())["nginx"]
TELLS = (b"uvicorn", b"starlette", b"fastapi", b"h11", b"python")
IMF = re.compile(
    r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d\d (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d\d:\d\d:\d\d GMT"
)
CHROME = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def get(path, version="1.1", extra="", method="GET"):
    host = "Host: localhost\r\n" if version == "1.1" else ""
    return f"{method} {path} HTTP/{version}\r\n{host}{extra}\r\n".encode()


def parse(data, heads=()):
    """Split a byte stream into (status_line, [(name, value)], body) by Content-Length."""
    out = []
    while data:
        hdr, _, rest = data.partition(b"\r\n\r\n")
        lines = hdr.decode("latin-1").split("\r\n")
        headers = [tuple(x.split(": ", 1)) for x in lines[1:]]
        h = dict(headers)
        n = 0 if len(out) in heads or " 304 " in lines[0] else int(h.get("Content-Length", 0))
        out.append((lines[0], headers, rest[:n]))
        data = rest[n:]
    return out


class FakeGate:
    def __init__(self, applied):
        self.applied, self.reqs = applied, []

    async def decide(self, req):
        self.reqs.append(req)
        return self.applied

    async def close(self):
        pass


class Srv:
    def __init__(self, decoy, port, profile, art):
        self.decoy, self.port, self.profile, self.art = decoy, port, profile, art

    async def talk(self, *chunks, eof=True, timeout=10.0):
        r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(build_header("203.0.113.9", 40001, "10.0.0.5", 80))
        for c in chunks:
            w.write(c)
            await w.drain()
        if eof:
            w.write_eof()
        try:
            return await asyncio.wait_for(r.read(-1), timeout)
        finally:
            w.close()

    async def events(self, sessions=1):
        for _ in range(300):
            if (
                sum(e["eventid"] == "http.session.closed" for e in self.decoy.log.records)
                >= sessions
            ):
                break
            await asyncio.sleep(0.01)
        return self.decoy.log.records

    def of(self, eventid):
        return [e for e in self.decoy.log.records if e["eventid"] == eventid]

    def route(self, path):
        return self.profile.routes[path]


@pytest.fixture(scope="module")
def profile(tmp_path_factory):
    out = render(ROOT / "decoys/profiles/web-db.yaml", 7, tmp_path_factory.mktemp("prof") / "p")
    return Profile.load(out / "http.json")


@pytest.fixture
async def srv(profile, tmp_path):
    decoy = Decoy(
        Protocol.HTTP, GateClient(None), EventLog(None), ArtifactStore(tmp_path / "art"), "dep-test"
    )
    server = await asyncio.start_server(
        connection_handler(decoy, Handler(profile), True), "127.0.0.1", 0
    )
    yield Srv(decoy, server.sockets[0].getsockname()[1], profile, tmp_path / "art")
    server.close()
    await server.wait_closed()


def assert_like_reference(resp, key, skip=("Date",)):
    status, headers, body = resp
    ref = REF[key]
    assert status == ref["status_line"]
    assert [k for k, _ in headers] == ref["header_order"]
    for k, v in headers:
        if k == "Date":
            assert IMF.fullmatch(v)
        elif k not in skip:
            assert v == ref["headers"][k], k
    assert body == ref["body"].encode()


CLOSE = "Connection: close\r\n"


@pytest.mark.parametrize(
    ("key", "request_bytes"),
    [
        ("404", get("/no-such-page", extra=CLOSE)),
        ("404_http10", get("/no-such-page", "1.0")),
        ("403", get("/server-status", extra=CLOSE)),
        ("403", get("/backup.sql", extra=CLOSE)),
        ("405", get("/", method="POST", extra="Content-Length: 0\r\n" + CLOSE)),
        ("413", get("/wp-login.php", method="POST", extra="Content-Length: 1048577\r\n")),
        ("400_garbage", b"GARBAGE\r\n\r\n"),
        ("400_no_host", b"GET / HTTP/1.1\r\n\r\n"),
    ],
)
async def test_error_pages_match_reference(srv, key, request_bytes):
    data = await srv.talk(request_bytes)
    (resp,) = parse(data)
    assert_like_reference(resp, key)


async def test_directory_redirect_matches_reference(srv):
    (resp,) = parse(await srv.talk(get("/phpmyadmin", extra=CLOSE)))
    assert_like_reference(resp, "301_dir", skip=("Date", "Location"))
    assert dict(resp[1])["Location"] == "http://localhost/phpmyadmin/"
    (resp,) = parse(
        await srv.talk(
            get("/.git?x=1", extra="Host: Example.COM:8080\r\n" + CLOSE).replace(
                b"Host: localhost\r\n", b""
            )
        )
    )
    assert dict(resp[1])["Location"] == "http://example.com/.git/?x=1"
    (resp,) = parse(await srv.talk(get("/.git/", extra=CLOSE)))
    assert resp[0] == "HTTP/1.1 403 Forbidden"


async def test_index_and_head_framing(srv, profile):
    route = srv.route("/")
    body = route["body"].encode()
    (resp,) = parse(await srv.talk(get("/", extra=CLOSE)))
    status, headers, got = resp
    assert status == "HTTP/1.1 200 OK"
    assert [k for k, _ in headers] == REF["index"]["header_order"] == profile.ok_order
    h = dict(headers)
    assert h["Server"] == REF["index"]["headers"]["Server"] == "nginx/1.22.1"
    assert h["Content-Type"] == route["content_type"]
    assert h["Content-Length"] == str(len(body))
    assert h["Last-Modified"] == http_date(profile.mtime)
    assert h["ETag"] == f'"{profile.mtime:x}-{len(body):x}"'
    assert re.fullmatch(r'"[0-9a-f]+-[0-9a-f]+"', h["ETag"])
    assert h["Accept-Ranges"] == "bytes" and h["Connection"] == "close"
    assert IMF.fullmatch(h["Date"])
    assert got == body

    data = await srv.talk(get("/", method="HEAD", extra=CLOSE))
    (resp,) = parse(data, heads=(0,))
    assert data.endswith(b"\r\n\r\n")
    assert [k for k, _ in resp[1]] == REF["head"]["header_order"]
    assert dict(resp[1])["Content-Length"] == str(len(body))


@pytest.mark.parametrize("path", ["/robots.txt", "/.env", "/.git/config"])
async def test_static_files(srv, path):
    route = srv.route(path)
    (resp,) = parse(await srv.talk(get(path, extra=CLOSE)))
    assert resp[0] == "HTTP/1.1 200 OK"
    assert dict(resp[1])["Content-Type"] == route["content_type"]
    assert resp[2] == route["body"].encode()
    assert [k for k, _ in resp[1]] == REF["index"]["header_order"]


async def test_keepalive_events_and_seq(srv):
    r, w = await asyncio.open_connection("127.0.0.1", srv.port)
    w.write(
        build_header("203.0.113.9", 40001, "10.0.0.5", 80)
        + get("/robots.txt", extra="User-Agent: probe/1\r\n")
    )
    first = await r.readuntil(b"\r\n\r\n")
    n = int(re.search(rb"Content-Length: (\d+)", first)[1])
    first += await r.readexactly(n)
    w.write(
        get("/nothing?url=http://169.254.169.254/", method="HEAD") + get("/robots.txt", extra=CLOSE)
    )
    rest = await r.read(-1)
    w.close()
    resps = parse(first) + parse(rest, heads=(0,))
    assert [x[0] for x in resps] == ["HTTP/1.1 200 OK", "HTTP/1.1 404 Not Found", "HTTP/1.1 200 OK"]
    assert [dict(x[1])["Connection"] for x in resps] == ["keep-alive", "keep-alive", "close"]
    assert resps[1][2] == b""

    ev = await srv.events()
    ids = [e["eventid"] for e in ev]
    assert ids == ["http.session.connect"] + ["http.policy.decision", "http.request"] * 3 + [
        "http.session.closed"
    ]
    assert len({e["session"] for e in ev}) == 1
    assert ev[0]["src_ip"] == "203.0.113.9" and ev[0]["sensor"] == "dep-test"
    decisions, requests = srv.of("http.policy.decision"), srv.of("http.request")
    assert [d["seq"] for d in decisions] == [r["seq"] for r in requests] == [1, 2, 3]
    assert [d["request_id"] for d in decisions] == [r["request_id"] for r in requests]
    assert [d["known"] for d in decisions] == [True, False, True]
    q = requests[1]
    assert (q["method"], q["path"], q["query"], q["status"], q["route"], q["outcome"]) == (
        "HEAD",
        "/nothing",
        "url=http://169.254.169.254/",
        404,
        None,
        "failure",
    )
    assert q["http_version"] == "1.1" and q["response_sha256"] == hashlib.sha256(b"").hexdigest()
    a = requests[0]
    assert (
        a["headers"] == [["Host", "localhost"], ["User-Agent", "probe/1"]]
        and a["user_agent"] == "probe/1"
    )
    assert a["route"] == "/robots.txt" and a["outcome"] == "success" and a["status"] == 200
    assert a["response_bytes"] == len(first) and a["body"] == {
        "size": 0,
        "sha256": hashlib.sha256(b"").hexdigest(),
        "text": "",
    }
    assert ev[-1]["inputs"] == 3


async def test_http10(srv):
    (resp,) = parse(await srv.talk(get("/", "1.0")))
    assert resp[0] == "HTTP/1.1 200 OK" and dict(resp[1])["Connection"] == "close"
    data = await srv.talk(
        get("/robots.txt", "1.0", "Connection: keep-alive\r\n") + get("/robots.txt", "1.0")
    )
    assert [dict(x[1])["Connection"] for x in parse(data)] == ["keep-alive", "close"]


async def test_http09_gets_the_body_alone(srv):
    assert (
        await srv.talk(b"GET /robots.txt\r\n", eof=False)
        == srv.route("/robots.txt")["body"].encode()
    )
    assert await srv.talk(b"POST /robots.txt\r\n", eof=False) == REF["400_garbage"]["body"].encode()


async def test_body_cap(srv):
    (resp,) = parse(
        await srv.talk(
            get("/x", method="POST", extra="Content-Length: 1048577\r\n") + b"a" * 1048577
        )
    )
    assert_like_reference(resp, "413")
    (resp,) = parse(
        await srv.talk(
            get("/x", method="POST", extra="Content-Length: 1048576\r\n" + CLOSE) + b"a" * 1048576
        )
    )
    assert resp[0] == "HTTP/1.1 404 Not Found"
    chunk = b"100000\r\n" + b"b" * 0x100000 + b"\r\n"
    (resp,) = parse(
        await srv.talk(
            get("/x", method="POST", extra="Transfer-Encoding: chunked\r\n")
            + chunk
            + chunk
            + b"0\r\n\r\n"
        )
    )
    assert resp[0] == "HTTP/1.1 413 Request Entity Too Large"
    reqs = srv.of("http.request")
    assert reqs[0]["status"] == 413 and reqs[0]["body"]["size"] == 0
    assert srv.of("http.policy.decision")[0]["input"] == "POST /x"


async def test_wp_login_captures_credentials(srv):
    route = srv.route("/wp-login.php")
    form = b"log=admin&pwd=hunter2%21&wp-submit=Log+In"
    extra = (
        f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(form)}\r\n{CLOSE}"
    )
    (resp,) = parse(await srv.talk(get("/wp-login.php", method="POST", extra=extra) + form))
    assert resp[0] == "HTTP/1.1 200 OK"
    # admin is one of the site's WordPress users, so WordPress names the password as wrong.
    assert resp[2] == route["post_bodies"]["known"].replace("{username}", "admin").encode()
    assert [k for k, _ in resp[1]] == REF["404"]["header_order"]  # a PHP page, not a file
    (resp,) = parse(await srv.talk(get("/wp-login.php", extra=CLOSE)))
    assert resp[2] == route["body"].encode()
    await srv.events(2)
    (login,) = srv.of("http.login.failed")
    assert (login["username"], login["password"], login["form"]) == (
        "admin",
        "hunter2!",
        "/wp-login.php",
    )
    assert login["seq"] == 1 and login["request_id"] == srv.of("http.request")[0]["request_id"]
    assert srv.of("http.request")[0]["body"]["text"] == form.decode()


@pytest.mark.parametrize(
    "garbage",
    [
        b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03",
        b"get / HTTP/1.1\r\n",
        b"GET foo HTTP/1.1\r\n",
        b"GET /../etc/passwd HTTP/1.1\r\n",
    ],
)
async def test_garbage_gets_400_at_once(srv, garbage):
    data = await srv.talk(garbage, eof=False, timeout=3)
    (resp,) = parse(data)
    assert_like_reference(resp, "400_garbage")
    (req,) = srv.of("http.request")
    assert (
        req["status"] == 400
        and req["seq"] == 1
        and req["raw"]["text"] == garbage.decode(errors="replace")
    )


@pytest.mark.parametrize(
    ("request_bytes", "status"),
    [
        (b"GET / HTTP/2.0\r\n\r\n", "HTTP/1.1 505 HTTP Version Not Supported"),
        (get("/", extra="Transfer-Encoding: gzip\r\n"), "HTTP/1.1 501 Not Implemented"),
        (get("/", extra="Content-Length: 1\r\nContent-Length: 1\r\n"), "HTTP/1.1 400 Bad Request"),
        (get("/", extra="Host: a\r\n"), "HTTP/1.1 400 Bad Request"),
        (b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\n", "HTTP/1.1 414 Request-URI Too Large"),
        (get("/", extra="X-Big: " + "a" * 9000 + "\r\n"), "HTTP/1.1 400 Bad Request"),
        (get("/", method="TRACE", extra=CLOSE), "HTTP/1.1 405 Not Allowed"),
        (get("/robots.txt", method="PUT", extra=CLOSE), "HTTP/1.1 405 Not Allowed"),
        (get("/nope", method="PUT", extra=CLOSE), "HTTP/1.1 404 Not Found"),
        (get("/server-status", method="DELETE", extra=CLOSE), "HTTP/1.1 403 Forbidden"),
        (get("/%2eenv", extra=CLOSE), "HTTP/1.1 200 OK"),
        (get("//robots.txt", extra=CLOSE), "HTTP/1.1 200 OK"),
        (get("/a/../robots.txt", extra=CLOSE), "HTTP/1.1 200 OK"),
        (get("/robots.txt%00", extra=CLOSE), "HTTP/1.1 400 Bad Request"),
        (get("/%zz", extra=CLOSE), "HTTP/1.1 400 Bad Request"),
        (
            b"GET http://other.example/robots.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK",
        ),
    ],
)
async def test_nginx_parsing_rules(srv, request_bytes, status):
    data = await srv.talk(request_bytes, timeout=3)
    assert parse(data)[0][0] == status


async def test_conditional_get_and_continue(srv, profile):
    body = srv.route("/robots.txt")["body"].encode()
    etag = f'"{profile.mtime:x}-{len(body):x}"'
    data = await srv.talk(get("/robots.txt", extra=f"If-None-Match: {etag}\r\n{CLOSE}"))
    (resp,) = parse(data)
    assert resp[0] == "HTTP/1.1 304 Not Modified" and data.endswith(b"\r\n\r\n")
    assert [k for k, _ in resp[1]] == ["Server", "Date", "Last-Modified", "Connection", "ETag"]
    data = await srv.talk(
        get("/robots.txt", extra=f"If-Modified-Since: {http_date(profile.mtime + 1)}\r\n{CLOSE}")
    )
    assert parse(data)[0][0] == "HTTP/1.1 200 OK"
    r, w = await asyncio.open_connection("127.0.0.1", srv.port)
    w.write(
        build_header("203.0.113.9", 1, "10.0.0.5", 80)
        + get("/x", method="POST", extra="Content-Length: 3\r\nExpect: 100-continue\r\n" + CLOSE)
    )
    assert await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 3) == b"HTTP/1.1 100 Continue\r\n\r\n"
    w.write(b"abc")
    assert (await r.read(-1)).startswith(b"HTTP/1.1 404 Not Found\r\n")
    w.close()


async def test_chrome_and_msie_get_padding(srv):
    for ua in (CHROME, "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)"):
        (resp,) = parse(await srv.talk(get("/nope", extra=f"User-Agent: {ua}\r\n{CLOSE}")))
        assert resp[2] == REF["404"]["body"].encode() + PADDING
        assert dict(resp[1])["Content-Length"] == str(len(resp[2]))
    (resp,) = parse(
        await srv.talk(
            get(
                "/nope",
                extra="User-Agent: Mozilla/5.0 (X11; rv:125.0) Gecko/20100101 Firefox/125.0\r\n"
                + CLOSE,
            )
        )
    )
    assert resp[2] == REF["404"]["body"].encode()


async def test_no_framework_tells(srv):
    reqs = [
        get("/", extra=CLOSE),
        get("/nope", extra=CLOSE),
        get("/server-status", extra=CLOSE),
        b"GARBAGE\r\n\r\n",
        b"GET / HTTP/1.1\r\n\r\n",
        get("/", method="POST", extra=CLOSE),
        get("/x", method="POST", extra="Content-Length: 99999999\r\n"),
        b"GET / HTTP/3.0\r\n\r\n",
        get("/", extra="Transfer-Encoding: x\r\n"),
        get("/", extra="Bad Header\r\n" + CLOSE),
        get("/", extra=f"User-Agent: {CHROME}\r\nContent-Length: zz\r\n"),
        b"\x00\x01\x02\r\n\r\n",
        get("/phpmyadmin", extra=CLOSE),
    ]
    for rb in reqs:
        data = await srv.talk(rb, timeout=3)
        assert data.startswith(b"HTTP/1.1 ")
        assert b"Server: nginx/1.22.1\r\n" in data
        assert not any(t in data.lower() for t in TELLS), data


@pytest.mark.parametrize(
    ("applied", "status", "body"),
    [
        (Applied(Action.FAKE_SUCCESS, output="<b>ok</b>"), "HTTP/1.1 200 OK", b"<b>ok</b>"),
        (
            Applied(Action.FAKE_ERROR, exit_code=503),
            "HTTP/1.1 503 Service Temporarily Unavailable",
            None,
        ),
        (
            Applied(Action.FAKE_ERROR, exit_code=404),
            "HTTP/1.1 404 Not Found",
            REF["404"]["body"].encode(),
        ),
        (Applied(Action.FAKE_ERROR, output="boom"), "HTTP/1.1 500 Internal Server Error", b"boom"),
        (
            Applied(Action.FAKE_ERROR, exit_code=200),
            "HTTP/1.1 400 Bad Request",
            REF["400_garbage"]["body"].encode(),
        ),
        (Applied(Action.DELAY, delay_ms=150), "HTTP/1.1 200 OK", None),
    ],
)
async def test_gate_actions(srv, applied, status, body):
    gate = FakeGate(applied)
    srv.decoy.gate = gate
    started = time.monotonic()
    (resp,) = parse(
        await srv.talk(get("/robots.txt?a=1", extra="User-Agent: t\r\nX-Other: y\r\n" + CLOSE))
    )
    assert resp[0] == status
    if body is not None:
        assert resp[2] == body
    if applied.action is Action.FAKE_SUCCESS:
        assert dict(resp[1])["Content-Type"] == "text/html"
    if applied.exit_code == 503:
        assert (
            resp[2]
            == b"<html>\r\n<head><title>503 Service Temporarily Unavailable</title></head>\r\n<body>\r\n<center><h1>503 Service Temporarily Unavailable</h1></center>\r\n<hr><center>nginx/1.22.1</center>\r\n</body>\r\n</html>\r\n"
        )
    if applied.action is Action.DELAY:
        assert time.monotonic() - started >= 0.15
        assert resp[2] == srv.route("/robots.txt")["body"].encode()
    (req,) = gate.reqs
    assert (req.method, req.path, req.query, req.known, req.seq) == (
        "GET",
        "/robots.txt",
        "a=1",
        True,
        1,
    )
    assert req.headers == {"host": "localhost", "user-agent": "t"}
    assert (
        req.body_len == 0
        and req.body_sha256 == hashlib.sha256(b"").hexdigest()
        and req.body_head == ""
    )
    (dec,) = srv.of("http.policy.decision")
    assert dec["action"] == applied.action.value and dec["fallback"] is False


async def test_terminate_closes_without_reply(srv):
    srv.decoy.gate = FakeGate(Applied(Action.TERMINATE))
    assert await srv.talk(get("/")) == b""
    await srv.events()
    (req,) = srv.of("http.request")
    assert req["status"] is None and req["response_bytes"] == 0


async def test_fallback_when_disabled(srv):
    (resp,) = parse(await srv.talk(get("/", extra=CLOSE)))
    assert resp[0] == "HTTP/1.1 200 OK"
    (dec,) = srv.of("http.policy.decision")
    assert (dec["action"], dec["fallback"], dec["fallback_reason"]) == ("allow", True, "disabled")


async def test_large_bodies_reach_the_artifact_store(srv):
    small, big = b"s" * 4096, bytes(range(256)) * 20  # 4 KiB inline, 5 KiB stored
    for body in (small, big):
        await srv.talk(
            get("/upload", method="POST", extra=f"Content-Length: {len(body)}\r\n{CLOSE}") + body
        )
    await srv.events(2)
    reqs = srv.of("http.request")
    assert reqs[0]["body"]["text"] == small.decode() and "head" not in reqs[0]["body"]
    digest = hashlib.sha256(big).hexdigest()
    assert (
        reqs[1]["body"]["size"] == len(big)
        and reqs[1]["body"]["sha256"] == digest
        and "text" not in reqs[1]["body"]
    )
    (art,) = srv.of("http.artifact")
    assert (art["sha256"], art["size"], art["kind"], art["stored"]) == (
        digest,
        len(big),
        "http.body",
        True,
    )
    assert (srv.art / digest).read_bytes() == big
    assert srv.of("http.policy.decision")[1]["input"] == "POST /upload"


async def post_form(srv, path: str, form: bytes):
    extra = (
        f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(form)}\r\n{CLOSE}"
    )
    (resp,) = parse(await srv.talk(get(path, method="POST", extra=extra) + form))
    return resp


async def test_wp_login_names_an_unknown_user_and_escapes_it(srv):
    route = srv.route("/wp-login.php")
    resp = await post_form(srv, "/wp-login.php", b"log=%3Cscript%3Ex%3C%2Fscript%3E&pwd=x")
    body = resp[2].decode()
    assert "is not registered on this site" in body
    assert "&lt;script&gt;x&lt;/script&gt;" in body and "<script>x" not in body
    empty = await post_form(srv, "/wp-login.php", b"log=&pwd=")
    assert empty[2] == route["post_bodies"]["empty"].encode()


async def test_wp_admin_redirects_to_the_login_like_php(srv):
    (resp,) = parse(await srv.talk(get("/wp-admin/", extra=CLOSE)))
    assert resp[0] == "HTTP/1.1 302 Moved Temporarily"
    headers = dict(resp[1])
    assert headers["Location"].endswith(
        "/wp-login.php?redirect_to=http%3A%2F%2Flocalhost%2Fwp-admin%2F&reauth=1"
    )
    assert resp[2] == b"" and "ETag" not in headers


async def test_post_replies_carry_no_file_metadata(srv):
    resp = await post_form(srv, "/contact/", b"your-name=a&your-email=a%40b.c&your-message=hi")
    assert resp[0] == "HTTP/1.1 200 OK" and b"Thank you for your message" in resp[2]
    assert "ETag" not in dict(resp[1]) and "Last-Modified" not in dict(resp[1])
    (page,) = parse(await srv.talk(get("/contact/", extra=CLOSE)))
    assert "ETag" in dict(page[1])  # the page itself is a cached file


async def test_phpmyadmin_form_posts_where_its_action_points(srv):
    page = (await srv.talk(get("/phpmyadmin/", extra=CLOSE))).decode()
    assert 'action="index.php?route=/"' in page
    resp = await post_form(
        srv, "/phpmyadmin/index.php?route=/", b"pma_username=root&pma_password=x&server=1"
    )
    assert b"Access denied for user 'root'@'localhost'" in resp[2]
    await srv.events(2)
    assert srv.of("http.login.failed")[0]["form"] == "/phpmyadmin/index.php"
