"""An explored fake_error looks like an error of its protocol (spec 2.5, the fake-error table)."""

from __future__ import annotations

import copy
import json
import random
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from mirage_policy.app import RULES_DIR, Settings, create_app
from mirage_policy.explore import BanditPolicy, allowed_actions
from mirage_policy.fake_errors import FakeErrors
from mirage_policy.verbs import verb_class
from mirage_schema.policy import Action, DecideRequest

TOKEN = "t" * 32
EXPLORE_IP = "198.19.0.7"
TABLE = RULES_DIR / "fake_errors.yaml"

APT = (
    "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1187"
    " (unattended-upgr)\n"
    "N: Be aware that removing the lock file is not a solution and may break your system.\n"
    "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend),"
    " is another process using it?\n"
)


def ssh(*argv: str, **over) -> dict:
    return {"protocol": "ssh", "argv": list(argv), **over}


def http(method: str | None) -> dict:
    return {"protocol": "http", "method": method, "path": "/wp-login.php"}


def redis(*argv: str) -> dict:
    return {"protocol": "redis", "argv": list(argv)}


def mysql(sql: str | None, command: str = "COM_QUERY") -> dict:
    return {"protocol": "mysql", "command": command, "sql": sql}


def render(body: dict) -> tuple[str, int | None]:
    req = DecideRequest.model_validate({"request_id": "r", **body})
    return FakeErrors.load(TABLE).render(req, verb_class(req))


# ------------------------------------------------------------------ the table's answers

CASES = [
    # a shell: one stderr line and an exit status, by verb, then verb class, then the default
    (ssh("cat", "/etc/passwd"), "cat: /etc/passwd: Input/output error\n", 1),
    (ssh("/bin/cat", "notes"), "/bin/cat: notes: Input/output error\n", 1),  # named as typed
    (ssh("LANG=C", "cat", "notes"), "cat: notes: Input/output error\n", 1),  # not the assignment
    (ssh("grep", "-ri", "password", "/var/www"), "grep: /var/www: Input/output error\n", 1),
    (ssh("ls", "-la", "/root"), "ls: cannot access '/root': Input/output error\n", 2),
    (ssh("rm", "-rf", "/tmp/x"), "rm: cannot remove '/tmp/x': Operation not permitted\n", 1),
    (
        ssh("chmod", "+x", "/tmp/m"),
        "chmod: changing permissions of '/tmp/m': Operation not permitted\n",
        1,
    ),
    (
        ssh("mkdir", "-p", "/opt/.c"),
        "mkdir: cannot create directory '/opt/.c': Operation not permitted\n",
        1,
    ),
    (ssh("touch", "/tmp/t"), "touch: cannot touch '/tmp/t': Operation not permitted\n", 1),
    (ssh("cp", "a", "/usr/bin/b"), "cp: /usr/bin/b: Operation not permitted\n", 1),
    (ssh("wget", "http://198.51.100.7/x.sh"), "wget: connect: Network is unreachable\n", 2),
    (ssh("ping", "-c", "1", "198.51.100.7"), "ping: connect: Network is unreachable\n", 2),
    (ssh("curl", "-s", "http://198.51.100.7/"), "curl: (7) Couldn't connect to server\n", 7),
    (ssh("apt-get", "install", "-y", "nmap"), APT, 100),
    (ssh("apt", "update"), APT, 100),
    (ssh("cd", "/srv/data"), "-bash: cd: /srv/data: Input/output error\n", 1),
    (
        ssh("cd", "/srv/data", interactive=False),
        "bash: line 1: cd: /srv/data: Input/output error\n",
        1,
    ),
    (ssh("echo", "hi"), "-bash: echo: write error: Input/output error\n", 1),
    # nothing more specific: the default
    (ssh("uname", "-a"), "Segmentation fault\n", 139),
    (ssh("frobnicate", "--now"), "Segmentation fault\n", 139),
    (ssh("cat"), "Segmentation fault\n", 139),  # the class's line needs a file to name
    (ssh("ls", "-la"), "Segmentation fault\n", 139),
    (ssh(), "Segmentation fault\n", 139),
    # http: a status, and no body, so the decoy sends its profile's own nginx page for it
    (http("GET"), "", 503),
    (http("HEAD"), "", 503),
    (http("POST"), "", 502),
    (http("PROPFIND"), "", 405),
    (http(None), "", 405),
    # redis: the text after "ERR " (the decoy adds that itself), and no code
    (redis("GET", "k"), "wrong number of arguments for 'get' command", None),
    (redis("config", "get", "dir"), "wrong number of arguments for 'config' command", None),
    (redis("FOO", "bar"), "wrong number of arguments for 'foo' command", None),
    (redis("BGSAVE"), "Background save already in progress", None),
    (redis("save"), "Background save already in progress", None),
    # mysql: a MariaDB error number that is SQLSTATE HY000, and its message
    (
        mysql("SELECT * FROM customers"),
        "Table definition has changed, please retry transaction",
        1412,
    ),
    (mysql("show databases"), "Table definition has changed, please retry transaction", 1412),
    (
        mysql("INSERT INTO t VALUES (1)"),
        "Lock wait timeout exceeded; try restarting transaction",
        1205,
    ),
    (mysql("DROP TABLE users"), "Lock wait timeout exceeded; try restarting transaction", 1205),
    (mysql("GRANT ALL ON *.* TO x"), "Unknown error", 1105),
    (mysql(None, command="COM_PING"), "Unknown error", 1105),
]


@pytest.mark.parametrize(("body", "output", "exit_code"), CASES)
def test_the_table_answers_in_the_protocols_own_words(body, output, exit_code):
    assert render(body) == (output, exit_code)


def test_every_answer_is_something_its_decoy_can_send():
    # What each decoy does with the two fields (the handlers cited in fake_errors.yaml).
    for body, _, _ in CASES:
        output, code = render(body)
        if body["protocol"] == "ssh":  # stderr as written, then $?
            assert output.endswith("\n") and 1 <= code <= 255
        elif body["protocol"] == "http":  # handler.py clamps the status to 400..599
            assert 400 <= code <= 599 and min(max(code, 400), 599) == code
        elif body["protocol"] == "redis":  # handler.py: Error(b"ERR " + output.strip())
            assert code is None and output and output == output.strip()
            assert "\n" not in output and not output.startswith("ERR")
        else:  # proto.py err_packet: a two-byte code, then the message
            assert output and code.to_bytes(2, "little") and "\n" not in output


def test_no_protocol_answers_with_the_old_empty_exit_1():
    for body, _, _ in CASES:
        output, code = render(body)
        assert (output, code) != ("", 1)
        assert output or body["protocol"] == "http"  # only http leaves the body to the decoy


# ------------------------------------------------------------------ a bad table


def _broken(tmp_path: Path, change) -> Path:
    data = copy.deepcopy(yaml.safe_load(TABLE.read_text()))
    change(data)
    path = tmp_path / "fake_errors.yaml"
    path.write_text(yaml.safe_dump(data))
    return path


def _set(*keys_and_value):
    *keys, last, value = keys_and_value

    def change(data: dict) -> None:
        node = data
        for k in keys:
            node = node.setdefault(k, {})
        node[last] = value

    return change


@pytest.mark.parametrize(
    "change",
    [
        _set("http", "default", {"exit_code": 200}),  # not an error status
        _set("http", "default", {"output": "nope"}),  # no status at all
        _set("http", "classes", "read", {"output": "{arg}", "exit_code": 404}),  # ssh-only
        _set("redis", "default", {"output": "ERR syntax error"}),  # the decoy adds ERR
        _set("redis", "default", {"output": "syntax error", "exit_code": 1}),  # no code in RESP
        _set("redis", "default", {"output": "two\nlines"}),
        _set("redis", "verbs", "save", {"output": "busy"}),  # would never match SAVE
        _set("mysql", "default", {"output": "Unknown error", "exit_code": 70000}),  # two bytes
        _set("mysql", "default", {"output": "", "exit_code": 1105}),  # an error has a message
        _set("ssh", "default", {"output": "Killed", "exit_code": 137}),  # no newline
        _set("ssh", "default", {"output": "Killed\n", "exit_code": 0}),  # an error exits non-zero
        _set("ssh", "default", {"output": "{verb}: {arg}: gone\n", "exit_code": 1}),  # no arg
        _set("ssh", "classes", "file_read", {"output": "{file}: gone\n", "exit_code": 1}),
        _set("ssh", "classes", "filesystem", {"output": "gone\n", "exit_code": 1}),  # no class
        _set("ssh", "default", {"output": "x\n", "exit_code": 1, "sqlstate": "HY000"}),
        lambda data: data.pop("mysql"),  # every protocol needs a default
        _set("version", 2),
    ],
)
def test_a_table_that_does_not_fit_the_decoys_is_refused_at_load(tmp_path, change):
    with pytest.raises(ValueError):
        FakeErrors.load(_broken(tmp_path, change))


def test_the_table_version_follows_its_content(tmp_path):
    a = FakeErrors.load(TABLE).version
    b = FakeErrors.load(_broken(tmp_path, _set("http", "default", {"exit_code": 504}))).version
    assert len(a) == 12 and a != b


def test_a_bad_table_stops_the_service_from_starting(tmp_path):
    bad = _broken(tmp_path, _set("http", "default", {"exit_code": 200}))
    settings = Settings(
        token=TOKEN,
        log_path=tmp_path / "d.json",
        rule_files=[RULES_DIR / "default.yaml"],
        fake_errors=bad,
    )
    with pytest.raises(ValueError):
        create_app(settings)


# ------------------------------------------------------------------ the service


def service(tmp_path: Path, monkeypatch, selftest: bool = False, seed: int = 7):
    monkeypatch.setenv("POLICY_EXPLORE", "lab")
    monkeypatch.delenv("POLICY_TECHNIQUE_RULES", raising=False)
    files = ([RULES_DIR / "selftest.yaml"] if selftest else []) + [RULES_DIR / "default.yaml"]
    log = tmp_path / "decisions.json"
    settings = Settings(token=TOKEN, log_path=log, rule_files=files)
    return TestClient(create_app(settings, rng=random.Random(seed))), log


def post(c: TestClient, body: dict, i: int, ip: str = EXPLORE_IP) -> dict:
    body = {"request_id": f"r{i}", "session_id": f"s{i}", "seq": 2, "src": {"ip": ip}, **body}
    r = c.post("/v1/decide", json=body, headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200, r.text
    return r.json()


def records(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text().splitlines()]


@pytest.mark.parametrize(
    ("body", "output", "exit_code"),
    [
        (ssh("cat", "/etc/passwd"), "cat: /etc/passwd: Input/output error\n", 1),
        (http("GET"), "", 503),
        (redis("KEYS", "*"), "wrong number of arguments for 'keys' command", None),
        (mysql("SELECT 1"), "Table definition has changed, please retry transaction", 1412),
    ],
)
def test_an_explored_fake_error_is_rendered_from_the_table(
    tmp_path, monkeypatch, body, output, exit_code
):
    c, log = service(tmp_path, monkeypatch)
    sent = [post(c, body, i) for i in range(300)]
    errors = [d for d in sent if d["action"] == "fake_error"]
    assert errors, "300 explored decisions should include a fake_error"
    for d in errors:
        assert d["output"] == output and d.get("exit_code") == exit_code
    for r in records(log):
        if r["action"] == "fake_error":
            assert r["output"] == output and r.get("exit_code") == exit_code
            assert r["acting"]["fake_errors_version"] == FakeErrors.load(TABLE).version
        else:  # no other action borrows the table
            assert r["output"] == "" and "exit_code" not in r


def test_the_table_changes_the_rendering_not_the_choice_or_its_probability(tmp_path, monkeypatch):
    # The service must draw exactly what the exploring policy alone draws from the same seed,
    # and log exactly its probability: the table is consulted after the choice is made.
    c, log = service(tmp_path, monkeypatch, seed=11)
    body = ssh("cat", "/etc/passwd")
    for i in range(500):
        post(c, body, i)
    policy, rng = BanditPolicy(), random.Random(11)
    allowed = allowed_actions(DecideRequest.model_validate({"request_id": "r", "seq": 2, **body}))
    want = [policy.sample(allowed, Action.ALLOW, rng) for _ in range(500)]
    got = records(log)
    assert [r["action"] for r in got] == [w.action.value for w in want]
    assert [r["propensity"] for r in got] == [w.propensity for w in want]
    assert all(r["acting"]["probs"] == w.probs for r, w in zip(got, want, strict=True))


def test_a_rules_own_fake_error_keeps_the_rules_output(tmp_path, monkeypatch):
    # selftest-fake-error says "selftest failed" with exit code 2. When the exploring policy
    # lands on the rule's own action it is the rule's answer that goes out, not the table's.
    c, _ = service(tmp_path, monkeypatch, selftest=True)
    sent = [post(c, ssh("mirage-selftest-fake-error"), i) for i in range(200)]
    errors = [d for d in sent if d["action"] == "fake_error"]
    assert len(errors) > 100  # the rule's action is the favoured one
    assert all((d["output"], d["exit_code"]) == ("selftest failed\n", 2) for d in errors)


def test_outside_the_explore_range_the_table_is_never_used(tmp_path, monkeypatch):
    c, log = service(tmp_path, monkeypatch, selftest=True)
    d = post(c, ssh("mirage-selftest-fake-error"), 0, ip="203.0.113.9")
    assert (d["action"], d["output"], d["exit_code"]) == ("fake_error", "selftest failed\n", 2)
    d = post(c, ssh("cat", "/etc/passwd"), 1, ip="203.0.113.9")
    assert d["action"] == "allow" and d["output"] == ""
    assert all("fake_errors_version" not in r["acting"] for r in records(log))
