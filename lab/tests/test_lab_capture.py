"""A step can capture a value from the decoy's answer and a later login can use it (gap
register M9).

Demo 2's attacker reads a web file holding a planted database credential and then logs in to
the database "with it". The runner used to take that password from the profile on disk, so the
login succeeded whatever the decoy had answered. Now the actor has only what it read.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from test_lab import CATALOGUE, ROOT, Scripted, drive, scenario, steps_of

from mirage_lab.drivers.base import AuthPhase, LoginResult
from mirage_lab.drivers.plain import MySQLDriver
from mirage_lab.models import Capture, Scenario, lint, load_split
from mirage_lab.runner import ActorRun, Settings
from mirage_lab.slots import Slots
from mirage_lab.truth import TruthWriter

SECRET = "Harbour7731xQwZ"  # stands in for the planted credential; the profile's is secret-pw
ENV = f"APP_ENV=production\nDB_USERNAME=app\nDB_PASSWORD={SECRET}\nREDIS_PORT=6379\n"

TWO = """
id: test-capture
actor: {class: scripted_bot, timing: bot-fast, patience: 4}
sessions:
  - protocol: ssh
    channel: exec
    login: {user: root}
    steps:
      - id: a
        procedure: sysinfo-uname-all
        capture: {name: db_password, regex: '(?m)^DB_PASSWORD=([^\\r\\n]+)'}
      - {id: b, procedure: owner-id}
  - protocol: ssh
    channel: exec
    source: 2
    login: {user: root, procedure: ssh-password-guessing, password_from: db_password}
    steps:
      - {id: c, procedure: owner-id}
"""


class Door(Scripted):
    """Lets in whoever knows the profile's password or the planted one; remembers which it
    was built with."""

    def __init__(self, dialer, timing, fingerprint, user, password, channel):
        super().__init__(dialer, timing, fingerprint, user, password, channel)
        self.password = password

    def login(self, guesses):
        ok = self.password in ("secret-pw", SECRET)
        t = self.conn.opened
        return LoginResult(ok, [AuthPhase(self.conn, t, t, guesses + 1, ok)])


def door(env: str):
    made: list[Door] = []

    def factory(*args):
        made.append(type("D", (Door,), {"answers": {r"^uname": (env, 0)}})(*args))
        return made[-1]

    return factory, made


def problems(doc: str) -> str:
    return " | ".join(lint(scenario(doc), CATALOGUE, Slots.names()))


# ------------------------------------------------------------------ the model and the lint


def test_a_capture_regex_has_exactly_one_group():
    assert Capture(name="pw", regex="KEY=(.+)").regex == "KEY=(.+)"
    for bad in ("KEY=.+", "(KEY)=(.+)"):
        with pytest.raises(ValidationError, match="exactly one group"):
            Capture(name="pw", regex=bad)
    with pytest.raises(ValidationError):
        Capture(name="Not A Name", regex="(x)")
    with pytest.raises(ValidationError):
        Capture(name="pw", regex="(unclosed")


def test_lint_ties_password_from_to_an_earlier_capture():
    assert problems(TWO) == ""
    assert "no earlier session captures" in problems(
        TWO.replace("password_from: db_password", "password_from: other")
    )
    # a login happens before its own session's steps, so a capture in that session is too late
    same = TWO.replace(
        "    login: {user: root}\n", "    login: {user: root, password_from: db_password}\n"
    )
    assert "no earlier session captures" in problems(same)
    twice = TWO.replace(
        "{id: b, procedure: owner-id}",
        "{id: b, procedure: owner-id, capture: {name: db_password, regex: '(x)'}}",
    )
    assert "already used" in problems(twice)
    upload = TWO.replace(
        "{id: b, procedure: owner-id}",
        "{id: b, procedure: transfer-sftp-put, capture: {name: other, regex: '(x)'}}",
    )
    assert "no output to capture from" in problems(upload)
    web = """
id: test-capture-web
actor: {class: scanner, timing: scan}
sessions:
  - protocol: ssh
    channel: exec
    actor: {class: scripted_bot, timing: bot-fast}
    steps:
      - {id: a, procedure: sysinfo-uname-all, capture: {name: pw, regex: '(x)'}}
  - protocol: http
    login: {password_from: pw}
    steps:
      - {id: w, procedure: web-get-index}
"""
    assert "only SSH and MySQL sessions log in with a password" in problems(web)


# ------------------------------------------------------------------ the runner


def test_a_later_login_uses_the_captured_value_not_the_profile(tmp_path):
    factory, made = door(ENV)
    records, actor, raised = drive(tmp_path, factory, doc=TWO)
    assert raised is None
    assert [d.password for d in made] == ["secret-pw", SECRET]  # profile, then what was read
    got = steps_of(records)
    assert got["a"] == ("ran", "ok")  # a capture that matched is a check that passed
    assert got["login-0"] == ("ran", "ok") and got["c"][0] == "ran"
    assert actor.captured == {"db_password": SECRET}
    # the value is the actor's alone: it is not in the ground truth
    assert SECRET not in (tmp_path / "gt.json").read_text()


def test_a_missed_capture_fails_the_step_and_the_login_gets_an_empty_password(tmp_path):
    # The decoy withheld the file. The actor has nothing, so it must not log in as if it had.
    factory, made = door("403 Forbidden\n")
    records, actor, raised = drive(tmp_path, factory, doc=TWO)
    assert raised is None
    assert [d.password for d in made] == ["secret-pw", ""]  # empty, never the profile's
    got = steps_of(records)
    assert got["a"] == ("ran", "failed")  # the step's outcome records the miss
    assert got["b"][0] == "ran"  # on_fail: continue, as for any failed check
    assert got["login-0"] == ("ran", "failed")  # the attempt was made, and it failed
    assert got["c"] == ("skipped", "unchecked")
    assert actor.captured == {}
    assert len([r for r in records if r["kind"] == "session"]) == 2


def test_a_missed_capture_obeys_on_fail(tmp_path):
    leave = TWO.replace(
        "regex: '(?m)^DB_PASSWORD=([^\\r\\n]+)'}",
        "regex: '(?m)^DB_PASSWORD=([^\\r\\n]+)'}\n        on_fail: leave",
    )
    factory, _made = door("nothing here\n")
    records, _actor, _raised = drive(tmp_path, factory, doc=leave)
    got = steps_of(records)
    assert got["a"] == ("ran", "failed") and got["b"] == ("skipped", "unchecked")


def test_a_mysql_login_with_password_from_never_reads_the_profile(tmp_path):
    doc = TWO.replace(
        "  - protocol: ssh\n    channel: exec\n    source: 2\n    login: {user: root, procedure: ssh-password-guessing, password_from: db_password}\n    steps:\n      - {id: c, procedure: owner-id}\n",
        "  - protocol: mysql\n    source: 2\n    login: {user: wp_user, procedure: mysql-login, password_from: db_password}\n    steps:\n      - {id: c, procedure: valid-mysql-session}\n",
    )
    sc = scenario(doc)
    assert lint(sc, CATALOGUE, Slots.names()) == []
    assert sc.sessions[1].protocol == "mysql"
    settings = Settings(target_ip="172.26.0.2", out_dir=tmp_path, profile_dir=tmp_path / "absent")
    truth = TruthWriter(tmp_path / "gt")
    actor = ActorRun(sc, 0, "198.18.0.9", "r1", CATALOGUE, settings, truth)
    truth.close()
    # there is no profile to fall back to: an uncaptured name is an empty password, not a lookup
    driver = actor._make_driver(sc.sessions[1])
    assert isinstance(driver, MySQLDriver) and driver.password == ""
    actor.captured["db_password"] = SECRET
    assert actor._make_driver(sc.sessions[1]).password == SECRET
    # without password_from the profile is still where the password comes from
    plain = sc.sessions[1].model_copy(
        update={"login": sc.sessions[1].login.model_copy(update={"password_from": None})}
    )
    with pytest.raises(FileNotFoundError):
        actor._make_driver(plain)


# ------------------------------------------------------------------ demo 2


DEMO2 = ROOT / "lab/scenarios/demo/demo-2-web-cred-mysql.yaml"


def test_demo_2_logs_in_with_what_it_read():
    sc = Scenario.load(DEMO2)
    split = load_split(ROOT / "eval/split.yaml")
    assert lint(sc, CATALOGUE, Slots.names(), split.procedures, split.scenarios) == []
    web, db = sc.sessions
    (capturing,) = [s for s in web.steps if s.capture]
    assert capturing.procedure == "creds-http-env"
    assert db.protocol == "mysql" and db.login.password_from == capturing.capture.name


@pytest.mark.parametrize("eol", ["\n", "\r\n"])
def test_demo_2_s_regex_reads_the_password_line_of_an_env_file(eol):
    regex = Scenario.load(DEMO2).sessions[0].steps[-1].capture.regex
    head = "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 99\r\n\r\n"
    body = ENV.replace("\n", eol)
    assert re.search(regex, head + body).group(1) == SECRET
    # the user name's line, a commented line and another key that ends the same are not it
    for other in (f"DB_USERNAME=app{eol}", f"#DB_PASSWORD=x{eol}", f"OLD_DB_PASSWORD=x{eol}"):
        assert re.search(regex, head + other) is None


def test_the_profile_generator_still_writes_the_key_the_regex_reads():
    # The key name is the profile generator's; if it changes there, the capture goes blind.
    source = (ROOT / "decoys/profiles/src/mirage_profiles/generator.py").read_text()
    regex = yaml.safe_load(Path(DEMO2).read_text())["sessions"][0]["steps"][-1]["capture"]["regex"]
    key = re.search(r"\^(\w+)=", regex).group(1)
    assert key == "DB_PASSWORD" and f"{key}=" in source
