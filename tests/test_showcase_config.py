"""The public showcase is the one deliberate way anything here is reachable from the
internet. These are the properties that make that acceptable, checked on the compose file,
the proxy's configuration, the console's scripts and the store's user file, so a later edit
cannot quietly remove one."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((ROOT / "compose" / "docker-compose.yml").read_text())
SERVICES, NETWORKS = COMPOSE["services"], COMPOSE["networks"]
PUBLIC, TUNNEL = SERVICES["grafana-public"], SERVICES["showcase-tunnel"]
CONSOLE, PROXY = SERVICES["showcase-console"], SERVICES["showcase-proxy"]
PROXY_CFG = (ROOT / "compose" / "showcase" / "haproxy.cfg").read_text()
ENTRYPOINT = (ROOT / "lab" / "console" / "entrypoint.sh").read_text()
SESSION = (ROOT / "lab" / "console" / "session.sh").read_text()
DOCKERFILE = (ROOT / "lab" / "console" / "Dockerfile").read_text()
# Everything an attacker would want that the showcase must not share a network with.
ELSEWHERE = (
    "cowrie",
    "http-decoy",
    "redis-decoy",
    "mysql-decoy",
    "policy",
    "edge",
    "runner",
    "nats",
    "grafana",
    "arm-r",
)


def members(network: str) -> set[str]:
    return {name for name, svc in SERVICES.items() if network in (svc.get("networks") or [])}


def rules(text: str) -> list[str]:
    """A configuration's lines without comments and blank lines."""
    return [
        ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")
    ]


def test_the_showcase_is_never_started_by_the_stack():
    for svc in (PUBLIC, TUNNEL, CONSOLE, PROXY):
        assert svc["profiles"] == ["showcase"]
        assert svc["restart"] == "no"  # it does not come back by itself after a reboot


def test_the_tunnel_can_reach_the_proxy_and_nothing_else():
    assert members("showcase") == {"showcase-proxy", "showcase-tunnel"}
    assert TUNNEL["networks"] == ["showcase"]
    assert TUNNEL["command"][-2:] == ["--url", "http://showcase-proxy:8080"]
    assert "ports" not in TUNNEL  # outbound only: it opens nothing on this machine


def test_behind_the_proxy_are_the_dashboards_and_the_console_and_nothing_else():
    assert members("showcase-inner") == {"showcase-proxy", "grafana-public", "showcase-console"}
    assert NETWORKS["showcase-inner"]["internal"] is True
    for name in ELSEWHERE:
        nets = SERVICES[name].get("networks") or []
        assert "showcase" not in nets and "showcase-inner" not in nets, name
    assert PROXY["networks"] == ["showcase", "showcase-inner"]
    # The one port the showcase has on this machine is the proxy's, on loopback.
    assert all(str(p).startswith("127.0.0.1:") for p in PROXY["ports"])
    assert "ports" not in PUBLIC and "ports" not in CONSOLE
    lines = rules(PROXY_CFG)
    assert "default_backend dashboards" in lines and "use_backend console if to_console" in lines
    servers = [ln.split()[2] for ln in lines if ln.startswith("server ")]
    assert servers == ["grafana-public:3000", "showcase-console:7681"]


def test_the_console_is_asked_for_only_with_its_password():
    lines = rules(PROXY_CFG)
    assert "acl to_console path_beg /console/" in lines
    assert "acl signed_in http_auth(console)" in lines
    ask = 'http-request auth realm "MIRAGE console" if to_console !signed_in !has_ticket'
    assert ask in lines
    # A request is refused at the proxy before the choice of backend is made.
    assert lines.index(ask) < lines.index("use_backend console if to_console")
    # The one thing accepted in place of the password is the ticket a signed-in browser was
    # handed: a hash of the password, compared in constant time, in a cookie that scripts
    # cannot read and that is not sent on another site's request.
    assert "acl has_ticket req.cook(mirage_console),secure_memcmp(txn.ticket)" in lines
    (made,) = [ln for ln in lines if ln.startswith("http-request set-var(txn.ticket) ")]
    assert made.endswith(
        'env(CONSOLE_PASSWORD),concat(":mirage-console-ticket"),sha2(256),hex,lower'
    )
    assert "http-request set-var(txn.hand_ticket) bool(true) if to_console signed_in" in lines
    # The console wants the password on every request. It is added for a request whose
    # ticket was checked, and under no other condition.
    added = [ln for ln in lines if ln.startswith("http-request set-header Authorization")]
    assert added == [
        'http-request set-header Authorization "Basic %[var(txn.basic)]" '
        "if to_console has_ticket !signed_in"
    ]
    assert lines.index(ask) < lines.index(added[0])
    cookies = [ln for ln in lines if "Set-Cookie" in ln]
    assert len(cookies) == 2 and sum("; Secure" in ln for ln in cookies) == 1
    for ln in cookies:
        assert "Path=/console/; " in ln and "HttpOnly; SameSite=Strict" in ln
        assert "if { var(txn.hand_ticket) -m bool }" in ln
    # Guesses are counted and slowed.
    assert "http-request sc-inc-gpc0(0) if to_console has_login !signed_in" in lines
    assert any(ln.startswith("http-request deny deny_status 429 if to_console") for ln in lines)
    # The proxy will not start with no password or an empty one: the console would be open.
    assert ".if !defined(CONSOLE_PASSWORD)" in lines
    assert '.if streq("${CONSOLE_PASSWORD}","")' in lines
    assert sum(ln.startswith(".alert ") for ln in lines) == 2
    # The password never reaches Grafana, which takes no logins.
    backend = lines[lines.index("backend dashboards") : lines.index("backend console")]
    assert "http-request del-header Authorization" in backend
    assert "http-request del-header Cookie" in lines[lines.index("backend console") :]
    # Both programs get it from the same secret, and compose refuses to start without it.
    wanted = "${SHOWCASE_CONSOLE_PASSWORD:?run make env}"
    assert PROXY["environment"]["CONSOLE_PASSWORD"] == wanted
    assert CONSOLE["environment"]["CONSOLE_PASSWORD"] == wanted
    # And the console checks it again itself, refusing a weak one.
    assert '--credential "$credential"' in ENTRYPOINT and "--check-origin" in ENTRYPOINT
    assert 'if [ "${#CONSOLE_PASSWORD}" -lt 24 ]' in ENTRYPOINT
    assert ENTRYPOINT.index("unset CONSOLE_PASSWORD") < ENTRYPOINT.index("exec ttyd")


def test_the_console_reaches_the_lab_edge_and_the_proxy_and_nothing_else():
    assert CONSOLE["networks"] == ["lab", "showcase-inner"]
    # Neither of its networks has a way out, or an address on this machine: the console
    # cannot reach the lab host's own services (its SSH port) through a gateway address.
    for name in CONSOLE["networks"]:
        assert NETWORKS[name]["internal"] is True, name
        mode = NETWORKS[name]["driver_opts"]["com.docker.network.bridge.gateway_mode_ipv4"]
        assert mode == "isolated", name
    assert members("lab") <= {
        "lab-edge",
        "runner",
        "sim-join",
        "showcase-console",
        "arm-r-edge",
    } | {"arm-a-edge"} | {
        # The fingerprint suite (make probe), there only while it runs: a client with no
        # listening port, and the way in to a second emulated decoy that nothing reads.
        "probe",
        "fleet-edge",
    }
    env = CONSOLE["environment"]
    assert env["LAB_TARGET"] == "lab-edge"
    assert env["LAB_SIDE_NETWORKS"] == "1"
    assert env["LAB_RECORD_SCENARIO"] == "showcase-visitor"
    assert 0 < int(env["LAB_RECORD_MAX_S"]) <= 1800
    assert 0 < int(env["CONSOLE_MAX_CLIENTS"]) <= 5 and 0 < int(env["CONSOLE_MAX_SESSIONS"]) <= 1000
    # The exception to "exactly one network" is the console's alone.
    assert "LAB_SIDE_NETWORKS" not in SERVICES["runner"]["environment"]
    # It is held like every other service, and can write to the lab's records only.
    assert CONSOLE["cap_drop"] == ["ALL"] and CONSOLE["read_only"] is True
    assert CONSOLE["security_opt"] == ["no-new-privileges:true"]
    assert CONSOLE["mem_limit"] and CONSOLE["pids_limit"] and CONSOLE["cpus"]
    writable = [v for v in CONSOLE["volumes"] if not str(v).endswith(":ro")]
    assert writable == ["lab-out:/var/lib/mirage-lab"]


def test_the_console_runs_the_recorder_and_nothing_else():
    assert rules(ENTRYPOINT)[-1] == "/usr/local/bin/console-session"
    assert rules(SESSION)[-1] == "exec mirage-lab record --user root"
    # Before anything listens, the recorder's own isolation check.
    assert ENTRYPOINT.index("mirage-lab check") < ENTRYPOINT.index("exec ttyd")
    # No file transfer through the terminal, and no shell of the container's own.
    for off in ("enableZmodem", "enableTrzsz", "/bin/bash", "/bin/sh -"):
        assert off not in ENTRYPOINT + SESSION
    # The visitor is told, before the shell, that the session is recorded and shown.
    assert "recorded and shown on the public dashboards" in SESSION
    # The terminal server is a pinned release, checked by its hash when the image is built.
    assert re.search(r"ADD --checksum=sha256:[0-9a-f]{64} \\\n", DOCKERFILE)
    assert "/releases/download/1.7.7/ttyd.x86_64 /usr/local/bin/ttyd" in DOCKERFILE
    assert rules(DOCKERFILE)[-2:] == [
        "USER 10001:10001",
        'ENTRYPOINT ["/usr/local/bin/console-entrypoint"]',
    ]


def test_nobody_can_sign_in_to_the_dashboards_and_every_visitor_only_reads():
    env = PUBLIC["environment"]
    assert (
        env["GF_AUTH_ANONYMOUS_ENABLED"] == "true" and env["GF_AUTH_ANONYMOUS_ORG_ROLE"] == "Viewer"
    )
    assert env["GF_AUTH_DISABLE_LOGIN_FORM"] == "true" and env["GF_AUTH_BASIC_ENABLED"] == "false"
    assert env["GF_USERS_ALLOW_SIGN_UP"] == "false" and env["GF_USERS_VIEWERS_CAN_EDIT"] == "false"
    assert env["GF_EXPLORE_ENABLED"] == "false" and env["GF_SNAPSHOTS_ENABLED"] == "false"
    # It is a different Grafana from the real one, with its own secrets and no kept state.
    real = SERVICES["grafana"]["environment"]
    assert env["GF_SECURITY_ADMIN_PASSWORD"] != real["GF_SECURITY_ADMIN_PASSWORD"]
    assert env["CLICKHOUSE_USER"] == "showcase" and real["CLICKHOUSE_USER"] != "showcase"
    assert env["CLICKHOUSE_PASSWORD"] != real["CLICKHOUSE_PASSWORD"]
    assert not any("grafana-data" in str(v) for v in PUBLIC.get("volumes", []))
    # Its store connection asks for no more time per query than its store user may have.
    ds = yaml.safe_load(
        (ROOT / "compose/grafana/provisioning-public/datasources/clickhouse.yaml").read_text()
    )["datasources"][0]
    xml = (ROOT / "compose/clickhouse/users.d/showcase.xml").read_text()
    ceiling = re.search(r"<max_execution_time><max>(\d+)</max>", xml).group(1)
    # The plugin asks for its timeout plus about 5 seconds, and the store refuses more than
    # its ceiling: every panel would then fail (measured 15 Nov 2026).
    assert ds["uid"] == "clickhouse"
    for timeout in ("queryTimeout", "dialTimeout"):
        assert int(ds["jsonData"][timeout]) + 5 <= int(ceiling), timeout
    assert any(
        str(v).startswith("./grafana/provisioning-public/datasources:") for v in PUBLIC["volumes"]
    )
    # It runs the store's plugin and no other: each plugin is a program a visitor can reach.
    assert env["GF_PLUGINS_PREINSTALL_SYNC"] == env["GF_PLUGINS_PREINSTALL"]
    assert env["GF_PLUGINS_PREINSTALL"] == "grafana-clickhouse-datasource"
    disabled = env["GF_PLUGINS_DISABLE_PLUGINS"].split(",")
    assert {"elasticsearch", "prometheus", "stackdriver"} <= set(disabled)
    assert "grafana-clickhouse-datasource" not in disabled
    # Its state is in memory, and the store's plugin must be able to run from there.
    (state,) = PUBLIC["tmpfs"]
    assert state.startswith("/var/lib/grafana:") and "exec" in state.split(":", 1)[1].split(",")
    # Dashboards and provisioning are mounted read-only.
    assert all(str(v).endswith(":ro") for v in PUBLIC["volumes"])


def test_the_showcase_s_store_user_can_only_read_under_limits_it_cannot_raise():
    text = (ROOT / "compose" / "clickhouse" / "users.d" / "showcase.xml").read_text()
    body = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    assert "<readonly>2</readonly>" in body
    assert re.findall(r"<query>(.*?)</query>", body) == ["GRANT SELECT ON mirage.*"]
    assert "<quota>showcase</quota>" in body and "<queries>" in body
    constraints = body[body.index("<constraints>") : body.index("</constraints>")]
    for setting in ("max_execution_time", "max_memory_usage", "max_result_rows", "max_threads"):
        assert f"<{setting}>" in body, setting
        assert f"<{setting}><max>" in constraints, f"{setting} can be raised by a visitor"
    mounts = SERVICES["clickhouse"]["volumes"]
    assert any(str(m).endswith("users.d/showcase.xml:ro") for m in mounts)


# ------------------------------------------------------------------ the console's password


@pytest.fixture
def env_fill(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("env_fill", ROOT / "tools" / "env_fill.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / ".env.example").write_text((ROOT / ".env.example").read_text())
    monkeypatch.setattr(module, "ROOT", tmp_path)
    return module


def values(path: Path) -> dict[str, str]:
    pairs = (ln.split("=", 1) for ln in path.read_text().splitlines() if "=" in ln[:60])
    return {k: v for k, v in pairs if not k.startswith("#")}


def test_the_console_s_password_is_generated_and_can_be_replaced(env_fill, tmp_path, capsys):
    assert "SHOWCASE_CONSOLE_PASSWORD" in env_fill.SECRETS
    assert values(tmp_path / ".env.example")["SHOWCASE_CONSOLE_PASSWORD"] == ""
    env_fill.main([])
    first = values(tmp_path / ".env")
    assert re.fullmatch(r"[0-9a-f]{32}", first["SHOWCASE_CONSOLE_PASSWORD"])

    env_fill.main([])  # completing a complete file changes nothing
    assert values(tmp_path / ".env") == first

    env_fill.main(["--renew", "SHOWCASE_CONSOLE_PASSWORD"])
    second = values(tmp_path / ".env")
    assert re.fullmatch(r"[0-9a-f]{32}", second["SHOWCASE_CONSOLE_PASSWORD"])
    assert second["SHOWCASE_CONSOLE_PASSWORD"] != first["SHOWCASE_CONSOLE_PASSWORD"]
    # Nothing else moved: a new store password here would lock the services out.
    del first["SHOWCASE_CONSOLE_PASSWORD"], second["SHOWCASE_CONSOLE_PASSWORD"]
    assert second == first
    # And no value was printed, then or ever.
    out = capsys.readouterr().out
    assert "replaced SHOWCASE_CONSOLE_PASSWORD" in out and not re.search(r"[0-9a-f]{32}", out)


@pytest.mark.parametrize(
    "args", [["--renew"], ["--renew", "CLICKHOUSE_PASSWORD"], ["--renew", "x"], ["x"]]
)
def test_no_other_secret_can_be_replaced_this_way(args, env_fill, tmp_path):
    env_fill.main([])
    before = (tmp_path / ".env").read_text()
    with pytest.raises(SystemExit, match="usage"):
        env_fill.main(args)
    assert (tmp_path / ".env").read_text() == before
