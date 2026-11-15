"""Every MIRAGE dashboard is provisioned, and every panel's query runs without error.

Grafana's /api/ds/query runs a panel's SQL exactly as the panel would, macros included, but it
does not substitute template variables (the browser does that). The test substitutes them with
real IDs from ClickHouse: the session and actor with the most honeytokens, so the drill-down
pages are exercised with data, not just with empty results.
"""

from __future__ import annotations

import json
import re

import httpx
import pytest

from .conftest import ROOT, docker, unavailable

pytestmark = pytest.mark.integration

DASHBOARDS = sorted(p.stem for p in (ROOT / "compose/grafana/dashboards").glob("mirage-*.json"))


@pytest.fixture(scope="module")
def grafana(env):
    base = f"http://127.0.0.1:{env.get('GRAFANA_PORT', '3300')}"
    client = httpx.Client(base_url=base, auth=("admin", env["GRAFANA_ADMIN_PASSWORD"]), timeout=30)
    try:
        client.get("/api/health").raise_for_status()
    except httpx.HTTPError:
        unavailable("Grafana not reachable; run make up")
    return client


@pytest.fixture(scope="module")
def variables(clickhouse) -> dict[str, str]:
    rows = clickhouse(
        "SELECT session_id, actor_id, protocol, src_ip FROM mirage.session_summary FINAL "
        "ORDER BY length(tokens) DESC, length(connections) DESC, end_ts DESC LIMIT 1"
    )
    if not rows:
        unavailable("no sessions yet; run the Gate 1 tests first")
    r = rows[0]
    return {"session": r["session_id"], "actor": r["actor_id"], "protocol": "all", "src": ""}


def substitute(sql: str, values: dict[str, str]) -> str:
    def one(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        return values[name] if name in values else m.group(0)

    return re.sub(r"\$\{(\w+)\}|\$(?!__)(\w+)", one, sql)


def test_every_dashboard_is_provisioned(grafana):
    found = {d["uid"] for d in grafana.get("/api/search", params={"tag": "mirage"}).json()}
    assert set(DASHBOARDS) <= found, set(DASHBOARDS) - found


@pytest.mark.parametrize("uid", DASHBOARDS)
def test_every_panel_query_runs(grafana, variables, uid):
    dash = grafana.get(f"/api/dashboards/uid/{uid}").json()["dashboard"]
    checked = 0
    for panel in dash["panels"]:
        for t in panel.get("targets", []):
            query = dict(t, rawSql=substitute(t["rawSql"], variables))
            resp = grafana.post(
                "/api/ds/query", json={"from": "now-7d", "to": "now", "queries": [query]}
            )
            body = resp.json()
            result = body.get("results", {}).get(t["refId"], {})
            assert resp.status_code == 200 and "error" not in result, (
                uid,
                panel["title"],
                json.dumps(body)[:600],
            )
            checked += 1
    assert checked, uid


@pytest.mark.parametrize("uid", ["mirage-sessions", "mirage-session"])
def test_session_pages_show_model_output_never_lab_ground_truth(uid):
    # Reads the generated JSON only, so it needs no stack. Tags come from the tagger
    # (mirage.labels) and the actor class from the classifier (mirage.actor_class); a sim_*
    # table holds what the scenario said about itself, which is what those are compared with.
    dash = json.loads((ROOT / "compose/grafana/dashboards" / f"{uid}.json").read_text())
    sql = [t["rawSql"] for panel in dash["panels"] for t in panel.get("targets", [])]
    assert any("mirage.labels FINAL" in q for q in sql), uid
    assert any("mirage.actor_class FINAL" in q for q in sql), uid
    assert not [q for q in sql if "sim_" in q], uid


def test_session_page_shows_the_sessions_timeline(grafana, variables):
    dash = grafana.get("/api/dashboards/uid/mirage-session").json()["dashboard"]
    panel = next(p for p in dash["panels"] if p["title"] == "Timeline")
    t = panel["targets"][0]
    resp = grafana.post(
        "/api/ds/query",
        json={
            "from": "now-7d",
            "to": "now",
            "queries": [dict(t, rawSql=substitute(t["rawSql"], variables))],
        },
    ).json()
    frame = resp["results"]["A"]["frames"][0]
    assert frame["data"]["values"][0], "the timeline of a known session is empty"


def test_grafana_reads_clickhouse_as_a_user_that_cannot_write(grafana, clickhouse):
    # Template variables reach SQL unescaped, so the datasource user must not be able to write.
    probe = "mirage.grafana_write_probe"
    try:
        for sql in (
            f"CREATE TABLE {probe} (x UInt8) ENGINE = Memory",
            "INSERT INTO mirage.tokens (token_id) VALUES ('grafana-write-probe')",
            "SELECT * FROM system.users",
        ):
            q = {"refId": "A", "datasource": {"uid": "clickhouse"}, "rawSql": sql, "format": 1}
            body = grafana.post(
                "/api/ds/query", json={"from": "now-1h", "to": "now", "queries": [q]}
            ).json()
            assert "error" in body.get("results", {}).get("A", {}), (sql, json.dumps(body)[:300])
        assert not clickhouse("SELECT 1 FROM mirage.tokens WHERE token_id = 'grafana-write-probe'")
    finally:
        # Only matters if the test failed because the CREATE succeeded.
        docker(
            "exec",
            "mirage-clickhouse-1",
            "sh",
            "-c",
            'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD"'
            f' -q "DROP TABLE IF EXISTS {probe}"',
            check=False,
        )
