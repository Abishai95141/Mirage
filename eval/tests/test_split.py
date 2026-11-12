"""The train/dev/test split: split by procedure, no scenario across splits, near-dupes together.

Synthetic benign procedures and scenarios, so the test says nothing about the real catalogue's
content; it exercises the assignment logic.
"""

from __future__ import annotations

from eval.split import build, check, jaccard, normalise, tokens
from mirage_lab.models import Catalogue, Procedure, Scenario


def cat(*rows: tuple) -> Catalogue:
    procs = {}
    for pid, tech, tactic, template in rows:
        procs[pid] = Procedure(
            id=pid, technique=tech, tactic=tactic, source="own", protocol="ssh", template=template
        )
    return Catalogue(attack_version="20.1", procedures=procs, sha256="deadbeef")


def scn(sid: str, *procedures: str) -> Scenario:
    return Scenario.model_validate(
        {
            "id": sid,
            "actor": {"class": "scripted_bot", "timing": "bot-fast"},
            "sessions": [
                {
                    "protocol": "ssh",
                    "steps": [{"id": f"s{i}", "procedure": p} for i, p in enumerate(procedures)],
                }
            ],
        }
    )


def test_normalise_collapses_slots_and_literals():
    assert normalise("wget http://{{host}}/{{file}}") == normalise(
        "wget http://{{domain}}/{{word}}"
    )
    assert jaccard(tokens(normalise("ls -la {{dir}}")), tokens(normalise("ls -la {{path}}"))) == 1.0
    assert jaccard(tokens(normalise("id")), tokens(normalise("whoami"))) < 0.5


def test_split_by_procedure_with_no_scenario_spanning():
    procedures = [
        (f"proc-{i:02d}", f"T10{i:02d}", "TA0007", f"cmd{i} {{{{dir}}}}") for i in range(20)
    ]
    catalogue = cat(*procedures)
    # each scenario uses two procedures; p0 is shared by two scenarios, tying them together
    scenarios = [
        scn(f"scen-{i:02d}", f"proc-{i:02d}", f"proc-{i + 1:02d}") for i in range(0, 18, 2)
    ]
    scenarios.append(scn("scen-shared", "proc-00", "proc-10"))
    split = build(catalogue, scenarios)
    result = check(split, catalogue, scenarios)
    assert result.ok, result.problems
    assert set(split.of_procedure.values()) == {"train", "dev", "test"}
    # sc0 (p0,p1) and shared (p0,p10) share p0, so they and p10/p11's scenario land together
    assert (
        split.of_procedure["proc-00"]
        == split.of_procedure["proc-10"]
        == split.of_procedure["proc-01"]
    )


def test_near_duplicate_commands_are_forced_into_one_split():
    catalogue = cat(
        ("alpha", "T1001", "TA0007", "curl http://{{host}}/{{file}} -o {{path}}"),
        ("beta", "T1002", "TA0007", "curl http://{{domain}}/{{word}} -o {{dir}}/{{file}}"),
        ("gamma", "T1003", "TA0007", "systemctl restart {{word}}"),
        ("delta", "T1004", "TA0007", "cat /etc/{{word}}"),
        ("epsilon", "T1005", "TA0007", "ps aux"),
        ("zeta", "T1006", "TA0007", "netstat -an"),
    )
    # alpha and beta are the same command skeleton: whatever the assignment, they match
    assert (
        jaccard(
            tokens(normalise(catalogue.procedures["alpha"].template)),
            tokens(normalise(catalogue.procedures["beta"].template)),
        )
        >= 0.9
    )
    split = build(catalogue, [])
    assert split.of_procedure["alpha"] == split.of_procedure["beta"]
    assert check(split, catalogue, []).ok


def test_check_flags_a_hand_broken_split():
    catalogue = cat(
        ("alpha", "T1001", "TA0007", "curl http://{{host}}/{{file}}"),
        ("beta", "T1002", "TA0007", "curl http://{{domain}}/{{word}}"),
        ("gamma", "T1003", "TA0007", "uptime"),
    )
    split = build(catalogue, [])
    # force the near-duplicate pair apart by hand; the content check must catch it
    split.of_procedure["alpha"] = "train"
    split.of_procedure["beta"] = "test"
    split.of_procedure["gamma"] = "train" if "test" in split.of_procedure.values() else "test"
    result = check(split, catalogue, [])
    assert not result.ok
    assert any("near-identical" in p for p in result.problems)
    assert any({a, b} == {"alpha", "beta"} for a, _, b, _, _ in result.similar_pairs)


def test_check_flags_a_scenario_that_mixes_splits():
    catalogue = cat(
        ("alpha", "T1001", "TA0007", "echo a {{word}}"),
        ("beta", "T1002", "TA0007", "echo b {{word}}"),
    )
    scenarios = [scn("scen-00", "alpha", "beta")]
    split = build(catalogue, scenarios)
    split.of_procedure["alpha"], split.of_procedure["beta"] = "train", "test"
    result = check(split, catalogue, scenarios)
    assert any("mixes splits" in p for p in result.problems)


def test_build_refuses_nothing_but_reports_coverage():
    catalogue = cat(*[(f"proc-{i:02d}", "T1082", "TA0007", f"probe{i}") for i in range(6)])
    split = build(catalogue, [])
    result = check(split, catalogue, [])
    assert result.techniques_total == 1
    # one technique, spread across splits by hash, so it is coverable
    assert result.coverage in (0, 1)
