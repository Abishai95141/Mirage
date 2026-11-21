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


def test_extend_adds_scenarios_without_moving_a_procedure():
    # A new scenario joins the frozen split by its procedures; `build` would re-run the
    # assignment over the changed scenario graph and could move procedures between splits.
    from eval import split as sp

    cat, scn = sp._load()
    frozen = sp.Split.load()
    extended, problems = sp.extend(frozen, cat, scn)
    assert problems == []
    assert extended.of_procedure == frozen.of_procedure
    assert extended.of_scenario == frozen.of_scenario  # the checked-in file is already extended
    assert set(extended.of_scenario) == {s.id for s in scn}


def test_extend_refuses_a_scenario_that_mixes_splits():
    from eval import split as sp
    from mirage_lab.models import Scenario

    cat, scn = sp._load()
    frozen = sp.Split.load()
    train = next(
        p
        for p, s in frozen.of_procedure.items()
        if s == "train" and cat.procedures[p].protocol == "redis"
    )
    test = next(
        p
        for p, s in frozen.of_procedure.items()
        if s == "test" and cat.procedures[p].protocol == "redis"
    )
    mixed = Scenario.model_validate(
        {
            "id": "mixed-splits",
            "actor": {"class": "scripted_bot", "timing": "bot-fast"},
            "sessions": [
                {
                    "protocol": "redis",
                    "steps": [{"id": "s1", "procedure": train}, {"id": "s2", "procedure": test}],
                }
            ],
        }
    )
    _, problems = sp.extend(frozen, cat, [*scn, mixed])
    assert any("mixed-splits mixes splits" in p for p in problems)


def test_build_will_not_overwrite_a_frozen_split(capsys):
    import pytest

    from eval import split as sp

    with pytest.raises(SystemExit) as exc:
        sp.main(["build"])
    assert exc.value.code == 1
    assert "is frozen" in capsys.readouterr().out


# ---------------------------------------------------------------- the depth split


def _depth_world():
    """Six scenarios in four groups: two pairs that share a procedure, and two on their own."""
    rows = [
        (f"d-p{i:02d}", f"T10{i:02d}", f"TA00{i % 4 + 1:02d}", f"word{i} --flag{i} {{{{file}}}}")
        for i in range(12)
    ]
    catalogue = cat(*rows)
    scenarios = [
        scn("depth-a1", "d-p00", "d-p01"),
        scn("depth-a2", "d-p01", "d-p02"),  # tied to a1 through d-p01
        scn("depth-b1", "d-p03", "d-p04"),
        scn("depth-b2", "d-p04", "d-p05"),  # tied to b1 through d-p04
        scn("depth-c1", "d-p06", "d-p07", "d-p08"),
        scn("depth-d1", "d-p09", "d-p10", "d-p11"),
    ]
    return catalogue, scenarios


def test_the_depth_split_deals_whole_groups_into_two_even_halves():
    from eval import split as sp

    catalogue, scenarios = _depth_world()
    split = sp.depth_build(catalogue, scenarios)
    assert split.status == "provisional"
    assert set(split.of_procedure.values()) == {"dev", "test"}  # nothing is trained on it
    assert sorted(split.manifest["scenarios_by_half"].values()) == [3, 3]
    # Scenarios that share a procedure are in the same half.
    assert split.of_scenario["depth-a1"] == split.of_scenario["depth-a2"]
    assert split.of_scenario["depth-b1"] == split.of_scenario["depth-b2"]
    assert sp.depth_check(split, catalogue, scenarios).problems == []
    # The deal does not depend on the order the files happen to be read in.
    again = sp.depth_build(catalogue, list(reversed(scenarios)))
    assert again.of_procedure == split.of_procedure


def test_the_depth_check_finds_what_would_make_the_halves_unsound():
    from eval import split as sp

    catalogue, scenarios = _depth_world()
    good = sp.depth_build(catalogue, scenarios)

    def problems(**change) -> str:
        split = sp.Split(
            dict(good.of_procedure),
            dict(good.of_scenario),
            good.catalogue_sha256,
            {},
            "provisional",
        )
        for key, value in change.items():
            setattr(split, key, value)
        return " | ".join(sp.depth_check(split, catalogue, scenarios).problems)

    assert "different depth catalogue" in problems(catalogue_sha256="0" * 64)
    assert "status" in problems(status=None)
    missing = {k: v for k, v in good.of_procedure.items() if k != "d-p00"}
    assert "d-p00 is in no half" in problems(of_procedure=missing)
    other = "dev" if good.of_procedure["d-p00"] == "test" else "test"
    assert "depth-a1 mixes halves" in problems(of_procedure={**good.of_procedure, "d-p00": other})
    assert "half is empty" in problems(of_procedure=dict.fromkeys(good.of_procedure, "dev"))
    assert "not filed under" in problems(of_scenario={**good.of_scenario, "depth-c1": "nowhere"})


def test_a_depth_test_command_that_phase_2_trains_on_is_reported_by_id_only():
    from eval import split as sp

    catalogue, scenarios = _depth_world()
    split = sp.depth_build(catalogue, scenarios)
    in_test = next(p for p, h in sorted(split.of_procedure.items()) if h == "test")
    same_text = catalogue.procedures[in_test].template
    phase2 = cat(
        ("phase2-twin", "T1082", "TA0007", same_text),
        ("phase2-other", "T1083", "TA0007", "ls {{dir}}"),
    )
    phase2_split = sp.Split({"phase2-twin": "train", "phase2-other": "test"}, {}, "x")
    result = sp.depth_check(split, catalogue, scenarios, phase2, phase2_split)
    assert result.problems == []  # reported, not refused
    assert [(a, b) for a, _sa, b, _sb, _score in result.similar_pairs] == [(in_test, "phase2-twin")]
    assert same_text not in str(result.similar_pairs)


def test_the_depth_files_leave_the_phase_2_split_as_it_was():
    # The checked-in files: the phase 2 set's hash is still the one the frozen split names,
    # every depth scenario is in the depth split, and no scenario is in both.
    from eval import split as sp
    from mirage_lab.models import DEPTH, PHASE2

    sets = sp.load_sets()
    frozen = sp.Split.load()
    assert sets[PHASE2][0].sha256 == frozen.catalogue_sha256
    assert check(frozen, *sets[PHASE2]).ok
    depth_catalogue, depth_scenarios = sets[DEPTH]
    depth = sp.Split.load(sp.DEPTH_SPLIT_FILE)
    assert sp.depth_check(depth, depth_catalogue, depth_scenarios, sets[PHASE2][0], frozen).ok
    assert set(depth.of_scenario) == {sc.id for sc in depth_scenarios}
    assert not set(depth.of_scenario) & set(frozen.of_scenario)
    assert not set(depth.of_procedure) & set(frozen.of_procedure)


def test_demo_procedures_are_in_no_split_and_are_held_against_the_test_ones():
    from eval import split as sp

    demo = cat(
        ("h-same", "T1082", "TA0007", "uname -a"),
        ("h-other", "T1033", "TA0007", "id"),
    )
    phase2 = cat(
        ("old-train", "T1082", "TA0007", "uname -a"),
        ("old-test", "T1082", "TA0007", "uname  -a"),
        ("old-far", "T1083", "TA0007", "ls {{dir}}"),
    )
    split = sp.Split({"old-train": "train", "old-test": "test", "old-far": "test"}, {}, "x")
    result = sp.demo_check(demo, [("phase 2", phase2, split)])
    assert result.problems == []  # reported, not refused
    # Only the held-out twin is listed: a training procedure may be the same command.
    assert [(a, b, sb) for a, _sa, b, sb, _score in result.similar_pairs] == [
        ("h-same", "old-test", "phase 2 test")
    ]
    assert "uname" not in str(result.similar_pairs)
    # A split that names a demo procedure has taken demo steps in as data.
    named = sp.Split({**split.of_procedure, "h-other": "train"}, {}, "x")
    problems = sp.demo_check(demo, [("phase 2", phase2, named)]).problems
    assert len(problems) == 1 and "h-other" in problems[0] and "phase 2 split" in problems[0]
