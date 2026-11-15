"""The catalogue's two sets: phase 2's frozen one and phase 3's depth procedures."""

from __future__ import annotations

import pytest
import yaml

from mirage_lab.models import DEPTH, PHASE2, Catalogue, Scenario, lint, load_split, set_of_file
from mirage_lab.slots import Slots

OLD = """attack_version: "20.1"
procedures:
  - {id: sysinfo-one, technique: T1082, tactic: TA0007, source: own, protocol: ssh, template: "uname -a"}
  - {id: files-one, technique: T1083, tactic: TA0007, source: own, protocol: ssh, template: "ls {{dir}}"}
"""
NEW = """attack_version: "20.1"
procedures:
  - {id: d-kernel-one, technique: T1082, tactic: TA0007, source: own, protocol: ssh, template: "uname -r"}
"""


def scenario(sid: str, *procedures: str) -> Scenario:
    steps = [{"id": f"s{i}", "procedure": p} for i, p in enumerate(procedures)]
    return Scenario.model_validate(
        {
            "id": sid,
            "actor": {"class": "scripted_bot", "timing": "bot-fast"},
            "sessions": [{"protocol": "ssh", "steps": steps}],
        }
    )


def test_a_file_s_set_comes_from_its_name():
    assert set_of_file("10-discovery.yaml") == PHASE2
    assert set_of_file("90-depth-facts.yaml") == DEPTH
    assert set_of_file("9-depth-x.yaml") == DEPTH
    assert set_of_file("90-probe.yaml") == PHASE2  # only the depth pattern is the depth set
    assert set_of_file("19-depth-notes.yaml") == PHASE2


def test_adding_or_changing_a_depth_file_leaves_the_phase_2_hash_alone(tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    for d in (before, after):
        d.mkdir()
        (d / "10-old.yaml").write_text(OLD)
    (after / "90-depth-new.yaml").write_text(NEW)
    alone, both = Catalogue.load(before), Catalogue.load(after)
    assert both.sha256 != alone.sha256  # the whole changed
    assert both.only(PHASE2).sha256 == alone.sha256  # the phase 2 set did not
    assert both.set_of == {"sysinfo-one": PHASE2, "files-one": PHASE2, "d-kernel-one": DEPTH}
    assert set(both.only(DEPTH).procedures) == {"d-kernel-one"}
    depth_hash = both.only(DEPTH).sha256
    (after / "90-depth-new.yaml").write_text(NEW.replace("uname -r", "uname -v"))
    changed = Catalogue.load(after)
    assert changed.only(DEPTH).sha256 != depth_hash
    assert changed.only(PHASE2).sha256 == alone.sha256
    with pytest.raises(KeyError):
        alone.only(DEPTH)


def test_a_scenario_may_not_draw_on_both_sets(tmp_path):
    (tmp_path / "10-old.yaml").write_text(OLD)
    (tmp_path / "90-depth-new.yaml").write_text(NEW)
    catalogue = Catalogue.load(tmp_path)
    mixed = scenario("mixed-one", "sysinfo-one", "d-kernel-one")
    assert catalogue.set_of_scenario(mixed) is None
    assert catalogue.set_of_scenario(scenario("depth-one", "d-kernel-one")) == DEPTH
    problems = lint(mixed, catalogue, Slots.names())
    assert any("mixes catalogue sets" in p for p in problems)
    # A depth scenario whose procedures are in no split is refused, as any other is.
    splits = {"sysinfo-one": "train", "files-one": "train"}
    unsplit = lint(scenario("depth-one", "d-kernel-one"), catalogue, Slots.names(), splits)
    assert any("no split" in p for p in unsplit)
    assert (
        lint(
            scenario("depth-one", "d-kernel-one"),
            catalogue,
            Slots.names(),
            {**splits, "d-kernel-one": "test"},
        )
        == []
    )


def test_the_depth_split_is_read_beside_the_phase_2_one(tmp_path):
    main = tmp_path / "split.yaml"
    main.write_text(
        yaml.safe_dump(
            {"procedures": {"train": ["a-one"], "test": ["b-one"]}, "scenarios": {"s-one": "train"}}
        )
    )
    assert load_split(main).procedures == {"a-one": "train", "b-one": "test"}
    depth = tmp_path / "split-depth.yaml"
    depth.write_text(
        yaml.safe_dump(
            {"procedures": {"dev": ["d-one"], "test": ["d-two"]}, "scenarios": {"depth-s": "dev"}}
        )
    )
    both = load_split(main)
    assert both.procedures == {"a-one": "train", "b-one": "test", "d-one": "dev", "d-two": "test"}
    assert both.scenarios == {"s-one": "train", "depth-s": "dev"}
    # One procedure in both files would be in two splits.
    depth.write_text(yaml.safe_dump({"procedures": {"dev": ["a-one"]}}))
    with pytest.raises(ValueError, match="two splits"):
        load_split(main)
