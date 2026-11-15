"""The pinned ATT&CK index, from a small synthetic STIX bundle."""

from __future__ import annotations

import json

import pytest
from mirage_intel.attack import Attack

pytestmark = pytest.mark.ml


def ref(external_id):
    return [{"source_name": "mitre-attack", "external_id": external_id}]


def phase(name):
    return {"kill_chain_name": "mitre-attack", "phase_name": name}


BUNDLE = {
    "objects": [
        {"type": "x-mitre-collection", "x_mitre_version": "20.1"},
        {"type": "x-mitre-tactic", "name": "Discovery", "x_mitre_shortname": "discovery",
         "external_references": ref("TA0007")},
        {"type": "x-mitre-tactic", "name": "Persistence", "x_mitre_shortname": "persistence",
         "external_references": ref("TA0003")},
        {"type": "x-mitre-tactic", "name": "Execution", "x_mitre_shortname": "execution",
         "external_references": ref("TA0002")},
        {"type": "attack-pattern", "name": "System Information Discovery",
         "description": "An adversary may get details of the system.\n\nLonger text.",
         "kill_chain_phases": [phase("discovery")], "external_references": ref("T1082")},
        {"type": "attack-pattern", "name": "Cron", "description": "Scheduling with cron.",
         "kill_chain_phases": [phase("execution"), phase("persistence")],
         "external_references": ref("T1053.003")},
        {"type": "attack-pattern", "name": "Old Technique", "revoked": True,
         "kill_chain_phases": [phase("discovery")], "external_references": ref("T1999")},
        {"type": "attack-pattern", "name": "Other framework",
         "kill_chain_phases": [{"kill_chain_name": "other", "phase_name": "discovery"}],
         "external_references": [{"source_name": "capec", "external_id": "CAPEC-1"}]},
    ]
}  # fmt: skip


def bundle(tmp_path):
    path = tmp_path / "enterprise-attack.json"
    path.write_text(json.dumps(BUNDLE))
    return path


def test_the_index_holds_ids_names_tactics_and_retirement(tmp_path):
    attack = Attack.from_stix(bundle(tmp_path))
    assert attack.version == "20.1" and len(attack.sha256) == 64
    assert set(attack.techniques) == {"T1082", "T1053.003", "T1999"}  # the CAPEC entry is not one
    assert attack.techniques["T1053.003"].tactics == ("TA0002", "TA0003")
    assert attack.techniques["T1999"].retired
    assert attack.tactics == {"TA0002": "Execution", "TA0003": "Persistence", "TA0007": "Discovery"}
    index = attack.to_index()
    assert "description" not in json.dumps(index)  # the committed index carries no prose
    path = tmp_path / "index.json"
    path.write_text(json.dumps(index))
    again = Attack.from_index(path)
    assert again.techniques["T1082"].name == "System Information Discovery"
    assert again.techniques["T1999"].retired and again.sha256 == attack.sha256


def test_a_revoked_technique_names_its_replacement_followed_to_the_end(tmp_path):
    doc = json.loads(json.dumps(BUNDLE))
    stix = {
        "T1999": "attack-pattern--a",
        "T1082": "attack-pattern--b",
        "T1053.003": "attack-pattern--c",
    }
    for o in doc["objects"]:
        if o["type"] == "attack-pattern" and o["external_references"][0].get("external_id") in stix:
            o["id"] = stix[o["external_references"][0]["external_id"]]
    # T1999 was replaced by T1082, which (in this made-up bundle) was replaced by T1053.003.
    doc["objects"] += [
        {"type": "relationship", "relationship_type": "revoked-by",
         "source_ref": "attack-pattern--a", "target_ref": "attack-pattern--b"},
        {"type": "relationship", "relationship_type": "revoked-by",
         "source_ref": "attack-pattern--b", "target_ref": "attack-pattern--c"},
        {"type": "relationship", "relationship_type": "uses",
         "source_ref": "attack-pattern--c", "target_ref": "attack-pattern--a"},
    ]  # fmt: skip
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(doc))
    attack = Attack.from_stix(path)
    assert attack.replaced_by == {"T1999": "T1053.003", "T1082": "T1053.003"}
    index = tmp_path / "index.json"
    index.write_text(json.dumps(attack.to_index()))
    assert Attack.from_index(index).replaced_by == attack.replaced_by


def test_a_bundle_without_replacements_has_none(tmp_path):
    assert Attack.from_stix(bundle(tmp_path)).replaced_by == {}


def test_a_label_is_checked_against_the_pinned_version(tmp_path):
    attack = Attack.from_stix(bundle(tmp_path))
    assert attack.problems("T1082", "TA0007", "p") == []
    assert attack.problems(None, None, "p") == []  # an explicit negative
    assert "is not a technique in ATT&CK v20.1" in attack.problems("T1234", "TA0007", "p")[0]
    assert "deprecated or revoked" in attack.problems("T1999", "TA0007", "p")[0]
    wrong = attack.problems("T1082", "TA0003", "procedure x")
    assert wrong == ["procedure x: T1082 is not under TA0003 in v20.1 (it is under TA0007)"]
    assert attack.problems("T1053.003", "TA0003", "p") == []  # one of its two tactics


def test_retrieval_text_is_the_name_and_first_paragraph(tmp_path):
    attack = Attack.from_stix(bundle(tmp_path))
    text = attack.text("T1082")
    assert text.startswith("System Information Discovery. An adversary may get details")
    assert "Longer text" not in text and len(attack.text("T1082", limit=20)) == 20


def test_every_label_in_the_catalogue_and_the_rules_is_valid_under_the_pinned_version():
    # The check that found five mislabelled procedures on its first run (15 November 2026):
    # four used a technique v20.1 had revoked, and one paired a technique with a tactic it is
    # not under.
    from mirage_intel.attack import VERSION, check_catalogue

    attack = Attack.from_index()
    assert attack.version == VERSION and len(attack.techniques) > 500
    assert check_catalogue(attack) == []
