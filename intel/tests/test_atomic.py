"""Atomic Red Team's index as labelled text, from a small made-up index."""

from __future__ import annotations

import pytest
import yaml
from mirage_intel import atomic

pytestmark = pytest.mark.ml

G1 = "11111111-1111-4111-8111-111111111111"
G2 = "22222222-2222-4222-8222-222222222222"
G3 = "33333333-3333-4333-8333-333333333333"
G4 = "44444444-4444-4444-8444-444444444444"


def entry(guid, command, name="sh", platforms=("linux",), arguments=None):
    return {
        "auto_generated_guid": guid,
        "supported_platforms": list(platforms),
        "input_arguments": arguments,
        "executor": {"name": name, "command": command},
    }


FIRST = entry(
    G1, "echo start\nuname -a | tee #{out}\n# a comment\n", arguments={"out": {"default": "/tmp/o"}}
)
INDEX = {
    "discovery": {
        "T1082": {
            "atomic_tests": [
                FIRST,
                entry(G2, "Get-ComputerInfo", name="powershell", platforms=("windows",)),
            ]
        },
        "T1999": {"atomic_tests": [entry(G3, "hostname && id")]},
    },
    # The index lists a test under each of its technique's tactics: it is indexed once.
    "collection": {"T1082": {"atomic_tests": [FIRST]}},
    "persistence": {"T1053.003": {"atomic_tests": [entry(G4, "crontab -l; cd /tmp", name="bash")]}},
}


@pytest.fixture
def tests(tmp_path):
    path = tmp_path / "linux-index.yaml"
    path.write_text(yaml.safe_dump(INDEX))
    return atomic.load(path)


def test_only_linux_shell_tests_are_read_once_each_with_defaults_filled(tests):
    assert [t.guid for t in tests] == [G1, G3, G4]
    assert tests[0].technique == "T1082"
    assert tests[0].lines == ("echo start", "uname -a | tee /tmp/o", "# a comment")


def test_scaffolding_is_not_indexed_and_pieces_split_on_shell_operators(tests):
    assert atomic.texts(tests[0], "line") == ["uname -a | tee /tmp/o"]
    assert atomic.texts(tests[0], "pieces") == ["uname -a", "tee /tmp/o"]
    assert atomic.texts(tests[2], "pieces") == ["crontab -l"]  # `cd` is scaffolding


def test_a_guid_is_read_out_of_a_catalogue_reference():
    refs = [f"ART T1082 test 3 ({G1})", "own procedure", None, f"see {G4}"]
    assert atomic.guids_in(refs) == {G1, G4}


def test_pairs_leave_out_excluded_tests_and_techniques_outside_the_label_space(tests):
    pairs = atomic.pairs(tests, "pieces", {"T1082", "T1053.003"}, exclude={G4})
    assert pairs == [("uname -a", "T1082"), ("tee /tmp/o", "T1082")]
    assert atomic.pairs(tests, "line", {"T1082"}, exclude={G1}) == []


def test_a_replaced_technique_is_translated_before_the_label_space_is_applied(tests):
    pairs = atomic.pairs(tests, "pieces", {"T1082"}, exclude={G1}, current={"T1999": "T1082"})
    assert pairs == [("hostname", "T1082")]  # `id` is under the minimum length
