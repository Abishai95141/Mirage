"""What the profile generator hands the responder (phase 3 spec 3.2b): `responder.json` is
the whole of what the model is told about a host, so it is held to two things here. The
responder can build its prompt from it, and nothing in it is a secret."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mirage_responder import prompt
from mirage_responder.filter import MARKER_WORDS, Filter

from mirage_profiles import generator

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "decoys/profiles/web-db.yaml"


@pytest.fixture(scope="module")
def rendered(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("profile") / "p"
    generator.render(PROFILE, 7, out)
    return out


def test_the_responder_can_build_its_prompt_from_a_rendered_profile(rendered: Path):
    profile = json.loads((rendered / "responder" / "responder.json").read_text())
    assert profile["version"] == 1 and profile["deployment_id"]
    text = prompt.system(profile)
    assert profile["hostname"] in text and profile["address"] in text
    for service in profile["services"]:
        # A version as a person would read it off the program, not a banner or a build line.
        assert service["version"] and "\n" not in service["version"], service
        assert f"{service['name']} {service['version']}" in text
    names = {s["name"]: s["version"] for s in profile["services"]}
    assert names["nginx"][0].isdigit() and names["mariadb"][0].isdigit()
    assert names["redis-server"][0].isdigit() and names["sshd"].startswith("OpenSSH_")
    assert profile["users"][0]["name"] == "root"


def test_the_prompt_passes_its_own_marker_rule(rendered: Path):
    """The prompt may not hold a word the output filter refuses: a model that repeats a fact
    of the host would otherwise be cut off for it."""
    profile = json.loads((rendered / "responder" / "responder.json").read_text())
    described = prompt.system(profile).split("\n\nThe server:")[1].lower()
    assert [w for w in MARKER_WORDS if w in described] == []
    checker = Filter(prompt.system(profile), prompt.facts(profile))
    for fact in prompt.facts(profile):
        assert checker.check(fact) is None, fact


def test_the_responder_is_given_a_directory_with_nothing_else_in_it(rendered: Path):
    """The service mounts this directory. The rest of the profile holds what it must never
    see: the decoys' login passwords and the planted tokens' values."""
    assert [p.name for p in (rendered / "responder").iterdir()] == ["responder.json"]
    compose = (ROOT / "compose/docker-compose.yml").read_text()
    assert "../build/profile/responder:/profile:ro" in compose
    assert "build/profile:/profile" not in compose.split("  responder:\n", 1)[1].split("\n\n", 1)[0]


def test_the_responders_profile_holds_no_secret(rendered: Path):
    text = (rendered / "responder" / "responder.json").read_text()
    profile = json.loads(text)
    tokens = json.loads((rendered / "tokens.json").read_text())
    tokens = tokens["tokens"] if isinstance(tokens, dict) else tokens
    assert tokens, "the profile plants tokens"
    for token in tokens:
        for key in ("value", "secret", "password", "token"):
            value = token.get(key)
            if isinstance(value, str) and len(value) >= 6:
                assert value not in text, f"a planted {key} is in responder.json"
    # The tokens are there as the paths to keep answers away from, and only as that.
    assert all(path.startswith("/") for path in profile["token_paths"])
    planted = {p for t in tokens for p in str(t.get("planted_at", "")).split(",") if "ssh:/" in p}
    assert len(profile["token_paths"]) == len({p.strip() for p in planted})
    assert set(profile) == {
        "version", "deployment_id", "hostname", "os", "kernel", "kernel_release", "arch",
        "address", "timezone", "hardware", "users", "services", "token_paths",
    }  # fmt: skip


def test_the_decoy_is_told_which_files_hold_a_token_and_where_its_checksums_are(rendered: Path):
    """The same paths the responder is given to protect are the ones the decoy protects."""
    import configparser

    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(rendered / "cowrie/cowrie.cfg")
    profile = json.loads((rendered / "responder" / "responder.json").read_text())
    assert cfg["mirage"]["token_paths"].split(",") == profile["token_paths"]
    assert cfg["mirage"]["file_hashes"] == "/cowrie/deployment/hashes.db"
