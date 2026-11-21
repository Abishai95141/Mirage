"""The SSH decoy checks the shape of state operations with code of its own (the fork does not
carry `mirage_schema`). Both implementations are run against one file of cases. This test
holds the fork's copy of that file, which travels inside the patch series, to the contract's:
a case added on one side and not the other would let the two drift apart unseen."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PATCHES = ROOT / "decoys/ssh/patches"
CONTRACT = ROOT / "schema/tests/ops_cases.json"
IN_FORK = "src/cowrie/test/mirage_ops_cases.json"


def file_from_patches(path: str) -> str | None:
    """A file as the patch series leaves it, for one that a single patch adds whole."""
    found = None
    for patch in sorted(PATCHES.glob("*.patch")):
        text = patch.read_text(encoding="utf8")
        marker = f"diff --git a/{path} b/{path}\n"
        if marker not in text:
            continue
        body = text.split(marker, 1)[1].split("\ndiff --git ", 1)[0]
        assert "new file mode" in body, f"{patch.name} changes {path}; this test reads additions"
        hunk = body.split("\n@@ ", 1)[1].split("\n", 1)[1]
        lines = [line[1:] for line in hunk.split("\n") if line.startswith("+")]
        found = "\n".join(lines) + "\n"
    return found


def test_the_forks_cases_are_the_contracts():
    in_fork = file_from_patches(IN_FORK)
    assert in_fork is not None, "no patch adds the cases file"
    assert in_fork == CONTRACT.read_text(encoding="utf8")
