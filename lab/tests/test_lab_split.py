"""The frozen split reaches the lint at run time, and inputs are checked against every ID (gap
register F7).

The one-split rule was in the lint all along, but neither the CLI nor the runner passed it the
split, so it never ran outside a unit test. And an input was checked only against its own
step's procedure and scenario: a command that named another procedure passed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from test_lab import BASE, CATALOGUE, GOOD, ROOT, Scripted, drive, scenario, steps_of

from mirage_lab import cli, runner, safety
from mirage_lab.models import (
    DEFAULT_SPLIT,
    DEPTH,
    Catalogue,
    Scenario,
    check_input,
    lint,
    load_split,
)
from mirage_lab.runner import Settings
from mirage_lab.slots import Slots
from mirage_schema.groundtruth import parse_record

BASE_PROCS = [
    "ssh-password-guessing", "sysinfo-uname-all", "probe-missing-tool", "files-list-dir",
    "owner-id", "transfer-sftp-put",
]  # fmt: skip


def write_split(tmp_path, moved: dict[str, str] | None = None, scenarios=("test-one",)) -> Path:
    """A split file that puts BASE's procedures in train, except those in ``moved``."""
    of = {**dict.fromkeys(BASE_PROCS, "train"), **(moved or {})}
    by_split: dict[str, list[str]] = {"train": [], "dev": [], "test": []}
    for pid, split in of.items():
        by_split[split].append(pid)
    doc = {"procedures": by_split, "scenarios": dict.fromkeys(scenarios, "train")}
    path = tmp_path / "split.yaml"
    path.write_text(yaml.safe_dump(doc))
    return path


def write_scenario(tmp_path, doc: str = BASE) -> Path:
    path = tmp_path / "scenarios" / "one.yaml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(doc)
    return path


def settings(tmp_path, split_file: Path) -> Settings:
    (tmp_path / "cowrie").mkdir(exist_ok=True)
    (tmp_path / "cowrie/userdb.txt").write_text("root:x:secret-pw\n")
    return Settings(
        target_ip="172.26.0.2",
        out_dir=tmp_path / "out",
        profile_dir=tmp_path,
        time_scale=0,
        split_file=split_file,
    )


@pytest.fixture
def scripted(monkeypatch):
    """The runner's SSH driver replaced by the scripted one; the drivers it built."""
    made: list[Scripted] = []

    def factory(*args):
        made.append(type("D", (Scripted,), {"answers": GOOD})(*args))
        return made[-1]

    monkeypatch.setattr(runner, "SSHDriver", factory)
    return made


# ------------------------------------------------------------------ the split file


def test_the_frozen_split_loads_and_covers_the_catalogue():
    # The phase 2 split and the depth split beside it: between them, every procedure.
    split = load_split(ROOT / "eval/split.yaml")
    assert set(split.procedures.values()) == {"train", "dev", "test"}
    assert set(CATALOGUE.procedures) <= set(split.procedures)
    assert split.scenarios and set(split.scenarios.values()) <= {"train", "dev", "test"}
    # A depth procedure is held out: it is never a training procedure.
    depth = {pid for pid, which in CATALOGUE.set_of.items() if which == DEPTH}
    assert depth and {split.procedures[pid] for pid in depth} == {"dev", "test"}


def test_a_broken_split_file_is_an_error_not_an_empty_split(tmp_path):
    with pytest.raises(OSError):
        load_split(tmp_path / "absent.yaml")
    bad = tmp_path / "bad.yaml"
    for text in ("", "procedures: [a, b]\n", "scenarios: {}\n", "procedures: {train: 3}\n", "{"):
        bad.write_text(text)
        with pytest.raises(ValueError, match="not a split file"):
            load_split(bad)
    bad.write_text("procedures: {train: [owner-id], test: [owner-id]}\n")
    with pytest.raises(ValueError, match="in two splits"):
        load_split(bad)


def test_every_shipped_scenario_passes_the_lint_with_the_frozen_split_and_every_id():
    # What the runner now enforces before it sends anything.
    split = load_split(ROOT / "eval/split.yaml")
    scenarios = [Scenario.load(p) for p in sorted((ROOT / "lab/scenarios").rglob("*.yaml"))]
    ids = sorted({s.id for s in scenarios} | set(split.scenarios))
    found = [p for s in scenarios for p in lint(s, CATALOGUE, Slots.names(), split.procedures, ids)]
    assert found == []


# ------------------------------------------------------------------ every ID, not the step's own


def tiny_catalogue(tmp_path) -> Catalogue:
    (tmp_path / "cat").mkdir()
    (tmp_path / "cat/c.yaml").write_text(
        'attack_version: "20.1"\n'
        "procedures:\n"
        "  - {id: list-here, source: own, protocol: ssh, template: 'alpha {{dir}}'}\n"
        "  - {id: names-a-procedure, source: own, protocol: ssh, template: 'beta list-here'}\n"
        "  - {id: names-a-scenario, source: own, protocol: ssh, template: 'gamma other-case'}\n"
    )
    return Catalogue.load(tmp_path / "cat")


LEAKY = """
id: this-case
actor: {class: scripted_bot, timing: bot-fast}
sessions:
  - protocol: ssh
    steps:
      - {id: a, procedure: PROC}
"""


def test_lint_refuses_an_input_that_names_any_procedure_or_scenario(tmp_path):
    cat = tiny_catalogue(tmp_path)

    def found(proc: str, **kw) -> str:
        return " | ".join(lint(scenario(LEAKY.replace("PROC", proc)), cat, Slots.names(), **kw))

    assert found("list-here") == ""
    # another procedure's ID: the old check looked only for the step's own
    assert "contains the ID 'list-here'" in found("names-a-procedure")
    # another scenario's ID is known only if the caller says which scenarios exist
    assert found("names-a-scenario") == ""
    assert "contains the ID 'other-case'" in found("names-a-scenario", scenario_ids=["other-case"])
    # a value a scenario gives a slot is part of the input too
    given = LEAKY.replace("PROC", "list-here, with: {dir: /srv/names-a-procedure}")
    assert "contains the ID 'names-a-procedure'" in " | ".join(
        lint(scenario(given), cat, Slots.names())
    )


def test_a_drawn_value_that_names_another_procedure_is_never_sent(tmp_path):
    # The same check runs on every rendered input at send time, against the same IDs.
    slot = CATALOGUE.procedures["transfer-sftp-put"].slots()[0]

    def plant(actor):
        assert "owner-id" in actor.forbidden_ids and "test-one" in actor.forbidden_ids
        actor.slots.values[slot] = "owner-id.sh"  # as if the generator had drawn it

    made: list[Scripted] = []

    def factory(*args):
        made.append(type("D", (Scripted,), {"answers": GOOD})(*args))
        return made[-1]

    records, _actor, raised = drive(tmp_path, factory, prepare=plant)
    assert raised is None
    got = steps_of(records)
    assert got["e"] == ("skipped", "unchecked") and got["d"] == ("ran", "ok")
    assert not any("owner-id" in text for text in made[0].sent)


def test_an_actor_knows_the_ids_the_run_gives_it(tmp_path):
    from mirage_lab.runner import ActorRun
    from mirage_lab.truth import TruthWriter

    truth = TruthWriter(tmp_path / "gt")
    s = Settings(target_ip="172.26.0.2", out_dir=tmp_path, profile_dir=tmp_path)
    actor = ActorRun(
        scenario(BASE), 0, "198.18.0.9", "r1", CATALOGUE, s, truth, ["some-other-case"]
    )
    truth.close()
    assert set(CATALOGUE.procedures) | {"test-one", "some-other-case"} == set(actor.forbidden_ids)
    assert check_input("cat /srv/some-other-case.txt", actor.forbidden_ids)


def test_an_expect_that_is_not_a_regex_is_a_validation_error():
    with pytest.raises(ValidationError, match="not a regular expression"):
        scenario(BASE.replace('expect: "Linux"', 'expect: "(unclosed"'))


# ------------------------------------------------------------------ the runner


def test_the_runner_refuses_to_run_without_the_split(tmp_path, scripted):
    s = settings(tmp_path, tmp_path / "absent.yaml")
    with pytest.raises(ValueError, match="refusing to run: no frozen split at"):
        runner.run([write_scenario(tmp_path)], CATALOGUE, s)
    assert scripted == [] and not (tmp_path / "out").exists()  # nothing sent, nothing written


def test_the_runner_s_default_split_is_the_container_mount(tmp_path, monkeypatch):
    monkeypatch.delenv("LAB_SPLIT", raising=False)
    assert Settings("172.26.0.2", tmp_path, tmp_path).split_file == Path(DEFAULT_SPLIT)
    assert DEFAULT_SPLIT == "/lab/split.yaml"
    monkeypatch.setenv("LAB_SPLIT", "/elsewhere/split.yaml")
    assert Settings("172.26.0.2", tmp_path, tmp_path).split_file == Path("/elsewhere/split.yaml")


def test_the_runner_enforces_the_one_split_rule(tmp_path, scripted):
    mixed = write_split(tmp_path, {"owner-id": "test"})
    with pytest.raises(ValueError, match=r"lint failed, nothing was sent:\n.*mixes splits"):
        runner.run([write_scenario(tmp_path)], CATALOGUE, settings(tmp_path, mixed))
    assert scripted == []
    unassigned = tmp_path / "split.yaml"
    unassigned.write_text(yaml.safe_dump({"procedures": {"train": BASE_PROCS[:-1]}}))
    with pytest.raises(ValueError, match="uses a procedure with no split"):
        runner.run([write_scenario(tmp_path)], CATALOGUE, settings(tmp_path, unassigned))
    assert scripted == []


def test_the_runner_checks_inputs_against_the_split_s_scenario_ids(tmp_path, scripted):
    # A run of one scenario still knows the IDs of all of them: the split file lists them.
    doc = BASE.replace(
        "{id: c, procedure: files-list-dir}",
        "{id: c, procedure: files-list-dir, with: {dir: /srv/another-case}}",
    )
    assert "dir" in CATALOGUE.procedures["files-list-dir"].slots()
    path = write_scenario(tmp_path, doc)
    alone = write_split(tmp_path)
    assert runner.run([path], CATALOGUE, settings(tmp_path, alone)).errors == []
    known = write_split(tmp_path, scenarios=("test-one", "another-case"))
    with pytest.raises(ValueError, match="contains the ID 'another-case'"):
        runner.run([path], CATALOGUE, settings(tmp_path, known))


def test_a_run_with_the_split_writes_its_records_and_closes(tmp_path, scripted):
    s = settings(tmp_path, write_split(tmp_path))
    summary = runner.run([write_scenario(tmp_path)], CATALOGUE, s)
    assert summary.errors == [] and summary.sessions == 1 and summary.steps == {"ran": 6}
    (path,) = (tmp_path / "out").glob("groundtruth.json*")
    assert path.name == f"groundtruth.json.{summary.run_id}"  # one file per run (R5)
    records = [parse_record(json.loads(line)) for line in path.read_text().splitlines()]
    assert [r.kind for r in records].count("session") == 1 and records[-1].kind == "run"
    assert records[-1].sessions == 1 and records[-1].steps == 6


# ------------------------------------------------------------------ the CLI


def cli_lint(capsys, *args: str) -> tuple[int, str, str]:
    with pytest.raises(SystemExit) as exit_:
        cli.main(["--catalogue", str(ROOT / "lab/catalogue"), *args])
    out = capsys.readouterr()
    return exit_.value.code, out.out, out.err


def test_cli_lint_enforces_the_split(tmp_path, capsys):
    path = str(write_scenario(tmp_path))
    code, out, err = cli_lint(capsys, "--split", str(write_split(tmp_path)), "lint", path)
    assert (code, err) == (0, "") and "1 scenario(s), 0 problem(s)" in out
    mixed = str(write_split(tmp_path, {"owner-id": "dev"}))
    code, out, _err = cli_lint(capsys, "--split", mixed, "lint", path)
    assert code == 1 and "test-one: mixes splits ['dev', 'train']" in out


def test_cli_lint_warns_when_the_split_is_absent(tmp_path, capsys):
    path = str(write_scenario(tmp_path))
    code, out, err = cli_lint(capsys, "--split", str(tmp_path / "absent.yaml"), "lint", path)
    assert code == 0 and "0 problem(s)" in out
    assert "warning: no split file at" in err and "one-split rule was not checked" in err
    # a file that is there and unreadable as a split is not a warning
    (tmp_path / "bad.yaml").write_text("scenarios: {}\n")
    code, _out, _err = cli_lint(capsys, "--split", str(tmp_path / "bad.yaml"), "lint", path)
    assert "not a split file" in str(code)


def test_cli_finds_the_split(tmp_path, monkeypatch):
    monkeypatch.delenv("LAB_SPLIT", raising=False)
    assert cli._split_file(tmp_path / "given.yaml") == tmp_path / "given.yaml"
    monkeypatch.chdir(ROOT)  # a checkout: no container mount, so the repository's own copy
    if not Path(DEFAULT_SPLIT).exists():
        assert cli._split_file(None) == Path("eval/split.yaml")
    monkeypatch.chdir(tmp_path)  # neither: the mount's path, which the runner then refuses
    if not Path(DEFAULT_SPLIT).exists():
        assert cli._split_file(None) == Path(DEFAULT_SPLIT)
    monkeypatch.setenv("LAB_SPLIT", str(tmp_path / "env.yaml"))
    assert cli._split_file(None) == tmp_path / "env.yaml"
    assert cli._split_file(tmp_path / "given.yaml") == tmp_path / "given.yaml"


def test_cli_lint_in_a_checkout_uses_the_frozen_split_by_default(capsys, monkeypatch):
    monkeypatch.delenv("LAB_SPLIT", raising=False)
    monkeypatch.chdir(ROOT)
    code, out, err = cli_lint(capsys, "lint", "lab/scenarios")
    assert code == 0 and ", 0 problem(s)" in out
    assert "warning" not in err  # the split was found and the rule was checked


def test_cli_run_refuses_without_the_split(tmp_path, capsys, monkeypatch, scripted):
    monkeypatch.setattr(safety, "require_lab", lambda target: "172.26.0.2")
    monkeypatch.setenv("LAB_OUT", str(tmp_path / "out"))
    monkeypatch.setenv("PROFILE_DIR", str(tmp_path))
    code, _out, _err = cli_lint(
        capsys, "--split", str(tmp_path / "absent.yaml"), "run", str(write_scenario(tmp_path))
    )
    assert "refusing to run: no frozen split at" in str(code)
    assert scripted == [] and not (tmp_path / "out").exists()


def test_cli_run_checks_the_target_before_the_split(tmp_path, capsys, monkeypatch):
    # The isolation check still comes first: nothing else is looked at outside the lab.
    monkeypatch.setattr(safety, "ROUTE4", tmp_path / "no-proc")
    code, _out, _err = cli_lint(
        capsys, "--split", str(tmp_path / "absent.yaml"), "run", str(write_scenario(tmp_path))
    )
    assert "refusing to run: no /proc/net/route" in str(code)
