"""What lives on the runner's volume and must not wrap or grow without bound (gap register R5):
the address counter and the ground-truth files.
"""

from __future__ import annotations

import fnmatch
import os
import random
import time
from pathlib import Path

import pytest
import yaml
from test_lab import BASE, CATALOGUE, ROOT

from mirage_lab import cli, runner, safety
from mirage_lab.net import PORT_HI, PORT_LO, RANGES, AddressesExhausted, AddressPool, Dialer
from mirage_lab.runner import Settings
from mirage_lab.truth import KEEP_DAYS, TRUTH_NAME, TruthWriter, prune, run_file

USABLE = RANGES["capture"].num_addresses - 2

# ------------------------------------------------------------------ addresses


def test_the_pool_hands_out_its_last_address_and_then_refuses(tmp_path):
    state = tmp_path / "addresses.capture"
    state.write_text(str(USABLE - 2))
    pool = AddressPool(state, "capture")
    assert pool.take(2) == ["198.18.255.253", "198.18.255.254"]  # the last two; .255 is broadcast
    with pytest.raises(AddressesExhausted, match="never reused"):
        pool.take(1)
    assert state.read_text() == str(USABLE)  # a refusal takes nothing
    assert pool.take(0) == []


def test_a_request_larger_than_what_is_left_takes_nothing(tmp_path):
    # It used to wrap: the request was served, and its tail reused the range's first addresses.
    state = tmp_path / "addresses.explore"
    state.write_text(str(USABLE - 3))
    pool = AddressPool(state, "explore")
    with pytest.raises(AddressesExhausted, match=r"5 address\(es\) wanted, 3 of 65534 left"):
        pool.take(5)
    assert state.read_text() == str(USABLE - 3)
    assert pool.take(3)[-1] == "198.19.255.254"


def test_a_run_that_needs_more_addresses_than_remain_sends_and_writes_nothing(
    tmp_path, monkeypatch
):
    built = []
    monkeypatch.setattr(runner, "SSHDriver", lambda *a: built.append(a))
    (tmp_path / "one.yaml").write_text(BASE)
    split = tmp_path / "split.yaml"
    procs = {
        "ssh-password-guessing", "sysinfo-uname-all", "probe-missing-tool", "files-list-dir",
        "owner-id", "transfer-sftp-put",
    }  # fmt: skip
    split.write_text(yaml.safe_dump({"procedures": {"train": sorted(procs)}}))
    out = tmp_path / "out"
    out.mkdir()
    (out / "addresses.capture").write_text(str(USABLE - 1))
    settings = Settings("172.26.0.2", out, tmp_path, repeat=2, split_file=split)
    with pytest.raises(AddressesExhausted):
        runner.run([tmp_path / "one.yaml"], CATALOGUE, settings)
    assert built == [] and list(out.glob(TRUTH_NAME + "*")) == []
    # ... and the CLI says so instead of printing a traceback
    monkeypatch.setattr(safety, "require_lab", lambda target: "172.26.0.2")
    monkeypatch.setenv("LAB_OUT", str(out))
    with pytest.raises(SystemExit, match="refusing to run: 2 address"):
        cli.main(
            ["--catalogue", str(ROOT / "lab/catalogue"), "--split", str(split), "run",
             str(tmp_path / "one.yaml"), "--repeat", "2"]
        )  # fmt: skip


def test_a_dialer_never_gives_one_address_the_same_port_twice(monkeypatch):
    class Sock:
        def setsockopt(self, *a):
            pass

        def sendall(self, data):
            pass

    monkeypatch.setattr("mirage_lab.net.socket.create_connection", lambda *a, **k: Sock())
    dialer = Dialer("172.26.0.2", "198.18.0.9", random.Random(3))
    ports = [dialer.connect(2222).src_port for _ in range(PORT_HI - PORT_LO + 1)]
    assert len(set(ports)) == len(ports) == PORT_HI - PORT_LO + 1  # every port, once
    with pytest.raises(RuntimeError, match="every source port once"):
        dialer.connect(2222)


# ------------------------------------------------------------------ ground-truth files


def aged(path: Path, days: float) -> Path:
    path.write_text("{}\n")
    then = time.time() - days * 86400
    os.utime(path, (then, then))
    return path


def test_prune_removes_only_ground_truth_no_run_has_touched_for_the_keep_time(tmp_path):
    old = aged(run_file(tmp_path, "r20260101000000-aaaaaa"), KEEP_DAYS + 1)
    legacy = aged(tmp_path / TRUTH_NAME, KEEP_DAYS + 30)  # the single file of earlier versions
    recent = aged(run_file(tmp_path, "r20261114000000-bbbbbb"), KEEP_DAYS - 1)
    counter = aged(tmp_path / "addresses.capture", KEEP_DAYS + 30)  # never a ground-truth file
    assert prune(tmp_path) == [legacy, old]
    assert recent.exists() and counter.exists() and not old.exists() and not legacy.exists()
    assert prune(tmp_path) == []


def test_prune_can_be_turned_off_and_survives_a_missing_directory(tmp_path):
    old = aged(run_file(tmp_path, "r20260101000000-aaaaaa"), 400)
    assert prune(tmp_path, 0) == [] and old.exists()
    assert prune(tmp_path / "absent") == []
    assert prune(tmp_path, 1) == [old]


def test_a_file_being_written_is_never_pruned(tmp_path):
    path = aged(run_file(tmp_path, "r20260101000000-aaaaaa"), 400)
    writer = TruthWriter(path)  # a run in flight: every record it writes refreshes the file
    writer._file.write("{}\n")
    writer.close()
    assert prune(tmp_path) == [] and path.exists()


def test_each_run_s_file_is_one_vector_already_reads():
    # The rotation relies on the include pattern of Vector's ground-truth source, which is not
    # the lab's to change. If that pattern changes, per-run files stop being shipped.
    config = yaml.safe_load((ROOT / "compose/vector/vector.yaml").read_text())
    (pattern,) = config["sources"]["sim_log"]["include"]
    assert pattern == "/lab-out/groundtruth.json*"
    path = run_file(Path("/lab-out"), "r20261114120000-0a1b2c")
    assert fnmatch.fnmatch(str(path), pattern)
    assert not fnmatch.fnmatch("/lab-out/addresses.capture", pattern)
