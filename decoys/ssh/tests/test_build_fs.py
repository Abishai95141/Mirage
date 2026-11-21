"""The SSH decoy's filesystem builder (decoys/ssh/build_fs.py), the part that needs no image.

The builder runs inside the Cowrie image and imports Cowrie's ``createfs`` for the layout of
a tree node. Here that module is a stand-in with the same constants, so what the builder
adds to the tree can be checked without Cowrie.
"""

from __future__ import annotations

import importlib.util
import stat
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
BOOT = 1_760_000_000


@pytest.fixture
def build_fs(monkeypatch):
    cf = types.ModuleType("cowrie.scripts.createfs")
    names = "A_NAME A_TYPE A_UID A_GID A_SIZE A_MODE A_CTIME A_CONTENTS A_TARGET A_REALFILE"
    for index, name in enumerate(names.split()):
        setattr(cf, name, index)
    for index, name in enumerate(
        ["T_LINK", "T_DIR", "T_FILE", "T_BLK", "T_CHR", "T_SOCK", "T_FIFO"]
    ):
        setattr(cf, name, index)
    cf.EMBED_PATHS = ()
    for name, module in (
        ("cowrie", types.ModuleType("cowrie")),
        ("cowrie.scripts", types.ModuleType("cowrie.scripts")),
        ("cowrie.scripts.createfs", cf),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    sys.modules["cowrie.scripts"].createfs = cf
    spec = importlib.util.spec_from_file_location("build_fs", ROOT / "decoys/ssh/build_fs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def root(cf) -> list:
    return ["/", cf.T_DIR, 0, 0, 4096, stat.S_IFDIR | 0o755, 1_700_000_000, [], None, None]


def test_dev_gets_what_the_kernel_puts_there(build_fs):
    cf, tree = build_fs.cf, root(build_fs.cf)
    build_fs.ensure_dir(tree, "/dev")  # as it comes out of an image: there, and empty
    build_fs.add_dev(tree, BOOT)

    dev = build_fs.find(tree, "/dev")
    nodes = {c[cf.A_NAME]: c for c in dev[cf.A_CONTENTS]}
    assert {"null", "zero", "full", "random", "urandom", "tty", "ptmx", "console"} <= set(nodes)
    assert {"pts", "shm", "fd", "stdin", "stdout", "stderr"} <= set(nodes)
    # Every node is a whole tree entry, of the kind and with the mode a real one has.
    assert all(len(c) == 10 for c in nodes.values())
    null = nodes["null"]
    assert null[cf.A_TYPE] == cf.T_CHR and stat.S_ISCHR(null[cf.A_MODE])
    assert stat.S_IMODE(null[cf.A_MODE]) == 0o666 and null[cf.A_SIZE] == 0
    assert stat.S_IMODE(nodes["shm"][cf.A_MODE]) == 0o1777 and nodes["shm"][cf.A_TYPE] == cf.T_DIR
    assert nodes["tty"][cf.A_GID] == 5 and stat.S_IMODE(nodes["console"][cf.A_MODE]) == 0o620
    out = nodes["stdout"]
    assert out[cf.A_TYPE] == cf.T_LINK and stat.S_ISLNK(out[cf.A_MODE])
    assert out[cf.A_TARGET] == "/proc/self/fd/1" and out[cf.A_SIZE] == len("/proc/self/fd/1")
    # They date from the boot, not from the day the reference image was built.
    assert {c[cf.A_CTIME] for c in nodes.values()} == {BOOT} and dev[cf.A_CTIME] == BOOT
    # Nothing of one machine's own hardware: that is the hardware classes' to decide.
    assert not {n for n in nodes if n.startswith(("sd", "vd", "nvme", "ttyS", "loop"))}


def test_adding_dev_twice_or_over_an_existing_node_changes_nothing(build_fs):
    cf, tree = build_fs.cf, root(build_fs.cf)
    dev = build_fs.ensure_dir(tree, "/dev")
    kept = ["null", cf.T_FILE, 0, 0, 7, stat.S_IFREG | 0o600, 1, [], None, None]
    dev[cf.A_CONTENTS].append(kept)
    build_fs.add_dev(tree, BOOT)
    count = len(dev[cf.A_CONTENTS])
    build_fs.add_dev(tree, BOOT + 60)
    assert len(dev[cf.A_CONTENTS]) == count == len(build_fs.DEV_NODES)
    assert build_fs.find(tree, "/dev/null") is kept and kept[cf.A_SIZE] == 7


def test_a_root_with_no_dev_at_all_gets_one(build_fs):
    tree = root(build_fs.cf)
    build_fs.add_dev(tree, BOOT)
    assert build_fs.find(tree, "/dev/null") is not None


LISTING = "\n".join(
    [
        "d\t755\t0\t0\t3200\t/dev\t",
        "c\t666\t0\t0\t0\t/dev/null\t",
        "b\t660\t0\t6\t0\t/dev/vda\t",
        "b\t660\t0\t6\t0\t/dev/vda1\t",
        "d\t755\t0\t0\t60\t/dev/disk\t",
        "d\t755\t0\t0\t80\t/dev/disk/by-uuid\t",
        "l\t777\t0\t0\t10\t/dev/disk/by-uuid/5015-40a8\t../../vda1",
        "c\t660\t0\t20\t0\t/dev/ttyS0\t",
        "p\t600\t0\t0\t0\t/dev/initctl\t",
        "not a line of the listing",
        "x\t644\t0\t0\t0\t/dev/unknown-type\t",
    ]
)


def test_a_class_s_tree_is_added_node_for_node(build_fs):
    cf, tree = build_fs.cf, root(build_fs.cf)
    assert build_fs.add_tree(tree, LISTING, BOOT) == 6  # the directories are not counted
    disk = build_fs.find(tree, "/dev/vda")
    assert disk[cf.A_TYPE] == cf.T_BLK and stat.S_ISBLK(disk[cf.A_MODE])
    assert (disk[cf.A_UID], disk[cf.A_GID], stat.S_IMODE(disk[cf.A_MODE])) == (0, 6, 0o660)
    link = build_fs.find(tree, "/dev/disk/by-uuid/5015-40a8")
    assert link[cf.A_TYPE] == cf.T_LINK and link[cf.A_TARGET] == "../../vda1"
    assert build_fs.find(tree, "/dev/initctl")[cf.A_TYPE] == cf.T_FIFO
    assert build_fs.find(tree, "/dev/ttyS0")[cf.A_GID] == 20
    assert build_fs.find(tree, "/dev")[cf.A_SIZE] == 4096  # a directory's size is Cowrie's
    assert build_fs.find(tree, "/dev/unknown-type") is None
    assert all(len(c) == 10 for c in build_fs.find(tree, "/dev")[cf.A_CONTENTS])
    assert build_fs.find(tree, "/dev/vda1")[cf.A_CTIME] == BOOT
    # Again, or after the fallback nodes: nothing is added twice, and the class's node wins.
    assert build_fs.add_tree(tree, LISTING, BOOT) == 0
    build_fs.add_dev(tree, BOOT)
    names = [c[cf.A_NAME] for c in build_fs.find(tree, "/dev")[cf.A_CONTENTS]]
    assert names.count("null") == 1 and "zero" in names and "vda" in names


def test_a_directory_that_exists_takes_the_recorded_owner_and_mode(build_fs):
    cf, tree = build_fs.cf, root(build_fs.cf)
    build_fs.ensure_dir(tree, "/sys")
    build_fs.add_tree(tree, "d\t555\t0\t0\t0\t/sys\t\nf\t444\t0\t0\t4096\t/sys/x\t", BOOT)
    sysdir = build_fs.find(tree, "/sys")
    assert stat.S_IMODE(sysdir[cf.A_MODE]) == 0o555 and sysdir[cf.A_CTIME] == BOOT
    assert build_fs.find(tree, "/sys/x")[cf.A_SIZE] == 4096


def test_a_link_says_what_it_says_on_the_reference_host(build_fs, tmp_path):
    cf = sys.modules["cowrie.scripts.createfs"]
    (tmp_path / "usr/bin").mkdir(parents=True)
    (tmp_path / "usr/lib").mkdir()
    (tmp_path / "etc").mkdir()
    (tmp_path / "usr/lib/os-release").write_text("ID=debian\n")
    (tmp_path / "bin").symlink_to("usr/bin")
    (tmp_path / "etc/os-release").symlink_to("../usr/lib/os-release")
    (tmp_path / "etc/mtab").symlink_to("/proc/self/mounts")
    tree = root(cf)

    def link(name: str, where_it_ends: str) -> list:
        # createfs records the resolved path, not the link's own text
        return [name, cf.T_LINK, 0, 0, 99, stat.S_IFLNK | 0o777, BOOT, [], where_it_ends, None]

    etc = ["etc", cf.T_DIR, 0, 0, 4096, stat.S_IFDIR | 0o755, BOOT, [], None, None]
    etc[cf.A_CONTENTS] += [
        link("os-release", "/usr/lib/os-release"),
        link("mtab", "/proc/self/mounts"),
    ]
    gone = link("gone", "/nowhere")  # in the tree and not in the root: left as it is
    tree[cf.A_CONTENTS] += [link("bin", "/usr/bin"), etc, gone]
    assert build_fs.true_links(tree, tmp_path) == 2
    said = {
        n[cf.A_NAME]: (n[cf.A_TARGET], n[cf.A_SIZE])
        for n in [tree[cf.A_CONTENTS][0], *etc[cf.A_CONTENTS]]
    }
    assert said == {
        "bin": ("usr/bin", 7),
        "os-release": ("../usr/lib/os-release", 21),
        "mtab": ("/proc/self/mounts", 17),
    }
    assert gone[cf.A_TARGET] == "/nowhere"


def test_the_images_own_checksums_are_recorded_for_what_the_tree_does_not_hold(build_fs, tmp_path):
    import hashlib
    import sqlite3

    cf = build_fs.cf
    ref = tmp_path / "ref"
    (ref / "usr/bin").mkdir(parents=True)
    (ref / "etc").mkdir()
    program = b"\x7fELF" + b"\x00" * 4000
    (ref / "usr/bin/ls").write_bytes(program)
    (ref / "usr/bin/changed").write_bytes(b"another size than the tree says")
    (ref / "etc/hostname").write_text("ref-host\n")
    (ref / "usr/bin/sh").symlink_to("ls")

    def file(name: str, size: int, contents=None, real=None) -> list:
        return [name, cf.T_FILE, 0, 0, size, stat.S_IFREG | 0o755, BOOT, contents or [], None, real]

    tree = root(cf)
    usr_bin = build_fs.ensure_dir(tree, "/usr/bin")
    usr_bin[cf.A_CONTENTS] += [
        file("ls", len(program)),
        file("changed", 7),  # not the size the reference has: no entry
        file("absent", 9),  # not in the reference at all (a hardware class's file)
        ["sh", cf.T_LINK, 0, 0, 2, stat.S_IFLNK | 0o777, BOOT, [], "ls", None],
    ]
    etc = build_fs.ensure_dir(tree, "/etc")
    # Its bytes are in the tree: hashed from them when asked for, so not in the table.
    etc[cf.A_CONTENTS] += [file("hostname", 9, contents=b"web01\n"), file("empty", 0)]

    out = tmp_path / "hashes.db"
    assert build_fs.write_hashes(tree, ref, out) == 1
    db = sqlite3.connect(out)
    rows = db.execute("SELECT path, md5, sha1, sha256, sha512 FROM hashes").fetchall()
    assert [r[0] for r in rows] == ["/usr/bin/ls"]
    for value, name in zip(rows[0][1:], build_fs.HASHES, strict=True):
        assert value == hashlib.new(name, program).digest()
    # The builder is run again on every image build: it starts from nothing each time.
    assert build_fs.write_hashes(tree, ref, out) == 1
