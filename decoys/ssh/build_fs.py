"""Build Cowrie's filesystem for one deployment, inside the image build (decoys/ssh/Dockerfile).

    build_fs.py <refroot> <profile-cowrie-dir> <out-dir>

The tree is a real Debian 12 root (the reference image, so nginx, Redis and MariaDB are where
the profile says they are), walked with Cowrie's own ``createfs``. Then the deployment's
profile is applied on top: its users' home directories, its web files, and its versions of
the identity files (/etc/hostname, /etc/passwd, /etc/shadow, ...). Writes:

    <out>/fs.pickle   Cowrie's tree (metadata, plus embedded contents for a few files)
    <out>/honeyfs/    file contents Cowrie serves: small text files from the reference /etc,
                      overridden by the profile's files
    <out>/txtcmds/    the profile's fixed-text commands, if it has a hardware class
    <out>/rendered.json  the profile's render library, which the fork answers from
    <out>/processes.json the profile's process list, which the fork's `ps` prints
    <out>/hashes.db   the real checksums of the image's own programs, for `md5sum` and the
                      like: the tree holds their names and sizes, not their bytes

This runs inside the Cowrie image with Cowrie's own code; the pickle is only ever read by
Cowrie, which already trusts its filesystem file.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from pathlib import Path

from cowrie.scripts import createfs as cf

# Present in the reference image only because of how it is built and probed.
REFERENCE_ONLY = {
    "/ready",
    "/ref-kernel.txt",
    "/ref-kernel-changelog.txt",
    "/entrypoint.sh",
    "/.dockerenv",
}
# Never copied into honeyfs: real secrets of the reference image. The profile supplies its own
# /etc/shadow; the rest simply read as empty or unreadable, as for a non-root user.
SECRET = (
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/ssh/ssh_host_",
    "/etc/mysql/debian.cnf",
    "/etc/ssl/private",
)
MAX_TEXT = 64 * 1024
# What the kernel puts in /dev on every running Linux system. The reference root is copied out
# of an image, and an image's /dev is empty: without these the decoy has no /dev/null, which
# any `cat /dev/null > file` shows at once (found by phase 3's depth baseline). Names, types,
# groups and modes as on Debian 12; they are the same on every host. A machine's own devices
# (disks, serial consoles, the virtual terminals) depend on its hardware and are not here:
# they come with the hardware classes of phase 3 (spec 3.2a).
TTY_GID = 5
DEV_NODES = (
    # name, type, gid, mode, link target
    ("null", cf.T_CHR, 0, 0o666, None),
    ("zero", cf.T_CHR, 0, 0o666, None),
    ("full", cf.T_CHR, 0, 0o666, None),
    ("random", cf.T_CHR, 0, 0o666, None),
    ("urandom", cf.T_CHR, 0, 0o666, None),
    ("tty", cf.T_CHR, TTY_GID, 0o666, None),
    ("ptmx", cf.T_CHR, TTY_GID, 0o666, None),
    ("console", cf.T_CHR, TTY_GID, 0o620, None),
    ("pts", cf.T_DIR, 0, 0o755, None),
    ("shm", cf.T_DIR, 0, 0o1777, None),
    ("mqueue", cf.T_DIR, 0, 0o1777, None),
    ("fd", cf.T_LINK, 0, 0o777, "/proc/self/fd"),
    ("stdin", cf.T_LINK, 0, 0o777, "/proc/self/fd/0"),
    ("stdout", cf.T_LINK, 0, 0o777, "/proc/self/fd/1"),
    ("stderr", cf.T_LINK, 0, 0o777, "/proc/self/fd/2"),
    ("core", cf.T_LINK, 0, 0o777, "/proc/kcore"),
)
_KIND = {cf.T_CHR: stat.S_IFCHR, cf.T_DIR: stat.S_IFDIR, cf.T_LINK: stat.S_IFLNK}


def find(tree: list, path: str) -> list | None:
    node = tree
    for part in [p for p in path.split("/") if p]:
        nxt = next((c for c in node[cf.A_CONTENTS] if c[cf.A_NAME] == part), None)
        if nxt is None:
            return None
        node = nxt
    return node


def ensure_dir(tree: list, path: str, uid: int = 0, gid: int = 0, mode: int = 0o755) -> list:
    node = tree
    for part in [p for p in path.split("/") if p]:
        nxt = next((c for c in node[cf.A_CONTENTS] if c[cf.A_NAME] == part), None)
        if nxt is None:
            nxt = [
                part,
                cf.T_DIR,
                uid,
                gid,
                4096,
                stat.S_IFDIR | mode,
                node[cf.A_CTIME],
                [],
                None,
                None,
            ]
            node[cf.A_CONTENTS].append(nxt)
        node = nxt
    return node


HASHES = ("md5", "sha1", "sha256", "sha512")


def write_hashes(tree: list, ref: Path, out: Path) -> int:
    """Record the reference root's own checksums for every regular file of the tree whose
    bytes the tree does not hold, and return how many. The fork's `md5sum`, `sha1sum`,
    `sha256sum` and `sha512sum` answer from this table for those files (they hash a file
    whose contents the tree has, and one a session wrote, directly). A file that is not in
    the reference root, or whose size there differs from the tree's, gets no entry: the
    command then declines, which is better than a checksum that anyone can compare with
    Debian's and find wrong."""
    import hashlib
    import sqlite3

    if out.exists():
        out.unlink()
    db = sqlite3.connect(out)
    columns = ", ".join(f"{name} BLOB" for name in HASHES)
    db.execute(f"CREATE TABLE hashes (path TEXT PRIMARY KEY, {columns}) WITHOUT ROWID")
    rows = []

    def walk(node: list, path: str) -> None:
        for child in node[cf.A_CONTENTS]:
            here = f"{path.rstrip('/')}/{child[cf.A_NAME]}"
            if child[cf.A_TYPE] == cf.T_DIR:
                walk(child, here)
                continue
            if child[cf.A_TYPE] != cf.T_FILE or isinstance(child[cf.A_CONTENTS], bytes):
                continue
            real = ref / here.lstrip("/")
            if child[cf.A_REALFILE] or child[cf.A_SIZE] <= 0 or real.is_symlink():
                continue
            try:
                if not real.is_file() or real.stat().st_size != child[cf.A_SIZE]:
                    continue
                digests = [hashlib.new(name) for name in HASHES]
                with real.open("rb") as fh:
                    while chunk := fh.read(1 << 20):
                        for digest in digests:
                            digest.update(chunk)
            except OSError:
                continue
            rows.append((here, *[d.digest() for d in digests]))

    walk(tree, "/")
    db.executemany("INSERT INTO hashes VALUES (?, ?, ?, ?, ?)", rows)
    db.commit()
    db.execute("VACUUM")
    db.close()
    return len(rows)


def remove(tree: list, path: str) -> None:
    parent = find(tree, os.path.dirname(path) or "/")
    if parent is not None:
        parent[cf.A_CONTENTS][:] = [
            c for c in parent[cf.A_CONTENTS] if c[cf.A_NAME] != os.path.basename(path)
        ]


def add_dev(tree: list, when: int) -> None:
    """Put the kernel's own nodes in /dev, dated ``when`` (they appear at boot). A name the
    reference root already has is left as it is."""
    dev = ensure_dir(tree, "/dev")
    dev[cf.A_CTIME] = when
    have = {c[cf.A_NAME] for c in dev[cf.A_CONTENTS]}
    for name, kind, gid, mode, target in DEV_NODES:
        if name in have:
            continue
        size = 4096 if kind == cf.T_DIR else (len(target) if target else 0)
        dev[cf.A_CONTENTS].append(
            [name, kind, 0, gid, size, _KIND[kind] | mode, when, [], target, None]
        )


# A line of a hardware class's tree listing starts with find's letter for the node's type.
_TREE_KIND = {
    "f": (cf.T_FILE, stat.S_IFREG),
    "d": (cf.T_DIR, stat.S_IFDIR),
    "l": (cf.T_LINK, stat.S_IFLNK),
    "c": (cf.T_CHR, stat.S_IFCHR),
    "b": (cf.T_BLK, stat.S_IFBLK),
    "s": (cf.T_SOCK, stat.S_IFSOCK),
    "p": (cf.T_FIFO, stat.S_IFIFO),
}


def add_tree(tree: list, listing: str, when: int) -> int:
    """Add the nodes a hardware class recorded for a directory the kernel fills (/dev, /proc,
    /sys) or the boot loader does (/boot). One line a node: type, mode, owner, group, size,
    path, link target (decoys/profiles: hardware.py). A directory that is already there
    takes the recorded owner and mode; any other node already there is left as it is.
    Returns how many nodes were added."""
    added = 0
    for line in listing.splitlines():
        cols = line.split("\t")
        if len(cols) < 6 or cols[0] not in _TREE_KIND or not cols[5].startswith("/"):
            continue
        letter, mode, uid, gid, size, path = cols[:6]
        target = cols[6] if len(cols) > 6 and cols[6] else None
        kind, fmt = _TREE_KIND[letter]
        if kind == cf.T_DIR:
            node = ensure_dir(tree, path)
            node[cf.A_UID], node[cf.A_GID] = int(uid), int(gid)
            node[cf.A_MODE], node[cf.A_CTIME] = stat.S_IFDIR | int(mode, 8), when
            continue
        parent = ensure_dir(tree, os.path.dirname(path))
        name = os.path.basename(path)
        if any(c[cf.A_NAME] == name for c in parent[cf.A_CONTENTS]):
            continue
        parent[cf.A_CONTENTS].append(
            [name, kind, int(uid), int(gid), int(size), fmt | int(mode, 8), when, [], target, None]
        )
        added += 1
    return added


def true_links(tree: list, ref: Path) -> int:
    """Give every symbolic link the text it has in the reference root. Cowrie's ``createfs``
    records where a link ends up (``/bin -> /usr/bin``), but ``ls -l``, ``readlink`` and
    ``stat`` show what the link says (``/bin -> usr/bin``), and its size is the length of
    that. Returns how many links were corrected."""
    corrected = 0

    def walk(node: list, path: str) -> None:
        nonlocal corrected
        for child in node[cf.A_CONTENTS]:
            here = f"{path.rstrip('/')}/{child[cf.A_NAME]}"
            if child[cf.A_TYPE] == cf.T_LINK:
                try:
                    text = os.readlink(ref / here.lstrip("/"))
                except OSError:
                    continue
                if text != child[cf.A_TARGET]:
                    corrected += 1
                child[cf.A_TARGET], child[cf.A_SIZE] = text, len(text)
            elif child[cf.A_TYPE] == cf.T_DIR:
                walk(child, here)

    walk(tree, "/")
    return corrected


def hash_path(path: str) -> int:
    import hashlib

    return int(hashlib.sha256(path.encode()).hexdigest()[:8], 16)


def is_text(data: bytes) -> bool:
    return b"\0" not in data[:4096]


def main(refroot: str, profile: str, out: str) -> None:
    ref, prof, dst = Path(refroot), Path(profile), Path(out)
    dst.mkdir(parents=True, exist_ok=True)
    s = os.stat(ref)
    tree = ["/", cf.T_DIR, 0, 0, 4096, s.st_mode, int(s.st_mtime), [], None, None]
    cf.recurse(str(ref), "/", tree[cf.A_CONTENTS], 100)
    print(f"links: {true_links(tree, ref)} given the text they have on the reference host")

    overlay = json.loads((prof / "fs-overlay.json").read_text())
    for p in list(REFERENCE_ONLY) + overlay["remove"]:
        remove(tree, p)
    # The profile's hardware class, where it has one: the kernel image and modules it boots
    # from go in now, so that they are dated with the rest of the installation below.
    trees = prof / "tree"
    if (trees / "boot.tsv").exists():
        add_tree(tree, (trees / "boot.tsv").read_text(), int(s.st_mtime) + 86400 * 365)

    # honeyfs: the reference's small text files under /etc, then the profile's files on top.
    honeyfs = dst / "honeyfs"
    etc = ref / "etc"
    for f in etc.rglob("*"):
        virt = "/" + str(f.relative_to(ref))
        if (
            not f.is_file()
            or f.is_symlink()
            or virt.startswith(SECRET)
            or f.stat().st_size > MAX_TEXT
        ):
            continue
        data = f.read_bytes()
        if is_text(data):
            target = honeyfs / virt.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    prof_fs = prof / "honeyfs"
    for f in prof_fs.rglob("*"):
        if f.is_file():
            target = honeyfs / f.relative_to(prof_fs)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, target)

    # Apply the overlay's owners and modes, creating what the reference lacks.
    for entry in overlay["add"]:
        path, uid, gid, mode = entry["path"], entry["uid"], entry["gid"], entry["mode"]
        if entry["dir"]:
            node = ensure_dir(tree, path, uid, gid, mode)
            node[cf.A_UID], node[cf.A_GID], node[cf.A_MODE] = uid, gid, stat.S_IFDIR | mode
            continue
        parent = ensure_dir(tree, os.path.dirname(path))
        node = find(tree, path)
        if node is None:
            node = [
                os.path.basename(path),
                cf.T_FILE,
                uid,
                gid,
                0,
                stat.S_IFREG | mode,
                parent[cf.A_CTIME],
                [],
                None,
                None,
            ]
            parent[cf.A_CONTENTS].append(node)
        node[cf.A_UID], node[cf.A_GID], node[cf.A_MODE] = uid, gid, stat.S_IFREG | mode

    # A profile file at a symlinked path (Debian's /etc/os-release -> ../usr/lib/os-release)
    # must also be the link target's contents, or `cat` follows the link to nothing.
    for f in list(prof_fs.rglob("*")):
        if not f.is_file():
            continue
        virt = "/" + str(f.relative_to(prof_fs))
        node = find(tree, virt)
        if node is not None and node[cf.A_TYPE] == cf.T_LINK:
            target = os.path.normpath(os.path.join(os.path.dirname(virt), node[cf.A_TARGET]))
            out_file = honeyfs / target.lstrip("/")
            out_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, out_file)

    # The reference image was built today, so everything apt created carries today's date: a
    # freshly installed host. Move anything newer than the reference's own package files back
    # to this deployment's install date, spread deterministically over a few hours.
    install = overlay["install_epoch"]
    newest_pkg = os.stat(ref / "usr/share/doc/debian-archive-keyring").st_mtime + 86400

    def age(node: list, path: str) -> None:
        if node[cf.A_CTIME] > newest_pkg:
            node[cf.A_CTIME] = install + (hash_path(path) % 14400)
        if node[cf.A_TYPE] == cf.T_DIR:
            for c in node[cf.A_CONTENTS]:
                age(c, f"{path.rstrip('/')}/{c[cf.A_NAME]}")

    age(tree, "/")
    # After the ageing, so the nodes keep the date they are given: the last boot, a little
    # into it. A profile rendered before the overlay carried that date gets the install date.
    boot = overlay.get("boot_epoch", install) + 3
    if trees.is_dir():
        # What the kernel of this hardware class shows in the directories it fills.
        for name in ("dev.tsv", "proc.tsv", "sys.tsv"):
            if (trees / name).exists():
                n = add_tree(tree, (trees / name).read_text(), boot)
                print(f"{name}: {n} nodes")
    add_dev(tree, boot)  # the few every system has, if the class did not bring them
    for entry in overlay["add"]:
        node = find(tree, entry["path"])
        if node is not None:
            node[cf.A_CTIME] = install + 86400 * (3 + hash_path(entry["path"]) % 40)

    # Every honeyfs file's size, and embedded contents where createfs embedded the reference's,
    # must be the profile's version, or `ls -l` and `cat` would disagree.
    for f in honeyfs.rglob("*"):
        if not f.is_file():
            continue
        virt = "/" + str(f.relative_to(honeyfs))
        node = find(tree, virt)
        kernel = virt.startswith(("/proc/", "/sys/"))
        if node is None and kernel:
            # A kernel file the profile has contents for and the recorded tree did not go
            # deep enough to list.
            parent = ensure_dir(tree, os.path.dirname(virt), mode=0o555)
            size = 4096 if virt.startswith("/sys/") else 0
            node = [os.path.basename(virt), cf.T_FILE, 0, 0, size, stat.S_IFREG | 0o444,
                    parent[cf.A_CTIME], [], None, None]  # fmt: skip
            parent[cf.A_CONTENTS].append(node)
        if node is None or node[cf.A_TYPE] != cf.T_FILE:
            continue
        data = f.read_bytes()
        if not kernel:  # the kernel's files have no length: 0 in /proc, a page in /sys
            node[cf.A_SIZE] = len(data)
        if isinstance(node[cf.A_CONTENTS], bytes) or virt in cf.EMBED_PATHS:
            node[cf.A_CONTENTS] = data
    # Embedded secrets of the reference must not survive where the profile gave no override.
    for virt in cf.EMBED_PATHS:
        node = find(tree, virt)
        if (
            node is not None
            and virt.startswith(SECRET)
            and not (honeyfs / virt.lstrip("/")).exists()
        ):
            node[cf.A_CONTENTS] = b""

    # The profile's fixed-text commands (its hardware class's own output for the reporting
    # commands Cowrie answers from a text file), where it has any: Cowrie looks here first.
    if (prof / "txtcmds").is_dir():
        shutil.copytree(prof / "txtcmds", dst / "txtcmds", dirs_exist_ok=True)
    for name in ("rendered.json", "processes.json"):
        if (prof / name).is_file():
            shutil.copy(prof / name, dst / name)

    # After everything that changes the tree: the table is of the tree as it will be served.
    # A file the profile or honeyfs supplies is hashed from its own bytes when asked for.
    served = {"/" + str(f.relative_to(honeyfs)) for f in honeyfs.rglob("*") if f.is_file()}
    for virt in served:
        node = find(tree, virt)
        if node is not None and not isinstance(node[cf.A_CONTENTS], bytes):
            node[cf.A_REALFILE] = "honeyfs"  # a marker for write_hashes only; not pickled so
    print(f"hashes.db: {write_hashes(tree, ref, dst / 'hashes.db')} files' checksums recorded")
    for virt in served:
        node = find(tree, virt)
        if node is not None and node[cf.A_REALFILE] == "honeyfs":
            node[cf.A_REALFILE] = None

    import pickle

    with open(dst / "fs.pickle", "wb") as fh:
        pickle.dump(tree, fh)
    print(f"fs.pickle: {sum(1 for _ in honeyfs.rglob('*'))} honeyfs entries")


if __name__ == "__main__":
    main(*sys.argv[1:4])
