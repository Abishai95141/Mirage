"""Build Cowrie's filesystem for one deployment, inside the image build (decoys/ssh/Dockerfile).

    build_fs.py <refroot> <profile-cowrie-dir> <out-dir>

The tree is a real Debian 12 root (the reference image, so nginx, Redis and MariaDB are where
the profile says they are), walked with Cowrie's own ``createfs``. Then the deployment's
profile is applied on top: its users' home directories, its web files, and its versions of
the identity files (/etc/hostname, /etc/passwd, /etc/shadow, ...). Writes:

    <out>/fs.pickle   Cowrie's tree (metadata, plus embedded contents for a few files)
    <out>/honeyfs/    file contents Cowrie serves: small text files from the reference /etc,
                      overridden by the profile's files

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


def remove(tree: list, path: str) -> None:
    parent = find(tree, os.path.dirname(path) or "/")
    if parent is not None:
        parent[cf.A_CONTENTS][:] = [
            c for c in parent[cf.A_CONTENTS] if c[cf.A_NAME] != os.path.basename(path)
        ]


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

    overlay = json.loads((prof / "fs-overlay.json").read_text())
    for p in list(REFERENCE_ONLY) + overlay["remove"]:
        remove(tree, p)

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
        if node is None or node[cf.A_TYPE] != cf.T_FILE:
            continue
        data = f.read_bytes()
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

    import pickle

    with open(dst / "fs.pickle", "wb") as fh:
        pickle.dump(tree, fh)
    print(f"fs.pickle: {sum(1 for _ in honeyfs.rglob('*'))} honeyfs entries")


if __name__ == "__main__":
    main(*sys.argv[1:4])
