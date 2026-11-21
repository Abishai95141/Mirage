"""A deployment's SSH host keys: the three kinds Debian 12 makes, a function of the seed down
to the byte, and readable by the tools that read such files."""

from __future__ import annotations

import base64
import io
import json
import struct
from pathlib import Path

import paramiko
import pytest

from mirage_profiles import hostkeys
from mirage_profiles.generator import main as mirage_profile

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def keys() -> dict[str, hostkeys.HostKey]:
    return {k.kind: k for k in hostkeys.mint("7", "web01")}


def test_the_three_kinds_debian_makes(keys):
    assert set(keys) == {"rsa", "ecdsa", "ed25519"}
    assert keys["rsa"].public.startswith("ssh-rsa ")
    assert keys["ecdsa"].public.startswith("ecdsa-sha2-nistp256 ")
    assert keys["ed25519"].public.startswith("ssh-ed25519 ")
    for key in keys.values():
        assert key.public.endswith(" root@web01\n")
        assert key.private.startswith("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        assert key.private.endswith("\n-----END OPENSSH PRIVATE KEY-----\n")
        assert all(len(line) <= 70 for line in key.private.splitlines())


@pytest.mark.parametrize(
    ("kind", "loader"),
    [("rsa", paramiko.RSAKey), ("ecdsa", paramiko.ECDSAKey), ("ed25519", paramiko.Ed25519Key)],
)
def test_a_private_key_file_is_a_real_one_and_matches_its_public_half(keys, kind, loader):
    loaded = loader.from_private_key(io.StringIO(keys[kind].private))
    assert loaded.get_base64() == keys[kind].blob
    if kind == "rsa":
        assert loaded.get_bits() == 3072
    # It can sign, and the public half verifies it: the pair is a working key.
    signature = loaded.sign_ssh_data(b"mirage")
    signature.rewind()
    public = loader(data=base64.b64decode(keys[kind].blob))
    assert public.verify_ssh_sig(b"mirage", signature)


def test_one_seed_gives_the_same_bytes_and_another_seed_other_keys(keys):
    again = {
        "rsa": hostkeys.rsa_key("7", "root@web01"),
        "ecdsa": hostkeys.ecdsa_key("7", "root@web01"),
        "ed25519": hostkeys.ed25519_key("7", "root@web01"),
    }
    for kind, key in again.items():
        assert (key.public, key.private) == (keys[kind].public, keys[kind].private)
    other = hostkeys.ed25519_key("8", "root@web01")
    assert other.blob != keys["ed25519"].blob
    assert hostkeys.ecdsa_key("8", "root@web01").blob != keys["ecdsa"].blob


def test_the_private_file_is_openssh_s_format_with_its_padding(keys):
    body = base64.b64decode("".join(keys["ed25519"].private.splitlines()[1:-1]))
    assert body.startswith(hostkeys.MAGIC)
    rest = body[len(hostkeys.MAGIC) :]
    fields = []
    for _ in range(3):
        (n,) = struct.unpack(">I", rest[:4])
        fields.append(rest[4 : 4 + n])
        rest = rest[4 + n :]
    assert fields == [b"none", b"none", b""]  # not encrypted, as a host key is
    assert struct.unpack(">I", rest[:4]) == (1,)
    (n,) = struct.unpack(">I", rest[4:8])
    (m,) = struct.unpack(">I", rest[8 + n : 12 + n])
    private = rest[12 + n : 12 + n + m]
    assert len(private) % 8 == 0
    assert private[:4] == private[4:8]  # the two check numbers agree
    assert b"root@web01" in private


def test_the_rsa_key_is_the_size_debian_makes():
    assert hostkeys.RSA_BITS == 3072


def test_a_kept_key_is_used_again_and_only_for_its_own_seed(tmp_path, monkeypatch):
    monkeypatch.setenv("MIRAGE_HOSTKEY_CACHE", str(tmp_path))
    made = []
    real = hostkeys.rsa_key

    def counted(seed: str, comment: str, bits: int = hostkeys.RSA_BITS):
        made.append(seed)
        return real(seed, comment, bits)

    monkeypatch.setattr(hostkeys, "rsa_key", counted)
    first = hostkeys._cached_rsa("7", "root@web01")
    again = hostkeys._cached_rsa("7", "root@web01")
    assert made == ["7"] and (again.public, again.private) == (first.public, first.private)
    (kept,) = tmp_path.glob("*.json")
    assert kept.stat().st_mode & 0o077 == 0  # the owner's alone
    # A damaged entry is made again, not trusted.
    kept.write_text("{not json")
    assert hostkeys._cached_rsa("7", "root@web01").private == first.private
    assert made == ["7", "7"]
    # Switched off, nothing is read or kept.
    monkeypatch.setenv("MIRAGE_HOSTKEY_CACHE", "off")
    assert hostkeys.cache_dir() is None


def test_a_rendered_profile_serves_from_the_keys_it_shows(tmp_path):
    mirage_profile(
        ["render", str(ROOT / "decoys/profiles/web-db.yaml"), "--seed", "7", "--out", str(tmp_path)]
    )
    host = json.loads((tmp_path / "host.json").read_text())
    ssh = tmp_path / "cowrie/honeyfs/etc/ssh"
    cfg = (tmp_path / "cowrie/cowrie.cfg").read_text()
    for kind in ("rsa", "ecdsa", "ed25519"):
        public = (ssh / f"ssh_host_{kind}_key.pub").read_text()
        assert public.endswith(f" root@{host['hostname']}\n")
        assert (ssh / f"ssh_host_{kind}_key").read_text().startswith("-----BEGIN OPENSSH")
        where = f"/cowrie/deployment/honeyfs/etc/ssh/ssh_host_{kind}_key"
        assert f"{kind}_private_key = {where}\n" in cfg
        assert f"{kind}_public_key = {where}.pub\n" in cfg
    proc = tmp_path / "cowrie/honeyfs/proc/sys/kernel"
    assert (proc / "hostname").read_text() == host["hostname"] + "\n"
    assert (proc / "osrelease").read_text() == host["kernel_release"] + "\n"
    assert (proc / "random/boot_id").read_text() == host["boot_id"] + "\n"
