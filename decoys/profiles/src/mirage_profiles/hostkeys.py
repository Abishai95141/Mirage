"""A deployment's SSH host keys (phase 3 spec 3.4, found by the fleet group).

The decoy showed `/etc/ssh/ssh_host_*_key.pub` with the reference image's sizes and nothing in
them, while the server itself presented keys Cowrie made up when it started. On a real host
the public key files are world-readable and are the keys the server presents; root can read
the private ones too. So the profile mints the three keys Debian 12's `ssh-keygen -A` makes
(RSA 3072, ECDSA P-256, Ed25519), the decoy serves from them, and the same files are what
`cat` shows.

Everything here is a function of the seed, the file bytes included, so that one seed renders
one profile. That is why the private keys are written out by hand in OpenSSH's own format
(`openssh-key-v1`): a library writes two random check numbers into it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

RSA_BITS = 3072  # what ssh-keygen -A makes on Debian 12
RSA_E = 65537
MAGIC = b"openssh-key-v1\0"
_SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % d for d in range(3, int(p**0.5) + 1, 2))]
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


@dataclass(frozen=True)
class HostKey:
    kind: str  # rsa, ecdsa or ed25519: the word in the file's name
    public: str  # the .pub file: "type base64 comment\n"
    private: str  # the private key file, OpenSSH format

    @property
    def blob(self) -> str:
        """The key as the server presents it, base64: the middle word of the .pub file."""
        return self.public.split()[1]


def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _mpint(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 8) // 8, "big") if value else b""
    return _string(raw)


def _digest(*parts: object) -> bytes:
    return hashlib.sha256(":".join(str(p) for p in parts).encode()).digest()


def _probably_prime(n: int, rng: random.Random, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(rounds):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int, rng: random.Random) -> int:
    while True:
        candidate = rng.getrandbits(bits) | (0b11 << (bits - 2)) | 1
        if candidate % RSA_E != 1 and _probably_prime(candidate, rng):
            return candidate


def _openssh_private(public_blob: bytes, private_fields: bytes, comment: str, check: int) -> str:
    """The private key file: OpenSSH's own format, not encrypted."""
    block = struct.pack(">II", check, check) + private_fields + _string(comment.encode())
    block += bytes(range(1, (-len(block)) % 8 + 1))
    body = (
        MAGIC
        + _string(b"none")
        + _string(b"none")
        + _string(b"")
        + struct.pack(">I", 1)
        + _string(public_blob)
        + _string(block)
    )
    text = base64.b64encode(body).decode()
    lines = [text[i : i + 70] for i in range(0, len(text), 70)]
    return (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "\n".join(lines)
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    )


def _key(kind: str, name: bytes, blob: bytes, fields: bytes, comment: str, seed: str) -> HostKey:
    check = int.from_bytes(_digest("hostkey-check", kind, seed)[:4], "big")
    public = f"{name.decode()} {base64.b64encode(blob).decode()} {comment}\n"
    return HostKey(kind, public, _openssh_private(blob, fields, comment, check))


def ed25519_key(seed: str, comment: str) -> HostKey:
    secret = _digest("hostkey", "ed25519", seed)
    key = ed25519.Ed25519PrivateKey.from_private_bytes(secret)
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    name = b"ssh-ed25519"
    blob = _string(name) + _string(public)
    fields = _string(name) + _string(public) + _string(secret + public)
    return _key("ed25519", name, blob, fields, comment, seed)


def ecdsa_key(seed: str, comment: str) -> HostKey:
    scalar = int.from_bytes(_digest("hostkey", "ecdsa", seed), "big") % (P256_ORDER - 1) + 1
    key = ec.derive_private_key(scalar, ec.SECP256R1())
    point = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    name, curve = b"ecdsa-sha2-nistp256", b"nistp256"
    blob = _string(name) + _string(curve) + _string(point)
    fields = _string(name) + _string(curve) + _string(point) + _mpint(scalar)
    return _key("ecdsa", name, blob, fields, comment, seed)


def rsa_key(seed: str, comment: str, bits: int = RSA_BITS) -> HostKey:
    rng = random.Random(_digest("hostkey", "rsa", seed))
    while True:
        p, q = _prime(bits // 2, rng), _prime(bits // 2, rng)
        if p != q and (p * q).bit_length() == bits:
            break
    if p < q:  # OpenSSH keeps p > q, so that iqmp is q's inverse modulo p
        p, q = q, p
    n = p * q
    d = pow(RSA_E, -1, (p - 1) * (q - 1))
    name = b"ssh-rsa"
    blob = _string(name) + _mpint(RSA_E) + _mpint(n)
    fields = (
        _string(name)
        + _mpint(n)
        + _mpint(RSA_E)
        + _mpint(d)
        + _mpint(pow(q, -1, p))
        + _mpint(p)
        + _mpint(q)
    )
    return _key("rsa", name, blob, fields, comment, seed)


_made: dict[tuple[str, str], list[HostKey]] = {}


def cache_dir() -> Path | None:
    """Where minted RSA keys are kept between runs, or None for nowhere. Finding two
    1536-bit primes in Python takes seconds, and a key is a function of its seed, so making
    it twice is waste. ``MIRAGE_HOSTKEY_CACHE`` names the directory (``off`` for none); by
    default it is ``build/cache/hostkeys`` of this repository, beside the rendered profile
    that holds the same keys, and like it never committed."""
    chosen = os.environ.get("MIRAGE_HOSTKEY_CACHE", "")
    if chosen == "off":
        return None
    if chosen:
        return Path(chosen)
    root = Path(__file__).resolve().parents[4]
    return root / "build/cache/hostkeys" if (root / "decoys/profiles").is_dir() else None


def _cached_rsa(seed: str, comment: str) -> HostKey:
    where = cache_dir()
    name = hashlib.sha256(f"rsa:{RSA_BITS}:{seed}:{comment}".encode()).hexdigest()[:32]
    path = where / f"{name}.json" if where else None
    if path is not None and path.is_file():
        try:
            kept = json.loads(path.read_text())
            if kept.get("seed") == seed and kept.get("comment") == comment:
                return HostKey("rsa", kept["public"], kept["private"])
        except (OSError, ValueError, KeyError):
            pass  # an unreadable entry is made again
    key = rsa_key(seed, comment)
    if path is not None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            with os.fdopen(os.open(path, flags, 0o600), "w") as f:
                json.dump(
                    {
                        "seed": seed,
                        "comment": comment,
                        "public": key.public,
                        "private": key.private,
                    },
                    f,
                )
        except OSError:
            pass  # the cache is a convenience; the key is already made
    return key


def mint(seed: str, hostname: str) -> list[HostKey]:
    """The three host keys of one deployment. The comment is what `ssh-keygen -A` writes: who
    made the key and where."""
    made = _made.get((seed, hostname))
    if made is None:
        comment = f"root@{hostname}"
        made = [_cached_rsa(seed, comment), ecdsa_key(seed, comment), ed25519_key(seed, comment)]
        _made[(seed, hostname)] = made
    return made
