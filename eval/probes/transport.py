"""The transport group of the fingerprint suite (phase 3 spec 3.4): spike S3's probes, as
checks. What a server does below anything a profile can change, on the decoy and on the real
reference host in the same run, compared item by item."""

from __future__ import annotations

from typing import Any

from eval.probes.default_tells import Result
from eval.probes.ssh_probes import BANNER_PROBES, NAME_LISTS

# (check ID suffix, key of the KEXINIT probe, what the check says)
KEXINIT = (
    ("banner", "banner", "the identification string is the reference's"),
    (
        "banner-line-ending",
        "banner_line_ending",
        "the identification string ends as the reference's",
    ),
    ("kexinit-order", "kexinit_before_client_id", "KEXINIT is sent when the reference sends it"),
    ("kexinit-padding", "padding_all_zero", "KEXINIT padding is zeroed as the reference's is"),
    ("first-kex-packet", "first_kex_packet_follows", "first_kex_packet_follows is the reference's"),
    ("hassh-server", "hassh_server", "HASSH-server is the reference's"),
)
BANNER_TEXT = {
    "version_2.2": "a client claiming SSH-2.2",
    "version_1.5": "a client claiming SSH-1.5",
    "version_1.99": "a client claiming SSH-1.99",
    "no_cr": "an identification string ending in LF alone",
    "http_get": "an HTTP request",
    "garbage": "bytes that are no identification string",
    "overlong": "an overlong identification string",
}


def compare(reference: dict[str, Any], decoy: dict[str, Any]) -> list[tuple[str, Result]]:
    """(check ID suffix, result) for every transport check, from two ``ssh_probes.probe``
    results."""
    out: list[tuple[str, Result]] = []

    def add(suffix: str, check: str, ok: bool, detail: str) -> None:
        out.append((suffix, Result("ssh", check, "pass" if ok else "fail", "" if ok else detail)))

    rk, dk = reference["kexinit"], decoy["kexinit"]
    for suffix, key, text in KEXINIT:
        add(suffix, text, dk[key] == rk[key], f"decoy {dk[key]!r}, reference {rk[key]!r}")
    for name in NAME_LISTS:
        mine, theirs = dk["algorithms"][name], rk["algorithms"][name]
        extra = sorted(set(mine) - set(theirs))
        missing = sorted(set(theirs) - set(mine))
        detail = (
            f"extra {extra}, missing {missing}" if extra or missing else "same set, other order"
        )
        add(
            f"algorithms-{name.replace('_', '-')}",
            f"{name} is the reference's list",
            mine == theirs,
            detail,
        )
    for name in BANNER_PROBES:
        r, d = reference["banners"][name], decoy["banners"][name]
        same = (r["reply_text"], r["closed"], r["kexinit_sent"]) == (
            d["reply_text"],
            d["closed"],
            d["kexinit_sent"],
        )
        add(
            f"reply-{name.replace('_', '-').replace('.', '-')}",
            f"{BANNER_TEXT[name]} is answered as the reference answers it",
            same,
            f"decoy {d['reply_text']!r} closed={d['closed']} kex={d['kexinit_sent']}; "
            f"reference {r['reply_text']!r} closed={r['closed']} kex={r['kexinit_sent']}",
        )
    return out
