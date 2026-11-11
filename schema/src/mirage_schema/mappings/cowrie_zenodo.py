"""Zenodo record 21260400 (160-instance Cowrie corpus, CC BY 4.0) -> MirageEvent.

The corpus is Cowrie events flattened into one wide table: every field present (null when
unused), ``ts`` instead of ``timestamp`` (no zone; taken as UTC), plus enrichment columns
(GeoIP, ASN, honeypot address) and ``group``, the deployment configuration (1-4). Addresses
are pseudonymised (``src_ip`` holds a short hash such as ``2d8e5953``); those go to
``Endpoint.pseudonym``. This cleans a record and delegates to the Cowrie mapping, keeping
country and ASN on the endpoints and tagging the payload with the dataset so replayed data is
never mistaken for our own sensors.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

from mirage_schema.events import Endpoint, MirageEvent
from mirage_schema.mappings import cowrie

DATASET = "zenodo:21260400"
_ENRICHMENT_PREFIXES = ("src_ip_geoip_", "honeypot_ip_geoip_")
_DROP = {"ts", "ts_indexed", "id", "group", "honeypot_ip"}


def _is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return True


def _clean(record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """The record as Cowrie would have logged it, plus pseudonyms taken out of address fields."""
    out = {
        k: v
        for k, v in record.items()
        if v is not None and k not in _DROP and not k.startswith(_ENRICHMENT_PREFIXES)
    }
    out["timestamp"] = record["ts"].replace(" ", "T") + "Z"
    out.setdefault("protocol", "ssh")  # the corpus is SSH only; it sets protocol on connect only
    if record.get("honeypot_ip") and not out.get("dst_ip"):
        out["dst_ip"] = record["honeypot_ip"]
    pseudonyms = {}
    for field in ("src_ip", "dst_ip"):
        if field in out and not _is_ip(out[field]):
            pseudonyms[field] = str(out.pop(field))
    return out, pseudonyms


def _asn(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def map_record(record: dict[str, Any], *, ingest_ts: datetime | None = None) -> MirageEvent:
    cleaned, pseudonyms = _clean(record)
    ev = cowrie.map_record(cleaned, ingest_ts=ingest_ts)
    src = Endpoint(
        ip=ev.src.ip,
        pseudonym=pseudonyms.get("src_ip"),
        port=ev.src.port,
        asn=_asn(record.get("src_ip_geoip_asn_number")),
        country=(record.get("src_ip_geoip_country_iso_code") or None),
    )
    dst = ev.dst.model_copy(update={"pseudonym": pseudonyms.get("dst_ip")})
    payload = ev.payload | {"dataset": DATASET, "deployment_group": record.get("group")}
    return ev.model_copy(update={"src": src, "dst": dst, "payload": payload, "raw": record})
