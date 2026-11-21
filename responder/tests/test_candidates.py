"""The cache's listing and eviction, as the promotion step uses them."""

from __future__ import annotations

from mirage_responder import candidates
from mirage_responder.cache import Answer, Cache


def test_the_cache_is_listed_and_a_refused_answer_is_evicted(tmp_path):
    path = tmp_path / "cache.db"
    cache = Cache(path, "model-1", "3:abc:1")
    cache.put("web-db-1", "locale", "", Answer("LANG=en_US.UTF-8\n", "", 0, 40))
    cache.put("web-db-1", "openssl version", "", Answer("OpenSSL 3.0.13\n", "", 0, 12))
    cache.put("web-db-1", "od -c /etc/hostname", "f1ng3r", Answer("0000000 w\n", "", 0, 20))
    cache.get("web-db-1", "locale", "")
    cache.get("web-db-1", "locale", "")
    rows = candidates.listed(path)
    assert [(r["command"], r["fingerprint"], r["hits"]) for r in rows] == [
        ("locale", "", 2),
        ("od -c /etc/hostname", "f1ng3r", 0),
        ("openssl version", "", 0),
    ]
    assert rows[0]["stdout"] == "LANG=en_US.UTF-8\n" and rows[0]["model_version"] == "model-1"

    gone = candidates.evict(path, [{"command": "locale", "fingerprint": ""}, {"command": "nope"}])
    assert gone == 1
    assert cache.get("web-db-1", "locale", "") is None  # the running service sees it gone
    assert cache.get("web-db-1", "openssl version", "") is not None
    cache.close()


def test_no_cache_file_is_an_empty_cache(tmp_path):
    assert candidates.listed(tmp_path / "none.db") == []
    assert candidates.evict(tmp_path / "none.db", [{"command": "x"}]) == 0


def test_standings_are_listed_and_forgiven_by_name_or_all(tmp_path):
    from mirage_responder.cache import REFUSED, WORKS, Cache

    path = tmp_path / "cache.db"
    cache = Cache(path, "m", "p", refusal_s=3600)
    cache.stand("web-db-1", "locale", REFUSED, "deadline:first_line")
    cache.stand("web-db-1", "factor", WORKS)
    assert not cache.stand("web-db-1", "locale", WORKS)  # the first answer decided
    cache.close()
    rows = candidates.standings(path)
    assert [(r["verb"], r["state"], r["reason"]) for r in rows] == [
        ("locale", "refused", "deadline:first_line"),
        ("factor", "works", ""),
    ]
    assert candidates.forgive(path, ["locale", "nosuch"]) == 1
    assert [r["verb"] for r in candidates.standings(path)] == ["factor"]
    assert candidates.forgive(path, []) == 1 and candidates.standings(path) == []
    # A cache from before standings were kept, or none at all, has none.
    assert candidates.standings(tmp_path / "absent.db") == []
    assert candidates.forgive(tmp_path / "absent.db", []) == 0
