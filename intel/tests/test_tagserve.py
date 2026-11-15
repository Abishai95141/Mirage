"""The chosen tagger: built, saved, loaded and served. A toy embedding stands in for the model;
the texts are harmless."""

from __future__ import annotations

import json

import numpy as np
import pytest
from mirage_intel import tag_worker, tagserve
from mirage_intel import tagscore as ts
from mirage_intel.embedders import Cache

pytestmark = pytest.mark.ml

WORDS = ["uname", "whoami", "crontab", "ls", "cat", "tee"]


def toy(_corpus):
    """A bag of known words, unit length: enough to make `uname -a` nearest to `uname -r`. A
    text with none of the words gets a direction of its own, near nothing in the index."""

    def embed(texts):
        rows = np.array(
            [[float(w in t.split()) for w in WORDS] + [0.0] for t in texts], dtype=np.float32
        )
        rows[:, -1] = (rows.sum(axis=1) == 0).astype(np.float32)
        return rows / np.linalg.norm(rows, axis=1, keepdims=True)

    return embed


def step(procedure, technique, line, pieces=(), split="train", tactic="TA0007"):
    return ts.Step(
        run="r", session_ref=f"s-{procedure}", step_id="1", split=split, protocol="ssh",
        procedure=procedure, technique=technique, tactic=tactic, source="own", line=line,
        pieces=tuple(pieces),
    )  # fmt: skip


CHOSEN = {
    "kind": "retrieval", "embedder": "minilm", "k": 1, "unit": "pieces", "threshold": 0.5,
    "atomic": True,
}  # fmt: skip
FIT_ON = [
    step("sysinfo", "T1082", "uname -a", ["uname -a"]),
    step("owner", "T1033", "whoami", ["whoami"]),
    step("cron", "T1053.003", "crontab -l", ["crontab -l"], tactic="TA0003"),
]


def test_a_choice_must_name_something_this_build_can_serve(tmp_path):
    path = tmp_path / "choices.yaml"
    with pytest.raises(tagserve.ChoiceError, match="names no tagger"):
        tagserve.choice(path)
    path.write_text("tagger: {kind: retrieval, embedder: nonesuch, unit: pieces}\n")
    with pytest.raises(tagserve.ChoiceError, match="unknown embedding model"):
        tagserve.choice(path)
    path.write_text("tagger: {kind: retrieval, embedder: minilm, unit: pieces, threshold: 0.6}\n")
    assert tagserve.choice(path)["threshold"] == 0.6


def test_the_served_model_is_the_fitted_one_and_plain_json(tmp_path):
    model = tagserve.fit(CHOSEN, FIT_ON, toy, extra=[("cat /etc/os-release", "T1082")])
    assert {e.origin for e in model.entries} == {"train", "atomic"}
    tactics = tagserve.tactic_map(FIT_ON, {e.technique for e in model.entries})
    assert tactics == {"T1082": "TA0007", "T1033": "TA0007", "T1053.003": "TA0003"}
    path = tagserve.save(model, CHOSEN, tactics, {"fitted_on": {"splits": ["train"]}}, tmp_path)
    body = json.loads(path.read_text())
    assert body["version"].startswith("tagger-minilm-") and body["unit"] == "pieces"
    served = tagserve.load(tmp_path, toy)
    texts = ["uname -r", "whoami", "nothing known here"]
    assert (
        [p.technique for p in served.model.predict("ssh", texts)]
        == [p.technique for p in model.predict("ssh", texts)]
        == ["T1082", "T1033", ""]
    )
    assert served.version == body["version"] and served.attack_version == "20.1"


def test_an_input_gets_its_most_confident_text_as_the_scorer_does(tmp_path):
    model = tagserve.fit(CHOSEN, FIT_ON, toy)
    tagserve.save(model, CHOSEN, tagserve.tactic_map(FIT_ON, set()), {}, tmp_path)
    served = tagserve.load(tmp_path, toy)
    # a line of three commands: one is noise, one is half a match, one is exact
    pieces = ["tee out", "uname tee", "crontab -l"]
    index, pred = served.tag("ssh", pieces)
    assert (index, pred.technique) == (2, "T1053.003")
    scored = ts.predict_steps(served.model, [step("x", "", " | ".join(pieces), pieces)], "pieces")
    assert scored[0].technique == pred.technique and scored[0].confidence == pred.confidence
    assert served.tag("ssh", ["tee out"]) is None  # below the threshold: no label


def test_the_cache_answers_only_for_what_the_model_embedded(tmp_path):
    texts = ["[ssh] uname -a", "[ssh] whoami"]
    cache = Cache.build("minilm", [*texts, texts[0]], toy(None))
    cache.save(tmp_path)
    again = Cache.load(tmp_path)
    assert np.array_equal(again(texts), toy(None)(texts))  # exactly the model's vectors
    assert again.verify(toy(None)) == 0.0
    with pytest.raises(LookupError, match="not in the frozen embedding cache"):
        again(["[ssh] crontab -l"])
    # vectors from another model are caught, and so is a file changed on disk
    with pytest.raises(ValueError, match="differs from the model"):
        again.verify(lambda t: np.roll(toy(None)(t), 1, axis=1))
    (tmp_path / "embeddings.npy").write_bytes(b"not the array")
    with pytest.raises(ValueError, match="does not match the hash"):
        Cache.load(tmp_path)


# ------------------------------------------------------------------ the worker


def ev(event_id, session, cls="policy_decision", source="cowrie", text="", age_ms=60_000, ts=None):
    return {
        "event_id": event_id, "session_id": session, "source": source,
        "protocol": "ssh" if source == "cowrie" else source, "class": cls,
        "ts": ts or f"2026-11-14 10:00:00.{int(event_id[1:]):06d}", "age_ms": age_ms,
        "command": text if source == "cowrie" else "", "input": "" if source == "cowrie" else text,
    }  # fmt: skip


def line(event_id, session, text, **kw):
    return ev(event_id, session, cls="process_activity", text=text, **kw)


def test_a_line_is_grouped_with_the_commands_that_follow_it():
    events = [
        line("e1", "a", "uname -a | tee out"),
        ev("e2", "a", text="uname -a"),
        ev("e3", "a", text="tee out"),
        line("e4", "a", "true"),  # a line that ran no gated command
        line("e5", "a", "whoami", age_ms=200),
        ev("e6", "a", text="whoami", age_ms=150),
        ev("e7", "b", source="redis", text="INFO"),
        ev("e8", "c", text="crontab -l"),  # an SSH command with no line before it
    ]
    found = tag_worker.groups(events)
    assert [(g.key, [e["event_id"] for e in g.pieces], g.closed) for g in found] == [
        ("e1", ["e2", "e3"], True),
        ("e4", [], True),  # closed by the next line
        ("e5", ["e6"], False),  # the session's last line, 150 ms old: may still grow
        ("e7", [], True),
        ("e8", [], True),
    ]
    # the model is shown a line's commands, or the line itself when it ran none
    assert found[0].texts("pieces") == ["uname -a", "tee out"]
    assert found[0].texts("line") == ["uname -a | tee out"]
    assert found[1].texts("pieces") == ["true"] and found[3].texts("pieces") == ["INFO"]
    # once nothing has been added for the settle time, the last line closes too
    old = [dict(e, age_ms=9_000) for e in events]
    assert all(g.closed for g in tag_worker.groups(old))


def test_a_decision_logged_at_the_same_instant_as_its_line_belongs_to_that_line():
    same = "2026-11-14 10:00:05.000000"
    events = [
        line("e1", "a", "whoami"),
        ev("e2", "a", text="whoami"),
        ev("e3", "a", text="uname -a", ts=same),  # sorts before its line by ID alone
        line("e9", "a", "uname -a", ts=same),
    ]
    found = tag_worker.groups(events)
    assert [(g.key, [e["event_id"] for e in g.pieces]) for g in found] == [
        ("e1", ["e2"]),
        ("e9", ["e3"]),
    ]


class FakeStore:
    def __init__(self, events):
        self.events, self.inserted, self.event_reads = events, [], 0

    def rows(self, sql):
        if sql.startswith("SELECT session_id, toString(max(ingest_ts))"):
            after = sql.split("parseDateTime64BestEffort('")[1].split("'")[0]
            newest: dict[str, str] = {}
            for e in self.events:
                newest[e["session_id"]] = max(newest.get(e["session_id"], ""), e["ingest"])
            rows = [{"session_id": s, "changed": c} for s, c in newest.items() if c >= after]
            return sorted(rows, key=lambda r: r["changed"])
        self.event_reads += 1
        return [e for e in self.events if f"'{e['session_id']}'" in sql]

    def insert(self, table, rows):
        assert table == "mirage.labels"
        self.inserted.extend(rows)

    def current(self):
        """What a reader of the table sees: the newest row per event, empty ones left out."""
        newest = {}
        for r in self.inserted:
            if r["version"] >= newest.get(r["event_id"], r)["version"]:
                newest[r["event_id"]] = r
        return {k: v["technique"] for k, v in newest.items() if v["technique"]}


def served_model(tmp_path):
    model = tagserve.fit(CHOSEN, FIT_ON, toy)
    tagserve.save(model, CHOSEN, tagserve.tactic_map(FIT_ON, set()), {}, tmp_path)
    return tagserve.load(tmp_path, toy)


T0, T1, T2 = (f"2026-11-14 10:00:0{i}.000000" for i in (1, 2, 3))


def test_the_worker_labels_each_input_once_and_waits_for_an_open_line(tmp_path):
    served = served_model(tmp_path)
    store = FakeStore(
        [
            dict(line("e1", "a", "uname -a | tee out"), ingest=T0),
            dict(ev("e2", "a", text="tee out"), ingest=T0),
            dict(ev("e3", "a", text="uname -a"), ingest=T0),
            dict(line("e4", "b", "crontab -l", age_ms=100), ingest=T1),
            dict(ev("e5", "b", text="crontab -l", age_ms=100), ingest=T1),
        ]
    )
    state = tag_worker.State("2026-11-14 10:00:00.000000")
    assert tag_worker.step(store, served, state) == (1, 1)
    (row,) = store.inserted
    # one label for the line, on its first gate decision (where the reward and the Session
    # page look for it), with the tactic and the evidence
    assert (row["event_id"], row["technique"], row["tactic"]) == ("e2", "T1082", "TA0007")
    assert row["kind"] == "input" and row["model_version"] == served.version
    assert row["rule_id"].endswith(":train") and row["session_id"] == "a"
    assert row["ts"] == store.events[1]["ts"]
    # session b's line is still open: it is read again, and labelled when it settles
    assert state.after == T1 and "b" not in state.handled
    for e in store.events:
        e["age_ms"] = 9_000
    assert tag_worker.step(store, served, state) == (1, 1)
    assert store.current() == {"e2": "T1082", "e5": "T1053.003"}
    # nothing new: no events are read again and nothing is written twice
    reads = store.event_reads
    assert tag_worker.step(store, served, state) == (0, 0)
    assert store.event_reads == reads and len(store.inserted) == 2


def test_a_command_that_arrives_late_rewrites_the_lines_one_label(tmp_path):
    # A line's commands are gated as they run. Here the second arrives after the line was
    # already labelled on its first: the input must still end up with exactly one label.
    served = served_model(tmp_path)
    store = FakeStore(
        [
            dict(line("e1", "a", "whoami ; crontab -l"), ingest=T0),
            dict(ev("e2", "a", text="whoami"), ingest=T0),
        ]
    )
    state = tag_worker.State("2026-11-14 10:00:00.000000")
    tag_worker.step(store, served, state)
    assert store.current() == {"e2": "T1033"}
    store.events.append(dict(ev("e3", "a", text="crontab -l"), ingest=T1))
    assert tag_worker.step(store, served, state) == (1, 1)
    # the later command's answer (a tie goes to the later text, as in the scorer), written
    # over the first in the same place: still one label for the input
    assert store.current() == {"e2": "T1053.003"}


def test_a_label_is_withdrawn_when_the_input_no_longer_earns_one(tmp_path):
    # A line with no gated command is read as itself. When its one command then arrives and
    # the model has nothing to say about it, the earlier label must not stay behind.
    served = served_model(tmp_path)
    store = FakeStore([dict(line("e1", "a", "uname -a"), ingest=T0)])
    state = tag_worker.State("2026-11-14 10:00:00.000000")
    tag_worker.step(store, served, state)
    assert store.current() == {"e1": "T1082"}  # on the line, while it has no decision
    store.events.append(dict(ev("e2", "a", text="tee out"), ingest=T1))
    assert tag_worker.step(store, served, state) == (1, 0)
    assert store.current() == {}
    assert store.inserted[-1]["rule_id"] == "withdrawn" and store.inserted[-1]["event_id"] == "e1"
    # had the command earned a label, it would have moved to the decision, not been doubled
    store = FakeStore([dict(line("e1", "a", "uname -a"), ingest=T0)])
    state = tag_worker.State("2026-11-14 10:00:00.000000")
    tag_worker.step(store, served, state)
    store.events.append(dict(ev("e2", "a", text="uname -a"), ingest=T1))
    assert tag_worker.step(store, served, state) == (1, 1)
    assert store.current() == {"e2": "T1082"}
    # ... and an input that never had a label gets no row at all when the model abstains
    store.events.append(dict(ev("e3", "z", source="redis", text="tee out"), ingest=T2))
    before = len(store.inserted)
    assert tag_worker.step(store, served, state) == (1, 0)
    assert len(store.inserted) == before


def test_a_model_chosen_for_whole_lines_is_shown_whole_lines(tmp_path):
    whole = {**CHOSEN, "unit": "line"}
    model = tagserve.fit(whole, FIT_ON, toy)
    tagserve.save(model, whole, tagserve.tactic_map(FIT_ON, set()), {}, tmp_path)
    served = tagserve.load(tmp_path, toy)
    assert served.unit == "line"
    group = tag_worker.groups([line("e1", "a", "crontab -l"), ev("e2", "a", text="tee out")])[0]
    (row,), placed = tag_worker.label_rows(served, [group], version=1)
    assert row["technique"] == "T1053.003"  # from the line; its one command says nothing
    assert placed == {"e1": "e2"}


def test_a_bad_watermark_is_refused_before_it_reaches_a_query():
    with pytest.raises(ValueError, match="not a timestamp"):
        tag_worker.step(FakeStore([]), None, tag_worker.State("x' OR 1=1 --"))


def test_the_store_being_away_is_retried_not_fatal():
    import httpx

    # what the worker's loop catches must include the client's own connection errors
    assert not issubclass(httpx.ConnectError, OSError)
    assert issubclass(httpx.ConnectError, httpx.HTTPError)
    assert issubclass(httpx.ReadTimeout, httpx.HTTPError)


def test_the_device_is_what_was_asked_for_or_an_error(monkeypatch):
    torch = pytest.importorskip("torch")  # the research environment only
    from mirage_intel import embedders

    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    monkeypatch.delenv("MIRAGE_EMBED_DEVICE", raising=False)
    assert embedders.device() == "cpu"  # auto, and no GPU to see
    monkeypatch.setenv("MIRAGE_EMBED_DEVICE", "cuda")
    with pytest.raises(RuntimeError, match="sees no GPU"):
        embedders.device()  # never a silent fall back to the CPU
    monkeypatch.setattr(torch.cuda, "is_available", lambda: True)
    assert embedders.device() == "cuda"
    monkeypatch.setenv("MIRAGE_EMBED_DEVICE", "cpu")
    assert embedders.device() == "cpu"  # the CPU can always be asked for
    monkeypatch.setenv("MIRAGE_EMBED_DEVICE", "gpu0")
    with pytest.raises(ValueError, match="'auto', 'cpu' or 'cuda'"):
        embedders.device()


def test_the_worker_asks_the_model_once_per_protocol_and_answers_as_one_at_a_time(tmp_path):
    served = served_model(tmp_path)
    events = [
        line("e1", "a", "uname -a | tee out"),
        ev("e2", "a", text="uname -a"),
        ev("e3", "a", text="tee out"),
        line("e4", "a", "whoami ; crontab -l"),
        ev("e5", "a", text="whoami"),
        ev("e6", "a", text="crontab -l"),
        line("e7", "a", "tee nothing"),
        ev("e8", "b", source="redis", text="uname"),
        ev("e9", "c", text=""),  # nothing to read
    ]
    todo = [dict(e, age_ms=9_000) for e in events]
    found = tag_worker.groups(todo)
    calls = []
    real = served.model.predict

    def counted(protocol, texts):
        calls.append((protocol, len(texts)))
        return real(protocol, texts)

    served.model.predict = counted
    together = tag_worker.answers(served, found)
    assert sorted(calls) == [("redis", 1), ("ssh", 5)]  # not one call per input
    served.model.predict = real
    alone = [served.tag(g.protocol, g.texts(served.unit)) for g in found]
    assert [(a[0], a[1].technique) if a else None for a in together] == [
        (a[0], a[1].technique) if a else None for a in alone
    ]
    assert [a[1].technique if a else "" for a in together] == [
        "T1082", "T1053.003", "", "T1082", "",
    ]  # fmt: skip


def test_a_tie_between_techniques_is_settled_by_rule_not_by_rounding_noise():
    from mirage_intel import tagmodels as tm

    # The same command under two techniques, once from the lab and once from the public
    # corpus: an exact tie. Whatever noise the arithmetic adds, the answer is the lab's entry,
    # and with two lab entries the lower technique ID.
    steps = [step("a", "T1082", "uname -a", ["uname -a"])]
    rng = np.random.default_rng(0)

    def noisy(_corpus):
        clean = toy(None)

        def embed(texts):
            return clean(texts) + rng.normal(0, 2e-8, size=(len(texts), len(WORDS) + 1)).astype(
                np.float32
            )

        return embed

    answers = set()
    for _ in range(20):
        model = tm.Retrieval(noisy, label="toy", extra=[("uname -a", "T1016")])
        model.fit(steps, "pieces")
        (pred,) = model.predict("ssh", ["uname -a"])
        answers.add((pred.technique, pred.evidence.rsplit(":", 1)[1], round(pred.confidence, 6)))
    assert answers == {("T1082", "train", 1.0)}
    two = [
        step("a", "T1082", "uname -a", ["uname -a"]),
        step("b", "T1016", "uname -a", ["uname -a"]),
    ]
    for _ in range(10):
        model = tm.Retrieval(noisy, label="toy").fit(two, "pieces")
        assert model.predict("ssh", ["uname -a"])[0].technique == "T1016"
    # saved and loaded, the order is the same
    again = tm.Retrieval.from_saved(model.to_saved(), toy)
    assert again.predict("ssh", ["uname -a"])[0].technique == "T1016"
