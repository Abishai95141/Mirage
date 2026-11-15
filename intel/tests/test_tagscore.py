"""The tagger's scorer and candidate models, on small harmless inputs."""

from __future__ import annotations

import pytest
from mirage_intel import tagmodels as tm
from mirage_intel import tagscore as ts
from mirage_intel.text import normalise, parent

pytestmark = pytest.mark.ml


def step(procedure, technique, line, *, split="dev", source="own", session="a", pieces=(), n=0):
    return ts.Step(
        run="r1",
        session_ref=session,
        step_id=f"{procedure}-{n}",
        split=split,
        protocol="ssh",
        procedure=procedure,
        technique=technique,
        tactic="TA0007" if technique else "",
        source=source,
        line=line,
        pieces=tuple(pieces),
    )


TRAIN = [
    step("sys-a", "T1082", "uname -a", split="train"),
    step("sys-b", "T1082", "cat /etc/os-release", split="train"),
    step("sys-c", "T1082", "hostnamectl status", split="train"),
    step("files-a", "T1083", "ls -la /tmp", split="train"),
    step("files-b", "T1083", "find /var -name config", split="train"),
    step("files-c", "T1083", "ls -R /home", split="train"),
    step("none-a", "", "cd /tmp", split="train"),
    step("none-b", "", "echo hello", split="train"),
]
SCORE = dict(
    train_techniques={"T1082", "T1083"},
    seen_skeletons=set(),
    tactic_of={"T1082": "TA0007", "T1083": "TA0007", "T1053.003": "TA0003"},
    draws=200,
)


class Fixed:
    """A model that answers from a table, for testing the scorer alone."""

    name = "fixed"

    def __init__(self, table):
        self.table = table

    def predict(self, protocol, texts):
        return [ts.Pred(*self.table.get(t, ("", 0.0))) for t in texts]


def test_text_normalisation():
    assert normalise("ping  -c 3 203.0.113.9") == "ping -c <n> <ip>"
    assert normalise("wget http://files.example/a1b2c3d4e5 -O /tmp/x") == normalise(
        "wget http://other.example/ffeeddccbb -O /tmp/x"
    )
    assert normalise("ls -R /home") != normalise("ls -r /home")  # case is kept: a flag's meaning
    assert parent("T1059.004") == "T1059" and parent("T1082") == "T1082"


def test_rows_become_steps_with_a_line_and_its_pieces():
    rows = [
        dict(run_id="r", session_ref="s", step_id="1", event_id="b", ts_ms=2, role="decision",
             input="grep root", split="dev", protocol="ssh", procedure_id="p", technique_id="T1087",
             tactic="TA0007", source="own"),
        dict(run_id="r", session_ref="s", step_id="1", event_id="a", ts_ms=1, role="input",
             input="cat /etc/passwd | grep root", split="dev", protocol="ssh", procedure_id="p",
             technique_id="T1087", tactic="TA0007", source="own"),
        dict(run_id="r", session_ref="s", step_id="1", event_id="c", ts_ms=1, role="decision",
             input="cat /etc/passwd", split="dev", protocol="ssh", procedure_id="p",
             technique_id="T1087", tactic="TA0007", source="own"),
    ]  # fmt: skip
    (s,) = ts.steps_from_rows(rows)
    assert s.line == "cat /etc/passwd | grep root"
    assert s.pieces == ("cat /etc/passwd", "grep root")
    assert s.texts("line") == (s.line,) and s.texts("pieces") == s.pieces


def test_a_step_takes_its_most_confident_piece():
    s = step("p", "T1087", "cat /etc/passwd | grep root", pieces=("cat /etc/passwd", "grep root"))
    model = Fixed({"cat /etc/passwd": ("T1087", 0.9), "grep root": ("T1083", 0.4)})
    (pred,) = ts.predict_steps(model, [s], unit="pieces")
    assert pred.technique == "T1087"
    (line_pred,) = ts.predict_steps(model, [s], unit="line")
    assert line_pred.technique == ""  # the table has no entry for the whole line


def test_repeats_of_one_procedure_are_one_unit():
    # Six renderings that differ only in a number are one skeleton; a procedure counts once.
    steps = [step("sys-x", "T1082", f"sleep {i}; uname -a", n=i) for i in range(6)]
    steps.append(step("files-x", "T1083", "ls /srv"))
    preds = [ts.Pred("T1082", 0.9)] * 6 + [ts.Pred("T1082", 0.9)]
    report, units = ts.score("m", steps, preds, **SCORE)
    assert report.n_procedures == 2 and len(units) == 2
    assert report.headline["precision"] == 0.5 and report.headline["recall"] == 0.5
    # without the collapse it would have been 6 right of 7
    assert report.headline["micro_f1"] == 0.5


def test_distinct_renderings_share_a_procedures_weight():
    steps = [step("sys-x", "T1082", "uname -a", n=0), step("sys-x", "T1082", "uname -r", n=1)]
    preds = [ts.Pred("T1082", 0.9), ts.Pred()]  # one found, one missed
    (unit,) = ts.units(steps, preds)
    assert unit.tp == 0.5 and unit.fn == 0.5 and unit.abstained == 0.5 and unit.fp == 0.0


def test_text_seen_in_training_is_dropped_and_counted():
    steps = [step("sys-x", "T1082", "uname -a"), step("files-x", "T1083", "ls /srv")]
    preds = [ts.Pred("T1082", 0.9), ts.Pred("T1083", 0.9)]
    seen = {("ssh", normalise("uname -a"))}
    report, _ = ts.score("m", steps, preds, **{**SCORE, "seen_skeletons": seen})
    assert report.n_leaked_renderings == 1 and report.headline["procedures"] == 1


def test_unseen_techniques_and_negatives_are_kept_apart():
    steps = [
        step("sys-x", "T1082", "uname -a"),
        step("cron-x", "T1053.003", "crontab -l"),  # no training procedure has this technique
        step("none-x", "", "cd /srv"),
    ]
    preds = [ts.Pred("T1082", 0.9), ts.Pred(), ts.Pred("T1083", 0.6)]  # fires on the negative
    report, units = ts.score("m", steps, preds, **SCORE)
    assert report.unseen == {"procedures": 1, "techniques": 1, "recall": 0.0, "abstention": 1.0}
    assert report.negatives == {"procedures": 1, "false_positive_rate": 1.0}
    assert {u.procedure for u in units} == {"sys-x", "none-x"}  # headline: seen + negatives
    assert report.headline["precision"] == 0.5 and report.headline["recall"] == 1.0


def test_a_sub_technique_folds_into_its_parent():
    steps = [step("cron-x", "T1053.003", "crontab -l")]
    preds = [ts.Pred("T1053.005", 0.8)]
    report, _ = ts.score("m", steps, preds, **{**SCORE, "train_techniques": {"T1053.003"}})
    assert report.headline["micro_f1"] == 0.0 and report.headline["micro_f1_parent_folded"] == 1.0


def test_session_tactic_sets():
    steps = [
        step("sys-x", "T1082", "uname -a", session="a"),
        step("cron-x", "T1053.003", "crontab -l", session="a"),
        step("none-x", "", "cd /srv", session="b"),
    ]
    steps[1] = ts.Step(**{**steps[1].__dict__, "tactic": "TA0003"})
    preds = [ts.Pred("T1082", 0.9), ts.Pred(), ts.Pred("T1053.003", 0.5)]
    got = ts.session_tactics(steps, preds, SCORE["tactic_of"])
    # truth: a={TA0007, TA0003}, b={}; predicted: a={TA0007}, b={TA0003}
    assert got == {"sessions": 2, "precision": 0.5, "recall": 0.5, "f1": 0.5}


def test_the_interval_and_the_paired_difference():
    steps = [step(f"sys-{i}", "T1082", f"uname -{c}") for i, c in enumerate("abcdefghij")]
    good = [ts.Pred("T1082", 0.9)] * 10
    bad = [ts.Pred("T1082", 0.9)] * 3 + [ts.Pred()] * 7
    _, good_units = ts.score("good", steps, good, **SCORE)
    _, bad_units = ts.score("bad", steps, bad, **SCORE)
    lo, hi = ts.bootstrap(bad_units, draws=500)
    assert 0.0 <= lo < hi <= 1.0
    point, d_lo, _ = ts.paired_difference(good_units, bad_units, draws=500)
    assert point > 0 and d_lo > 0  # better on the same procedures, beyond the interval
    same = ts.paired_difference(good_units, good_units, draws=100)
    assert same == (0.0, 0.0, 0.0)


def test_the_baseline_comes_from_training_not_from_the_split_being_scored():
    model = tm.MostFrequent().fit(TRAIN)
    assert model.technique == "T1082"  # three procedures each for T1082 and T1083: ties by ID
    dev_only = [step(f"cron-{i}", "T1053.003", "crontab -l", n=i) for i in range(5)]
    assert tm.MostFrequent().fit(TRAIN).predict("ssh", ["x"])[0].technique == "T1082"
    assert all(p.technique == "T1082" for p in ts.predict_steps(model, dev_only))


def test_the_linear_model_learns_and_abstains_on_harmless_input():
    model = tm.LinearNgram(threshold=0.3).fit(TRAIN)
    got = model.predict("ssh", ["uname -r", "ls -la /var", "cd /opt"])
    assert [p.technique for p in got[:2]] == ["T1082", "T1083"]
    assert got[2].technique == ""  # the negative class is an abstention
    one_class = tm.LinearNgram().fit([s for s in TRAIN if s.technique == "T1082"])
    assert one_class.predict("ssh", ["anything"])[0].technique == "T1082"


def test_retrieval_names_a_neighbour_and_an_unseen_technique_from_attack_text():
    model = tm.Retrieval(k=1).fit(TRAIN)
    assert model.predict("ssh", ["uname -a"])[0].technique == "T1082"
    assert all(e.technique for e in model.entries)  # negatives are not indexed
    with_attack = tm.Retrieval(
        k=1, attack_text={"T1053.003": "[ssh] crontab schedule a job with cron"}
    ).fit(TRAIN)
    hit = with_attack.predict("ssh", ["crontab -l"])[0]
    assert hit.technique == "T1053.003" and hit.evidence.endswith(":attack")
    strict = tm.Retrieval(k=1, threshold=0.99).fit(TRAIN)
    assert strict.predict("ssh", ["tar czf backup.tgz docs"])[0].technique == ""


def test_a_cascade_asks_in_order_and_respects_thresholds():
    first = Fixed({"uname -a": ("T1082", 0.9), "ls /srv": ("T1083", 0.2)})
    second = Fixed({"ls /srv": ("T1083", 0.7), "uname -a": ("T1083", 0.99)})
    cascade = tm.Cascade([(first, 0.5), (second, 0.5)])
    got = cascade.predict("ssh", ["uname -a", "ls /srv", "cd /"])
    assert [p.technique for p in got] == ["T1082", "T1083", ""]
    assert got[1].confidence == 0.7  # the first layer's weak answer was passed over


def test_threshold_tuning_prefers_the_lower_of_equal_scores():
    assert tm.tune_threshold(lambda t: 1.0 if t <= 0.3 else 0.5, [0.1, 0.3, 0.5]) == (0.1, 1.0)
    assert tm.tune_threshold(lambda t: t, [0.1, 0.3, 0.5]) == (0.5, 0.5)


def test_the_bench_fits_on_one_split_and_tunes_on_another():
    from mirage_intel.experiments import tagger_bench as bench

    dev = [
        step("sys-x", "T1082", "uname -r"),
        step("files-x", "T1083", "ls -la /var"),
        step("none-x", "", "cd /opt"),
    ]
    report, units, threshold = bench.run_one(
        "linear", tm.LinearNgram(), "line", True, TRAIN, dev, "dev", draws=50
    )
    assert report.split == "dev" and report.headline["micro_f1"] == 1.0
    assert 0.0 <= threshold <= 0.95 and len(units) == 3
    # a threshold handed in (the final run) is used as given, not tuned again
    _, _, fixed = bench.run_one(
        "linear", tm.LinearNgram(), "line", True, TRAIN, dev, "test", threshold=0.4, draws=50
    )
    assert fixed == 0.4
    base, _, t0 = bench.run_one(
        "most-frequent", tm.MostFrequent(), "line", False, TRAIN, dev, "dev", draws=50
    )
    assert t0 == 0.0 and base.headline["recall"] == 0.5  # right for one of the two techniques
    ctx = bench.context(TRAIN)
    assert ctx["train_techniques"] == {"T1082", "T1083"} and ctx["tactic_of"]["T1082"] == "TA0007"
    names = [c[0] for c in bench.candidates({}, {}, None)]
    assert names[0] == "most-frequent" and len(names) == len(set(names))
