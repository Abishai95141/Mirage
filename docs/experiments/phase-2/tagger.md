# Experiment: which technique tagger

15 November 2026 · [phase 2 spec 2.4](../../05-phase-2-spec.md) · Gate 2 test 7 · gap register V4, V5, M2 · script: `intel/src/mirage_intel/experiments/tagger_bench.py`

## Question

Given one input an attacker sent, which ATT&CK technique is it? The spec proposes three layers: hand-written rules, retrieval over known procedures, and LogPrécis for tactics when the first two abstain. Each is measured alone and together, and a layer that does not help is dropped.

## Data

Development collection: capture run `r20261114182725-983b55`, lab seed. 1,704 steps over 201 of the catalogue's 205 procedures, split by procedure as frozen in `eval/split.yaml`: 123 train, 41 dev, 41 test.

Selection used train and dev only. The test split was read with the choice already fixed.

## Protocol

- **Scored per step, weighted per procedure.** A step is one typed line or request. Many renderings of one procedure count as one procedure, so a procedure with more slot values does not weigh more.
- **Headline population:** dev procedures whose technique has a training procedure (28 procedures, 15 techniques). Procedures of techniques unseen in training (12) and explicit negatives (5) are reported apart.
- **Leak guard:** a scored input whose normalised text also occurs in what the model was fitted on is dropped and counted (6 renderings on dev).
- **Intervals resample procedures** (1,000 draws). The difference to the baseline is paired over the same procedures.
- **Baseline:** always answer the most frequent technique of the training split.
- **Abstention threshold** tuned on dev for each candidate. That makes dev numbers optimistic.
- **Two units:** the whole line, or each gated command the line expanded to (a pipeline has several), taking the most confident.

## Candidates

- Most-frequent baseline; the starter rules.
- Linear classifier on character n-grams (two n-gram ranges, two regularisation strengths).
- Nearest-neighbour retrieval over training inputs, with one or three neighbours, under five embeddings: TF-IDF, `bge-small-en-v1.5`, `all-MiniLM-L6-v2`, `SecureBERT2.0-biencoder`, `SecureShellBert`.
- Each retrieval variant with ATT&CK technique descriptions added to the index.
- Each learned variant with **Atomic Red Team's Linux tests** added (Red Canary, MIT licence): 204 lines or 294 gated commands from 423 shell tests. The 28 tests a dev or test procedure quotes are excluded by GUID before anything is fitted.
- The rules in front of the best three; LogPrécis alone at tactic level.

CmdCaliper, the one published command-line embedding model, is excluded: gated weights, no licence stated, trained on Windows command lines.

## Results on dev

Technique micro-F1 over the headline population. All retrieval rows use one neighbour and the gated-command unit unless noted.

| Candidate | Micro-F1 | 95% interval | Abstains |
| --- | --- | --- | --- |
| Most-frequent technique | 0.000 | | 0.00 |
| Starter rules | 0.000 | | 0.86 |
| **SecureShellBert + Atomic** | **0.405** | 0.229 to 0.588 | 0.06 |
| MiniLM + Atomic | 0.385 | 0.219 to 0.573 | 0.14 |
| bge-small + Atomic | 0.360 | 0.184 to 0.545 | 0.12 |
| Linear n-gram + Atomic | 0.360 | 0.192 to 0.545 | 0.04 |
| TF-IDF, 3 neighbours, whole line + Atomic | 0.340 | 0.091 to 0.556 | 0.77 |
| MiniLM, lab procedures only | 0.329 | 0.165 to 0.511 | 0.13 |
| SecureBERT 2.0 + Atomic | 0.262 | 0.099 to 0.431 | 0.22 |
| Linear n-gram, lab procedures only | 0.258 | 0.058 to 0.458 | 0.53 |
| SecureShellBert, lab procedures only | 0.238 | 0.079 to 0.402 | 0.09 |

What the layers and additions did:

| Change | Effect |
| --- | --- |
| Atomic Red Team text in the index | Every candidate improved, by 0.06 to 0.17 |
| ATT&CK descriptions in the index | No change for any embedding: a description was never the nearest entry |
| Starter rules in front of the model | Worse: 0.405 to 0.324 (SecureShellBert), 0.385 to 0.343 (MiniLM), 0.360 to 0.240 (linear) |
| Gated commands instead of the whole line | Better for SecureShellBert (0.351 to 0.405), the same for MiniLM |

At tactic level on SSH steps, against the published baseline:

| | Micro-F1 | 95% interval | Session tactic F1 |
| --- | --- | --- | --- |
| Chosen tagger, read at tactic level | 0.502 | 0.345 to 0.664 | 0.582 |
| LogPrécis alone | 0.394 | 0.242 to 0.563 | 0.428 |

For the chosen candidate on dev: by source, Atomic-derived procedures 0.667 (6 procedures), corpus 0.333 (9), own 0.316 (13). Techniques with no training procedure: recall 0.0 of 12 procedures. Explicit negatives: 4 of 5 wrongly given a technique.

## Decision

**Nearest neighbour over the training procedures and Atomic Red Team's Linux tests, embedded with SecureShellBert, one answer per input from its most confident gated command, threshold 0.95.** It has the best dev micro-F1, which is the rule the plan set.

- **Rules layer: dropped for single inputs.** The starter rules know only harmless discovery commands, fire on 14% of steps, and were wrong each time on held-out procedures. Session rules stay: they cover what no single input shows, such as many failed logins and then a success. If offensive rules are added later, this comparison is run again.
- **LogPrécis layer: dropped.** Alone it is weaker at its own level, and the chosen tagger abstains on 6% of steps, so the most a fallback could add is small. It stays as the reported baseline.
- **ATT&CK descriptions: not indexed.** They changed nothing.

## The held-out result

The choice was fixed, then the test split was read. First on the development collection, then on the clean collection that became the frozen dataset (`eval/datasets/gate2`, capture run `r20261114212942-973f72`); the two agree to the third decimal, as they should, since the lab seed renders the same commands.

| | Held-out test |
| --- | --- |
| Procedures and techniques scored | 35 and 23 |
| **Technique micro-F1** | **0.212** (95% interval 0.067 to 0.346) |
| Most-frequent baseline | 0.000; paired difference 0.067 to 0.346 |
| Precision / recall | 0.24 / 0.19 |
| Macro-F1 | 0.188 |
| Abstention | 0.20 |
| With sub-techniques folded into their parent | 0.212 |
| By source | own 0.264 (20 procedures), Atomic-derived 0.203 (10), corpus 0.000 (5) |
| Technique with no lab training procedure | recall 0.25 on 4 procedures (the public corpus covers it) |
| Session tactic set | precision 0.41, recall 0.53, F1 0.464 over 54 sessions |
| Dropped by the leak guard | 12 renderings |
| Leaving out inputs that share one gated command with the index | 0.192 (0.066 to 0.332), 33 procedures |
| Explicit negatives | none in this split, so not measured here |

It beats the baseline by more than its interval, which is what Gate 2 asks. It is also about half of what dev suggested (0.405), and the gap is the expected one: dev's figure was the best of about a hundred candidates on 28 procedures.

**The live worker gives the same answers.** For the 246 held-out steps of that capture run, the label the worker wrote to `mirage.labels` is the offline answer in 246 cases, with no input labelled twice.

**Two corrections made after the read, neither a tuning choice.** Ties between index entries that name different techniques were being settled by floating-point noise, differently on two machines; they now follow a fixed order (the lab's procedures, then the public corpus, then technique ID), written before looking at which answer it favours. Technique micro-F1 did not change; session tactic F1 went from 0.473 on Linux and 0.505 on macOS to 0.464 on both. And the leak guard now holds every fitted text in the unit the model reads, not only whole lines.

## What this does not show, and what would help

- **Dev picked a winner among about a hundred candidates on 28 procedures.** The intervals of the top ten overlap almost entirely. The dev figure for the pick is the maximum of many noisy estimates, and the held-out figure is what to believe.
- **A held-out procedure is a different command for the same technique, by construction.** That is the hard case. A command the tagger has seen is matched exactly, and repeated commands are most of what bots send; the leak guard keeps those out of the score on purpose.
- **About three training procedures per technique.** The public corpus helped more than any change of model. More labelled procedures is the lever, not a larger encoder.
- **A technique with no index entry is never named.** Retrieval can only answer with what it holds. The public corpus widens that a little: on test, a technique with no lab training procedure got recall 0.25; on dev, three such techniques got none.
- **Choosing by cross-validation over train and dev** (164 procedures instead of 41) would make the choice less noisy. It has to be judged on procedures nobody has scored yet, so it waits for the catalogue to grow.

## Reproduce

```bash
uv run --group research python -m mirage_intel.experiments.tagger_bench \
    --embedders bge-small,minilm,securebert2,shellbert \
    --attack data/attack/enterprise-attack-20.1.json --atomic data/atomic/linux-index.yaml \
    --together 3 --logprecis
```

Result files on the lab host: `build/experiments/tagger/dev-20261114T194537Z.json` (full grid) and `dev-20261114T200341Z.json` (layers together, LogPrécis).
