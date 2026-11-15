# Experiment: which actor classifier

15 November 2026 · [phase 2 spec 2.3](../../05-phase-2-spec.md) · gap register V7, V8, M3 · script: `intel/src/mirage_intel/experiments/classifier_bench.py`

## Question

Which model family should say whether a session is a scanner, a scripted bot or a person, and what do the keystroke features add to the event-level ones?

## Data

Development collection: capture run `r20261114182725-983b55` on the lab host, rendered from the lab seed. 390 logical sessions from 58 scenarios in 50 scenario groups (a scenario and its timing twins form one group).

This is not the frozen dataset. The choice made here is fixed in `eval/choices.yaml` and measured again on the frozen collection, so the figure the gate reads is not the one that won this comparison.

## Protocol

- **Held out by scenario group**, five folds dealt class by class, so a human-paced twin is never tested against a model trained on its bot original. Every session is predicted once.
- **Five fold seeds** per candidate; the mean over seeds is compared.
- **Scored on the sessions the rule leaves.** A session that never held access is a scanner by definition, and the rule says so without a model. Counting those would flatter any candidate.
- **Intervals resample scenario groups** (1,000 draws), not sessions.
- **Candidates are compared as pairs.** Under one fold seed two candidates predict the same sessions, so each resample gives their difference on identical sessions. That interval is far tighter than either candidate's own.
- **Pick:** the simplest family (logistic regression, then random forest, then gradient boosting) shown to be within 0.02 macro-F1 of the best, meaning the upper end of the 95% interval on (best − candidate) is at most 0.02. Otherwise the best.
- **Fixed hyperparameters** per family. With 44 groups a tuning grid would mostly fit noise.

The spec fixes the two variants that are served: event-level (works on any Cowrie data) and full (event-level plus keystrokes). The experiment picks a family for each. Feature sets are compared as an ablation.

## Two corrections the first pass forced

**The pick rule.** The first version took the simplest candidate whose mean was inside the best one's own interval. That interval was 0.3 wide and the rule chose logistic regression on event features at 0.720 over a random forest at 0.894. The paired rule above replaced it.

**The scanner class.** In the first pass the model was asked to separate scanners from bots among sessions with no login, and got 0.72 F1 on scanners. Every one of those errors was a session without access carrying a bot's label, or a Redis session (which needs no login) mistaken for a scanner. A model that does not read content cannot tell these apart, and the spec's definition does not ask it to: a scanner is a session with no authenticated activity. So:

- the session label is now `scanner` when the session never held access, whoever made it;
- access means a login that succeeded, or input to a service that asks for none (Redis here);
- the rule settles all of those, and the model's job is bot or person.

This moved 42 sessions from the model to the rule (78 rule-settled, 312 left to the model).

## Results

312 sessions left to the model (258 scripted bot, 54 human) in 44 groups. Majority-class macro-F1 is 0.453.

| Candidate | Macro-F1 | 95% interval | Above majority | Best of its set − this | Human F1 | Bot F1 |
| --- | --- | --- | --- | --- | --- | --- |
| forest / both | **0.993** | 0.980 to 1.000 | +0.515 to +0.567 | best | 0.99 | 1.00 |
| gbm / both | 0.986 | 0.967 to 1.000 | +0.505 to +0.559 | 0.000 to +0.022 | 0.98 | 0.99 |
| logreg / both | 0.986 | 0.967 to 1.000 | +0.503 to +0.563 | −0.003 to +0.027 | 0.98 | 0.99 |
| forest / event | **0.903** | 0.805 to 0.968 | +0.338 to +0.521 | best | 0.84 | 0.97 |
| gbm / event | 0.879 | 0.777 to 0.951 | +0.309 to +0.505 | −0.015 to +0.080 | 0.80 | 0.96 |
| logreg / event | 0.837 | 0.693 to 0.941 | +0.226 to +0.497 | −0.022 to +0.171 | 0.74 | 0.94 |
| forest / keystrokes | 0.992 | 0.979 to 1.000 | +0.513 to +0.565 | best | 0.99 | 1.00 |
| gbm / keystrokes | 0.987 | 0.968 to 1.000 | +0.505 to +0.561 | 0.000 to +0.017 | 0.98 | 1.00 |
| logreg / keystrokes | 0.968 | 0.939 to 0.998 | +0.477 to +0.552 | −0.004 to +0.053 | 0.95 | 0.99 |

Ablation for the chosen family: the full model gains +0.023 to +0.187 over event-level features alone, and 0.000 to +0.004 over keystrokes alone.

The full model's errors: one human-paced session per seed in `human-probe-files` called a bot, and one in five seeds in `smoke-human-look`.

## Decision

- **Full variant: random forest on both feature sets.** No simpler family is shown to be within 0.02.
- **Event-level variant: random forest on event features**, for data with no keystroke log (the Zenodo sample).
- A keystroke-only model scores the same as the full one here, and is not served: a session on a protocol with no terminal has no keystrokes, and only the event features can speak for it.

The forest is saved as plain JSON arrays and predicted by the project's own code (`classifier.Forest`), in evaluation and when served, so no pickle is loaded and there is one implementation to trust. A test checks it against scikit-learn.

## On the frozen collection

The choice was fixed, then measured again on the clean collection that became `eval/datasets/gate2` (capture run `r20261114212942-973f72`): the same scenarios, a separate run.

| | Sessions the rule leaves (312, 44 groups) |
| --- | --- |
| Full variant, forest / both | 0.994 (0.981 to 1.000); human 0.991, bot 0.998 |
| Above the majority class | +0.516 to +0.569 |
| All 390 sessions, above the rule alone | +0.343 to +0.379 (0.996 against 0.635) |
| Event-level variant, forest / event | 0.902 (0.787 to 0.979); human 0.839, bot 0.965 |
| Errors of the full variant | one human-paced session called a bot |

**Real traffic.** On 3,560 sessions of the replayed public Cowrie sample, the rule settles 2,774 and the event-level model calls all of the other 786 scripted bots, none a person. It agrees with the "same commands from three or more sources" heuristic on all 381 such sessions, and calls the 88 that logged in and typed nothing bots where the heuristic says scanner. Nothing here has ground truth.

## What this does not show

- **The human class is our own typing generator.** Eight of nine human scenarios are twins of bot scenarios with generated keystrokes. The result says the model separates that generator from a bot replaying the same steps. It says nothing yet about real people; `make lab-human` records them (spec Q8).
- **Every human session is SSH.** Nothing here tests a person on MySQL, Redis or HTTP.
- **Scanner versus the rest is a rule**, right by construction. It is reported in the all-session figure and kept out of the gate.

## Reproduce

```bash
uv run python -m mirage_intel.dataset --run r20261114182725-983b55 --out build/dataset
uv run --group research python -m mirage_intel.experiments.classifier_bench --seeds 5 --draws 1000
```

Result file on the lab host: `build/experiments/classifier/cv-20261114T200315Z.json`.
