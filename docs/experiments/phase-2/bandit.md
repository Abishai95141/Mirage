# Experiment: does a learned response policy beat the rules

15 November 2026 · [phase 2 spec 2.5](../../05-phase-2-spec.md) · Gate 2 test 9 · gap register V10 to V13 · script: `intel/src/mirage_intel/experiments/bandit_bench.py`

## Question

From decisions logged while the lab's exploring policy acted, can a policy be learned that would have earned more than the rules? And which learner should shadow the rules in the meantime?

## Data

Explore run `r20261114184239-c901a6` on the lab host: 944 sessions, 5,156 logged decisions. 5,132 are usable; 24 are excluded because the decoy fell back to `allow` and did not apply what the log says. No usable decision has an applied action that differs from the logged one.

Decisions are split by their scenario's split: 3,568 to fit on (train), 763 in 144 sessions to compare on (dev), 801 held back (test).

Reward is reward-to-go as the spec defines it: every decision is paid for what follows it in its session. It is computed twice, from ground truth and from the tagger's labels. Selection uses ground truth, which only the lab has.

## Protocol

- **Logging policy:** epsilon-greedy around the rule's action, ε = 0.3, with the exact probability of each action logged.
- **Learners:** a per-context table of mean rewards with back-off (three support levels); a ridge-regularised linear model per action, with and without inverse-propensity weights (three strengths each); Vowpal Wabbit contextual bandit with three cost estimators.
- **Estimators:** inverse propensity (IPS), self-normalised (SNIPS) and doubly robust (DR), each on the difference between the learner and the rules over the same decisions.
- **Intervals resample sessions** (1,000 draws). Decisions in one session share a reward and are not independent.
- **A learned policy is scored as it would act:** its choice, with a tenth of the probability spread over every allowed action. The rules are scored as they act.
- **Fit to act** means all three estimators agree in sign and the DR interval is above zero. The pick is the simplest such learner. If none qualifies, the rules stay.

## Results

Rules' value on dev sessions (SNIPS): 1.565.

| Learner | DR difference | 95% interval | SNIPS | IPS | Share of decisions changed | Effective sample |
| --- | --- | --- | --- | --- | --- | --- |
| table, support ≥ 60 | −0.036 | −0.064 to −0.011 | −0.038 | −0.030 | 0.00 | 670 |
| table, support ≥ 15 | −0.133 | −0.312 to +0.001 | −0.134 | −0.132 | 0.08 | 364 |
| table, support ≥ 30 | −0.277 | −0.650 to +0.108 | −0.261 | −0.196 | 0.25 | 180 |
| linear, weighted (any ridge) | +0.359 | −0.273 to +0.977 | +0.247 | +0.407 | 0.67 | 90 |
| linear, ridge 0.3 | +0.322 | −0.371 to +0.991 | +0.212 | +0.376 | 0.73 | 86 |
| linear, ridge 1 or 3 | +0.264 | −0.391 to +0.942 | +0.117 | +0.313 | 0.69 | 90 |
| Vowpal Wabbit, MTR | +0.109 | −0.464 to +0.702 | +0.114 | +0.275 | 0.51 | 110 |
| Vowpal Wabbit, DR | +0.109 | −0.469 to +0.661 | +0.059 | +0.182 | 0.59 | 97 |
| Vowpal Wabbit, IPS | +0.141 | −0.491 to +0.741 | −0.004 | +0.138 | 0.62 | 96 |

When every session is given equal weight, every learner's difference is negative (−0.07 to −0.91).

## Decision

- **To act: the rules.** No learner is fit to act. The linear models look better by about a quarter of the rules' value, but the interval runs from well below zero to well above, and the session-balanced estimate has the opposite sign.
- **To shadow: the weighted linear model (ridge 1).** Among learners that can be saved as a file and differ from the rules on at least 5% of decisions, it has the highest lower end of the DR interval. The policy service loads it read-only and logs what it would have done beside every decision. It never acts.

Gate 2 test 9 asks for the shadow policy's value against the rules' with an interval, not for it to win. That is what this reports.

## On the frozen collection

The shadow was fixed, refitted on the train and dev sessions of the clean explore run (`r20261114214550-b64a24`) and scored once on its test sessions: 874 usable decisions in 160 sessions.

| Estimator | Shadow minus rules | 95% interval |
| --- | --- | --- |
| Doubly robust | −0.164 | −0.509 to +0.107 |
| SNIPS | −0.130 | −0.364 to +0.093 |
| IPS | −0.031 | −0.303 to +0.250 |

Effective sample 208; the shadow differs from the rules on 25% of decisions. On dev the same learner looked better than the rules by 0.36 with an interval from −0.27 to +0.98; here it looks slightly worse, with an interval that still includes zero. Both readings say the same thing: there is no evidence that it beats the rules. It shadows, and the rules act.

In this run 126 of 5,181 logged decisions were excluded because the decoy had fallen back to `allow`. The cause was CPU contention from the tagger's worker, since fixed (spec, section 12).

## Why the evidence is thin

A policy that changes two decisions in three is judged only on the logged decisions where the explorer happened to pick the same action. With ε = 0.3 over four or five allowed actions, each alternative is taken about one time in fifteen. 763 decisions shrink to an effective sample of about 90, and the interval is as wide as the effect.

Two things would narrow it, and neither changes the method:

- more explore sessions (the estimate's width falls with the square root of their number);
- a higher ε in the lab's explore range, which costs nothing there. ε is fixed at 0.3 by the spec, so this is a decision for the phase 3 plan, not something changed here.

## What this does not show

- Rewards come from lab scenarios whose steps are scripted. A scripted attacker reacts to a fake error only as far as its scenario's `expect` checks allow, so the reward a response earns here is a narrow version of what a real attacker's reaction would be. Phase 4's agents are the real test.
- The context carried no verb class in this run (the policy image predated it). The clean run does.

## Reproduce

```bash
uv run python -m mirage_intel.decisions --run r20261114184239-c901a6 --out build/dataset
uv run --group research python -m mirage_intel.experiments.bandit_bench --draws 1000
```

Result files on the lab host: `build/experiments/bandit/dev-20261114T194507Z.json` and `final-20261114T222603Z.json`. The held-out figures above are also in `eval/baselines/gate2.json`.
