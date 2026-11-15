# Experiment: is there anything for a learned policy to gain

15 November 2026 · [phase 3 spec 3.3, "First"](../../06-phase-3-spec.md) · asked for by [the survey](../../research/deception-rl.md), section 5 · script: `intel/src/mirage_intel/experiments/rl_checks.py`

## Question

Phase 2 found no learned policy that beats the rules. Before phase 3 builds a better learner, four things are checked on the decisions phase 2 already logged:

1. Does what the decoy answers change what the attacker does next, and does any answer raise what a session is worth?
2. Is a careful learner, at the careful end of its dial, the rule?
3. How do learners that leave the rule only where the data support it compare with the rules?
4. How much of the reward's exit penalty is coincidence, and is one file paid for many times?

## Data

The frozen phase 2 decisions (`eval/datasets/gate2/decisions.parquet`), train and dev sessions only: 4,181 usable decisions in 782 sessions from 40 scenario groups. The test sessions were read once for phase 2's shadow and are not read here.

The explorer chose each action at random with a logged probability (ε = 0.3 around the rule, which is `allow` on every one of these decisions). So each decision is a small randomised experiment, and the effect of an answer can be read without a model.

## Protocol

- **An answer's effect** is the outcome after that answer minus the outcome after `allow`, each a self-normalised inverse-propensity mean over the decisions where the answer was allowed.
- **Outcomes:** whether the session goes on, how many inputs follow, whether the next input repeats this one, the reward-to-go, and the reward-to-go without the −2 exit penalty.
- **Learners** are cross-fitted over five folds of scenario groups, so every decision is scored by a policy and a reward model that saw no session of its scenario. The figure is the doubly robust difference to the rules per decision.
- **Like for like.** The candidate and the rules are scored with the same 10% exploration share. Phase 2 scored the rules without it.
- **Intervals** are 95%, computed twice (resampling sessions, and resampling scenario groups, since sessions of one scenario are repeats of one script), and the wider is reported. The exact interval the offline screen will add is not built yet.
- **Reward** is the ground-truth one, as in phase 2's selection.

## Results

### 1. Answers change what follows, and only for the worse

After `allow` a session goes on 85% of the time and 3.2 more inputs follow.

| Answer | Times taken | Session goes on | Inputs that follow | Reward-to-go | Reward-to-go without the exit penalty |
| --- | --- | --- | --- | --- | --- |
| `delay` | 315 | −0.03 (−0.08 to +0.01) | −0.12 (−0.43 to +0.23) | −0.48 (−0.75 to −0.21) | −0.13 (−0.35 to +0.12) |
| `fake_success` | 278 | −0.05 (−0.12 to +0.01) | −0.22 (−0.59 to +0.18) | −0.66 (−0.98 to −0.36) | −0.26 (−0.52 to −0.01) |
| `fake_error` | 277 | −0.11 (−0.17 to −0.05) | −0.51 (−0.82 to −0.20) | −0.83 (−1.10 to −0.59) | −0.32 (−0.52 to −0.13) |
| `terminate` | 136 | −0.78 (−0.84 to −0.66) | −2.84 (−3.61 to −1.88) | −3.10 (−3.64 to −2.47) | −1.25 (−1.75 to −0.70) |

- The lab's attackers do react: a fake error makes a session 11 points less likely to go on and costs half an input. A delay changes nothing that can be detected.
- No answer raises the reward. Three of the four lower it even with the exit penalty taken out.
- Looked at by protocol and by verb class (32 cases where an answer was taken at least 20 times), none has an interval above zero. The nearest is network commands: `fake_error` +0.67 (−0.02 to +1.37, 28 times) and `delay` +0.62 (−0.07 to +1.31, 25 times).

### 2. Imitation

The rule is `allow` on all 4,181 decisions, so this is trivial here: both learner families agree with the rule on 100% of held-out decisions at the careful end of their dial. It becomes a real check with rules v2.

### 3. Careful learners lose less; none gains

| Learner | Difference to the rules | Decisions changed | Effective sample: decisions, sessions |
| --- | --- | --- | --- |
| Table, support ≥ 60 or 120 | 0 (it is the rule) | 0% | |
| Table, support ≥ 30 | −0.016 (−0.069 to +0.037) | 2% | 2,764, 540 |
| Table, support ≥ 15 | −0.066 (−0.162 to +0.021) | 8% | 1,981, 498 |
| Cautious linear, z = 3 | −0.025 (−0.079 to +0.013) | 2% | 2,896, 541 |
| Cautious linear, z = 2 | −0.046 (−0.112 to +0.009) | 4% | 2,383, 522 |
| Cautious linear, z = 1 | −0.167 (−0.307 to −0.036) | 21% | 1,062, 416 |
| Cautious linear, z = 0 | −0.415 (−0.616 to −0.220) | 52% | 592, 328 |
| Linear, greedy (phase 2's shadow) | −0.408 (−0.621 to −0.217) | 53% | 579, 318 |

- The dial works: the more careful the learner, the fewer decisions it changes, the more of the data it keeps, and the closer it is to the rules.
- Nothing gains, which is what result 1 predicts. A learner that is not careful is worse than the rules with an interval that excludes zero.
- The ten heaviest sessions carry 4% to 7% of the weight, so no handful of sessions decides these figures.
- **Phase 2 charged every learned policy 0.08 before looking at its choices.** The rules with the 10% exploration share, minus the rules without it: −0.081 (−0.096 to −0.067). Phase 2's held-out figure for the shadow (−0.164) includes that charge.

### 4. The reward

- **The exit penalty is mostly coincidence for the mild answers.** It fired on 309 decisions (−618 in all, against 6,357 paid for everything else). A session ends after `allow` 15% of the time anyway, so of the times the penalty fired, the session would have ended there regardless in 81% of cases for `delay`, 73% for `fake_success`, 57% for `fake_error` and 16% for `terminate`.
- **One file is paid for many times.** In the explore run 224 distinct file contents were captured 307 times, one of them in 28 sessions: 27% of the file reward was for content already captured. (Counted in the lab host's store for run `r20261114214550-b64a24`; the frozen table holds only the total.)
- **Never leaving `allow` is not a loophole here.** It is the best policy on this traffic with or without the penalty.

## What it means for phase 3

1. **With phase 2's five actions there was nothing to win.** They can only withhold or break something, and the reward pays for the attacker getting further. No learner, estimator or amount of data would have changed that result.
2. **A learned policy can win only through the new actions**, `respond` and `plant_token`, which give the attacker a reason to go on. The campaign's exploration belongs there. The spec's campaign now puts two thirds of the exploration share on them where they are eligible.
3. **Score like for like.** The offline screen scores the candidate and the rules with the same exploration share.
4. **The two reward fixes are confirmed on data**: the exit penalty is reported with and without, and a file is paid once per content.
5. **One hypothesis to carry into the campaign:** an error or a delay on a network fetch may push the attacker to another route that leaves more behind. It is not established here.

## What this does not show

- These are phase 2's scripted scenarios. Depth scenarios react more by construction; LLM agents and people are untested. "Nothing to gain" is a statement about this traffic and these five actions.
- The contexts were examined one way at a time. A gain confined to a narrower context would be missed.
- The intervals are bootstrap intervals. The estimate itself is a one-step claim: it says what one departure from the rules is worth.
- The reward is the lab's ground-truth reward.

## Reproduce

```bash
uv run python -m mirage_intel.experiments.rl_checks --draws 1000
```

It needs no model and no running stack, and takes about half a minute. The result file is `build/experiments/phase-3/rl-checks.json`.
