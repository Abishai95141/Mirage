# RL for the response policy: what is known, and what it changes

15 November 2026 · [phase 3 spec, R23 and 3.3](../06-phase-3-spec.md) · the long version with every source: [the survey report](../../reports/Deception%20RL%20design%20survey.md)

This is the survey R23 asks for before the learned policy of 3.3 is designed. It has three parts: what the literature and the open-source code say, what our own decision log says when read in that light, and a decision on each default of 3.3. Decisions marked **yours** changed the spec's scope; all three were agreed on 15 November 2026 and the spec's section 3.3 is revised from the table in section 4.

**How it was made.** Six research threads, one per question, each told to open a source before citing it and to mark what it read only as an abstract or took second-hand. A seventh pass wrote [the report](../../reports/Deception%20RL%20design%20survey.md). I then opened the thirteen sources the decisions below lean on most and checked the numbers quoted from them (section 6), and recomputed the arithmetic on our own logs. Nothing from any repository was installed or run.

## 1. The short version

- **Nobody has published this design.** No honeypot paper treats the choice of a response to each input as a contextual bandit, and none evaluates a policy from logs with logged probabilities. No public honeypot code or dataset records action probabilities. There is no baseline to copy.
- **The published evidence for RL honeypots is thin.** They are small tabular learners with hand-set rewards, compared without intervals. A learned policy that fails to beat rules is the common result, and gains appear only where attackers branch on the decoy's output.
- **The problem is sequential, but a few thousand decisions support one step.** Every formal model of in-session deception is sequential, and people and LLM agents do react to responses. What can be learned and checked at our scale is a one-step improvement on the rules.
- **Phase 2's estimate was a one-step claim.** Scoring a decision by its reward-to-go estimates "depart from the rules once, then follow them", not the value of the learned policy acting through a session. Our logs cannot support the second claim at all (section 2).
- **The campaign 3.3 planned would have made evaluation harder.** Eight actions at the same ε cut the effective sample by about a third.
- **In the lab the clean test is affordable.** Sessions are cheap and the attacker is ours, so whole sessions can be randomised between the rules and a candidate. That measures session value with no weights and no model, and it also tells us how far to trust the offline estimate when, on real traffic, it is the only one available.
- **The reward is mostly right.** It already avoids the proxies the literature criticises (session length, command counts). It has four loopholes worth closing before a learned policy acts.
- **Scripts cannot settle it.** In one 2026 measurement 99.23% of authenticated SSH sessions were non-interactive. A policy meant for agents and people has to be tested on them, which is phase 4.

## 2. What our own logs say

Computed on the frozen phase 2 decisions (`eval/datasets/gate2/decisions.parquet`, 5,055 usable decisions in 942 sessions).

| Fact | Value | Why it matters |
| --- | --- | --- |
| The rule's action | `allow` on every decision | Phase 2's rules never do anything else, so the question the bandit faced was only "when is something other than allow better" |
| Logged action equals the rule's | 76.7% | As designed (ε = 0.3 over four or five allowed actions) |
| Effective sample per decision, predicted | 0.23 with four actions, 0.19 with five, for a policy that departs on a quarter of decisions | From the formula below |
| Effective sample on the test split, predicted against measured | 186 against 208 (874 decisions) | The formula describes our data. The effective sample is counted in decisions of the evaluated split, not in sessions |
| Sessions in which every logged action was the rule's | 263 of 942 (28%) | A whole-session estimate keeps only sessions whose every step matches the policy being judged. For a policy that departs from the rules it keeps almost none |
| A session's value (reward after its first decision) | mean 2.08, standard deviation 2.15; 1.11 within a scenario | Pairing by scenario halves the spread, so a randomised comparison needs a quarter of the sessions |

**Effective sample under ε-greedy logging.** For a policy that picks one action and departs from the rule on a share *d* of decisions, with *K* allowed actions:

    effective sample per decision = 1 / [ (1 − d) / (1 − ε + ε/K) + d·K/ε ]

| ε = 0.3 | d = 0.1 | d = 0.25 | d = 0.5 |
| --- | --- | --- | --- |
| K = 5 | 0.35 | 0.19 | 0.11 |
| K = 8 | 0.26 | 0.13 | 0.07 |

Two levers follow, and neither is "more of the same": a learner that departs rarely keeps two to three times as much of the data, and fewer eligible actions per context keep more.

**How much data.** The phase 2 test interval had a half-width of 0.31 on 160 sessions. An interval that excludes zero with 80% power then needs about 350 evaluation sessions for a true improvement of 0.3 per decision, 790 for 0.2 and 1,400 for 0.15, under the same logging; about half as many again with eight actions. A randomised comparison paired by scenario needs about 215 sessions per arm to detect a difference of 0.3 in session value, and 480 for 0.2. (The survey report's own table of sessions needed started from 950 sessions and is about six times too high; this replaces it.)

## 3. What was found

**Formulation.** The standard taxonomy of defensive deception says dynamic models are needed for attacker engagement, and every model found for in-session response is sequential ([Pawlick, Colbert and Zhu 2019](https://arxiv.org/abs/1712.05441)). People react: among 123 professional red teamers, 52% of commands naming an address went to decoys, and being told deception might be present changed their behaviour ([Ferguson-Walter et al. 2021](https://www.usenix.org/system/files/sec21-ferguson-walter.pdf)). LLM agents react: 21 models exploited planted traps 73.4% of the time even after recognising them ([Prinos et al. 2026](https://arxiv.org/abs/2606.21037), preprint). Scripts mostly do not: 99.23% of 177,622 authenticated SSH sessions were non-interactive ([Valeros et al. 2026](https://arxiv.org/abs/2606.28006), preprint). Against that, small-data work treats a short horizon as a regulariser, and the one sequential learner that worked from a few hundred episodes used a deliberately tiny design: 311 dialogues, 42 states with two vetted actions each, uniform choice between them ([Singh et al. 2002](https://arxiv.org/abs/1106.0676)).

**Reward.** The closest precedent pays +5 for a malware upload, +1 for an exploit and −1 when a session ends with neither, and captured 467 uploads against 92 for its random-reply arm ([Guan et al. 2023](https://arxiv.org/abs/2305.06430)). Length is a poor proxy: a prompt that kept LLM attackers talking raised requests from 78.5 to 101.9 and the rate at which they detected the honeypot from 0.24 to 0.45 ([Vero et al. 2026](https://arxiv.org/abs/2605.29963), preprint). No study validates a honeypot reward against an analyst's judgement of value.

**Exploration and logging.** A deployed bandit team warns that ε-greedy leaves little for a policy that departs from the logger (with 20 actions and ε = 0.1, 1% of the data), found that keeping the learned policy near the logger raised the effective sample about fivefold, and advises starting by imitating the production policy ([Karampatziakis et al. 2019](https://arxiv.org/abs/1905.02219)). The logging policy that minimises the variance of a later evaluation can be computed when the target is known ([Tucker and Joachims 2022](https://arxiv.org/abs/2202.01721)); with nothing known it is uniform. Exploration is itself a tell: an agent that randomly blocks ordinary commands can be fingerprinted (survey report, exploration section).

**Evaluation.** The session is the independent unit. Bootstrap intervals are approximate and can be too narrow when a few sessions carry most of the weight, which is our case; exact intervals built on betting are the tightest exact option reported, on their authors' own simulations (survey report, evaluation section; not opened by me). A candidate chosen on the data it is tested on is overestimated, so the candidate is frozen first.

**Learners and software.** What suits a few thousand decisions is a small model that stays with the rule unless the data support leaving it. Nothing supports deep offline RL at this size. The two dedicated evaluation libraries are dormant (Open Bandit Pipeline since 2022, SCOPE-RL since 2023); Vowpal Wabbit is alive (9.11.9, 27 September 2026) with one main maintainer. The earlier RL honeypots' code is unmaintained and mostly unlicensed.

**Attackers.** Told that a system "might be real or a honeypot", 69.8% of participants called an LLM shell a honeypot and 65.2% called a real Ubuntu system one ([Sladić et al. 2025](https://arxiv.org/abs/2510.06975)), so a judgement without a real-host control means little. LLM pentesting agents told about honeypot fingerprints went from 19% to 97% correct identification ([Cordeiro et al. 2026](https://arxiv.org/abs/2609.26555), preprint).

## 4. Decisions on the defaults of 3.3

| Default in 3.3 | Decision | To what, and why |
| --- | --- | --- |
| A contextual bandit on reward-to-go | **Keep**, and say what it claims | It learns one step of improvement on the rules. The spec and every report say "depart once, then follow the rules", never "the policy's value" |
| Sequential RL out of scope (section 9) | **Keep, yours** | Our logs cannot evaluate it (28% of sessions follow the rules throughout; the estimate for a departing policy keeps almost none). The ladder in section 5 says when it comes back |
| Context: the rules-based `last_tactic` | **Change** | The starter rules fire on one input in seven. Use an exact-match lookup from the tagger's index, in-process, and add history features: the previous action, and whether this session has already seen a non-allow action |
| `escalate` as an explored action | **Change, yours** | Decide it by rule at session level and keep it out of the per-input learner. It is close to irreversible, published systems treat it as a session decision, and each action removed from exploration returns effective sample |
| Reward v2 terms | **Keep, with four fixes** | A captured file counts once per hash across sessions; token contact is counted apart when the policy planted or pointed to the token; the −2 stays as a logged component and every result is also given without it; the outcome is reported as a vector beside the scalar |
| Exploration: ε = 0.3 around rules v2 over all allowed actions, at least 600 sessions | **Change** | Explore within a per-context eligible set, logged with the decision. About 1,200 sessions, every one evaluated through cross-fitting by scenario group, so that an improvement of 0.2 is detectable |
| Training: Vowpal Wabbit | **Change** | A small learner that leaves the rule only where support allows, with the threshold as the dial. First show it can imitate the rule. Phase 2's table with a support threshold is this idea; add a linear model with a lower-confidence-bound rule. Vowpal Wabbit stays as a comparison |
| Off-policy gate: support, effective sample of 200, interval above zero | **Keep, tightened** | One candidate named before the evaluation data are read. The difference is computed per session. An exact interval is reported beside the bootstrap and the wider one decides. Effective sample is counted per session, with the share of weight held by the top sessions |
| Acting in the act range, 200 sessions per arm, difference reported | **Keep, and make it decide** | Sessions randomised between rules v2 and the frozen candidate, paired by scenario and seed, 500 per arm. This is the only measurement of whole-session value |
| (new) Does the offline estimate predict the randomised result? | **Add** | Reported for every candidate that reaches the act range. It is what tells us how far to trust the offline gate on real traffic, where no randomised arm will exist |
| Estimators: IPS, SNIPS, doubly robust | **Keep**, written here | No new dependency. The dormant libraries are used to cross-check |

## 5. What to run first, and the ladder

On the frozen phase 2 decisions, train and dev sessions only (the test sessions have been read once). **Run on 15 November 2026: [the results](../experiments/phase-3/rl-checks.md).** In short, the attackers do react, but with phase 2's five actions no answer raises the reward anywhere, so rung 1 is where the work stays and the new actions are where a gain can come from.

1. **The closed-loop test.** Given the context, does the next input, or whether the session continues, depend on the action taken? If it does not, no policy can gain anything on that traffic and the scenarios need attackers that react. If it does, the next rung is justified.
2. **Imitation.** Can the model reproduce the rule from the log? If it cannot, nothing built on it means anything.
3. **Conservative learners** at several support thresholds, each judged by per-session differences with both intervals.
4. **The reward's loopholes**: the same file counted across sessions, and a policy that never leaves `allow`.

The ladder, and what moves the work up it:

| Rung | What | What justifies it |
| --- | --- | --- |
| 1 (now) | One-step improvement on the rules, conservatively learned, decided by randomised sessions | Nothing more is needed |
| 2 | The same, with history features and a small penalty for delayed effects | The closed-loop test finds dependence |
| 3 | A small sequential model over a coarse session state, with the rule as fallback where data are thin | Attackers that react (phase 4's agents) and about ten times the sessions |
| 4 | Deliberately randomised, game-style policies | Evidence that attackers learn the policy across sessions |

## 6. What I checked myself

| Source | Checked against its own text |
| --- | --- |
| Vero et al. 2026 (Honeyval) | 78.5 and 101.9 requests, detection 0.24 and 0.45, the real-application control |
| Valeros, Sladić and Garcia 2026 | 177,622 sessions, 99.23% non-interactive, 0.10% interactive |
| Cordeiro et al. 2026 (Rouxii) | 19% to 97%, 1,544 attack reports (abstract) |
| Prinos et al. 2026 | 21 models, 73.4%, worse than 47 people (abstract) |
| Sladić et al. 2025 (VelLMes) | 89 participants, 69.77% and 65.22%, what they were told |
| Bridges et al. 2025; Möller 2025 | That they exist and are what the report says (abstracts) |
| Guan, Liu and Cao 2023 (HoneyIoT) | Rewards 5, 1 and −1; 467 against 92 uploads; trained on a model built from traces |
| Ferguson-Walter et al. 2021 | 123 participants, 52%, 11.74 and 20.59 minutes, 6.5 and 1.4 exploits |
| Karampatziakis et al. 2019 | The 0.01n example, the imitation advice, the seed incident |
| Singh et al. 2002 (NJFun) | 311 dialogues, 42 choice-states, 52% to 64% |
| Tucker and Joachims 2022 | Title and what it computes (abstract) |
| Vowpal Wabbit | Release 9.11.9 on 27 September 2026 |
| Our decision log | Every number in section 2 |

Not checked by me: everything else in [the report](../../reports/Deception%20RL%20design%20survey.md), which carries its own tags for abstract-only and second-hand reading. The founding papers (Heliza, RASSH, IRASSH-T) were behind paywalls and are described second-hand throughout. The 2026 items are preprints and may change.

## 7. Decisions that are yours

All three were accepted on 15 November 2026.

1. **Keep sequential RL out of this phase's scope**, with the ladder above as the way back in. The alternative is to build rung 3 now, on scripted attackers, where it cannot be evaluated.
2. **Take `escalate` out of the learned policy** and decide it by rule.
3. **Make the randomised comparison the deciding test** for a learned policy in the lab, with the offline gate as the screen before it. Gate 3 test 9 would then read: the offline screen passes, and in randomised sessions the learned policy is better than rules v2 by more than its interval.
