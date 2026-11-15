# Exploration strategies and problem formulations for learning a per-step response policy from little data with exactly logged propensities

Notes written 15 November 2026. All source text is paraphrased; numbers are as reported by the source. Conventions used below:

- "Opened" means I fetched the page or PDF and read the part cited. Abstract-only reads are marked "(abstract)"; full-text reads are marked "(full text)".
- "[venue unverified]" means the page I opened did not show the venue and the venue given is from my prior knowledge.
- Anything reported second-hand (search snippet, or a citation inside another source) is labelled "second-hand".
- Items under "Inferences" are my own reasoning or arithmetic, not statements made by a source.

---

## 1. Contextual-bandit exploration that yields exact, loggable propensities

### Takeaway
Any exploration rule whose action distribution is a closed-form function of model scores (epsilon-greedy, softmax, inverse-gap weighting/SquareCB, RegCB-elimination, vote shares from bagging or cover) gives an exact propensity for free at decision time; Thompson sampling does not for more than two actions and is logged in practice with Monte Carlo estimates, and deterministic rules (LinUCB, RegCB-optimistic, greedy) give no usable propensity at all. The only direct experiment I found on off-policy evaluation (OPE) quality by exploration method (the Bake-off paper) reports a trade-off: the most regret-efficient explorers produced poor OPE logs, while epsilon-greedy with its uniform floor produced good ones.

### Cited Findings

**Why the propensity is logged and what it buys**
- The Decision Service logs each event as (context x, action a, reward r, probability p) where p is the exploration policy's probability of the chosen action, and records (x, a, p) at decision time; logging p is what makes unbiased policy learning and evaluation possible. — [Agarwal et al. 2016](https://arxiv.org/abs/1606.03966)
- Its IPS error bound for evaluating K policies simultaneously is about sqrt((C/(eps*N)) * log(K/delta)), where eps is the minimum per-action probability (eps0/|A| for epsilon-greedy) and N the number of events; error grows only as log K in the number of policies, against sqrt(K/N * log(K/delta)) for A/B testing. With eps = 0 arbitrary policies cannot be evaluated. — [Agarwal et al. 2016](https://arxiv.org/abs/1606.03966)
- In a simulated failure study in the same paper, logging an incorrect probability produced a 3.0x train/test discrepancy; leaking the decision into the features 8.7x; reward-delay bias 1.3x. It also warns that downstream overrides of the chosen action make the logged probability wrong. — [Agarwal et al. 2016](https://arxiv.org/abs/1606.03966)
- IPS needs the logging policy to give non-zero probability to every action in every context (full support); the authors show existing IPS-based methods can fail badly when support is deficient and analyse three remedies (restrict the action space, extrapolate rewards, restrict the policy space). — [Sachdeva, Su, Joachims 2020](https://arxiv.org/abs/2006.09438)

**Epsilon-greedy (fixed, decaying, uniform floor)**
- Distribution: p(a) = eps/K + (1 - eps) * 1{a = greedy action}. — [Bietti, Agarwal, Langford 2021](https://arxiv.org/abs/1802.04064)
- Defaults in deployed systems: Vowpal Wabbit (VW) uses epsilon-greedy with eps = 0.05 if no exploration flag is given; the Decision Service default at MSN was eps = 33%; Azure Personalizer used epsilon-greedy with a configurable exploration percentage. — [VW wiki](https://github.com/VowpalWabbit/vowpal_wabbit/wiki/Contextual-Bandit-algorithms); [Agarwal et al. 2016](https://arxiv.org/abs/1606.03966); [Personalizer exploration docs (archived)](https://learn.microsoft.com/en-us/previous-versions/azure/ai-services/personalizer/concepts-exploration)
- Regret view: across 500+ datasets, uniform exploration hurt performance in most cases, and epsilon-greedy and Cover-with-uniform-mixing were weakest on easy datasets where greedy can be best. — [Bietti, Agarwal, Langford 2021](https://arxiv.org/abs/1802.04064)
- OPE view (same paper, Figure 3): when IPS was used to evaluate the uniform-random policy from each method's logs, greedy, RegCB-optimistic and Cover-NU gave poor estimates while epsilon-greedy did well; the authors conclude there may be a trade-off between efficient exploration and good counterfactual evaluation and that uniform exploration may be needed for accurate offline experiments. — [Bietti, Agarwal, Langford 2021](https://arxiv.org/abs/1802.04064)
- A production team recommends against plain epsilon-greedy because it treats all non-preferred actions as equally plausible: with 20 actions and eps = 0.1, a target policy that agrees with the logging policy half the time has an effective sample size of about 0.01n. They moved to rank-weighted randomisation among plausible candidates and suggest softmax over a promoted model's scores. — [Karampatziakis et al. 2019](https://arxiv.org/abs/1905.02219)
- Decaying epsilon: epsilon_t-greedy plays the empirically best arm with probability 1 - eps_t and otherwise uniform; regret of slowly decreasing schedules was analysed by Auer, Cesa-Bianchi and Fischer 2002 (second-hand, cited in the book; not opened). — [Lattimore and Szepesvari, Bandit Algorithms, ch. 6](https://tor-lattimore.com/downloads/book/book.pdf)
- Explore-first (tau-first): VW takes each action with probability 1/k on the first tau examples and then follows the learned predictor. — [VW wiki](https://github.com/VowpalWabbit/vowpal_wabbit/wiki/Contextual-Bandit-algorithms)

**Softmax / Boltzmann**
- VW: P(a) = exp(-lambda * score_a) / sum_i exp(-lambda * score_i) on predicted costs (lambda default 1; higher lambda exploits more); adding --epsilon guarantees each action at least eps/num_actions. Only available with action-dependent features (cb_explore_adf). — [VW wiki](https://github.com/VowpalWabbit/vowpal_wabbit/wiki/Contextual-Bandit-algorithms)
- Theory (multi-armed case): Boltzmann exploration with any monotone learning-rate schedule is suboptimal; a variant with per-arm learning rates achieves near-optimal bounds without knowing the horizon or gap. — [Cesa-Bianchi et al. 2017](https://arxiv.org/abs/1705.10257) (abstract)

**Thompson sampling and how its propensities are obtained**
- Linear-payoff Thompson sampling has a high-probability regret bound of about d^{3/2} sqrt(T) (abstract). — [Agrawal and Goyal 2012](https://arxiv.org/abs/1209.3352)
- Empirically strong and robust to delayed/batched feedback because it randomises: with feedback every delta steps, the UCB/TS regret ratio rose from 2.65 (delta = 1) to 3.82 (delta = 1000); in display-ad simulation TS (posterior scaled by 0.5) had 3.72% regret vs 4.14 to 4.99% for LinUCB and about 5% for epsilon-greedy and exploit-only; shrinking the posterior (alpha < 1) helped; exploit-only did surprisingly well, attributed to implicit exploration from context variation. — [Chapelle and Li 2011](https://papers.nips.cc/paper/2011/hash/e53a0a2978c28872a4505bdb51db06dc-Abstract.html) (full text)
- Propensities by simulation, after the fact: the Open Bandit Dataset computed Bernoulli-TS action probabilities by Monte Carlo simulation from the policy parameters used during collection (the code example uses 100,000 simulations); they are estimates, not closed-form values. — [Saito et al. 2020](https://arxiv.org/abs/2008.07146) (full text)
- Propensities by simulation, online: balanced linear TS takes the propensity of an arm to be the fraction of Monte Carlo posterior draws in which that arm has the highest sampled reward, and clips propensities at a threshold (0.1 suggested; tuned over 0.01 to 0.2). — [Dimakopoulou et al. 2018](https://arxiv.org/abs/1812.06227) (full text)
- Two-action case with clipping: HeartSteps V2 randomises with the posterior probability that a Gaussian linear treatment effect exceeds a threshold, clipped to [0.1, 0.8]; Oralytics clips to [0.35, 0.75]. Both state that keeping probabilities away from 0 and 1 is needed for stable post-study off-policy and causal analyses. — [Liao et al. 2019](https://arxiv.org/abs/1909.03539) (full text); [Trella et al. 2022](https://arxiv.org/abs/2206.03944) (full text)
- Statistical cost of adaptive, decaying propensities: IPW estimates become skewed and heavy-tailed as propensities approach zero, and sample means from adaptively collected data are negatively biased; fixes are adaptively re-weighted AIPW/DR estimators. — [Hadad et al. 2019](https://arxiv.org/abs/1911.02768); [Zhan et al. 2021](https://arxiv.org/abs/2106.02029); [Nie et al. 2018](https://arxiv.org/abs/1708.01977) (abstracts)

**Bagging (bootstrap Thompson sampling) and Online Cover in VW**
- Bag: N policies each trained on a Poisson(1) bootstrap of the stream; the action distribution is proportional to the number of policies choosing each action. Bag-greedy trains the first policy on the un-resampled stream. — [Bietti, Agarwal, Langford 2021](https://arxiv.org/abs/1802.04064)
- Cover: N policies trained for diversity; probabilities are vote shares mixed with uniform exploration eps_t; Cover-NU drops the uniform mixing (VW flag --nounif; --psi default 1). — [Bietti, Agarwal, Langford 2021](https://arxiv.org/abs/1802.04064); [VW 9.6.0 command-line docs](https://vowpalwabbit.org/docs/vowpal_wabbit/python/9.6.0/command_line_args.html)
- Underlying theory: statistically optimal regret for general policy classes with about sqrt(KT / log N) oracle calls. — [Agarwal et al. 2014](https://arxiv.org/abs/1402.0555) (abstract)
- VW flag defaults (version 9.6.0 docs; may be outdated relative to the current release): --bag has epsilon default 0; --cover has epsilon default 0.05; --softmax epsilon default 0. — [VW 9.6.0 command-line docs](https://vowpalwabbit.org/docs/vowpal_wabbit/python/9.6.0/command_line_args.html)

**RegCB**
- Builds confidence bounds from a regression oracle. Optimistic variant: uniform over the actions minimising the lower confidence bound (deterministic up to ties). Elimination variant: uniform over actions whose lower bound is no larger than the smallest upper bound. Needs the loss range in advance. — [Bietti, Agarwal, Langford 2021](https://arxiv.org/abs/1802.04064); [Foster et al. 2018](https://arxiv.org/abs/1803.01088) (abstract)
- VW: --regcb is the elimination variant, --regcbopt the optimistic one; mellowness c_0 default 0.1; cost bounds default [0, 1]; only the mtr (regression) cb_type is supported. — [VW 9.6.0 command-line docs](https://vowpalwabbit.org/docs/vowpal_wabbit/python/9.6.0/command_line_args.html)
- Empirically RegCB-optimistic was best overall and greedy a close second; both have known failure modes and struggle when n is small without a uniform warm start; Cover-NU was more conservative but robust and more competitive on small datasets. — [Bietti, Agarwal, Langford 2021](https://arxiv.org/abs/1802.04064); [JMLR page](https://jmlr.org/papers/v22/18-863.html)

**SquareCB / inverse-gap weighting**
- Rule (attributed by the authors to Abe and Long 1999): with predicted losses y_hat and best action b, p(a) = 1 / (mu + gamma * (y_hat(a) - y_hat(b))) for a != b, remainder on b; mu = K and gamma = sqrt(K T / (Reg_Sq(T) + log(2/delta))). — [Foster and Rakhlin 2020](https://arxiv.org/abs/2002.04926) (full text)
- Regret at most 4 sqrt(K T Reg_Sq(T)) + 8 sqrt(K T log(2/delta)) under realizability, with adversarially chosen contexts allowed; per-round cost is K oracle evaluations; under eps-misspecification regret degrades by an additive term of order eps * sqrt(K) * T. — [Foster and Rakhlin 2020](https://arxiv.org/abs/2002.04926) (full text)
- VW: gamma = gamma_scale * (number of examples)^gamma_exponent, defaults 10 and 0.5; --elim restricts SquareCB to the RegCB plausible-action set. — [VW 9.6.0 command-line docs](https://vowpalwabbit.org/docs/vowpal_wabbit/python/9.6.0/command_line_args.html)
- Offline-oracle counterpart: optimal regret with only O(log T) calls to an offline regression oracle (O(log log T) if T is known). — [Simchi-Levi and Xu 2020](https://arxiv.org/abs/2003.12699) (abstract)

**LinUCB and other deterministic rules: what is logged**
- LinUCB was evaluated offline on previously recorded uniformly random traffic, not on its own logs; it gave a 12.5% click lift over a context-free bandit on 33 million events. — [Li et al. 2010](https://arxiv.org/abs/1003.0146); [Li et al. 2011](https://arxiv.org/abs/1003.5956)
- The replay method uses uniformly randomised serving events and substantially reduces effective data size when the number of arms is large. — [Chapelle and Li 2011](https://papers.nips.cc/paper/2011/hash/e53a0a2978c28872a4505bdb51db06dc-Abstract.html) (full text)
- For UCB the propensity is not known because assignment is deterministic; balanced LinUCB estimates it by fitting a multinomial logistic regression to the history of (context, arm) pairs. — [Dimakopoulou et al. 2018](https://arxiv.org/abs/1812.06227) (full text)
- Methods exist for learning from logs where no randomisation occurred or was recorded. — [Strehl et al. 2010](https://arxiv.org/abs/1003.0120) (abstract)
- Randomised exploration yields logs usable for offline evaluation, in contrast to deterministic greedy and RegCB-optimistic. — [Bietti, Agarwal, Langford 2021](https://arxiv.org/abs/1802.04064)

**Which estimator the logs feed**
- In the agnostic contextual setting IPS and DR match the minimax lower bound up to constants; SWITCH uses a possibly inconsistent reward model for a better bias-variance trade-off. — [Wang, Agarwal, Dudik 2017](https://arxiv.org/abs/1612.01205) (abstract)
- In multi-armed bandits the regression estimator is minimax optimal and the other standard estimators can be arbitrarily worse. — [Li, Munos, Szepesvari 2015](https://proceedings.mlr.press/v38/li15b.html) (abstract)
- DR is accurate if either the reward model or the propensity model is good. — [Dudik et al. 2014](https://arxiv.org/abs/1503.02834); [Dudik, Langford, Li 2011](https://arxiv.org/abs/1103.4601)
- Shrinking importance weights to minimise an MSE bound improves finite-sample DR; self-normalisation counters propensity overfitting. — [Su et al. 2020](https://arxiv.org/abs/1907.09623); [Swaminathan and Joachims 2015b](https://papers.nips.cc/paper/2015/hash/39027dfad5138c9ca0c474d71db915c3-Abstract.html)
- Sample-size dependence: on the Open Bandit Dataset the direct method was most accurate at n = 10,000 while DR with optimistic shrinkage was best at n = 300,000. — [Saito et al. 2020](https://arxiv.org/abs/2008.07146) (full text)
- VW's cb_type options: ips, dm, dr, mtr (default), sm; explore_eval evaluates exploration algorithms from logged (action, cost, probability) data by rejection sampling and is described as very data hungry. — [VW wiki](https://github.com/VowpalWabbit/vowpal_wabbit/wiki/Contextual-Bandit-algorithms); [VW Explore-Eval wiki](https://github.com/VowpalWabbit/vowpal_wabbit/wiki/Explore-Eval)

### Inferences

Comparison table (synthesised from the findings above; the last column is my judgement):

| Method | Action distribution | Exact propensity at decision time | Every action has p > 0 | Extra requirements | Suitability for later OPE of a different policy |
|---|---|---|---|---|---|
| Epsilon-greedy, fixed | eps/K floor plus mass on greedy | Yes, trivial | Yes | None | Good and simple; inefficient use of exploration mass |
| Epsilon-greedy, decaying or context-dependent | Same with eps(t) or eps(x) | Yes, if eps(x) is a logged deterministic function | Yes while eps > 0 | Log eps with each event; data no longer identically distributed across time | Good while the floor stays well above zero; importance weights grow as eps decays |
| Explore-first | Uniform for tau rounds, then greedy | Yes | Only in the first phase | None | Excellent for the uniform block; later block unusable for IPS |
| Softmax | exp(-lambda*cost) normalised, optional eps floor | Yes, closed form | Yes | Calibrated score scale; lambda | Good; concentrates exploration on plausible actions |
| SquareCB / inverse-gap weighting | 1/(K + gamma*gap) | Yes, closed form | Yes (at least 1/(K + gamma*max gap)) | Regression model, gamma schedule | Good early; propensities of poor actions shrink as gamma grows |
| RegCB-elimination | Uniform over surviving actions | Yes | No (eliminated actions get 0) | Confidence widths, loss range | Good inside surviving set; zero support outside |
| RegCB-optimistic, LinUCB, greedy | Deterministic | Propensity is 1; no information | No | - | Not usable with IPS; needs a separate random bucket or a reward model |
| Bagging | Vote share of N bootstrap policies | Yes (multiples of 1/N) | No unless eps added | N models at decision time | Fair with an eps floor; granular propensities |
| Online Cover | Vote share plus uniform eps_t (or none with nounif) | Yes | Yes with uniform mixing | N models, more hyperparameters | Fair; robust |
| Thompson sampling | Probability the arm's posterior draw is best | Closed form only for 2 actions; otherwise Monte Carlo estimate | Yes in principle, can be tiny | Posterior; simulation budget | Weak for exact logging unless clipped and computed offline from frozen parameters |

- Effective sample size arithmetic for epsilon-greedy around a fixed rule (ESS/n = 1 / E[w^2] for a deterministic target that agrees with the rule a fraction q of the time; this formula reproduces the 0.01n figure in Karampatziakis et al. for K = 20, eps = 0.1, q = 0.5). With 5 actions and eps = 0.3 the propensities are 0.76 (rule action) and 0.06 (others); ESS/n is 0.11 at q = 0.5, 0.23 at q = 0.8 and 0.06 at q = 0. With 8 actions (0.7375 and 0.0375) it is 0.07 at q = 0.5 and 0.16 at q = 0.8. Uniform logging gives 0.20 (5 actions) or 0.125 (8 actions) for any deterministic target. So epsilon-greedy at 0.3 only beats uniform logging for targets that agree with the rule more than about three-quarters of the time.
- Moving from 5 to 8 actions at fixed eps cuts the floor from 0.06 to 0.0375 and raises the maximum importance weight from 16.7 to 26.7; holding ESS constant needs a larger eps or exploration restricted to a per-context plausible subset.
- Thompson sampling conflicts with "exactly known probability" at 5 to 8 actions: the logged value would be a Monte Carlo estimate, and a high-accuracy simulation at decision time does not fit a few-millisecond budget. If TS is wanted, the workable patterns in the sources are (a) freeze posterior parameters per batch and compute propensities offline to high precision, or (b) clip to a fixed interval.
- Because training is offline with no online updates, the logging policy is fixed within each deployment period. Events within a period are then independent draws from a fixed policy, so the adaptive-data problems (Hadad, Zhan, Nie) apply only across periods, not within them. This favours batch-fixed softmax or inverse-gap weighting over continuously updated TS/UCB.
- Logging the full action distribution (not just the chosen action's probability), the eligible action set, policy version and random seed costs little and enables balanced multi-logger estimators and audits later.

### Gaps
- I found only one experiment comparing exploration methods by downstream OPE accuracy (Bake-off Figure 3), and it evaluates only the uniform-random target policy on simulated bandit data from supervised datasets. No source compares softmax, SquareCB and TS logs for OPE of an arbitrary learned policy at small n.
- No opened source analyses context-dependent epsilon specifically.
- Not opened: Auer, Cesa-Bianchi, Fischer 2002 (decaying epsilon; cited second-hand via the book); Abe and Long 1999 (origin of inverse-gap weighting; cited second-hand via Foster and Rakhlin).
- VW flag descriptions are from the version 9.6.0 documentation and a wiki page last edited 1 February 2026; the 9.6.0 page was truncated before the generic cb_explore section. Check against the VW version actually used.
- The Bake-off study is on stationary, simulated-bandit data (2018 preprint, 2021 journal version); its rankings may not transfer.

### Sources first cited in this section
- Agarwal, Bird, Cozowicz, Hoang, Langford, Lee, Li, Melamed, Oshri, Ribas, Sen, Slivkins. 2016 (revised 2017). "Making Contextual Decisions with Low Technical Debt" (the Decision Service paper). arXiv preprint. https://arxiv.org/abs/1606.03966 (full text via ar5iv)
- Bietti, Agarwal, Langford. 2021. "A Contextual Bandit Bake-off". JMLR 22(133):1-49. https://arxiv.org/abs/1802.04064 and https://jmlr.org/papers/v22/18-863.html (full text, first 100k characters)
- Sachdeva, Su, Joachims. 2020. "Off-policy Bandits with Deficient Support". KDD 2020. https://arxiv.org/abs/2006.09438 (abstract)
- Karampatziakis, Kochman, Huang, Mineiro, Osborne, Chen. 2019. "Lessons from Contextual Bandit Learning in a Customer Support Bot". arXiv preprint. https://arxiv.org/abs/1905.02219 (full text)
- Vowpal Wabbit wiki, "Contextual Bandit algorithms" (last edited 1 Feb 2026). https://github.com/VowpalWabbit/vowpal_wabbit/wiki/Contextual-Bandit-algorithms
- Vowpal Wabbit 9.6.0 documentation, "Command line options". https://vowpalwabbit.org/docs/vowpal_wabbit/python/9.6.0/command_line_args.html
- Vowpal Wabbit wiki, "Explore Eval" (last edited 10 Jul 2023). https://github.com/VowpalWabbit/vowpal_wabbit/wiki/Explore-Eval
- Microsoft, Azure AI Personalizer documentation (archived), "Exploration". https://learn.microsoft.com/en-us/previous-versions/azure/ai-services/personalizer/concepts-exploration
- Lattimore, Szepesvari. "Bandit Algorithms". Cambridge University Press (free online edition; print year 2020 [unverified on the opened file]). https://tor-lattimore.com/downloads/book/book.pdf (full text searched)
- Cesa-Bianchi, Gentile, Lugosi, Neu. 2017. "Boltzmann Exploration Done Right". arXiv [venue unverified: NeurIPS 2017]. https://arxiv.org/abs/1705.10257
- Agrawal, Goyal. 2012. "Thompson Sampling for Contextual Bandits with Linear Payoffs". arXiv [venue unverified: ICML 2013]. https://arxiv.org/abs/1209.3352
- Chapelle, Li. 2011. "An Empirical Evaluation of Thompson Sampling". NIPS 24. https://papers.nips.cc/paper/2011/hash/e53a0a2978c28872a4505bdb51db06dc-Abstract.html
- Saito, Aihara, Matsutani, Narita. 2020. "Open Bandit Dataset and Pipeline: Towards Realistic and Reproducible Off-Policy Evaluation". arXiv [venue unverified: NeurIPS 2021 Datasets and Benchmarks]. https://arxiv.org/abs/2008.07146
- Dimakopoulou, Zhou, Athey, Imbens. 2018. "Balanced Linear Contextual Bandits". arXiv [venue unverified: AAAI 2019]. https://arxiv.org/abs/1812.06227
- Liao, Greenewald, Klasnja, Murphy. 2019. "Personalized HeartSteps: A Reinforcement Learning Algorithm for Optimizing Physical Activity". arXiv [venue unverified: IMWUT 2020]. https://arxiv.org/abs/1909.03539
- Trella, Zhang, Nahum-Shani, Shetty, Doshi-Velez, Murphy. 2022. "Designing Reinforcement Learning Algorithms for Digital Interventions: Pre-implementation Guidelines". Algorithms 15(8):255 (DOI 10.3390/a15080255). https://arxiv.org/abs/2206.03944
- Hadad, Hirshberg, Zhan, Wager, Athey. 2019. "Confidence Intervals for Policy Evaluation in Adaptive Experiments". arXiv [venue unverified: PNAS 2021]. https://arxiv.org/abs/1911.02768
- Zhan, Hadad, Hirshberg, Athey. 2021. "Off-Policy Evaluation via Adaptive Weighting with Data from Contextual Bandits". arXiv [venue unverified: KDD 2021]. https://arxiv.org/abs/2106.02029
- Nie, Tian, Taylor, Zou. 2018. "Why Adaptively Collected Data Have Negative Bias and How to Correct for It". AISTATS 2018. https://arxiv.org/abs/1708.01977
- Agarwal, Hsu, Kale, Langford, Li, Schapire. 2014. "Taming the Monster: A Fast and Simple Algorithm for Contextual Bandits". arXiv [venue unverified: ICML 2014]. https://arxiv.org/abs/1402.0555
- Foster, Agarwal, Dudik, Luo, Schapire. 2018. "Practical Contextual Bandits with Regression Oracles". arXiv [venue unverified: ICML 2018]. https://arxiv.org/abs/1803.01088
- Foster, Rakhlin. 2020. "Beyond UCB: Optimal and Efficient Contextual Bandits with Regression Oracles". ICML 2020. https://arxiv.org/abs/2002.04926
- Simchi-Levi, Xu. 2020. "Bypassing the Monster: A Faster and Simpler Optimal Algorithm for Contextual Bandits under Realizability". Mathematics of Operations Research (listed as forthcoming). https://arxiv.org/abs/2003.12699
- Li, Chu, Langford, Schapire. 2010. "A Contextual-Bandit Approach to Personalized News Article Recommendation". WWW 2010. https://arxiv.org/abs/1003.0146
- Li, Chu, Langford, Wang. 2011. "Unbiased Offline Evaluation of Contextual-bandit-based News Article Recommendation Algorithms". WSDM 2011. https://arxiv.org/abs/1003.5956
- Strehl, Langford, Kakade, Li. 2010. "Learning from Logged Implicit Exploration Data". arXiv [venue unverified: NIPS 2010]. https://arxiv.org/abs/1003.0120
- Wang, Agarwal, Dudik. 2017. "Optimal and Adaptive Off-policy Evaluation in Contextual Bandits". ICML 2017. https://arxiv.org/abs/1612.01205
- Li, Munos, Szepesvari. 2015. "Toward Minimax Off-policy Value Estimation". AISTATS 2015, PMLR 38:608-616. https://proceedings.mlr.press/v38/li15b.html
- Dudik, Erhan, Langford, Li. 2014. "Doubly Robust Policy Evaluation and Optimization". Statistical Science 29(4):485-511. https://arxiv.org/abs/1503.02834
- Dudik, Langford, Li. 2011. "Doubly Robust Policy Evaluation and Learning". ICML 2011. https://arxiv.org/abs/1103.4601
- Su, Dimakopoulou, Krishnamurthy, Dudik. 2020. "Doubly robust off-policy evaluation with shrinkage". ICML 2020. https://arxiv.org/abs/1907.09623
- Swaminathan, Joachims. 2015b. "The Self-Normalized Estimator for Counterfactual Learning". NIPS 28. https://papers.nips.cc/paper/2015/hash/39027dfad5138c9ca0c474d71db915c3-Abstract.html

---

## 2. Designing the logging policy for evaluation rather than regret

### Takeaway
The variance-optimal logging distribution for evaluating a known target puts mass in proportion to the target's action probability times the root second moment of reward, and when nothing is known about targets or rewards it reduces to uniform; data should be pooled across logging policies with a balanced (mixture-denominator) estimator. Safety relative to a baseline can be added either by spending a conservative budget (conservative bandits), by constrained optimal design, or offline by deviating from the baseline only where data is sufficient (SPIBB, high-confidence improvement), and any action masked to zero probability becomes unevaluable by IPS in that context.

### Cited Findings

**Optimal logging for known targets**
- For a single target policy and IPS, the variance-optimal logging policy is proportional to target probability times the square root of the expected squared reward of the action, normalised per context. With no existing logs, an unrestricted policy class and constant reward second moments, the optimum is uniform over actions. For a set of targets or a policy class, the same structure holds with the pointwise maximum target probability across the class. — [Tucker and Joachims 2022](https://arxiv.org/abs/2202.01721) (full text)
- When adding data to existing logs ("augmentation logging"), the IPS-optimal augmentation ignores what is already logged, so the paper uses the balanced estimator whose denominator is the mixture (1 - alpha) * pi_log + alpha * pi_aug; this is unbiased whenever each target action is covered by either source. The method needs the reward second moment, which can be bounded or regressed; unbiasedness holds even if that estimate is wrong. On the Yahoo front-page data the method beat both uniform augmentation and logging from the target policy itself. — [Tucker and Joachims 2022](https://arxiv.org/abs/2202.01721) (full text)
- Running the target policy itself is not the minimum-MSE way to evaluate it: an analytically optimal behaviour policy exists, and searching for a better behaviour policy lowered MSE empirically (MDP setting). — [Hanna et al. 2017](https://arxiv.org/abs/1706.03469) (abstract)
- A 2026 preprint frames logging design as a reward-coverage trade-off (mass on high-reward actions lowers variance but risks missing actions the target may take) and derives optimal logging policies when the target and reward distribution are known, unknown, or partly known through noisy estimates. — [Douglas, Persson, Provost 2026](https://arxiv.org/abs/2605.15108) (abstract; not peer reviewed as of this date)
- Second-hand (search-result summary of the same preprint, not confirmed in the abstract I opened): uniform randomisation is minimax optimal when neither target nor rewards are known, and feeding noisy reward predictions into logging design tends to inflate downstream IPW variance. — [Douglas, Persson, Provost 2026](https://arxiv.org/abs/2605.15108)
- The Decision Service authors state that randomisation need not be uniform and for best performance should not be. — [Agarwal et al. 2016](https://arxiv.org/abs/1606.03966)

**Combining data from several logging policies (stratified collection)**
- Naively pooling IPS over multiple loggers can be highly suboptimal, to the point that dropping data can lower variance; two alternative estimators are proposed and give substantially better accuracy. — [Agarwal, Basu, Schnabel, Joachims 2017](https://arxiv.org/abs/1703.06180) (abstract)
- Treating multiple loggers with fixed sample sizes as stratified sampling, an efficient (lowest-variance) estimator exists and is attained given consistent q-function estimates; a control variate can be selected to minimise variance under misspecification. — [Kallus, Saito, Uehara 2020](https://arxiv.org/abs/2010.11002) (abstract)
- Deployed examples of a stratified design: a random fraction of visits served uniformly at random alongside the production policy (Yahoo news), and each impression randomly assigned to either a uniform-random or a Bernoulli-TS policy (Open Bandit Dataset). — [Chapelle and Li 2011](https://papers.nips.cc/paper/2011/hash/e53a0a2978c28872a4505bdb51db06dc-Abstract.html); [Saito et al. 2020](https://arxiv.org/abs/2008.07146)

**Safe or conservative exploration against a baseline**
- Conservative bandits: explore while keeping cumulative reward above a fixed baseline uniformly over time (not just at the end); the stochastic-setting algorithm is near-optimal by a lower bound, and the price of the constraint appears higher in the adversarial setting. — [Wu et al. 2016](https://arxiv.org/abs/1602.04282) (abstract)
- Conservative linear UCB: performance at least a fixed fraction of the baseline's at all times; regret splits into the usual linear-UCB term plus a constant term that does not grow with the horizon. — [Kazerouni et al. 2016](https://arxiv.org/abs/1611.06426) (abstract)
- Mixing the production policy with uniform exploration is safe but suboptimal for information gain; a "safe optimal" logging policy can be computed by a water-filling technique, with extensions to side information and linear contextual models, and a safe phased-elimination algorithm achieves optimal regret with logarithmically many policy updates. — [Zhu and Kveton 2021](https://arxiv.org/abs/2111.04835) (abstract)
- Safe data collection specifically for bandit policy evaluation and comparison has been formulated, with exploration policies derived for several variants. — [Wan, Kveton, Song 2022](https://arxiv.org/abs/2202.13234) (abstract only; constraint and objective not stated there)
- Offline analogue, SPIBB: copy the baseline's action probabilities on state-action pairs seen fewer than a threshold number of times and optimise elsewhere; needs the baseline policy's probabilities and counts. In a 5x5 gridworld with 10 to 10,000 trajectories SPIBB stayed safe across sizes while plain model-based RL had poor 1%-CVaR performance even on large datasets, a reward-adjusted variant had catastrophic runs on small datasets, and a high-confidence method was safe but far from optimal. With uniform-random data it was not completely safe at very small thresholds and 20 or fewer trajectories. — [Laroche, Trichelair, Tachet des Combes](https://arxiv.org/abs/1712.06924) (full text)
- Soft-SPIBB replaces the binary threshold with a constraint proportional to local model uncertainty and is less conservative. — [Nadjahi, Laroche, Tachet des Combes 2019](https://arxiv.org/abs/1907.05079) (abstract)
- High-confidence policy improvement returns a new policy only with a user-chosen probabilistic guarantee against falling below a user-chosen performance bound; tested on gridworld, mountain car and a digital-marketing dataset. — [Thomas, Theocharous, Ghavamzadeh 2015](http://proceedings.mlr.press/v37/thomas15.html) (abstract)
- Practice: regularising the learned policy toward the logging policy raised effective sample size about fivefold with little loss of mean reward; a first learned model should imitate high-reward production decisions. — [Karampatziakis et al. 2019](https://arxiv.org/abs/1905.02219)

**Action elimination and masking**
- Business rules should sit outside the policy: the agent may explore on every request but may never take an action that breaks a rule; log the legal action set and a superset of candidates so rule changes can be evaluated offline; cap the probability of newly legalised actions; avoid downstream overrides because they corrupt the logs. — [Karampatziakis et al. 2019](https://arxiv.org/abs/1905.02219)
- Confidence-interval-based elimination of likely-suboptimal actions finds an eps-optimal arm in about (n/eps^2) log(1/delta) pulls and speeds up RL relative to epsilon-greedy Q-learning. — [Even-Dar, Mannor, Mansour 2006](https://jmlr.org/papers/v7/evendar06a.html) (abstract)
- Masking invalid actions before sampling is theoretically justified for policy-gradient methods and matters more as the invalid set grows. — [Huang and Ontanon 2022](https://arxiv.org/abs/2006.14171) (abstract)
- Exploration-time elimination is built into RegCB-elimination and SquareCB --elim. — [VW 9.6.0 command-line docs](https://vowpalwabbit.org/docs/vowpal_wabbit/python/9.6.0/command_line_args.html)
- Zero-probability actions break IPS for any target that would take them (see Sachdeva et al. in section 1). — [Sachdeva, Su, Joachims 2020](https://arxiv.org/abs/2006.09438)
- Clinical-trial-style bandits fix hard probability bounds in advance ([0.1, 0.8]; [0.35, 0.75]) chosen with domain experts. — [Liao et al. 2019](https://arxiv.org/abs/1909.03539); [Trella et al. 2022](https://arxiv.org/abs/2206.03944)

### Inferences
- For a known finite set of deterministic candidate policies, the Tucker-Joachims pointwise-max result implies logging uniformly over the set of actions that at least one candidate would take in the current context (weighted by root second moment of reward if known), and giving no more than a small floor to actions no candidate proposes. With 5 to 8 actions and a handful of candidates this is cheap to compute at decision time.
- If candidate policies are not known in advance, the sources agree that uniform (or a high uniform floor) is the safe default for evaluation; epsilon-greedy around the rule is efficient only for targets close to the rule (section 1 arithmetic).
- For session-ending or session-damaging actions there are three distinct designs, each with a different evaluation consequence: (a) mask them where a rule forbids them and log the eligible set, accepting that policies using them there cannot be evaluated by IPS; (b) give them a small known floor only in contexts where they are plausible (stratified, context-dependent exploration) and rely on DR or a reward model to control the resulting large weights; (c) spend a conservative-bandit style budget so that costly exploration happens only when accumulated reward relative to the baseline rule allows. Option (b) with a logged per-context floor keeps propensities exact.
- A dedicated uniformly random stratum (a fixed share of sessions or steps) alongside a production stratum, combined with a balanced estimator, gives both an unbiased replay set and efficient use of the remaining data.
- The offline counterpart of "explore safely" is "improve safely": SPIBB-style bootstrapping to the hand-written rule in rarely observed contexts needs exactly the quantities already being logged (baseline probabilities and counts).

### Gaps
- Formal constraints and objectives of Zhu and Kveton and of Wan, Kveton and Song were not verified beyond their abstracts.
- Tucker and Joachims leave the doubly robust extension unworked; experiments use one dataset. Venue is WSDM 2023 according to a search listing, not confirmed on the page I opened.
- The Douglas et al. preprint is six months old and unreviewed; treat as provisional.
- The arXiv comment for Agarwal, Basu, Schnabel, Joachims was relayed to me as "KDD 2018"; I recall KDD 2017. Check before citing the venue.
- I found no source that quantifies how to price a terminating action's exploration cost against its information value in a contextual setting.
- Not opened: Thomas, Theocharous, Ghavamzadeh 2015 "High Confidence Off-Policy Evaluation" (AAAI).

### Sources first cited in this section
- Tucker, Joachims. 2022. "Variance-Optimal Augmentation Logging for Counterfactual Evaluation in Contextual Bandits". arXiv [WSDM 2023 per search listing]. https://arxiv.org/abs/2202.01721
- Hanna, Thomas, Stone, Niekum. 2017. "Data-Efficient Policy Evaluation Through Behavior Policy Search". ICML 2017. https://arxiv.org/abs/1706.03469
- Douglas, Persson, Provost. 2026. "Logging Policy Design for Off-Policy Evaluation". arXiv preprint (14 May 2026). https://arxiv.org/abs/2605.15108
- Agarwal, Basu, Schnabel, Joachims. 2017. "Effective Evaluation using Logged Bandit Feedback from Multiple Loggers". KDD (year to be checked). https://arxiv.org/abs/1703.06180
- Kallus, Saito, Uehara. 2020. "Optimal Off-Policy Evaluation from Multiple Logging Policies". arXiv [venue unverified: ICML 2021]. https://arxiv.org/abs/2010.11002
- Wu, Shariff, Lattimore, Szepesvari. 2016. "Conservative Bandits". arXiv (page says submitted to ICML 2016). https://arxiv.org/abs/1602.04282
- Kazerouni, Ghavamzadeh, Abbasi-Yadkori, Van Roy. 2016. "Conservative Contextual Linear Bandits". arXiv [venue unverified: NIPS 2017]. https://arxiv.org/abs/1611.06426
- Zhu, Kveton. 2021 (revised 2022). "Safe Data Collection for Offline and Online Policy Learning". arXiv preprint. https://arxiv.org/abs/2111.04835
- Wan, Kveton, Song. 2022. "Safe Exploration for Efficient Policy Evaluation and Comparison". arXiv [venue unverified: ICML 2022]. https://arxiv.org/abs/2202.13234
- Laroche, Trichelair, Tachet des Combes. 2017 preprint. "Safe Policy Improvement with Baseline Bootstrapping". arXiv [venue unverified: ICML 2019]. https://arxiv.org/abs/1712.06924
- Nadjahi, Laroche, Tachet des Combes. 2019. "Safe Policy Improvement with Soft Baseline Bootstrapping". ECML-PKDD 2019. https://arxiv.org/abs/1907.05079
- Thomas, Theocharous, Ghavamzadeh. 2015. "High Confidence Policy Improvement". ICML 2015, PMLR 37:2380-2388. http://proceedings.mlr.press/v37/thomas15.html
- Even-Dar, Mannor, Mansour. 2006. "Action Elimination and Stopping Conditions for the Multi-Armed Bandit and Reinforcement Learning Problems". JMLR 7:1079-1105. https://jmlr.org/papers/v7/evendar06a.html
- Huang, Ontanon. 2022. "A Closer Look at Invalid Action Masking in Policy Gradient Algorithms". FLAIRS 35. https://arxiv.org/abs/2006.14171

---

## 3. Delayed and aggregated reward within a session; bias from ignoring sequential dependence

### Takeaway
Delay by itself is cheap in stochastic settings (an additive regret term) provided rewards are joined with a uniform waiting window and censoring is handled; the harder issue is that a per-step bandit with session reward-to-go estimates the value of deviating once and then following the logging policy, not the value of the new policy applied at every step. The literature treats the discount factor or horizon as a regulariser: with little data a short horizon (bandit or one-step improvement, possibly with a hand-built proxy for delayed effects) can beat a full sequential model, at the cost of a bias that grows with how far the new policy departs from the logged one.

### Cited Findings

**Delayed feedback in bandits**
- Delay multiplies regret in adversarial problems but only adds to it in stochastic problems; black-box wrappers convert non-delayed algorithms to delayed ones. — [Joulani, Gyorgy, Szepesvari 2013](https://arxiv.org/abs/1306.0686) (abstract)
- Delayed-conversion bandits: each action may trigger a reward after a random delay; the model assumes the delay distribution is known and distinguishes uncensored from censored feedback (late conversions never observed). — [Vernade, Cappe, Perchet 2017](https://arxiv.org/abs/1706.09186) (abstract)
- Delayed, aggregated, anonymous feedback: only the sum of rewards arriving in a round is seen, without knowing which action produced which; the additive (expected-delay) regret cost can still be achieved if the expected delay or a bound on it is known. — [Pike-Burke et al. 2018](https://arxiv.org/abs/1709.06853) (abstract)
- Randomised algorithms degrade less under delay than deterministic ones (numbers in section 1). — [Chapelle and Li 2011](https://papers.nips.cc/paper/2011/hash/e53a0a2978c28872a4505bdb51db06dc-Abstract.html)
- Engineering practice: fix an "experimental unit" (how long to wait for reward; 10 minutes at MSN), assign a default reward if nothing arrives, and enforce the same delay for all events before releasing them to the learner, because rewards that arrive faster for some actions otherwise bias learning (1.3x discrepancy in their simulation). — [Agarwal et al. 2016](https://arxiv.org/abs/1606.03966)

**Attribution and proxies**
- A support-bot team attributed the eventual "solved?" outcome to the earlier disambiguation action as an accepted simplification, imputed missing rewards with a model fit on held-out responses (avoiding features caused by poor experience), and logged several reward signals so definitions could be changed offline. — [Karampatziakis et al. 2019](https://arxiv.org/abs/1905.02219)
- Intermediate proxy signals can reduce regret under long delays; a residual architecture stays robust when the proxy is uninformative. — [Mann et al. 2018](https://arxiv.org/abs/1807.09387) (abstract)
- A Bayesian filter that fuses partial short- and medium-term outcomes into a belief about the eventual long-term reward outperformed both optimising short-term proxies and waiting for the full outcome (podcast recommendation, two-month horizon). — [McDonald et al. 2023](https://arxiv.org/abs/2307.09943) (abstract)
- Long-term OPE from short-term data usually rests on a restrictive surrogacy assumption; a reward-decomposition estimator needs a weaker assumption and uses short-term rewards to cut variance. — [Saito et al. 2024](https://arxiv.org/abs/2404.15691) (abstract)
- When only the total reward of a trajectory is observed, per-step rewards can be recovered by least-squares regression of trajectory totals on visited state-actions. — [Efroni, Merlis, Mannor 2021](https://arxiv.org/abs/2008.06036) (abstract)

**What goes wrong when sequential dependence is ignored**
- Counterfactual estimators that assume rewards are independent across positions are a poor fit when engagement is sequential; an estimator that models the reward interactions had lower bias and better data efficiency in simulation and on a live system. — [McInerney et al. 2020](https://arxiv.org/abs/2007.12986) (abstract)
- Most practical recommenders optimise immediate engagement and ignore effects on long-term behaviour; long-term value can be layered on top of an existing myopic system. — [Ie et al. 2019 (SlateQ)](https://arxiv.org/abs/1905.12767) (abstract)
- Importance-sampling OPE has excessively high variance in long-horizon problems, potentially unbounded in the infinite-horizon case; DR extends from bandits to sequential problems with lower variance than importance sampling. — [Liu et al. 2018](https://arxiv.org/abs/1810.12429); [Jiang and Li 2016](https://arxiv.org/abs/1511.03722) (abstracts)
- Planning horizon as complexity control: with a model estimated from limited data, a shorter planning horizon than the true one can give a better policy; the discount factor monotonically controls the number of policies that can be optimal (one policy at gamma = 0), and the planning-loss bound has one term favouring long horizons and one favouring short. — [Jiang, Kulesza, Singh, Lewis 2015](https://www.ifaamas.org/Proceedings/aamas2015/aamas/p1181.pdf) (full text, pages 1-2)
- Applied confirmation: with 140 decision times per user and noisy rewards, the Oralytics designers chose a contextual bandit over an MDP, describing a bandit as the extreme of discount regularisation (gamma = 0) and noting a full MDP might learn very little in the study. — [Trella et al. 2022](https://arxiv.org/abs/2206.03944) (full text)
- Middle path: HeartSteps V2 keeps a Thompson-sampling bandit for the immediate effect but subtracts a delayed-effect term computed from a low-dimensional proxy MDP over a "dosage" variable (decay 0.95); setting that term to zero recovers the plain bandit. In simulation from 37 participants' prior data it beat the plain TS bandit for 29 of 37; in the 8-person pilot the authors noted, for one participant examined, that the proxy responded too slowly and needs improvement. — [Liao et al. 2019](https://arxiv.org/abs/1909.03539) (full text)
- One-step improvement: a single step of constrained policy improvement on an on-policy Q estimate of the behaviour policy beat iterative offline RL on a large part of D4RL; the authors attribute iterative methods' weakness to high-variance off-policy evaluation compounded over iterations. — [Brandfonbrener et al. 2021](https://arxiv.org/abs/2106.08909) (abstract)
- Similar idea with pilot data: approximate one step of policy iteration, which reduces to a prediction task on the historical dataset; with a randomised pilot policy there is an approximation guarantee. — [Baek et al. 2023](https://arxiv.org/abs/2303.12206) (abstract). Second-hand (search snippet of the full text, not in the abstract): the paper calls the contextual bandit myopic by design and says full RL would substantially raise data requirements.
- Dialogue precedent for delayed reward handled as an MDP on tiny data: reward was a single binary task-completion value at the end of the dialogue (+1/-1), and the authors argue RL is more data-efficient than comparing whole policies because it evaluates actions as a function of state. — [Singh, Litman, Kearns, Walker 2002](https://arxiv.org/abs/1106.0676) (full text)

### Inferences
- Using session reward-to-go as the bandit reward for step t is a Monte Carlo estimate of Q under the logging policy. A policy that is greedy with respect to it is exactly one step of policy improvement over the logging policy (the Brandfonbrener / Baek construction). It is unbiased for "act differently at this step, then follow the logged policy" and biased for "act differently at every step"; the bias is small when the new policy stays close to the logging policy and grows with the number of steps at which it differs.
- Step-wise IPS with reward-to-go therefore evaluates the wrong counterfactual for a policy that changes several steps in a session. The unbiased alternative multiplies the per-step ratios; with a 0.06 floor the worst-case weight is 16.7 per disagreeing step, about 4,600 after three such steps, which is unusable at a few thousand transitions. This is the practical form of the "curse of horizon".
- Reward-to-go does capture the main sequential effect of a terminating action (no further reward), which an immediate-reward bandit would miss entirely. What it misses is how a non-terminal action changes the value of later non-logged choices.
- Open sessions at training cut-off are a censoring problem: dropping them, or scoring them with partial reward, biases against actions that prolong sessions. A fixed attribution window per decision (the experimental-unit idea) or training only on closed sessions avoids this.
- A cheap diagnostic for whether the bandit formulation is adequate: regress reward-to-go on (state, action) and on (state, action, previous action / step index / cumulative-exposure features). If history features add predictive power, add them to the context (HeartSteps-style proxy) before moving to a full MDP.

### Gaps
- I found no paper that quantifies, for a fixed small dataset, the bias of reward-to-go bandit learning against a fitted sequential model as a function of horizon; the horizon-as-regulariser results (Jiang et al.) are for tabular certainty-equivalence planning.
- Not opened: Chapelle 2014 "Modeling delayed feedback in display advertising" (KDD); Precup, Sutton, Singh 2000 (per-decision importance sampling). The Lattimore-Szepesvari book contains no treatment of delayed feedback beyond bibliography entries (text search).
- Jiang and Li's horizon-dependence analysis is in the full paper, which I did not read; only the abstract is cited.
- SlateQ's abstract gives no size for the gain of non-myopic over myopic policies.

### Sources first cited in this section
- Joulani, Gyorgy, Szepesvari. 2013. "Online Learning under Delayed Feedback". ICML 2013 (extended version). https://arxiv.org/abs/1306.0686
- Vernade, Cappe, Perchet. 2017. "Stochastic Bandit Models for Delayed Conversions". UAI 2017. https://arxiv.org/abs/1706.09186
- Pike-Burke, Agrawal, Szepesvari, Grunewalder. 2018. "Bandits with Delayed, Aggregated Anonymous Feedback". ICML 2018. https://arxiv.org/abs/1709.06853
- Mann, Gowal, Gyorgy, Jiang, Hu, Lakshminarayanan, Srinivasan. 2018. "Learning from Delayed Outcomes via Proxies with Applications to Recommender Systems". arXiv [venue unverified: ICML 2019]. https://arxiv.org/abs/1807.09387
- McDonald, Maystre, Lalmas, Russo, Ciosek. 2023. "Impatient Bandits: Optimizing Recommendations for the Long-Term Without Delay". KDD 2023. https://arxiv.org/abs/2307.09943
- Saito, Abdollahpouri, Anderton, Carterette, Lalmas. 2024. "Long-term Off-Policy Evaluation and Learning". The Web Conference 2024. https://arxiv.org/abs/2404.15691
- Efroni, Merlis, Mannor. 2021. "Reinforcement Learning with Trajectory Feedback". AAAI 2021. https://arxiv.org/abs/2008.06036
- McInerney, Brost, Chandar, Mehrotra, Carterette. 2020. "Counterfactual Evaluation of Slate Recommendations with Sequential Reward Interactions". arXiv (DOI 10.1145/3394486.3403229) [venue unverified: KDD 2020]. https://arxiv.org/abs/2007.12986
- Ie, Jain, Wang, Narvekar, Agarwal, Wu, Cheng, Lustman, Gatto, Covington, McFadden, Chandra, Boutilier. 2019. "Reinforcement Learning for Slate-based Recommender Systems: A Tractable Decomposition and Practical Methodology" (SlateQ). arXiv; short version IJCAI 2019. https://arxiv.org/abs/1905.12767
- Liu, Li, Tang, Zhou. 2018. "Breaking the Curse of Horizon: Infinite-Horizon Off-Policy Estimation". NeurIPS 2018 (spotlight). https://arxiv.org/abs/1810.12429
- Jiang, Li. 2016. "Doubly Robust Off-policy Value Evaluation for Reinforcement Learning". ICML 2016. https://arxiv.org/abs/1511.03722
- Jiang, Kulesza, Singh, Lewis. 2015. "The Dependence of Effective Planning Horizon on Model Accuracy". AAMAS 2015, pp. 1181 ff. https://www.ifaamas.org/Proceedings/aamas2015/aamas/p1181.pdf
- Brandfonbrener, Whitney, Ranganath, Bruna. 2021. "Offline RL Without Off-Policy Evaluation". NeurIPS 2021. https://arxiv.org/abs/2106.08909
- Baek, Boutilier, Farias, Jonasson, Yoeli. 2023 (revised 2024). "Policy Optimization for Personalized Interventions in Behavioral Health". arXiv preprint. https://arxiv.org/abs/2303.12206
- Singh, Litman, Kearns, Walker. 2002. "Optimizing Dialogue Management with Reinforcement Learning: Experiments with the NJFun System". JAIR 16:105-133 (DOI 10.1613/jair.859). https://arxiv.org/abs/1106.0676

---

## 4. Sequential formulations for short sessions with few actions, at small data scale

### Takeaway
Sequential learning from hundreds to thousands of logged episodes has worked when the state space is deliberately tiny, exploration is randomised only among pre-approved actions, and the learner is tabular or shallow and anchored to the baseline (NJFun, SPIBB, hybrid supervised/RL dialogue policies); modern deep offline RL is benchmarked at about a million transitions and is reported to overfit on small datasets. Simulators built from prior logs are used mainly to choose among candidate algorithms and hyperparameters, not as ground truth.

### Cited Findings

**Formulations**
- Contextual MDP: transition and reward functions depend on a static, hidden per-episode context (for example user characteristics); the paper treats the finite-horizon case with a small known number of contexts and learns the latent contexts and their models. — [Hallak, Di Castro, Mannor 2015](https://arxiv.org/abs/1502.02259) (abstract)
- Session-level RL in recommenders at industrial scale: off-policy-corrected REINFORCE with an action space in the millions and data from multiple behaviour policies; long-term-value Q-learning decomposed over slates. — [Chen et al. 2018](https://arxiv.org/abs/1812.02353); [Ie et al. 2019](https://arxiv.org/abs/1905.12767) (abstracts)

**Small-data precedents (dialogue)**
- NJFun: an MDP with 42 choice-states of 2 allowed actions each (2^42 policies); training data came from 311 dialogues in which the system chose uniformly at random between the two hand-vetted actions at each choice-state; transition probabilities were estimated by counting and the MDP solved for the optimal policy; binary task completion rose from 52% in training to 64% over 124 test dialogues. The authors stress that the state space must be kept small because the learned policy is unreliable at rarely visited states, and that every exploratory choice must be sensible to the user. — [Singh, Litman, Kearns, Walker 2002](https://arxiv.org/abs/1106.0676) (full text)
- Hybrid RL/supervised learning from a fixed corpus: because a fixed dataset covers only a small part of a large state and policy space, supervised learning restricts the learned policy to the region the data supports while RL optimises reward within it, with linear function approximation; on the COMMUNICATOR corpus the hybrid beat pure supervised and pure RL policies and improved on the average hand-built system by 10% (evaluated with a user simulator trained on a different part of the data). — [Henderson, Lemon, Georgila 2008](https://aclanthology.org/J08-4002/) (abstract from the PDF)
- Batch RL for open-domain dialogue used a KL penalty toward a prior model fit on the data, plus dropout-based lower bounds on target Q-values. — [Jaques et al. 2019](https://arxiv.org/abs/1907.00456) (abstract)
- End-to-end neural dialogue control needs thousands of dialogues for simple behaviours; encoding domain knowledge as software and action templates greatly reduces the data needed, with supervised and/or reinforcement training. — [Williams, Asadi, Zweig 2017](https://arxiv.org/abs/1702.03274) (abstract)

**Offline RL: what the surveys and benchmarks say about scale**
- Surveys: offline RL learns from fixed data without further collection and current algorithms have limitations that make this hard; a taxonomy and a summary of which method class suits which dataset properties are given. — [Levine et al. 2020](https://arxiv.org/abs/2005.01643); [Prudencio, Maximo, Colombini 2023](https://arxiv.org/abs/2203.01387) (abstracts)
- Standard off-policy methods fail offline because of value overestimation under distribution shift; conservative Q-learning learns a lower bound. — [Kumar et al. 2020 (CQL)](https://arxiv.org/abs/2006.04779) (abstract)
- With data from a single partially trained behaviour policy, many batch deep RL algorithms underperformed both online DQN and the behaviour policy itself; a discrete-action BCQ variant did best. — [Fujimoto et al. 2019](https://arxiv.org/abs/1910.01708) (abstract)
- Positive results for offline deep RL were attributed to dataset size and diversity as well as algorithm choice. — [Agarwal, Schuurmans, Norouzi 2020](https://arxiv.org/abs/1907.04543) (abstract)
- Offline RL can beat behavioural cloning under sparse rewards or noisy data sources, especially on long horizons. — [Kumar et al. 2022](https://arxiv.org/abs/2204.05618) (abstract)
- Common benchmarks use over a million data points whereas many applications have far less; offline RL algorithms overfit on small datasets; sparsity regularisation helps (continuous control). — [Arnob, Fujimoto, Precup 2025](https://arxiv.org/abs/2506.17155) (abstract)
- With limited data, algorithm and hyperparameter selection should use repeated train/validation splits; this matters substantially at small n (healthcare, education, robotics simulations). — [Nie et al. 2022](https://arxiv.org/abs/2210.08642) (abstract)
- For ranking candidate policies offline, fitted Q evaluation gave the most reliable ranking but at high computational cost; a two-stage selection is proposed. — [Tang and Wiens 2021](https://arxiv.org/abs/2107.11003) (abstract)
- Pitfalls in observational evaluation: state representation choices, estimator variance and confounded ad hoc measures can make policy-quality estimates misleading. — [Gottesman et al. 2018](https://arxiv.org/abs/1805.12298) (abstract)
- Classical batch RL: fitted Q iteration with tree ensembles learns from a set of (state, action, reward, next state) tuples; extremely randomised trees gave the best accuracy. — [Ernst, Geurts, Wehenkel 2005](https://jmlr.org/papers/v6/ernst05a.html) (abstract)
- Small-data safe improvement (SPIBB, Soft-SPIBB, high-confidence improvement) is covered in section 2; SPIBB experiments run from 10 to 10,000 trajectories and, in a deep variant, 10k to 30k transitions, where plain DQN made the baseline worse. — [Laroche et al.](https://arxiv.org/abs/1712.06924)

**Model-based approaches and simulators built from logs**
- Pessimistic model-based offline RL: learn a model from the dataset and either plan in a pessimistic MDP whose value approximately lower-bounds true performance, or penalise rewards by model uncertainty. — [Kidambi et al. 2020 (MOReL)](https://arxiv.org/abs/2005.05951); [Yu et al. 2020 (MOPO)](https://arxiv.org/abs/2005.13239) (abstracts)
- Simulators for choosing an algorithm before deployment: Oralytics built environment variants from a prior study of 32 users over 28 days (which contained no interventions, so treatment effects had to be imputed), then compared candidate algorithms over 100 Monte Carlo trials; the simplest model with full pooling won, and a richer reward model underperformed for lack of data. HeartSteps used 37 participants over 42 days to set priors and to tune by cross-validated simulation. — [Trella et al. 2022](https://arxiv.org/abs/2206.03944); [Liao et al. 2019](https://arxiv.org/abs/1909.03539) (full text)
- Configurable recommender simulators exist for studying sequential interaction at an abstract level. — [Ie et al. 2019 (RecSim)](https://arxiv.org/abs/1909.04847) (abstract)
- The earliest news-bandit work already warned that simulator-based evaluation is hard to build and introduces modelling bias, motivating replay on real random logs. — [Li et al. 2011](https://arxiv.org/abs/1003.5956) (abstract)

### Inferences
- At thousands of transitions and 5 to 8 actions, the evidence points to a ladder, in increasing data demand: (1) contextual bandit with immediate or reward-to-go reward (one-step improvement); (2) the same with hand-built history features or a low-dimensional delayed-effect proxy; (3) a small tabular or linear MDP over a deliberately coarse session state, solved by counting plus value iteration or fitted Q iteration with trees/linear models, with SPIBB-style fallback to the rule in rarely visited state-actions; (4) deep offline RL (CQL, BCQ and similar), which nothing I found supports at this scale.
- NJFun is the closest structural precedent: short episodes, two-to-few actions per decision, delayed terminal reward, random choice among pre-approved actions with known probability, a few hundred episodes. Its design choices (hand-restricted state, exploration only where every option is acceptable) are what made a sequential model learnable.
- A learned simulator from a few thousand logged transitions inherits the logging policy's coverage gaps; the sources use such simulators to rank candidate designs under several plausible environment variants, not to estimate the deployed value. For terminating actions rarely explored, the simulator would be extrapolating.
- The contextual-MDP framing (a static hidden per-session type that changes dynamics) suggests an intermediate design: infer a coarse session type from early steps and use it as context for a bandit, which captures some sequential structure without estimating transitions.
- Model selection is itself a small-data problem: use repeated splits by session, and OPE with confidence intervals and effective-sample-size reporting, before trusting any ranking between a bandit and a sequential candidate.

### Gaps
- No opened source benchmarks standard offline RL algorithms head-to-head at around 1,000 to 10,000 discrete-action transitions. A NeurIPS 2023 paper on small-sample offline RL (TSRL) appeared in search results but I did not open it (second-hand).
- Whether the top-K REINFORCE system estimates its behaviour-policy propensities (rather than logging them) is not stated in the abstract I opened.
- Not opened: Komorowski et al. 2018 (tabular RL for sepsis); Schatzmann et al. 2006 (survey of dialogue user simulation); Lagoudakis and Parr 2003 (LSPI).
- Offline RL surveys cited are from 2020 to 2023 and the field moves quickly; newer small-data methods may exist that my searches did not surface.

### Sources first cited in this section
- Hallak, Di Castro, Mannor. 2015. "Contextual Markov Decision Processes". arXiv preprint. https://arxiv.org/abs/1502.02259
- Chen, Beutel, Covington, Jain, Belletti, Chi. 2018. "Top-K Off-Policy Correction for a REINFORCE Recommender System". arXiv [venue unverified: WSDM 2019]. https://arxiv.org/abs/1812.02353
- Henderson, Lemon, Georgila. 2008. "Hybrid Reinforcement/Supervised Learning of Dialogue Policies from Fixed Data Sets". Computational Linguistics 34(4):487-511 (DOI 10.1162/coli.2008.07-028-R2-05-82). https://aclanthology.org/J08-4002/
- Jaques, Ghandeharioun, Shen, Ferguson, Lapedriza, Jones, Gu, Picard. 2019. "Way Off-Policy Batch Deep Reinforcement Learning of Implicit Human Preferences in Dialog". arXiv preprint. https://arxiv.org/abs/1907.00456
- Williams, Asadi, Zweig. 2017. "Hybrid Code Networks: practical and efficient end-to-end dialog control with supervised and reinforcement learning". ACL 2017. https://arxiv.org/abs/1702.03274
- Levine, Kumar, Tucker, Fu. 2020. "Offline Reinforcement Learning: Tutorial, Review, and Perspectives on Open Problems". arXiv preprint. https://arxiv.org/abs/2005.01643
- Prudencio, Maximo, Colombini. 2023. "A Survey on Offline Reinforcement Learning: Taxonomy, Review, and Open Problems". IEEE TNNLS (DOI 10.1109/TNNLS.2023.3250269). https://arxiv.org/abs/2203.01387
- Kumar, Zhou, Tucker, Levine. 2020. "Conservative Q-Learning for Offline Reinforcement Learning". arXiv [venue unverified: NeurIPS 2020]. https://arxiv.org/abs/2006.04779
- Fujimoto, Conti, Ghavamzadeh, Pineau. 2019. "Benchmarking Batch Deep Reinforcement Learning Algorithms". NeurIPS 2019 Deep RL Workshop. https://arxiv.org/abs/1910.01708
- Agarwal, Schuurmans, Norouzi. 2020. "An Optimistic Perspective on Offline Reinforcement Learning". ICML 2020, PMLR 119:104-114. https://arxiv.org/abs/1907.04543
- Kumar, Hong, Singh, Levine. 2022. "When Should We Prefer Offline Reinforcement Learning Over Behavioral Cloning?". ICLR 2022. https://arxiv.org/abs/2204.05618
- Arnob, Fujimoto, Precup. 2025. "Sparse-Reg: Improving Sample Complexity in Offline Reinforcement Learning using Sparsity". arXiv preprint. https://arxiv.org/abs/2506.17155
- Nie, Flet-Berliac, Jordan, Steenbergen, Brunskill. 2022. "Data-Efficient Pipeline for Offline Reinforcement Learning with Limited Data". NeurIPS 2022. https://arxiv.org/abs/2210.08642
- Tang, Wiens. 2021. "Model Selection for Offline Reinforcement Learning: Practical Considerations for Healthcare Settings". MLHC 2021. https://arxiv.org/abs/2107.11003
- Gottesman et al. (19 authors incl. Doshi-Velez). 2018. "Evaluating Reinforcement Learning Algorithms in Observational Health Settings". arXiv preprint. https://arxiv.org/abs/1805.12298
- Ernst, Geurts, Wehenkel. 2005. "Tree-Based Batch Mode Reinforcement Learning". JMLR 6:503-556. https://jmlr.org/papers/v6/ernst05a.html
- Kidambi, Rajeswaran, Netrapalli, Joachims. 2020. "MOReL: Model-Based Offline Reinforcement Learning". NeurIPS 2020. https://arxiv.org/abs/2005.05951
- Yu, Thomas, Yu, Ermon, Zou, Levine, Finn, Ma. 2020. "MOPO: Model-based Offline Policy Optimization". NeurIPS 2020. https://arxiv.org/abs/2005.13239
- Ie, Hsu, Mladenov, Jain, Narvekar, Wang, Wu, Boutilier. 2019. "RecSim: A Configurable Simulation Platform for Recommender Systems". arXiv preprint. https://arxiv.org/abs/1909.04847

---

## 5. Non-stationarity and adaptive users or adversaries

### Takeaway
Adversarial bandit algorithms (Exp3, Exp4) need no statistical assumptions and have explicit sampling distributions, but their guarantees are regret against a fixed comparator under an online update loop, are loose at a few thousand rounds, and are explicitly noted as not meaningful against an opponent who reacts to the learner's past actions. An opponent who adapts within a session is better modelled as state (a sequential formulation); drift across sessions is handled in practice by retraining, recency weighting and a permanent exploration floor.

### Cited Findings
- Exp3 family: with no assumptions on how payoffs are generated, per-round payoff approaches that of the best arm at rate T^{-1/2} (weak regret of order sqrt(K G_max ln K), with a matching sqrt(KT) lower bound); against the best of N strategies the rate is sqrt(log N) * T^{-1/2}; against sequences of arms with S switches, regret is of order S sqrt(K T ln(KT)). — [Auer, Cesa-Bianchi, Freund, Schapire 2002](https://cseweb.ucsd.edu/~yfreund/papers/bandits.pdf) (author-hosted manuscript dated Nov 2001, pages 1-3)
- Exp4 with M experts and k actions over n rounds: expected regret at most sqrt(2 n k log M) (Theorem 18.1). — [Lattimore and Szepesvari, ch. 18](https://tor-lattimore.com/downloads/book/book.pdf)
- Exp4.P gives the same order with high probability; a variant handles infinite policy classes of finite VC dimension. — [Beygelzimer et al. 2010](https://arxiv.org/abs/1002.4058) (abstract)
- Oblivious versus reactive adversaries: the Exp3 analysis extends to adversaries whose rewards depend on the learner's past actions, but the book questions whether the usual regret definition makes sense there and calls non-oblivious regret a strange measure because it does not capture the reactive nature of the environment; for policy regret, no algorithm can guarantee sublinear regret in general because an early action can fix all later rewards. — [Lattimore and Szepesvari, ch. 11 notes](https://tor-lattimore.com/downloads/book/book.pdf)
- Policy regret: standard regret is inadequate against adaptive adversaries; sublinear policy regret is impossible against unbounded-memory adversaries, but for bounded memory any bandit algorithm with sublinear regret can be converted into one with sublinear policy regret. — [Arora, Dekel, Tewari 2012](https://arxiv.org/abs/1206.6400) (abstract)
- Slowly or abruptly changing stochastic rewards: minimal achievable regret is tied directly to a budget of allowed reward variation; discounted UCB and sliding-window UCB match the lower bound for abrupt changes up to a log factor. — [Besbes, Gur, Zeevi 2014](https://arxiv.org/abs/1405.3316); [Garivier and Moulines 2008](https://arxiv.org/abs/0805.3415) (abstracts)
- Non-stationary contextual bandits: the Exp4-style baseline is computationally inefficient; oracle-based algorithms with change-detection tests reach about sqrt(S T) regret for S stationary periods, or Delta^{1/3} T^{2/3} for total variation Delta. — [Luo et al. 2017](https://arxiv.org/abs/1708.01799) (abstract)
- Exp3.S can be read as an efficient Exp4 over action sequences with a bounded number of switches. — [Lattimore and Szepesvari, ch. 31 notes](https://tor-lattimore.com/downloads/book/book.pdf)
- Delay interacts badly with adversarial settings (multiplicative regret cost). — [Joulani, Gyorgy, Szepesvari 2013](https://arxiv.org/abs/1306.0686)
- Offline-friendly approach to drift: fit a trend to counterfactual estimates of past policy performance and optimise the forecast of future performance, without modelling the non-stationarity explicitly. — [Chandak et al. 2020](https://arxiv.org/abs/2005.08158) (abstract)
- Deployed-system stance: non-stationarity is listed as a core failure mode and addressed by continuous retraining (new model every 5 minutes at MSN) and ongoing exploration; Personalizer's documentation says zero exploration leads to model stagnation and drift; a support-bot team versions business rules and stamps models with them. — [Agarwal et al. 2016](https://arxiv.org/abs/1606.03966); [Personalizer exploration docs](https://learn.microsoft.com/en-us/previous-versions/azure/ai-services/personalizer/concepts-exploration); [Karampatziakis et al. 2019](https://arxiv.org/abs/1905.02219)
- The Bake-off study covers stationary data only and lists non-stationarity and delayed/batched rewards as unaddressed. — [Bietti, Agarwal, Langford 2021](https://arxiv.org/abs/1802.04064)

### Inferences
- Scale check (my arithmetic on the cited orders, ignoring constants): sqrt(K T ln K) at T = 5,000 is about 200 for K = 5 and about 290 for K = 8, that is 4 to 6% of T; the Exp4 bound sqrt(2 n k log M) at n = 5,000, k = 5, M = 100 experts is about 480, nearly 10% of n. These are worst-case guarantees against the best fixed arm or expert only, so at this scale they say little about beating a competent hand-written rule.
- Exp3 and Exp4 are online algorithms: their guarantees depend on updating weights after every round. With offline-only training and no online updates they reduce to a fixed stochastic policy between retrains, and the adversarial guarantee no longer applies. Their propensities are loggable (explicit distributions), but that is not a reason to choose them over softmax.
- An adversary who changes behaviour in response to the system's earlier actions within a session is a reactive environment in the book's sense. The literature's answer is not a non-stationary bandit but modelling the dependence (state features, an MDP, or a game), which ties this question to the bandit-versus-sequential decision in sections 3 and 4.
- For drift across sessions (new tools, new populations), the applicable practices are: time-ordered train/validation splits, recency weighting or sliding windows when refitting, tracking OPE of the current policy over time as a drift monitor, and never letting the exploration floor reach zero so that old policies remain evaluable on new data.
- A population that learns to recognise the system over repeated encounters makes rewards depend on the deployed policy itself; no OPE method on past logs can see that effect, so periodic fresh randomised data is the only check.

### Gaps
- I did not find an empirical study of Exp3/Exp4 versus stochastic methods at a few thousand rounds with contexts; the practicality judgement above rests on bound arithmetic and on the offline-training constraint.
- The published version of Auer et al. (SIAM J. Comput. 32(1), 2002, DOI 10.1137/S0097539701398375) was not opened; I read the authors' manuscript.
- Arora et al.'s conversion mechanism for bounded-memory adversaries is not described in the abstract and was not verified.
- Not opened: Jagerman, Markov, de Rijke 2019 on OPE under non-stationarity.

### Sources first cited in this section
- Auer, Cesa-Bianchi, Freund, Schapire. 2002. "The Nonstochastic Multiarmed Bandit Problem". SIAM Journal on Computing 32(1) (DOI 10.1137/S0097539701398375; manuscript version read). https://cseweb.ucsd.edu/~yfreund/papers/bandits.pdf
- Beygelzimer, Langford, Li, Reyzin, Schapire. 2010. "Contextual Bandit Algorithms with Supervised Learning Guarantees". arXiv [venue unverified: AISTATS 2011]. https://arxiv.org/abs/1002.4058
- Arora, Dekel, Tewari. 2012. "Online Bandit Learning against an Adaptive Adversary: from Regret to Policy Regret". ICML 2012. https://arxiv.org/abs/1206.6400
- Besbes, Gur, Zeevi. 2014. "Optimal Exploration-Exploitation in a Multi-Armed-Bandit Problem with Non-stationary Rewards". arXiv preprint. https://arxiv.org/abs/1405.3316
- Garivier, Moulines. 2008. "On Upper-Confidence Bound Policies for Non-Stationary Bandit Problems". arXiv (the book cites a 2011 published version). https://arxiv.org/abs/0805.3415
- Luo, Wei, Agarwal, Langford. 2017. "Efficient Contextual Bandits in Non-stationary Worlds". arXiv [venue unverified: COLT 2018]. https://arxiv.org/abs/1708.01799
- Chandak, Theocharous, Shankar, White, Mahadevan, Thomas. 2020. "Optimizing for the Future in Non-Stationary MDPs". ICML 2020. https://arxiv.org/abs/2005.08158

---

## 6. Practical guidance from deployed systems on moving from rules to a learned policy

### Takeaway
Deployed systems converge on the same sequence: keep the existing rule as the default and as the fallback, randomise around it with logged probabilities, first train a model to imitate the rule, evaluate candidates counterfactually with confidence intervals before any switch, and close the loop manually at first. The recurring failure causes are wrong or missing logged probabilities, downstream overrides, reward-delay bias and exploration that is too uniform to give usable effective sample size.

### Cited Findings

**The Decision Service (Microsoft)**
- Four failure modes motivate the design: partial feedback and bias, incorrect data collection, environment change, and weak monitoring/debugging; specific bugs include probabilities accidentally included as features, actions overridden downstream, delay-related bias and features changing between decision and training time. — [Agarwal et al. 2016](https://arxiv.org/abs/1606.03966)
- Before the first model exists a user-supplied default policy is used, guaranteeing a minimum performance while randomisation explores; candidate policies are estimated offline before deployment and can be compared in real time against default or "safe" policies, with rollback if a policy deviates too much. — [Agarwal et al. 2016](https://arxiv.org/abs/1606.03966)
- Reported operating points: epsilon-greedy at 33% on MSN, experimental unit 10 minutes, model refresh every 5 minutes, average decision latency 0.2 ms, about 2,000 events per second per core; reported lifts include more than 25% click-through on one MSN segment over two weeks. The paper's abstract and introduction give slightly different lift ranges. — [Agarwal et al. 2016](https://arxiv.org/abs/1606.03966)

**Azure Personalizer (documentation archived; the pages state the service retires on 25 August 2026, so it is no longer available as of this note, with microsoft/learning-loop named as the open-source replacement)**
- Apprentice mode: the service returns the application's baseline action every time and trains by imitating it, with no exploration and no user-visible effect; it can approach but never exceed the baseline; switch to online mode once it matches the baseline about 60 to 80% of the time; about 50,000 historical events may be needed to reach that when replaying history; it is also used to validate features and API wiring. — [Personalizer apprentice-mode docs](https://learn.microsoft.com/en-us/azure/ai-services/personalizer/concept-apprentice-mode)
- Online mode explores with epsilon-greedy on a configured share of calls; 0% causes stagnation and 100% discards learning; the application must not behave differently depending on whether a call was exploratory. — [Personalizer exploration docs](https://learn.microsoft.com/en-us/previous-versions/azure/ai-services/personalizer/concepts-exploration)
- Offline evaluation compares the online policy, the baseline (first listed action), a random policy and custom or optimised policies by counterfactual evaluation that keeps only logged events whose action matches the evaluated policy's choice; it discards much data when there are many actions; a minimum of 50,000 events is recommended and confidence bounds must be inspected; it gives no guidance on how much to explore. — [Personalizer offline-evaluation docs](https://learn.microsoft.com/en-us/previous-versions/azure/ai-services/personalizer/concepts-offline-evaluation)
- The replacement repository describes itself as the joiner and trainer for an online reinforcement-learning loop. — [microsoft/learning-loop](https://github.com/microsoft/learning-loop)

**Lessons from a contextual-bandit customer-support bot**
- Start by imitating high-reward production decisions; regularise toward the logging policy; keep business rules outside the policy and never explore across them; log legal actions, candidates, chosen action and probability on a channel separate from diagnostics; seed the sampler deterministically from request identifiers and verify the seed inputs are diverse (a mostly-empty identifier broke offline/online agreement); track effective sample size; treat importance-weight capping as temporary; simplify the action space at first; close the loop manually with an A/B test and train only on the traffic assigned to the loop. — [Karampatziakis et al. 2019](https://arxiv.org/abs/1905.02219)
- Their framing of risk: exploration done in a safe, controlled way is indistinguishable from statistical fluctuation. — [Karampatziakis et al. 2019](https://arxiv.org/abs/1905.02219)

**News recommendation and Vowpal Wabbit**
- Yahoo front page: a random fraction of visits was served uniformly at random to create an unbiased offline evaluation set (over 34 million randomised events in 7 days) on which candidate bandit algorithms were replayed; offline results agreed with online bucket tests. — [Chapelle and Li 2011](https://papers.nips.cc/paper/2011/hash/e53a0a2978c28872a4505bdb51db06dc-Abstract.html); [Li et al. 2011](https://arxiv.org/abs/1003.5956)
- VW input format for logged bandit data is action:cost:probability followed by features; --cb learns from already-collected data, --cb_explore and --cb_explore_adf add an exploration algorithm; cb_type selects the off-policy estimator (default mtr). — [VW tutorial](https://vowpalwabbit.org/docs/vowpal_wabbit/python/latest/tutorials/python_Contextual_bandits_and_Vowpal_Wabbit.html); [VW wiki](https://github.com/VowpalWabbit/vowpal_wabbit/wiki/Contextual-Bandit-algorithms)
- Bake-off recommendations: greedy or RegCB are strong defaults when contexts are diverse but may need a uniform warm start at small n; doubly robust should be preferred to IPS for policy-based methods and importance-weighted regression is typically best for epsilon-greedy and bagging; cost encoding matters. — [Bietti, Agarwal, Langford 2021](https://arxiv.org/abs/1802.04064)

**Small-n field studies**
- Pre-deployment discipline when the algorithm cannot be changed mid-study and data is scarce: build several simulation environments from pilot data, compare candidate algorithms by average and lower-quartile outcomes, prefer the simplest model that wins, fix probability bounds in advance with domain experts, and require stable unattended operation. — [Trella et al. 2022](https://arxiv.org/abs/2206.03944); [Liao et al. 2019](https://arxiv.org/abs/1909.03539)

### Inferences
- A staged path consistent with all of the above: (1) instrument the rule with randomisation and log context, eligible set, full action distribution, chosen action, its probability, policy version and seed; (2) verify the logs by re-computing propensities offline and by checking that IPS evaluation of the logging policy on its own logs reproduces its observed mean reward; (3) fit an imitation model of the rule and check agreement; (4) train candidates offline and compare with DR/SNIPS plus confidence intervals and effective sample size, on repeated session-level splits; (5) deploy the candidate as the new centre of exploration in the lab with the rule as fallback and a rollback trigger; (6) keep a permanent exploration floor or uniform stratum for future evaluations.
- The few-millisecond, no-network constraint is compatible with every closed-form exploration rule above: the Decision Service reports 0.2 ms average decision latency for model-plus-sampling, and SquareCB or softmax cost one model evaluation per action. Only Monte Carlo propensity estimation for Thompson sampling is at odds with it.
- The Personalizer thresholds (60 to 80% baseline match; 50,000 events) come from a general-purpose product with larger action sets and should not be read as requirements at 5 to 8 actions; the general point that match-based ("replay") evaluation wastes data proportional to the number of actions still applies and favours IPS/DR with logged propensities over matching.
- Offline-only training simplifies the Decision Service architecture: no online join or learner latency, and the logging policy is fixed per release, which removes the adaptive-data inference problems within a release.

### Gaps
- Personalizer documentation is archived and the service is past its stated retirement date; details may not match the open-source successor, whose README gives no information on exploration algorithms or logging format.
- I did not find a public write-up from a deployed system that explores actions which end the session; the conservative-exploration literature in section 2 is theoretical or simulated.
- The Decision Service numbers date from 2016-2017; the Bake-off from 2018-2021; the support-bot lessons from 2019. Tooling versions and defaults may have changed.
- The Decision Service paper's publication venue is not shown on the arXiv page I opened.

### Sources first cited in this section
- Microsoft. Azure AI Personalizer documentation (archived), "Apprentice mode" (page dated 19 Jan 2024; archive updated 1 Sep 2026). https://learn.microsoft.com/en-us/azure/ai-services/personalizer/concept-apprentice-mode
- Microsoft. Azure AI Personalizer documentation (archived), "Use the Offline Evaluation method". https://learn.microsoft.com/en-us/previous-versions/azure/ai-services/personalizer/concepts-offline-evaluation
- Microsoft. "learning-loop" repository (README). https://github.com/microsoft/learning-loop
- Vowpal Wabbit documentation, tutorial "Contextual Bandits and Vowpal Wabbit" (latest). https://vowpalwabbit.org/docs/vowpal_wabbit/python/latest/tutorials/python_Contextual_bandits_and_Vowpal_Wabbit.html
