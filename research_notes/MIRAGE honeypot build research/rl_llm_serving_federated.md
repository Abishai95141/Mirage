# MIRAGE implementation research: RL/bandit response policy, local LLM responder, federated learning with Flower (state as of 2026-11-11)

Method note: package versions/dates were read directly from the PyPI JSON API and repo status from the GitHub REST API on 2026-11-11 (cited as the package/repo page). Flower facts were checked against flower.ai docs v1.43.x. Anything not verified against a primary source is in **Gaps** or flagged "(unverified)". Speed (tokens/s) figures come from secondary blogs and are flagged as weak.

---

## 1.1 RL formulation: contextual bandit vs tabular Q-learning vs DQN/PPO at low data volume

### Takeaway
Start with a contextual bandit (per-command decision, logged propensities, end-of-session reward credited back to each decision) plus hard-rule action masking; prior honeypot RL work is almost all tabular Q-learning on tiny state spaces, and nothing in the literature justifies DQN/PPO at hundreds-to-low-thousands of sessions. Deep/sequential RL should be an offline experiment evaluated with OPE, not the first production policy.

### Cited Findings
- RASSH (Pauna et al.) used Q-learning to choose responses to attacker commands, with a reward "primarily based on session duration". — [arXiv 2512.07827 (related-work summary)](https://arxiv.org/pdf/2512.07827)
- Cannypot (Politecnico di Torino; Cowrie extension) selects answers "aiming to keep them connected and sending more commands"; state is the last command (`reinforcement_state = single`) or the last N commands (`multiple`, `multiple_out`, default `num_entry_states = 3`). — [Cannypot thesis](https://webthesis.biblio.polito.it/19256/1/tesi.pdf); [Cannypot repo](https://github.com/SmartData-Polito/cannypot)
- Q-Cowrie (Int. J. Information Security, 2026) is Cowrie + Q-learning + an MDP model; i.e. still tabular. — [Springer](https://link.springer.com/article/10.1007/s10207-026-01221-5)
- Asgard/Midgard (2021-2022) use Q-learning with two objectives: engage attackers to collect tools and guard against compromise. — [SCITEPRESS 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf); [Applied Sciences 12(10):5224](https://mdpi.com/2076-3417/12/10/5224)
- HoneyIoT reports PPO converging fastest, but over 100 *simulated* sessions. — [HoneyIoT (WiSec'23)](https://mcn.cse.psu.edu/paper/guan-chongqi/wisec23-chongqi.pdf)
- Logged bandit feedback only reveals the reward of the chosen arm; OPE requires accurately logged action propensities. — [Lefortier et al., arXiv 1612.00367](https://arxiv.org/pdf/1612.00367); [Li et al., arXiv 1003.5956](https://arxiv.org/pdf/1003.5956)
- Doubly-robust estimation is unbiased if either the propensity or reward model is right, but is high-variance/data-inefficient for deterministic target policies; delayed-feedback bandit OPE can mislead and needs diagnostics. — [arXiv 2608.11560](https://arxiv.org/pdf/2608.11560)
- In small-sample early phases, bandit results are sensitive to the outcome model; simpler policies help. — [arXiv 1711.07077](https://web3.arxiv.org/pdf/1711.07077v3)
- 99.2% of traffic seen by one LLM-honeypot deployment was low-sophistication scanning ("data desert"), so informative sessions are far fewer than total sessions. — [SoK: Honeypots & LLMs, arXiv 2510.25939](https://arxiv.org/html/2510.25939v4)

### Inferences
- Recommended staging: (a) rule policy + epsilon-greedy/softmax exploration over the *allowed* action set, logging `(context, allowed_actions, action, propensity, session_id, step)`; (b) contextual bandit (VW `--cb_explore_adf` or LinUCB/Thompson with a linear model) using a per-step proxy reward plus the session-end reward distributed to steps (e.g. discounted return-to-go); (c) only then offline sequential RL (discrete CQL / DQN) scored with FQE against the bandit.
- Seven actions x a compact context (command class, session phase, attacker type, #commands so far) is small enough for a linear CB to learn from ~1-2k sessions; a DQN/PPO needs orders of magnitude more interaction, which only a simulator can provide.
- `terminate` and `escalate` are absorbing/hand-off actions with state consequences: treat them as rule-gated rather than bandit arms initially, since a bandit cannot credit long-horizon effects.
- Action-dependent features (ADF format) let "plant honeytoken" be available only when a token is ready, which is the natural way to express masks in VW.

### Gaps
- No source found that directly benchmarks contextual bandits vs Q-learning vs DQN for honeypot response selection; the recommendation above is inference from OPE literature and from the tabular nature of prior systems.
- Full Q-Cowrie reward/state definitions are paywalled (Springer redirect); not read.

---

## 1.2 Library state (versions, maintenance, Python 3.12/3.13, Apple Silicon)

### Takeaway
Actively maintained and Python-3.13-ready: Vowpal Wabbit, river, contextualbandits, Stable-Baselines3/sb3-contrib, Gymnasium, PettingZoo, RLlib. Stale: Open Bandit Pipeline (2023), SCOPE-RL (2023), MABWiser (2024), CleanRL's PyPI package (2023), d3rlpy (last release Mar 2025) — use these in a pinned Python 3.10/3.11 container or reimplement the few estimators needed.

### Cited Findings
| Library | Latest (date) | Python | Notes | Source |
|---|---|---|---|---|
| vowpalwabbit | 9.11.9 (2026-09-27) | >=3.10; classifiers 3.10-3.13; macOS arm64 wheels cp310-cp314 | BSD-3; repo pushed 2026-10-15 | [PyPI](https://pypi.org/project/vowpalwabbit/), [repo](https://github.com/VowpalWabbit/vowpal_wabbit) |
| vowpal-wabbit-next | 0.7.0 (2023-10-06) | wheels only to cp312 | stale; do not use | [PyPI](https://pypi.org/project/vowpal-wabbit-next/) |
| river | 0.26.1 (2026-08-21) | >=3.11; wheels cp311-cp315 | BSD-3; repo pushed 2026-11-10 | [PyPI](https://pypi.org/project/river/), [repo](https://github.com/online-ml/river) |
| mabwiser | 2.7.4 (2024-08-30) | classifier only 3.8 | Apache-2.0; repo last pushed 2024-09 | [PyPI](https://pypi.org/project/mabwiser/), [repo](https://github.com/fidelity/mabwiser) |
| contextualbandits | 0.3.31 (2026-10-28) | no wheels published (sdist) | BSD-2; repo pushed 2026-10-28 | [PyPI](https://pypi.org/project/contextualbandits/), [repo](https://github.com/david-cortes/contextualbandits) |
| obp (Open Bandit Pipeline) | 0.5.7 (2023-04-14) | classifiers 3.8-3.10 | Apache-2.0; repo last pushed 2024-06 | [PyPI](https://pypi.org/project/obp/), [repo](https://github.com/st-tech/zr-obp) |
| scope-rl | 0.2.1 (2023-07-30) | classifiers 3.9-3.11 | Apache-2.0 | [PyPI](https://pypi.org/project/scope-rl/) |
| stable-baselines3 / sb3-contrib | 2.9.2 (2026-10-26) | >=3.10; 3.10-3.13 | MIT | [PyPI](https://pypi.org/project/stable-baselines3/), [PyPI](https://pypi.org/project/sb3-contrib/) |
| cleanrl | PyPI 1.2.0 (2023-05-22), `>=3.7.1,<3.11` | repo pushed 2026-04-20 | use by copying single files from the repo, not pip | [PyPI](https://pypi.org/project/cleanrl/), [repo](https://github.com/vwxyzjn/cleanrl) |
| ray (RLlib) | 2.60.0 (2026-11-04) | >=3.10; arm64 wheels cp310-cp314 | Apache-2.0 | [PyPI](https://pypi.org/project/ray/) |
| d3rlpy | 2.8.1 (2025-03-02) | >=3.9; classifiers 3.9-3.11 | MIT; repo last pushed 2025-09-10; README pins `gymnasium==1.0.0`, `torch>=2.5.0`; supports Linux/macOS/Windows | [PyPI](https://pypi.org/project/d3rlpy/), [repo](https://github.com/takuseno/d3rlpy) |
| gymnasium | 1.4.0 (2026-10-05) | >=3.10; 3.10-3.14 | MIT | [PyPI](https://pypi.org/project/gymnasium/) |
| pettingzoo | 1.27.0 (2026-08-13) | >=3.10,<3.15 | MIT | [PyPI](https://pypi.org/project/pettingzoo/) |
| torch | 2.15.0 (2026-10-28) | >=3.11; macOS arm64 wheels cp311-cp315 | | [PyPI](https://pypi.org/project/torch/) |
| Minari (offline RL dataset format) | repo pushed 2026-10-14 | | Farama | [repo](https://github.com/Farama-Foundation/Minari) |

- VW contextual bandit API: label format `action:cost:probability | features`; `--cb N` (learn from logged data, no exploration), `--cb_explore N`, `--cb_explore_adf` (changing/rich action sets, multi-line examples); exploration `--first`, `--epsilon`, `--bag`, `--cover`, `--softmax --lambda`; `--cb_type {ips,dr,dm,mtr}`; Python: `vowpalwabbit.Workspace("--cb 4", quiet=True)`, `.learn()`, `.predict()`, `.save()`, reload with `-i`. Note VW uses **cost** (negative reward). — [VW CB tutorial](https://vowpalwabbit.org/docs/vowpal_wabbit/python/latest/tutorials/python_Contextual_bandits_and_Vowpal_Wabbit.html)
- d3rlpy algorithms with discrete-action support: BC, NFQ, DQN, Double DQN, SAC, BCQ, CQL (e.g. `d3rlpy.algos.DiscreteCQLConfig`), Decision Transformer. — [d3rlpy README](https://github.com/takuseno/d3rlpy)
- OBP estimators: DM, IPW, SNIPW, DR, Switch, MRDR, DRos, SGIPW, SGDR, DML (+ slate and continuous variants); `bandit_feedback` dict keys `context, action, reward, pscore, n_rounds`; `OffPolicyEvaluation(bandit_feedback, ope_estimators=[IPW()]).estimate_policy_values(action_dist=...)`. — [zr-obp README](https://github.com/st-tech/zr-obp)

### Inferences
- Default stack on the M4/Python 3.13: `vowpalwabbit` (bandit + built-in IPS/DR learning) or a 100-line NumPy LinUCB/Thompson; `gymnasium` 1.4 for the replay environment; `sb3-contrib` MaskablePPO for simulator experiments.
- OBP/SCOPE-RL/d3rlpy declare no 3.12/3.13 support; run them in a `python:3.11` Docker image (linux/arm64) dedicated to offline evaluation. d3rlpy pins `gymnasium==1.0.0`, so it will conflict with gymnasium 1.4 in one environment. IPS/SNIPS/DR are ~30 lines each, so hand-rolling them is a realistic alternative to OBP.
- contextualbandits ships no wheels, so installation needs a C compiler/Cython toolchain (Xcode CLT on macOS).

### Gaps
- Whether river's published wheels include macOS arm64 was not confirmed (my wheel-tag parse found cp311-cp315 tags but could not confirm the platform tag).
- Did not verify river's current bandit module contents or whether d3rlpy/obp actually install and run on 3.13 despite missing classifiers.
- RLlib new-API-stack specifics (2.60) not reviewed; it is heavyweight for this problem and not recommended as the starting point (inference).

---

## 1.3 Offline RL, off-policy evaluation, and safe RL / action masking

### Takeaway
Log propensities from day one; evaluate candidate policies with SNIPS and DR (bandit view) and FQE (sequential view) before deployment, and enforce safety rules as an action mask outside the learner, not as a reward penalty.

### Cited Findings
- OPE depends on logged propensities; IPS and self-normalised IPS are the standard starting estimators. — [arXiv 1612.00367](https://arxiv.org/pdf/1612.00367)
- DR is high variance for deterministic target policies because it only uses the ~1/K of events that match. — [arXiv 2608.11560](https://arxiv.org/pdf/2608.11560)
- VW can learn from logged data with `--cb` and choose the estimator via `--cb_type ips|dr|dm|mtr`; a separate "Offline Policy Evaluation Using the Command Line" tutorial exists. — [VW CB tutorial](https://vowpalwabbit.org/docs/vowpal_wabbit/python/latest/tutorials/python_Contextual_bandits_and_Vowpal_Wabbit.html)
- SCOPE-RL is an OPE/selection library built on d3rlpy. — [d3rlpy README](https://github.com/takuseno/d3rlpy)
- MaskablePPO (sb3-contrib): boolean masks (True = valid) via an env `action_masks()` method or the `ActionMasker` wrapper; supports Discrete/MultiDiscrete/MultiBinary actions; no recurrent policies; `ActionMasker` cannot be used with `SubprocVecEnv`; `check_env` gives false errors on masked envs; must use `sb3_contrib.common.maskable.evaluation.evaluate_policy` and `MaskableEvalCallback` or masks are not applied in evaluation. — [sb3-contrib docs](https://sb3-contrib.readthedocs.io/en/master/modules/ppo_mask.html)
- Asgard explicitly builds self-protection into the objective (collect tools vs guard against compromise). — [SCITEPRESS 2021](https://www.scitepress.org/Papers/2021/107191/107191.pdf)

### Inferences
- Minimum log schema per decision: `session_id, step, context_vector, allowed_action_mask, chosen_action, propensity_of_chosen_action, policy_version, per-step signals, session_outcome`. Without `propensity` and the mask, IPS/DR are impossible retroactively.
- Keep a floor of exploration (e.g. epsilon >= 0.05 spread over allowed actions) in the logging policy so importance weights are bounded; clip weights and report effective sample size alongside every OPE estimate. With ~1k sessions, expect wide confidence intervals: use OPE to reject clearly worse policies, then confirm with a small online A/B split by session.
- Safety layer = deterministic policy shield: compute the mask from rules (e.g. never `execute` commands with outbound network effect, never `plant honeytoken` twice, force `terminate` on budget breach). The learner samples only within the mask; the mask itself is logged so OPE stays valid.
- Sequential evaluation: build a d3rlpy/Minari dataset from sessions and run FQE for discrete actions; treat FQE as a ranking signal only at this data size.

### Gaps
- d3rlpy's FQE API (`d3rlpy.ope.DiscreteFQE`) is from prior knowledge; it was not shown on the README fetched (unverified against current docs).
- No honeypot paper found that reports OPE of a response policy before deployment; this appears to be unpractised in the literature reviewed.
- Constrained-RL libraries (e.g. Lagrangian PPO implementations) were not researched; masking covers hard rules.

---

## 1.4 Cyber RL environments and whether to pre-train in them

### Takeaway
The existing gyms model network-level attack/defence (lateral movement, re-imaging, decoy placement), not per-command response selection inside one shell session, so pre-training a honeypot response policy in them is not realistic; build a small custom Gymnasium environment that replays recorded/simulated attacker sessions. Cyberwheel and CAGE-4 are the only maintained-ish ones with first-class decoy actions and are useful only for a separate "where to place decoys" question.

### Cited Findings
- CyberBattleSim: mainly attacker-centric (lateral movement; attacker takes ownership of nodes); the defender is a "basic stochastic defender" that scans and re-images with preset probabilities; Python 3.10 setup; MIT; no deception elements in the README; repo last pushed 2026-10-30, not archived. — [microsoft/CyberBattleSim](https://github.com/microsoft/CyberBattleSim)
- A research extension added decoys, honeypots and honeytokens to CyberBattleSim to study placement against an attacker agent (attacker penalised -100 for touching them); attacker progress depended on number and location of deceptive elements. The RL agent there is the attacker. — [Walter et al., "Incorporating Deception into CyberBattleSim"](https://www.researchgate.net/publication/353779928_Incorporating_Deception_into_CyberBattleSim_for_Autonomous_Defense); [IJCAI-21 ACD workshop proceedings, arXiv 2108.13980](https://arxiv.org/pdf/2108.13980)
- CAGE Challenge 4: multi-agent blue (five network defenders), PettingZoo-conformant wrapper, `DeployDecoy` blue action (decoy service on a host; red exploit against it fails and raises an alert); bundles its own `CybORG` directory; competition phase ended 10 May 2024; repo last pushed 2025-10-27. — [cage-challenge-4](https://github.com/cage-challenge/cage-challenge-4)
- The standalone `cage-challenge/CybORG` repo was last pushed 2024-06-03; `cage-challenge-2` is MIT and was pushed 2025-09-25; CybORG and CC4 report a non-standard licence (GitHub: NOASSERTION, `LICENSE.txt` present). — [CybORG](https://github.com/cage-challenge/CybORG); [cage-challenge-2](https://github.com/cage-challenge/cage-challenge-2)
- Cyberwheel (ORNL): blue agent "mainly deploys decoys" to slow/stop red; red built on Atomic Red Team techniques mapped to ATT&CK kill-chain phases; Gymnasium-based; Python 3.10 required; v2.0 added FIREWHEEL emulation and multi-agent support; MIT; last pushed 2025-08-26. — [ORNL/cyberwheel](https://github.com/ORNL/cyberwheel)
- NASim: attacker (pentest) simulator; PyPI 0.12.0 from 2023-05-14; repo last pushed 2024-02. — [PyPI nasim](https://pypi.org/project/nasim/); [repo](https://github.com/Jjschwartz/NetworkAttackSimulator)
- PenGym: pentesting training framework for RL agents (attacker side), BSD-3, last pushed 2024-12-19. — [cyb3rlab/PenGym](https://github.com/cyb3rlab/PenGym)
- A 2026 paper combines network-level RL deception with an LLM-driven device-level honeypot (DNP3) and penalises the RL agent when honeypot realism degrades. — [arXiv 2603.17272](https://arxiv.org/html/2603.17272)
- Cannypot's "Explorer" is the closest thing to a honeypot-specific response oracle: it replays unknown commands against real backend VMs (libvirt) and stores outputs for the Learner; it must run as root on a separate machine. — [Cannypot repo](https://github.com/SmartData-Polito/cannypot)
- Public real session data to drive a replay simulator: MURHCAD multi-regional T-Pot/Cowrie dataset with deployment tutorial. — [arXiv 2601.05813](https://arxiv.org/pdf/2601.05813)
- Many Cowrie sessions end early because bots detect the honeypot, so logs embed the logging honeypot's own tells. — [CEUR-WS Vol-4198 paper51](https://ceur-ws.org/Vol-4198/paper51.pdf)

### Inferences
- Custom env sketch: `reset()` samples an attacker script (real Cowrie session, or a parametrised bot/human model); observation = features of current command + session history; `step(action)` advances the script using a response model: P(continue | command class, action) estimated from logs, with script branches (e.g. bot aborts after `fake error` on `wget`, human retries). `action_masks()` implements safety rules. Episode reward = intelligence metrics at session end.
- Simulator bias is the central risk: logged attackers reacted to Cowrie's behaviour, not to MIRAGE's. Use the simulator for plumbing, hyper-parameters and sanity checks; trust only OPE on real MIRAGE logs and online A/B for policy selection.
- An LLM-driven attacker agent could serve as an additional synthetic adversary (the SoK recommends co-evolving LLM attackers and honeypots), but it models "Tier-2 automated" attackers, not the scripted bots that dominate traffic.

### Gaps
- CyGIL: no primary source located in this research; status unknown.
- No published, reusable honeypot attacker-behaviour simulator (Gymnasium env replaying SSH sessions) was found; searches returned only datasets.
- Could not confirm whether a CAGE Challenge 5 or newer CybORG release exists (GitHub API rate-limited; CC4 README mentions none).
- Exact CybORG/CC4 licence terms not read.

---

## 1.5 Reward design lessons (RASSH, Asgard, Cannypot, Q-Cowrie, others)

### Takeaway
Pure "session length / number of commands" rewards (RASSH, Cannypot) are easy but reward stalling; later work shifts to state-action-coupled rewards that pay for specific intelligence events (malware upload, new techniques) and penalise risk or realism loss. MIRAGE should reward novelty and captured artefacts, not duration.

### Cited Findings
- RASSH: reward primarily session duration; a 2025 honeynet paper argues a quality-based reward valuing novel and significant interactions is preferable to longevity. — [arXiv 2512.07827](https://arxiv.org/pdf/2512.07827)
- Cannypot: objective is keeping intruders connected and sending more commands; in a month-long deployment it was "exploited with longer sequences of commands than a static honeypot". — [Cannypot thesis](https://webthesis.biblio.polito.it/19256/1/tesi.pdf)
- A related RL-honeypot paper ("conceal honeypot functionality") uses a reward maximising attacker command transitions. — [Univ. of Galway record](https://research.universityofgalway.ie/en/publications/using-reinforcement-learning-to-conceal-honeypot-functionality-3/)
- Asgard defines reward from environment state (the Linux command) *and* the action; Midgard uses state only; Asgard is reported to collect higher-quality data than Cowrie while evading detection, though a reviewer flagged an inconsistency in average-command figures. — [Applied Sciences 12(10):5224](https://mdpi.com/2076-3417/12/10/5224); [review report](https://www.mdpi.com/2076-3417/12/10/5224/review_report)
- HoneyIoT: moderate reward for vulnerability exploitation, highest reward for uploading malicious code. — [HoneyIoT](https://mcn.cse.psu.edu/paper/guan-chongqi/wisec23-chongqi.pdf)
- HoneyGPT finding: failed commands end engagements, so command success rate matters. Guan et al.: 2.96 commands per effective attack on Cowrie vs 5.83 for the best LLM variant. — [SoK arXiv 2510.25939](https://arxiv.org/html/2510.25939v4)
- SoK proposal (untested): a novelty-based "information gain" metric as the RL/prompt-optimisation objective; evaluation tetrad = believability, fidelity, attacker cost/intelligence (session length, ATT&CK diversity), defender cost (tokens, latency, hardware). — [SoK arXiv 2510.25939](https://arxiv.org/html/2510.25939v4)
- Bounded composite reward with a realism-degradation penalty. — [arXiv 2603.17272](https://arxiv.org/html/2603.17272)

### Inferences
- Suggested session reward: `w1*new_unique_commands + w2*new_ATT&CK_techniques + w3*captured_payload_hashes(new) + w4*honeytoken_touched - w5*LLM_tokens_spent - w6*risk_events - w7*early_disconnect_after_fake_error`, bounded/normalised. Dedupe by campaign (same script from many IPs counts once), or botnets dominate the reward.
- `fake error` likely shortens sessions (HoneyGPT observation), so it should be valued only when it protects against risk; `delay` trades attacker cost against bot timeouts.
- Because reward arrives at session end, emit dense proxies per step (did the attacker send another command within T seconds? was the command new?) for the bandit, and reserve the end-of-session composite for offline evaluation.

### Gaps
- Exact reward formulas for Cannypot, Q-Cowrie and Asgard were not extracted (README lacks them; papers paywalled/not opened). QRASSH/IRASSH/Heliza not researched.

---

## 2.1 Small open-weight models for terminal/HTTP output simulation (16 GB Apple Silicon; 16-24 GB GPU)

### Takeaway
On a 16 GB M4 the realistic band is 4B-9B (up to ~12B) at 4-bit: Qwen3.5 4B/9B, Gemma 4 E4B/12B, Qwen3 4B/8B, Phi-4-mini 3.8B, Qwen2.5-Coder 7B; a 16-24 GB GPU additionally fits Phi-4 14B, Qwen3 14B, gpt-oss 20B and Mistral Small 3.2 24B. Published honeypot evaluations show sub-2B models are fast but unfaithful and that >~2 s latency is itself a tell, so pick the smallest model that passes a fidelity test set and put a deterministic layer in front of it.

### Cited Findings
- Ollama library (checked 2026-11-11): `qwen3.5` tags 0.8b/2b/4b/9b/27b/35b/122b with `-mlx` variants; `gemma4` tags e2b/e4b/12b/26b/31b with `-mlx` variants; `qwen3` 0.6b/1.7b/4b/8b/14b/30b/32b/235b; `gemma3` 270m/1b/4b/12b/27b; `phi4-mini` 3.8b (2.5 GB); `phi4` 14b (9.1 GB); `llama3.2` 1b/3b (1.3/2.0 GB); `qwen2.5-coder` 0.5b-32b; `qwen3-coder` only 30b (19 GB) and 480b; `mistral-small3.2` 24b (15 GB); `granite4` 350m/1b/3b; `gpt-oss` 20b (14 GB)/120b. — [qwen3.5](https://ollama.com/library/qwen3.5); [gemma4](https://ollama.com/library/gemma4); [qwen3](https://ollama.com/library/qwen3); [gemma3](https://ollama.com/library/gemma3); [phi4-mini](https://ollama.com/library/phi4-mini); [phi4](https://ollama.com/library/phi4); [llama3.2](https://ollama.com/library/llama3.2); [qwen2.5-coder](https://ollama.com/library/qwen2.5-coder); [qwen3-coder](https://ollama.com/library/qwen3-coder); [mistral-small3.2](https://ollama.com/library/mistral-small3.2); [granite4](https://ollama.com/library/granite4); [gpt-oss](https://ollama.com/library/gpt-oss)
- Licences (secondary sources): Qwen3.5 small series Apache 2.0, 262,144 native context; Gemma 4 reported as Apache 2.0 (one blog says Gemma licence; release 31 Mar or 2 Apr 2026 depending on source), lineup E2B, E4B, 12B, 26B MoE, 31B; Phi-4-mini 3.8B MIT. — [open-weight-models list](https://github.com/xigh/open-weight-models); [Wikipedia: Gemma](https://en.wikipedia.org/wiki/Gemma_(language_model)); [Wikipedia: Qwen](https://en.wikipedia.org/wiki/Qwen)
- Speed on 16 GB Macs (secondary, partly *estimated* not measured): Gemma 4 12B 4-bit ~7 GB and ~13-17 tok/s; Qwen3 8B Q4_K_M 13-17 tok/s on M3 16 GB; one community-measured 38.2 tok/s at MLX 4-bit on a 16 GB M4. — [llmcheck benchmarks](https://llmcheck.net/benchmarks); [llmcheck 16GB guide](https://llmcheck.net/blog/best-local-llm-16gb-mac/)
- LLMHoney: 13 open-weight models 0.36B-3.8B plus Gemini-2.0; Qwen2.5:1.5B and Phi3:3.8B were the most reliable local ones with mean latency "around 3 seconds"; smaller models often incorrect/out of character; dictionary-based virtual filesystem handles common commands. — [arXiv 2509.01463](https://arxiv.org/abs/2509.01463)
- SBASH (local 4B/8B/12B): system-prompt-tuned model without RAG matches untuned+RAG accuracy with slightly lower latency; the largest model's ~2 s delay judged too long to pass as a real system. — [arXiv 2510.21459](https://arxiv.org/abs/2510.21459); [SoK summary](https://arxiv.org/html/2510.25939v4)
- Phase-adaptive routing (Future Internet 2026): Gemma3-1B answers in <0.5 s but diverges sharply from ground truth; proposes routing commands to different backends by attack phase. — [MDPI Future Internet 18(7):359](https://www.mdpi.com/1999-5903/18/7/359) (page returned 403; claim from search snippet)
- Otal & Canbaz found code-specialised models (CodeLlama, Codestral) *less* effective than Llama3-8B for shell simulation and Llama3-70B too slow. — [arXiv 2409.08234](https://arxiv.org/html/2409.08234v2)
- Unsloth QLoRA minimum VRAM: 3B 3.5 GB; 7B 5 GB; 8B 6 GB; 9B 6.5 GB; 14B 8.5 GB; 27B 22 GB. — [Unsloth requirements](https://unsloth.ai/docs/get-started/fine-tuning-for-beginners/unsloth-requirements)

### Inferences
- Shortlist for the M4 (Docker Desktop and the dev tools also need RAM, so budget <= ~7 GB for the model): (1) Qwen3.5 4B or Gemma 4 E4B as the default responder; (2) Qwen3.5 9B / Qwen3 8B as "high-fidelity" tier for interactive-looking sessions; (3) Phi-4-mini (MIT) where licence simplicity matters. Disable "thinking" modes for shell output (latency and leakage of reasoning text).
- Shell/HTTP responses are short (tens to low hundreds of tokens), so time-to-first-token and prompt-prefix caching matter more than raw tok/s; at ~20-40 tok/s a 60-token `ls -la` answer is 1.5-3 s unless streamed, hence streaming to the PTY plus caps like `max_tokens` 256.
- Don't assume coder variants are better (Otal & Canbaz); test general 4B-9B models on a ground-truth command set (Levenshtein/SBERT vs a real container) before choosing.

### Gaps
- Exact per-tag sizes for qwen3.5/gemma4/qwen3 were scraped approximately and not mapped tag-by-tag; verify with `ollama show`.
- No primary, measured tok/s or TTFT benchmark for these models on an M4 16 GB was found; all numbers above are secondary/estimated. Benchmark locally (`llama-server` `timings`, `mlx_lm.generate --verbose`).
- Llama 4 small variants, Phi-5, and Mistral "Ministral" current status not verified; Gemma 4 licence conflict between sources unresolved (check the HF model card).
- Did not verify licence texts on HuggingFace model cards directly.

---

## 2.2 Serving: Ollama vs llama.cpp server vs MLX-LM vs vLLM

### Takeaway
For MIRAGE use `llama-server` (llama.cpp) as the primary responder backend: it has per-request GBNF/JSON-schema constraints, explicit slot/KV-cache control, API keys and Prometheus metrics. Ollama is the convenient alternative (JSON-schema `format`, MLX engine on Apple Silicon since 2026); `mlx_lm.server` is dev-only; vLLM proper is the Linux/GPU production option, with Apple Silicon only via the community `vllm-metal` plugin. All run natively on macOS, not inside Docker Desktop (no Metal GPU in Linux containers — see Gaps).

### Cited Findings
- llama.cpp server: OpenAI-style `/v1/completions`, `/v1/chat/completions`, `/v1/models`; constraints via `--grammar`, `--grammar-file`, per-request `grammar`, `-j/--json-schema`, per-request `json_schema`, and `response_format` (`json_object` or `json_schema`); `--cache-prompt` on by default; `--cache-reuse N` (KV shifting, default 0); `--slot-save-path` + `POST /slots/{id_slot}?action=save|restore|erase`; request `id_slot` pins a slot; `-cram/--cache-ram N` host-memory prompt cache (default 8192 MiB); `-np/--parallel`; `-cb` continuous batching (default on); `-c/--ctx-size`; `-n/--n-predict` (default -1 = unlimited); response `timings` (`prompt_ms`, `predicted_per_second`, `cache_n`, `prompt_n`, `predicted_n`) and `usage.prompt_tokens_details.cached_tokens`; `--api-key`, `--api-key-file`; `--metrics` (Prometheus `/metrics`). — [llama.cpp server README](https://raw.githubusercontent.com/ggml-org/llama.cpp/master/tools/server/README.md)
- Ollama structured outputs: pass a JSON schema in `format` (or `"json"`); also via OpenAI-compatible `response_format`; recommended to repeat the schema in the prompt and use temperature 0; not supported on Ollama cloud; docs do not expose GBNF. — [Ollama docs](https://docs.ollama.com/capabilities/structured-outputs)
- Ollama on Apple Silicon moved to an MLX engine (preview announced 30 Mar 2026, performance update 11 Jun 2026); v0.30 (May 2026) added llama.cpp compatibility alongside MLX. Library now carries `-mlx` tags. — [Ollama blog: MLX](https://registry.ollama.ai/blog/mlx); [Ollama blog: MLX performance](https://registry.ollama.ai/blog/mlx-performance); [gemma4 tags](https://ollama.com/library/gemma4)
- mlx-lm 0.32.2 (2026-10-16), Python >=3.11; `mlx_lm.server --model ...` on localhost:8080 with `/v1/chat/completions`, `/v1/models`; fields include `max_tokens` (default 512), `stop`, `logit_bias`, `adapters`, `draft_model`; docs do not mention `response_format`/JSON schema; quantised KV cache (`--kv-bits`) disables batching; "not recommended for production as it only implements basic security checks". — [PyPI mlx-lm](https://pypi.org/project/mlx-lm/); [mlx-lm SERVER.md](https://raw.githubusercontent.com/ml-explore/mlx-lm/main/mlx_lm/SERVER.md)
- vLLM 0.33.0 (2026-11-02), Python >=3.11,<3.15. Official docs route Apple Silicon GPU acceleration to **vLLM-Metal**, a community-maintained plugin using MLX/Metal, distributed separately; v0.29.0 requires Apple Silicon + macOS 15+; installed via script or Homebrew; recommends `mlx-community` models; Docker Model Runner also exposes it. — [PyPI vllm](https://pypi.org/project/vllm/); [vLLM GPU install docs](https://docs.vllm.ai/en/latest/getting_started/installation/gpu/); [vllm-metal announcement](https://vllm.ai/blog/2026-09-22-vllm-metal-v0-28-0); [vllm-metal repo](https://github.com/vllm-project/vllm-metal)
- Constrained-decoding libraries: outlines 1.3.3 (2026-08-06, Python <3.14); guidance 0.3.1 (2026-02-03); llama-cpp-python 0.3.36 (2026-10-01); lmql stale (0.7.3, 2023). — [outlines](https://pypi.org/project/outlines/); [guidance](https://pypi.org/project/guidance/); [llama-cpp-python](https://pypi.org/project/llama-cpp-python/); [lmql](https://pypi.org/project/lmql/)

### Inferences
- Minimal responder architecture: honeypot core -> responder service (FastAPI) -> `llama-server` bound to 127.0.0.1 with `--api-key`, `-np 2-4`, fixed `-c 4096-8192`, `--metrics`. Requests use one shared static system prompt prefix (host persona + filesystem summary) so `cache_prompt` reuses the KV prefix; pin each attacker session to a slot (`id_slot`) only if concurrent sessions <= slots, otherwise rely on prefix reuse plus `--cache-ram`.
- Use a JSON schema such as `{"stdout": str, "exit_code": int, "state_delta": {"cwd": str, "files_created": [...]}}` to keep output bounded and machine-checkable, with `n_predict`/`max_tokens` cap and `stop` strings (prompt marker). GBNF can additionally forbid markdown fences and chat-style preambles for raw-terminal output.
- From Docker Desktop containers reach the native server at `host.docker.internal:<port>`; keep the port firewalled from the honeypot's attacker-facing network namespace.
- Abstract the backend behind the OpenAI chat API so the same code targets `llama-server`/Ollama on laptops and vLLM on a Linux GPU box in deployment; vLLM gives the best multi-session throughput (continuous batching) on a 16-24 GB GPU.

### Gaps
- Not verified from a primary source in this session: that Docker Desktop on macOS cannot pass the Metal GPU to Linux containers (widely known; treat as unverified here), Ollama env vars `OLLAMA_NUM_PARALLEL`/`OLLAMA_KEEP_ALIVE` current semantics, and current Ollama version number (GitHub API rate-limited; one blog claiming "0.40 MLX by default" conflicts with others topping out at 0.31.x).
- No primary TTFT measurements on M-series for these servers were found.
- vLLM structured-output backend options (xgrammar/guidance/outlines) in 0.33 not checked.

---

## 2.3 Response caching design (exact, normalised, semantic; state-awareness)

### Takeaway
Use a three-tier design — deterministic emulator/dictionary, then a state-keyed exact/normalised cache, then the LLM — and make every cache key include the session's virtual-state fingerprint; semantic (embedding) caches are a poor fit for shell commands where one character changes the correct output.

### Cited Findings
- Ragsdale & Boppana (2023) proposed caching deterministic responses; HoneyGPT routes simple commands to traditional emulators or a cache; the canonical LLM-honeypot architecture has a Filter/Router (signatures detect scanners; only novel interactions go to the LLM), a Session History Curator and a System State Manager that "tracks changes to the virtual environment"; context pruning drops prior commands that do not change state. — [SoK arXiv 2510.25939](https://arxiv.org/html/2510.25939v4)
- LLMHoney: dictionary-based virtual filesystem for common commands, LLM for novel input. — [arXiv 2509.01463](https://arxiv.org/abs/2509.01463)
- Hard cases for LLM simulation: dynamic commands (`top`, `vim`), chained commands, and outbound network actions (`wget`, C2) that produce no real traffic. — [SoK arXiv 2510.25939](https://arxiv.org/html/2510.25939v4)
- GPTCache: last PyPI release 0.1.44 (2024-08-01), repo still receiving pushes (2026-09-22). redisvl (Redis vector library incl. semantic cache) 0.32.0 released 2026-11-11, Python >=3.11. — [PyPI gptcache](https://pypi.org/project/gptcache/); [GPTCache repo](https://github.com/zilliztech/GPTCache); [PyPI redisvl](https://pypi.org/project/redisvl/)

### Inferences
- Why state-aware: the correct output of `ls`, `cat x`, `pwd`, `whoami`, `ps` depends on cwd, prior `touch/rm/echo >`, `cd`, `su`, env vars and downloaded files. A cache keyed only on the command returns stale or contradictory output — the easiest honeypot fingerprint (`touch a; ls` not showing `a`).
- Key design: `key = H(persona_id, normalised_command, state_fingerprint)` where `state_fingerprint = H(cwd, uid, relevant subtree mtime/hash, env subset)` scoped to what the command class reads. Classify commands: (a) state-independent & static (`uname -a`, `cat /etc/os-release`, `cat /proc/cpuinfo`) -> global per-persona cache, consistent across sessions and sites; (b) state-reading -> key includes fingerprint; (c) state-mutating -> never cached, apply `state_delta` to the virtual FS then answer; (d) time/random-varying (`date`, `uptime`, `top`, `free`) -> templates with live values, never cached verbatim.
- Normalisation: collapse whitespace, canonicalise flag order for a whitelist of commands, template out attacker-specific literals (IPs, URLs, random filenames) so `wget http://x/a.sh` variants share one templated response. For HTTP paths: normalise case/trailing slash/query order and cache per `(method, path-template, persona)`.
- Persist LLM answers back into the cache/virtual FS so repeated probes are consistent (consistency across repeated commands is a key believability property) and so LLM spend falls over time; this also yields fine-tuning data.
- Semantic caches (GPTCache/Redis vector) may be acceptable for HTTP "unknown path" pages, but for shell use embeddings at most to pick few-shot examples, not to serve answers.

### Gaps
- No published design or measurement of state-aware caching for LLM honeypots was found; the SoK says prior work gives no detail on cache structure. The above is design inference.
- GPTCache's compatibility with current Python/numpy versions not tested.

---

## 2.4 Prompt-injection and denial-of-wallet defence when all input is hostile

### Takeaway
Treat the LLM as an untrusted text generator with zero privileges: no tools, no secrets in the prompt, schema-bounded output, strict token/time/rate budgets per IP and session, and deterministic fallbacks; injection classifiers (Prompt Guard 2) are useful as *telemetry and routing* signals rather than as a blocking defence, since blocking itself is a tell. LLM Guard and Rebuff are archived and should not be adopted.

### Cited Findings
- OWASP LLM Top 10 (2025) LLM10 "Unbounded Consumption" examples: variable-length input flood, Denial of Wallet, continuous input overflow, resource-intensive queries, model extraction. Mitigations: input size limits, limit logprobs/logit_bias exposure, rate limiting and per-user quotas, resource allocation caps, timeouts and throttling, sandboxing the LLM's network/internal access, logging/monitoring/anomaly detection, graceful degradation, limits on queued actions, glitch-token filtering. — [OWASP GenAI LLM10:2025](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/)
- LLM01 Prompt Injection: mitigations include input/output filtering, isolating untrusted content, least privilege and logging; instructing the model in the system prompt to ignore injections is not reliable under adversarial input. — [practitioner summary](https://dev.to/amasen/owasp-llm-top-10-what-every-engineer-building-with-ai-needs-to-know-in-2025-2gp8); [Barracuda summary](https://blog.barracuda.com/2024/11/20/owasp-top-10-risks-large-language-models-2025-updates)
- A newer list revision (reported published 4 Aug 2026) is said to move Unbounded Consumption from 10th to 6th. — [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/prompt-injection-llm-risk/) (secondary; ranking not verified on OWASP site)
- Honeypot-specific: input flooding (DoS) and prompt injection are identified weaknesses of LLM honeypots; LIMBOSH applies input transformations plus a random-forest prompt-injection classifier and uses a separate LLM context to check output fidelity; a Filter/Router keeps LLM request rates bounded. Researchers also exploit differences between human-believable and LLM-believable output to unmask LLM honeypots. — [SoK arXiv 2510.25939](https://arxiv.org/html/2510.25939v4)
- Llama Prompt Guard 2: 86M (mDeBERTa, multilingual) and 22M (DeBERTa-xsmall) classifiers labelling benign/malicious; 512-token window (segment longer inputs); 92.4 ms / 19.3 ms per 512 tokens on an A100; Llama 4 Community License (gated); limitations: adaptive attackers can evade, performance depends on the application's prompt distribution, fine-tuning recommended. — [HF model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
- `protectai/llm-guard` is **archived** (last push 2026-07-08; PyPI 0.3.16 from 2025-05-19, Python <3.13); `protectai/rebuff` is **archived** (last push 2024-08; PyPI 0.1.1 from 2024-01). — [llm-guard repo](https://github.com/protectai/llm-guard); [PyPI llm-guard](https://pypi.org/project/llm-guard/); [rebuff repo](https://github.com/protectai/rebuff); [PyPI rebuff](https://pypi.org/project/rebuff/)
- NeMo Guardrails 0.24.1 (2026-09-16), Python >=3.10,<3.14, Apache-2.0 (repo has moved orgs). PurpleLlama (Llama Guard / Prompt Guard / CyberSecEval) actively pushed 2026-11-09. — [PyPI nemoguardrails](https://pypi.org/project/nemoguardrails/); [PurpleLlama](https://github.com/meta-llama/PurpleLlama)
- llama.cpp server provides the enforcement hooks: `n_predict` cap, `--api-key`, `--parallel` slots, `/metrics` token counters. — [llama.cpp server README](https://raw.githubusercontent.com/ggml-org/llama.cpp/master/tools/server/README.md)

### Inferences
- Threat model for MIRAGE's responder: (1) *persona break* (attacker gets "As an AI..." or the system prompt -> honeypot unmasked); (2) *resource exhaustion* (local model, so "wallet" = CPU/GPU time, queue starvation, latency for other sessions); (3) *content abuse* (using the honeypot as a free LLM); (4) *log/analyst-side injection* (attacker text later fed to an analyst LLM or dashboard). There is no tool-use or data-exfiltration risk if the responder has no tools, no network and no secrets — design for that invariant.
- Practical controls, in order of value: pre-LLM router (known command -> emulator/cache; over-long, binary, or non-shell-like input -> canned `command not found`/syntax error); hard caps (input chars e.g. 512-1024, `max_tokens` 128-256, wall-clock timeout ~3-5 s then deterministic fallback); budgets (LLM calls and tokens per session, per source IP, per /24, and a global concurrency semaphore with circuit breaker to "emulator-only mode"); output validation (JSON schema, strip chat artefacts, regex deny-list for "language model", "I cannot", markdown fences; on failure return a bash-style error); prompt structure (attacker input passed as delimited data in a fixed slot, never concatenated into instructions; system prompt contains nothing sensitive, no site name, no real hostnames).
- Run Prompt Guard 2 (22M, CPU-feasible) asynchronously: a "malicious" score becomes a session feature ("attacker is probing for an LLM" — itself valuable intelligence and a bandit context feature) and can route the session to deterministic-only responses; do not show a refusal.
- NeMo Guardrails-style dialogue rails add latency and LLM calls of their own and are designed for chatbots; for a single-turn bounded generator, schema constraints plus budgets cover most of the need.
- Keep attacker-controlled strings quarantined in downstream analysis (escape in dashboards; label as untrusted if summarised by another LLM).

### Gaps
- OWASP LLM01:2025 page itself was not fetched (summaries only); the reported August 2026 list revision was not verified against genai.owasp.org.
- No empirical study of prompt-injection classifier efficacy on shell-command input distributions was found; false-positive rate on legitimate-looking shell one-liners is unknown — measure on own logs.
- Llama Guard (content classifier) current version not checked; likely low relevance here.

---

## 2.5 Fine-tuning a small model on terminal transcripts (LoRA/QLoRA; Unsloth, MLX-LM, PEFT)

### Takeaway
Fine-tuning is feasible on the laptop with `mlx_lm.lora` (QLoRA on a 4-bit model) and trivially on a 16-24 GB GPU with Unsloth/PEFT, but published shell-simulation fine-tunes used only hundreds of examples and showed modest gains; prompt-tuning plus caching should come first, with fine-tuning as a later improvement once MIRAGE has its own ground-truth transcripts.

### Cited Findings
- Otal & Canbaz: Llama3-8B fine-tuned with LoRA (8-bit quantised, Llama-Factory, NEFTune) on 617 commands (174 from Cowrie logs, 160 common Linux commands, 283 man-page summaries); LR 5e-4, 36 steps, ~14 minutes on 2x RTX A6000; cosine similarity 0.663 -> 0.695, Jaro-Winkler 0.534 -> 0.599, Levenshtein 0.332 -> 0.285 on 140 samples; model published at `hotal/honeypot-llama3-8B`. — [arXiv 2409.08234](https://arxiv.org/html/2409.08234v2)
- Jimenez et al. (2025): fine-tuned Llama 3 8B on a curated LDAP dataset with "dramatic gains" where the base model was poor. SoK recommends (untested) per-protocol LoRA heads on one shared base model; notes the Prague dataset of real shell sessions (shelLM) is small. — [SoK arXiv 2510.25939](https://arxiv.org/html/2510.25939v4)
- SBASH: system-prompt tuning alone reached accuracy similar to RAG on untuned models. — [arXiv 2510.21459](https://arxiv.org/abs/2510.21459)
- MLX-LM LoRA: `pip install "mlx-lm[train]"`; `mlx_lm.lora --model <m> --train --data <dir> --iters 600`; data as JSONL `chat` (`messages`), `completions` (`prompt`/`completion`) or `text`, files `train.jsonl`/`valid.jsonl`/`test.jsonl`; `--fine-tune-type lora|dora|full`; `--num-layers` (default 16); `--batch-size` (default 4); `--mask-prompt`; `--grad-checkpoint`; `--grad-accumulation-steps`; pointing `--model` at a quantised model gives QLoRA automatically; low-memory advice: batch 1-2, layers 4-8, shorter sequences; `mlx_lm.fuse` merges adapters and `--export-gguf` works only for Mistral/Mixtral/Llama-style fp16 models; `mlx_lm.server` accepts an `adapters` field. — [mlx-lm LORA.md](https://raw.githubusercontent.com/ml-explore/mlx-lm/main/mlx_lm/LORA.md); [SERVER.md](https://raw.githubusercontent.com/ml-explore/mlx-lm/main/mlx_lm/SERVER.md)
- Unsloth 2026.11.3 (2026-11-06), Python <3.15; docs say training works on NVIDIA/AMD/Intel and Mac, but also "Apple/Silicon/MLX is in the works" for Unsloth Core; QLoRA VRAM minimums 3B 3.5 GB, 8B 6 GB, 14B 8.5 GB. PEFT 0.21.2 (2026-10-01). — [PyPI unsloth](https://pypi.org/project/unsloth/); [Unsloth requirements](https://unsloth.ai/docs/get-started/fine-tuning-for-beginners/unsloth-requirements); [PyPI peft](https://pypi.org/project/peft/)

### Inferences
- Best training data is self-generated ground truth: replay the commands seen in honeypot logs (plus common-command lists) inside disposable real containers matching each persona, record `(state summary, command) -> (stdout, exit code, state delta)`. This is Cannypot's Explorer idea used as a data generator; aim for low thousands of pairs with state diversity rather than the ~600 used in the literature.
- On the 16 GB M4: QLoRA a 4-bit 4B model with `--batch-size 1-2 --num-layers 4-8 --grad-checkpoint --mask-prompt`; an 8-9B QLoRA is borderline with Docker Desktop running. Use a cloud/desktop GPU with Unsloth for anything larger.
- Because GGUF export from MLX is limited, decide the serving stack first: MLX adapters served by MLX/Ollama-MLX, or train with PEFT/Unsloth and convert to GGUF for `llama-server`.
- Hold out a per-persona test set and track exact-match/Levenshtein/SBERT plus a "tell" checklist (chat phrasing, markdown, refusals) — the same metrics the literature uses.

### Gaps
- No published fine-tune of a <=4B model for shell simulation with latency + fidelity numbers was found; no data-requirement study exists (sizes in the literature are small and ad hoc).
- Unsloth's Apple Silicon training support is stated inconsistently in its own docs; not tested.
- Whether Qwen3.5/Gemma 4 architectures are supported by `mlx_lm.lora` today (doc lists older families) not verified.

---

## 3.1 Flower in late 2026: version, architecture, API migration, strategies, SecAgg, DP, Opacus

### Takeaway
Flower is at 1.43.0 (2026-11-04, Python 3.11-3.13) and is now a `flwr run`-driven platform: apps are a `ServerApp` + `ClientApp` using the Message API (`flwr.serverapp` / `flwr.clientapp` / `flwr.app`), run on a SuperLink/SuperNode/SuperExec infrastructure over HTTP. The Message-API strategy module includes FedAvg/FedProx, robust aggregators (Krum, MultiKrum, Bulyan, FedTrimmedAvg, FedMedian) and central-DP wrappers; SecAgg+ still lives in the *legacy* `flwr.server.workflow` / `flwr.client.mod` path and DP is officially "preview".

### Cited Findings
- flwr 1.43.0 released 2026-11-04; `requires-python >=3.11,<4.0`; classifiers 3.11-3.13; Apache-2.0. flwr-datasets 0.6.1 (2026-09-08). — [PyPI flwr](https://pypi.org/project/flwr/); [PyPI flwr-datasets](https://pypi.org/project/flwr-datasets/)
- Message API (Flower >=1.21) migration: `flwr.common.Context` -> `flwr.app.Context`; `flwr.server.ServerApp` -> `flwr.serverapp.ServerApp`; `flwr.client.ClientApp` -> `flwr.clientapp.ClientApp`; `flwr.server.strategy.*` -> `flwr.serverapp.strategy.*`; `FitIns/FitRes` -> `Message` carrying a `RecordDict` (`ArrayRecord`, `MetricRecord`, `ConfigRecord`). Server: `app = ServerApp()`; `@app.main() def main(grid: Grid, context: Context)`; `strategy = FedAvg(fraction_train=0.5)`; `result = strategy.start(grid=grid, initial_arrays=ArrayRecord(model.state_dict()), num_rounds=3)`. Client: `@app.train()` / `@app.evaluate()` handlers taking and returning `Message` (`Message(content=RecordDict({"arrays": ..., "metrics": ...}), reply_to=msg)`); include `"num-examples"` in metrics for FedAvg weighting. Renames: `fraction_fit`->`fraction_train`, `min_fit_clients`->`min_train_nodes`, `min_available_clients`->`min_available_nodes`. `NumPyClient`/`client_fn`/`server_fn`/`ServerAppComponents` are the replaced style; old import paths deprecated. — [Upgrade to Message API](https://flower.ai/docs/framework/how-to-upgrade-to-message-api.html)
- Strategies in `flwr.serverapp.strategy`: FedAvg, FedAvgM, FedProx, FedAdam, FedAdagrad, FedYogi, QFedAvg, FedMedian, FedTrimmedAvg, Krum, MultiKrum, Bulyan, FedXgbBagging, FedXgbCyclic, and DP wrappers `DifferentialPrivacyServerSideFixedClipping`, `...ServerSideAdaptiveClipping`, `...ClientSideFixedClipping`, `...ClientSideAdaptiveClipping`. — [flwr.serverapp.strategy reference](https://flower.ai/docs/framework/ref-api/flwr.serverapp.strategy.html)
- Recent changelog: 1.43.0 — `Strategy.start()` gets `should_stop(server_round, result)`; **breaking**: SuperLink no longer auto-generates error replies for unavailable nodes (custom strategies must handle missing replies); Fleet and Control APIs are HTTP-only, legacy gRPC services removed. 1.42.0 (2026-10-22) — requires `certifi>=2026.10.19` and `uv` 0.13.x after a CA compromise. 1.40.0 (2026-10-14) — SuperNodes connect over HTTP to SuperLink `--host/--port` (default 8000); `--fleet-api-type/--fleet-api-address` deprecated; `cryptography` 50.x required. 1.37.0 (2026-09-15) — Control API over HTTP; unified `--ssl-certfile/--ssl-keyfile/--ssl-ca-certfile`; Exec API options removed; `FedTrimmedAvg` requires `beta` in [0, 0.5). 1.35/1.34 — `PrivacyAccountant` research preview and RDP accounting primitives. — [Flower changelog](https://flower.ai/docs/framework/main/en/changelog/index.html)
- Configuration moved out of `pyproject.toml` federations into a Flower Configuration file (`config.toml`, since 1.26); since 1.28 simulation settings live on the SuperLink, local profile is `[superlink.local] address = ":local:"`; CLI: `flwr config list`, `flwr federation list`. — [Upgrade to Flower 1.28](https://flower.ai/docs/framework/how-to-upgrade-to-flower-1.28.html)
- Secure aggregation: Flower provides SecAgg and SecAgg+ — `SecAggPlusWorkflow` (`flwr.server.workflow`) on the ServerApp and `secaggplus_mod` (`flwr.client.mod`) on the ClientApp. Parameters: `num_shares`, `reconstruction_threshold`, `max_weight` (1000.0), `clipping_range` (8.0), `quantization_range` (2^22), `modulus_range` (2^32), `timeout` (None = wait for all). Server sees only the aggregate, which is passed to `Strategy.aggregate_fit`; clients must report `num_examples` in `FitRes`. The workflow source raises TypeError unless given a `LegacyContext`. Example: `flwr new @flwrlabs/flower-secure-aggregation` (demo mode on by default; set `is-demo=false`). — [Secure aggregation protocols](https://flower.ai/docs/framework/explanation-ref-secure-aggregation-protocols.html); [SecAggPlusWorkflow reference](https://flower.ai/docs/framework/ref-api/flwr.server.workflow.SecAggPlusWorkflow.html); [workflow source](https://flower.ai/docs/framework/_modules/flwr/server/workflow/secure_aggregation/secaggplus_workflow.html); [example](https://flower.ai/docs/examples/flower-secure-aggregation.html)
- Differential privacy: "Differential Privacy in Flower is in a preview phase" (contact the team before production use with sensitive data). Central DP = wrap a strategy: `DifferentialPrivacyServerSideFixedClipping(strategy, noise_multiplier, clipping_norm, num_sampled_clients)`; client-side clipping variant pairs `DifferentialPrivacyClientSideFixedClipping` with `from flwr.clientapp.mod import fixedclipping_mod` (`ClientApp(mods=[fixedclipping_mod])`), adaptive variants analogous. Local DP: `LocalDpMod(clipping_norm, sensitivity, epsilon, delta)` applied as `@app.train(mods=[local_dp_obj])` (apply only to train; DP mods should run last). Central DP requires trusting the server; local DP lowers accuracy. For record-level DP-SGD the docs point to Opacus (`flwr new @flwrlabs/opacus-fl`; per-client `noise_multiplier`, `max-grad-norm` run-config). — [How to use DP](https://flower.ai/docs/framework/how-to-use-differential-privacy.html); [DP explanation](https://flower.ai/docs/framework/explanation-differential-privacy.html); [Opacus example](https://flower.ai/docs/examples/opacus.html)
- Opacus 1.6.0 released 2026-05-05 (Apache-2.0). — [PyPI opacus](https://pypi.org/project/opacus/)

### Inferences
- New code should be written only against the Message API; tutorials using `start_server`/`start_client`/`NumPyClient`/`start_simulation` are obsolete patterns (their reference pages still exist in the docs sidebar, so they are not yet fully removed, but the gRPC transport they were built on was removed in 1.43).
- SecAgg+ and the Message-API strategies/DP wrappers appear to be on *different* API generations (LegacyContext + `aggregate_fit` vs `strategy.start(grid=...)`). Expect to choose: legacy-style ServerApp with SecAgg+ and old `flwr.server.strategy` classes, or Message-API app with robust/DP strategies and no SecAgg. Verify against the example's current code before committing.
- Central-DP wrappers give *client(site)-level* DP; with 2-5 sites the noise for any meaningful epsilon swamps the signal (noise std scales with `noise_multiplier * clip / num_sampled_clients`). Record-level DP-SGD via Opacus inside each site's `@app.train()` is the only DP notion likely to remain usable.
- Pin `flwr==1.43.*` and the Docker image tags together; the 1.36-1.43 series contains repeated breaking transport/CLI changes, so mixed versions across sites will fail.

### Gaps
- Could not confirm from docs whether SecAgg+ works with Message-API strategies in 1.43 (docs silent; source suggests not), nor SecAgg+'s threat model statement (semi-honest server assumed in the original protocol — unverified here).
- Whether Flower's privacy accountant covers end-to-end epsilon across rounds for the DP wrappers is unclear ("research preview" only).
- The Opacus example's API style and Opacus 1.6 compatibility with torch 2.15 / Python 3.13 were not verified.
- Removal status/timeline for `start_server`/`NumPyClient` not found in the portion of the changelog read (page truncated at ~v1.36).

---

## 3.2 Realistic expectations: 2-5 non-IID sites, DP, poisoning defences, SecAgg vs robust aggregation

### Takeaway
At 2-5 small non-IID sites there is no evidence that FL with site-level DP beats local-only training, and good reason to expect it will not; FL's realistic value is recall on attack types a site has not yet seen locally. Byzantine-robust aggregators need more clients than MIRAGE will have (Krum's guarantee needs n >= 2f+3, i.e. >= 5 sites to tolerate one), and they are structurally incompatible with secure aggregation, which hides the per-client updates they must inspect.

### Cited Findings
- Hernandez-Ramos et al. (arXiv 2308.09522): systematic review of FL-based IDS literature 2018-2022, with taxonomy of models, datasets, aggregation functions and libraries, and a critical view of challenges. — [arXiv 2308.09522](https://arxiv.org/abs/2308.09522)
- Campos et al.: evaluated FL IDS on ToN_IoT partitioned by device IP and attack type into three non-IID settings with different aggregation functions (IBMFL), concluding with open challenges. — [arXiv 2108.00974](https://arxiv.org/abs/2108.00974)
- Doriguzzi-Corin et al. (2025, rev. Nov 2026): FedAvg "converges poorly" under non-IID and unbalanced client data; compares FL algorithms for DDoS detection on detection performance, training time and communication. — [arXiv 2509.17836](https://arxiv.org/abs/2509.17836)
- StatAvg authors: no existing FL method/aggregation strategy for non-IID data outperforms the others in all cases. — [arXiv 2405.13062](https://arxiv.org/pdf/2405.13062)
- Liu, Hu, Wu, Smith (NeurIPS 2022), cross-silo FL under silo-specific sample-level DP: FedAvg "may underperform simple local training due to data heterogeneity"; local training can beat FedAvg without privacy, while under DP, federation averages out per-silo noise; mean-regularised MTL (MR-MTL), interpolating between local training and FedAvg, is "at least as good as local" and a strong baseline — but its advantage depends on tuning lambda, and hyper-parameter tuning itself costs privacy. — [NeurIPS 2022 paper](https://proceedings.neurips.cc/paper_files/paper/2022/file/2788b4cdf421e03650868cc4184bfed8-Paper-Conference.pdf)
- Kokin, Lytvyn, Nguyen (Scientific Reports, Sept 2026), low-client-count cross-silo FL, four datasets: SecAgg protects per-client updates but does not reduce final-model leakage and adds ~49-106% training time; record-level DP-SGD preserved utility best and was the only usable option on image classification, where both client-level mechanisms (LDP, CDP) fell to chance accuracy; CDP >= LDP at equal budget; DP-SGD needs ~1/10 the noise thanks to subsampling amplification. — [Zenodo record / DOI 10.1038/s41598-026-70584-5](https://zenodo.org/records/23012579)
- Krum's Byzantine-resilience guarantee requires n >= 2f+3 (runs when n >= f+3 but without the guarantee); a 2026 study notes N=4 is below the bound for f=1, and Krum can still collapse under inner-product-manipulation attacks even when the bound holds. — [arXiv 2608.04045](https://arxiv.org/pdf/2608.04045); [arXiv 2609.16099](https://arxiv.org/pdf/2609.16099)
- Distance-based robust rules (Krum, RFA) need per-client updates that secure aggregation hides; dedicated protocols (He, Karimireddy, Jaggi "Secure Byzantine-Robust ML"; BREA; ByzSecAgg) exist to reconcile them, not off-the-shelf features. — [arXiv 2006.04747](https://pdf.arxiv.org/pdf/2006.04747); [ByzSecAgg arXiv 2302.09913](https://arxiv.org/pdf/2302.09913)
- Flower's SecAgg+ passes only the aggregate to the strategy. — [SecAggPlusWorkflow reference](https://flower.ai/docs/framework/ref-api/flwr.server.workflow.SecAggPlusWorkflow.html)
- Entente (NDSS 2026): cross-silo FL for graph-based intrusion detection (LANL, OpTC, Pivoting) outperforms FL baselines and bounds poisoning success via contribution scaling; no DP/SecAgg. — [arXiv 2503.14284](https://arxiv.org/abs/2503.14284)
- IDS under DP: tight privacy budgets "can result in very poor detection performance". — [PMC11023508](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC11023508/)

### Inferences
- Evaluation protocol MIRAGE must run before claiming FL value: for each site compare (a) local-only, (b) FedAvg/FedProx, (c) personalised (FedAvg + local fine-tune, or MR-MTL-style proximal term), (d) centralised upper bound, on each site's own held-out data *and* on other sites' attack classes; report per-site deltas, not a global average. Expect (b) to lose to (a) on a site's own distribution and win on unseen-class recall.
- Privacy posture that is defensible at 2-5 sites: TLS + SuperNode authentication, share only model updates for classifiers trained on derived features (not raw payloads), optional record-level DP-SGD (Opacus) with a stated epsilon; do not claim site-level DP. With n=2, secure aggregation is vacuous (each party can subtract its own update); it only starts to mean something at n >= 3 and adds 50-100% overhead.
- Poisoning defences that fit few known, authenticated sites: server-side norm clipping, coordinate-wise median / trimmed mean (FedMedian, FedTrimmedAvg with beta < 0.5) as a mild robustifier, per-round validation of each client update on a server-held clean holdout with rejection/down-weighting, update-norm and cosine-similarity anomaly logging, and governance (sites are accountable organisations). Krum/Bulyan are not meaningful below 5 sites (Bulyan's requirement, n >= 4f+3, is stricter still — from prior knowledge, unverified here).
- Choose one: SecAgg (privacy from the server, no per-client inspection) or robust aggregation/validation (needs plaintext updates). For a small consortium with a trusted coordinator, robust aggregation + validation is the more valuable choice.

### Gaps
- No study was found that directly evaluates FL-with-DP vs local-only for intrusion detection at 2-5 clients; the conclusion is extrapolated from general cross-silo results (NeurIPS 2022; Sci. Rep. 2026).
- The full text of Hernandez-Ramos et al. and Doriguzzi-Corin et al. was not read (abstracts only), so their specific findings on evaluation pitfalls, client counts and FL-vs-local comparisons are not captured here.
- No FL evaluation on honeypot-derived data (session/command classifiers) was found.

---

## 3.3 Simulating multi-site federation on one laptop

### Takeaway
Two tiers: `flwr run` with the Simulation Runtime (Ray backend, virtual SuperNodes, managed local SuperLink) for algorithm work, then Flower's Docker Compose "complete" setup (SuperLink + N SuperNodes + SuperExec containers, optional TLS and state persistence) to rehearse a real multi-site deployment on Docker Desktop.

### Cited Findings
- Simulation is the default mode of `flwr run`; `flwr new @flwrlabs/quickstart-pytorch` then `flwr run`; profiles with `address = ":local:"` start a managed local SuperLink reused by `flwr list`, `flwr log`, `flwr stop`. Default: 2 SuperNodes, 2 CPU cores per backend worker. Persistent config: `flwr federation simulation-config --num-supernodes 100 --client-resources-num-cpus 4 --client-resources-num-gpus 0.25`; per run: `flwr run . --federation-config="num-supernodes=256 client-resources-num-cpus=1"`. Max parallel ClientApps N = min(floor(SYS_CPUS/num_cpus), floor(SYS_GPUS/num_gpus)); extra clients are batched. Backend is Ray; "Flower fully supports Linux and macOS"; Windows experimental (WSL2 advised). — [Run simulations](https://flower.ai/docs/framework/how-to-run-simulations.html)
- Install with `pip install -U "flwr[simulation]"`. — [Upgrade to Flower 1.28](https://flower.ai/docs/framework/how-to-upgrade-to-flower-1.28.html)
- ray 2.60.0 has macOS arm64 wheels for cp310-cp314. — [PyPI ray](https://pypi.org/project/ray/)
- Docker Compose deployment: clone `framework/docker/complete` at tag `v1.43.0` from `flwrlabs/flower`; `export PROJECT_DIR=quickstart-pytorch`; `docker compose up --build -d`; add to `config.toml`: `[superlink.local-deployment] address = "127.0.0.1:8000"`, `insecure = true`; `flwr run quickstart-pytorch local-deployment --stream`. Images `flwr/supernode:1.43.0`, `flwr/superexec:1.43.0`; SuperLink on port 8000 with `--isolation process`; add nodes by uncommenting `supernode-3`/`superexec-clientapp-3` (unique name, port, `--node-config` partition). TLS: `docker compose -f certs.yml run --rm --build gen-certs`, then `-f compose.yml -f with-tls.yml` and `root-certificates` in the connection; state: `-f with-state.yml` (`state/state.db`). Without TLS traffic is unencrypted. — [Docker Compose quickstart](https://flower.ai/docs/framework/docker/tutorial-quickstart-docker-compose.html)
- The Opacus example notes users cannot currently set `NodeConfig` for simulated ClientApps (per-client settings are derived from `partition_id`). — [Opacus example](https://flower.ai/docs/examples/opacus.html)
- The repo/organisation path in current docs is `flwrlabs/flower` (the old `adap/flower` API path redirects). — [Docker Compose quickstart](https://flower.ai/docs/framework/docker/tutorial-quickstart-docker-compose.html)

### Inferences
- For MIRAGE: simulate 3-5 "sites" with `num-supernodes=5 client-resources-num-cpus=2` on the M4 (10 cores -> all five in parallel); partition honeypot data by *site* (natural non-IID) rather than with synthetic Dirichlet splits, mapping `partition-id` to a site's dataset directory.
- Keep models small (logistic/GBDT/small MLP on session features) so CPU-only clients finish in seconds; do not co-run the LLM server during FL simulation on 16 GB.
- In the Compose rehearsal, mount a different data volume per SuperNode and pass `--node-config "site=<name>"`; test node dropout by stopping a container — relevant since 1.43 changed how missing replies are surfaced to strategies.
- Docker Desktop on Apple Silicon runs linux/arm64 containers; confirm the `flwr/*` images publish arm64 variants (or accept emulation) before standardising.

### Gaps
- Not verified: arm64 availability of `flwr/superlink|supernode|superexec` images; whether `mods` (DP clipping, SecAgg+) behave identically under the Simulation Runtime in 1.43 (an old forum post said mods were not simulation-compatible; the current SecAgg example defaults to simulation, suggesting this is resolved).
- Ray memory overhead on a 16 GB machine with 5+ SuperNodes not measured.
