# MIRAGE AI/ML design

Status: draft for review · 11 November 2026
Companion docs: [build plan](01-build-plan.md) · [architecture](02-architecture.md)

The rule for every task: build the simple baseline first, measure it on the held-out scenario suite, and replace it only with something that beats it there. The research found several places where published deep-model numbers do not survive a proper split.

## 1. Summary

| Task | Phase | Baseline (build first) | Stronger model (later, if it wins) | Not doing, and why |
| --- | --- | --- | --- | --- |
| Response policy | 1–3 | Rules, then a contextual bandit with an action mask | Tabular or offline Q-learning over session stages | DQN/PPO and gym pre-training: no data to support them, and the gyms model a different problem |
| Actor classification | 2 | Rules plus LightGBM | Sequence encoder over commands and timing | — |
| Tactic and technique tagging | 2–3 | LogPrécis (tactics) plus rules and retrieval (techniques) | Encoder fine-tuned on lab ground truth | Zero-shot LLM labelling as the primary tagger: about 72% reported |
| Generative responder | 3 | Emulator, then output pre-rendered per profile, then cache | 8–9B local model with external state, for novel commands only, streamed, on a GPU | Pure-LLM shell, or live generation on the laptop: S2 measured median 8.6 s per command |
| Flow and tool tagging | 3–4 | Gradient-boosted trees on Zeek/Suricata features | — | ET-BERT, E-GraphSAGE: benchmark results do not hold under per-flow splits |
| Anomaly detection | 4 | First-seen counters plus Isolation Forest | Masked-LM surprisal from a shell encoder | Deep SVDD, DeepLog, LogBERT at this data scale |
| Campaign correlation | 4 | Shared-indicator graph plus Leiden | GNN, only with thousands of labelled campaign memberships | Heterogeneous GNN now |
| LLM-agent detection | 4 | Injection canaries plus timing features | Fused classifier once labelled agent sessions exist | Treating it as a solved classifier |
| Analyst | 4 | Retrieval-backed summary; rules validated by pySigma | — | Autonomous rule deployment |
| Federation | 5 | Flower simulation, FedAvg/FedProx | DP and either SecAgg or robust aggregation | Promising all three together |

## 2. Response policy

**Formulation.** Each command is a decision with a context and a small action set: allow, fake success, fake error, delay, plant a token, escalate, terminate. The reward arrives at session end. Start by treating it as a contextual bandit and attribute the session reward to its decisions; move to a sequential formulation only when session counts allow.

**Why not deep RL.** RASSH, Cannypot, Asguard and Q-Cowrie all use tabular Q-learning with a handful of states. Q-Cowrie uses eight ATT&CK-stage states, rewards of +5/+2/+1 by severity, and an offline warm start. Nothing published supports a deep policy at hundreds to low thousands of sessions. No bandit-based shell honeypot was found, so this choice is our inference, not a replicated result.

**Context features.** Session stage (last tactic seen), actor class and confidence, command class, whether the emulator knows the command, commands so far, novelty score, time since last command.

**Action mask.** Hard rules remove actions before the policy chooses: no escalation without a sandbox available, no real egress ever, terminate on budget exhaustion. The policy never sees a masked action.

**Reward.** Pay for events, not for time. Duration and command-count rewards (RASSH, Cannypot) teach the policy to stall.

- Positive: each new distinct technique observed; a captured artifact; a honeytoken taken.
- Negative: the session ends immediately after a faked response (a likely tell); LLM tokens spent; a failed probe-suite check.

**Logging and evaluation.** Every decision is logged with its context, action and propensity from the first day, including while rules are in charge. That makes off-policy evaluation possible (inverse propensity scoring, self-normalised IPS, doubly robust). A new policy is allowed to act only after it beats the rule baseline offline and then in the lab.

**Libraries.** Vowpal Wabbit 9.11 for the bandit (arm64 wheels for Python 3.13). The off-policy estimators are short enough to write ourselves; Open Bandit Pipeline and SCOPE-RL have not been released since 2023. Gymnasium 1.4 for the replay environment. d3rlpy, if offline Q-learning is tried, needs a pinned Python 3.11 environment.

**Replay environment.** A Gymnasium environment that replays recorded and simulated sessions, with a simple attacker model that continues, changes course or leaves depending on the response. It is for testing the training loop and for regression, not a faithful attacker.

## 3. Actor classification

**Classes:** scanner, scripted bot, human, LLM agent.

**State of the field.** Published work on Cowrie sessions is almost all unsupervised clustering. No public labelled dataset of human, bot and agent sessions was found. Labels therefore come from the lab (the scenario runner's timing profiles and lab agents) and from heuristics on real data.

**Features.** Inter-command timing and its variance; typing artifacts (backspaces, typos, pasted blocks); command novelty against the corpus; session length; credential patterns; client version and HASSH as weak features, not identity.

**Model.** Rules for the obvious cases (no commands, known scanner fingerprints), LightGBM for the rest. Report macro-F1 per class and a confusion matrix; evaluate on real sessions with heuristic labels as a sanity check.

## 4. ATT&CK tagging

**What exists.** LogPrécis (`SmartDataPolito/logprecis`, Apache-2.0) labels each part of a shell session with one of seven labels: Execution, Persistence, Discovery, Impact, Defense Evasion, Harmless, Other. It was trained on 360 sessions and reports token accuracy 0.912 but session fidelity 0.669. It has no technique labels. Models trained on threat-report prose (TRAM, TTPXHunter) do not transfer directly to shell commands.

**Step 1, phase 2: tactics.** Run LogPrécis as is. Map its Defense Evasion label through `attack_version`, since ATT&CK v19 split that tactic.

**Step 2, phase 2: techniques by rules and retrieval.** Regex rules for the frequent, unambiguous cases (cron edits, authorized_keys writes, download-and-execute). For the rest, embed the command and retrieve the nearest ATT&CK technique descriptions and Atomic Red Team procedures; an LLM re-ranks the top candidates offline. Output the top technique with a confidence and abstain below a threshold.

**Step 3, phase 3: fine-tuned encoder.** Fine-tune a small encoder (SecureShellBert or a ModernBERT-class security model) on lab ground truth for multi-label technique classification. Training fits on the laptop or a single modest GPU; LogPrécis trained in 10–50 minutes on a 16 GB GPU.

**Evaluation.** Micro- and macro-F1 at technique level on a split by `procedure_id`. Report tactic-level results against LogPrécis on its public data. Report abstention rate alongside accuracy.

**HTTP and database sessions.** Rules first (path and payload classes); extend the encoder once labelled lab data exists for those protocols.

## 5. Generative responder

**Model.** A general 8–9B open-weight model at 4-bit in GGUF. Published evaluations found models under 2B fast but unfaithful (LLMHoney: 488 ms with 25.9% hallucination for a 1B model) and code-specialised models worse than a general 8B model for shell output. HydraPoT used a local Qwen3.5-9B, but on an RTX 4060, not a laptop.

**Measured on the M4 (spike S2).** Qwen3.5-9B Q4_K_M generated 12.5 tokens/s. With prompt caching the first token came at 0.48 s, but the median command took 8.6 s and none of 150 finished under 1.5 s. Four concurrent sessions halved each stream. Quality was good on state consistency and staying in character (0 of 150 broke it), but 3 of 50 answers contained a mistake a careful attacker would notice. Root was refused `/etc/shadow`, `which` used RHEL's format on a Debian host, and `ss` printed `netstat`'s header. The model is fine for **offline pre-rendering** of profile output, where speed does not matter and every answer is checked. For live answers it needs a GPU, a smaller model, or both; the next comparison is a 4B model on the same 50 commands.

**Serving.** `llama-server`: per-request JSON-schema output, prompt caching, slot reuse, metrics. Native on the Mac.

**Targets from the literature.** HoneyGPT's best model averaged 5.83 commands per effective session against 2.96 for Cowrie alone. AdvancedShelLM was rated like a real Ubuntu host by humans (n=26). A response time of about 2 s was judged a tell in one study, so the latency target for LLM-rendered answers is under 1.5 s, with most answers coming from the emulator or cache.

**Fine-tuning.** Not in the first build. The one published shell fine-tune used 617 examples for modest gains, and its ground truth was Cowrie output, not a real host. If done later, collect transcripts from the real reference host.

**Fidelity check.** Every pre-rendered output, and a sample of live ones, is compared with the same command run in a real container of the claimed distribution and release. That is the same method spike S3 uses for the SSH transport. The comparison is structural (format, fields, exit code), not exact text.

**Evaluation.** Unit tests on state consistency (a created file is listed, a removed file is gone); the fingerprint probe suite; response-time distribution against the reference host; tokens and cost per session; a blind human test once the rest is stable. For the HTTP decoy, Honeyval (Google Research, Apache-2.0) is an existing evaluation harness to try before writing our own.

## 6. Flow and tool tagging

A honeypot has no benign traffic, so a benign-versus-malicious classifier adds little. What is useful is naming the tool or attack type. Use gradient-boosted trees on Zeek connection features and Suricata alerts. Under proper per-flow splits, tree models reached about 78–83 macro-F1 on tasks where ET-BERT's per-packet 97.4% fell to 28.0%; a randomly initialised ET-BERT matched the pretrained one, and the shortcuts were sequence numbers, timestamps and IPs.

Public flow datasets (CICIoT2023, the corrected CIC-IDS releases, the NetFlow sets) have documented flaws and unconfirmed licences. Use them for smoke tests only and report final numbers on lab traffic.

## 7. Anomaly detection

First-seen counters (new command, new binary hash, new credential pair, new client fingerprint) catch most of what matters and are explainable. Add Isolation Forest or kNN distance on session features and a TF-IDF/SVD embedding of commands. Studies in the log-anomaly literature (ICSE 2022, ICSE 2024) found simple methods matching deep ones; no evaluation on honeypot sessions was found, so this is transferred guidance. A high score routes the session to an analyst and raises the policy's novelty feature.

## 8. Campaign correlation

Build a graph of sessions and indicators (source IP and ASN, credentials, payload hashes, download URLs, client fingerprints). Weight edges by rarity, so that a shared rare payload counts and a shared common password does not. Add similarity edges between payloads (TLSH, MinHash). Cluster with connected components and Leiden. Store in ClickHouse and NetworkX or igraph; no graph database is needed yet (Kuzu is archived). Evaluate on lab scenarios where campaign membership is known by construction.

## 9. LLM-agent detection

**What is published.** Palisade's honeypot used a modified Cowrie with prompt injections in the banner, command output and files, and a response-time threshold of about 1.5–1.7 s calibrated on one model. It logged 8.13 million interactions and flagged 8 potential agents, with no validated precision or recall. "Say Shibboleth" (November 2026) reports identifying the model and harness of agents at about 90%, but its code is not public.

**Design.** Canary instructions with a unique nonce planted where only something reading the output as instructions would act on them; contingency probes; timing features (latency against output length, regularity). Emit an agent-likelihood signal with the evidence attached.

**Honest limits.** No public dataset of confirmed agent sessions exists. Lab agents provide the positives, so measured precision applies to those agents only. Report it as such.

## 10. Analyst

A larger model, run offline, receives the session transcript, tags and retrieved ATT&CK and prior-session context, and writes a short summary and a draft Sigma rule. Secrets are redacted before the prompt. Every rule must parse with pySigma and is tested against replayed benign and malicious sessions before a person reviews it. Nothing is deployed automatically.

## 11. Federation

**Framework.** Flower 1.43 with the Message API. Releases 1.36–1.43 changed transport and CLI repeatedly, so versions are pinned across sites.

**Constraints the research found**

- SecAgg+ runs only on the legacy workflow API and raises an error with current strategies.
- Differential privacy in Flower is still marked preview.
- Robust aggregation (Krum, trimmed mean) needs the individual updates that secure aggregation hides. Choose one.
- Krum's guarantee needs n ≥ 2f + 3 sites: five to tolerate one bad one.
- No study was found comparing federated training with DP against local-only training for intrusion detection at 2–5 sites. General cross-silo results show FedAvg can lose to local training under heterogeneous data.

**Plan.** Simulate five sites on one machine with non-IID splits of the session data. Compare local-only, centralised, FedAvg and FedProx for the actor classifier and the tagger. Then add central DP and measure the utility cost. Write down the threat model and pick secure or robust aggregation. Indicator sharing over STIX is the cross-site value that does not depend on this result.

## 12. Data

| Source | Size and licence | Use |
| --- | --- | --- |
| Cowrie corpus, Zenodo 21260400 | 38M sessions, 211M events, CC BY 4.0 | Unlabelled pretraining, replay, realistic command distribution |
| CyberLab honeynet, Zenodo 3687527 | 10 GB, CC BY 4.0 | Same |
| LogPrécis data | 360 sessions; annotations CC BY 4.0, underlying sessions under separate terms | Tactic tagger evaluation |
| Lab ground truth | Ours | Training and evaluation for classifier, tagger, policy |
| Own sensors | Ours | Reality check for every model |

**Split discipline.** By `procedure_id` for lab data and by time for real data. De-duplicate sessions before any split; bot traffic repeats heavily, and reported next-command accuracies of 94–99% mostly measure that repetition.

## 13. Where things train and run

| Work | Where |
| --- | --- |
| LightGBM, Isolation Forest, bandit, graph clustering | Laptop CPU |
| Encoder fine-tuning (110–150M parameters) | Laptop (MPS) or a small cloud GPU |
| LLM responder inference | Laptop native, or the Linux host |
| LLM fine-tuning, anything larger | Cloud GPU |

The laptop feasibility figures are estimates; spike S2 measures the LLM, and phase 2 measures the rest.
