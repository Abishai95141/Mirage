# ML techniques for honeypot detection, ATT&CK tagging, anomaly detection, LLM-agent detection and campaign correlation (state: Nov 2026)

Verification legend used on every bullet:
- **[V]** = I opened the primary source this session and read the claim there.
- **[S]** = seen only in a search-result snippet/summary this session (page itself not opened); treat numbers as needing a check.
- **[R]** = recollection from prior knowledge; URL given from memory and NOT opened this session. Verify before citing in the final report.

Team constraints assumed throughout: 3-4 people, one Apple M4 16 GB laptop, modest cloud GPU.

---

## 1. ATT&CK / intent tagging of shell and HTTP sessions (LogPrécis and alternatives)

### Takeaway
LogPrécis is the only public, honeypot-specific pretrained tagger, but it is **tactic-level only (5 ATT&CK tactics + Harmless + Other), trained on just 360 labelled sessions**; it is a good free "first signal", not a technique tagger. For technique-level tags, no off-the-shelf model exists for shell sessions: the pragmatic route is rules/regex + retrieval over ATT&CK/Atomic Red Team with a command-line embedding model (CmdCaliper), then an LLM re-ranker, and later a small fine-tuned encoder trained on your own adversary-emulation ground truth.

### Cited Findings

**LogPrécis (what it actually provides)**
- [V] Two HF models: `SmartDataPolito/logprecis` (intent/tactic token classifier) and `SmartDataPolito/SecureShellBert` (CodeBERT domain-adapted to Unix shell); both based on `microsoft/codebert-base`. Code + models Apache-2.0; dataset annotations/splits CC BY 4.0, but the underlying HaaS (Honeypot-as-a-Service) data keeps its own Terms of Use, "not open-data". Fine-tuning: clone repo, conda env, run scripts in `2.Training/supervised_training/`, set `model_name` to a HF model; own data via `1.Dataset/Inference/` README — [GitHub repo](https://github.com/SmartData-Polito/logprecis)
- [V] Label set: **five tactics — Execution, Persistence, Discovery, Impact, Defense Evasion — plus "Harmless" and "Other"** (tactics seen <100 times in training). **No technique-level labels.** — [arXiv 2307.08309v3](https://arxiv.org/html/2307.08309v3)
- [V] Data: 360 labelled HaaS sessions (60/20/20 split, 5 random splits; ~17.7k words in train); domain adaptation on NLP2Bash (12,612) + HaaS (7,208) unlabelled sessions; inference-only corpora Cyberlab (233,047 sessions, 2019-20) and PoliTO (160,475 sessions, 2021-23) — [arXiv 2307.08309v3](https://arxiv.org/html/2307.08309v3)
- [V] Metrics (HaaS test): best config CodeBERT + context chunking + domain adaptation, token entities: accuracy 0.912, ROUGE-1 0.853, **session fidelity 0.669** (i.e. only ~2/3 of sessions get a fully correct tactic sequence). From-scratch BERT: acc 0.772 / F1 0.408. Word2Vec+RF: ROUGE-1 0.282. Fine-tuned GPT-3 Davinci: ROUGE-1 0.829, fidelity 0.560, 68 s inference, $105.65 — i.e. the 130M-param encoder beat the 175B LLM — [arXiv 2307.08309v3](https://arxiv.org/html/2307.08309v3)
- [V] Token accuracy 0.899 corresponds to macro-F1 of only 0.624 for plain CodeBERT (Table 3) — the headline "91% accuracy" hides weak minority-tactic performance; accuracy drops to 0.82 at tactic boundaries, and human annotators also found boundaries hard — [arXiv 2307.08309v3](https://arxiv.org/html/2307.08309v3)
- [V] Training cost: single 16 GB Tesla V100; domain adaptation ~50 min, fine-tune 10-20 min. Stated limitations: identical fingerprints for different attacks; low-interaction honeypots skew to Discovery; only validated on Unix shell — [arXiv 2307.08309v3](https://arxiv.org/html/2307.08309v3)
- [S] HF model card states 91.2% test accuracy and that it loads with the `transformers` token-classification pipeline; ~400k unique scripts reduce to <3,000 tactic "fingerprints" — [HF model card](https://huggingface.co/SmartDataPolito/logprecis), [project page](https://smartdata.polito.it/logprecis)
- [V] Published version: Computers & Security, DOI 10.1016/j.cose.2024.103805 — [GitHub repo](https://github.com/SmartData-Polito/logprecis)

**Command-line / shell representation models**
- [S] CmdCaliper (CyCraft, EMNLP 2024): first command-line-specific embedding models (small/base/large), trained on CyPHER = 28,520 LLM-generated similar-command pairs, tested on 2,807 real-attack pairs; authors state code/data/weights released under BSD licence; HF pages are gated (contact-info click-through). Third-party summary claims the ~30M-param small model beats 10x larger general sentence-embedding models on malicious-command detection/classification — [arXiv 2411.01176](https://arxiv.org/abs/2411.01176), [GitHub](https://github.com/cycraft-corp/CmdCaliper), [HF model](https://huggingface.co/CyCraftAI/CmdCaliper-base), [HF dataset](https://huggingface.co/datasets/CyCraftAI/CyPHER). Caveat: CyPHER is Windows-command-line heavy [R], so Linux shell transfer is unproven.
- [R] Shell Language Processing (SLP, Trizna 2021): bash tokeniser (bashlex-based) + TF-IDF/one-hot encoders for Unix commands, evaluated with gradient-boosted trees — a ready-made TF-IDF baseline for shell — [arXiv 2107.02438](https://arxiv.org/abs/2107.02438), [GitHub](https://github.com/dtrizna/slp)

**CTI-text-to-technique models (useful for retrieval/zero-shot, NOT trained on commands)**
- [S] TRAM (MITRE CTID): fine-tuned SciBERT predicting the **50 most common techniques** from CTI sentences; MITRE blog reports "88 of 100" correct; no F1 found for that figure — [MITRE Engenuity blog](https://medium.com/mitre-engenuity/our-tram-large-language-model-automates-ttp-identification-in-cti-reports-5bc0a30d4567); repo [R]: [github.com/center-for-threat-informed-defense/tram](https://github.com/center-for-threat-informed-defense/tram)
- [S] TTPHunter covered only the top-50 TTPs (data scarcity); TTPXHunter (SecureBERT-based, 2024) reports F1 92.42% on its *augmented* sentence dataset and 97.09% on a report-level dataset, claiming gains over TRAM, LADDER, rcATT — [arXiv 2403.03267](https://arxiv.org/abs/2403.03267). These are in-distribution numbers on an augmented set built by the authors.
- [S] Counter-evidence on inflation: SynthCTI reports SecureBERT macro-F1 of only **0.4412**, rising to 0.6558 with synthetic augmentation, on CTI-to-MITRE and TRAM datasets — [arXiv 2507.16852](https://arxiv.org/html/2507.16852v1). So honest macro-F1 over a long-tailed technique set is ~0.45-0.65, not 0.9+.
- [S] 2025 WWW-companion paper: LLM summarisation + retrained SciBERT on rebalanced data, "several" techniques >0.90 F1 (per-technique, not macro) — [arXiv 2505.03147](https://arxiv.org/abs/2505.03147); two-stage trained LLM technique classifier — [arXiv 2411.18755](https://arxiv.org/pdf/2411.18755); Fayyazi et al. compare encoder-only vs decoder-only + RAG on procedure descriptions — [arXiv 2401.00280](https://arxiv.org/abs/2401.00280); RAG-ATT&CK (Twente thesis 2025) improves over a bare LLM but "does not surpass state-of-the-art" fine-tuned methods — [essay.utwente.nl/106511](https://essay.utwente.nl/essays/106511)
- [S] SecureBERT 2.0 (Cisco, ModernBERT-base backbone, Apache-2.0): base, bi-encoder, cross-encoder, NER, code-vuln variants on HF; vendor-reported NER F1 0.945 vs 0.734 for SecureBERT 1 — [arXiv 2510.00240](https://arxiv.org/abs/2510.00240), [GitHub](https://github.com/cisco-ai-defense/securebert2), [HF base](https://huggingface.co/cisco-ai/SecureBERT2.0-base), [bi-encoder](https://huggingface.co/cisco-ai/SecureBERT2.0-biencoder), [cross-encoder](https://huggingface.co/cisco-ai/SecureBERT2.0-cross_encoder)
- [R] Other encoders: SecureBERT v1 [HF](https://huggingface.co/ehsanaghaei/SecureBERT) / [arXiv 2204.02685](https://arxiv.org/abs/2204.02685); CySecBERT [HF](https://huggingface.co/markusbayer/CySecBERT) / [arXiv 2212.02974](https://arxiv.org/abs/2212.02974); ATTACK-BERT sentence-embedding model for ATT&CK text [HF](https://huggingface.co/basel/ATTACK-BERT); rcATT (TF-IDF + linear SVM multi-label on reports) [GitHub](https://github.com/vlegoy/rcATT)

**Honeypot-/command-specific technique mapping**
- [V] Aalborg MSc thesis (Cermáková & Kütük, June 2026): Cowrie data; maps individual commands to techniques by **search + re-rank over ATT&CK data and Atomic Red Team examples with command normalisation**; second classifier = human-vs-automated on session behavioural features. Abstract gives no metrics; admits heuristic labels, limited per-command context, modest dataset — [AAU project page](https://projekter.aau.dk/automated-attampck-mapping-and-adversary-classification-in-ssh-honeypot-sessions-66476c4b.html)
- [S] SoK "Honeypots & LLMs" (2025): cites GPT-4 prompted labelling of logs with techniques at **72.46% accuracy**; a ChatGPT/SSH study claiming 98.84% ATT&CK mapping accuracy whose own authors warn of high false positives; earlier rule-based mapping (XT-Pot) and an ML-classifier honeypot (SYNAPSE); quotes that ATT&CK mapping is "resource-intensive and subjective" — [arXiv 2510.25939](https://arxiv.org/pdf/2510.25939), [Kent EICC 2024 paper](https://www.cs.kent.ac.uk/people/staff/ba284/home/Papers/HoneypotChatGPT-EICC2024-AAM.pdf)
- [S] Trace2ATT&CK (Sept 2026): compares pure LLM prompting vs RAG (local vector store of ATT&CK Enterprise) for kernel-telemetry→technique mapping; prompts reason over the whole command flow, not isolated commands — [arXiv 2609.12841](https://arxiv.org/pdf/2609.12841)
- [S] PoliTO thesis (Oct 2025): LLM ATT&CK mapping of Windows telemetry with **one Atomic Red Team technique per run as ground truth**; Hamming loss 0.0026 in-domain, weaker cross-domain — [webthesis.biblio.polito.it/37688](https://webthesis.biblio.polito.it/37688/1/tesi.pdf)
- [R] Ground-truth sources: Atomic Red Team (MIT licence; YAML with technique ID → concrete commands, Linux coverage included) [GitHub](https://github.com/redcanaryco/atomic-red-team); MITRE Caldera abilities (technique-tagged commands) [GitHub](https://github.com/mitre/caldera)

### Inferences
- **Baseline to build first:** (1) run LogPrécis as-is for tactic spans; (2) a hand-written rule layer (regex/Sigma-style on normalised commands: `wget|curl … | sh` → T1105/T1059.004, `crontab` → T1053.003, `authorized_keys` → T1098.004, `history -c` → T1070.003, etc.). On Cowrie traffic, a few dozen rules will cover the large majority of volume because the command distribution is extremely head-heavy (LogPrécis collapsing ~400k scripts to <3k fingerprints supports this). Rules also give explainable, auditable tags — important because technique labelling is subjective.
- **Stronger model:** retrieval + re-rank. Index ATT&CK technique descriptions + Atomic Red Team/Caldera commands with CmdCaliper (command↔command) and SecureBERT 2.0 bi-encoder or ATTACK-BERT (command-explanation↔technique text); take top-k; re-rank with an LLM (local 4-bit 7-8B via MLX, or API) that sees the *whole session* context. Cache by normalised command so LLM cost is paid once per unique command.
- **With adversary-emulation ground truth:** because Caldera/Atomic runs give you exact (command, technique) pairs, train a multi-label classifier over only the 30-60 techniques you actually emulate: TF-IDF (char n-grams + SLP tokens) + logistic regression/LightGBM first; then fine-tune SecureShellBert/CodeBERT (LogPrécis recipe, context chunking) with technique labels. Expect the TF-IDF model to be near the encoder for verbatim/near-verbatim commands; the encoder/LLM only earns its keep on obfuscated or paraphrased commands. **Pitfall:** emulation data is templated — random splits leak near-duplicates. Split by *procedure/ability ID* or by tool, and hold out real honeypot sessions hand-labelled by two people as the true test set; report macro-F1 and per-technique support.
- CTI-sentence models (TRAM, TTPXHunter, rcATT) are trained on prose, not commands; use them only via an intermediate "explain this command in one sentence" LLM step, or not at all.
- Reported 0.92-0.97 F1 figures for CTI technique classifiers are on augmented/in-distribution splits; the 0.44→0.66 macro-F1 of SecureBERT in SynthCTI and 72% GPT-4 accuracy are more realistic planning numbers. For shell commands with rules+retrieval+LLM on a restricted technique set, 70-85% top-1 at technique level is a reasonable expectation (my estimate, no published benchmark).
- HTTP sessions: no ATT&CK-tagging model found; rule mapping from Suricata/ET signature metadata and CVE→technique tables is the practical route (inference; see Gaps).

### Gaps
- No public benchmark of technique-level tagging of **Linux shell honeypot sessions** was found; AAU thesis metrics were not in the abstract (full PDF not opened).
- MITREtrieval (ontology + DL fusion for CTI reports): I recall it exists (IEEE, ~2024) but did not locate/verify a URL or metrics this session.
- Exact TTPXHunter-vs-TRAM per-model table not opened; TRAM F1 not found.
- CmdCaliper licence/gating and the "30M params beats 10x larger" claim come from snippets; Linux coverage of CyPHER unverified.
- No source found for ATT&CK tagging of HTTP honeypot sessions specifically.

---

## 2. Session / actor classification (scanner / scripted bot / human / LLM agent) on Cowrie-style sessions

### Takeaway
The literature is mostly **unsupervised clustering** of Cowrie command sessions (edit distance, BoW/Word2Vec, topic models, HDBSCAN); supervised human-vs-bot classification exists only in theses with heuristic labels. No labelled public dataset with a human/bot/LLM-agent column was found, so start with rules + gradient-boosted trees on hand-engineered session features and generate your own labels by emulation.

### Cited Findings
- [S] Nested Dirichlet / topic models for Cowrie-style terminal sessions (sessions = documents, commands = sentences; session-level and command-level topics; clustering + outlier spotting; v4 Dec 2024) — [arXiv 2301.02505](https://arxiv.org/abs/2301.02505)
- [S] PoliTO: ~200k Cowrie shell sessions projected with Bag-of-Words vs Word2Vec then clustered — [iris.polito.it PDF](https://iris.polito.it/retrieve/handle/11583/2969416/595492)
- [S] Shamsi et al. 2022: consensus clustering across multiple honeypots (incl. Cowrie) to identify single actors behind many IPs; related work measures bot vs human activity — [arXiv 2206.13614](https://ar5iv.labs.arxiv.org/html/2206.13614)
- [S] Edit-distance clustering of Cowrie sessions; clusters almost universally Mirai-associated — [NSF PAR 10206353](https://par.nsf.gov/servlets/purl/10206353)
- [V] AAU 2026 thesis: ML on session-level behavioural features to label human-driven vs automated; heuristic labels, modest data, no metrics in abstract — [AAU](https://projekter.aau.dk/automated-attampck-mapping-and-adversary-classification-in-ssh-honeypot-sessions-66476c4b.html)
- [S] Practitioner notebook (Project Lost Piglet 2): HDBSCAN on Cowrie sessions as behavioural taxonomy, "ejects botnet mass as noise", skeleton-based cross-session attribution — [site](https://justinmmcc.github.io/LP2-Behavioral-Threat-Intelligence/)
- [S] HASSH is a soft identity signal: in one botnet-mapping write-up the shared HASSH also appeared on ~120 addresses outside the cluster — [write-up mirror](https://hackernews-dynamic.seasondane.workers.dev/news/48320615)
- [V] Palisade classifies actors into bots / LLM agents / humans using prompt-injection response + response latency (details in section 5) — [arXiv 2410.13919v2](https://arxiv.org/html/2410.13919v2)
- [R] Fingerprint tooling: HASSH (Salesforce, BSD-3) [GitHub](https://github.com/salesforce/hassh); JA4+ suite incl. JA4SSH/JA4H/JA4T (JA4 TLS is BSD-3; other JA4+ methods under FoxIO Licence 1.1 — check terms for commercial use) [GitHub](https://github.com/FoxIO-LLC/ja4); Cowrie logs HASSH, per-keystroke TTY logs with timestamps, and credentials [GitHub](https://github.com/cowrie/cowrie)
- [R] Tree models beat deep nets on medium-size tabular data (Grinsztajn et al., NeurIPS 2022) — [arXiv 2207.08815](https://arxiv.org/abs/2207.08815)

### Inferences
- **Baseline:** deterministic rules get scanner vs interactive almost for free (no auth / auth-only / exec-channel one-liner / interactive PTY). Then LightGBM/XGBoost on ~40 features: command count, unique-command ratio, session duration, inter-command gap mean/CV/min, per-keystroke inter-arrival stats (bots paste whole lines → near-zero intra-line gaps), backspace/typo/tab-completion counts, PTY requested + terminal size/TERM env, exec vs shell channel, HASSH/client-version string, credential-list signature (known Mirai/default lists), command-sequence hash seen-before count (from the fingerprint dictionary), response to errors (retry/adapt vs plough on), download+execute pattern.
- The decisive human-vs-script features are timing/keystroke and "novelty relative to fleet" features, not command content; content features mostly identify the *botnet family*.
- **Stronger model:** concatenate tabular features with a session embedding (TF-IDF SVD or SecureShellBert mean-pool) into the same GBT; a sequence transformer over (command, delta-t) is only worthwhile after ≥10^4 labelled interactive sessions.
- **Labels:** scripted-bot labels are abundant; human and LLM-agent sessions are rare in the wild (Palisade: 8 potential agents in 8.1M). You must synthesise: red-team volunteers + runs of open agent frameworks against your own honeypot. Risk: classifier learns "our lab's IP/timing" — hold out entire operators/agent frameworks/models when evaluating.
- Treat HASSH/JA4 as *features and graph edges with low weight*, never as identity (common libraries — paramiko, libssh, Go x/crypto — share fingerprints across unrelated actors).

### Gaps
- No peer-reviewed supervised human/bot/LLM classifier on Cowrie with reported metrics found. No public labelled dataset for this 4-way task found.
- No paper found evaluating JA4SSH or inter-keystroke timing specifically for honeypot actor typing.

---

## 3. Flow / traffic classification (ET-BERT, E-GraphSAGE, datasets) — and is it useful on a honeypot?

### Takeaway
Do not build on ET-BERT-class pretrained traffic models: SIGCOMM 2025 showed their ~97% accuracy is a per-packet-split leakage artefact (ET-BERT falls to 28% unfrozen / 11% frozen under per-flow split; random-init equals pretrained) and that **RF/XGBoost/LightGBM on header features match or beat them at a fraction of cost**. On a honeypot, a benign-vs-malicious flow classifier has little value (everything is unsolicited); flow features are useful as *descriptors* for attack-type tagging, tool fingerprinting and clustering, for which Zeek/Suricata + GBT is sufficient.

### Cited Findings
- [V] "The Sweet Danger of Sugar: Debunking Representation Learning for Encrypted Traffic Classification" (ACM SIGCOMM 2025). TLS-120 packet-level accuracy / macro-F1: ET-BERT 97.4/96.8 (per-packet split) → 28.0/21.5 (per-flow, unfrozen) → 10.9/6.7 (per-flow, frozen); YaTC 98.2/97.7 → 36.6/31.4 → 15.5/9.6; NetMamba 97.4/96.8 → 40.7/35.3 → 8.8/4.5; TrafficFormer 86.0/83.3 → 43.7/38.9 → 29.7/24.0; netFound 71.0/67.4 → 39.9/35.2 → 1.9/0.5 — [arXiv 2507.16438](https://arxiv.org/html/2507.16438v1)
- [V] Shortcuts: explicit IPs and implicit flow IDs (TCP seq/ack numbers, TCP timestamps). Randomising seq/ack+timestamps at test time dropped ET-BERT F1 from 96.8 to 15.4; **randomly initialised ET-BERT scored 96.4 F1, on par with pretrained** — [arXiv 2507.16438](https://arxiv.org/html/2507.16438v1)
- [V] Shallow baselines (macro-F1, header features, per-flow): VPN-app RF 81.1 / XGBoost 82.1 / LightGBM 82.6; TLS-120 RF 78.0 / XGB 82.0 / LGBM 82.4 — matching or beating the authors' own Pcap-Encoder (71.0 / 63.7 frozen). RF trains+validates in ~22 s; representation models need 2x-500x more training time; netFound up to ~2048x slower at inference. netFound flow-level unfrozen reached 89.7 F1 on TLS-120 (best deep result) — [arXiv 2507.16438](https://arxiv.org/html/2507.16438v1)
- [V] Their recommendations: per-flow splits, freeze the encoder to test the representation, always compare to simple baselines, report macro-F1, audit for leakage — [arXiv 2507.16438](https://arxiv.org/html/2507.16438v1)
- [S] Corroborating: "SoK: Decoding the Enigma of Encrypted Network Traffic Classifiers" — [arXiv 2503.20093](https://arxiv.org/pdf/2503.20093); "Bias in the Shadows" (BiasSeeker, 2026) on dataset-specific shortcut features — [arXiv 2601.10180](https://arxiv.org/pdf/2601.10180v1); newer papers (FlowCLIP, Traffic-CBM, 2026) adopt time-based / leakage-controlled splits — [arXiv 2606.17746](https://arxiv.org/html/2606.17746), [arXiv 2606.29909](https://arxiv.org/pdf/2606.29909)
- [R] ET-BERT original (WWW 2022) code/weights — [arXiv 2202.06335](https://arxiv.org/abs/2202.06335), [GitHub](https://github.com/linwhitehat/ET-BERT)
- [S] Apruzzese, Laskov, Schneider, "SoK: Pragmatic Assessment of ML for NID" (EuroS&P 2023): hundreds of configurations, four hardware platforms, practitioner user study; concludes the state of research "hardly allows one to estimate the value of ML for NID" — [arXiv 2305.00550](https://arxiv.org/abs/2305.00550)
- [S] Flood, Engelen, Aspinall et al., "Bad Design Smells in Benchmark NIDS Datasets" (EuroS&P 2024): seven popular datasets, six "design smells" correlated with poor diversity, murky labelling, ill-defined generalisation — [IEEE Xplore 10629000](https://ieeexplore.ieee.org/document/10629000)
- [S] Liu, Engelen, Lynar, Essam, Joosen, "Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018" (IEEE CNS 2022): undocumented errors in attack orchestration, feature generation, documentation and labelling; released fully recreated datasets with reverse-engineered, corrected labelling logic — [abstract](https://archive.cps-vo.org/node/97449), [code](https://www.github.com/GintsEngelen/CNS2022_Code); corrected-data site [R]: [intrusion-detection.distrinet-research.be/CNS2022](https://intrusion-detection.distrinet-research.be/CNS2022/)
- [S] E-GraphSAGE (Lo et al., NOMS 2022): edge-classification GraphSAGE on flow graphs; reports 96.8% binary / 86.2% multiclass accuracy on UNSW-NB15-type data and claims SOTA — [arXiv 2103.16329](https://arxiv.org/abs/2103.16329). No published head-to-head critique vs tuned GBT was found this session.
- [S] UQ NetFlow datasets (Sarhan, Layeghy, Portmann): UNSW-NB15, BoT-IoT, ToN-IoT, CSE-CIC-IDS2018 converted to a common NetFlow feature set; **v3 has 53 extended NetFlow features incl. temporal fields**; NF-ToN-IoT-v3 = 27,520,260 flows, 38.98% attack — [UQ dataset page](https://staff.itee.uq.edu.au/marius/NIDS_datasets/), [NF-UNSW-NB15-v3 record](https://researchdata.edu.au/nf-unsw-nb15-v3/3485172), [NF-ToN-IoT-v3 record](https://researchdata.edu.au/nf-ton-iot-v3/3485175), [v1 paper arXiv 2011.09144](https://arxiv.org/abs/2011.09144); same group shows poor cross-dataset generalisation of ML NIDS — [arXiv 2205.04112](https://arxiv.org/pdf/2205.04112)
- [S] CICIoT2023: 33 attacks, 105 IoT devices (UNB CIC); critiques (mostly lightly reviewed) cite severe class imbalance, label/feature-definition mismatch, leakage risk, synthetic artefacts — [arXiv 2604.11324](https://arxiv.org/pdf/2604.11324), [IFIP WMNC 2025](https://dl.ifip.org/db/conf/wmnc/wmnc2025/1571185543.pdf); dataset home [R]: [unb.ca/cic/datasets/iotdataset-2023.html](https://www.unb.ca/cic/datasets/iotdataset-2023.html)

### Inferences
- **Is a flow classifier useful on a honeypot?** Not as an IDS (no benign class; base rate of hostile ≈ 100%, apart from research scanners/backscatter). Useful sub-tasks: (a) attack-type/tool tagging of flows hitting non-emulated ports (scan vs brute-force vs exploit vs DoS-reflection probe), (b) scanner-tool fingerprinting (ZMap/Masscan/Nmap header quirks, JA4T) — mostly rules, (c) per-source behavioural features feeding session classification and campaign graph. Suricata with ET Open rules already labels known exploits better than any ML model trained on CIC data.
- **Baseline:** Zeek conn/ssh/http/ssl logs + Suricata alerts → per-flow and per-source aggregates → LightGBM. Train on *your own* traffic with labels from Suricata signatures/port/protocol heuristics; public NIDS datasets are lab testbeds from 2015-2018 with different address space and benign mix, so models trained there do not transfer (UQ generalisability paper).
- **Benchmarks are saturated and inflated:** on CIC-IDS2017/2018 and the NF-* sets, RF/XGBoost reach ~99% F1 with random splits [R, widely reported incl. in the UQ papers]; that makes them poor discriminators between models, and a GNN reporting +0.5 pt is noise. E-GraphSAGE's graphs are built from IP:port endpoints inside one testbed capture, so train/test share topology (my assessment; transductive leakage risk), and its edge is not demonstrated against tuned GBT under temporal splits.
- **If you must use public data** (e.g. to sanity-check a pipeline): prefer the Engelen/Liu corrected CIC-IDS2017/CSE-CIC-IDS2018 and NF-*-v3 (temporal features allow time-based splits); drop IPs, ports-as-identity, timestamps and flow IDs; split by time or by attacker host; report macro-F1 per class.
- **Stronger model later:** only if you add encrypted C2/tunnel detection on outbound traffic from high-interaction decoys — then flow-level statistical features + GBT still first; netFound-style flow-level models are the only deep option with any evidence under proper splits and need a cloud GPU.

### Gaps
- Licences of NF-*-v3, corrected CIC-IDS, and CICIoT2023 were **not confirmed** — the search surfaced no licence text. From recollection, UNB CIC datasets are distributed with a "cite the paper" condition and no standard open licence, and the UQ sets were historically marked non-commercial/research with attribution; verify on the download pages before any commercial use.
- Engelen et al. 2021 ("Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study", IEEE S&P WTMC) recalled but not opened; no URL verified.
- No verified numeric GBT-vs-E-GraphSAGE comparison on identical splits; no published flow-classification study on honeypot traffic found.

---

## 4. Anomaly detection on sessions / session embeddings at small data scale

### Takeaway
At small scale, use classical detectors on engineered + embedded session vectors (Isolation Forest / kNN-distance / HDBSCAN noise) plus a simple "never-seen fingerprint" novelty counter; the log-anomaly literature shows deep sequence models (DeepLog, LogBERT-class) are not reliably better than simple baselines and are fragile to evaluation choices.

### Cited Findings
- [S] Le & Zhang, "Log-based Anomaly Detection with Deep Learning: How Far Are We?" (ICSE 2022): five deep models re-evaluated across training-data selection, class distribution, early detection etc.; "all the studied models do not always work well"; problem "not solved" — [arXiv 2202.04301](https://arxiv.org/abs/2202.04301), [code](https://github.com/logintelligence/logadempirical)
- [S] Yu et al., "Deep Learning or Classical Machine Learning? An Empirical Study on Log-Based Anomaly Detection" (ICSE 2024): simple algorithms (kNN, single-layer NN) **outperform DL methods in both accuracy and time** on five public datasets; attributes this to dataset simplicity and redundant preprocessing — [ICSE 2024 page](https://conf.researchr.org/details/icse-2024/icse-2024-research-track/21/Deep-Learning-or-Classical-Machine-Learning-An-Empirical-Study-on-Log-Based-Anomaly-)
- [S] Systematic comparison of supervised/semi-supervised traditional vs deep log AD (accuracy, time, hyper-parameter sensitivity) — [arXiv 2307.16714](https://arxiv.org/pdf/2307.16714v2.pdf)
- [S] LogBERT's own paper claims highest F1 on three datasets by large margins (authors' baselines) — [arXiv 2103.04475](https://arxiv.org/pdf/2103.04475)
- [V] LogPrécis-style fingerprints reduce ~400k sessions to <3k tactic sequences — a natural basis for frequency-based novelty — [arXiv 2307.08309v3](https://arxiv.org/html/2307.08309v3)
- [S] Topic-model clustering of sessions explicitly used for outlier discovery — [arXiv 2301.02505](https://arxiv.org/abs/2301.02505)
- [R] ADBench (NeurIPS 2022, 30 algorithms x 57 datasets): no unsupervised detector is statistically better than the rest; a handful of labels (semi-supervised) beats all unsupervised methods — [arXiv 2206.09426](https://arxiv.org/abs/2206.09426); library: PyOD [GitHub](https://github.com/yzhao062/pyod); Deep SVDD reference code [GitHub](https://github.com/lukasruff/Deep-SVDD-PyTorch)

### Inferences
- **Baseline:** (1) novelty by counting — first-seen normalised command, first-seen command-sequence hash / tactic fingerprint, first-seen (HASSH, credential, payload-hash) tuple; (2) Isolation Forest (or ECOD/kNN from PyOD) on the tabular session features from section 2 concatenated with a 32-64-d SVD of TF-IDF command n-grams; (3) HDBSCAN noise points as a second opinion. All run in seconds on the M4.
- In a honeypot "anomalous" should mean "unlike the botnet mass" — precisely the rare human/novel-tool sessions you want to escalate. Evaluate by precision@k on analyst-reviewed top-k per day, not AUROC on a synthetic split.
- **Stronger model:** after ≥50-100k sessions, a small autoencoder or a masked-command model (fine-tune SecureShellBert with MLM on your sessions; anomaly = mean token surprisal / next-command perplexity) adds order-sensitivity that bag-of-commands misses. Deep SVDD is prone to hypersphere collapse and tuning pain [R]; it rarely beats IF/kNN on embeddings and is not worth it for this team. DeepLog/LogBERT assume a closed log-template vocabulary; attacker shell input is open-vocabulary, so they need heavy normalisation and are a poor fit.
- Add ~50-200 analyst labels and switch to semi-supervised/GBT ranking as soon as possible (ADBench lesson).
- Pitfalls: concept drift (a new botnet wave is "anomalous" for a day then dominant — use time-decayed frequency); duplicated sessions dominate density estimates (dedupe by fingerprint before fitting); embeddings from a pretrained encoder cluster by surface syntax (IPs/URLs/filenames) unless you mask those tokens.

### Gaps
- No published evaluation of anomaly detectors on honeypot session embeddings with ground truth found; guidance above is transferred from log-AD and tabular-AD literature.
- ADBench and Deep SVDD claims are recollection, not re-opened.

---

## 5. Detecting LLM-driven attack agents vs humans vs scripted bots

### Takeaway
The only published in-the-wild method is Palisade's Cowrie-based honeypot: prompt-injection canaries in banner / command output / files plus a response-latency test (~1.5-1.7 s agent range); it found only 8 "potential" agents in 8.13M interactions, and the method is admittedly preliminary, evadable, and has no ground-truth validation. No 2025-2026 peer-reviewed follow-up with a validated behavioural fingerprint for SSH was found; 2026 industry reports confirm autonomous agents are being run in the wild, mainly against exposed AI services.

### Cited Findings
- [V] Design: customised Cowrie with deliberately vulnerable SSH version and altered default users/outputs; prompt injections in (a) SSH banner, (b) outputs of common commands such as `uname`, (c) readable system files. Injection types: classic "ignore previous instructions and do X", "Important message" goal hijack (e.g. "return the colour of …"), then **prompt stealing** (ask for the system prompt) only after a goal hijack succeeds — [arXiv 2410.13919v2](https://arxiv.org/html/2410.13919v2)
- [V] Logic: scripted bots cannot answer natural-language challenges; humans can but slowly. "Potential AI agent" = complied with injection; "confirmed" = also passed timing. Calibration: authors' own GPT-4o-based agents averaged ~1.7 s per response including to injections; most wild bot interactions were also <1.7 s; humans need several seconds; in the slow case, gaps often exceeded 10 s (likely human). Authors call the timing analysis preliminary and mainly a false-positive reducer — [arXiv 2410.13919v2](https://arxiv.org/html/2410.13919v2). Note: a search snippet of the same paper quotes "within 1.5 seconds" — threshold wording differs between versions/sections; treat as 1.5-1.7 s.
- [V] Scale: 8,130,731 interaction attempts over ~3 months, **8 potential AI agents**; 10 IPs in several countries, DNS names with sensitive-looking domains, indexed on Shodan/Censys. v1 17 Oct 2024, v2 10 Feb 2025. No code repo linked; live dashboard at [ai-honeypot.palisaderesearch.org](https://ai-honeypot.palisaderesearch.org/) — [arXiv abs](https://arxiv.org/abs/2410.13919), [v2 HTML](https://arxiv.org/html/2410.13919v2)
- [S] Earlier LessWrong write-up of the same project: 7,584,034 attempts, 7 potential + 1 "confirmed" agent, and the authors themselves say the single confirmed case may have been a human who happened to comply — [LessWrong](https://www.lesswrong.com/posts/mmXx7KWviAtT3FixP/hunting-for-ai-hackers-llm-agent-honeypot). (Counts differ from the arXiv v2 figures — different snapshot dates.)
- [V] Stated limitations: narrow slice of internet traffic, SSH only, targets fully autonomous agents not AI-assisted humans, false positives and evasion not yet addressed — [arXiv 2410.13919v2](https://arxiv.org/html/2410.13919v2)
- [S] 2026 industry evidence: Symantec honeypot imitating an exposed AI service captured an autonomous agent's full instruction set (summer 2026; >127,000 requests logged) — [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/symantec-ai-agent-llmjacking/); Zenity reports actors hijacking exposed AI endpoints to run offensive agents (e.g. Strix) against third-party targets — [Zenity blog](https://zenity.io/blog/real-world-ai-infrastructure-attacks-honeypots). Vendor reports, not peer-reviewed.
- [S] SoK on honeypots and LLMs (2025) surveys LLM-honeypot work incl. detection of AI agents — [arXiv 2510.25939](https://arxiv.org/pdf/2510.25939)

### Inferences
- **Baseline (build first):** replicate Palisade as a *scored signal ensemble*, not a binary rule:
  1. Canary instructions at several depths: banner/MOTD, `uname`/`id`/`ls` output, a tempting file (`notes.txt`, `.bash_history`, README in a "backup" dir), HTTP response comments/headers for web decoys. Use *unique, harmless, verifiable* actions (run `echo <nonce>`; `cat /opt/.<nonce>`; fetch a per-session canary URL/DNS name) so compliance is unambiguous and attributable; rotate wording so agents' guardrails/blocklists don't learn it.
  2. Timing: latency from output-flush to next input vs **output length** (LLM latency grows with tokens read/generated; humans scale with reading time; scripts are constant and often do not wait for output at all). Whole-line paste with zero intra-line keystroke gaps + 1-30 s think-time between commands is the typical agent signature; humans show keystroke jitter, backspaces, tab completion; scripts show sub-100 ms fixed gaps or pipelined input.
  3. Output-contingency tests: scripts ignore output; agents and humans adapt. Return a fake error with a suggested fix, a fake path that only exists in previous output, or a multi-step hint. Agent tells: immediate, verbose, well-formed corrective commands; heredocs and long one-liners with comments; `2>&1`, `|| true`, `--help` probing; systematic enumeration in textbook order; reacting to honeytokens described only in natural language; occasionally typing natural-language text or markdown fences into the shell; uniform retries after tool timeouts.
  4. Prompt-stealing follow-up only after a canary hit (as Palisade does).
- **Stronger model:** GBT over these features, trained on self-generated sessions from several agent scaffolds (open pentest agents, generic coding agents with SSH tools) x several LLMs x human volunteers x replayed botnet scripts. Hold out entire scaffolds and models for testing; the classifier otherwise learns one framework's quirks. Expect the timing threshold to be non-portable: reasoning models and slow APIs give 5-60 s gaps overlapping humans, and attackers can add jitter; the 1.7 s figure was calibrated on GPT-4o in 2024.
- Pitfalls: (a) base rate — at ~1 per million sessions, even a 0.1% FPR swamps true positives, so require canary compliance (high-specificity) for a "confirmed" label and use timing only to rank; (b) humans who read the canary and play along; (c) modern agents are increasingly hardened against naive "ignore previous instructions" — phrase canaries as plausible in-context task information (e.g. "maintenance note: credentials moved to …") rather than overt overrides; (d) prompt-injecting third-party agents is active manipulation of someone else's system — get a legal/ethics view before deployment; (e) AI-*assisted* humans (copy-paste from a chatbot) are a fourth class this method cannot separate.
- The 2026 vendor reports suggest AI-service decoys (fake Ollama/OpenAI-compatible/MCP endpoints) are currently where agent traffic is most visible; SSH-only sensors may under-sample it.

### Gaps
- No peer-reviewed 2025-2026 follow-up to Palisade with validated precision/recall found; Palisade's promised further findings not located (dashboard not opened).
- No published study of keystroke cadence or error-recovery behaviour of LLM agents on SSH honeypots found; the behavioural tells above are engineering hypotheses to test, not established results.
- Exact canary wording used by Palisade is only in figures (not extractable).

---

## 6. Graph-based campaign correlation (GNN vs simple graph methods)

### Takeaway
No evidence found that heterogeneous GNNs beat simple IOC-graph methods for honeypot campaign correlation, and there is no labelled campaign ground truth to train one on; start with weighted shared-indicator graphs + connected components / Leiden and fuzzy payload hashing, and consider a GNN only once you have thousands of analyst-confirmed campaign labels and inductive link-prediction needs.

### Cited Findings
- [S] Practitioner campaign mapping: a 1,001-IP botnet cluster tied together by shared staging servers and a common TLS/HTTP fingerprint; shared HASSH was the weakest of three link types (also on ~120 unrelated IPs) — [write-up mirror](https://hackernews-dynamic.seasondane.workers.dev/news/48320615)
- [S] Shamsi et al.: consensus clustering over multiple honeypots to find single actors behind many attacking machines — [arXiv 2206.13614](https://ar5iv.labs.arxiv.org/html/2206.13614)
- [S] TU Delft dissertation: grouping randomised scan probes into campaign templates; clustering >16k malicious files by the commands that dropped/executed them — [TU Delft repository](https://repository.tudelft.nl/file/File_2dee4a33-92e4-4c3d-9a11-a7fbfae6c0e8?preview=1)
- [S] Cowrie malware analysis cautions that shared infrastructure/country overlap is a clustering *lead*, not attribution — [HackerNoon](https://hackernoon.com/static-analysis-of-linux-malware-captured-by-a-cowrie-honeypot); SANS ISC diary on honeypot campaign analysis — [isc.sans.edu/diary/33086](https://isc.sans.edu/diary/33086)
- [V] LogPrécis tactic fingerprints group sessions with identical tactic sequences (≈3k fingerprints over ~400k scripts) — usable as a behavioural edge type — [arXiv 2307.08309v3](https://arxiv.org/html/2307.08309v3)
- [S] E-GraphSAGE is the usual GNN reference in security but is a flow classifier, not a campaign-correlation method — [arXiv 2103.16329](https://arxiv.org/abs/2103.16329)
- [R] Tools: Leiden algorithm (fixes Louvain's badly-connected communities) [arXiv 1810.08473](https://arxiv.org/abs/1810.08473), [leidenalg](https://github.com/vtraag/leidenalg), [python-igraph](https://github.com/igraph/python-igraph), [NetworkX](https://github.com/networkx/networkx); TLSH fuzzy hash (Apache-2.0) [GitHub](https://github.com/trendmicro/tlsh); MinHash/LSH [datasketch](https://github.com/ekzhu/datasketch); [PyTorch Geometric](https://github.com/pyg-team/pytorch_geometric) (HeteroData, HGT/R-GCN); graph stores: [Neo4j](https://github.com/neo4j/neo4j) (Community GPLv3), [Memgraph](https://github.com/memgraph/memgraph) (BSL), [Kuzu](https://github.com/kuzudb/kuzu) (embedded, MIT — I recall the repo was archived in Oct 2025 after the company was acquired; check for a maintained fork before adopting)

### Inferences
- **Baseline:** bipartite/hetero graph session—indicator, with indicator types weighted by specificity: payload SHA-256 (strong), download URL/host and C2 IP (strong), SSH public key added to `authorized_keys` (very strong), normalised command-sequence hash (medium-strong), TLSH distance ≤ threshold between payloads or MinHash-Jaccard between command shingles (medium), credential pair (weak unless rare), HASSH/JA4/client version (weak), ASN//24 (weak). Down-weight by inverse document frequency (an indicator touching 5% of all sessions carries no information), drop super-nodes, project to session-session, then connected components on strong edges and Leiden on the weighted graph. Add temporal windows so campaigns can split/merge over time. igraph/NetworkX handle 10^6-10^7 edges on a 16 GB laptop; a graph DB is for *querying/visualising*, not required for the clustering.
- **When a GNN is justified:** (i) you have ≥ thousands of labelled campaign memberships or reliable weak labels; (ii) you need inductive scoring of new nodes with rich node features (payload embeddings, session embeddings) where exact-match IOCs are deliberately randomised; (iii) simple methods demonstrably over-merge/under-merge on a held-out labelled set. Even then, try node2vec/metapath2vec or GraphSAGE embeddings + HDBSCAN before a heterogeneous transformer. A hetero-GNN trained self-supervised (link prediction) will mostly re-learn the shared-IOC structure you already have.
- Evaluation without ground truth: seed with known families (Mirai variants, known cryptominer kits via payload AV labels/YARA), measure cluster purity/ARI on those, plus analyst spot checks; track over-merge caused by hub indicators (public pastebins, common busybox loaders, `root/admin`).
- Storage choice for this team: start with SQLite/DuckDB/Postgres edge tables + igraph; add Neo4j or Memgraph when analysts need Cypher exploration.

### Gaps
- No peer-reviewed comparison of heterogeneous GNNs vs Louvain/Leiden/connected-components for honeypot campaign correlation found; no public labelled campaign dataset found.
- No source found using TLSH + community detection specifically on SSH honeypot payloads (pieces exist separately).
- Kuzu project status is recollection only.

---

## 7. Next-command / next-technique prediction on attacker sessions

### Takeaway
Published results exist but are weak evidence: high reported accuracies (94-99%) come from frequency/Markov models on bot-dominated Cowrie data where the next command is nearly deterministic; no transformer benchmark or proper de-duplicated evaluation was found. An n-gram/Markov model is the right baseline and a hard one to beat.

### Cited Findings
- [S] Sadique & Sengupta: Cowrie deployments; command-chain *frequency* model predicts next attacker command with 94-99% accuracy — [NSF PAR 10295059](https://par.nsf.gov/servlets/purl/10295059)
- [S] LSTM on Cowrie logs predicting attacker moves, 98% accuracy after tuning (low-tier journal; evaluation setup unclear) — [J. Network & Information Security](https://publishingindia.com/archive/jnis/ai-enabled-honeypot)
- [S] Cowrie attack-traffic modelling: factorial HMM gives accuracy comparable to deep RNNs at much lower training time — [arXiv 1905.11824](https://arxiv.org/pdf/1905.11824); general attacker-prediction comparison: LSTM beats HMM only with sufficient data — [arXiv 2402.13081](https://arxiv.org/pdf/2402.13081v2)
- [S] GPT-2C: GPT-2 fine-tuned to *parse* Cowrie logs (89% inference accuracy) — parsing, not prediction — [arXiv 2109.06595](https://ar5iv.labs.arxiv.org/html/2109.06595)
- [S] A US patent describes an LSTM attack-technique predictor with ~90% top-5 accuracy (not Cowrie) — [USPTO 12495054](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12495054)
- [V] Why numbers are inflated: honeypot sessions are massively duplicated (≈400k scripts → <3k fingerprints) — [arXiv 2307.08309v3](https://arxiv.org/html/2307.08309v3)

### Inferences
- With random session splits, the test set consists of scripts already seen in training; "98%" measures memorisation of botnet scripts. Evaluate on (a) de-duplicated sessions, (b) temporal split, (c) only interactive/human-labelled sessions, and report top-1/top-5 against a "most frequent next command" and bigram baseline.
- **Baseline:** order-2/3 Markov with back-off over normalised commands (or over tactic/technique labels — far smaller vocabulary, more useful for an adaptive honeypot deciding what to emulate next). **Stronger:** causal LM fine-tuned on sessions (small GPT-2/CodeGPT-size or SecureShellBert-initialised decoder), or simply ask an LLM for likely next techniques given the tagged session. For adaptive deception, predicting the next *technique class* (e.g. "will download payload", "will attempt persistence") is both easier and more actionable than exact command strings.

### Gaps
- No peer-reviewed transformer next-command/next-technique benchmark on honeypot sessions with de-duplicated evaluation found; cited accuracy figures are from snippets and setups were not inspected.

---

## 8. What runs on Apple Silicon (M4, 16 GB) — PyTorch MPS / MLX

### Takeaway
Everything recommended as a baseline (rules, TF-IDF + linear models, LightGBM/XGBoost, Isolation Forest/PyOD, HDBSCAN, igraph/Leiden, TLSH/MinHash) is CPU-only and trivial on an M4; fine-tuning 110-150M-parameter encoders (CodeBERT, SecureShellBert, SecureBERT 2.0, CmdCaliper) is feasible on MPS; only traffic foundation models, large-scale GNN training and LLM fine-tuning need the cloud GPU.

### Cited Findings
- [V] LogPrécis-class training budget: CodeBERT (≈130M params) domain adaptation ~50 min + fine-tune 10-20 min on one 16 GB V100 — [arXiv 2307.08309v3](https://arxiv.org/html/2307.08309v3)
- [V] RF on traffic header features trains+validates in ~22 s; pretrained traffic models cost 2x-500x more training time and up to ~2048x slower inference — [arXiv 2507.16438](https://arxiv.org/html/2507.16438v1)
- [S] SecureBERT 2.0 is ModernBERT-base-sized, Apache-2.0 — [HF](https://huggingface.co/cisco-ai/SecureBERT2.0-base); CmdCaliper has small/base/large variants — [arXiv 2411.01176](https://arxiv.org/abs/2411.01176)
- [R] PyTorch MPS backend supports training of standard transformer encoders on Apple GPUs, with some unsupported ops falling back to CPU via `PYTORCH_ENABLE_MPS_FALLBACK=1` — [PyTorch MPS notes](https://pytorch.org/docs/stable/notes/mps.html); MLX / mlx-lm run and LoRA-fine-tune quantised LLMs on unified memory — [MLX](https://github.com/ml-explore/mlx), [mlx-lm](https://github.com/ml-explore/mlx-lm)

### Inferences
(Engineering estimates from parameter counts and the cited V100 timings; not benchmarked.)

| Component | M4 16 GB | Notes |
|---|---|---|
| Rules, TF-IDF + LR/SVM, LightGBM/XGBoost, PyOD, HDBSCAN | Yes, CPU, seconds-minutes | Native arm64 wheels |
| LogPrécis / SecureShellBert inference | Yes (MPS or CPU) | ~125M params; hundreds of sessions/s batched is plausible |
| Fine-tune CodeBERT / SecureBERT 2.0 / CmdCaliper-base (token or sequence classification) | Yes on MPS | Batch 8-16, max_len 256-512, fp32; expect roughly 2-5x slower than the V100 timings → ~1-3 h for LogPrécis-scale jobs. Use cloud GPU for sweeps (LogPrécis explored 81 configs) |
| Embedding retrieval (bi-encoder + FAISS/numpy) over ATT&CK + Atomic | Yes | Few thousand docs; trivial |
| Local LLM re-ranker (7-8B, 4-bit, MLX/Ollama) | Yes, ~5-6 GB RAM | Slow for bulk; cache per unique command. 14B 4-bit is borderline alongside other workloads; larger → API/cloud |
| LoRA fine-tune of 7-8B LLM | Marginal on 16 GB; do on cloud GPU | |
| igraph/Leiden, NetworkX on 10^6-10^7 edges | Yes | NetworkX is memory-hungry; prefer igraph |
| PyTorch Geometric GNNs | Small graphs on CPU; MPS support for sparse/scatter ops is incomplete [R] | Train on cloud GPU if ever needed |
| ET-BERT / YaTC / NetMamba / netFound pretraining or fine-tuning | Not recommended anywhere (see §3); needs cloud GPU | |
| Deep SVDD / small autoencoders / small causal LM on sessions | Yes on MPS | Small models |

- MPS pitfalls [R]: no fp16 autocast parity with CUDA for all ops, occasional op fallbacks, unified memory shared with the OS (keep batch sizes modest; watch swap); bitsandbytes quantisation is CUDA-only — use MLX or GGUF for quantised LLMs.

### Gaps
- No measured MPS benchmarks for these specific models were found or run; the table is an estimate. PyG-on-MPS status and MPS/MLX capability statements are recollection — re-check current docs.

---

## Cross-cutting summary for the report writer (inferences)

| Task | Build first | Build later | Realistic numbers | Biggest trap |
|---|---|---|---|---|
| (a) Session classification | Rules + LightGBM on timing/keystroke/novelty features | + session embeddings; sequence model after ≥10^4 labelled interactive sessions | No public benchmark | Labels from your own lab → learns lab artefacts |
| (a) Flow classification | Zeek/Suricata + rules; LightGBM for attack-type tags | Flow-level model for outbound/C2 only if needed | GBT ≈ 80% macro-F1 on hard encrypted-traffic tasks under per-flow split; ET-BERT 21.5% | Per-packet split leakage; lab datasets that do not transfer; no benign class on a honeypot |
| (b) ATT&CK tagging | LogPrécis (tactics) + regex rules (techniques) | Retrieval (CmdCaliper/SecureBERT 2.0 + Atomic Red Team) + LLM re-rank; fine-tuned encoder on emulation data | Tactic token acc 0.91 but session fidelity 0.67; CTI technique macro-F1 0.44-0.66 honest vs 0.92-0.97 claimed; GPT-4 72% | Templated emulation data leaking across splits; subjective labels |
| (c) Anomaly detection | First-seen counters + Isolation Forest/kNN on features+TF-IDF SVD | MLM-surprisal from SecureShellBert; semi-supervised ranking | Simple ≥ deep in log-AD studies | Duplicates and drift; AUROC on synthetic splits |
| (d) LLM-agent detection | Canary injections + latency-vs-output-length + contingency tests, scored | GBT over behavioural features trained on multi-scaffold emulation | Palisade: 8 potential agents / 8.13M; no validated precision/recall | Base rate; non-portable timing thresholds; legal/ethics of injecting |
| (e) Campaign correlation | IDF-weighted IOC graph → components + Leiden; TLSH/MinHash edges | node2vec/GraphSAGE embeddings + HDBSCAN; hetero-GNN only with labels | No benchmark | Hub indicators over-merging; treating HASSH as identity |
