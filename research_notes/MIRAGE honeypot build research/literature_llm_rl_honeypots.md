# Academic literature on LLM-based honeypots, adaptive/RL honeypots and honeypot fingerprinting (state as of 11 Nov 2026)

Method note for the report writer. Evidence grades used below:
- **[P]** = I read the primary paper text (PDF text extracted locally) and the number/claim is in it.
- **[A]** = taken from the paper's abstract / landing page / repository README only.
- **[S]** = secondary: reported by another paper (usually the SoK, arXiv 2510.25939v4) or by a search-result snippet; not checked against the primary full text.
Anything not marked was not verified and is listed under Gaps instead.

---

## 1. LLM honeypots: what each system contributes; state consistency; latency/cost/believability; fine-tuned small models

### Takeaway
The field converged between 2023 and 2026 on a hybrid design: deterministic responder/Cowrie for scanners and simple commands, an LLM only for novel commands, plus an explicit out-of-prompt system-state store and a pruned session history. Measured gains are real but modest (e.g. 2.96 -> 5.83 commands/session; 30% of 89 humans fooled; ~$0.80/hour with GPT-3.5), and small local models need fine-tuning or a strong deterministic layer to be usable.

### Cited Findings

**shelLM — Sladić, Valeros, Catania, Garcia, "LLM in the Shell: Generative Honeypots", IEEE EuroS&PW 2024, arXiv 2309.00155**
- Built: SSH Linux shell simulated entirely by GPT-3.5-turbo-16k at temperature 0, using a "personality prompt" combining few-shot examples, chain-of-thought and repeated instructions [P] — [arXiv 2309.00155](https://arxiv.org/pdf/2309.00155)
- State handling: the initial prompt plus the whole history is kept in context; when the 16k-token context fills, the history is deleted and the personality prompt restored (authors call this a known weakness to fix) [P] — [arXiv 2309.00155](https://arxiv.org/pdf/2309.00155)
- Evaluation: 12 human participants (told in advance it was a honeypot), 226 commands, 76 unique; overall accuracy 0.9204, TNR 0.90, FNR 0.0232; breakdown of the 226 commands: 167 (74%) credible and judged credible, 41 (18%) correctly flagged as wrong, 17 (7.5%) false positives, 1 (0.5%) false negative [P] — [arXiv 2309.00155](https://arxiv.org/pdf/2309.00155)
- Cost: ~$0.70 for one full 16k-token session ($0.658 input, $0.042 output); ~$0.40 per 30 min of active use (~$0.80/hour); whole experiment cost $5.29 [P] — [arXiv 2309.00155](https://arxiv.org/pdf/2309.00155)
- Code: paper links https://anonymous.4open.science/r/shelLM [P]; the maintained successor repo is stratosphereips/VelLMes-AI-Deception-Framework (GPL-2.0; contains YAML config files with the personality prompts, a "Fine-Tuning Dataset" folder, "Unit Tests for LLMs", a human-evaluation folder and an Attacker LLM) [A] — [GitHub](https://github.com/stratosphereips/VelLMes-AI-Deception-Framework)
- The SoK credits shelLM with releasing the "Prague Dataset, a small dataset of real shell sessions" [S] — [SoK 2510.25939](https://arxiv.org/pdf/2510.25939)
- Lesson: whole-history-in-context is the simplest baseline and the most expensive one (input tokens are 94% of cost); temperature 0 plus few-shot prompt is the reusable starting prompt.

**VelLMes — Sladić, Valeros, Catania, Garcia, "VelLMes: A high-interaction AI-based deception framework", EuroS&PW 2025 (Active Defense and Deception Workshop), arXiv 2510.06975**
- Built: extends shelLM to SSH, MySQL, POP3 and HTTP; protocol is identified and a protocol-specific CoT prompt plus history is sent to the LLM [A][S] — [arXiv 2510.06975](https://arxiv.org/abs/2510.06975); [SoK](https://arxiv.org/pdf/2510.25939)
- Results: some models reach 100% pass rate on unit tests; in a human study with 89 attackers about 30% believed the SSH honeypot was a real system; 10 SSH instances deployed on the Internet answered most commands correctly [A] — [arXiv 2510.06975](https://arxiv.org/abs/2510.06975)
- HydraPoT's related-work section says VelLMes also fine-tunes Llama 3 8B on Cowrie traces [S] — [HydraPoT 2610.27722](https://arxiv.org/html/2610.27722v1)
- Lesson: "unit tests for LLM shells" (a term the SoK attributes to this group) are a reusable, cheap regression harness; a 30% deception rate against informed-ish humans is the realistic bar.

**AdvancedShelLM — Sladić, Alibalić, Valeros, Catania, Garcia, "AdvancedShelLM: A Stateful Multi-Agent LLM Honeypot for SSH Deception", arXiv 2606.27990 (26 Jun 2026)** (newer than the SoK; listed here because it is the direct shelLM successor)
- Architecture: Worker LLM drafts output; Manager LLM in a separate context (real UTC time, worker prompt, last 6 turns, 19 bash-correctness rules) answers APPROVED or REPROMPT and emits filesystem patches (ADD/REMOVE); up to 3 worker attempts; rejected drafts never enter history; filesystem kept as JSON outside the conversation and persisted across sessions so returning attackers see their changes; `.bash_history` synced both ways [A-html] — [arXiv 2606.27990](https://arxiv.org/html/2606.27990v1)
- Models: gpt-oss-120B (local) and gpt-5.1 (cloud) in four Worker/Manager combinations, temperature 0 — [arXiv 2606.27990](https://arxiv.org/html/2606.27990v1)
- Results: 34 unit tests: 98.04% (single-session) vs 78.43% for shelLM; 99.02% (fresh-session) vs 83.33%. Human blind study, 26 participants: Cowrie called a honeypot 100% of the time, real Ubuntu 70%, AdvancedShelLM 71.4%. AI attacker (ARACNE, 30 runs/target/goal, 20-command cap): adjusted honeypot-classification 0.45 for AdvancedShelLM vs 0.47-0.53 Cowrie vs 0.40-0.45 real Ubuntu. 14-day deployment on 11 DigitalOcean servers: 148,850 sessions of which only 150 interactive, 1,720 source IPs, 7,247 unique commands — [arXiv 2606.27990](https://arxiv.org/html/2606.27990v1)
- Limitations stated: latency, uniform timing noticed by humans, occasional reasoning leaking into output; deception did not improve in proportion to unit-test gains — [arXiv 2606.27990](https://arxiv.org/html/2606.27990v1)
- Code: https://anonymous.4open.science/r/AdvancedShelLM-946B/README.md — [arXiv 2606.27990](https://arxiv.org/html/2606.27990v1)
- Lesson: generate-then-verify with state stored outside the prompt is currently the best-measured consistency design; note it multiplies LLM calls per command.

**HoneyGPT — Wang, You, Wang, Yuan, Lv, Wang, Sun, "HoneyGPT: Breaking the Trilemma in (Terminal) Honeypots with Large Language Model(s)", arXiv 2406.01882 (v2 15 Feb 2025)**
- Architecture: Terminal Protocol Proxy + Prompt Manager. Each LLM call returns three things: terminal output A_i, system-state changes C_i, and an impact factor F_i (0 = read file/show info, 1 = create file/install tool, 2 = modify files/cd/change shell, 3 = start/stop service, download, privilege escalation, 4 = impact services, delete files, password change). (Q_i, A_i) is appended to history H_i and C_i to a System State Register SR_i [P] — [arXiv 2406.01882](https://arxiv.org/pdf/2406.01882)
- Memory pruning: every turn multiply all stored impact factors by a Weaken Factor w (time decay); when the prompt nears the context limit, drop the history entry with the smallest decayed F. The state register is never pruned. Constraint given for w: F_{i+3}·w^3 > F_i [P] — [arXiv 2406.01882](https://arxiv.org/pdf/2406.01882)
- Baseline replay data: two Cowrie-captured corpora, 5,099,153 attacks -> 2,479 effective sessions and 1,261,689 attacks -> 7,374 effective sessions (Table III); cleaned to 160 sessions / 1,489 commands for the comparison [P] — [arXiv 2406.01882](https://arxiv.org/pdf/2406.01882)
- Interaction-level results (Table IV, Cowrie / HoneyGPT GPT-3.5-turbo / HoneyGPT GPT-4, values as extracted from the table): full-session response rate 81.88% / 93.75% / 99.38%; command response rate 96.98% / 99.13% / 99.93%; mean session length percentage 57.28% / 71.73% / 99.93%; mean interaction degree percentage 83.24% / 94.45% / 99.91% [P] — [arXiv 2406.01882](https://arxiv.org/pdf/2406.01882)
- Field evaluation: HoneyGPT (GPT-4) and default-config Cowrie in the same network for three months (v2 text); HoneyGPT elicited six attack action types across five ATT&CK techniques that Cowrie did not (T1082, T1016, T0842, T1497, T1027) [P] — [arXiv 2406.01882](https://arxiv.org/pdf/2406.01882)
- Limitations stated: no effect on fixed-sequence bots; prompt-based attacks are an open risk; LLMs "overfit" to incorrect commands (return plausible output for invalid input); API rate limits; no viable small specialised model yet due to missing corpus [P] — [arXiv 2406.01882](https://arxiv.org/pdf/2406.01882)
- Code: I found no working repository URL in the paper text (only a bare "https://github.com/" fragment) [P] — [arXiv 2406.01882](https://arxiv.org/pdf/2406.01882)
- Lesson: have the LLM emit a structured (output, state-delta, impact) triple; keep state separate from history; prune by impact x recency rather than FIFO.

**HoneyLLM (PSU) — Guan, Cao, Zhu, "HoneyLLM: Enabling Shell Honeypots with Large Language Models", IEEE CNS 2024**
- Architecture: SSH front end; sessions matching fingerprints of predetermined scanning scripts are redirected to Cowrie; only "effective" sessions go to a commercial LLM; only one active session is processed by the LLM at a time, all other concurrent sessions are redirected to Cowrie (rate-limit control) [P] — [author PDF](https://www.cse.psu.edu/~sxz16/papers/HoneyGPT.pdf)
- Prompt: Instruction block (e.g. "without any additional explanation", "Do not auto-correct misspelled commands") + in-context response examples retrieved from collected attack traces + session history; a second LLM query asks whether the command changes system state, and only state-changing commands are added to history [P] — [author PDF](https://www.cse.psu.edu/~sxz16/papers/HoneyGPT.pdf)
- Four failure types of vanilla LLM shells: unknown command, incorrect response format, clearly incorrect content, inconsistency with history [S, consistent with P] — [SoK](https://arxiv.org/pdf/2510.25939)
- Offline: 50 constructed attack sessions, six models (GPT-3.5 turbo, GPT-4/4o, Claude-2, Claude-3 Haiku, Claude-3 Opus, Llama-2 70B); prompt engineering raises short-session success to nearly 100% for several models; GPT-4o best at 90.2% average session success and ~80% on long complex sessions [P] — [author PDF](https://www.cse.psu.edu/~sxz16/papers/HoneyGPT.pdf)
- Online: three instances for three weeks in May 2024. Table II: effective attack sessions / average session length (interaction rounds): GPT-3.5 turbo 2,672 / 4.37; GPT-4o 2,763 / 5.83; Claude-3 Haiku 2,797 / 5.36; Cowrie-only 2,386 / 2.96. For the GPT-3.5 instance the 2,672 effective sessions were "approximately 9.8% of total attack sessions" [P] — [author PDF](https://www.cse.psu.edu/~sxz16/papers/HoneyGPT.pdf)
- Prompt injection is acknowledged as unmitigated future work [P] — [author PDF](https://www.cse.psu.edu/~sxz16/papers/HoneyGPT.pdf)
- Code: none found in the paper [P].
- Lesson: a scanner-fingerprint filter in front of the LLM plus a single-LLM-session concurrency cap is a cheap, measured DoS/denial-of-wallet control.

**HoneyLLM (ICICS) — Fan, Yang, Liu, Qin, Liu, "HoneyLLM: A Large Language Model-Powered Medium-Interaction Honeypot", ICICS 2024 (Springer)**
- Proposes seven fidelity metrics; compares GPT-4, GPT-4o, Gemini Pro 1.5, Claude 3 Opus, Mistral 7B on fidelity, latency, throughput, cost; concludes GPT-4o best; Raspberry Pi front end filters problematic inputs; longer wall-clock sessions than Cowrie and Amun in the wild [S] — [SoK](https://arxiv.org/pdf/2510.25939)

**Ragsdale & Boppana, "On Designing Low-Risk Honeypots Using Generative Pre-Trained Transformer Models With Curated Inputs", IEEE Access 11, 2023**
- First to trim prior commands that do not alter context (token efficiency) and to cache deterministic responses; per-command Levenshtein fidelity slightly better than Cowrie; campaign replay shows Cowrie often fails within the first few commands; flags outbound connections (C2, downloads, exfiltration) as an unavoidable tell because no traffic is generated [S] — [SoK](https://arxiv.org/pdf/2510.25939)

**Otal & Canbaz, "LLM Honeypot: Leveraging Large Language Models as Advanced Interactive Honeypot Systems", IEEE CNS 2024, arXiv 2409.08234**
- Model and method: Llama3-8B fine-tuned with LlamaFactory using LoRA, QLoRA with 8-bit quantisation, NEFTune noise and Flash Attention 2; learning rate 5e-4; 36 training steps; 14 minutes on 2x NVIDIA RTX A6000 [P] — [arXiv 2409.08234](https://arxiv.org/pdf/2409.08234)
- Data: 617 Linux commands (public Cowrie command data + top-100 Linux commands expanded to 160 + others) executed against a local Cowrie to capture responses, plus man-page summaries of 283 commands for a second "Linux expert" task; system prompt given verbatim in the paper ("You are mimicking a Linux server...") [P] — [arXiv 2409.08234](https://arxiv.org/pdf/2409.08234)
- Results on 140 random samples: cosine similarity 0.695, Jaro-Winkler 0.599 (Levenshtein also reported); code-centric models (CodeLlama, Codestral, Phi-3) were judged less suitable than Llama3 [P] — [arXiv 2409.08234](https://arxiv.org/pdf/2409.08234)
- Deployment: custom SSH server with Paramiko + HF Transformers inference [P].
- Public artefacts: model [hotal/honeypot-llama3-8B](https://huggingface.co/hotal/honeypot-llama3-8B), dataset hotal/honeypot_logs on Hugging Face, code [AI-in-Complex-Systems-Lab/LLM-Honeypot](https://github.com/AI-in-Complex-Systems-Lab/LLM-Honeypot) (training scripts not included; no licence stated on the repo page) [P][A]
- Lesson: the fine-tuning recipe is trivially cheap, but the ground truth was Cowrie output, so the model learns to imitate Cowrie rather than a real host; MIRAGE should generate ground truth from real VMs/containers.

**LLMHoney — Malhotra, "LLMHoney: A Real-Time SSH Honeypot with Large Language Model-Driven Dynamic Response Generation", arXiv 2509.01463 (2025)**
- Architecture: dictionary-based virtual filesystem and command-state tracking; a local dictionary cache answers common commands; unseen commands go to an LLM (Gemini API or Ollama) [P] — [arXiv 2509.01463](https://arxiv.org/pdf/2509.01463)
- Benchmark: 138 Linux commands, 13 models. Mean latency (ms): Gemma3-1B 488; LLaMA3.2-1B 931; Qwen2.5-coder 1305; Qwen2.5-1.5B 1979; Gemini-1.5-flash 2079; SmolLM2-360M 3104; Falcon-3B 3155; Gemini-2.0-flash 3172; StableLM-Zephyr-3B 3388; Granite3.1-2B 3497; Phi3-3.8B 3596; CodeGemma-2B 9923; DeepSeek-1.5B 13110 [P] — [arXiv 2509.01463](https://arxiv.org/pdf/2509.01463)
- Fidelity: Gemini-2.0 best (BLEU 0.245, TF-IDF cosine 0.405, Jaro-Winkler 0.711, hallucination 12.9%); Phi3-3.8B lowest hallucination (5.8%); Gemma3-1B fastest but worst (BLEU 0.027, cosine 0.170, hallucination 25.9%) [P] — [arXiv 2509.01463](https://arxiv.org/pdf/2509.01463)
- No code URL found in the paper text [P].
- Lesson: sub-2B models answer in under 1 s but hallucinate a quarter of outputs; absolute similarity scores are low even for the best model, so a deterministic layer must carry common commands.

**LLMPot — Vasilatos, Mahboobeh, Lamri, Alam, Maniatakos, "LLMPot: Dynamically Configured LLM-based Honeypot for Industrial Protocol and Physical Process Emulation", IEEE EuroS&P 2025, arXiv 2405.05999**
- Built: ICS honeypot that fine-tunes ByT5 (byte-level) on request/response captures from a real PLC for Modbus and S7comm, including physical-process emulation; metrics BCA (byte-to-byte comparison accuracy), RVA (response validity accuracy), RVA-epsilon [P] — [arXiv 2405.05999](https://arxiv.org/pdf/2405.05999)
- Results: byt5-small (300M params) with a 1,600-sample dataset reaches 99.30% RVA; byt5-base (580M) gives no advantage; datasets above 3,200 samples overfit; Llama3.2 (1B) scored near zero (tokenisation); LoRA on byt5-small gave poor results [P] — [arXiv 2405.05999](https://arxiv.org/pdf/2405.05999)
- Latency: 160 ms per response on an RTX 3090 Ti, 110-140 ms on an A100, vs ~100 ms for real PLCs [P]. Deployment: 2 months, 4,895 connection attempts from unique IPs; Nmap identified the target device with 95% confidence; Shodan did not label it a honeypot [P] — [arXiv 2405.05999](https://arxiv.org/pdf/2405.05999)
- Code: https://github.com/momalab/LLMPot [P]
- Lesson: for binary protocols use a small byte-level model fully fine-tuned on a few thousand captured pairs; general chat LLMs and LoRA were both worse.

**Galah — Adel Karimi, open-source LLM web honeypot (cited as software, not a paper)**
- Generates HTTP headers and body for arbitrary requests; providers: OpenAI, GoogleAI, Vertex AI, Anthropic, Cohere, Ollama; response cache keyed per port with default 24 h duration (0 disables, -1 never expires); optional Suricata-rule matching logged as `suricataMatches`; Apache-2.0; README warns it is identifiable via network fingerprinting, prolonged response times and non-standard responses, and advises setting API usage limits against denial-of-wallet [A] — [GitHub 0x4D31/galah](https://github.com/0x4D31/galah)
- T-Pot ships Galah and Beelzebub with Ollama in a dedicated "LLM-based honeypots" section [S] — [SoK](https://arxiv.org/pdf/2510.25939)

**SYNAPSE — Gizzarelli, "Honeypot and Generative AI", MSc thesis, Politecnico di Torino, 2024**
- Linux terminal + MySQL simulated with GPT-4o; ten-day in-the-wild deployment, AI-vs-AI test, and human study where nearly 80% of 18 participants judged it more realistic than its static equivalent; ATT&CK mapping classifier at 75% precision / 68% recall [S] — [SoK](https://arxiv.org/pdf/2510.25939)

**MySQL-Pot — Hu, Cheng, Ma, Chen, Xiao, Zheng, "MySQL-Pot: A LLM-Based Honeypot for MySQL Threat Protection", ICBDA 2024**
- LLM answers attacker SQL queries; longer sessions than an analogous non-LLM system [S] — [SoK](https://arxiv.org/pdf/2510.25939)

**Other systems catalogued by the SoK (all [S])** — [SoK](https://arxiv.org/pdf/2510.25939)
- LIMBOSH (Johnson, Hassing, Pijpker, Loves, IEEE CSR 2024): modular shell with prompt-injection mitigation (input transformations + random-forest injection classifier) and a separate LLM context that checks output fidelity; four professionals red-teamed it against a real Ubuntu server.
- Weber, Feger, Pilgermann, "Don't Stop Believin'" (IEEE Access 2024): five CS graduate students graded GPT-3.5 responses on >1,400 request-response pairs over 230 base commands; SBERT cosine similarity to real output predicts believability.
- Jiménez-Román et al., LDAP honeypot (arXiv 2509.16682): base Llama 3 8B is poor at LDAP; fine-tuning on a curated dataset gives "dramatic gains".
- OHRA (Safargalieva, Rüffer, Vasilomanolakis, NordSec 2025): SSH/Telnet/HTTP fully, FTP/SMTP/IPP/SNMP partially; ten LLMs; GPT-4o-mini best overall; latency sometimes unrealistically slow and sometimes unusually fast.
- DecoyPot (Sezgin & Boyacı, Computers & Security 154, 2025): RAG-based web-API honeypot.
- Badran & Niazi (MSc, Malmö 2025): GPT-4o labels HTTP requests (87% label accuracy) then answers as a web server (80% of responses judged convincing).
- Beelzebub: open-source LLM honeypot framework for TCP/HTTP with claimed full SSH support.

**SBASH — Adebimpe, Neukirchen, Welsh, "SBASH: a Framework for Designing and Evaluating RAG vs. Prompt-Tuned LLM Honeypots", FLLM 2025, arXiv 2510.21459**
- Local lightweight LLMs; RAG improves accuracy for untuned models; models "tuned" via a system prompt reach similar accuracy without RAG at slightly lower latency; metrics Levenshtein, SBERT, BERTScore, human realism [A] — [arXiv 2510.21459](https://arxiv.org/abs/2510.21459)

### Inferences
- State-consistency designs, in increasing maturity: (1) whole history in context with reset at overflow (shelLM); (2) only state-changing commands kept in history, decided by a second LLM call (HoneyLLM-PSU); (3) separate state register + impact-weighted, time-decayed pruning (HoneyGPT); (4) dictionary virtual filesystem with LLM fallback (LLMHoney); (5) out-of-prompt JSON filesystem with verifier-emitted patches and cross-session persistence (AdvancedShelLM); (6) a typed six-category SYSTEM_STATE dictionary shared by static and LLM agents (HydraPoT, see section 2). MIRAGE can adopt (5)+(6) directly.
- Realistic targets implied by the literature: per-command latency 0.5-3.5 s for local small models and cloud models alike; ~$0.8/hour of active session on 2023 GPT-3.5 pricing without pruning; 30% (89 humans) to parity-with-real-Ubuntu (26 humans, small n) for believability; roughly 2x Cowrie's commands per effective session in the wild.
- Fine-tuning evidence for small local models is thin: one Llama3-8B LoRA/QLoRA run on 617 Cowrie-generated commands (cosine 0.695), one Llama3-8B LDAP fine-tune, and ByT5-small for ICS. No paper located reports a QLoRA shell model trained on real-system ground truth with rank/alpha fully specified.

### Gaps
- LoRA rank, alpha and dropout for Otal & Canbaz are not in the paper text or on the repo page; the Levenshtein value was not captured.
- HoneyGPT latency and dollar cost per session: not found in the v2 text.
- VelLMes, OHRA, LIMBOSH, SYNAPSE, MySQL-Pot, HoneyLLM-ICICS, DecoyPot and Ragsdale & Boppana were not read in full; numbers above for them come from the SoK or abstracts.
- Whether the "Prague Dataset" is in the VelLMes repo was not confirmed.
- I located no public model weights for an LLM shell honeypot other than hotal/honeypot-llama3-8B.

---

## 2. Papers newer than the SoK (2025-2026): hybrid deterministic+LLM shells, prompt-injection defence, denial-of-wallet, honeypots for AI agents / MCP, LLM-agent detection

### Takeaway
2026 work moves in three directions the SoK predicted: cost-aware routing across static/local/cloud responders with a shared state store (HydraPoT), verifier-agent consistency (AdvancedShelLM), and honeypots aimed at LLM attack agents (Honeyval, Say Shibboleth, Cloak-Honey-Trap, Palisade). I found no peer-reviewed MCP-honeypot paper; MCP decoys exist only as prototypes and blog posts.

### Cited Findings

**HydraPoT — Saengtong, Saengyingyongwattana, Janpuangtong, Rattanavipanon, "HydraPoT: A Configurable Multi-Agent Framework for Cost-Aware LLM-Assisted Honeypots", arXiv 2610.27722 (20 Oct 2026)** — [arXiv html](https://arxiv.org/html/2610.27722v1)
- Architecture: AsyncSSH fake service -> Honey Router -> Complexity Evaluator assigning impact levels F0-F4 (adapted from HoneyGPT's impact factor) -> one of three agents: static Cowrie (official Docker image), local LLM (Qwen3.5-9B GGUF Q5_K_M via llama-cpp-python, context 8192, max 256 tokens, temperature 0, repetition penalty 1.15), or cloud LLM (DeepSeek-V4 Flash). A State/Log Manager keeps a per-session `SYSTEM_STATE` dictionary with six categories (working directory, files, packages, users/groups, security settings, services). Case-study policy: state-independent F0 -> Cowrie; state-dependent F0-F2 -> local LLM; F3-F4 -> cloud.
- Hardware: i7-11700K, 32 GB RAM, RTX 4060.
- Results: context preservation 100% with state sync vs 14.9%-79.3% without (29 command pairs, 3 runs). Fidelity on 2,179 commands from 109 sessions against Ubuntu 22.04 ground truth, HydraPoT vs cloud-only: cosine 0.662 vs 0.699; BERTScore 0.642 vs 0.691; Levenshtein 0.643 vs 0.682; Jaro-Winkler 0.766 vs 0.795; BLEU 0.450 vs 0.487; exact match 0.286 vs 0.311. Tokens 3,238,807 vs 11,802,012 (-72.6%); cloud-routed commands 531 vs 2,179; cost $0.5415 vs $1.98 (3.7x lower). Architecture overhead ~5% (static) and ~2% (LLM agents). LLM-as-judge (GPT-5, 1-5 scale) ~0.25 points below cloud-only.
- Datasets used: mrheinen/linux-commands (480 commands) and ML4Net SSH-Shell-Attacks.
- Limitations: no human study, no live deployment, prompt-injection mitigation unexplored, Cowrie could not read the external state.
- Code: https://github.com/Kamolchanok-Saengtong/HydraPoT
- Lesson: this is the closest published design to a MIRAGE router; reuse the F0-F4 complexity scale, the six-category state schema and the evaluation recipe (real-VM ground truth + six similarity metrics + judge).

**Magazov, Abeshev, Shamuratov, Uralova, Aksholak, "Benchmarking LLM Backends for Generative SSH Honeypots: Security, Fidelity, Hallucination, Latency, and Stability", AI (MDPI) 7(8):287, 2026, DOI 10.3390/ai7080287**
- Uses deterministic handlers for most commands to confine hallucination and reduce LLM usage [S] — [HydraPoT related work](https://arxiv.org/html/2610.27722v1)
- 33 of 42 tested commands produced identical output across backends; the remaining nine generative commands carry the model-specific risk; "flag fabrication" ranges 0-95% across backends; latency spans an order of magnitude; a held-out classifier identifies the backend model from a single response at 71% vs 9% chance (fingerprinting risk); prompt leakage measured against a known prompt corpus following OWASP LLM07 without an LLM judge [S, search snippets of the article] — [MDPI article](https://www.mdpi.com/2673-2688/7/8/287)
- Lesson: the security floor comes from the architecture (deterministic handlers), not the model; the LLM's style is itself a fingerprint.

**AdvancedShelLM (arXiv 2606.27990)** — see section 1.

**Honeyval — Vero, Kaczmarczyck, Petrov, Shumailov, Hayes, Heinen, Fan, Invernizzi, Vechev, "Honeyval: A Comprehensive Evaluation Framework for LLM-powered HTTP Honeypots", arXiv 2605.29963 (v1 28 May 2026, v2 9 Nov 2026)** — [arXiv](https://arxiv.org/abs/2605.29963)
- Evaluation framework grounded in 16 backend applications, two control tasks, and AI hacking agents with verifiable exploit goals as attackers. Cost-efficient LLM honeypots produced substantially longer attacker interactions than rule-based baselines, were detected less often even by frontier models, and kept a running-cost advantage over agentic attackers on average; extensions trade lower latency for more detection [A]. No numbers or code URL on the abstract page.
- Lesson: this is the SoK's "adversarial research ecosystem" realised for HTTP; MIRAGE's evaluation should copy the agent-as-attacker-with-verifiable-goal method.

**Say Shibboleth — Pasquini, Reworr, Ateniese, Bhatt, Epp, "Say Shibboleth: Fingerprinting the LLMs and Harnesses Behind Agentic Attacks", arXiv 2611.12386 (9 Nov 2026)** — [arXiv](https://arxiv.org/abs/2611.12386)
- "Shibboleth traps": modular honeypot services that make an informative interaction the condition for obtaining a resource the agent wants, eliciting model self-declarations and writing style without needing a successful prompt injection; harness probes reveal secret-masking, command time limits and tool-call scheduling. Distinguishes 15 candidate models with average 90% top-1 accuracy; identifies the harness among four with 92% accuracy; agents told to hide identity still leak behavioural evidence [A].

**Palisade — Reworr & Volkov, "LLM Agent Honeypot: Monitoring AI Hacking Agents in the Wild", arXiv 2410.13919 (2024, revised 2025)** — [arXiv](https://arxiv.org/pdf/2410.13919)
- Method: Cowrie hardened per Cabral et al.; prompt injections placed in the SSH banner, in outputs of common commands (e.g. `uname`) and in system files; two injection types (goal hijacking, then prompt stealing); timing analysis with a 1.5 s response threshold separates LLM agents from humans; the paper also notes most ordinary bots answered in under 1.7 s, so timing alone does not separate LLM agents from scripts [P].
- Result: ~3 months public deployment, 8,130,731 interaction attempts, 8 potential AI agents [P].
- Artefacts: code [PalisadeResearch/llm-honeypot](https://github.com/PalisadeResearch/llm-honeypot) (hidden messages via ANSI escape codes in `pwd`, `whoami`, `ps`, `ls`, `df` output; no licence shown; no session dataset advertised) [A]; live dashboard https://ai-honeypot.palisaderesearch.org [P].
- Limitations stated: narrow coverage, SSH only, detection methods new and not validated against false positives or evasion [P].

**Cloak, Honey, Trap — Ayzenshteyn, Weiss, Mirsky, USENIX Security 2025, pp. 8095-8114** — [USENIX](https://www.usenix.org/conference/usenixsecurity25/presentation/ayzenshteyn)
- 6 strategies / 15 techniques exploiting LLM-agent weaknesses (biases, memory limits, tokenisation), most without prompt injection; protected 11 CTF machines with 100% success under black-box assumptions; releases the CHeaT tool; USENIX artifact badges "available" and "functional" [A].

**HoneyRoute — Han Jin, "HoneyRoute: Honeypot-Model Routing for Adversarial LLM Serving", arXiv 2609.08306 (Sep 2026)** — [arXiv](https://arxiv.org/abs/2609.08306)
- Different problem (protecting a production LLM endpoint by diverting malicious prompts to a honeypot model), but the router numbers are a useful target: F1 = 0.911 with 38 ms median added latency; 96% of a two-tier guard-LLM cascade's F1 at 1/385 of its latency; 0% evasion under 13 adversarial transformations; production-model token consumption cut 97.8% under flooding [A].

**LLM pentest agents vs honeypots — Xie, Nagasubramaniam, Karamchandani, Zhu, "LLM-Based Penetration Testing in the Presence of Honeypots", arXiv 2609.08093 (Sep 2026)** — [arXiv](https://arxiv.org/abs/2609.08093)
- Formalises honeypot-aware target selection as a budgeted decision process with a detector-guided skip policy; defences out of scope; no numbers in the abstract [A]. Confirms that LLM attackers will reason over banners, timing and incomplete functionality.

**Prompt-injection defence / denial-of-wallet specifically**
- SoK position: the Filter/Router "prevents prompt injection, Denial-of-Service (DoS), and Denial-of-Wallet (DoW) attacks" and lowers cost; hardening against injection, flooding and context overflow is listed as continuing research [P] — [SoK](https://arxiv.org/pdf/2510.25939)
- Measured controls found: HoneyLLM-PSU scanner filter + one-LLM-session cap keeps token use under Tier-1 API limits [P] — [author PDF](https://www.cse.psu.edu/~sxz16/papers/HoneyGPT.pdf); LIMBOSH input transformation + random-forest classifier [S] — [SoK](https://arxiv.org/pdf/2510.25939); Galah response cache and API spend caps [A] — [GitHub](https://github.com/0x4D31/galah); HydraPoT token reduction of 72.6% via routing — [arXiv](https://arxiv.org/html/2610.27722v1)

**MCP honeypots**
- Only non-peer-reviewed artefacts located: the "agent-honeypot" pre-alpha GitHub prototype (decoy MCP tool server, fingerprinting of agent behaviour) and Cobalt's "Honey-AI" blog series [S, search snippets] — [GitHub alizafarbati/agent-honeypot](https://github.com/alizafarbati/agent-honeypot); [Cobalt blog](https://www.cobalt.io/blog/building-honey-ai-part-1-why-ai-infrastructure-needs-its-own-honeypot)
- arXiv 2604.13301 "Honeypot Protocol" (Hasan, Apr 2026) is an AI-control evaluation protocol, not a network honeypot; not relevant to MIRAGE — [arXiv](https://arxiv.org/abs/2604.13301)

### Inferences
- The "hybrid deterministic+LLM shell" now has two independent 2026 measurements pointing the same way: ~75-80% of commands can be answered without a cloud LLM (HydraPoT 531/2,179 cloud-routed; Magazov 33/42 backend-independent).
- Dual-use of prompt injection: Palisade/Say-Shibboleth use it to unmask agents; the same channel is the honeypot's own attack surface. A MIRAGE design needs both an outbound "agent tripwire" layer and inbound sanitisation.
- No paper located reports a measured denial-of-wallet attack against an LLM honeypot; all evidence is about ordinary traffic volume exceeding rate limits.

### Gaps
- Magazov et al. and Honeyval full texts were not accessible/read (MDPI returned 403; Honeyval abstract only); per-backend numbers are missing.
- "Honey for the Agent: Cyber Deception and Behavioral Fingerprinting of LLM-Based Attackers" (ResearchGate, Sep 2026) and GASH (DQN + LLM, cited in arXiv 2512.07827) surfaced in search but were not opened; no details verified.
- No peer-reviewed MCP honeypot paper was found.

---

## 3. RL / adaptive honeypots: state, action, reward, training, measurements; game theory

### Takeaway
Every RL shell honeypot since Heliza uses essentially the same tiny formulation: state = attacker command (or command class / ATT&CK stage), actions = {allow, block, substitute, delay, insult}, tabular SARSA/Q-learning (DQN in QRASSH and Asgard2.0), reward = hand-set constants for downloads/severity/session length. Evaluations are small, mostly simulated or self-defined, and none shows a large, independently reproduced engagement gain.

### Cited Findings

**Heliza — Wagener, State, Dulaunoy, Engel, "Heliza: talking dirty to the attackers", Journal in Computer Virology, 2011**
- Modified vulnerable Linux SSH host; state = attacker command; actions allow, block, substitute, insult; SARSA; configurable objective: collect attack tools or keep the attacker busy; finding reported by Asguard authors: to collect tools, `wget`/`sudo` should be allowed, while to keep attackers busy `sudo` should be blocked; insult doubles as a reverse Turing test [S] — [Asguard paper](https://www.scitepress.org/Papers/2021/107191/107191.pdf)

**RASSH — Pauna & Bica, "RASSH - Reinforced adaptive SSH honeypot", 2014**
- Kippo + SARSA (PyBrain); adds the delay action; reward primarily session duration [S] — [search summary / Semantic Scholar record](https://www.semanticscholar.org/paper/RASSH-Reinforced-adaptive-SSH-honeypot-Pauna-Bica/8f77c1df86d0f62653405f0cce85e94bce76ad7c); [Asguard paper](https://www.scitepress.org/Papers/2021/107191/107191.pdf)

**QRASSH — Pauna, Iacob, Bica, "QRASSH - A self-adaptive SSH Honeypot driven by Q-Learning", 2018**
- Cowrie + DQN; 57 states (Linux commands) and 5 actions; Q-Cowrie authors note its complex, poorly defined reward hampered policy learning [S] — [Q-Cowrie paper](https://researchcommons.waikato.ac.nz/items/cfc0e5b5-0f3f-4434-9a55-458d98dafc92)

**Dowling, Schukat, Barrett, "Using Reinforcement Learning to Conceal Honeypot Functionality", ECML-PKDD 2018; "New framework for adaptive and agile honeypots", ETRI Journal 2020**
- SARSA on Cowrie aimed at automated malware rather than humans; reduced action set allow/block/substitute; commands classified as bash vs compound [S] — [Q-Cowrie paper](https://researchcommons.waikato.ac.nz/items/cfc0e5b5-0f3f-4434-9a55-458d98dafc92); [Springer chapter](https://link.springer.com/chapter/10.1007/978-3-030-10997-4_21)

**Suratkar et al., "An adaptive honeypot using Q-Learning with severity analyzer", J. Ambient Intell. Humaniz. Comput., 2021**
- Cowrie + Q-learning; six command groups (CheckConf, Install, Download, Run, Password, ChangeConf); actions allow/block/delay/substitute/insult; fixed severity reward 1.0 high-risk, 0.5 medium, 0.0 reconnaissance; converged in ~25 attacks vs 65 for comparable systems [S] — [Q-Cowrie paper](https://researchcommons.waikato.ac.nz/items/cfc0e5b5-0f3f-4434-9a55-458d98dafc92); [Springer](https://link.springer.com/article/10.1007/s12652-021-03229-2)

**Asguard / Asgard — Touch & Colin, "Asguard: Adaptive Self-guarded Honeypot", WEBIST/DMMLACS 2021; "A Comparison of an Adaptive Self-Guarded Honeypot with Conventional Honeypots", Applied Sciences 12(10):5224, 2022**
- Architecture: SSH proxy in front of a real Linux server running in Docker; a decision maker returns an action per command [P] — [Asguard paper](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- State = attacker command, with classes D (download commands such as wget/curl/ftpget) and C (custom commands the attacker had to download first); actions {allow, block, substitute} (insult and delay deliberately dropped); reward r(s,a) = +1 if s in D and a = allow; -1 if s in C and a = allow; 0 otherwise; tabular Q-learning with decaying epsilon-greedy [P] — [Asguard paper](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- Training/evaluation in the 2021 paper: a fake botnet simulator replaying real attack data (proof of concept, not live attackers) [P] — [Asguard paper](https://www.scitepress.org/Papers/2021/107191/107191.pdf)
- 2022 journal paper compares Asgard with Cowrie and with Midgard (variant whose reward uses state only) and reports higher-quality attacker data than Cowrie while evading detection [S] — [MDPI](https://www.mdpi.com/2076-3417/12/10/5224)
- Code: https://github.com/sereysethy/asgard [S]; a DRL follow-up "An Adaptive Self-guarded and Risk-Aware Honeypot Using DRL" exists as a Springer chapter [S] — [Springer](https://link.springer.com/chapter/10.1007/978-3-032-16092-8_11)
- Lesson: making reward depend on (state, action) is how you encode "collect the payload but never run it".

**Cannypot — SmartData@PoliTO (MSc thesis + code)**
- Cowrie-based "Learner" front end plus a root-privileged "Explorer" back end that runs unknown commands on real Libvirt VMs and stores the outputs for later reuse; RL state configurable as last command or last N commands (`reinforcement_state`, `num_entry_states`) [A] — [GitHub SmartData-Polito/cannypot](https://github.com/SmartData-Polito/cannypot); thesis: [PoliTO](https://webthesis.biblio.polito.it/19256/1/tesi.pdf)
- Lesson: the Explorer pattern (learn real outputs offline from sacrificial VMs, serve them from a medium-interaction front end) is directly reusable as MIRAGE's ground-truth and cache-warming pipeline.

**Q-Cowrie — Var Naseri, Welch, Haseeb, Mansoori, "Q-Cowrie: An adaptive honeypot to analyse attackers' behaviour", International Journal of Information Security 25(2), 2026, DOI 10.1007/s10207-026-01221-5 (CC BY 4.0; open copy at Waikato Research Commons)** — the paper exists and was read [P] — [Waikato](https://researchcommons.waikato.ac.nz/items/cfc0e5b5-0f3f-4434-9a55-458d98dafc92); [Springer](https://link.springer.com/article/10.1007/s10207-026-01221-5)
- MDP: eight attack-lifecycle states S0-S7 mapped to MITRE ATT&CK stages; attacker actions move between stages; transition probabilities estimated empirically from Cowrie logs; reward by tactical severity +5 high, +2 medium, +1 low, 0 otherwise.
- Q-learning: alpha = 0.1, gamma = 0.9, epsilon = 0.1, 1,000 episodes; Q-table initialised by offline simulation over the empirical MDP to avoid cold start.
- Honeypot responses: allow, block (with deceptive feedback such as a simulated DNS/network failure), delay, insult (Heliza-inspired); Cowrie command handling modified to add randomised 3-5 s response delays.
- Data: Phase 1 = two Cowrie instances for 21 days tuned to attract cryptomining/botnet attacks; ~249,000 sessions refined for the model; "over 400,000 attack sessions" analysed overall.
- Reported results: 94% successful dynamic response generation; ~80% "improvement in adaptability and learning" (stability metric defined by the authors).
- Availability: data "available from the corresponding author upon request"; no code link found.

**IoTCandyJar — Luo, Xu, Jin, Jia, Ouyang (Palo Alto Networks), Black Hat USA 2017**
- "Intelligent-interaction" IoT honeypot: harvests real device responses by replaying captured attacker requests to Internet devices, then uses an MDP response-selection algorithm to pick the response most likely to keep the attacker going [S] — [Black Hat whitepaper](https://www.blackhat.com/docs/us-17/thursday/us-17-Luo-Iotcandyjar-Towards-An-Intelligent-Interaction-Honeypot-For-IoT-Devices-wp.pdf)

**Game-theoretic / SMDP — Huang & Zhu, "Adaptive Honeypot Engagement through Reinforcement Learning of Semi-Markov Decision Processes", GameSec 2019 (Springer DOI 10.1007/978-3-030-32430-8_13), arXiv 1906.12182** — [arXiv](https://arxiv.org/abs/1906.12182)
- Models attacker movement in a honeynet as an infinite-horizon SMDP with stochastic transitions and sojourn times, with an explicit reward (information) vs risk (penetration) trade-off; RL is used to avoid needing the model; claims fast, robust convergence and low penetration probability across attacker persistence levels [A]. No real-attacker data in the abstract.

**Other items surfaced (not opened)**: NCI thesis using Q-learning and DQN with Cowrie on synthetic attackers reporting 83% accuracy [S] — [NORMA](https://norma.ncirl.ie/9524/); arXiv 2512.07827 using DQN for honeynet deployment decisions and citing GASH (DQN + LLM) [S] — [arXiv 2512.07827](https://arxiv.org/pdf/2512.07827)

### Inferences
- No bandit-based shell honeypot paper was located; contextual bandits over response strategies would be a novel but lower-risk fit for the sparse-data regime the SoK describes (99%+ scripted traffic gives almost no reward signal for full RL).
- Practical reusable pieces: Asguard's (state, action) safety reward; Q-Cowrie's offline MDP warm start from existing Cowrie logs; Cannypot's Explorer; HoneyGPT's impact factor as a ready-made severity signal for reward shaping.
- "Insult" and long fixed delays are risky for MIRAGE: Asguard dropped both, and uniform timing was noticed by humans in AdvancedShelLM.

### Gaps
- Heliza, RASSH, QRASSH, Dowling, Suratkar, IoTCandyJar and the 2022 Asgard journal paper were not read in primary form; their state/action/reward details above are as described by later papers.
- Asgard 2022 numeric results (MDPI returned 403) and Asgard2.0 details are missing.
- Cannypot's exact reward function and RL algorithm are in the thesis, which was not read.
- Q-Cowrie reports no head-to-head session-length or commands-per-session delta versus Cowrie in the passages read; its 94%/80% figures are author-defined metrics and should not be treated as engagement gains.

---

## 4. Fingerprinting: Bitter Harvest methods, later Cowrie/Kippo and LLM-honeypot detection, timing, countermeasures

### Takeaway
Transport-layer deviations from the impersonated implementation identify Cowrie/Kippo with one packet, and that weakness is architectural, so MIRAGE should terminate SSH with real OpenSSH (or a byte-exact stack) rather than a library server. LLM honeypots add new fingerprints: latency distribution, missing egress/side effects, model-specific output style and prompt-injection susceptibility.

### Cited Findings

**Vetterl & Clayton, "Bitter Harvest: Systematically Fingerprinting Low- and Medium-interaction Honeypots at Internet Scale", USENIX WOOT 2018** [P] — [USENIX PDF](https://www.usenix.org/system/files/conference/woot18/woot18-paper-vetterl.pdf)
- Method: send a set of probes to real implementations and to honeypots/their libraries, represent responses as feature vectors, compute cosine similarity, and pick the probe whose responses are least similar across implementations; honeypots are then flagged when their response matches a known honeypot response exactly (cosine 1.0).
- SSH: 192 client version strings x KEXINIT variants tested against OpenSSH 6.6/6.7/6.8/7.2/7.5, TwistedConch and eight Kippo/Cowrie versions; Kippo/Cowrie average similarity to OpenSSH only 0.66-0.81; best single probe is version string `SSH-2.2-OpenSSH` plus a KEXINIT with ecdh-sha2-nistp521 / ssh-dss / blowfish-cbc / hmac-sha1 / zlib@openssh.com and wrong padding. A second tell: TwistedConch (Kippo/Cowrie) pads KEXINIT with random bytes while OpenSSH uses NULL padding.
- Scale: 7,605 honeypot instances on 6,125 IPv4 addresses across nine honeypot implementations (2,779 SSH, 1,166 Telnet, 3,660 HTTP); equal error rate 0.0183 with one packet; 97.4% of Telnet and 97.0% of HTTP honeypots answered follow-up probes as predicted.
- Hygiene: 27% of SSH honeypots not updated in 31 months; only 39% updated within 7 months; 546 of 758 Kippo instances (72%) still vulnerable to a fingerprint disclosed in 2014.
- Countermeasures: authors call it a "class break" that trivial patches cannot fix; library maintainers can patch individual distinguishers in the medium term, but a new architecture is needed; they explicitly say this is not an argument that everyone should run high-interaction honeypots.

**Later Cowrie/default-configuration work (via the SoK)** [S] — [SoK](https://arxiv.org/pdf/2510.25939)
- Morishita et al. 2019: 20 signatures for default responses found over 19,000 honeypots in the wild.
- Srinivasa, Pedersen, Vasilomanolakis 2021 ("Gotta catch 'em all"): multistage framework found over 21,000; targets low/medium-interaction only.
- Cabral, Valli, Sikos, Wakeling 2019/2021: Cowrie artefact review and "Advanced Cowrie configuration" showing that changing banners, filesystem, network services and OS descriptions significantly improves evasion. Palisade explicitly followed these recommendations [P] — [arXiv 2410.13919](https://arxiv.org/pdf/2410.13919)
- Huang et al. 2019: SVM/k-NN/Naive Bayes over protocol, flow (e.g. average TTL) and system (e.g. ICMP timing) features.
- Timing lineage: Defibaugh-Chavez et al. 2006 (slow ICMP replies), Fu et al. 2006 (Honeyd link latency differing by an order of magnitude), Mukkamala et al. 2007 (ML on ICMP/TCP timing).
- Egress tells: Krawetz 2004 "Honeypot Hunter" connect-back test; botnets testing whether a host can attack onward (Wang et al. 2010).

**SoK taxonomy of detection vectors and what LLMs can/cannot fix (Table 1)** [P] — [SoK](https://arxiv.org/pdf/2510.25939)
- Contents & posture: LLM helps with diverse context-aware content; cannot hide open ports or TCP/IP stack signatures.
- Outputs & behaviour: LLM gives context-aware, stochastic responses; cannot reproduce temporal fidelity or real-time dynamics (static `htop`, timing anomalies).
- Functional limits: LLM can fake success messages; cannot generate real traffic, file creation or kernel execution (`vim`, `wget` egress, binary execution fail).
- Feature synthesis: multi-vector ML/LLM classifiers; combined vectors raise detection confidence.
- "Moving to LLM-based honeypots, timing remains a critical and unresolved challenge."

**LLM-honeypot-specific detection evidence**
- Beekeeper (Ilg, Germek, Duplys, Menth, IEEE Access 2025): LLM-driven honeypot realism analysis; attempted download and use of files often gives decoys away; shows LLM attackers can fingerprint honeypots automatically [S] — [SoK](https://arxiv.org/pdf/2510.25939)
- Backend-model identification from one response at 71% vs 9% chance (Magazov et al. 2026) [S] — [MDPI](https://www.mdpi.com/2673-2688/7/8/287)
- OHRA: latency sometimes unrealistically slow, sometimes unusually fast [S] — [SoK](https://arxiv.org/pdf/2510.25939)
- AdvancedShelLM human study: participants noticed uniform timing and leaked reasoning artefacts [A-html] — [arXiv 2606.27990](https://arxiv.org/html/2606.27990v1)
- Galah README self-reports identifiability via network fingerprinting, long response times and non-standard responses [A] — [GitHub](https://github.com/0x4D31/galah)
- LLMPot countermeasure evidence: Nmap fingerprint copied from the real PLC gives 95% device-match confidence; Shodan does not flag it [P] — [arXiv 2405.05999](https://arxiv.org/pdf/2405.05999)
- Aradi et al., Acta Polytechnica Hungarica 22(12), 2025: evaluation framework including a fingerprinting-resistance metric, recommended by the SoK [S] — [SoK](https://arxiv.org/pdf/2510.25939)

### Inferences
- Countermeasures with measured support: (1) non-default Cowrie configuration (Cabral); (2) real protocol stack at the edge (implied by Bitter Harvest's class-break argument; Asguard's proxy-to-Docker design does this); (3) copying the real device's network fingerprint (LLMPot); (4) deterministic handlers so identical commands return identical output regardless of model (Magazov). No paper located evaluates a latency-shaping countermeasure (e.g. padding responses to a real-host latency distribution) for LLM shells.
- Timing cuts both ways: under ~1.5 s responses mark the attacker as non-human (Palisade), and multi-second or bimodal responses mark the honeypot as LLM-backed.

### Gaps
- I did not find a dedicated paper whose main contribution is fingerprinting LLM honeypots by timing; evidence is scattered observations.
- Whether current Cowrie releases still fail the specific Bitter Harvest SSH probes was not checked.
- Morishita, Srinivasa, Cabral, Huang and Beekeeper papers were not read directly.

---

## 5. Public honeypot datasets: size, labels, licences

### Takeaway
Large unlabeled Cowrie corpora with permissive licences exist (CyberLab 10 GB, CC BY 4.0; a 2026 160-sensor corpus with 38 M sessions, CC BY 4.0); labelled data is scarce (LogPrécis tactic labels; small command-response sets). The SoK names the lack of large labelled datasets as the main blocker.

### Cited Findings
- **CyberLab honeynet dataset** — Sedlar, Kren, Štefanič Južnič, Volk (Univ. of Ljubljana), Zenodo v1.0, 29 Feb 2020, DOI 10.5281/zenodo.3687527. Cowrie 1.6.0 then 2.0.2 (high-interaction proxy mode after 8 Nov 2019, tagged `sensor:ubuntu_basic_pool`), ~50 nodes at EU/US universities and companies, 13 May 2019 - 29 Feb 2020, 293 daily `.json.gz` files, 10.0 GB, unlabeled Cowrie JSON events, licence CC BY 4.0 — [Zenodo](https://zenodo.org/records/3687527)
- **"Deployment of 160 Cowrie SSH honeypot instances across four distinct configurations"** — Mikuláš, Krajčík, Helebrandt, Kotuliak (STU Bratislava), Zenodo, 8 Jul 2026; companion article in Scientific Data (in press), DOI 10.1038/s41597-026-08668-0. 50 continuous days, 160 instances in 14 countries, >211 M Cowrie events, >38 M SSH sessions, >214,000 source IPs, 1,770 transferred file artefacts (password-protected malware archive), 28.7 GB by file sizes; four configurations: default baseline, hardened "enhanced", and two persistence-enabled (per-user and global filesystem state); CC BY 4.0 — [Zenodo](https://zenodo.org/records/21260400)
- **LogPrécis data** — Boffa et al., Computers & Security 141 (2024), arXiv 2307.08309. Cowrie sessions from the CyberLab and PoliTO deployments (about 400,000 unique Unix shell sessions over two years; ~17 M and ~28 M words) with per-statement MITRE ATT&CK tactic labels for a manually labelled subset; rows are `session_id` + `statements`; LogPrécis reduces sessions to ~3,000 tactic-sequence fingerprints; code/data at github.com/SmartData-Polito/logprecis and model at huggingface.co/SmartDataPolito/logprecis; licence not confirmed [S] — [arXiv 2307.08309](https://arxiv.org/pdf/2307.08309); [Hugging Face](https://huggingface.co/SmartDataPolito/logprecis). SoK: LogPrécis achieves over 90% tactic-labelling accuracy — [SoK](https://arxiv.org/pdf/2510.25939)
- **hotal/honeypot_logs** (Hugging Face) — command/response pairs from Otal & Canbaz (617 commands run on local Cowrie + 283 man-page summaries); licence not stated on the GitHub page — [GitHub](https://github.com/AI-in-Complex-Systems-Lab/LLM-Honeypot); [arXiv 2409.08234](https://arxiv.org/pdf/2409.08234)
- **VelLMes / shelLM repo** — contains "Fine-Tuning Dataset", unit tests and human-evaluation folders; GPL-2.0 — [GitHub](https://github.com/stratosphereips/VelLMes-AI-Deception-Framework)
- **Palisade** — public dashboard of the 8.1 M-interaction deployment; repository has a `process_logs` folder but does not advertise a session dataset; no licence shown — [GitHub](https://github.com/PalisadeResearch/llm-honeypot); [dashboard](https://ai-honeypot.palisaderesearch.org/)
- **HoneyGPT replay corpora** — two Cowrie-captured sets (5,099,153 attacks / 2,479 effective sessions; 1,261,689 / 7,374) taken from cited prior sources; HoneyGPT's own field data not released as far as the paper states — [arXiv 2406.01882](https://arxiv.org/pdf/2406.01882)
- **Used by HydraPoT as evaluation inputs**: `mrheinen/linux-commands` (480 commands) and `ML4Net SSH-Shell-Attacks` (109 sessions / 2,179 commands sampled) — [arXiv 2610.27722](https://arxiv.org/html/2610.27722v1)
- **MURHCAD** — "Multi-Regional Cloud Honeynet Dataset" (T-Pot across Azure regions), Zenodo record 15716735 and descriptor arXiv 2601.05813; located via search, contents not inspected [S] — [Zenodo](https://zenodo.org/records/15716735); [arXiv 2601.05813](https://arxiv.org/pdf/2601.05813)
- **Q-Cowrie data** — available from the corresponding author on request only — [Waikato](https://researchcommons.waikato.ac.nz/items/cfc0e5b5-0f3f-4434-9a55-458d98dafc92)

### Inferences
- For fine-tuning or cache-warming, the practical path is: mine command frequency from CyberLab / the 160-sensor corpus (both CC BY 4.0), then generate ground-truth outputs on real VMs (Cannypot Explorer / HydraPoT method). No public dataset pairs real attacker commands with real-system outputs at scale.
- The 160-sensor corpus's persistence-enabled configurations make it the only public data I found on how filesystem persistence changes attacker behaviour, which is directly relevant to MIRAGE's state design.

### Gaps
- LogPrécis licence, exact labelled-subset size and the PoliTO data's availability terms were not confirmed.
- hotal/honeypot_logs record count and licence not confirmed.
- No public dataset of confirmed LLM-agent attack sessions was found.

---

## 6. What the SoK says: recommended architecture, open problems, and verification of five specific claims

### Takeaway
The SoK (Bridges, Mitchell, Muñoz, Henriksson; arXiv 2510.25939, v1 29 Oct 2025, v4 7 Apr 2026) recommends a filter/router + deterministic responder + prompt creator + system-state manager + session-history curator + LLM architecture, argues the right target is autonomous LLM attack agents, and says no open-source implementation of the full architecture exists. Four of the five quoted numbers appear in the SoK as claimed and three trace cleanly to primary sources; the "99.2% scanning" figure does not match the author-hosted HoneyLLM paper, which implies about 90%.

### Cited Findings

**Recommended ("canonical") architecture (Fig. 1, section 4.1)** [P] — [SoK](https://arxiv.org/pdf/2510.25939)
- Attacker-facing server -> Filter/Router -> Deterministic Responder for simple or cached responses, otherwise Prompt Creator -> LLM, with a System State Manager (tracks changes to the virtual environment) and a Session History Curator (prunes command history); all interactions logged to a honeypot data store. The LLM block "may represent multiple models or fine-tuned LoRA heads, each specialized for a different protocol".
- "no comprehensive, easily configurable architecture that implements all these features exists as open source. This is a direct engineering gap."
- Trade-off stated: proprietary API models give more deceptiveness/fidelity but cost, latency and loss of inference privacy; open-weight local models are faster/private but less accurate, and "most research shows worthwhile gains" after per-protocol fine-tuning; per-protocol LoRA heads on one base model are recommended.

**Evaluation tetrad and attacker trichotomy (section 4.2)** [P] — [SoK](https://arxiv.org/pdf/2510.25939)
- Tetrad: (1) believability/deception (human studies, semantic similarity); (2) fidelity (latency statistics, Levenshtein to ground truth, command execution success); (3) attacker cost and intelligence (session length, unique ATT&CK patterns elicited); (4) defender cost (tokens, API latency, hardware). (3) and (4) are the success indicators; (1) and (2) are diagnostics.
- Tier 1 scripted bots: LLM simulation is likely wasted; use static decoys with LLM-generated content. Tier 2 autonomous LLM agents: the primary target. Tier 3 skilled humans: simulation, LLM or not, is insufficient; high-interaction needed.

**Open problems / roadmap (section 5)** [P] — [SoK](https://arxiv.org/pdf/2510.25939)
- Unsolved simulation problems: continuously updating/interactive commands (`top`, `vim`); long, chained or complex commands; outbound network actions (`wget`, C2).
- Hardening against prompt injection, flooding and context overflow.
- Open-source modular honeynet frameworks; small language models, fine-tuning/distillation, LoRA multi-protocol heads.
- A contained "adversarial research ecosystem" pitting LLM attackers against honeypots to escape the "data desert" and to generate labelled attacks.
- Large open labelled datasets for ATT&CK labelling; honeypot-to-SOC and honeypot-to-honeypot feedback loops; an information-gain metric as an objective for RL or prompt optimisation; federated honeypots; mid-attack reconfiguration to "steer" the attacker; REST/JSON API honeypots.

**Claim verification**

| Claim | In the SoK? | Primary source check | Verdict |
|---|---|---|---|
| 99.2% of activity is scanning | Yes: "99.2% of all honeypot activity consisted of simple scanning scripts", attributed to Guan et al. (HoneyLLM, CNS 2024) | Author-hosted PDF says, for the GPT-3.5 instance, effective sessions were "approximately 9.8% of total attack sessions", i.e. roughly 90.2% filtered as scanning. The string "99.2" does not occur in that PDF; "90.2%" occurs separately as GPT-4o's offline success rate | **Not supported by the accessible primary text.** Accurate as a quotation of the SoK, but the underlying figure appears to be about 90%, not 99.2% (the IEEE Xplore version was not checked) |
| 0.58% and 0.048% of connections become valid post-login sessions | Yes, attributed to Wang et al. (HoneyGPT) | HoneyGPT Table III: 7,374 effective sessions of 1,261,689 attacks = 0.584%; 2,479 of 5,099,153 = 0.0486%. The percentages are not printed in the v2 paper; they are derivable | **Accurate** (derived ratios; paper's units are "attacks" and "effective attack sessions") |
| LLM honeypot 5.83 vs Cowrie 2.96 commands/session | Yes, Guan et al. | Table II: GPT-4o 5.83, Claude-3 Haiku 5.36, GPT-3.5 4.37, Cowrie-only 2.96 "interaction rounds", for effective sessions only, three weeks in May 2024 | **Accurate**, with caveats: best model only (GPT-4o); filtered effective sessions only; I found no significance test in the author PDF although the SoK says "statistically significantly" |
| GPT-4 ATT&CK labelling 72.46% | Yes, attributed to Ozkok et al. (EICC 2024) with GPT-4 | Abstract of "Honeypot's Best Friend?" reports 72.46% accuracy matching an attack to one or more techniques (and 97.26% / 98.84% on the SSH subset for consequence explanation / technique mapping); data: 627 Elasticsearch-honeypot requests and 73 SSH attacks | **Number accurate.** The abstract says "ChatGPT"; the specific model version (GPT-4) was not confirmed from the full text |
| 52% GPT-3.5 believability baseline | Yes: Weber et al. "concluded that only 52% of the generated responses were convincing" (five CS graduate students, >1,400 pairs, 230 base commands, GPT-3.5) | Catalogue/abstract records confirm the >1,400 pairs / 230 base commands and a 77.85% macro-F1 for the paraphrase-mining classifier, but the 52% figure is not in the abstract | **Accurately quoted from the SoK; not independently verified** against the full IEEE Access text |

Sources for the table: [SoK](https://arxiv.org/pdf/2510.25939); [HoneyLLM author PDF](https://www.cse.psu.edu/~sxz16/papers/HoneyGPT.pdf); [HoneyGPT arXiv 2406.01882](https://arxiv.org/pdf/2406.01882); [Ozkok et al. record, Sabancı Univ.](https://research.sabanciuniv.edu/id/eprint/49551/); [Weber et al. record, DOAJ](https://doaj.org/article/17434d89860d419993a4fb5d27a65e1d)

**Other SoK statements worth cross-checking before reuse**
- SoK says HoneyGPT ran "a four-week in-the-wild deployment" and elicited "six ATT&CK techniques"; arXiv v2 of HoneyGPT says three months and "six distinct types of attack actions across five ATT&CK technologies" [P] — [SoK](https://arxiv.org/pdf/2510.25939); [HoneyGPT](https://arxiv.org/pdf/2406.01882)
- SoK's literature search ended October 2025, so it omits AdvancedShelLM, HydraPoT, Magazov et al., Honeyval, Say Shibboleth and Q-Cowrie [P] — [SoK](https://arxiv.org/pdf/2510.25939)
- The SoK discloses Gemini 2.5 Pro was used for wording and reference checking, with manual review [P] — [SoK](https://arxiv.org/pdf/2510.25939)

### Inferences
- MIRAGE's stated goal (open-source, adaptive, hybrid) matches the SoK's named engineering gap; as of Nov 2026 HydraPoT (code released) partially fills it for SSH but has no live deployment, no injection defence and no adaptive policy.
- Realistic success criteria from the SoK's framing: report all four tetrad axes; expect well under 1% (possibly ~10% after scanner filtering) of sessions to exercise the LLM; treat "about 2x Cowrie's commands per effective session" as the prior-art bar; evaluate against LLM attack agents, not only Internet noise or small human panels.
- The 99.2% vs ~90% discrepancy matters for capacity planning: with a HoneyLLM-style filter, plan for roughly one in ten sessions reaching the LLM path, not one in a hundred; HoneyGPT's raw-connection ratios (0.05%-0.6%) apply before any login succeeds.

### Gaps
- The IEEE Xplore version of HoneyLLM (CNS 2024) was not accessed; if it differs from the author-hosted PDF, the 99.2% figure could originate there.
- Weber et al. and Ozkok et al. full texts were not read.
- SoK v1-v3 were not diffed against v4; all quotations are from v4 (7 Apr 2026).
