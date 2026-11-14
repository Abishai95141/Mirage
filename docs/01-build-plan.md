# MIRAGE build plan

Status: draft for review · 11 November 2026, phase 1 tightened and built (except 1.5) 12 November
Inputs: the technical report (11 Nov 2026) and the research in [`reports/MIRAGE honeypot build research.md`](../reports/MIRAGE%20honeypot%20build%20research.md)
Companion docs: [architecture](02-architecture.md) · [AI/ML design](03-ai-ml-design.md) · [phase 1 spec](04-phase-1-spec.md) · [phase 2 spec](05-phase-2-spec.md) · [phase 3 spec](06-phase-3-spec.md)

## 1. What we are building first

A working closed loop on one laptop, then on one Linux host:

1. An attacker (real or simulated) talks to an SSH, HTTP or database decoy.
2. Every command passes through a policy gate that decides how the decoy answers.
3. Every event lands in one normalised schema, is grouped into sessions, and is stored.
4. A scenario runner replays labelled attack scenarios against the decoys and publishes ground-truth ATT&CK labels.
5. Models trained on those labels classify the actor and tag the session, and a bandit learns which responses yield more intelligence.
6. A dashboard shows sessions, tags and alerts.

That is the MVP (phases 0–2, about 10–12 weeks for 3–4 people). The LLM responder, the high-interaction sandbox, campaign correlation, agent detection and federation come after, each behind its own gate.

## 2. Decisions that change the technical report

The research supports the report's overall shape and corrects these parts. Each row is a decision this plan assumes; say so if you disagree with any of them.

| # | Report said | Plan does | Why |
| --- | --- | --- | --- |
| D1 | Kafka/Redpanda, Flink/Faust, OpenSearch + ClickHouse, MinIO, Feast | Vector → NATS JetStream → plain Python normaliser → single-node ClickHouse; Parquet + DuckDB for training data; files on disk for samples; no feature store | The report's stack does not fit in 16 GB beside a local LLM. Faust is inactive and MinIO's community repo is archived. Event volume is a few per second. Revisit when a single host can no longer keep up. |
| D2 | ECS-compatible schema | Pydantic models aligned to OCSF 1.9, with ECS field names as a secondary projection | OCSF has classes for network, process and (since 1.8/1.9) AI activity. No published Cowrie → OCSF mapping exists, so the mapping is ours to write. |
| D3 | "Thin adapter" on Cowrie | A thin, pinned **fork** of Cowrie (BSD-3) | Cowrie has no pre-execution hook, and its backend is one of shell, proxy or LLM. The gate has to live in `shell/honeypot.py` (verified at HEAD). |
| D4 | qeeqbox as the database decoy base; Galah-style web fallback | Write the HTTP decoy (FastAPI) and the database decoys ourselves; reuse Galah's prompt and response contract (Apache-2.0) | qeeqbox is AGPL and captures credentials only. Nothing permissive offers query-level emulation. Galah and Beelzebub are Go. |
| D5 | Beelzebub, Conpot, T-Pot, Canarytokens as components | Run them only as separate, unmodified containers; copy no code or config from them | They are GPL/AGPL. Mixing their code into an Apache-2.0/MIT project is a licence conflict. |
| D6 | LogPrécis-style tagger extended to techniques | Three steps: LogPrécis for tactics now, retrieval over ATT&CK for techniques next, a fine-tuned encoder once lab labels exist | LogPrécis has seven labels (five tactics) from 360 sessions. No technique-level tagger for shell sessions exists. |
| D7 | ET-BERT and E-GraphSAGE flow classifiers | Drop both. Gradient-boosted trees on Zeek/Suricata features, used only for tool and attack-type tagging | ET-BERT falls from 97.4% to 28.0% accuracy under a per-flow split (SIGCOMM 2025). On a honeypot all traffic is hostile, so benign-vs-malicious has little value. |
| D8 | Heterogeneous GNN for campaigns | Weighted shared-indicator graph with Leiden clustering | No evidence was found that a GNN beats simple graph methods here, and no labelled campaign data exists to train one. |
| D9 | DQN/PPO pre-trained in CyberBattleSim/CybORG | Rules plus a contextual bandit with an action mask; a custom replay environment; deep RL only if the data later supports it | Prior honeypot RL is all tabular. The cyber gyms model network-level defence, not per-command response choice. |
| D10 | Llama-3-8B/Qwen-2.5 via vLLM/Ollama answering unknown commands live | Profile-dependent commands are pre-rendered offline per profile and served instantly; the live LLM (an ~8–9B GGUF model under `llama-server`, state outside the prompt) answers only novel commands, streams its output, and runs on the Linux host's GPU from phase 3 | Spike S2 (Nov 2026): Qwen3.5-9B on the M4 generates 12.5 tokens/s, median 8.6 s per command even with prompt caching, 0 of 150 under 1.5 s, and takes about 9 GB. vLLM has no first-party Apple GPU support. See [spike results](../spikes/README.md#s2--local-llm-latency). |
| D11 | Flower with SecAgg+ **and** robust aggregation **and** DP | Phase 5 chooses one of secure aggregation or robust aggregation; the exit gate is an honest comparison, not "federated beats local" | SecAgg+ only works on Flower's legacy API. Robust aggregation needs the per-client updates SecAgg hides. Krum needs at least 5 sites to tolerate one bad one. |
| D12 | "Unfingerprintable", detectability as a CI gate | Keep the CI gate; scope the claim to "passes the known probe set". Phase 1 trims Cowrie's configurable algorithm extras; phase 3 decides on a real OpenSSH front end | Spike S3 (Nov 2026): Bitter Harvest's padding tell is fixed upstream, but Cowrie's algorithm list (HASSH-server) identifies it from one passive packet, and Twisted cannot implement what is missing. See [spike results](../spikes/README.md#s3--ssh-transport-probes). |
| D13 | "99%+ of traffic is scanning" | Use "about 90%" | The paper the SoK cites reports about 9.8% effective sessions. Routing scanners away from the LLM still pays. |
| D14 | Caldera runs against the honeypot fleet | A scenario runner drives the medium-interaction decoys; Caldera (apache/caldera 5.3.0) drives the high-interaction sandbox from phase 3 | Caldera's agent has to execute on a real host. An emulated Cowrie shell cannot run it. |
| D15 | Everything on Docker | High-interaction mode, eBPF sensors and gVisor run on a Linux host only | Cowrie's backend pool needs QEMU/KVM; Tetragon and Tracee do not support Docker Desktop for Mac. |

## 3. Open decisions for you

These block specific phases, not the start.

| Decision | Needed by | Default if you say nothing |
| --- | --- | --- |
| Project licence | Phase 0 | Apache-2.0 |
| May attacker input ever be sent to a cloud LLM API? | Phase 3 | No; local model only |
| Linux host for the high-interaction sandbox and the first external sensor (provider, budget) | End of phase 1 | A small VPS from a provider whose terms allow honeypots; check the AUP in writing first (DigitalOcean requires prior consent for security research) |
| Who authorises internet exposure and the rules of engagement for the lab | Before the first external sensor | No external exposure until this exists |
| Team size and hours | Phase 0 | 3–4 people as in the report; durations stretch roughly in proportion otherwise |
| Keep Cowrie's vendored JA4+ code (FoxIO licence bars commercial use) | Before any commercial use | Remove it in the fork |

## 4. Risk spikes (week 1)

Results are in [spikes/README.md](../spikes/README.md): S1 passed (2.4 ms per command), S2 showed live generation on the laptop is far too slow (median 8.6 s per command), and S3 found a transport tell other than the one expected.

Three short experiments run before the plan hardens, because each could change it.

| Spike | Question | Method | If the answer is bad |
| --- | --- | --- | --- |
| S1 · Cowrie gate | Can a fork consult an external service before every command, asynchronously, without breaking pipes, `sudo` or `busybox`? | Patch `_run_expanded` in `shell/honeypot.py` and `getCommand`/`call_command` in `shell/protocol.py`; call a stub HTTP service with treq; run Cowrie's own test suite | Fall back to a gate that only covers top-level commands, and record the bypasses as known gaps |
| S2 · LLM latency | What time-to-first-token and tokens/sec does an 8–9B Q4 model give on the M4 with the rest of the stack running? | `llama-server` native on macOS, 50 representative shell prompts, with and without prompt caching | Drop to a 4B model, or move the LLM to the Linux host with a GPU |
| S3 · Transport tell | Does Cowrie HEAD still fail the Bitter Harvest SSH probes (KEXINIT padding, bad-version string)? | Re-implement the two probes as tests against stock Cowrie and against real OpenSSH | Plan a front-end fix in phase 3 (patch Twisted Conch, or terminate SSH on a real OpenSSH and proxy) |

## 5. Phases

Each phase ends at a gate. Work does not start on the next phase until the gate passes or the gate is consciously changed.

### Phase 0 · Foundations (weeks 1–2)

Goal: one honeypot's events flow end to end, inside a network that cannot reach the internet.

| Work package | Deliverable |
| --- | --- |
| 0.1 Repo and tooling | Monorepo, `uv` workspace, Python 3.12, ruff, pytest, pre-commit, GitHub Actions |
| 0.2 Compose stack | `make up` starts stock Cowrie, Vector, NATS, normaliser, ClickHouse, Grafana |
| 0.3 Event schema v0 | Pydantic models, JSON Schema export, Cowrie mapping, schema tests |
| 0.4 Containment baseline | Decoy network with no route out; a test that fails if any decoy container can reach the internet |
| 0.5 Spikes S1–S3 | A one-page result for each |
| 0.6 Seed data | Download the Zenodo Cowrie corpus (38M sessions, CC BY 4.0) and load a sample through the normaliser |

**Gate 0:** a scripted SSH login appears as a normalised session in ClickHouse and on a Grafana panel; the egress test passes; the three spike results are written up.

**Status (11 November 2026):** passed.

| Work package | State |
| --- | --- |
| 0.1 Repo and tooling | Done. `uv` workspace (`schema`, `pipeline`), ruff, pytest, pre-commit, GitHub Actions (lint and unit, integration against the real stack, Cowrie fork against Cowrie's own suite). |
| 0.2 Compose stack | Done. `make up`; measured footprint about 0.9 GB for all seven services. |
| 0.3 Event schema v0 | Done. OCSF-aligned envelope, ground-truth record, JSON Schema export, Cowrie mapping covering every documented session event. |
| 0.4 Containment baseline | Done. Decoy network has no route to the internet (IPv4 and IPv6), the pipeline or the host; six integration tests with a positive control. |
| 0.5 Spikes | All three done; results in [spikes/README.md](../spikes/README.md). |
| 0.6 Seed data | Done for a sample. Range requests pull one day from the corpus without downloading the 19 GB archive; 20,000 records replayed through the pipeline with none rejected. |

**Found in phase 0 that changes later phases**

- Cowrie ships its own OCSF mapping (`core/ocsf.py`, OCSF 1.8). Our mapping follows its class choices.
- Cowrie accepts the PROXY protocol (`haproxy:` endpoints). The SSH edge uses it, so sessions carry the client's address.
- The Zenodo corpus is a flattened export with pseudonymised IPs, not raw Cowrie logs. The schema gained `Endpoint.pseudonym`, which phase 5 will also need for cross-site sharing.
- The policy service in phase 1 must listen dual-stack, keep connections alive and disable Nagle (S1).
- Phase 3's responder work starts with offline pre-rendering per profile and a fidelity check against a real Debian container, not with live generation (S2). The Linux host needs a GPU for the live model.

### Phase 1 · Decoys and capture (weeks 3–5)

Goal: three protocols, each behind the policy gate, with full session capture.

The full specification, with acceptance criteria for every package, is in [04-phase-1-spec.md](04-phase-1-spec.md). It settles ten gaps in the earlier draft (its section 1). The ones that change this plan:

- Decoys reach the policy service over a separate internal gate network.
- Honeytokens are planted when the profile is generated, and detected in the pipeline.
- The HTTP cache moves to phase 3.
- The default-tell checks are written now, not in phase 3.
- All distribution facts come from a pinned Debian 12 reference image.

| Work package | Deliverable |
| --- | --- |
| 1.1 Cowrie fork | A patch series on pinned v3.1.6. Contains: the S1 gate; unknown commands routed to the gate; `cowrie.fs.change` events from the filesystem mutators; JA4+ removed; key exchanges OpenSSH 9.2p1 never offered removed |
| 1.2 Policy service v0 | FastAPI, gate contract v1 for all four protocols. Rules only, from YAML. Returns allow, fake_success, fake_error, delay or terminate. Bearer token, dual-stack, keep-alive, p95 under 10 ms. Every decision logged with its rule and rules version |
| 1.3 SSH profile hardening | Debian 12 reference image; per-deployment profile generator for all four services; default tells removed; configurable algorithm extras trimmed; default-tell checks for every protocol |
| 1.4 HTTP decoy | FastAPI imitating the profile's nginx: planted endpoints, nginx-identical errors, every request gated, no outbound requests |
| 1.5 Database decoys | Redis 7.0 (RESP2 and inline commands) and MariaDB 10.11 (handshake, native auth, a defined query subset over per-source SQLite) with Faker data. Classic attacks are recorded, and `LOCAL INFILE` is never requested. PostgreSQL after the MVP |
| 1.6 Honeytokens | A library and CLI. Tokens are minted and planted by the profile generator; a pipeline matcher emits `token.triggered` |
| 1.7 Sessioniser | `session_summary` for all protocols; fingerprints; `actor_links` (honeytoken use, HASSH plus credentials, source address) |
| 1.8 Artifact store | Files named by hash, mode 0400, on volumes mounted read-write only by their writer; an index table; size caps; never executed |

**Status (12 November 2026):** built and tested on the laptop, including 1.5 (the Redis and MySQL decoys). All ten Gate 1 tests pass. Details: [spec section 10](04-phase-1-spec.md#10-implementation-status-12-november-2026).

**Gate 1:** the ten tests in [spec section 6](04-phase-1-spec.md#6-gate-1) pass in CI. In short:

- A scripted session on each protocol is captured in full, as [spec section 5](04-phase-1-spec.md#5-what-captured-in-full-means) defines.
- Every input has exactly one recorded decision.
- A honeytoken read over SSH and used on MySQL links both sessions to one actor.
- The decoys keep working with the policy service down.
- The extended containment tests pass.
- The default-tell checks pass apart from listed known gaps.
- Gating adds under 20 ms at p95.

### Phase 2 · Lab, labels and first models (weeks 6–10)

Goal: the loop closes. Labelled data exists, models are trained on it, and the bandit learns in shadow.

| Work package | Deliverable |
| --- | --- |
| 2.1 Scenario runner | Runs YAML scenarios (steps tagged with technique IDs) against the decoys on the isolated network; publishes `sim.groundtruth` records |
| 2.2 Label join | Joins ground truth to captured events by scenario, source and time window; writes labelled Parquet |
| 2.3 Actor classifier v0 | Rules plus LightGBM over timing, novelty and fingerprint features |
| 2.4 Tagger v0 | LogPrécis for tactics; regex rules and retrieval over ATT&CK for techniques |
| 2.5 Bandit responder (shadow) | Contextual bandit logs what it would have chosen, with propensities; rules still decide |
| 2.6 Evaluation harness | Held-out scenario suite split by procedure; MLflow tracking; a CI job that fails on regression |
| 2.7 Dashboard v1 | Grafana: session list, replay link, tactic heatmap, alerts |
| 2.8 Demos 1 and 2 | Run in CI; expected tags and alerts asserted |
| 2.9 First external sensor (optional) | One hardened SSH decoy on the Linux host, only after the exposure checklist in section 7 is signed off |

Specified in the [phase 2 spec](05-phase-2-spec.md) (draft, 12 November 2026), which redefines demos 1 and 2 for what phases 0 to 2 contain, moves `plant_token` to phase 3 and leaves 2.9 out of the gate.

**Gate 2 (MVP):** demos 1 and 2 pass in CI with the expected tactic tags; the tagger and classifier report metrics on a held-out split that shares no procedures with training; the bandit has logged propensities for at least a few hundred lab sessions.

### Phase 3 · Adaptation and the LLM responder (5–6 weeks)

| Work package | Deliverable |
| --- | --- |
| 3.1 State manager | Per-session state (filesystem delta, cwd, processes, users, environment) held outside the prompt |
| 3.2 LLM responder | `llama-server`, constrained output, state-aware cache, per-IP and per-session token budgets, timeout that falls back to the emulator |
| 3.3 Bandit goes live in the lab | Off-policy evaluation against the rule baseline before it is allowed to act; action mask enforces safety rules |
| 3.4 Fingerprint regression suite | Extends phase 1's default-tell checks with the Bitter Harvest probes and latency-distribution checks; runs on every release |
| 3.5 High-interaction escalation | Linux host only: sandboxed real container, default-deny egress with sinkholed DNS/HTTP, reset per session |
| 3.6 Caldera in the lab | Operations against the sandbox; event logs converted to `sim.groundtruth` |
| 3.7 Tagger v1 | Encoder fine-tuned on lab labels |

Specified in the [phase 3 spec](06-phase-3-spec.md) (draft, 14 November 2026). It defines demo 3, adds the actions `respond`, `plant_token` and `escalate` (gate contract v2), puts a pre-rendered library ahead of the live model, sets up the D12 decision as a time-boxed spike, and splits the gate into a core part and a part that needs the Linux host (3.5, 3.6 and the live model's GPU numbers).

**Gate 3:** demo 3 passes; on lab scenarios the adaptive stack yields more distinct techniques per session than stock Cowrie; median LLM response time and cost per session are reported; the probe suite passes or its failures are listed as known gaps.

### Phase 4 · Correlation, agents and analyst output (4–5 weeks)

| Work package | Deliverable |
| --- | --- |
| 4.1 Campaign correlation | Shared-indicator graph, Leiden clusters, payload similarity edges |
| 4.2 Anomaly detection | First-seen counters and Isolation Forest on session features |
| 4.3 LLM-agent detector | Injection canaries plus timing features; reported as a signal with measured precision on lab agents |
| 4.4 Analyst | Retrieval-backed session summary; drafted Sigma rules validated with pySigma before a human sees them |
| 4.5 Intel export | STIX 2.1 bundles |

**Gate 4:** demo 4 passes against a lab agent; campaign clusters are shown on real or replayed data; every drafted rule parses and is tested on replayed sessions.

### Phase 5 · Federation and scale (4–6 weeks)

| Work package | Deliverable |
| --- | --- |
| 5.1 Simulation | Flower simulation with 5 virtual sites on one machine, non-IID splits |
| 5.2 Privacy choice | Decide between secure aggregation and robust aggregation, with the threat model written down |
| 5.3 Multi-node rehearsal | Flower's Docker Compose deployment across two or more hosts, versions pinned |
| 5.4 Scale-up review | Decide whether to move to Kafka and add a search store |

**Gate 5:** a written comparison of federated, local-only and centralised training at the chosen privacy setting, whichever way it comes out.

## 6. What "done" means for each model

No model is promoted on a benchmark number alone. Each must beat the incumbent on the fixed held-out scenario suite, and that suite is split by procedure so that a model cannot pass by memorising command templates. The baseline for each task is the simple method in the [AI/ML design](03-ai-ml-design.md); a deep model replaces it only when it wins there.

## 7. Safety and exposure checklist

Nothing faces the internet until every line is true.

- A named person has authorised the deployment, and the provider's terms allow it in writing.
- The decoy network has no route to anything we own, and outbound traffic is denied by default.
- Captured files are stored quarantined and are never executed outside a sandbox.
- The LLM responder has input caps, token budgets and a timeout, and degrades to the emulator.
- The lab range has no route to the internet or to production, and the scenario runner refuses any target outside the lab subnet.
- Captured data (IPs, credentials) has a retention period and an owner.

## 8. Top risks

| Risk | Sign | Response |
| --- | --- | --- |
| Lab data does not transfer to real attackers | Models score well on lab scenarios and poorly on real sessions | Evaluate on real sessions from the external sensor and the Zenodo corpus as early as phase 2; treat lab-only metrics as an upper bound |
| Label leakage from scenario templates | Near-perfect tagger scores | Split by procedure; strip technique IDs and scenario markers from commands |
| The Cowrie fork drifts from upstream (weekly releases, recent shell rewrite) | Merge conflicts in `shell/honeypot.py` | Keep the patch small and isolated; pin a commit; rebase monthly; offer the hook upstream |
| LLM latency is a tell | Responses at about 2 s where a real host answers instantly | Emulate first; shape latency from a reference host; measure in the probe suite |
| The transport-level SSH tell cannot be fixed in a profile | Confirmed by S3: the algorithm list identifies Cowrie passively | Trim configurable extras in phase 1; decide on a real OpenSSH front end in phase 3; until then state the limit plainly |
| Federation shows no benefit at small scale | Gate 5 comparison favours local-only | Ship indicator sharing (STIX) as the cross-site value; keep federation as research |
