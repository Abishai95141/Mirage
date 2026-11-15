# Phase 2 completion plan · the gap register

Status: every row below is closed or listed as open in [section 5](#5-where-each-gap-stands) · 15 November 2026
Parent: [phase 2 spec](05-phase-2-spec.md) · Follows the first live run (spec section 12) and an independent audit of the code against the spec.

Phase 2 was built while Docker was down and declared mostly done. The first live run found four defects, and an audit that read every requirement against the code found many more. The worst of them share one shape: something passes without measuring what the spec asks. This document lists every gap, what closes it, and how to tell it is closed. Nothing here is a new requirement; each row cites the spec line it serves.

## 1. Rules for closing a gap

1. **A gate reads what the system produced.** A test that asserts a tactic, a class or an alert reads the tagger's, the classifier's or the alert worker's output, never a `sim_*` table. Ground truth is only what a prediction is compared with.
2. **Every gate can fail, and failing exits non-zero.** A skipped test, a missing metric or an empty split is a failure in a gate run.
3. **Every comparison has an interval, over the unit that is independent.** Scenarios for sessions, procedures for commands, sessions for decisions. Repeats of one scenario are not new evidence.
4. **Held-out data covers the catalogue.** A score over the half of the test procedures that scenarios happened to use is not a held-out score.
5. **Models are chosen on dev and scored on test once.** The experiment scripts refuse the test split unless asked for the final report.
6. **A choice of model or architecture is an experiment with a written result**, in `docs/experiments/phase-2/`: the candidates, the protocol, the numbers and the reason for the pick.

## 2. Gap register

Lanes: **L** lab runner · **P** pipeline · **D** dashboards and policy service · **M** models and experiments · **H** harness, CI and docs.

### Measurement validity

| ID | Gap (spec) | What closes it | Closed when | Lane |
| --- | --- | --- | --- | --- |
| V1 | The demo tests assert tactics from `sim_steps` and actor class from `sim_sessions`, which are the scenario's own labels; skipped steps count; no test reads `mirage.alerts` (2.8, Gate 2 tests 3 and 4) | Demos assert `mirage.labels` (tagger), `mirage.actor_class` (classifier) and `mirage.actor_alerts`; ground truth appears only as the expected value | The demo tests fail with the tagger or classifier worker stopped | M, P |
| V2 | Alerts are one row per connection with one address, so "one alert naming both sessions" cannot be expressed (2.7, 2.8) | `mirage.actor_alerts`: one row per actor, listing its sessions, addresses and classes | Demo 2 yields one actor alert with two sessions and two addresses | P |
| V3 | Scenarios exercise 139 of 205 procedures, and 20 of the 41 held-out ones (section 5) | Generated coverage scenarios, from IDs only (`mirage_lab.generate`) | A test asserts every procedure is exercised. **Done.** | L |
| V4 | The tagger scorer has no interval, builds its baseline from test labels, and lacks parent-folded F1, per-session tactic precision and recall, F1 by source, and the unseen-technique split (2.4, Gate 2 test 7) | A scorer with the whole table of 2.4; baseline from the training split; intervals that resample procedures | Each number in 2.4's "Reported" paragraph is in the report | M |
| V5 | No de-duplication; identical gated commands can sit on both sides of the split (section 5, items 3 and 7) | Score unique normalised inputs; report test inputs whose normalised form occurs in train or dev apart, and keep them out of the headline | The report states both counts | M |
| V6 | The session export repeated one logical session once per connection (2.2) | One row per logical session | **Done** in the export; a test guards it | M |
| V7 | Rule-settled sessions are right by definition, and the classifier gate counts them (2.3, Gate 2 test 6) | Gates on the sessions the rule leaves to the model; the all-session figure is reported beside it | The gate names the population it is computed on | M |
| V8 | `decisions` and `fallbacks` are classifier features, and both describe our own policy service, not the actor (2.3) | Removed; keystroke features added from the TTY logs (2.0) | The feature list is behaviour only; an ablation shows what each group adds | M |
| V9 | The "no lab marker" check compares two constants (section 5, item 8) | A test on the real Parquet schema against an allowlist, and a scan of `steps.input` for lab addresses, IDs and marker words | The test fails when a `sim_*`, address or time column is added | M |
| V10 | The reward pays each item once, to the first decision that reaches it; the spec pays every decision for what follows it in its session. Nothing computes it from stored events (2.5) | Reward-to-go as specified, built from the store, from tagger labels and, in the lab, from ground truth, with the difference reported | Unit tests state the spec's sentence case by case; a report from the live explore run | M |
| V11 | The explore check reads only the policy service's log; a decoy that fell back applied `allow` while the log says otherwise (Gate 2 test 8) | Join each logged decision to the decoy's own decision event; exclude fallbacks from learning and count them; check applied equals logged | The check fails on a log whose applied action differs | M |
| V12 | The estimators' bootstrap resamples decisions, not sessions (Gate 2 test 9) | Resample sessions | Interval width grows on clustered synthetic logs, and the test shows it | M |
| V13 | The "shadow policy" is the acting epsilon-greedy policy; no model is trained; explore decisions log no shadow (2.5, Gate 2 test 9) | A model trained offline from the explore logs, loaded read-only by the policy service and logged on every decision; its value against the rules' reported with intervals | The policy service logs a second, different distribution; the report exists | M, D |
| V14 | The dataset export does not refuse a run with `no_event` or `mismatch`, does not require `final` for sessions, hashes one table of two, and drops unknown scenarios silently (2.2, Gate 2 test 2) | Refuse; require; hash both; count and fail on drops; manifest carries scenario, split, seed and code hashes | Export fails on an unhealthy run | M |
| V15 | Datasets came from a random deployment seed (Q16) | `make lab-seed` pins the public lab seed; the freeze step refuses any other | A dataset from another seed cannot be frozen | H |
| V16 | Technique IDs are checked by pattern only; nothing checks them against ATT&CK v20.1 (Q14) | The catalogue and rules validated against the pinned v20.1 file; tactics derived from it | Lint fails on an ID v20.1 does not have | M |

### Gates that cannot fail

| ID | Gap | What closes it | Lane |
| --- | --- | --- | --- |
| F1 | `make eval` exits 0 whatever the gates say; `make gate2` cannot fail on tests 2, 5, 6, 7 or 8 and reads every capture run in the store | `make gate2` names its runs, runs every check, and exits non-zero on any | H |
| F2 | Integration tests skip when the lab is down, and a skip is green | `MIRAGE_REQUIRE_STACK=1` turns those skips into failures; CI and `gate2` set it | H |
| F3 | The regression check uses a fixed 0.05 and skips metrics absent from the baseline (2.6, Gate 2 test 10) | Compare against the baseline's own interval; a metric missing on either side fails; a test lowers a metric and sees the job fail | H |
| F4 | The harness does not run the section 5 checks before reporting (2.6) | It runs them and refuses to report on failure | H |
| F5 | `eval-regression` is an `echo`; CI runs only on `main` and pull requests, so the demos have never run in CI; `uv sync --frozen \|\| uv sync` hides a stale lock | A frozen lab-seed dataset and a real job; CI on `phase-*` pushes; `--frozen` only | H |
| F6 | The lab-profile containment claim is a string search in `compose config`; the runner probe fails at DNS, not routing (Gate 2 test 1) | Probe by address; send a PROXY header through the real edge and assert it is not believed; assert `mirage_lab` is internal and who is on it | L, H |
| F7 | The lint's one-split rule is never given the split at run time; it checks only a step's own IDs (section 3) | Runner and CLI load the frozen split; inputs are checked against every catalogue and scenario ID | L |

### Missing pieces

| ID | Gap (spec) | What closes it | Lane |
| --- | --- | --- | --- |
| M1 | Keystroke statistics (2.0) | `ttystats`, `mirage.tty_stats`, `mirage.tty_by_session`. **Done**; on the first live data human-paced sessions are 99% single-key writes with about three corrections, bots none | P |
| M2 | Tagger layers 2 and 3, and the technique rules (2.4) | Learned layers chosen by experiment; LogPrécis as the tactic baseline. The hand-written rules stay with the other tool and are no longer needed to pass | M |
| M3 | Classifier: two variants, the real-traffic check, the novelty feature (2.3) | Event-level and full models; agreement with heuristic labels on the Zenodo sample; novelty against that corpus | M |
| M4 | No classifier worker, so no predicted class on any page or alert (2.3, 2.7) | A worker that writes `mirage.actor_class` and recomputes as a session grows | M |
| M5 | Session and Sessions pages show no tags or class; the Lab page no split sizes, metrics or baselines; the Policy page no shadow agreement; the heatmap is a time series with no by-class view (2.7) | Panels for each, reading `mirage.labels`, `mirage.actor_class`, `mirage.actor_alerts`, `mirage.eval_metrics` | D |
| M6 | `make lab-human` does not exist (Q8) | A recorder: a person types through the lab edge; the session is recorded as real and human | L |
| M7 | Explored `fake_error` is empty output with exit code 1 for every verb and protocol; the mask has no per-protocol part; no policy version is logged; the verb is raw, not a class (2.5) | A per-protocol, per-verb error table; a mask that knows what each protocol can express; versions in the record | D |
| M8 | MLflow tracking (2.6) | The experiment scripts log to a local MLflow store | M |
| M9 | Demo 2's attacker takes the database password from the profile, not from the response it just read (2.8) | A step can capture a value from its output and a later login can use it | L |

### Robustness

| ID | Problem | What closes it | Lane |
| --- | --- | --- | --- |
| R1 | An SSH failure path leaves a session with no start time; its ground-truth record raises outside the guard, is never written, and every step of that session becomes `no_event`. The likely cause of the six in the first explore run | Always stamp the session; a regression test drives the failure path | L |
| R2 | The join never compares the run record's session and step counts with what arrived; invalid records are acknowledged and dropped; a run with no closing record is never joined or shown | Health columns for missing sessions and steps; a run without its closing record is joined as incomplete after a wait and shown as such | P |
| R3 | A session whose honeytoken trigger is its last event gets no alert: the tagger reads rows the sessioniser writes later | A reconciliation sweep recomputes alerts for recently changed sessions | P |
| R4 | The brute-force session rule needs three failures and a success in one session, but each connection is a session | Session rules read the logical session or actor | P |
| R5 | The simulated address pool wraps, against section 2; the ground-truth file grows without bound | Refuse to reuse an address; rotate the file per run | L |
| R6 | The policy context evicts by creation order, so a long session loses its state; `seen_before` is per session where the spec says per process; a missing `seq` masks `terminate` for ever | Evict least recently used; fix the two | D |
| R7 | The join accepts an `auth` step on any one event, and a non-SSH step without its content event | Count the attempts; require the content event | P |

### Claims to correct

Spec section 12 calls 2.7 and 2.8 done, says the export reads no command text (the steps table does), and carries stale counts. The README still says the models are not started. All are rewritten when the rows above close.

## 3. Decisions made by experiment

Each gets a page in `docs/experiments/phase-2/`. Selection uses train and dev; the test split is read once, for the final table.

| Decision | Candidates | Chosen by |
| --- | --- | --- |
| Tagger | Most-frequent baseline; rules; character n-gram linear model; nearest-neighbour retrieval over training procedures and ATT&CK technique text with each of several embedding models; LogPrécis at tactic level; combinations with abstention | Technique micro-F1 on dev over techniques seen in training, interval by procedure; abstention and unseen-technique behaviour reported |
| Embedding model | A general small model, a security-domain bi-encoder (SecureBERT 2.0), a shell-domain encoder (SecureShellBert), and a non-neural TF-IDF baseline. CmdCaliper is excluded: gated, no licence stated, trained on Windows command lines | The same |
| Classifier | Rules only; logistic regression; random forest; gradient boosting; each on event-level, keystroke-level and both feature sets | Macro-F1 on held-out scenarios over the sessions the rule leaves, interval by scenario; the simplest family shown to be within 0.02 of the best by a paired comparison (the first wording, "within the best one's interval", was too loose and was replaced before the choice was made) |
| Policy learner | The rules; Vowpal Wabbit contextual bandit with inverse-propensity, doubly robust and direct-method cost estimates; a per-context empirical best action | Doubly robust value on held-out explore sessions, interval by session; the other estimators must agree in sign |

## 4. Order

1. Foundations that change the data: lint, coverage scenarios, the lab seed, keystroke statistics, the runner and join fixes.
2. Collect: one capture run of every scenario, one explore run, the real-traffic sample.
3. Experiments on the exported data; decisions written down.
4. Serving: the tagger's learned layer, the classifier worker, the trained shadow policy, actor alerts, dashboards.
5. Gates: demos on real output, the harness that can fail, the frozen dataset, CI.
6. One clean live run of `make gate2` on the lab host, then the spec's status is rewritten from what it measured.

## 5. Where each gap stands

Closed means the code is in, it has a test that fails without it, and where it touches the running system it was exercised on the lab host. The measured results are in [the spec, section 12](05-phase-2-spec.md#12-implementation-status-15-november-2026).

| Rows | State | How it was checked |
| --- | --- | --- |
| V1, V2, M9, R3, R4 | Closed | The demo tests read `mirage.labels`, `mirage.actor_class` and `mirage.actor_alerts`. Demo 2 asserts one actor alert naming both sessions and both addresses, and the attacker logs in with the password it captured. They pass live and cannot pass with the tagger or classifier worker stopped. |
| V3, F7, R1, R5 | Closed | Generated coverage scenarios; the runner refuses without the split; the failure path writes its session record. The harness check `held_out_coverage` finds all 41 test procedures in the collection. |
| V4, V5 | Closed | The scorer reports every figure of 2.4 with intervals by procedure. The leak guard holds every text the model was fitted on, in the unit it reads, and the report counts what it dropped and what shares one gated command with the index. |
| V6, V7, V8 | Closed | One row per logical session; the gate is computed on the sessions the rule leaves; features are behaviour only, with the ablation in the classifier experiment. |
| V9, F4 | Closed | The harness reads the Parquet schema against the allowlist and scans every input for lab addresses, IDs and marker words, before reporting anything. A test adds a `src_ip` column and a lab address and sees both checks fail. |
| V10, V11, V12 | Closed | Reward-to-go with the spec's sentence as unit tests; decisions joined to what the decoy applied, fallbacks excluded and counted; intervals resample sessions. |
| V13, M7, R6 | Closed | A linear model trained offline shadows on every decision, loaded by the policy service through the code that trained it; a parity test compares the two. Its value against the rules' is reported with an interval. |
| V14, V15 | Closed | The export refuses an unhealthy run; `make freeze` refuses anything not rendered from the lab seed, and a failed freeze leaves nothing behind. |
| V16 | Closed | `python -m mirage_intel.attack check` validates every catalogue and rule ID against the pinned v20.1 index, in CI. It found five labels on techniques v20.1 had replaced. |
| F1, F2, F3 | Closed | `make gate2` stops at the first failing step. `MIRAGE_REQUIRE_STACK=1` turns a missing stack into a failure. The regression check fails on a metric below the baseline's interval, a metric missing on either side, a lost gate, another dataset or another choice of models; each has a test. |
| F5 | Closed in the repository, **not yet run on GitHub** | CI runs on `phase-*` branches, uses `--frozen` only, and `eval-regression` is a real job on the frozen dataset. It first runs when the branch is pushed. |
| F6 | Closed | The runner's reach is probed by address; a PROXY header sent through the real edge is not believed; the lab network is internal and holds only the lab edge. |
| M1, M4, M5, M8 | Closed | Keystroke statistics; the classifier worker; the dashboard panels, each query run against the live store by a test; MLflow logging in the experiment scripts (best effort: a locked store never stops an experiment). |
| M2 | Closed | The learned layer was chosen by experiment and runs live, from Docker or from the host (CPU or GPU). Its labels were read back from the store and match the offline answer on all 246 held-out steps. The hand-written rules and LogPrécis were measured and dropped as input-level layers. |
| M3 | **Partly open** | Done: event-level and full variants, and the real-traffic check (`mirage_intel.realcheck`). Not built: the novelty feature. |
| M6 | Closed, **unused** | `make lab-human` records a person's session as real and human. Nobody has been recorded yet. |
| R2, R7 | Closed | The join's health columns, the incomplete-run path, and the content-event requirement, with tests. |

Found on the way, and fixed:

- **The first collection attempt could not start.** The new worker image was missing from the Docker allowlist, and `make up` waited for workers that needed a table the migration created only afterwards. Neither had ever run. A small end-to-end pass now comes before any long run.
- **A feature bug hid for a day.** A `coalesce` on a join that returns empty strings, not NULLs, zeroed the timing features of every SSH session. The export now fails if timing features are flat.
- **An independent review of the new code found nine defects**, among them: a line whose commands arrive seconds apart could keep two labels; a frozen index was used without checking it was the chosen model's; the split column was never compared with the frozen split. Each has a test now.
- **The classifier's first result was a labelling problem, not a model problem.** See the classifier experiment.
- **The full run showed three more.** The tagger's worker asked the model about one input at a time and starved the policy service of CPU (the decoys fell back on 2.4% of decisions); ties in the tagger's index were settled by floating-point noise, differently on two machines; and the frozen vectors were stored at half precision. All three are fixed and described in the spec's section 12.
