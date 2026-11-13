# Finishing Phase 2 — completion runbook

Everything in Phase 2 is built and unit-tested on the `phase-2` branch. What remains is the
work that needs the live stack (Docker) or the offensive technique rules, plus the Gate 2
checks that confirm it. This runbook is the exact sequence; `make gate2` chains the stack-up
steps.

## Blocked on, in order

1. **Docker running.** Every step below that touches the stack needs it. Nothing here runs
   while the daemon is down.
2. **The technique rules** (`intel/rules/*.yaml`) from the catalogue tool
   (`docs/handoffs/phase-2-technique-rules.md`). Without them the tagger only recognises the
   benign discovery starters, so Gate 2 test 7 cannot pass meaningfully. Everything else can be
   finished and checked before they land.

## Steps

### 1. Bring the stack up and smoke it
```
make up          # core stack: decoys, policy, pipeline, clickhouse, grafana, tagger-worker
make lab-up      # lab-edge + sim-join (profile: lab)
```
Confirm every container is healthy (`make ps`). `tagger-worker` is new this phase — check it is
`healthy`.

### 2. Freeze a balanced dataset
The dev store is skewed (ad-hoc runs piled into train). Freeze a clean one from a single
controlled run that exercises every split in balance:
```
make lab-run SCENARIOS=/lab/scenarios ARGS="--seed 1 --repeat 6"
```
Then wait for `sim-join` to finalise (`SELECT * FROM mirage.sim_runs FINAL` shows the run with
`no_event = 0 AND mismatch = 0`), export, and commit the dataset as the CI fixture:
```
make dataset
mkdir -p eval/datasets/gate2 && cp build/dataset/*.parquet build/dataset/*.json eval/datasets/gate2/
make eval                       # writes eval/baselines/gate2.json
git add eval/datasets/gate2 eval/baselines/gate2.json
```
Gate 2 tests 2 and 5: the run must show zero `no_event`/`mismatch`; the content check
(`python -m eval.split check`) must stay clean.

### 3. The bandit explore run (Gate 2 test 8)
Restart the policy service with exploration on, drive the explore range, confirm ≥300 explore
sessions with propensities that match the observed action frequencies:
```
POLICY_EXPLORE=lab docker compose --env-file .env -f compose/docker-compose.yml up -d --force-recreate policy
make lab-run SCENARIOS=/lab/scenarios ARGS="--mode explore --seed 2 --repeat 10"
```
Check: `SELECT countIf(JSONExtractBool(payload,'explore')) FROM mirage.events WHERE source='policy'`
≥ 300 sessions' worth of decisions; per context bucket the action frequencies agree with the
logged `acting.probs` (chi-square); no masked action taken; nothing acted outside 198.19/16.
Turn exploration back off afterwards (recreate `policy` with `POLICY_EXPLORE=`).

### 4. Re-run the gates
```
make itest       # Gate 0, Gate 1, the lab tests (Gate 2 tests 1-4), containment, tells, dashboards
```
Gate 1 must still pass with the enriched decision record and the context work in place
(including the latency test — the per-request context + tactic match must not push p95 over
20 ms). The dashboard test exercises every new panel's query (Lab, Alerts, Policy explore).

### 5. Model metrics on the frozen dataset (Gate 2 tests 6, 7)
```
make classifier  # macro-F1 beats rules-only and majority on the held-out split
make tagger      # with the real rules: technique micro-F1 beats most-frequent, by source
```

### 6. Gate 2 and merge
When tests 1-10 pass (test 8's explore data collected, tests 6/7 beating their baselines on the
frozen split), update `docs/05-phase-2-spec.md` section 12 to "Gate 2 passed", open the PR so CI
runs lint-unit + ml + integration, and merge `phase-2` to `main`.

## The eval-regression CI job

`.github/workflows/ci.yml` has an `eval-regression` job that runs `python -m mirage_intel.harness
check` against the committed `eval/datasets/gate2` fixture. It is a no-op until that fixture is
committed (step 2), then it fails any PR that drops a tracked metric below its baseline.
