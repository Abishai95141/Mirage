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
The store also holds sessions from tests and ad-hoc runs. Freeze the dataset from one controlled
run, named by its ID, so nothing else enters it:
```
make lab-run SCENARIOS=/lab/scenarios ARGS="--seed 1 --repeat 6"   # prints the run ID
```
Then wait for `sim-join` to finalise (`SELECT * FROM mirage.sim_runs FINAL` shows the run with
`no_event = 0 AND mismatch = 0`; a run that is not settled is joined two minutes after it ends),
export, and commit the dataset as the CI fixture:
```
make dataset ARGS="--run <run ID>"        # --run may be repeated
mkdir -p eval/datasets/gate2 && cp build/dataset/*.parquet build/dataset/*.json eval/datasets/gate2/
make eval                       # writes eval/baselines/gate2.json
git add eval/datasets/gate2 eval/baselines/gate2.json
```
Gate 2 tests 2 and 5: the run must show zero `no_event`/`mismatch`; the content check
(`python -m eval.split check`) must stay clean.

### 3. The bandit explore run (Gate 2 test 8)
One target switches exploration on, drives the explore range and switches it off again, and a
second checks the logs:
```
make lab-explore SCENARIOS=/lab/scenarios ARGS="--seed 2 --repeat 20"
make explore-check ARGS="--since <UTC time the run started>"
```
Do not switch exploration on by hand and then call `make lab-run`: compose recreates the policy
service from `.env` on that call and exploration is silently off again. That is what happened on
the first live run (14 November 2026).

`explore-check` asserts Gate 2 test 8: at least 300 explore sessions and 3,000 decisions; within
each bucket the action counts agree with the logged `acting.probs` (chi-square); a uniform
target's mean importance weight is 1 within its interval; no masked action; nothing explored
outside 198.19/16, and only the rules acted elsewhere.

### 4. Re-run the gates
```
make itest       # Gate 0, Gate 1, the lab tests (Gate 2 tests 1-4), containment, tells, dashboards
```
Gate 1 must still pass with the enriched decision record and the context work in place
(including the latency test — the per-request context + tactic match must not push p95 over
20 ms). The dashboard test exercises every new panel's query (Lab, Alerts, Policy explore).

### 5. Model metrics on the frozen dataset (Gate 2 tests 6, 7)
```
make classifier  # held-out scenarios: macro-F1 beats rules-only and majority by more than its interval
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
