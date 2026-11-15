# MIRAGE

An adaptive honeypot and attack-simulation platform. Phase 0 (foundations) is built. Phase 1 (decoys and capture) is built: a hardened SSH decoy, an HTTP decoy, and Redis and MySQL decoys, all behind a policy gate; per-deployment profiles from a Debian 12 reference; honeytokens; sessions and actor links; an artifact index. Status and what is open: [phase 1 spec, section 10](docs/04-phase-1-spec.md#10-implementation-status-12-november-2026). Phase 2 (lab, labels and first models) is built and passes its gate on a lab host: an isolated attack-simulation lab with ground-truth labels, an actor classifier, a technique tagger and a shadow response policy, each chosen by a written experiment and scored on held-out data, with a frozen dataset that CI re-scores on every push. What was measured and what is open: [phase 2 spec, section 12](docs/05-phase-2-spec.md#12-implementation-status-15-november-2026).

## Quick start

Needs Docker Desktop and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

```bash
make up
```

```bash
make itest
```

`make up` writes a `.env` with random secrets and a profile seed on first run, renders this deployment's profile into `build/profile`, then builds and starts the stack. The SSH decoy's build needs the Debian 12 reference image: run `make reference-image` once first. `make itest` runs the Gate 0, Gate 1, containment and default-tell tests against the stack.

| What | Where |
| --- | --- |
| SSH decoy (Cowrie 3.1.6 + `decoys/ssh/patches`) | `ssh -p 2222 root@127.0.0.1`; the accepted root passwords are in `build/profile/cowrie/userdb.txt` |
| HTTP decoy: a generated WordPress-style company site behind an nginx 1.22 imitation | http://127.0.0.1:8081 (also `/wp-login.php`, `/phpmyadmin/`, `/wp-json/wp/v2/users`, `/feed/`) |
| Grafana: seven MIRAGE pages (Overview, Sessions, Session, Actors, Honeytokens, Artifacts, Policy), linked from a bar at the top of each | http://127.0.0.1:3300 (user `admin`, password in `.env`). Grafana reads ClickHouse as a read-only user. |
| ClickHouse HTTP | http://127.0.0.1:8123 (`mirage.events`, `mirage.session_summary`, `mirage.actor_links`, `mirage.artifacts`, `mirage.tokens`) |
| NATS monitoring | http://127.0.0.1:8222 |

Every port binds to 127.0.0.1, and the ports can be changed in `.env`. Nothing here is meant to face the internet; read the exposure checklist in the build plan first.

Other targets: `make dashboards` (regenerate the Grafana pages from `tools/grafana_dashboards.py`), `make test` (unit tests), `make lint`, `make schema` (export JSON Schema), `make probe` (SSH transport probes), `make profile` (re-render the profile), `make profile-ref` (rebuild the reference image and re-extract its facts), `make migrate` (re-apply ClickHouse DDL), `make down`, `make nuke` (also deletes data).

The default-tell checks run on their own too: `uv run python -m eval.probes.default_tells`.

### The lab and the models (phase 2)

The lab replays labelled attack scenarios against the decoys from simulated addresses, on a network with no route out. It is for a lab host only, never an exposed sensor.

```bash
make lab-seed
```

```bash
make up
```

```bash
make lab-up
```

```bash
make lab-run SCENARIOS=/lab/scenarios/smoke
```

`make lab-seed` pins the public lab seed, which every frozen dataset is rendered from. A run prints its run ID; `make dataset CAPTURE=<run> EXPLORE=<run>` exports it, and `make eval` scores the chosen models on the export and exits non-zero if a check or gate is not met.

| What | How |
| --- | --- |
| Re-score the frozen dataset against its baseline (no stack, no model needed) | `make eval-regression` |
| Train the models the workers load | `make models DATA=eval/datasets/gate2` |
| The learned tagger, live | `make ml-image` then `make tagger-model` (Docker, CPU), or `make tagger-model-host` (add `GPU=1` after `make gpu-env` on a host with an NVIDIA GPU) |
| The whole phase 2 gate | `make gate2` |
| Copy this checkout to a lab host, history included, so runs there record the right commit | `tools/lab-host/sync.sh user@host` |
| A lab host's root steps for phase 3 (GPU in containers, the sandbox runtime) | on the host: `sudo bash tools/lab-host/install-runtimes.sh` |
| Model experiments | `uv sync --group research`, then the scripts in `intel/src/mirage_intel/experiments/`; results in [docs/experiments/phase-2](docs/experiments/phase-2/) |

Which models run, and why, is in `eval/choices.yaml`. Grafana gains an Alerts page and a Lab page (runs, join health, the harness's metrics and gates).

Replay a sample of the public Cowrie corpus (Zenodo 21260400, CC BY 4.0) through the pipeline:

```bash
uv run python tools/seed_sample.py sample ../logs_by_day/2025-06-27.json.gz --lines 20000
```

```bash
uv run python tools/seed_sample.py replay data/seed/2025-06-27.json.sample.json
```

## Layout

| Path | Contents |
| --- | --- |
| `schema/` | Event envelope (OCSF-aligned), ground-truth record, source mappings |
| `pipeline/` | Normaliser (NATS → MirageEvent → ClickHouse), sessioniser (sessions, honeytoken findings, actor links), artifact indexer, label join for lab runs |
| `lab/` | Simulation lab: the scenario runner, its procedure catalogue and scenarios. Runs only on its own isolated network (`make lab-up`, `make lab-run`). |
| `policy/` | Policy service: gate contract v1, YAML rules, decision log |
| `decoys/` | Cowrie patch series (`ssh/`), HTTP decoy, shared decoy library, profile generator and Debian 12 reference, honeytokens, and the Redis and MySQL decoys (`db/`) |
| `compose/` | Docker Compose stack and service configs |
| `tests/integration/` | Gate 0, Gate 1, containment and default-tell tests |
| `eval/probes/` | SSH transport probes and the default-tell checks |
| `spikes/` | Week-1 experiments and their results |
| `tools/` | Corpus sampling and replay |
| `docs/` | Plan, architecture, AI/ML design |

## Read in this order

1. [Build plan](docs/01-build-plan.md): phases, gates, decisions, phase 0 and phase 1 status.
2. [Spike results](spikes/README.md): the Cowrie policy gate (S1) and SSH transport probes (S3).
3. [Architecture](docs/02-architecture.md): components, the Cowrie fork, event schema, containment, measured memory.
4. [AI/ML design](docs/03-ai-ml-design.md): baseline and later model per task, data, evaluation.
5. [Phase 1 spec](docs/04-phase-1-spec.md): decoys and capture, with acceptance criteria, the Gate 1 tests and the implementation status.
6. [Phase 2 spec](docs/05-phase-2-spec.md): the lab, the label join, the first models and the bandit, with the Gate 2 tests and the implementation status.
7. [Phase 2 completion plan](docs/07-phase-2-completion.md) and the [phase 2 experiments](docs/experiments/phase-2/): every gap an audit found between the phase 2 code and its spec, how each was closed, and the three model choices with their numbers.
8. [Phase 3 spec](docs/06-phase-3-spec.md): the render library, the LLM responder, the live bandit, the probe suite and the sandbox, with the Gate 3 tests. A draft; nothing in it is built.
9. [Research report](reports/MIRAGE%20honeypot%20build%20research.md): the evidence behind the plan.
