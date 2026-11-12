# MIRAGE

An adaptive honeypot and attack-simulation platform. Phase 0 (foundations) is built: one SSH decoy, the event pipeline, storage, a dashboard, a locked-down decoy network, and the first two risk spikes.

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

`make up` writes a `.env` with random passwords on first run, then builds and starts the stack. `make itest` runs the Gate 0 and containment tests against it.

| What | Where |
| --- | --- |
| SSH decoy (stock Cowrie 3.1.6) | `ssh -p 2222 root@127.0.0.1`, any password except `root` and `123456` |
| Grafana, dashboard "MIRAGE · Sessions" | http://127.0.0.1:3300 (user `admin`, password in `.env`) |
| ClickHouse HTTP | http://127.0.0.1:8123 (`mirage.events`, `mirage.sessions`) |
| NATS monitoring | http://127.0.0.1:8222 |

Every port binds to 127.0.0.1, and the ports can be changed in `.env`. Nothing here is meant to face the internet; read the exposure checklist in the build plan first.

Other targets: `make test` (unit tests), `make lint`, `make schema` (export JSON Schema), `make probe` (SSH transport probes), `make migrate` (re-apply ClickHouse DDL), `make down`, `make nuke` (also deletes data).

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
| `pipeline/` | Normaliser: NATS → MirageEvent → ClickHouse |
| `compose/` | Docker Compose stack and service configs |
| `tests/integration/` | Gate 0 and containment tests |
| `eval/probes/` | SSH transport fingerprint probes |
| `spikes/` | Week-1 experiments and their results |
| `tools/` | Corpus sampling and replay |
| `docs/` | Plan, architecture, AI/ML design |

## Read in this order

1. [Build plan](docs/01-build-plan.md): phases, gates, decisions, phase 0 status.
2. [Spike results](spikes/README.md): the Cowrie policy gate (S1) and SSH transport probes (S3).
3. [Architecture](docs/02-architecture.md): components, the Cowrie fork, event schema, containment, measured memory.
4. [AI/ML design](docs/03-ai-ml-design.md): baseline and later model per task, data, evaluation.
5. [Phase 1 spec](docs/04-phase-1-spec.md): decoys and capture, with acceptance criteria and the Gate 1 tests.
6. [Research report](reports/MIRAGE%20honeypot%20build%20research.md): the evidence behind the plan.
