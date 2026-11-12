# MIRAGE

An adaptive honeypot and attack-simulation platform. Phase 0 (foundations) is built. Phase 1 (decoys and capture) is built: a hardened SSH decoy, an HTTP decoy, and Redis and MySQL decoys, all behind a policy gate; per-deployment profiles from a Debian 12 reference; honeytokens; sessions and actor links; an artifact index. Status and what is open: [phase 1 spec, section 10](docs/04-phase-1-spec.md#10-implementation-status-12-november-2026). Phase 2 (lab, labels and first models) is under way: the scenario runner and the label join work for SSH; the models are not started. See the [phase 2 spec](docs/05-phase-2-spec.md#12-implementation-status-12-november-2026).

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
6. [Research report](reports/MIRAGE%20honeypot%20build%20research.md): the evidence behind the plan.
