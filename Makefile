COMPOSE := docker compose --env-file .env -f compose/docker-compose.yml

.PHONY: help env profile profile-ref reference-image dashboards up migrate down nuke ps logs lab-seed lab-generate lab-up lab-run lab-explore lab-human lab-down split dataset models freeze eval eval-regression explore-check ml-image tagger-model tagger-model-host gpu-env gate2 test itest lint fmt schema probe

help:
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n",$$1,$$2}'

env: ## Create or complete .env (random secrets; never printed)
	@python3 tools/env_fill.py

reference-image: ## Build the Debian 12 reference image (the SSH decoy's build needs it)
	docker build -t mirage/reference:debian-12 decoys/profiles/reference

profile-ref: reference-image ## Build the reference image and re-extract its facts
	uv run python -m mirage_profiles.reference

profile: env ## Render this deployment's profile into build/profile (seed from .env)
	uv run mirage-profile render decoys/profiles/web-db.yaml --seed $$(grep '^MIRAGE_SEED=' .env | cut -d= -f2) --out build/profile

up: profile ## Apply the ClickHouse DDL, then build and start the stack
	@mkdir -p build/models
	@# The store first, and its DDL before anything that reads it: a worker that waits for a
	@# table this version adds would otherwise never turn healthy on an existing store, the
	@# start would fail, and the migration that creates the table would never run.
	$(COMPOSE) up -d --wait clickhouse
	@$(MAKE) --no-print-directory migrate >/dev/null
	$(COMPOSE) up -d --build --wait --remove-orphans
	@# These read the profile once at start; compose does not restart them when it changes.
	$(COMPOSE) restart http-decoy redis-decoy mysql-decoy sessioniser

dashboards: ## Regenerate the Grafana dashboards (compose/grafana/dashboards)
	uv run python tools/grafana_dashboards.py

migrate: ## Re-apply ClickHouse DDL (idempotent) to a running stack
	$(COMPOSE) exec -T clickhouse sh -c 'clickhouse-client --user "$$CLICKHOUSE_USER" --password "$$CLICKHOUSE_PASSWORD" --multiquery' < compose/clickhouse/init.sql

down: ## Stop the stack, the lab included (keeps data)
	$(COMPOSE) --profile lab down

nuke: ## Stop the stack and delete all data volumes
	$(COMPOSE) --profile lab down -v

ps: ## Show service status
	$(COMPOSE) ps

logs: ## Follow logs
	$(COMPOSE) logs -f --tail=50

test: ## Unit tests
	uv run pytest

LAB := $(COMPOSE) --profile lab
# The public seed every frozen dataset is rendered from (phase 2 spec, Q16), so no deployment's
# honeytokens or names can reach the repository. Never the seed of an exposed sensor.
LAB_SEED := 20261114
SCENARIOS ?= /lab/scenarios/smoke

lab-seed: env ## Pin this host's profile to the public lab seed, then re-render: for lab hosts only
	@sed -i.bak "s/^MIRAGE_SEED=.*/MIRAGE_SEED=$(LAB_SEED)/" .env && rm -f .env.bak
	@echo "MIRAGE_SEED is now the lab seed ($(LAB_SEED)); run make up"

lab-generate: ## Regenerate the human twins and coverage scenarios from the catalogue's IDs
	uv run python -m mirage_lab.generate
	uv run python -m eval.split extend

lab-up: ## Start the lab edge and the label join (never on an exposed sensor)
	$(LAB) up -d --build --wait lab-edge sim-join
	$(LAB) build -q runner

lab-run: ## Run scenarios in the lab: make lab-run SCENARIOS=/lab/scenarios/smoke ARGS="--repeat 3"
	$(LAB) run --rm -e MIRAGE_CODE_VERSION=$$(git rev-parse --short HEAD) runner run $(SCENARIOS) $(ARGS)

# Compose recreates a service whose configuration differs from the command's environment, so
# the switch must be set on every compose call of the run: turning it on with `up` and then
# calling `make lab-run` silently turns it off again (found on the first live run).
lab-explore: ## Bandit explore run (lab explore range only), then exploration off again: make lab-explore SCENARIOS=/lab/scenarios ARGS="--seed 2 --repeat 20"
	POLICY_EXPLORE=lab $(COMPOSE) up -d --wait policy
	@sleep 5
	POLICY_EXPLORE=lab $(LAB) run --rm -e MIRAGE_CODE_VERSION=$$(git rev-parse --short HEAD) runner run $(SCENARIOS) --mode explore $(ARGS); \
	  status=$$?; $(COMPOSE) up -d --wait policy; exit $$status

lab-human: ## Record a real person's SSH session through the lab edge (spec Q8); needs a terminal
	$(LAB) run --rm -e MIRAGE_CODE_VERSION=$$(git rev-parse --short HEAD) runner record $(ARGS)

lab-down: ## Stop the lab containers; the decoys and the pipeline keep running
	$(LAB) stop lab-edge sim-join

split: ## Freeze the train/dev/test split (eval/split.yaml) from the catalogue
	uv run python -m eval.split build

DATA ?= build/dataset
FROZEN := eval/datasets/gate2
# The experiments' environment (PyTorch, sentence-transformers, MLflow), kept apart from the
# default one so the unit tests and CI never need it.
# GPU=1 uses the GPU environment instead (make gpu-env): the same locked versions with
# PyTorch's CUDA build. Its interpreter is called directly, because `uv run` would sync the
# environment back to the lock file, which names the CPU build.
TORCH_CUDA ?= cu132
ifeq ($(GPU),1)
RESEARCH := $(CURDIR)/.venv-research-gpu/bin/python
else
RESEARCH := UV_PROJECT_ENVIRONMENT=$(CURDIR)/.venv-research uv run --group research python
endif

dataset: ## Export labelled sessions and steps, and explore decisions: make dataset CAPTURE=RUN_ID EXPLORE=RUN_ID
	uv run python -m mirage_intel.dataset $(if $(CAPTURE),--run $(CAPTURE)) --out $(DATA) $(ARGS)
	$(if $(EXPLORE),uv run python -m mirage_intel.decisions --run $(EXPLORE) --out $(DATA))

models: ## Train the chosen models (eval/choices.yaml) into build/models, where the workers load them: make models DATA=eval/datasets/gate2
	uv run python -m mirage_intel.classifier --data $(DATA)/sessions.parquet
	$(RESEARCH) -m mirage_intel.tagserve --data $(DATA)
	uv run python -m mirage_intel.experiments.bandit_bench --data $(DATA) --final --save build/models/policy/shadow.json

freeze: ## Lab host: freeze build/dataset as the regression dataset (needs the embedding model and the Atomic file)
	$(RESEARCH) -m mirage_intel.harness freeze --data $(DATA) --name gate2 $(ARGS)

eval: ## Score the chosen models on a dataset; exits non-zero if a check or gate is not met: make eval DATA=eval/datasets/gate2
	uv run python -m mirage_intel.harness run --data $(DATA) $(ARGS)

eval-regression: ## Gate 2 test 10: the frozen dataset against its committed baseline (needs no model and no store)
	uv run python -m mirage_intel.harness check --data $(FROZEN)

explore-check: ## Gate 2 test 8: check the bandit's logged probabilities (after an explore run)
	uv run python -m mirage_intel.explore_check $(ARGS)

ml-image: ## Build the learned tagger's image (downloads PyTorch for CPU, about 0.5 GB)
	$(COMPOSE) --profile ml build tagger-model

tagger-model: ## Start the learned tagger in Docker (after make ml-image and make models)
	$(COMPOSE) --profile ml up -d --wait tagger-model

tagger-model-host: ## Run the learned tagger from this host's research environment instead (foreground; GPU=1 for the GPU one)
	@# Low priority: on a busy host the tagger must wait, never the policy service the decoys
	@# are waiting on.
	nice -n 10 $(RESEARCH) -m mirage_intel.tag_worker

gpu-env: ## Lab host with an NVIDIA GPU: a research environment with PyTorch's CUDA build (about 2.5 GB of downloads)
	@mkdir -p build
	uv export --frozen --group research --no-hashes --no-emit-workspace -o build/research.txt >/dev/null
	grep -v '^torch==' build/research.txt > build/research-gpu.txt
	uv venv --python 3.12 --allow-existing .venv-research-gpu
	uv pip install --python .venv-research-gpu/bin/python --index-url https://download.pytorch.org/whl/$(TORCH_CUDA) \
	  "torch==$$(grep -o '^torch==[0-9.]*' build/research.txt | head -1 | cut -d= -f3)"
	uv pip install --python .venv-research-gpu/bin/python -r build/research-gpu.txt
	uv pip install --python .venv-research-gpu/bin/python --no-deps -e schema -e lab -e intel
	.venv-research-gpu/bin/python -c "import torch; assert torch.cuda.is_available(), 'this PyTorch build sees no GPU'; print('PyTorch', torch.__version__, 'on', torch.cuda.get_device_name(0))"

# Every step can fail, and the first failure stops the run. The integration tests fail, not
# skip, when the stack or the lab is missing. TAGGER_MODEL=host leaves the learned tagger to a
# `make tagger-model-host` already running; otherwise it is started in Docker.
gate2: ## Full Phase 2 validation on a lab host (after a lab-seed capture and explore run): make gate2 [TAGGER_MODEL=host]
	uv run python -m eval.split check
	uv run python -m mirage_intel.attack check
	uv run python -m mirage_lab.generate --check
	uv run pytest -q
	uv run pytest -m ml -q
	$(MAKE) eval-regression
	$(MAKE) up
	$(MAKE) lab-up
	$(MAKE) models DATA=$(FROZEN)
	@# The workers read their model once, at start.
	$(COMPOSE) restart policy classifier-worker
	$(if $(filter host,$(TAGGER_MODEL)),,$(COMPOSE) --profile ml up -d --wait --force-recreate tagger-model)
	MIRAGE_REQUIRE_STACK=1 uv run pytest -m integration -v
	uv run python -m mirage_intel.explore_check $(ARGS)

itest: ## Integration tests against the running stack (Gates 0 and 1)
	uv run pytest -m integration -v

lint: ## Lint and format check
	uv run ruff check . && uv run ruff format --check .

fmt: ## Auto-format
	uv run ruff format . && uv run ruff check --fix .

schema: ## Export JSON Schema files to schema/json
	uv run mirage-schema-export schema/json

probe: ## Run the SSH fingerprint probes against the stack (spike S3)
	uv run python -m eval.probes.ssh_probes 127.0.0.1:2222
