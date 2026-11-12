COMPOSE := docker compose --env-file .env -f compose/docker-compose.yml

.PHONY: help env profile profile-ref reference-image dashboards up migrate down nuke ps logs lab-up lab-run lab-down split test itest lint fmt schema probe

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

up: profile ## Build and start the stack, then apply the ClickHouse DDL
	$(COMPOSE) up -d --build --wait --remove-orphans
	@# These read the profile once at start; compose does not restart them when it changes.
	$(COMPOSE) restart http-decoy redis-decoy mysql-decoy sessioniser
	@$(MAKE) --no-print-directory migrate >/dev/null

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
SCENARIOS ?= /lab/scenarios/smoke

lab-up: ## Start the lab edge and the label join (never on an exposed sensor)
	$(LAB) up -d --build --wait lab-edge sim-join
	$(LAB) build -q runner

lab-run: ## Run scenarios in the lab: make lab-run SCENARIOS=/lab/scenarios/smoke ARGS="--repeat 3"
	$(LAB) run --rm -e MIRAGE_CODE_VERSION=$$(git rev-parse --short HEAD) runner run $(SCENARIOS) $(ARGS)

lab-down: ## Stop the lab containers; the decoys and the pipeline keep running
	$(LAB) stop lab-edge sim-join

split: ## Freeze the train/dev/test split (eval/split.yaml) from the catalogue
	uv run python -m eval.split build

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
