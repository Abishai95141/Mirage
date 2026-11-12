COMPOSE := docker compose --env-file .env -f compose/docker-compose.yml

.PHONY: help env profile profile-ref reference-image up migrate down nuke ps logs test itest lint fmt schema probe

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
	@$(MAKE) --no-print-directory migrate >/dev/null

migrate: ## Re-apply ClickHouse DDL (idempotent) to a running stack
	$(COMPOSE) exec -T clickhouse sh -c 'clickhouse-client --user "$$CLICKHOUSE_USER" --password "$$CLICKHOUSE_PASSWORD" --multiquery' < compose/clickhouse/init.sql

down: ## Stop the stack (keeps data)
	$(COMPOSE) down

nuke: ## Stop the stack and delete all data volumes
	$(COMPOSE) down -v

ps: ## Show service status
	$(COMPOSE) ps

logs: ## Follow logs
	$(COMPOSE) logs -f --tail=50

test: ## Unit tests
	uv run pytest

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
