COMPOSE := docker compose --env-file .env -f compose/docker-compose.yml

.PHONY: help env up migrate down nuke ps logs test itest lint fmt schema probe

help:
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-8s %s\n",$$1,$$2}'

env: ## Create .env with random passwords (once)
	@test -f .env && echo ".env exists, leaving it" || { \
	  sed -e "s/^CLICKHOUSE_PASSWORD=.*/CLICKHOUSE_PASSWORD=$$(openssl rand -hex 16)/" \
	      -e "s/^GRAFANA_ADMIN_PASSWORD=.*/GRAFANA_ADMIN_PASSWORD=$$(openssl rand -hex 16)/" \
	      .env.example > .env && chmod 600 .env && echo "wrote .env"; }

up: env ## Build and start the stack
	$(COMPOSE) up -d --build --wait

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

itest: ## Integration tests against the running stack (Gate 0)
	uv run pytest -m integration -v

lint: ## Lint and format check
	uv run ruff check . && uv run ruff format --check .

fmt: ## Auto-format
	uv run ruff format . && uv run ruff check --fix .

schema: ## Export JSON Schema files to schema/json
	uv run mirage-schema-export schema/json

probe: ## Run the SSH fingerprint probes against the stack (spike S3)
	uv run python -m eval.probes.ssh_probes 127.0.0.1:2222
