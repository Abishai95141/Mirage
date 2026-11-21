COMPOSE := docker compose --env-file .env -f compose/docker-compose.yml

.PHONY: help env profile profile-ref render-emulated render-inventory render-record render-library render-coverage render-candidates llm-evict hardware-capture hardware reference-image dashboards up migrate down nuke ps logs lab-seed lab-generate lab-up lab-run lab-explore lab-human lab-down arm-r-image arm-r-check lab-arm lab-arm-r arm-report arm-failed arm-clear showcase-image showcase-preview showcase-check showcase-up showcase-url showcase-password showcase-password-new showcase-down split dataset models freeze eval eval-regression explore-check ml-image tagger-model tagger-model-host gpu-env gate2 test itest lint fmt schema probe probe-report probe-local fleet-profile llm-up llm-up-cpu llm-down llm-status llm-bench llm-inject llm-record-on llm-record-off llm-record-save tune-set tune-score llm-standings llm-forgive

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

# Phase 3's render library (spec 3.2a). The inventory ranks the commands the SSH decoy answers
# wrongly, from the corpus sample and the lab procedures outside every test split.
CORPUS ?= data/seed/2025-06-27.json.sample.json
render-emulated: ## List what the built SSH decoy image emulates (run after a fork patch adds commands, on a host with the image)
	bash decoys/profiles/rendered/sources/list-emulated.sh

render-inventory: ## Rank the commands the SSH decoy answers wrongly: make render-inventory [CORPUS="file ..."]
	uv run mirage-profile inventory --corpus $(CORPUS)

# The library itself: what real hosts printed for the inventory's reporting commands. The
# first target records them in a throwaway reference container with no network (a lab host
# with Docker; needs make reference-image); the second builds the committed entries and the
# review file from that record and the hardware classes, and reports coverage.
render-record: ## Record the render library's commands on a throwaway reference host
	bash decoys/profiles/rendered/record/record.sh

render-library: ## Build the render library from its records and report its coverage
	uv run mirage-profile render-library

render-coverage: ## Report the committed render library's coverage; change nothing
	uv run mirage-profile render-library --coverage

# Promotion (spec 3.2b): what the live model was asked moves to the library, where the real
# host's own answer is given. `render-candidates` reads the responder's cache and adds its
# stateless commands to decoys/profiles/rendered/promoted.yaml; then `render-record` and
# `render-library` as above (the second also names the cached answers that are not the real
# host's, in build/rendered/evict.json); `llm-evict` drops those from the cache.
render-candidates: ## Add what the responder's cache holds to the list of promoted commands
	@mkdir -p build/rendered
	@$(COMPOSE) exec -T responder python -m mirage_responder.candidates list > build/rendered/candidates.json
	uv run mirage-profile render-library --candidates build/rendered/candidates.json

llm-evict: ## Drop the cached answers the reference host contradicted (build/rendered/evict.json)
	@$(COMPOSE) exec -T responder python -m mirage_responder.candidates evict < build/rendered/evict.json

# Hardware classes (spec 3.2a, R6): the machines a deployment can claim to be. Each is recorded
# from Debian 12 booted on that virtual hardware, on a lab host with KVM and Docker, no root.
# The first run downloads Debian's cloud image (about 430 MB, checked against its SHA-512).
hardware-capture: ## Record the hardware classes from throwaway virtual machines: make hardware-capture [CLASS=id]
	bash decoys/profiles/hardware/capture/capture.sh $(CLASS)

hardware: ## Turn what hardware-capture recorded (build/hardware) into the committed classes
	uv run mirage-profile hardware build/hardware/*

up: profile ## Apply the ClickHouse DDL, then build and start the stack
	@mkdir -p build/models
	@# The store first, and its DDL before anything that reads it: a worker that waits for a
	@# table this version adds would otherwise never turn healthy on an existing store, the
	@# start would fail, and the migration that creates the table would never run.
	$(COMPOSE) up -d --wait clickhouse
	@$(MAKE) --no-print-directory migrate >/dev/null
	$(COMPOSE) up -d --build --wait --remove-orphans
	@# These read the profile once at start; compose does not restart them when it changes.
	$(COMPOSE) restart http-decoy redis-decoy mysql-decoy sessioniser responder

dashboards: ## Regenerate the Grafana dashboards (compose/grafana/dashboards)
	uv run python tools/grafana_dashboards.py

migrate: ## Re-apply ClickHouse DDL (idempotent) to a running stack
	$(COMPOSE) exec -T clickhouse sh -c 'clickhouse-client --user "$$CLICKHOUSE_USER" --password "$$CLICKHOUSE_PASSWORD" --multiquery' < compose/clickhouse/init.sql

# Every profile: the learned tagger (ml), the model server (llm) and the showcase are
# started by their own targets, and a `down` that left them running was not one (found on
# 20 November 2026: the tagger's model worker was still up after it).
down: ## Stop the stack and everything started beside it: lab, tagger model, model server, showcase (keeps data)
	$(COMPOSE) --profile lab --profile ml --profile llm --profile showcase down

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
# What a run records as the code that produced it: the commit, with "-dirty" when the files
# differ from it. A lab host has to hold this checkout's history for that to be true
# (tools/lab-host/sync.sh copies it); with no history at all a run records "dev".
CODE_VERSION = $$(git describe --always --dirty --abbrev=7 2>/dev/null || echo dev)

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
	$(LAB) run --rm -e MIRAGE_CODE_VERSION=$(CODE_VERSION) runner run $(SCENARIOS) $(ARGS)

# Compose recreates a service whose configuration differs from the command's environment, so
# the switch must be set on every compose call of the run: turning it on with `up` and then
# calling `make lab-run` silently turns it off again (found on the first live run).
lab-explore: ## Bandit explore run (lab explore range only), then exploration off again: make lab-explore SCENARIOS=/lab/scenarios ARGS="--seed 2 --repeat 20"
	POLICY_EXPLORE=lab $(COMPOSE) up -d --wait policy
	@sleep 5
	POLICY_EXPLORE=lab $(LAB) run --rm -e MIRAGE_CODE_VERSION=$(CODE_VERSION) runner run $(SCENARIOS) --mode explore $(ARGS); \
	  status=$$?; $(COMPOSE) up -d --wait policy; exit $$status

lab-human: ## Record a real person's SSH session through the lab edge (spec Q8); needs a terminal
	$(LAB) run --rm -e MIRAGE_CODE_VERSION=$(CODE_VERSION) runner record $(ARGS)

lab-down: ## Stop the lab containers; the decoys and the pipeline keep running
	$(LAB) stop lab-edge sim-join

# Phase 3's depth comparison (spec section 5). Arm R is a real Debian host: what a scenario
# sends there really runs, as root, in a container with no route anywhere that is thrown away
# after each scenario. Lab hosts only, and only after `make arm-r-check` has passed there.
ARMS := $(COMPOSE) --profile lab --profile arms
ARM_SEED ?= 1
ARM_TIME_SCALE ?= 0.2
DEPTH ?= lab/scenarios/depth

arm-r-image: ## Build the reference-host arm and the runner (needs make reference-image)
	$(ARMS) build -q arm-r runner

arm-r-check: ## Check from inside arm R that it can reach nothing but its lab edge
	bash tools/lab-host/arm-r-check.sh

# The arms that exist so far: r is the reference host (inputs really run), a is stock Cowrie,
# b is this stack as it stands, through lab-edge. r and a are recreated for every scenario.
ARM ?= r
# Where an arm's records go on the arms volume. Its own name by default; give another
# (ARM_OUT=b-look) for a run that must not be counted with the arm's measured ones. Every arm
# run keeps what a failed check saw (make arm-failed ARM=<that name>), without the input.
ARM_OUT ?= $(ARM)
ARM_TARGET_r := arm-r-edge
ARM_TARGET_a := arm-a-edge
ARM_TARGET_b := lab-edge
ARM_SERVICES_r := arm-r arm-r-edge
ARM_SERVICES_a := arm-a arm-a-edge
ARM_REAL_r := -e LAB_REAL_HOST=1
# Before a reference host is thrown away: a scenario may have set the immutable flag on a
# file, and Docker cannot delete a container that still holds one. Only what the container
# changed can carry a flag, so the flags are cleared on exactly those paths (walking the whole
# filesystem took four minutes a scenario on the lab host's disk).
ARM_CLEAN_r = docker diff mirage-arm-r-1 | cut -c3- | $(ARMS) exec -T arm-r xargs -r -d '\n' chattr -f -i -a 2>/dev/null;

lab-arm: ## Run each scenario against one arm: make lab-arm ARM=r|a|b [DEPTH=lab/scenarios/depth] [ONLY=name]
	@test -n "$(ARM_TARGET_$(ARM))" || { echo "no arm called $(ARM)"; exit 1; }
	@host=$$(python3 -c "import json;print(json.load(open('build/profile/host.json'))['hostname'])"); \
	for f in $(DEPTH)/$(if $(ONLY),$(ONLY),*).yaml; do \
	  $(if $(ARM_SERVICES_$(ARM)),ARM_HOSTNAME=$$host $(ARMS) up -d --force-recreate --wait $(ARM_SERVICES_$(ARM)) >/dev/null 2>&1 \
	    || { echo "$$f: arm $(ARM) did not start"; exit 1; };) \
	  $(ARMS) run --rm -e LAB_TARGET=$(ARM_TARGET_$(ARM)) -e LAB_OUT=/var/lib/mirage-arms/$(ARM_OUT) $(ARM_REAL_$(ARM)) -e LAB_KEEP_FAILED=1 \
	    -e MIRAGE_CODE_VERSION=$(CODE_VERSION) runner run /$$f --seed $(ARM_SEED) \
	    --time-scale $(ARM_TIME_SCALE) --workers 1 | tail -1; \
	  $(ARM_CLEAN_$(ARM)) \
	done; \
	$(if $(ARM_SERVICES_$(ARM)),$(ARMS) rm -sf $(ARM_SERVICES_$(ARM)) >/dev/null 2>&1,true)

lab-arm-r: ## The same against the reference host (after make arm-r-check)
	@$(MAKE) --no-print-directory lab-arm ARM=r

arm-report: ## What the runs against an arm recorded, from the runner's own records: make arm-report [ARM=r]
	@$(ARMS) run --rm --no-deps runner arm-report /var/lib/mirage-arms/$(ARM)

arm-failed: ## The checks that failed on an arm, with what the host answered: make arm-failed [ARM=r]
	@$(ARMS) run --rm --no-deps --entrypoint cat runner /var/lib/mirage-arms/$(ARM)/failed-checks.jsonl

arm-clear: ## Forget every run recorded against the arms
	docker volume rm mirage_arm-out

# The public showcase (docs/08-showcase.md): a read-only copy of the dashboards that anyone
# with the link can open, and at <link>/console/ a terminal into the SSH decoy for whoever
# also has the console's password. It is the one deliberate way anything here is reachable
# from the internet. No decoy is on the internet: the console is the lab's own recorder with
# a browser in front. Nobody can sign in to the dashboards, which read the store as a user
# that can only read, under hard limits. Everything in the mirage database is readable
# through it while it is up, so it belongs on a lab host with lab data, never on a sensor
# that has seen real traffic. Starting it is the owner's act: `make up` never does.
#
# The code version is set on every compose call, because compose recreates a service whose
# configuration differs from the command's environment (see lab-explore).
SHOWCASE := MIRAGE_CODE_VERSION=$(CODE_VERSION) $(COMPOSE) --profile lab --profile showcase
SHOWCASE_SERVICES := grafana-public showcase-console showcase-proxy

showcase-image: ## Build the console's image and the lab image it is built on (x86-64 lab hosts)
	$(LAB) build -q runner
	$(SHOWCASE) build -q showcase-console

showcase-preview: env showcase-image ## The showcase on this machine only (http://127.0.0.1:3301, console at /console/): what a visitor would see, no public link
	$(SHOWCASE) up -d --wait lab-edge sim-join $(SHOWCASE_SERVICES)
	@echo "preview: http://127.0.0.1:$$(grep '^SHOWCASE_PORT=' .env | cut -d= -f2 | grep . || echo 3301)   console: /console/ (make showcase-password)"

showcase-check: ## Try the preview as a visitor would, console included; sends nothing off this machine
	@python3 tools/lab-host/showcase-check.py

showcase-up: showcase-preview ## Open the public link (a new address each time; share it with whoever you like)
	$(SHOWCASE) up -d showcase-tunnel
	@$(MAKE) --no-print-directory showcase-url

showcase-url: ## Print the showcase's public link
	@for i in $$(seq 1 40); do \
	  url=$$($(SHOWCASE) logs showcase-tunnel 2>&1 | grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' | tail -1); \
	  [ -n "$$url" ] && break; sleep 1; \
	done; echo "$${url:-no link yet; run make showcase-url again}"

showcase-password: ## Print the console's user and password, for you to give to people you would let type into the decoy
	@echo "user:     presenter"; echo "password: $$(grep '^SHOWCASE_CONSOLE_PASSWORD=' .env | cut -d= -f2)"

showcase-password-new: ## Replace the console's password; then make showcase-down and make showcase-up
	@python3 tools/env_fill.py --renew SHOWCASE_CONSOLE_PASSWORD

showcase-down: ## Close the public link and stop the showcase (the lab edge keeps running)
	$(SHOWCASE) rm -sf showcase-tunnel showcase-proxy showcase-console grafana-public

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
# `env`, so the assignment also works behind another command (`nice`, below).
RESEARCH := env UV_PROJECT_ENVIRONMENT=$(CURDIR)/.venv-research uv run --group research python
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

# The live model (phase 3 spec 3.2c): a llama.cpp server on the internal model network, and
# the responder switched to it. RESPONDER_MODEL names the model and its build; it is kept with
# every cached answer, so a change of model empties the cache by itself.
# Another model: LLAMA_MODEL_FILE=<file in data/models> make llm-up LLM_MODEL_NAME=<its name>.
# A tuned one (step 5b) is its base file and an adapter beside it: add LLAMA_LORA=<adapter
# file, relative to data/models> and give the pair a name of its own.
LLM := $(COMPOSE) --profile llm
LLM_MODEL_NAME ?= qwen3.5-9b-q4_k_m
LLM_SLOTS ?= 4
LLM_ENV = RESPONDER_BACKEND=llama RESPONDER_LLM_URL=http://llama:8080 RESPONDER_MODEL=$(LLM_MODEL_NAME) RESPONDER_CONCURRENCY=$(LLM_SLOTS) LLAMA_SLOTS=$(LLM_SLOTS)
llm-up: ## Linux host: start the model server on the GPU and switch the responder to it
	@ls data/models/*.gguf >/dev/null 2>&1 || { echo "no model file in data/models (phase 3 spec, section 10)"; exit 1; }
	@docker info --format '{{json .Runtimes}}' | grep -q nvidia || { echo "Docker has no nvidia runtime: sudo bash tools/lab-host/install-runtimes.sh"; exit 1; }
	$(LLM_ENV) $(LLM) up -d --wait llama
	$(LLM_ENV) $(LLM) up -d --wait --force-recreate responder

# No GPU runtime yet: the same server on the CPU, one slot, to prove the path (compose/llm-cpu.yml).
LLM_CPU := $(COMPOSE) -f compose/llm-cpu.yml --profile llm
LLM_CPU_ENV = RESPONDER_BACKEND=llama RESPONDER_LLM_URL=http://llama:8080 RESPONDER_MODEL=$(LLM_MODEL_NAME)-cpu RESPONDER_CONCURRENCY=1 LLAMA_SLOTS=1 LLAMA_GPU_LAYERS=0 LLAMA_CTX=4096
llm-up-cpu: ## The model server on the CPU: slow, for proving the path before the GPU runtime is installed
	@ls data/models/*.gguf >/dev/null 2>&1 || { echo "no model file in data/models (phase 3 spec, section 10)"; exit 1; }
	$(LLM_CPU_ENV) $(LLM_CPU) up -d --wait llama
	$(LLM_CPU_ENV) $(LLM_CPU) up -d --wait --force-recreate responder

llm-down: ## Stop the model server and put the responder back on recorded answers
	-$(LLM) stop llama
	-$(LLM) rm --force llama
	$(COMPOSE) up -d --wait --force-recreate responder

llm-status: ## The model server's health and the GPU's memory
	@$(LLM) ps llama responder
	@nvidia-smi --query-gpu=name,memory.used,memory.total,utilization.gpu --format=csv,noheader 2>/dev/null || true

# The bench (phase 3 spec 3.2c; eval/probes/llm_bench.py): every command of
# eval/probes/llm_commands.yaml through the decoy and on the reference host, one at a time and
# then from LLM_SLOTS logins at once. The responder starts each pass with an empty cache, so
# what is timed is the model. Needs `make llm-up` first.
LLM_BENCH := build/llm
LLM_BENCH_ARGS ?=
LLM_PROBE := $(ARMS) run --rm --entrypoint python probe -m eval.probes.llm_bench run
LLM_EMPTY_CACHE = $(LLM_ENV) RESPONDER_CACHE=/tmp/bench-cache.db $(LLM) up -d --wait --force-recreate responder >/dev/null 2>&1 && sleep 8
llm-bench: ## Linux host, model up: time the model's answers and hold them against the reference host
	@mkdir -p $(LLM_BENCH)
	@host=$$(python3 -c "import json;print(json.load(open('build/profile/host.json'))['hostname'])"); \
	ARM_HOSTNAME=$$host $(ARMS) up -d --build --wait lab-edge arm-r arm-r-edge >/dev/null 2>&1 \
	  || { echo "the reference host did not start (make arm-r-image)"; exit 1; }
	@$(ARMS) build -q probe
	@$(LLM_EMPTY_CACHE)
	@$(LLM_PROBE) --out /var/lib/mirage-arms/probe/llm-sequential.json $(LLM_BENCH_ARGS)
	@$(LLM_EMPTY_CACHE)
	@$(LLM_PROBE) --sessions $(LLM_SLOTS) --out /var/lib/mirage-arms/probe/llm-parallel.json $(LLM_BENCH_ARGS)
	@for pass in sequential parallel; do \
	  $(ARMS) run --rm --no-deps --entrypoint cat probe /var/lib/mirage-arms/probe/llm-$$pass.json > $(LLM_BENCH)/$$pass.json; done
	@$(COMPOSE) exec -T responder cat /var/log/mirage-responder/answers.json > $(LLM_BENCH)/answers.jsonl
	@$(LLM_ENV) $(LLM) up -d --wait --force-recreate responder >/dev/null 2>&1
	@$(ARM_CLEAN_r) $(ARMS) rm -sf arm-r arm-r-edge >/dev/null 2>&1; true
	@uv run python -m eval.probes.llm_bench report --records $(LLM_BENCH)/answers.jsonl --model $(LLM_MODEL_NAME) \
	  --gpu-memory "$$(nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader 2>/dev/null)" \
	  --out $(LLM_BENCH)/bench.json $(LLM_BENCH)/sequential.json $(LLM_BENCH)/parallel.json

llm-standings: ## Which programs the responder refuses for this deployment, and which it has answered
	@$(COMPOSE) exec -T responder python -m mirage_responder.candidates standings

llm-forgive: ## Forget the refused programs (after a model or prompt change): make llm-forgive [VERBS="locale dpkg"]
	@$(COMPOSE) exec -T responder python -m mirage_responder.candidates forgive $(VERBS)

llm-inject: ## Model up: the injection set against the live model; fails on a leak or an invalid operation
	@mkdir -p $(LLM_BENCH)
	@$(COMPOSE) exec -T responder python -m mirage_responder.inject < eval/probes/injection.yaml > $(LLM_BENCH)/inject.json

# Fine-tuning (step 5b; eval/tune). `tune-set` builds the training and held-out rows from what
# a throwaway reference host really prints: the candidates come from each program's own help,
# every one is run three times, and only answers that can be the decoy's are kept. Training
# runs elsewhere (eval/tune/train_lora.py, one file, on a 16 GB GPU). `tune-score` serves a
# trained adapter beside the stock base and scores it on the rows no training saw.
TUNE := build/tune
tune-set: ## Linux host: build the fine-tuning set (needs make reference-image and a rendered profile)
	@mkdir -p $(TUNE)
	bash eval/tune/collect_help.sh $(TUNE)/help
	@python3 -c "import json; print('\n'.join(json.load(open('decoys/profiles/rendered/sources/emulator-commands.json'))['commands']))" > $(TUNE)/emulated.txt
	uv run python -m eval.tune.candidates --help-dir $(TUNE)/help --emulated $(TUNE)/emulated.txt --out $(TUNE)/candidates.jsonl
	uv run python -m eval.tune.label --candidates $(TUNE)/candidates.jsonl --out $(TUNE)/labels.jsonl
	uv run python -m eval.tune.build --labels $(TUNE)/labels.jsonl --profile build/profile/responder/responder.json --out $(TUNE)/set

tune-score: ## Linux host: serve data/models/adapter-NAME beside the stock 4B and score it: make tune-score NAME=v1
	bash eval/tune/score_adapter.sh $(NAME)

# Recordings (spec 3.2b, R10): with RESPONDER_RECORD the live backend also writes every answer
# down, keyed by a hash of the whole model request, and `replay` serves them afterwards with
# no model. They are written on the responder's own volume (its user may not write into the
# repository, and should not); `make llm-record-save` copies them to RECORDINGS_OUT.
LLM_RECORDED := /var/lib/mirage-responder/recordings
RECORDINGS_OUT ?= build/llm/recordings
llm-record-on: ## Model up: the responder also records what the model says
	$(LLM_ENV) RESPONDER_RECORD=1 RESPONDER_RECORDINGS=$(LLM_RECORDED) $(LLM) up -d --wait --force-recreate responder

llm-record-off: ## Stop recording; the responder stays on the live model
	$(LLM_ENV) $(LLM) up -d --wait --force-recreate responder

llm-record-save: ## Copy what was recorded out of the responder: make llm-record-save [RECORDINGS_OUT=eval/recordings]
	@mkdir -p $(RECORDINGS_OUT)
	@$(COMPOSE) cp responder:$(LLM_RECORDED)/. $(RECORDINGS_OUT)/ >/dev/null && ls $(RECORDINGS_OUT) | wc -l

itest: ## Integration tests against the running stack (Gates 0 and 1)
	uv run pytest -m integration -v

lint: ## Lint and format check
	uv run ruff check . && uv run ruff format --check .

fmt: ## Auto-format
	uv run ruff format . && uv run ruff check --fix .

schema: ## Export JSON Schema files to schema/json
	uv run mirage-schema-export schema/json

# The fingerprint regression suite (phase 3 spec 3.4). It runs inside the lab network, where
# the decoy (behind lab-edge) and a real reference host (arm R, behind its own edge) are both
# one proxy away, so the two are compared, and timed, from one place. Lab hosts only: arm R
# really runs what it is sent, which here is the fixed list in eval/probes/commands.yaml.
# The fleet group needs a second deployment: the same decoy built from another seed's profile
# (build/profile-fleet), started beside the reference host and removed with it.
PROBE_ARGS ?=
FLEET_SEED ?= 20261116
PROBING := $(ARMS) --profile fleet
fleet-profile: ## Render a second deployment's profile, from another seed, for the suite's fleet group
	@uv run mirage-profile render decoys/profiles/web-db.yaml --seed $(FLEET_SEED) --out build/profile-fleet >/dev/null

probe: fleet-profile ## The fingerprint suite, decoy against the reference host: make probe [PROBE_ARGS="--groups emulator"]
	@host=$$(python3 -c "import json;print(json.load(open('build/profile/host.json'))['hostname'])"); \
	ARM_HOSTNAME=$$host $(PROBING) up -d --build --force-recreate --wait lab-edge arm-r arm-r-edge cowrie-fleet fleet-edge >/dev/null 2>&1 \
	  || { echo "the reference host or the second deployment did not start (make arm-r-image)"; exit 1; }
	@$(PROBING) build -q probe
	@$(PROBING) run --rm probe --json /var/lib/mirage-arms/probe/report.json $(PROBE_ARGS); status=$$?; \
	$(ARM_CLEAN_r) $(PROBING) rm -sf arm-r arm-r-edge cowrie-fleet fleet-edge >/dev/null 2>&1; exit $$status

probe-report: ## The last suite run's full report, as JSON
	@$(PROBING) run --rm --no-deps --entrypoint cat probe /var/lib/mirage-arms/probe/report.json

probe-local: ## The groups that need no reference host, from this machine's shell
	uv run python -m eval.probes.suite --groups tells,library
