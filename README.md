# Mirage

**Fine-tuning a small language model to answer like a real Linux server, inside an adaptive SSH honeypot.**

A honeypot is only useful while the attacker believes it. Emulated shells such as Cowrie give themselves away on the first command they do not implement, and a general-purpose LLM asked to stand in for the shell gets the details wrong. It invents a version, half-remembers an output format, or prints a checksum it never computed. Mirage trains a model on what a real Debian 12 host actually prints and puts it behind a deterministic emulator, so the model answers only the long tail. Everything it says is then held to a live reference host.

| | Stock Qwen3.5-9B | Stock Qwen3.5-4B | **Qwen3.5-4B + LoRA (ours)** |
| --- | --- | --- | --- |
| Exact real-host answers, other invocations of trained programs (162) | 5 | 2 | **42** |
| Exact real-host answers, programs never seen in training (382) | 27 | 15 | **76** |
| Median time to whole answer, live path | 912 ms | | **718 ms** |
| GPU memory | 6.3 GB | 4.0 GB | **3.9 GB** |
| Prompt-injection set (20): in character / aborted / broke a rule | 17 / 3 / 0 | 15 / 5 / 0 | 18 / 2 / 0 |

"Exact" means stdout, stderr and exit status all equal the real host's, scored through the honeypot's own request path. The full write-up, including where the tuned model is worse, is in [docs/experiments/phase-3/lora-v1.md](docs/experiments/phase-3/lora-v1.md).

## The fine-tuning pipeline

```
candidate commands ──► throwaway Debian 12 host ──► filtered rows ──► LoRA training ──► GGUF adapter ──► scored live
(278 programs,          (each run 3×, no network,     (2,210 kept;        (Kaggle T4,        (beside the 4-bit   (held-out programs
 4,655 commands)         as root; answers recorded)    split by program)   3 h 12 min)        base, no merge)     and invocations)
```

1. **Candidates** ([`eval/tune/candidates.py`](eval/tune/candidates.py)). For every program the honeypot's emulator does not implement and that is safe to run, the pipeline generates its `--version` and its short `--help`, each option its own help lists (alone and with a small file), and an option it does not have. 241 more are written by hand ([`seeds.yaml`](eval/tune/seeds.yaml)).
2. **Labels come from a real machine, never from a model** ([`label.py`](eval/tune/label.py)). Each command runs three times on a fresh reference container with no network. The pipeline drops answers that differ between runs, hold a time of day, name the container, change the host, or exceed the answer budget. With each label it records the file view the honeypot would send in its prompt.
3. **Rows** ([`build.py`](eval/tune/build.py)). Each row is rendered with the responder's own prompt code under one of four host identities. No program gets more than 24 rows, no answer appears more than twice, and no row holds a password hash or private key. A tenth of whole programs is held out, as is a tenth of the remaining invocations and every command of the live bench.
4. **Training** ([`train_lora.py`](eval/tune/train_lora.py)). The base is `Qwen/Qwen3.5-4B` in 16-bit, with rank-16 LoRA on every projection (128 modules, 21 M parameters). Loss falls on the answer only, under the model's own chat template with thinking off. Training ran 2 epochs on one T4; validation loss went from 0.85 to 0.41. The log is [lora-v1-train.jsonl](docs/experiments/phase-3/lora-v1-train.jsonl).
5. **Serving and scoring** ([`score_adapter.sh`](eval/tune/score_adapter.sh)). The adapter is converted to GGUF and served by llama.cpp beside the stock 4-bit base. Both held-out sets go through the responder's real request path, and the 57-command bench and the injection set run end to end over SSH.

```bash
make tune-set
```

```bash
make tune-score NAME=v1
```

### What the results say

- **Where the gain is.** It is in how Debian's tools refuse and report: the exact option error, the `Try '... --help'` line, the exit status. On options a program does not have, the tuned model matches the real host 19 times out of 33 on unseen programs. The stock 9B manages 5.
- **Where it is not.** On hand-written commands for unseen programs the tuned 4B is no better than the stock 9B (7 of 62 against 9). Neither model reproduces a help text.
- **One regression, and its cause.** On commands that change files the tuned model proposed 5 file operations where the 9B proposed 26. Every training row is a read-only command whose answer ends with `"ops": []`, so the model learned that nothing ever changes. The fix is known: label state-changing commands by the difference they leave on the host.
- **The serving decision.** The stock 9B serves the live path for now. The tuned adapter is kept, and the labelling pipeline is reused to check every fixed answer against a real host in bulk. Each command that can be computed exactly moves into the emulator, which is right every time.

## Where the model sits: the answer ladder

An attacker's command goes to the first rung that can answer it:

| Rung | What answers | Right how often |
| --- | --- | --- |
| 1. Emulator | 171 commands and a bash-compatible shell in a patched Cowrie ([24 patches](decoys/ssh/patches/)), computed from the session's own file system, accounts, sockets and processes | Byte for byte against recordings of real bash and coreutils: 229 of 234 shell lines, about 180 file-command lines |
| 2. Render library | Recorded real output for fixed facts of the image (versions, package records) | Checked against the reference host |
| 3. Cache | Earlier model answers that passed the offline check | Evicted when the real host disagrees |
| 4. **Model** | Everything else: streamed, with a token budget, structured file operations and an output filter | Measured live: first byte 0.59 s, whole answer 0.81 s at the median on an RTX 3060 Ti |

The model never touches a real system. It proposes file operations in a fixed vocabulary, and the decoy validates and applies them before showing the answer, so the next `ls` agrees with what the model said. A program that fails once is refused for the deployment, so the decoy does not contradict itself between logins.

## How it is checked

- **Fingerprint suite** (`make probe`): 474 checks of the decoy against a live reference host in the same run. They cover transport, emulator output, timing, consistency (the same question asked twice and across logins; a reported file change against what is then seen) and a second decoy from another seed. The latest run had 0 failures and 10 listed known gaps.
- **Depth comparison**: 24 frozen attack scenarios whose later steps depend on what earlier ones printed. They run against a real host (280 of 280 steps), stock Cowrie (69) and Mirage. The held-out half is read once, for the final comparison.
- **Prompt-injection set**: 20 hostile inputs through the live model. None leaked prompt text or produced an invalid operation.
- **Tests**: 1,354 unit tests, 2,009 tests of the Cowrie fork, and 75 end-to-end tests on the running stack.

## The rest of the platform

Mirage also captures and labels what attackers do:

- Decoys for SSH, HTTP, Redis and MySQL, with per-deployment profiles and honeytokens.
- An event pipeline into ClickHouse, with Grafana dashboards.
- An isolated attack-simulation lab that produces ground-truth labels.
- Models chosen by written, held-out experiments ([docs/experiments](docs/experiments/)):
  - an actor classifier (scanner, bot or person; macro-F1 0.99 on the lab's sessions);
  - an ATT&CK technique tagger;
  - a response policy evaluated off-policy as a contextual bandit.

## Quick start

Needs Docker and [uv](https://docs.astral.sh/uv/). The live model needs a Linux host with an NVIDIA GPU (8 GB is enough).

```bash
uv sync
```

```bash
make reference-image
```

```bash
make up
```

```bash
make llm-up
```

```bash
make probe
```

`make up` writes a `.env` with random secrets on first run, renders the deployment's profile and starts the stack. Every port binds to 127.0.0.1. Nothing here is meant to face the internet; read the exposure checklist in the [build plan](docs/01-build-plan.md) first. The order to show things in is in [docs/08-showcase.md](docs/08-showcase.md).

| Command | What it does |
| --- | --- |
| `make llm-bench` | Time the model's answers and hold them against the reference host |
| `make llm-inject` | Run the injection set against the live model |
| `make llm-down` | Stop the model server; the responder falls back to recorded answers |
| `make itest` | End-to-end tests against the running stack |
| `make test`, `make lint` | Unit tests and lint |
| `make lab-up`, `make lab-run` | The simulation lab (lab hosts only) |
| `make gate2` | The phase 2 gate on a frozen dataset |

## Layout

| Path | Contents |
| --- | --- |
| `eval/tune/` | The fine-tuning pipeline: candidates, real-host labelling, rows, LoRA training, adapter scoring |
| `responder/` | The model service: state manager, command classes, prompt, output filter, cache, backends |
| `decoys/ssh/patches/` | The Cowrie fork: emulator, shell, state journal, the respond client |
| `decoys/profiles/` | Profile generator, hardware classes, render library, Debian 12 reference |
| `eval/probes/` | Fingerprint suite, model bench, injection set |
| `policy/` | Policy service: rules, mask, budgets, decision log |
| `pipeline/`, `schema/` | Event pipeline and schema |
| `lab/` | Simulation lab and scenario runner |
| `intel/` | Classifier, tagger and policy experiments |
| `docs/` | Plan, architecture, specs, experiment write-ups |

## Read next

1. [Fine-tuning write-up](docs/experiments/phase-3/lora-v1.md)
2. [The live model, measured](docs/experiments/phase-3/llm-bench.md): latency, fidelity, the 9B against the 4B, repeat consistency
3. [Depth baseline](docs/experiments/phase-3/depth-baseline.md)
4. [Architecture](docs/02-architecture.md) and [AI/ML design](docs/03-ai-ml-design.md)
5. [Phase 3 spec](docs/06-phase-3-spec.md) and its [working record](docs/phase-3-context.md)
