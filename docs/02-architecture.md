# MIRAGE architecture (build view)

Status: draft for review · 11 November 2026, aligned with the phase 1 spec 12 November
Companion docs: [build plan](01-build-plan.md) · [AI/ML design](03-ai-ml-design.md) · [phase 1 spec](04-phase-1-spec.md)

This describes what gets built in phases 0–3 and what each piece is adapted from. Line numbers refer to Cowrie `main` at commit `ea9513e` (6 Nov 2026).

## 1. Runtime layout

```
                       decoy network (no route out)
 attacker / scenario ──► ssh-decoy (Cowrie fork) ─┐
        runner       ──► http-decoy (FastAPI)    ─┼─► policy service ──► LLM responder (phase 3)
                     ──► db-decoy (Redis, MySQL) ─┘        │
                              │ JSON logs                  │ decisions
                              ▼                            ▼
                           Vector ───────────────► NATS JetStream
                                                       │
                              sim.groundtruth ─────────┤
                                                       ▼
                                      normaliser + sessioniser (Python)
                                                       │
                                   ┌───────────────────┼─────────────────┐
                                   ▼                   ▼                 ▼
                              ClickHouse         Parquet lake       intel workers
                                   │            (DuckDB, training)  (classifier, tagger)
                                   ▼
                                Grafana
```

Four networks:

- `edge`: the only one the outside reaches; HAProxy alone sits on it.
- `decoy`: internal, attacker-facing, no egress.
- `gate`: internal; the decoys and the policy service only.
- `core`: the pipeline and the models.

Decoys reach only the policy service, over `gate`, with a bearer token. Decoys and the policy service write logs to volumes that Vector tails read-only; they never send telemetry over the network. Details and the containment tests are in the [phase 1 spec](04-phase-1-spec.md#2-topology).

## 2. Adopt, fork, write

| Component | Choice | Source and licence | Notes |
| --- | --- | --- | --- |
| SSH/Telnet decoy | Fork | cowrie/cowrie, BSD-3 | Pin a commit. The shell was recently rewritten (Lark grammar, Deferred-driven), so older write-ups do not match. |
| HTTP decoy | Write | Borrow Galah's prompt and `{"headers","body"}` contract (Apache-2.0) | Static routes first, LLM only on the catch-all. |
| Responder reference | Read before building | HydraPoT (MIT), HoneyGPT (BSD-3 per its README) | Closest published designs to the router and state manager. Neither has a policy, injection defence or live deployment. |
| Database decoys | Write | — | Deterministic wire framing in code; templates or the LLM supply only result content. |
| Honeytokens | Write a minimal library and CLI | Canarytokens (modified GPLv3) only as a separate container, if at all | Its licence reaches software built specifically to run it and parse its results. Phase 1 mints tokens when profiles are generated and detects their use in the pipeline, so decoys never call a token service. |
| MCP / ICS decoys | Run stock, later | Beelzebub (GPL-3.0), Conpot (GPL-2.0) | Separate containers; consume their logs only. Conpot's public image is amd64-only and old. |
| Shipper | Adopt | Vector 0.61 | File tail → NATS. |
| Bus | Adopt | NATS JetStream 2.14 | Subjects mirror the report's topics: `raw.honeypot`, `raw.network`, `raw.host`, `raw.artifact`, `sim.groundtruth`, `events.normalised`, `policy.decisions`. |
| Normaliser | Write | Plain asyncio consumers | No stream framework; Faust is inactive and Bytewax is community-maintained. |
| Store | Adopt | ClickHouse single node, memory-capped | Parquet export nightly for training; DuckDB to query it. |
| Dashboard | Adopt | Grafana 13 | Custom UI deferred. |
| Model tracking | Adopt | MLflow 3.x with SQLite | Run on demand. |
| Local LLM | Adopt | llama.cpp `llama-server` | Native on macOS, not in Docker. |
| Lab driver (decoys) | Write | — | Scenario runner, section 7. |
| Lab driver (sandbox) | Adopt, phase 3 | apache/caldera 5.3.0, Apache-2.0 | Needs about 8 GB; run on demand on the Linux host. |
| Sensors | Adopt, Linux host | Zeek 8, Suricata 8 | eBPF sensors on Linux only. |
| Federation | Adopt, phase 5 | Flower 1.43 | Pin exactly; recent releases broke transport and CLI. |

Deferred until scale demands: Kafka, OpenSearch, Flink, Feast, an object store (MinIO is archived; Garage or SeaweedFS when needed), CAPE, MISP/OpenCTI, Arkime.

## 3. The Cowrie fork

Cowrie has no hook that runs before a command, and output plugins only see events afterwards. The fork adds one.

**Where commands flow today**

- `HoneyPotShell.runCommand` (`shell/honeypot.py:932`) parses the line and chains `_run_expanded` (lines 991–993).
- `_run_expanded` (`:1154`) calls `protocol.getCommand` (`shell/protocol.py:246`) to resolve a class, then `protocol.call_command` (`:312`, interactive override `:547`) to run it.
- An unknown command hits the not-found branch (`honeypot.py:1215–1239`): it emits `cowrie.command.failed`, prints `-bash: X: command not found` and sets exit code 127.
- `sudo`, `busybox` and `command.exec_command` call `getCommand`/`call_command` directly.

**What the fork changes** (built and measured in spike S1; patch in [`spikes/s1-cowrie-gate/mirage-gate.patch`](../spikes/s1-cowrie-gate/mirage-gate.patch))

1. Done in S1: `runCommand` hands each expanded simple command to `mirage_gate.gate_then_run` instead of `_run_expanded`. Every pipeline stage, loop body and command substitution passes through it. The gate asks the policy service with a non-blocking client and waits on the Deferred, as `wget` and `curl` already do.
2. Done in S1: while a decision is pending, a placeholder command sits on Cowrie's command stack, so typed-ahead input queues behind the command and Ctrl-C cancels it.
3. Done in S1: unknown commands reach the gate (`known: false`) before Cowrie prints "command not found", so the policy can answer them.
4. Done in S1: TCP_NODELAY on pty sessions (`shell/session.py`), as OpenSSH does. Without it any asynchronously answered output costs about 40 ms.
5. Done in S1: a new `cowrie.policy.decision` event, registered in `core/eventids.py` and documented in `docs/OUTPUT.rst` (Cowrie's own test enforces both).
6. Phase 1: wrappers on the `HoneyPotFilesystem` mutators (`mkfile`, `mkdir`, `write`, `remove`, `rename`, `chmod`; `shell/fs.py:119`) that emit state-change events. The filesystem is copy-on-write per session and has no change hook of its own. The working directory lives on `HoneyPotShell.cwd`.
7. Phase 1: removal of the vendored JA4+ code (`vendor/ja4/`, `core/fingerprint.py` and its two call sites) unless the FoxIO licence is acceptable. There is no config switch for it.

`sudo X` and `busybox X` reach the gate once, as their whole argv; the inner command is not gated again. This is accepted rather than patched: the policy sees the full command.

**Gate contract** (as built in S1)

```
POST /v1/decide
{ "request_id", "session_id", "protocol": "ssh", "argv": [...], "cwd",
  "known": true|false, "interactive": true|false, "user" }
→ { "action": "allow" | "delay" | "fake_success" | "fake_error" | "terminate",
    "output": "...",      // fake_* only; capped at 64 KiB
    "exit_code": 1,       // fake_error only
    "delay_ms": 0,        // delay only; capped at 10 s
    "decision_id", "propensity" }
```

Phase 1 extends this to contract v1, adding the `http`, `redis` and `mysql` protocols and the fields `deployment_id`, `seq`, `src`, `rule_id` and `rules_version`, plus a bearer token ([phase 1 spec §3](04-phase-1-spec.md#3-gate-contract-v1)). `plant_token` joins the action set in phase 2 with the bandit (phase 1 plants tokens statically), and `escalate` joins in phase 3. Any missing, late, non-200 or malformed reply means `allow`, and the shell behaves exactly like stock Cowrie. The decoy must never hang on the policy service. Config: `[mirage] policy_enabled`, `policy_url`, `policy_timeout_ms` (target 50), `policy_idle_ms` (60000, under the policy service's 75 s keep-alive).

**Requirements on the policy service**, all measured in S1: listen on IPv4 and IPv6 (Docker resolves names to IPv6 first, and an IPv4-only service costs 300 ms per connection); HTTP/1.1 keep-alive with an idle timeout above the gate's 2 s; TCP_NODELAY (otherwise about 40 ms per decision).

Cowrie's own `llm` backend is not used. It keeps about five command/response pairs, never updates the working directory and has no filesystem. Its `LLMClient.get_response()` (`llm/llm.py:258`) is a reusable Twisted client pattern.

**Default tells to remove:** hostname `svr04`; user `phil`; the wire banner (`OpenSSH_9.2p1`) disagreeing with the shell's `ssh_version` (`OpenSSH_7.9p1`); the 2024 kernel build string; the example user database, which ends with `*:x:*` and so accepts any user with any password.

**A tell profiles cannot remove** (spike S3). Bitter Harvest's padding tell is gone: Cowrie now zero-pads its key exchange as OpenSSH does. What remains is the algorithm list. Cowrie offers algorithms OpenSSH 9.2p1 never did (CBC, 3DES, `hmac-md5`, and `mlkem768x25519-sha256`, which arrived in OpenSSH 9.9). It lacks ones Twisted does not implement (chacha20-poly1305, AES-GCM, ETM MACs, sntrup761, strict KEX). Its HASSH-server therefore matches no real OpenSSH release, and one passive look identifies it. It also rejects an `SSH-2.2` client that OpenSSH accepts. Phase 1 trims the configurable extras (`[ssh] ciphers`, `macs`, `compression`); the key-exchange list needs a code change, and the missing algorithms need either a Twisted change or a real OpenSSH in front (phase 3 decision).

**PROXY protocol.** Cowrie accepts `haproxy:` listen endpoints. The SSH edge sends a PROXY v2 header, so events carry the client's address. Only the edge can reach Cowrie, so the header cannot be forged from outside.

**Cowrie's own OCSF output.** Cowrie 3.1 ships `core/ocsf.py` (OCSF 1.8.0). MIRAGE keeps its own mapping, because it needs the policy, label and simulation fields, but follows Cowrie's class choices.

## 4. Event schema

One envelope for every source, aligned to OCSF 1.9 class names, with ECS field names available as a projection for SIEM export.

| Field | Meaning |
| --- | --- |
| `event_id`, `ts`, `ingest_ts` | Identity and times (UTC) |
| `schema_version` | Version of this schema |
| `source` | `cowrie`, `http-decoy`, `db-decoy`, `zeek`, `suricata`, `policy`, `sim` |
| `class` | OCSF-aligned class, e.g. `authentication`, `process_activity`, `network_activity`, `http_activity`, `file_activity`; `detection_finding` for the pipeline's own `token.triggered` findings (source `pipeline`) |
| `session_id`, `actor_id` | Grouping keys |
| `src`, `dst` | IP, port, ASN, geo |
| `protocol`, `action`, `outcome` | What was attempted and what the decoy returned |
| `payload` | Command, request, query or file hash |
| `policy` | `decision_id`, action, propensity |
| `labels` | Actor class, tactics, techniques, each with `model_version` and `attack_version` |
| `sim` | `scenario_id` and `step_id`, only on lab traffic |
| `raw` | The original record |

Two rules:

- Every ATT&CK label carries `attack_version`. ATT&CK v19 (April 2026) split Defense Evasion into Stealth (TA0005) and Defense Impairment (TA0112), so labels from different versions are not comparable without it.
- Lab traffic is always marked in `sim`, and that field is never a model input.

Ground-truth record on `sim.groundtruth`: `scenario_id`, `step_id`, `procedure_id`, `technique_id`, `tactic`, `attack_version`, `src`, `dst`, `start_ts`, `end_ts`, `status` (ran, failed, skipped).

## 5. LLM responder (phase 3)

The order of answering is fixed: deterministic emulator, then pre-rendered profile output, then cache, then the LLM. Spike S2 measured why the LLM has to be last and rare: on the M4 a 9B model takes a median 8.6 s per command even with prompt caching.

- **Pre-rendered profile output.** Most commands Cowrie lacks (`lscpu`, `free`, `df`, `ss`, `cat /etc/hosts`) depend only on the host profile. They are rendered once per profile, offline, checked against a real container of the claimed distribution, and installed as Cowrie text commands (`txtcmds_path`). Answers are instant and identical across sessions, as on a real host.
- **Streaming.** When the live LLM does answer, stdout streams to the terminal as it is generated (first token about 0.5 s with the cache). That reads as a slow command rather than a silent pause.
- **Where it runs.** The live model needs about 9 GB on the laptop and serves one session at a time. From phase 3 it runs on the Linux host's GPU; on the laptop it is for development only.

- **State outside the prompt.** The state manager holds the session's filesystem delta, cwd, users, processes and environment. The prompt receives the relevant slice. The model returns the output and a proposed state change, which the state manager validates and applies. This follows HoneyGPT and AdvancedShelLM; HydraPoT uses a shared state dictionary the same way.
- **Cache key:** profile ID, normalised command, and a fingerprint of the state the command depends on. Commands are classed as stateless (`uname`), state-reading (`ls`), state-changing (`touch`) and volatile (`date`, `ps`); only the first two are cached. Galah's cache ignores method and body, which this design avoids.
- **Constrained output:** JSON schema per request, so the model cannot break the response contract. S2 found the structure also improves accuracy: raw text was 62% shorter but invented missing tools. The phase 3 format puts stdout first so it can stream.
- **Budgets:** input length cap, tokens per session, tokens per source IP, concurrent-session limit, hard timeout. On any limit the emulator's answer is used.
- **Prompt injection:** attacker input is always hostile, so classifiers such as Prompt Guard 2 are a telemetry signal, not a control. The controls are that the model has no tools, no secrets and no network, and that its output passes through the state manager.
- **Never faked by the LLM:** interactive programs (`vim`, `top`) and outbound network actions. These escalate or fail believably.

## 6. Containment

| Layer | Laptop (development) | Linux host (lab and external sensor) |
| --- | --- | --- |
| Network | Docker `internal` networks for decoys and the gate. The CI egress test also allows exactly one destination, the policy port on `gate`. | nftables default-deny egress; DNS and HTTP sinkholed |
| Runtime | Standard containers, read-only root, dropped capabilities, non-root user | gVisor for decoys; microVM or QEMU pool for the high-interaction sandbox |
| Samples | Hashed, written to a quarantined volume, not executable | Same, plus optional offline detonation later |
| Sensors | Application logs only | Zeek, Suricata, eBPF syscall capture, PCAP ring buffer |

The medium-interaction decoys never execute attacker code. Only the phase-3 sandbox does, and it exists only on the Linux host, with no third-party egress under any policy decision.

## 7. Simulation lab

The lab's job is labelled telemetry. It has two drivers because the decoys differ.

**Scenario runner (phase 2), for emulated decoys.** A scenario is a YAML file of ordered steps. Each step names a protocol, an input, a `procedure_id` and an ATT&CK technique ID. The runner opens sessions against the decoys over the lab network with ordinary SSH, HTTP and database clients, applies timing profiles (scripted, human-paced), and publishes one ground-truth record per step. It refuses to run against any address outside the lab subnet.

Scenario content comes from three places: public honeypot sessions (the Zenodo corpus and CyberLab) replayed and labelled; procedure definitions indexed by technique in Atomic Red Team; and scenarios the team writes under its own rules of engagement.

**Caldera (phase 3), for the high-interaction sandbox.** Operations run against real sandboxed hosts. After each operation, `POST /api/v2/operations/{id}/event-logs` returns per-action records with `attack_metadata.{tactic, technique_id, technique_name}` and `delegated_timestamp`, `collected_timestamp` and `finished_timestamp`. A small adapter converts these to `sim.groundtruth` records.

**Documented pitfalls the design accounts for**

- Technique IDs and tool names embedded in commands leak the label. Strip them, and split train and test by `procedure_id`.
- Steps fail silently. Record `status` and drop failed steps from training.
- The people who write scenarios also assign labels, which biases the data. Keep a small set labelled independently.
- Simulated attackers are more regular than real ones. Evaluate on real sessions as soon as any exist.

## 8. Repository layout

```
mirage/
  compose/            docker compose files, networks, Vector and Grafana config
  schema/             pydantic models, JSON Schema, mappings (cowrie, http, db, zeek)
  decoys/
    common/           PROXY v2 parser, gate client, JSON-lines logging
    ssh/              Cowrie fork as a patch series on a pinned commit, patch notes
    http/             FastAPI decoy, templates
    db/               Redis and MySQL decoys
    profiles/         profile generator, profiles, Debian reference facts
    tokens/           honeytoken library and CLI
  policy/             policy service: rules, bandit, action mask
  responder/          state manager, cache, llama-server client      (phase 3)
  pipeline/           normaliser, sessioniser, ClickHouse DDL, Parquet export
  intel/              actor classifier, tagger, anomaly, correlation, analyst
  lab/                scenario runner, scenarios, ground-truth join, Caldera adapter
  eval/               held-out suite, probe suite, demo tests
  docs/
```

## 9. Memory budget on the 16 GB laptop

Measured with `docker stats` on the running phase 0 stack (11 November 2026), idle after the Gate 0 tests and a 20,000-record replay. The LLM row is still an estimate until spike S2.

| Item | Memory limit | Measured |
| --- | --- | --- |
| Cowrie | 512 MB | 55 MB |
| edge (HAProxy) | 128 MB | 13 MB |
| NATS JetStream | 256 MB | 12 MB |
| Vector | 256 MB | 116 MB |
| Normaliser | 256 MB | 48 MB |
| ClickHouse | 2 GB (server capped at 1.5 GB) | 337 MB |
| Grafana | 512 MB | 336 MB |
| **Stack total** | | **about 0.9 GB** |
| LLM, Qwen3.5-9B Q4_K_M, 4 × 4K context, native | — | about 9 GB (spike S2; free memory 19% with it running, 77% after stopping it) |
| macOS and Docker VM overhead | — | 3–4 GB (estimate) |

The stack uses less than half the 2–3 GB first estimated. The LLM does not fit comfortably beside it: with both running macOS swapped about 12.8 GB. Process RSS understates the LLM (0.9 GB) because GPU-mapped weights and the KV cache are not counted; measure system free memory instead. Caldera, MLflow and model training still run on demand rather than alongside it. HAProxy needs an explicit `maxconn`; without it, it sized itself from the container's file-descriptor limit and filled its memory limit.
