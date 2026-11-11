# MIRAGE infrastructure layer: event pipeline, storage, schema, sensing, containment, emulation lab, TI export, MLOps (state as of 11 Nov 2026)

Reading notes for the report writer:
- "Cited Findings" contain only things I confirmed against a fetched page or a search result this session. Where the source was a secondary/aggregator page I say so.
- Anything tagged **[UNVERIFIED-BACKGROUND]** comes from my prior knowledge (cutoff mid-2026) and was NOT re-checked this session; these are placed under Inferences or Gaps, never under Cited Findings.
- Memory footprints: I found almost no primary-source numbers. All footprint figures in the "Inferences" blocks are engineering estimates, to be measured with `docker stats` in week 1, not quoted as facts.
- Scope was very wide; about 45 tool calls were used. Version numbers for several tools still need a 2-minute check on the official release page before pinning (listed per section).

---

## 0. Overall recommendation: right-sized 12-week stack and what to defer

### Takeaway
For a 3-4 person team on a 16 GB arm64 Mac, the minimum viable infrastructure is: honeypots writing JSON logs -> Vector (file tail) -> NATS JetStream (single binary bus) -> a plain Python asyncio consumer (normaliser/sessioniser, pydantic models aligned to OCSF with ECS field names kept as aliases) -> ClickHouse (single node, memory-capped) plus Parquet files on disk for ML -> Grafana. Everything JVM-based (Kafka, OpenSearch, Elastic/T-Pot stack), eBPF sensors, Arkime, CAPEv2, MISP/OpenCTI, Feast, gVisor/Kata are deferred to the Linux deployment phase or until scale demands them.

### Cited Findings
- T-Pot's own stated requirement is 16 GB RAM / 256 GB SSD for a standard Hive and 8 GB / 128 GB for a sensor; it is built on the Elastic Stack (Elasticsearch, Logstash, Kibana) plus Suricata, P0f, Fatt, attack map, Spiderfoot, CyberChef; it is multi-arch (amd64, arm64); Docker Desktop on macOS is supported "with limits" (not all honeypots/features) — [telekom-security/tpotce README](https://github.com/telekom-security/tpotce)
- Caldera alone recommends 8 GB+ RAM and 2+ CPUs for the server host — [apache/caldera README](https://github.com/apache/caldera)
- OpenCTI Core alone is documented at 2 cores and >= 8 GB RAM (5.7 and 6.1 docs; no v7-specific figure found) — [OpenCTI deployment overview](https://docs.opencti.io/latest/deployment/overview/)
- OpenSearch defaults to a 1 GB JVM heap (`-Xms1g -Xmx1g`), docs examples use 512 MB for dev; heap is conventionally about half of node RAM — [OpenSearch 3.4 install docs](https://docs.opensearch.org/3.4/install-and-configure/install-opensearch/index/); a user reported roughly doubled memory use after upgrading 2.15 -> 3.4 — [OpenSearch forum](https://forum.opensearch.org/t/opensearch-upgrade-2-15-3-4-using-almost-double-the-amount-of-memory/27760)

### Inferences
- RAM budget on a 16 GB Mac (estimates, not measured): macOS + IDE + browser about 5-6 GB; Docker Desktop VM capped at about 8 GB; inside it: small local LLM (a 3-4 GB quantised model is the single biggest tenant), 2-3 honeypot containers (about 0.3-0.6 GB total), NATS (< 100 MB), Vector (< 150 MB), Python normaliser (about 100-200 MB), ClickHouse capped at 1.5-2 GB, Grafana (about 150-250 MB), MLflow with SQLite (about 300 MB, started on demand). That fits. Adding any one of OpenSearch (>= 1.5-2 GB realistic), Kafka JVM (>= 1 GB), Caldera (docs say 8 GB recommended), OpenCTI (>= 8 GB) or T-Pot (16 GB) breaks the budget, so those must be run on demand in a separate compose profile or on the Linux host.
- Use Docker Compose **profiles**: `core` (bus, vector, normaliser, clickhouse, grafana), `honeypots`, `llm`, `lab` (emulation range, never up at the same time as `llm` on the laptop), `ti` (medallion/STIX export), `mlops` (mlflow).
- Deferral list with trigger: Kafka/Redpanda (when > about 5k events/s sustained, multi-consumer replay with partitions, or you need the Kafka connector ecosystem); OpenSearch (when analysts need full-text search/Dashboards or Sigma-on-OpenSearch backends); Arkime (when PCAP retention > tens of GB and needs indexed session search); Falco/Tetragon/Tracee (Linux host only); gVisor (Linux VPS deployment, week 8+); CAPEv2 (needs KVM host, separate project); MISP/OpenCTI (when sharing with a community); Feast (when there is online feature serving with train/serve skew risk); Flink (never at this scale).

### Gaps
- No primary-source idle-memory numbers were found for NATS, Vector, ClickHouse, Redpanda, Grafana or MLflow; all need measuring.

---

## 1. Event bus: Kafka (KRaft) vs Redpanda vs NATS JetStream vs Redis Streams

### Takeaway
At a few events/s to low thousands/s every option is over-capacity; the choice is about footprint, licence and operational simplicity. NATS JetStream (Apache-2.0, single small Go binary) is the minimum viable durable bus; Redis/Valkey Streams is the fallback if a Redis-compatible store is already in the stack; Kafka/Redpanda are deferred.

### Cited Findings
- Apache Kafka: Apache-2.0; Kafka 4.0 removed ZooKeeper so all 4.x is KRaft-only — [Conduktor glossary](https://conduktor.io/glossary/redpanda-vs-kafka). Kafka 4.2.0 announced 17 Feb 2026; 4.2.1 on 30 May 2026; 4.2.2 on 29 Sep 2026; the Apache blog index also lists a 4.3.0 announcement, so 4.3.x is probably the newest line — [Kafka 4.2.2 announcement](https://kafka.apache.org/blog/2026/09/29/apache-kafka-4.2.2-release-announcement/), [Kafka blog index](https://kafka.apache.org/blog/)
- Redpanda: Community Edition is BSL 1.1, converting to Apache-2.0 after 4 years; the restriction is mainly on offering it as a managed service, not on internal use (secondary source) — [Conduktor glossary](https://conduktor.io/glossary/redpanda-vs-kafka). Current lines: 26.1 (GA 31 Mar 2026, supported until 31 Mar 2027) and 26.2 (v26.2.5 dated 16 Oct 2026) — [Redpanda release notes](https://docs.redpanda.com/streaming/current/reference/releases/redpanda/), [Redpanda 26.1 press release](https://www.redpanda.com/press/redpanda-streaming-26-1-introduces-industrys-first-adaptable-streaming-engine)
- NATS: Apache-2.0, CNCF; ships as a single roughly 20 MB `nats-server` binary (vendor white paper, Synadia) — [Synadia "Beyond streaming"](https://www.synadia.com/resources/beyond-streaming). nats-server 2.12 added counter streams, delayed message scheduling and strict JetStream API mode by default — [NATS 2.12 what's new](https://docs.nats.io/release-notes/whats_new/whats_new_212). The newest 2.12 patch seen was v2.12.14, and the release-tracker pages show the latest overall release as v2.14.4, i.e. 2.14.x is the current line — [newreleases.io nats-server v2.12.14](https://newreleases.io/project/github/nats-io/nats-server/release/v2.12.14)
- Redis: BSD-3 up to 7.2.x, RSALv2/SSPLv1 from 7.4, and Redis 8 (May 2025) is tri-licensed RSALv2 / SSPLv1 / AGPLv3 — [Redis blog](https://redis.io/blog/what-is-valkey/), [AlternativeTo news](https://alternativeto.net/news/2025/5/redis-goes-open-source-again-with-the-launch-of-redis-8-under-the-agplv3-license)
- Valkey: BSD-3-Clause, Linux Foundation governance; Valkey 9.x is current (sources disagree whether 9.0.0 was Oct 2025 or a GA in April 2026) — [cloudmagazin](https://www.cloudmagazin.com/en/2026/04/14/valkey-9-ga-what-the-cache-fork-means-for-dach-ops-teams-18/), [tech-insider](https://tech-insider.org/valkey-vs-redis-2026/)
- A third-party benchmark exists for Kafka 4.2.0 KRaft vs Redpanda 26.1.2 on 4 vCPU / 8 GB (results not retrieved) — [computingforgeeks](https://computingforgeeks.com/kafka-vs-redpanda-benchmarks/)

### Inferences
- Recommended: **NATS JetStream 2.14.x**, one container, file storage, one stream per stage (`raw.>`, `norm.>`, `labels.>`). Python client `nats-py` (asyncio). Vector has both a `nats` source and sink **[UNVERIFIED-BACKGROUND — check the Vector component docs for JetStream support in the source/sink at 0.61]**.
- Lighter alternative: **Valkey Streams** (BSD-3) if a KV/cache is needed anyway; avoid Redis 8 only if AGPL/RSAL terms are a concern for a redistributed product (for internal research use AGPL is fine).
- Even lighter: no bus at all for weeks 1-3 (Vector -> ClickHouse directly, plus Vector -> file for the Python normaliser). Introduce the bus when the second consumer (ML scorer / adaptive engine) appears.
- If the team wants Kafka API compatibility for CV/ecosystem reasons: Redpanda single-node in dev-container mode is lighter than JVM Kafka **[UNVERIFIED-BACKGROUND: `--mode dev-container --smp 1 --memory 1G` flags and multi-arch image]**; BSL does not restrict an internal honeypot platform but would matter if MIRAGE were ever offered as hosted streaming.
- Keep the producer/consumer code behind a thin `EventBus` interface so the bus can be swapped to Kafka later without touching the normaliser.

### Gaps
- Exact latest patch versions for Kafka (4.3.x?), NATS (2.14.x) and Valkey (9.1.x?) need checking on their release pages.
- No measured idle RSS for each broker on arm64 Docker; the only footprint evidence is vendor/secondary.
- I did not verify the reported "2025 NATS relicensing dispute" beyond a secondary mention that NATS stayed Apache-2.0/CNCF.

---

## 2. Collection: Vector vs Fluent Bit vs Filebeat

### Takeaway
Vector is the best fit (one static Rust binary, VRL for light parsing, sinks for every candidate bus/store). Fluent Bit is the lighter alternative; Filebeat only makes sense if committing to the Elastic stack.

### Cited Findings
- Vector latest is 0.61.0 (29 Oct 2026); 0.60.0 (19 Oct), 0.59.0 (6 Oct), 0.58.0 (26 Aug 2026). Release cadence is fast (three releases in October) — [vector.dev/releases](https://vector.dev/releases/)
- Vector 0.57 deprecated `${VAR}`/`SECRET[...]` placeholders in structural positions of config; 0.54 deprecated `azure_monitor_logs`; i.e. config needs re-validating on upgrade — [Vector 0.57.0 notes](https://vector.dev/releases/0.57.0/), [Vector 0.54.0 notes](https://vector.dev/releases/0.54.0/)

### Inferences
- **[UNVERIFIED-BACKGROUND]** Vector is MPL-2.0 (Datadog-owned), publishes multi-arch images (`timberio/vector`, including arm64), and has `file`/`docker_logs` sources and `kafka`, `nats`, `clickhouse`, `elasticsearch` (used for OpenSearch), `aws_s3`, `file`, `http` sinks. Confirm on [vector.dev/docs/reference/configuration](https://vector.dev/docs/reference/configuration/) and the repo LICENSE.
- **[UNVERIFIED-BACKGROUND]** Fluent Bit is Apache-2.0, C, single-digit-MB footprint, arm64 images, outputs for Kafka/NATS/OpenSearch/HTTP; ClickHouse is reached via the HTTP output. Filebeat is Elastic License 2.0 and has no native ClickHouse/NATS output.
- Pattern: honeypot containers write JSON to a shared named volume (read-only mount into Vector); Vector adds `sensor_id`, `honeypot_type`, ingestion timestamp and ships raw events unchanged to the bus. Keep heavy normalisation in Python where it is unit-testable; use VRL only for envelope fields.

### Gaps
- Licence, arm64 image and exact sink list for Vector 0.61 not re-verified this session; Fluent Bit and Filebeat current versions not checked.

---

## 3. Stream processing for a small Python normaliser/sessioniser

### Takeaway
Do not build on Faust. For MIRAGE volumes a plain asyncio consumer (about 200-400 lines) with pydantic validation and an in-memory session table keyed by `session_id` with idle timeout is sufficient; Quix Streams is the only healthy Python streaming framework if the team later moves to Kafka/Redpanda.

### Cited Findings
- `faust-streaming/faust` is the community fork of robinhood/faust, created because of the upstream release process; New BSD licence; aiokafka-only; 118 open issues / 34 open PRs; README is internally inconsistent about Python versions (3.6 vs 3.10+); repo carries `RELEASE_NOTES_v0.12.1.md` — [faust-streaming/faust](https://github.com/faust-streaming/faust)
- Snyk rates faust-streaming maintenance as "inactive" (no PyPI release in the past year, little PR/issue activity) — page undated — [Snyk faust-streaming](https://security.snyk.io/package/pip/faust-streaming)
- Bytewax (Apache-2.0) repo banner: "Bytewax is now community-maintained"; as of May 2025 the company is no longer commercially viable and the core team stepped back; maintainer pool being rebuilt — [bytewax/bytewax](https://github.com/bytewax/bytewax)
- Quix Streams: Apache-2.0; "Python Streaming DataFrames for Kafka"; windowing, group-by, joins, stateful ops, sources/sinks API, exactly-once via Kafka transactions; requires Python 3.11+ and Kafka 0.10+ — [quixio/quix-streams](https://github.com/quixio/quix-streams)
- Arroyo (Rust, SQL-first) was acquired by Cloudflare (announced 10 Apr 2025) to power Cloudflare Pipelines; engine remains open source but focus is Cloudflare integration — [Cloudflare blog](https://blog.cloudflare.com/cloudflare-acquires-arroyo-pipelines-streaming-ingestion-beta/)

### Inferences
- Recommendation: plain consumer (`nats-py` pull consumer with explicit ack, or `confluent-kafka`/`aiokafka` later). Sessionisation is easy for honeypots because Cowrie already emits a `session` id and `cowrie.session.closed`; the consumer only needs timeout-based close for protocols without an explicit end and a periodic flush of session summaries.
- Quix Streams is Kafka-only, so it is not usable with NATS; adopt it only together with Redpanda/Kafka.
- Flink/PyFlink: JVM cluster (JobManager + TaskManager), multi-GB; overkill at this scale. **[UNVERIFIED-BACKGROUND]** robinhood/faust has had no release since 2020.
- Make the normaliser idempotent (deterministic `event_uid` = hash of source + raw line offset) so replays from the bus do not duplicate rows (ClickHouse `ReplacingMergeTree` or dedup at query time).

### Gaps
- Latest release numbers/dates for faust-streaming, Bytewax and Quix Streams were not visible on the fetched pages (check PyPI).

---

## 4. Storage: OpenSearch vs ClickHouse vs lighter start; what T-Pot uses

### Takeaway
Start with ClickHouse only (analytics + dashboards) plus Parquet on disk (ML training sets, DuckDB for notebooks). OpenSearch is the heaviest single component a small stack can add and should be deferred until full-text search or OpenSearch Dashboards/Sigma backends are actually needed.

### Cited Findings
- OpenSearch: 3.7.0 is on Docker Hub and docs exist up to 3.8, so the current line is 3.7/3.8; default heap is 1 GB; dev examples run 512 MB heap — [OpenSearch 3.8 install docs](https://docs.opensearch.org/3.8/install-and-configure/install-opensearch/index/), [newreleases.io OpenSearch 3.7.0](https://newreleases.io/project/github/opensearch-project/OpenSearch/release/3.7.0)
- ClickHouse: monthly releases; trackers disagree on newest stable — 26.9.18.11-stable (13 Oct 2026) with 26.8.x as LTS per versionlog; GitClear lists v26.10.2.103-stable (24 Oct 2026) — neither is an official page — [versionlog](https://versionlog.com/clickhouse/), [GitClear](https://www.gitclear.com/open_repos/ClickHouse/clickhouse/release/v26.9.25.15-stable)
- T-Pot uses the Elastic Stack and asks for 16 GB (hive) / 8 GB (sensor); licence GPL-3.0; README references 24.04.x; it ships data to Telekom's Sicherheitstacho by default via `ewsposter` (opt-out by removing that service) — [tpotce README](https://github.com/telekom-security/tpotce)
- Grafana 13 was released April 2026 (GrafanaCON) and advertises 170+ data sources — [Grafana press release](https://grafana.com/press/2026/04/21/grafana-labs-launches-grafana-13-at-grafanacon-2026-makes-open-observability-easier-to-run-at-scale/)

### Inferences
- **[UNVERIFIED-BACKGROUND]** ClickHouse is Apache-2.0, official `clickhouse/clickhouse-server` image is multi-arch incl. arm64, and can be constrained for laptops with `max_server_memory_usage` (or `max_server_memory_usage_to_ram_ratio`), reduced `mark_cache_size`, and small `background_pool_size`; realistic laptop cap 1.5-2 GB. Grafana has an official ClickHouse data source plugin, an OpenSearch plugin, built-in PostgreSQL (Timescale), and community DuckDB/Infinity plugins. Grafana OSS is AGPLv3.
- Lighter-still alternatives: (a) **DuckDB + Parquet** — zero server, ideal for the ML side and for week 1-2 before any DB exists, but no concurrent writer/live dashboards; (b) **Postgres/TimescaleDB** — sensible if the team also needs a relational store for the control plane (sessions, honeypot configs, labels), about 200-400 MB; a reasonable MVP is "Postgres for state + ClickHouse for events", or Postgres-only for the first weeks.
- "Both" (ClickHouse + OpenSearch) doubles ops burden; the only strong reason is analyst free-text search over command strings/payloads — ClickHouse token/ngram bloom-filter or text indexes cover most of that at MIRAGE scale.
- Do not adopt T-Pot as the base: its 16 GB requirement equals the whole laptop. Borrow from it instead: honeypot Dockerfiles, attack-map idea, Kibana dashboard layouts; run a T-Pot sensor only on the VPS if wanted.

### Gaps
- No official ClickHouse minimum-RAM statement retrieved; exact newest stable needs checking at [ClickHouse changelog](https://clickhouse.com/docs/whats-new/changelog).
- Latest T-Pot version (24.04.1 or newer) not confirmed; OpenSearch licence (Apache-2.0) and arm64 image not re-verified this session.

---

## 5. Event schema: ECS vs OCSF vs OpenTelemetry semconv; Cowrie mapping

### Takeaway
Align the canonical MIRAGE event with OCSF (vendor-neutral, class-based, versioned, now has AI-operation and record-integrity profiles useful for an LLM honeypot) and pin a version (1.9.0 current); keep ECS-style dotted names as a secondary projection for Sigma/Elastic-ecosystem compatibility. OTel semantic conventions are for instrumenting MIRAGE's own services, not for security events.

### Cited Findings
- OCSF latest is 1.9.0 (3 Aug 2026): adds user/role management, clipboard activity and device power state classes, a `record_integrity` profile (cryptographic attestation of events), a `delegation` object for the `ai_operation` profile, DNS Activity restructuring. 1.8.0 (16-18 Mar 2026): `ai_operation` profile with AI model/message objects, macOS extension, `packet` object. 1.7.0 (14 Nov 2025): Peripheral Activity class, `reporter` object. 1.6.0 (1 Aug 2025): IAM Analysis Finding, `port_info` — [ocsf-schema releases](https://github.com/ocsf/ocsf-schema/releases)
- ECS: current line is 9.x; 9.4.0 added field-maturity (alpha/beta/GA) definitions; 9.0.0 added an ECS<->OpenTelemetry mapping; 9.1.0 generates against OTel semconv v1.34.0; a third-party page references 9.5.0 as latest (unconfirmed) — [ECS release notes](https://www.elastic.co/docs/release-notes/ecs)
- Tenzir's OCSF operators track schema versions (1.6.0 support added Aug 2025) and Tenzir publishes per-version class references — a usable validator/mapper reference implementation — [Tenzir OCSF reference](https://docs.tenzir.com/reference/ocsf)
- Cowrie: a secondary guide reports v3.1.3 (19 Oct 2026) as latest and BSD licence; official changelog shows output plugins added over time (Datadog, Oracle, Remote Syslog, Axiom) — [Cowrie changelog](https://docs.cowrie.org/en/stable/CHANGELOG.html), [tech-insider (secondary)](https://tech-insider.org/sv/?p=4300)

### Inferences
- **[UNVERIFIED-BACKGROUND]** Relevant OCSF classes (verify UIDs at [schema.ocsf.io](https://schema.ocsf.io)): Network Activity 4001, HTTP Activity 4002, DNS Activity 4003, SSH Activity 4007, File Transfer/FTP 4008, Authentication 3002, Process Activity 1007, File System Activity 1001, Detection Finding 2004; ATT&CK is carried in the `attacks[]` object (tactic/technique/sub_technique) which makes OCSF a natural carrier for ground-truth labels and model predictions.
- **[UNVERIFIED-BACKGROUND]** Proposed Cowrie eventid -> OCSF / ECS mapping (no official mapping was found; this is a design proposal):
  - `cowrie.session.connect` -> Network Activity (Open) / ECS `event.category:[network]`, `event.type:[connection,start]`, `source.ip`, `source.port`, `destination.port`, `network.protocol:ssh`
  - `cowrie.client.version`, `cowrie.client.kex` (incl. `hassh`) -> SSH Activity / ECS `ssh.*`-style custom fields, `user_agent.original`; put HASSH under a `mirage.fingerprint.hassh` extension
  - `cowrie.login.success|failed` -> Authentication (Logon; status success/failure) / ECS `event.category:[authentication]`, `event.outcome`, `user.name` (password in a custom, access-restricted field)
  - `cowrie.command.input|failed` -> Process Activity (Launch) with `process.cmd_line` (emulated shell; mark `metadata.labels:["emulated"]`) / ECS `event.category:[process]`, `process.command_line`
  - `cowrie.session.file_download|file_upload` -> File Transfer / File System Activity (Create) with `file.hashes[]`, `url` / ECS `file.hash.sha256`, `url.original`
  - `cowrie.direct-tcpip.request|data` -> Network Activity (tunnelled; `proxy`/`dst_endpoint`) / ECS `destination.*`
  - `cowrie.log.closed` (tty log) -> artefact reference (object-store key + sha256) ; `cowrie.session.closed` -> Network Activity (Close) with `duration`
- **[UNVERIFIED-BACKGROUND]** Python libraries: `py-ocsf-models` (pydantic models, from the Prowler team, partial class coverage), `ocsf-lib-py`/`ocsf-validator` (schema tooling); `ecs-logging` (ECS JSON log formatter for MIRAGE's own service logs, not a model library). Existence/versions were not confirmed this session — check PyPI. Safer plan: generate pydantic v2 models for just the 6-8 classes needed from the OCSF JSON schema export for the pinned version, and validate in CI.
- Envelope design: `metadata.version` (OCSF version), `metadata.uid` (deterministic), `metadata.product` (honeypot name/version), `time` (event) vs `metadata.logged_time` (ingest), `observables[]`, plus a namespaced `unmapped`/`mirage.*` extension for honeypot-specific fields (persona id, LLM prompt/response ids, deception action taken, ground-truth label id).

### Gaps
- No published Cowrie -> ECS or Cowrie -> OCSF mapping was found (Elastic's legacy Filebeat/Logstash Cowrie configs and T-Pot's Logstash pipeline are the nearest prior art; not fetched).
- Did not confirm the status of the ECS -> OpenTelemetry donation/convergence beyond the 9.0/9.1 release-note entries.
- OCSF class UIDs above not verified against 1.9.0.

---

## 6. Sensing: Zeek, Suricata, fingerprints, eBPF, PCAP

### Takeaway
On the Mac, do application-level logging only (honeypot JSON logs carry HASSH etc.) plus an optional tcpdump sidecar; run Zeek/Suricata and any eBPF sensor only on the Linux host, where the Docker bridge is a real host interface. JA4 (TLS client) is BSD-3 and safe; the rest of JA4+ is under the FoxIO Licence 1.1 (fine for internal research, not for a monetised product without an OEM licence).

### Cited Findings
- Zeek: 8.0.x is the current LTS (8.0.9 dated 6 Jul 2026 on the official page; a secondary source mentions 8.0.10 on 19 Aug 2026); 8.1 was introduced Jan 2026 and 8.2 RCs appeared Apr 2026 — [zeek.org/get-zeek](https://zeek.org/get-zeek/), [Introducing Zeek 8.1](https://zeek.org/2026/01/introducing-zeek-8-1/)
- JA4+ Zeek plugin v1.0.0 was tested on amd64 and arm64 against Zeek 8.0.x and 8.2.x; installable with `zkg install zeek/foxio/ja4` — [FoxIO ja4 v1.0.0](https://newreleases.io/project/github/FoxIO-LLC/ja4/release/v1.0.0), [Zeek blog: JA4 in Zeek](https://zeek.org/2026/01/how-to-use-ja4-network-fingerprints-in-zeek/)
- Licensing: JA4 (TLS client) is BSD 3-Clause "same as JA3"; JA4S, JA4L, JA4H, JA4X, JA4SSH, JA4T, JA4TScan "and all future additions" are FoxIO License 1.1, which permits most uses but bars monetisation without an OEM licence; open-source projects may implement JA4+ if they reference the FoxIO licence — [FoxIO License FAQ](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md)
- Suricata: 8.0.x is current (8.0.3 in Jan 2026; 8.0.5 referenced by Security Onion 3.1.0 on 21 May 2026) — [Security Onion blog](https://blog.securityonion.net/search/label/release?m=0)
- Tetragon: install docs say it cannot be run on Docker Desktop for macOS because of the Docker Desktop VM; the FAQ adds that sensors can load on recent Docker Desktop (e.g. 24.0.6, kernel 6.4.16-linuxkit) and that older VMs lacked BTF — [Tetragon FAQ](https://tetragon.cilium.io/docs/faq/), [Tetragon Docker install](https://tetragon.netlify.app/docs/getting-started/install-docker)
- Tracee: Linux only; docs say the Docker Desktop macOS VM kernel historically lacked CO-RE support and recommend a Linux VM — [Tracee mac docs](https://aquasecurity.github.io/tracee/dev/docs/advanced/mac)
- General guidance for eBPF on a Mac: use a full Linux VM (Lima/Multipass), not Docker Desktop's LinuxKit kernel — [dev.to guide](https://dev.to/hyperredstart/ebpf-on-a-mac-a-5-minute-linux-vm-with-multipass-or-lima-5dng)
- T-Pot's sensor set is Suricata + P0f + Fatt (fingerprinting) — [tpotce README](https://github.com/telekom-security/tpotce)
- Arkime 6 requires Node.js 22, moved the UI to Vue 3 and adds 30+ parsers; it needs an OpenSearch/Elasticsearch backend — [Arkime v6 release](https://arkime.com/release-v6)

### Inferences
- macOS vs Linux capture: on Linux, `docker network create` produces a `br-<id>` bridge on the host; a sensor container with `network_mode: host` + `NET_ADMIN`/`NET_RAW` can sniff it. On Docker Desktop the bridge lives inside the LinuxKit VM: a `network_mode: host` container sees the VM's interfaces (so capture can work inside the VM), but it is fragile across Docker Desktop versions and not representative. Portable alternative that works on both: a **sidecar sharing the honeypot's network namespace** (`network_mode: "service:cowrie"`) running `tcpdump -G 3600 -W 24` (hourly ring buffer) or Suricata in pcap mode.
- **[UNVERIFIED-BACKGROUND]** Official `zeek/zeek` and `jasonish/suricata` images are multi-arch incl. arm64; Suricata 7+/8 computes JA4 natively (`ja4.hash`, build/feature-gated) and JA3/JA3S; Zeek has JA3 and HASSH via zkg packages (`salesforce/ja3`, `salesforce/hassh`); Cowrie itself logs `hassh` in `cowrie.client.kex`. JA3 and HASSH are BSD-3 (Salesforce).
- Falco **[UNVERIFIED-BACKGROUND]**: Apache-2.0, CNCF graduated, modern-eBPF probe needs BTF and a supported kernel; treat as Linux-only like Tetragon/Tracee. For the MVP none of the three is needed: a medium-interaction honeypot (Cowrie-style) has no real syscalls worth tracing; eBPF only matters once there are high-interaction containers. Pick **one** (Tetragon for low overhead and policy-based enforcement, or Falco for rule ecosystem) at that point.
- PCAP: tcpdump ring buffer + Zeek logs is sufficient for the first 12 weeks; Arkime drags in OpenSearch and Node 22 and is only justified for analyst-driven session search over large retention.
- Development recommendation: give one team member a small Linux arm64 VM (Lima/UTM/OrbStack) or use the VPS as the "sensor integration" environment from about week 6; keep Mac compose files sensor-free.

### Gaps
- No Falco statement about Docker Desktop for Mac found; no current primary confirmation of arm64 tags for zeek/suricata images; Suricata 8 JA4 status not confirmed; latest Suricata 8.0.x patch as of Nov 2026 unknown.

---

## 7. Containment, sinkholes, sample storage, AUPs

### Takeaway
Minimum safe containment for an internet-facing medium-interaction honeypot on a VPS: dedicated throwaway VM (nothing else on it, separate cloud account/project and SSH keys), honeypot containers non-root with all capabilities dropped and read-only rootfs, on a Docker network with no route out except explicitly allow-listed download egress via a logging proxy (or none), host firewall default-deny outbound for the honeypot bridge with rate-limited exceptions, management plane reachable only via VPN/allow-listed IP, logs shipped off-box. gVisor is the pragmatic extra layer on a cloud VM (no KVM needed); Kata/Firecracker need KVM/nested virtualisation.

### Cited Findings
- gVisor's default Systrap platform runs on any Linux host without KVM; runsc can be added as a runtime inside Docker Desktop (2024 write-up); Kata could not be tested in Docker Desktop because it needs nested virtualisation — [dev.to: gVisor in Docker Desktop](https://dev.to/rimelek/using-gvisors-container-runtime-in-docker-desktop-374m), [Northflank: Kata vs gVisor](https://northflank.com/blog/kata-containers-vs-gvisor)
- Kata Containers and Firecracker need a hardware virtualisation backend (KVM); inside a cloud VM that means nested virtualisation, which many providers disable or reserve for bare metal — [fly.io: Firecracker vs gVisor](https://fly.io/learn/firecracker-vs-gvisor/), [Northflank: microVM vs gVisor](https://northflank.com/blog/microvm-vs-gvisor)
- Caldera and T-Pot both state explicitly that they should not be exposed/trusted: T-Pot says compromise cannot be ruled out, keep no sensitive data, firewall management ports (> 64000) to trusted IPs, and notes some honeypots need outbound connections to fetch attacker malware — [tpotce README](https://github.com/telekom-security/tpotce)
- MinIO community edition: admin features stripped from the console (May 2025); Docker images/binaries no longer published (Oct 2025); maintenance mode from 3 Dec 2025; repository archived in 2026 (sources give 12-13 Feb 2026 and a re-archive on 25 Apr 2026) — [InfoQ](https://www.infoq.com/news/2025/12/minio-s3-api-alternatives), [It's FOSS](https://itsfoss.com/news/minio-moves-away-from-open-source/), [vonng blog](https://blog.vonng.com/en/db/minio-resurrect/), [glukhov.org](https://glukhov.org/data-infrastructure/object-storage/minio-dead/)
- Garage: AGPLv3, aimed at small self-hosted/geo-distributed deployments, 2.x line current (v2.3.0, April 2026 per secondary sources) — [deuxfleurs-org/garage](https://github.com/deuxfleurs-org/garage), [youngju.dev comparison](https://www.youngju.dev/blog/2026-07-17-minio-archived-garage-seaweedfs-ceph-rgw.en)
- SeaweedFS: core Apache-2.0 with a proprietary enterprise edition; 4.x line (4.39, 10 Jul 2026 per an aggregator) — [ideaproof aggregator](https://ideaproof.io/open-source/project/seaweedfs)
- INetSim: latest is still 1.3.2 dated 2020-05-19 (as packaged by Kali, package page updated Mar 2026) — [Kali tools: inetsim](https://www.kali.org/tools/inetsim/)
- FakeNet-NG: releases up to v3.5 exist (dates not retrieved) — [flare-fakenet-ng releases](https://github.com/fireeye/flare-fakenet-ng/releases)
- DigitalOcean AUP: "You may not ... conduct any security or malware research on or using the Services, without DigitalOcean's prior written consent"; it also prohibits hosting "Harmful Software" (viruses, malware, ...). Honeypots are not mentioned by name — [DigitalOcean AUP](https://www.digitalocean.com/legal/acceptable-use-policy)
- AWS AUP prohibits network abuse (DDoS, open proxies/relays) and allows suspension without notice; honeypots/malware research are not named in the retrieved text — [AWS AUP](https://aws.amazon.com/aup)
- Wiz's cloud-honeypot guidance: check the provider AUP (some prohibit deception/security research) and put honeypots in separate subnets with explicit deny-all egress — [Wiz academy](https://www.wiz.io/academy/detection-and-response/what-is-a-honeypot-in-cloud-security)

### Inferences
- Enforcement recipe (Linux VPS): (1) `docker network create --internal hp_net` for honeypots (no NAT/gateway); (2) publish ports via a tiny L4 forwarder/reverse proxy container that sits on both `hp_net` and the public network, so the honeypot itself has no default route; (3) if download capture is wanted, route only through an egress proxy container that allow-lists HTTP/HTTPS GET, caps size/rate, logs, and writes straight to quarantine storage; (4) nftables rules in the `DOCKER-USER` chain: default drop for traffic sourced from the honeypot bridge, explicit drop of SMTP/25, SSH/22 and RFC1918/metadata-service (169.254.169.254) destinations, rate limit new outbound connections; (5) cloud security group mirrors the same policy as a second layer; (6) per-container `--cap-drop=ALL --security-opt no-new-privileges --read-only --pids-limit --memory --cpus`, userns-remap or rootless Docker, default seccomp; (7) `--runtime=runsc` for anything executing attacker-influenced code. On the Mac, only (1), (2) and (6) are meaningful — and the Mac must never be internet-exposed.
- Cilium is a Kubernetes-scale answer (eBPF dataplane, L7 policy); not for a single-VPS Docker Compose deployment. Revisit only if MIRAGE moves to k3s.
- Sinkholes: INetSim is effectively unmaintained since 2020 but still works for DNS/HTTP faking; FakeNet-NG is maintained by Mandiant/FLARE (Windows/Linux). For MIRAGE's medium-interaction honeypots a sinkhole is rarely needed: Cowrie emulates `wget/curl` itself. A minimal sinkhole = CoreDNS/dnsmasq answering everything with the sinkhole IP + a catch-all HTTP server that logs requests. Only high-interaction/detonation needs more.
- Sample handling: store by sha256, never executable bit, never on the dev Mac's host filesystem in plain form (macOS XProtect/AV and corporate EDR will react; and it avoids accidental execution) — keep inside a Docker named volume, optionally password-zip ("infected") or XOR-encode at rest; hash-only lookups to external services by default; no sample uploads to third parties without a team decision. Storage choice: **plain filesystem volume with content-addressed paths for the MVP**; if an S3 API is wanted, Garage (single binary, AGPL — fine for internal use) or SeaweedFS (Apache-2.0); do not start new work on MinIO CE. 
- **[UNVERIFIED-BACKGROUND]** CAPEv2 needs a dedicated x86-64 Ubuntu LTS host with KVM/QEMU (bare metal or nested virt), Windows guest images, Postgres/Mongo; it does not run usefully on an arm64 Mac or a small VPS. Defer; for the MVP use static triage only (hash, file type, YARA, strings) in a no-network container.
- AUP practice: choose a provider whose terms do not forbid security research, or get written consent (DigitalOcean explicitly requires it for malware research). Tell the provider's abuse desk in advance, keep egress default-deny so no abuse reports are generated, and keep the honeypot in an account/project isolated from anything else the team owns.

### Gaps
- Hetzner, OVH, Vultr, Linode/Akamai, GCP and Azure terms on honeypots/malware were not retrieved; the AWS AUP text seen was a 2021-dated snippet. Needs direct checking before choosing a host.
- gVisor's own arm64 support statement and runsc-on-Docker-Desktop-arm64 not confirmed from gVisor docs.
- CAPEv2 requirements not verified from its docs; FakeNet-NG release dates not confirmed.
- MinIO archive date is inconsistent across sources (Feb vs Apr 2026).

---

## 8. Adversary-emulation lab for labelled data (isolated purple-team range)

### Takeaway
Caldera (now Apache Caldera, Apache-2.0, v5.3.0) already emits exactly the ground-truth record needed: per-link ATT&CK tactic/technique IDs with delegated/collected/finished timestamps, agent host/paw/pid, in both the operation report and the event-log JSON. But Caldera is heavy (8 GB recommended) and aimed at endpoint post-compromise behaviour; for labelled SSH/HTTP honeypot sessions a small scripted scenario runner that writes its own label records is the lighter and more relevant MVP, with Caldera/Atomic used later on a Linux host. The documented pitfalls (label leakage via artefacts, designer bias, failed steps, benign-background realism) must be designed for from day one.

### Cited Findings
Caldera
- Repo is now `apache/caldera`; licence Apache-2.0; latest release v5.3.0 (the release page shows "24 Apr"; a mirror dates it 24 Apr 2025), preceded by 5.2.0, 5.1.0 and 5.0.0 "Magma"; v5.1.0+ patches CVE-2025-27364 (users are urged to upgrade) — [apache/caldera releases](https://github.com/apache/caldera/releases), [apache/caldera README](https://github.com/apache/caldera)
- MITRE announced (May 2026) it is contributing Caldera to the Apache Incubator as Apache Caldera (Incubating) — [MITRE 360, July 2026](https://www.mitre.org/news-insights/mitre-360/mitre-360-july-2026)
- Requirements: Linux or macOS, Python 3.10+, 8 GB+ RAM and 2+ CPUs recommended, Go 1.24+ to compile agents, NodeJS 16+ for the v5 Vue UI. Docker: `docker build --build-arg VARIANT=full -t caldera .` ("full" for offline environments; "slim" fetches emu/atomic data on demand); prebuilt `ghcr.io/apache/caldera:latest` may be outdated — [apache/caldera README](https://github.com/apache/caldera)
- Default plugins: Access, Atomic, Builder, Caldera for OT, Compass, Debrief, Emu, Fieldmanual, GameBoard, Human, Magma, Manx, Response, Sandcat, SSL, Stockpile, Training. Stockpile supplies the stock abilities/adversary profiles/planners; Mock provides simulated agents — [apache/caldera README](https://github.com/apache/caldera), [Caldera Getting Started](https://caldera.readthedocs.io/en/latest/Getting-started.html)
- Security posture: "strongly recommend" a secure network, do not expose to the internet; the web UI has only basic auth and has not been hardened — [apache/caldera README](https://github.com/apache/caldera)
- Operation **report** JSON: top-level `name`, `host_group`, `start`, `finish`, `steps`, `planner`, `adversary`, `jitter`, `objectives`, `facts`, `skipped_abilities`. `steps` maps agent paw -> list of steps with `link_id`, `ability_id`, `command` (base64), `delegated`, `run`, `status`, `platform`, `executor`, `pid`, `description`, `name`, `attack{tactic, technique_name, technique_id}`, optional `output{stdout, stderr, exit_code}` (plus `agent_reported_time` in samples). `facts` carry `technique_id`, `collected_by`, `links`, `relationships`. `skipped_abilities` lists `reason`, `ability_id`, `ability_name` per agent — [Caldera Operation Results](https://caldera.readthedocs.io/en/latest/Operation-Results.html)
- Operation **event logs**: a flat list, one record per link execution, with `command` (base64), `delegated_timestamp`, `collected_timestamp`, `finished_timestamp`, `agent_reported_time` (when the agent actually ran the command; absent if the agent cannot report it), `status`, `platform`, `executor`, `pid`, `agent_metadata{paw, group, architecture, username, location, pid, ppid, privilege, host, contact, created}`, `ability_metadata{ability_id, ability_name, ability_description}`, `operation_metadata{operation_name, operation_start, operation_adversary}`, `attack_metadata{tactic, technique_id, technique_name}`, optional `output`. Facts and skipped abilities are omitted — [Caldera Operation Results](https://caldera.readthedocs.io/en/latest/Operation-Results.html)
- Event logs are written automatically when an operation finishes to `$reports_dir/event_logs/operation_$id.json`; they contain command output and are unencrypted on disk. Reports and event logs can also be downloaded from the operations UI — [Caldera Operation Results](https://caldera.readthedocs.io/en/latest/Operation-Results.html), [Caldera Getting Started](https://caldera.readthedocs.io/en/latest/Getting-started.html)

Atomic Red Team / Invoke-AtomicRedTeam
- Execution logging: default CSV `Invoke-AtomicTest-ExecutionLog.csv` in the temp dir (`-ExecutionLogPath` to change, `-NoExecutionLog` to disable), recording Execution Time (UTC and local), Technique, Test Number, Test Name, Hostname, IP Address, Username, GUID, ProcessId, ExitCode. Alternative loggers: `Attire-ExecutionLogger` (JSON with full command input/output, importable to VECTR), `Syslog-ExecutionLogger` (JSON to a syslog server with tags), `WinEvent-ExecutionLogger`. Only actual executions are logged (not `-ShowDetails`, `-CheckPrereqs`, `-Cleanup`) — [Invoke-AtomicRedTeam wiki: Execution Logging](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Execution-Logging)
- A 2026 paper notes each atomic test "provides a pre-defined labeling scheme" removing manual annotation, but the executing command may embed the ATT&CK ID itself, so identifiers had to be sanitised before inference — [arXiv 2609.12841](https://arxiv.org/pdf/2609.12841)

How existing projects build labelled datasets
- Splunk `attack_data` (Apache-2.0): `datasets/attack_techniques/<T-ID>/<tool>/` with log files plus a YAML (author, id, date, description, environment, `mitre_technique`, `datasets[]` with path/sourcetype/source); mostly generated automatically with Attack Range (and an `attack_data_service`), some by manual attack + Attack Range dump; stored in Git LFS (> 9 GB); replay via `bin/replay.py` or TOTAL-REPLAY — [splunk/attack_data](https://github.com/splunk/attack_data)
- OTRF Security-Datasets (formerly Mordor): goals include mapping datasets to Sigma, Atomic Red Team, Threat Hunter Playbook and ATT&CK; docs at securitydatasets.com; licence shown inconsistently (MIT in sidebar vs GPL-3.0 in README) — [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets)
- DARPA OpTC: about 1 TB compressed JSON from 500 Windows 10 hosts (of about 1,000) over a two-week evaluation in an isolated range; benign-only period first, then red team activity with benign activity continuing; eCAR endpoint events + Zeek, with `ecar-bro` linking the two; ground truth is a red-team-authored PDF (`OpTCRedTeamGroundTruth.pdf`), i.e. narrative, not per-event labels; released as-is and "practically guaranteed to be imperfect", with an errata file — [FiveDirections/OpTC-data](https://github.com/FiveDirections/OpTC-data)
- PWNJUTSU: 22 red teamers each attacking a dedicated instrumented instance; about 16 M logs and 172 GB of network traces; public at pwnjutsu.irisa.fr; a 2025 survey calls it "unfortunately, unlabeled" while follow-up work added ATT&CK tactics manually — [PWNJUTSU paper](https://www.academia.edu/95670184/PWNJUTSU_A_dataset_and_a_semantics_driven_approach_to_retrace_attack_campaigns), [Network Intrusion Datasets survey, arXiv 2502.06688](https://arxiv.org/html/2502.06688v1), [process-mining follow-up](https://www.researchgate.net/publication/383128399_A_process_mining-based_method_for_attacker_profiling_using_the_MITRE_ATTCK_taxonomy)
- ATLAS / ATLASv2 label events only malicious vs benign, without ATT&CK technique granularity; UWF-ZeekData22 is 99.97% reconnaissance (extreme class imbalance) — [arXiv 2606.18190](https://arxiv.org/html/2606.18190)
- LMDG (lateral-movement dataset generation) uses Caldera as the emulation platform and reports that some emulated attacks failed, which must be reflected in labels — [arXiv 2508.02942](https://arxiv.org/pdf/2508.02942)

Documented pitfalls
- Designer/annotation bias: the team that designed the attacks also assigned the ground truth — [arXiv 2606.18190](https://arxiv.org/html/2606.18190)
- Label leakage through artefacts (technique IDs embedded in commands/paths) — [arXiv 2609.12841](https://arxiv.org/pdf/2609.12841)
- ATT&CK STIX bundle can diverge from the website (campaign-group relationships), so labels keyed to it may be stale/incomplete — [arXiv 2512.12078](https://arxiv.org/html/2512.12078)
- Fictional IPs/domains and incomplete host coverage in isolated ranges (OpTC) — [FiveDirections/OpTC-data](https://github.com/FiveDirections/OpTC-data)

### Inferences
- Label-record design (publish to `labels.>` on the bus and to a `ground_truth` table): `label_id`, `source` (caldera|atomic|scenario-runner), `run_id`/operation id, `link_id`, `technique_id`, `tactic`, `technique_name`, `attack_version` (pin, e.g. v20), `t_start` = `agent_reported_time` if present else `collected_timestamp`, `t_end` = `finished_timestamp`, `host`, `paw`, `pid`, `src_ip` of the emulation client, `honeypot_session_id` (joined later), `status` (success/failed/skipped), `command_sha256` (not the command itself in the feature store), scenario seed. Join labels to telemetry by (host or src_ip, pid where real, time window with small skew tolerance). Requires NTP/chrony-synchronised clocks in the range and UTC everywhere.
- Caldera timestamps: `delegated` is when the server queued the link, not when it ran; use `agent_reported_time`/`collected`..`finished` as the labelled interval, and treat status != success and `skipped_abilities` as "attempted/failed" or drop them — never label a window as technique X if the step did not execute.
- **[UNVERIFIED-BACKGROUND]** REST API v2 (Swagger UI at `/api/docs` on the server): `GET/POST /api/v2/operations`, `POST /api/v2/operations/{id}/report`, `POST /api/v2/operations/{id}/event-logs` (body `{"enable_agent_output": true|false}`), `GET /api/v2/operations/{id}/links` and `/links/{link_id}/result`, `/api/v2/abilities`, `/adversaries`, `/agents`, `/facts`; authentication with a `KEY` header (API key from `conf/local.yml`). These paths were not confirmed this session — verify against the running server's `/api/docs`. Plugins: Sandcat = default Go agent (HTTP/other contacts); Access = initial-access/remote-exec helpers; Emu = CTID adversary-emulation-library plans; Atomic = imports Atomic Red Team tests as abilities tagged with technique IDs; an SSH-contact/"agentless" path was not verified.
- **[UNVERIFIED-BACKGROUND]** Atomic Red Team indexes atomics as `atomics/T<id>/T<id>.yaml` with per-test GUIDs and markdown/CSV indexes by tactic and platform (MIT licence); `atomic-operator` (Python, cross-platform) is the non-PowerShell runner — its maintenance status was not checked.
- Lighter-weight labelled SSH/HTTP sessions (recommended MVP, weeks 4-8): a `scenario-runner` container on the isolated lab network that plays YAML scenarios against the honeypot (via an SSH client library / HTTP client), each step annotated by the author with technique ID(s); it emits a label record before and after each step. Sources of scenarios: (a) hand-written playbooks per ATT&CK technique relevant to SSH/Linux honeypots (discovery, credential access, persistence, ingress tool transfer, etc.); (b) replay of command sequences from public honeypot datasets (unlabelled, so label with rules/LLM-assist plus human review and mark `label_source=weak`); (c) parameter jitter (timing, typos, ordering, alternative binaries) to reduce memorisation. This is orchestration only; no payload development is required because the honeypot is emulated.
- Isolation design: Docker `--internal` lab network (no gateway), separate compose project and separate Docker context from anything internet-facing; no bind mounts of the host home dir; Caldera `full` image so nothing needs downloading at run time; lab profile and internet-facing profile never run on the same host; on the VPS use a different VM. Tag every lab event `env=lab` at the collector so lab traffic can never be mistaken for wild traffic (and vice versa).
- Leakage/realism controls to build in: split train/test **by scenario/run and by time**, never by event; hold out entire techniques and entire "attacker styles" for evaluation; strip or randomise emulation artefacts (agent binary names such as `sandcat`/`splunkd`, fixed paths, Atomic GUIDs, T-IDs in command lines, constant source IPs, hostnames, fixed inter-command timing, beacon cadence); mix emulated sessions with real wild-traffic sessions as the benign/unknown background; record failed steps; keep label provenance (`strong` from emulation vs `weak` from heuristics); report results separately on lab-only vs wild data, since a model that only separates "lab" from "wild" is learning the environment, not the technique.
- **[UNVERIFIED-BACKGROUND]** CIC (Canadian Institute for Cybersecurity) methodology: B-profiles (statistical models of benign user behaviour) and M-profiles (scripted attack scenarios) on a testbed, flows extracted with CICFlowMeter and labelled by time window/IP; later critiques (e.g. Engelen et al. 2021; Liu et al. 2022; Arp et al. "Dos and Don'ts of Machine Learning in Computer Security", USENIX Security 2022; Sommer & Paxson 2010; Flood et al. "Bad Design Smells in Benchmark NIDS Datasets") document labelling errors, flow-construction artefacts, shortcut features and temporal/spatial leakage. These citations should be verified before use in the report.

### Gaps
- Caldera API v2 endpoint paths and auth header not verified from primary docs (the readthedocs "Getting started" page does not list them).
- Whether Caldera has had any release after v5.3.0 under Apache incubation (2026) is unconfirmed; the release page showed no years.
- No peer-reviewed "Caldera -> labelled dataset" paper was fetched in full; only abstract-level statements from search results (LMDG, arXiv 2606.18190, 2609.12841). Their quantitative results were not extracted.
- Splunk Attack Range current version/requirements not checked (it is cloud/Vagrant based and heavy; not a laptop tool).
- Public SSH honeypot datasets suitable for replay (names, licences) were not researched here — likely covered by another researcher.

---

## 9. Threat-intel output: STIX/TAXII, MISP/OpenCTI, Sigma, ATT&CK, Engage, D3FEND

### Takeaway
MVP = generate STIX 2.1 bundles with the `stix2` Python library and write them to disk/object storage (optionally serve via medallion in the lab only); validate generated Sigma rules with pySigma/sigma-cli in CI; pin ATT&CK to a version (v20 current). MISP and OpenCTI are too heavy for a 16 GB laptop and should be integration targets, not components.

### Cited Findings
- ATT&CK v20 released 13 Oct 2026 (current; v20.1 point release listed): adds first Enterprise techniques for direct/indirect prompt injection, AI-enabled exfiltration and AI result poisoning. v19 (28 Apr 2026) split Defense Evasion into Stealth (keeps TA0005) and Defense Impairment (TA0112). v19.2 (Aug 2026) was the first "agile" interim release — [ATT&CK updates](https://attack.mitre.org/resources/updates/), [SecurityWeek on v20](https://www.securityweek.com/mitre-attck-v20-catalogs-ai-abuse-mfa-bypass-water-utility-attacks/amp/), [D3 Security on v19](https://d3security.com/blog/mitre-attack-v19/)
- medallion (`oasis-open/cti-taxii-server`): v3.0.0, BSD-3-Clause, TAXII 2.1, memory and MongoDB backends; README states it is a prototype/reference implementation and "is not intended for production use" — [oasis-open/cti-taxii-server](https://github.com/oasis-open/cti-taxii-server)
- OpenCTI: Core documented at 2 cores / >= 8 GB (plus Elasticsearch/OpenSearch, Redis, RabbitMQ, MinIO/S3, workers and connectors); v7 line exists (7.260224.0) with breaking changes and a required `APP_ENCRYPTION_KEY` — [OpenCTI deployment docs](https://docs.opencti.io/latest/deployment/overview/), [OpenCTI 7.260224.0 release](https://newreleases.io/project/github/OpenCTI-Platform/opencti/release/7.260224.0)
- sigma-cli 2.0.x is current (2.0.1 after 2.0.0, which moved to pySigma 1.0 and added cache management for MITRE content; later dependency bump to pySigma 1.4.0); sigma-cli is LGPL-2.1+ (per MacPorts metadata) — [sigma-cli releases](https://github.com/SigmaHQ/sigma-cli/releases), [MacPorts py-sigma-cli](https://ports.macports.org/port/py-sigma-cli/stats/)

### Inferences
- The v19 tactic split and v20 AI techniques matter directly: any label taxonomy trained before April 2026 that uses "Defense Evasion" must be remapped; store `attack_version` with every label and prediction, and build the label vocabulary from a pinned STIX bundle.
- **[UNVERIFIED-BACKGROUND]** `stix2` (oasis-open/cti-python-stix2, BSD-3, 3.0.x) supports STIX 2.1 objects, custom extensions and a `TAXIICollectionSource/Sink` via `taxii2-client`; `mitreattack-python` (Apache-2.0) wraps ATT&CK STIX data (`MitreAttackData`); ATT&CK data is published as STIX 2.1 in `mitre-attack/attack-stix-data` (and legacy 2.0 in `mitre/cti`); OpenTAXII (EclecticIQ, BSD-3) is the more production-capable server with TAXII 2.1 support added in later releases. MISP in Docker (`misp-docker`) typically wants about 4 GB+ (MariaDB + Redis + PHP + workers). MITRE Engage (v1.0, 2022) maps engagement activities to ATT&CK techniques and is the right vocabulary for describing deception actions; D3FEND (1.x, with ATT&CK mappings via digital artifacts, JSON-LD/OWL downloads and an API) is for defensive countermeasure tagging. None of these versions/licences were checked this session.
- Output objects for a honeypot: `indicator` (IP/hash/URL patterns with `valid_until`), `observed-data`/SCOs, `malware` (hash only), `attack-pattern` references by ATT&CK external id, `sighting`, `infrastructure`, `note`/`opinion` for model confidence; mark with TLP marking definitions; include `confidence` from the classifier and `x_mirage_*` custom properties via a STIX extension definition.
- Sigma validation gate in CI: `sigma check` (syntax + validators) and `sigma convert -t <backend>` round-trip for LLM-generated rules, plus replay against stored lab telemetry to compute rule precision/recall before export. Because the store is ClickHouse, check availability of a pySigma ClickHouse backend (community) or evaluate rules in Python directly against normalised events.

### Gaps
- Latest versions/licences of stix2, taxii2-client, OpenTAXII, mitreattack-python, pySigma (PyPI page showed 1.3.3 while sigma-cli notes mention 1.4.0), MISP and D3FEND/Engage were not confirmed.
- MISP memory requirements: no source retrieved.

---

## 10. MLOps at small scale

### Takeaway
MLflow 3.x with a SQLite backend and local artefact directory (run on demand) plus DVC or plain content-addressed Parquet for dataset versioning is enough; Feast is overkill; evaluation gates belong in GitHub Actions on small frozen eval sets.

### Cited Findings
- MLflow 3.17.0 released 6 Oct 2026 (changelog and mailing-list announcement); 3.13 added RBAC with an admin UI and automatic trace archival; 3.10 was Feb 2026; 3.14.0 was 17 Jun 2026 — [MLflow CHANGELOG](https://raw.githubusercontent.com/mlflow/mlflow/master/CHANGELOG.md), [mlflow-users 3.17.0](https://groups.google.com/g/mlflow-users/c/LDktHclrHU4)
- DVC: the open-source project was acquired by lakeFS (Nov 2025), which says it continues as an independent open-source tool for data scientists with smaller datasets; version reports conflict (3.67.1 on 31 Mar 2026 vs "4.1.0, March 2026") — [lakeFS acquires DVC](https://lakefs.io/blog/lakefs-acquires-dvc/)
- MinIO CE is archived (see section 7), which affects the common "MLflow + MinIO" tutorial pattern — [InfoQ](https://www.infoq.com/news/2025/12/minio-s3-api-alternatives)

### Inferences
- **[UNVERIFIED-BACKGROUND]** MLflow is Apache-2.0; `mlflow server --backend-store-uri sqlite:///mlflow.db --artifacts-destination ./mlartifacts` idles at a few hundred MB; MLflow 3 adds GenAI tracing/evaluation (useful for logging the honeypot LLM's prompts/outputs and judge-based evals) and a LoggedModel concept. Lighter alternatives: Aim, plain JSON/CSV metrics committed with the code, or Weights & Biases (SaaS; do not send captured attacker data or samples there).
- Feast: needed only when the same features must be served online at low latency and offline with point-in-time correctness across teams. MIRAGE's features are computed in the stream consumer and stored in ClickHouse/Parquet; a versioned `features.py` module shared by training and inference removes train/serve skew without a feature store.
- Dataset versioning: DVC with a local/SSH remote (or S3-compatible Garage later) or simply immutable dated Parquet snapshots with a manifest (sha256, row counts, label distribution, ATT&CK version, scenario ids). Tie each MLflow run to a dataset manifest hash and git commit.
- CI evaluation gates (GitHub Actions): on PR, run unit tests for the normaliser/schema (pydantic + golden files), then train-free evaluation of the current model on a small frozen eval set stored in the repo/LFS (< 50 MB): fail if macro-F1 / per-technique recall drops more than a tolerance vs the registered baseline, if schema validation fails, or if generated Sigma rules fail `sigma check`. Nightly (self-hosted runner on the VPS, or manual on the Mac): full retrain + evaluation on scenario-held-out and time-held-out splits, log to MLflow, promote via model alias only when gates pass. GitHub-hosted runners must never receive live malware samples or raw attacker payload corpora; use hashes/sanitised features only.

### Gaps
- Feast current version not established (one unverified mirror suggested 0.59.0, Jan 2026); DVC current version conflicting; MLflow memory footprint not sourced.

---

## 11. Dashboard

### Takeaway
Grafana on ClickHouse for operational and research dashboards in the first 12 weeks; a custom Next.js UI only for the product-specific views (session replay, deception-decision timeline, label review) once the data model is stable. OpenSearch Dashboards only if OpenSearch is adopted.

### Cited Findings
- Grafana 13 released April 2026 with dashboard suggestions, Git Sync GA (dashboards as code), 170+ data sources — [Grafana press release](https://grafana.com/press/2026/04/21/grafana-labs-launches-grafana-13-at-grafanacon-2026-makes-open-observability-easier-to-run-at-scale/)
- T-Pot ships Kibana dashboards, an animated Attack Map, Elasticvue, CyberChef and Spiderfoot behind NGINX — [tpotce README](https://github.com/telekom-security/tpotce)

### Inferences
- Borrowable ideas: T-Pot attack map (geo-IP live arcs; **[UNVERIFIED-BACKGROUND]** separate repo `t3chn0m4g3/t-pot-attack-map`, uses Elasticsearch + Redis), T-Pot/Cowrie Kibana panels (top usernames/passwords, top commands, source ASN/country, HASSH distribution, downloads by hash, session duration histogram), Grafana Geomap panel as the lightweight attack-map replacement, Grafana community dashboards for Cowrie (quality varies).
- Use Grafana provisioning (dashboards as JSON in git, or Git Sync in Grafana 13) so the 3-4 person team reviews dashboard changes like code.
- MIRAGE-specific panels: events/s per stage and consumer lag (pipeline health), sessions by predicted technique vs ground truth (lab), model confidence distribution, LLM latency/cost per session, deception actions taken, egress-block counter (containment health — any non-zero allowed egress is an alert).

### Gaps
- Grafana licence (AGPLv3) and plugin availability for ClickHouse/OpenSearch on Grafana 13 not re-verified; specific existing Cowrie Grafana dashboard IDs not collected.

---

## 12. Legal/ethical basics of research honeypots

### Takeaway
Entrapment is largely a myth for privately run research honeypots (it is a defence concerning law-enforcement inducement), but privacy/data-protection (IP addresses and captured content are personal data under EU law) and liability for onward attacks are real; the mitigations are data control (default-deny egress), data minimisation/retention policy, documented purpose and legal basis, and provider consent. ENISA itself tells operators to get local legal counsel.

### Cited Findings
- ENISA's 2012 report "Proactive Detection of Security Incidents II - Honeypots" treats legal questions as out of scope and encourages CERTs to consult legal counsel about implications in their own country; it has a short "Legal counsel" section (4.5) — [ENISA report page](https://www.enisa.europa.eu/publications/proactive-detection-of-security-incidents-II-honeypots), [SecurityWeek coverage](https://www.securityweek.com/enisa-issues-comprehensive-report-deploying-honeypots/)
- Walden & Flanagan, "Honeypots: a sticky legal landscape?": examines entrapment and privacy; entrapment is concerned with the involvement of public law-enforcement authorities and their agents in inducing a crime; honeypots capturing communications raise lawful-interception/privacy questions — [vLex abstract](https://law-journals-books.vlex.com/vid/sticky-legal-landscape-53160867)
- Sokol, Misek, Husak, "Honeypots and honeynets: issues of privacy" (EURASIP J. Information Security, 2017): privacy determines how a honeypot may be deployed, what data may be collected and how it may be used; under EU law an IP address is personal data; most earlier literature is US-centric — [MIT CyberIR record](https://cyberir.mit.edu/site/honeypots-and-honeynets-issues-privacy), [Springer chapter (related)](https://link.springer.com/chapter/10.1007/978-3-319-32525-5_10)
- Sokol & Andrejko (2015) "Deploying Honeypots and Honeynets: Issues of Liability" addresses data control, data capture, data collection and liability — [CPS-VO record](https://archive.cps-vo.org/node/33443)
- Classic US-side treatment: Scottberg, Yurcik, Doss, "Internet honeypots: Protection or entrapment?" (2002) — cited in [Sokol et al.](https://is.muni.cz/publication/1374313/Misek_Husak_clanek.pdf)
- T-Pot's disclaimer: operator runs it at own responsibility; data is shared to a community backend by default (a data-sharing decision the operator must make consciously) — [tpotce README](https://github.com/telekom-security/tpotce)
- Provider terms can require prior written consent for security/malware research (DigitalOcean) — [DigitalOcean AUP](https://www.digitalocean.com/legal/acceptable-use-policy)

### Inferences
- Practical checklist for MIRAGE: (1) written purpose statement and, if in the EU/UK, a legitimate-interest assessment (GDPR Art. 6(1)(f); Recital 49 on network security is the usual anchor — **[UNVERIFIED-BACKGROUND]**) and a short DPIA-style note; (2) retention limits and pseudonymisation of IPs in ML datasets and anything published; never publish raw credentials (they may be real reused passwords); (3) data control first: no onward attacks, enforced technically (section 7) — this is the main liability mitigation and the Honeynet Project's long-standing "data control over data capture" principle **[UNVERIFIED-BACKGROUND]**; (4) no "hack-back" or active interaction beyond the deception surface; (5) university/company ethics or security-office sign-off if applicable; (6) provider consent in writing; (7) no banner inviting access (and no real user data in lures); (8) incident plan if the honeypot is compromised (kill switch: security-group lockdown + snapshot).
- The LLM dimension adds two new issues not covered in the classic literature: attacker text is sent to a model (keep it local or ensure the API provider's terms allow it and no personal data leaves the jurisdiction), and LLM-generated content must not provide real operational help or real credentials/data.

### Gaps
- The ENISA report's legal section text and the Honeynet Project's own legal guidance were not fetched directly; Sokol/Walden conclusions are from abstracts/snippets only.
- No India-specific (IT Act 2000 / DPDP Act 2023) or other national analysis was researched; the team's jurisdiction is unknown.
- No source found this session that addresses operator liability case law for onward attacks.

---

## Version/licence quick table (confidence flagged)

| Tool | Version seen (Nov 2026) | Licence | Confidence / source |
|---|---|---|---|
| Apache Kafka | 4.2.2 (29 Sep 2026); 4.3.0 exists | Apache-2.0 | version: official blog; check 4.3.x |
| Redpanda | 26.2.5 (16 Oct 2026); 26.1.x supported to Mar 2027 | BSL 1.1 -> Apache-2.0 after 4 yrs | version: official docs; licence: secondary |
| NATS server | 2.14.4 (2.12.14 on older line) | Apache-2.0 | tracker pages; verify |
| Redis / Valkey | Redis 8.x; Valkey 9.x | RSALv2/SSPLv1/AGPLv3; BSD-3 | secondary |
| Vector | 0.61.0 (29 Oct 2026) | MPL-2.0 (unverified) | version: official |
| Quix Streams | not seen | Apache-2.0 | official README |
| Bytewax | not seen; community-maintained since May 2025 | Apache-2.0 | official README |
| faust-streaming | 0.12.x? | BSD-3 | repo; Snyk says inactive |
| ClickHouse | 26.9/26.10 stable, 26.8 LTS | Apache-2.0 (unverified) | trackers only |
| OpenSearch | 3.7-3.8 | Apache-2.0 (unverified) | docs/Docker Hub |
| T-Pot | 24.04.x referenced | GPL-3.0 | official README |
| OCSF | 1.9.0 (3 Aug 2026) | Apache-2.0 (unverified) | official releases |
| ECS | 9.4-9.5 | Apache-2.0 (unverified) | official notes (9.5 unconfirmed) |
| Zeek | 8.0.9/8.0.10 LTS; 8.1/8.2 feature | BSD (unverified) | official page |
| Suricata | 8.0.5+ | GPL-2.0 (unverified) | secondary |
| JA4 / JA4+ | plugin v1.0.0 | BSD-3 (JA4) / FoxIO 1.1 (rest) | official FAQ |
| Caldera | 5.3.0 | Apache-2.0 | official repo |
| medallion | 3.0.0 | BSD-3 | official README |
| sigma-cli / pySigma | 2.0.1 / 1.3.3-1.4.0 | LGPL-2.1+ | releases page / MacPorts |
| ATT&CK | v20 (13 Oct 2026), v20.1 | ATT&CK terms of use | official |
| MLflow | 3.17.0 (6 Oct 2026) | Apache-2.0 (unverified) | official changelog |
| DVC | 3.67.x or 4.1.0 (conflict) | Apache-2.0 | secondary |
| Grafana | 13.x (Apr 2026) | AGPLv3 (unverified) | press release |
| Garage | 2.3.0 (Apr 2026) | AGPLv3 | repo + secondary |
| SeaweedFS | 4.39 (Jul 2026) | Apache-2.0 core | aggregator |
| MinIO CE | archived 2026 | AGPLv3 | multiple secondary |
| INetSim | 1.3.2 (2020) | GPL (unverified) | Kali page |
| Arkime | 6.x | Apache-2.0 (unverified) | official release page |
| OpenCTI | 7.x | Apache-2.0 CE (unverified) | docs / tracker |
