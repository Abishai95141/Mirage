# Phase 1 specification · Decoys and capture

Status: draft for review · 12 November 2026
Parent: [build plan, phase 1](01-build-plan.md#phase-1--decoys-and-capture-weeks-35) · Companion docs: [architecture](02-architecture.md) · [spike results](../spikes/README.md)

Phase 1 puts three protocols (SSH, HTTP and a database pair, Redis and MySQL) behind the policy gate and captures every session in full. This document defines each work package exactly enough to test: what it must do, what it must not do, and the test that proves it. Gate 1 (section 6) is the only exit criterion.

## 1. Decisions this spec makes

These close the gaps found when reviewing the build plan. Each is a default; say so if you disagree.

| # | Gap | Decision |
| --- | --- | --- |
| P1 | Every decoy must reach the policy service, but the containment test forbids decoys reaching anything | A third internal network, `mirage_gate`, holds only the decoys and the policy service. The containment test allows exactly one destination on it, the policy port, and still forbids everything else. The edge is not on it. |
| P2 | Anything the decoy can reach, an attacker inside the emulation might try to reach | The policy service requires a per-deployment bearer token that `make env` generates. Cowrie's emulated `wget`, `curl` and `tftp` already refuse private and link-local addresses (`core/network.py`), so the gate address is not reachable from the shell; a containment test proves it. |
| P3 | The architecture adds a `plant_token` action in phase 1; the build plan's action list does not | Phase 1 plants honeytokens statically, when the profile is generated. `plant_token` moves to phase 2 with the bandit. Token use is detected in the pipeline, so decoys never call a token service at runtime. |
| P4 | The HTTP decoy has a response cache, but static templates have nothing to cache | No cache in phase 1. It arrives in phase 3 with generated responses, keyed as the architecture describes. |
| P5 | The default-tell checks Gate 1 depends on are scheduled for phase 3 (3.4) | Phase 1 writes them as part of 1.3, against reference containers. Phase 3 extends the same suite. |
| P6 | "Captured in full" is undefined | Defined in section 5 and asserted by the Gate 1 tests. |
| P7 | The database query subset is unspecified | Defined in 1.5. |
| P8 | One profile, several services | A profile describes one host. SSH, HTTP, Redis and MySQL are four ports on one address behind one edge, and every fact they reveal (hostname, OS, versions, users, data) comes from the same generated profile. |
| P9 | Hand-typed version strings drift and contradict each other (Cowrie's defaults pair an OpenSSH 9.2 banner with a 7.9 `ssh -V`) | Every distribution-level fact comes from a pinned Debian 12 reference image, extracted by a script. Nothing is typed by hand. |
| P10 | Attackers writing to shared decoy state see each other and can poison it | Mutable decoy state (Redis keyspace, MySQL tables) is kept per source address and reset after 24 hours. A returning actor sees its own changes; no one sees anyone else's. |

## 2. Topology

```
 client ──► edge (HAProxy, TCP mode, PROXY v2 to every decoy)
              │  mirage_decoy (internal)
              ├──► cowrie        :2222  ─┐
              ├──► http-decoy    :8080  ─┤ mirage_gate (internal)
              ├──► redis-decoy   :6379  ─┼──► policy :8000 (bearer token)
              └──► mysql-decoy   :3306  ─┘
     each decoy and the policy service write JSON lines to their own volume
              ▼
   Vector (mirage_core, volumes mounted read-only) ──► NATS ──► normaliser ──► sessioniser ──► ClickHouse
```

- **Networks.** `mirage_decoy` and `mirage_gate` are both `internal: true`. Only the edge is on `mirage_edge`. The policy service is on `mirage_gate` alone, so it has no route to the pipeline or the internet either.
- **Logging.** Decoys and the policy service never send telemetry over the network. They write JSON lines to a volume, and Vector tails it read-only, as it does for Cowrie in phase 0.
- **Ports.** Host ports come from `.env` and bind to 127.0.0.1. Defaults avoid ports already used on the development laptop (3000, 8080): `SSH_PORT=2222`, `HTTP_PORT=8081`, `REDIS_PORT=6380`, `MYSQL_PORT=3307`.
- **PROXY protocol.** All four decoys read a PROXY v2 header and refuse connections without one. Only the edge can reach them, so the header cannot be forged. One shared parser (`decoys/common/proxyproto.py`) serves the three decoys we write. Uvicorn reads `X-Forwarded-For` but not, as far as we know, the PROXY protocol; confirm this, and if so the HTTP decoy needs its own listener in front of the ASGI app. Running HAProxy in HTTP mode instead would be simpler, but HAProxy would then answer malformed requests itself, which is a tell.
- **Memory.** The new services are capped at 128 MB each: policy, http-decoy, redis-decoy and mysql-decoy. The measured stack stays under 1.5 GB.

## 3. Gate contract v1

This extends the contract built in S1 ([architecture §3](02-architecture.md#3-the-cowrie-fork)). Fields that already exist keep their meaning, so the S1 patch keeps working.

```
POST /v1/decide            Authorization: Bearer <POLICY_TOKEN>
{
  "request_id", "session_id", "deployment_id", "seq",     // seq: input number within the session, from 1
  "protocol": "ssh" | "http" | "redis" | "mysql",
  "src": {"ip", "port"}, "known": true|false,
  // ssh:   "argv", "cwd", "user", "interactive"
  // http:  "method", "path", "query", "headers" (host, user-agent, content-type, content-length),
  //        "body_len", "body_sha256", "body_head" (first 1 KiB)
  // redis: "argv" (each element cut to 1 KiB), "db"
  // mysql: "command" (COM_QUERY, COM_INIT_DB, ...), "sql" (cut to 4 KiB), "db", "user"
}
→ { "action", "output", "exit_code", "delay_ms", "decision_id", "propensity", "rule_id", "rules_version" }
```

**What each action means**

| Action | ssh | http | redis | mysql |
| --- | --- | --- | --- | --- |
| `allow` | Run the emulated command | Serve the profile's route or 404 | Emulate the command | Emulate the statement |
| `fake_success` | Print `output`, exit 0 | 200 with `output` as body | Bulk reply `output` (or `+OK` when empty) | OK packet |
| `fake_error` | `output` to stderr, `exit_code` | Status `exit_code` (400–599), body `output` | `-ERR` with `output` | ERR packet, code `exit_code`, message `output` |
| `delay` | Wait `delay_ms`, then allow | same | same | same |
| `terminate` | Close the channel | Close the connection | Close | Close |

**Failure semantics**, unchanged from S1 and the same for every decoy: a missing, late, non-200, unauthorised or malformed reply means `allow`, and the decoy records a fallback with its reason. Each decoy's timeout is configurable, with a 50 ms target. A decoy never waits on the policy service longer than that.

## 4. Work packages

### 1.1 Cowrie fork

The fork is a patch series applied to pinned Cowrie v3.1.6 (`ea9513e`) at image build time (`decoys/ssh/patches/`). It is not a long-lived branch. CI applies the series to a fresh clone and runs Cowrie's own suite, as the phase 0 job already does.

| Change | Acceptance |
| --- | --- |
| The S1 gate, moved from the spike into `decoys/ssh` | The S1 tests pass. Requests carry `deployment_id`, `seq`, `src` and the bearer token. |
| Unknown commands reach the gate before "command not found" | Already in S1. A rule can answer an unknown command with `fake_success`. |
| Filesystem mutators (`mkfile`, `mkdir`, `write`, `remove`, `rename`, `chmod` in `shell/fs.py`) emit a new `cowrie.fs.change` event: `op`, `path`, `new_path`, `mode`, `size`, plus `sha256` for writes | One event per mutation, including redirections (`echo x > f`) and SFTP. The event is registered in `core/eventids.py` and documented in `docs/OUTPUT.rst`. |
| Remove the vendored JA4+ code (`vendor/ja4/`, `core/fingerprint.py` and its two call sites) | Default from the build plan's open decisions. Cowrie's suite still passes; no event field goes missing other than the JA4 ones. |
| Drop key-exchange entries OpenSSH 9.2p1 never offered (`mlkem768x25519-sha256`, `ext-info-s`) in `ssh/factory.py`, where Cowrie already edits `supportedKeyExchanges` | Every algorithm Cowrie offers is in OpenSSH 9.2p1's list. HASSH-server still differs, because of what Twisted lacks: a known gap (section 8). |

### 1.2 Policy service v0

| Requirement | Acceptance |
| --- | --- |
| FastAPI under uvicorn, implementing contract v1 | Contract tests for every protocol and action, plus the bad-token, malformed-request and oversized-field cases |
| Listens on IPv4 and IPv6; keep-alive timeout of at least 5 s (above the gate's 2 s idle); TCP_NODELAY | A test connects over each address family. Over 1,000 sequential decisions on one connection, none hits a stale-connection retry. |
| Server-side p95 under 10 ms on the laptop | Measured in the Gate 1 latency test |
| Rules live in a YAML file (`policy/rules/default.yaml`), first match wins. A rule matches on protocol, `known`, `argv[0]`, a regex over the input, HTTP method and path, or SQL verb. | Every decision carries the `rule_id`, and the `rules_version` (a hash of the rules file) |
| An invalid rules file stops the service from starting | Config errors fail closed at the service, and the decoys fail open to `allow` |
| Load-time action mask: `output` capped at 64 KiB, `delay_ms` at 10 s, only the five actions allowed | A rule outside the mask is rejected at load, not at decision time |
| Deterministic rules only: `propensity` 1.0, same input gives the same decision | Phase 2's bandit replaces this. The log format already carries propensities. |
| Every decision is logged as one JSON line: the full request, `rule_id`, `rules_version`, action, `decision_id` and latency | Vector publishes it to `raw.policy.decision`. The normaliser maps it to `policy_decision` events with source `policy`. |

The default rule set allows everything, plus one rule per action that is used only by tests. Making the rules smarter is phase 2 work. Phase 1 proves the plumbing and the record.

Two events describe each decision, joined on `request_id`. The decoy's event records what was actually applied, fallbacks included. The policy service's record says why.

### 1.3 SSH profile hardening and the profile generator

**Reference image.** A Dockerfile builds `debian:bookworm` (pinned by digest) with `openssh-server`, `nginx`, `redis-server` and `mariadb-server` from Debian's own packages. `make profile-ref` extracts the facts the decoys repeat into `decoys/profiles/reference/debian-12.json`:

- the OpenSSH banner and `ssh -V`
- the algorithm lists
- the kernel versions and their build strings
- `/etc/os-release` and `/etc/issue`
- nginx's `Server` header, its error pages and its header order
- Redis `INFO` and `COMMAND COUNT`
- MariaDB's handshake, capability flags, server variables and error texts

The same image is what the default-tell checks compare against.

**Generator.** The command is `mirage-profile render <profile.yaml> --seed <n> --out <dir>`. A profile names a distribution (only `debian-12` in phase 1), a role (`web-db` by default), its users and services, and its planted data. It renders:

| For | Output |
| --- | --- |
| Cowrie | Config overrides: hostname, `kernel_version` and a matching `kernel_build_string`, `ssh_version` agreeing with the banner, and `[ssh] ciphers`, `macs` and `compression` trimmed to the subset OpenSSH 9.2p1 also offers. A userdb that accepts a short seeded list of weak root passwords and rejects everything else; it has no `*` wildcard entries (Cowrie's example userdb ends with `*:x:*`, any user and any password). A honeyfs tree and a filesystem pickle built with Cowrie's `createfs`: no `phil`, users from the profile, matching `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/hostname`, `/etc/hosts`, `/etc/machine-id`, `/proc/version`. Host keys generated for each deployment. |
| HTTP | The route table, templates, `Server` header and error pages |
| Redis and MySQL | Version strings, `INFO` fields, server variables, schema and Faker rows (seeded) |
| Tokens | Every honeytoken planted in the outputs above, registered with 1.6 |

**Acceptance**
- The same profile and seed give byte-identical output.
- Two seeds differ in hostname, users, machine-id, host keys and token values.
- Nothing the generator emits contradicts the reference file.

**Default-tell checks** (`eval/probes/default_tells.py`, run by `make probe` and in CI). Each check reports pass, fail, or known gap with a pointer to section 8.

| Protocol | Checks |
| --- | --- |
| SSH | Hostname is not `svr04` or any other Cowrie default. No user `phil`, no `/home/phil`. The banner version agrees with `ssh -V`. The kernel build date is consistent with the kernel version in the reference. `/etc/os-release` agrees with the banner's distribution. Five random root passwords are all rejected, as is a random user. Offered ciphers, MACs, compression and key exchanges are each a subset of OpenSSH 9.2p1's. HASSH-server equality is a known gap. |
| HTTP | No `uvicorn`, `starlette` or `FastAPI` in any header or body. `Server` equals the reference. The 404 and 413 bodies match nginx 1.22's byte for byte. The header set and order on 200 and 404 responses match the reference. |
| Redis | `INFO server` fields agree with the reference version. The unknown-command error matches Redis 7.0's format for five samples. `COMMAND COUNT` equals the reference. |
| MySQL | The handshake version string and capability flags equal the reference MariaDB 10.11. The access-denied message format matches. |

Run against stock phase 0 Cowrie, the SSH checks must fail. That proves the checks detect the tells.

### 1.4 HTTP decoy

| Requirement | Acceptance |
| --- | --- |
| FastAPI app imitating the profile's nginx 1.22 site. The default `web-db` profile plants `/`, `/robots.txt`, `/.env` (database credentials, which are honeytokens), `/.git/config`, `/wp-login.php` (GET serves the form; POST records the credentials and always fails), `/phpmyadmin/` (login page), `/server-status` (403) and `/backup.sql` (403). | Each route returns what the profile defines. Every other path gets nginx's 404. |
| Every request is gated | One decision per request, applied as the action table says |
| Bodies over 1 MiB get nginx's 413 page. Bodies over 4 KiB go to the artifact store, and the event keeps the hash and the first 4 KiB. | Tested at 4 KiB and at 1 MiB plus one byte |
| The decoy never makes an outbound request, whatever a parameter says (SSRF bait such as `?url=` is only recorded) | The decoy has no outbound HTTP code path. Containment would also block one. |
| One event per request: method, path, query, headers, body hash and size, status, response hash, decision | Mapped as `http_activity` |

### 1.5 Database decoys

Both decoys are asyncio servers we write, with deterministic framing and content from the profile. Both gate every input unit: a RESP command, or a MySQL command packet.

**Redis** imitates the Debian 12 `redis-server` (7.0), with no authentication by default. An exposed Redis without a password is what attackers look for. A profile can set `requirepass` to a honeytoken instead.

| Scope | Behaviour |
| --- | --- |
| Framing | RESP2, plus inline commands (`PING\r\n` typed over telnet) |
| Commands | `PING`, `ECHO`, `AUTH`, `HELLO 2`, `SELECT`, `QUIT`, `INFO [section]`, `CONFIG GET/SET`, `DBSIZE`, `KEYS`, `SCAN`, `TYPE`, `TTL`, `EXISTS`, `GET`, `SET`, `DEL`, `FLUSHDB`, `FLUSHALL`, `SAVE`, `BGSAVE`, `COMMAND COUNT`, `CLIENT SETNAME/GETNAME/LIST` |
| The classic attacks, recorded with their arguments | `CONFIG SET dir` and `dbfilename` followed by `SAVE` (writing cron jobs or SSH keys) returns OK. `SLAVEOF` and `REPLICAOF` return OK, record the target and never connect; `INFO replication` then shows the link down. `MODULE LOAD` returns the error a missing file gives. `EVAL` returns the error a patched Debian Redis gives (CVE-2022-0543 probes use `package.loadlib`). |
| Everything else | Redis 7.0's exact `-ERR unknown command` text |
| State | Keyspace seeded from the profile, kept per source address, reset after 24 hours (P10) |
| Limits | Bulk strings over 1 MiB close the connection with Redis's protocol error. Values over 4 KiB go to the artifact store. |

**MySQL** imitates the Debian 12 `mariadb-server` (10.11).

| Scope | Behaviour |
| --- | --- |
| Handshake | Protocol v10. The version string uses MariaDB's `5.5.5-` prefix. Capability flags come from the reference; TLS is not offered, matching the default Debian install. |
| Auth | `mysql_native_password`. Only the profile's credentials, including the planted honeytokens, succeed. Others get error 1045 in MariaDB's exact format, quoting the user and the client address. |
| Commands | `COM_QUIT`, `COM_PING`, `COM_INIT_DB`, `COM_QUERY`. `COM_FIELD_LIST` (the `mysql` client's tab completion) is answered from the schema. Prepared statements get a MariaDB error: a known gap. |
| Query subset | Session and metadata: `SELECT` of `@@` variables, `VERSION()`, `DATABASE()`, `USER()`, `CURRENT_USER()`, `NOW()`; `SET`; `SHOW DATABASES`, `TABLES`, `VARIABLES [LIKE]`, `GRANTS`, `CREATE TABLE`; `DESCRIBE`; `USE`. Data: single-table `SELECT` with `WHERE` comparisons, `ORDER BY`, `LIMIT` and `COUNT(*)`, plus `INSERT`, `UPDATE`, `DELETE`, `CREATE TABLE` and `DROP TABLE`. The client's connect-time queries (`SELECT @@version_comment LIMIT 1` and others) always work. |
| How | Statements are parsed with `sqlglot` (MIT) and run against an in-memory SQLite copy of the profile's tables, one copy per source address (P10). SQLite errors are mapped to MariaDB codes: 1064 for syntax, 1146 for a missing table, 1054 for an unknown column. Anything outside the subset gets 1064 in MariaDB's message format. |
| The classic attacks, recorded | `INTO OUTFILE` and `INTO DUMPFILE` give the error the reference gives under its `secure_file_priv`. `LOAD_FILE()` returns NULL. `CREATE FUNCTION ... SONAME` (UDF loading) gives error 1126. |
| Must not | Never send a `LOCAL INFILE` request to the client. A rogue MySQL server can read files from the connecting client, and the decoy never attacks its visitor. |
| Limits | Packets over the profile's `max_allowed_packet` (1 MiB, and reported as such) get MariaDB's error 1153. Statements over 4 KiB go to the artifact store. |

PostgreSQL waits until after the MVP, as the build plan says.

### 1.6 Honeytokens

This is a library plus a CLI (`mirage-tokens`), not a network service (P3).

- **Types:**
  - **Credentials:** a user and password that work on another decoy, for example the database password in `/.env` and in `/var/www/html/wp-config.php`.
  - **URLs:** paths on the HTTP decoy that are linked from nowhere public.
  - **Records:** distinctive emails and names in MySQL rows and Redis values.
  - **Cloud-key lookalikes:** recorded only. Detecting their use needs an external callback, which phase 1 does not have.
- **Minting.** The profile generator mints and plants tokens at render time and writes each one to `mirage.tokens`: `token_id`, type, value, `deployment_id`, where it was planted, and when. Values are generated for each deployment and never committed to the repository.
- **Detection.** A pipeline matcher scans every captured input (auth attempts, commands, HTTP requests, SQL, Redis arguments) for token values. Each match emits a `token.triggered` event naming the token, where it was planted and the session that used it.
- **Acceptance.** Gate 1's token-chain test (section 6).

### 1.7 Sessioniser

This is a pipeline stage that consumes `events.normalised.>` and writes to ClickHouse.

| Requirement | Detail |
| --- | --- |
| Session boundaries | SSH: Cowrie's session ID. Redis and MySQL: one TCP connection. HTTP: source address plus user agent, closed after 30 minutes idle. |
| `mirage.session_summary` (ReplacingMergeTree) | One row per session on any protocol. Columns: protocol, source, start and end, number of inputs, decisions and fallbacks, auth attempts and success, credentials used, fingerprints, tokens triggered, artifacts. |
| Fingerprints | SSH: client HASSH and client version. HTTP: user agent and a hash of header order. MySQL: connect attributes (`_client_name`, `_os`, ...). Redis: `CLIENT SETNAME` and the order of the first commands. No JA4, because 1.1 removes it. |
| `mirage.actor_links` | Each link between two sessions records its reason and evidence. Links: honeytoken use, where a token planted in one session is used in another (strongest); the same HASSH and client version plus a shared credential pair; the same source address within 24 hours (weakest). The `actor_id` is the connected component, computed deterministically. |
| No models | Phase 2's actor classifier consumes these tables. |

The existing `mirage.sessions` view stays for SSH until the summary table replaces it on the dashboard.

### 1.8 Artifact store

| Requirement | Detail |
| --- | --- |
| Sources | Cowrie downloads and SFTP uploads (Cowrie already names them by SHA-256), files written by redirection, HTTP bodies, Redis values and SQL statements over 4 KiB |
| Storage | Files are named by SHA-256 with no extension and mode 0400, on volumes that only the writing decoy mounts read-write. Every other mount is read-only and is taken only by the indexer. |
| Index | `mirage.artifacts`: hash, size, detected type (`puremagic`, MIT), first and last seen, sessions, source |
| Never executed | No container that mounts an artifact volume runs anything that reads beyond hashing and type detection. Detonation is a phase 3+ decision on the Linux host. |
| Caps | 50 MiB per file (Cowrie's `download_limit_size` is set to match) and 5 GiB per deployment. Index rows are kept when files are evicted, oldest first. |

In the lab the decoy network has no egress, so `wget` and `curl` inside Cowrie fail as on a host without internet. Phase 1 artifacts come from uploads and writes. Phase 2's scenario runner will need a lab payload host that Cowrie's private-address block allows; that is a phase 2 decision.

## 5. What "captured in full" means

For every session on every protocol, ClickHouse holds:

1. Connection open and close, with the client's real address (via PROXY v2) and the deployment.
2. Every authentication attempt with its credentials and outcome.
3. Every input unit in order, each with its `seq`: a command line, an HTTP request, a RESP command or a MySQL command packet.
4. Exactly one applied decision per input from the decoy, and one policy record joined on `request_id`. The only exception is a recorded fallback, which has no policy record and carries its reason.
5. What the decoy returned: for SSH, Cowrie's TTY log, which `playlog` must replay; for the others, status, size and hash, with the content in the event up to 4 KiB and in the artifact store beyond that.
6. Every state change: filesystem events, Redis writes, SQL writes.
7. Every artifact, by hash.
8. Every honeytoken use.

## 6. Gate 1

All of these run in CI (`tests/integration/test_gate1.py`, plus the updated containment tests). The gate passes when all pass. A probe listed as a known gap in section 8 does not block it.

| # | Test | Asserts |
| --- | --- | --- |
| 1 | Scripted SSH session (paramiko): log in with a profile password, run known and unknown commands, write a file, attempt a download, upload over SFTP | Every item in section 5. Inputs equal decisions with no fallbacks. `cowrie.fs.change` events. An artifact row for the upload. The TTY log replays. |
| 2 | Scripted HTTP session (httpx): `/`, `/.env`, a POST to `/wp-login.php`, a 404, a body over the 1 MiB cap | One decision per request; credentials captured; nginx-identical 404 and 413 |
| 3 | Scripted Redis session (raw socket, inline and RESP): `PING`, `INFO`, `CONFIG SET dir` and `dbfilename`, `SET`, `SAVE`, `SLAVEOF` | One decision per command. The replication target is recorded. The state is visible to the same source and invisible to another. |
| 4 | Scripted MySQL session (PyMySQL): log in, `SHOW DATABASES`, a `SELECT`, an `INSERT` then a `SELECT` that sees it, an `INTO OUTFILE` attempt | One decision per packet. Reference-identical errors. |
| 5 | Token chain: the SSH session reads `/var/www/html/.env`, then a MySQL session logs in with those credentials | A `token.triggered` event, and both sessions share an `actor_id` linked by honeytoken use |
| 6 | Policy service stopped | All four decoys still answer as their unmodified emulation would, and record fallbacks with reasons |
| 7 | Containment, extended | The phase 0 tests, on every decoy. From each decoy, only the policy port is reachable on `mirage_gate`. The policy service has no egress. The edge cannot reach the policy service. Cowrie's emulated `wget` and `curl` cannot reach the policy service's address. A wrong bearer token is refused. |
| 8 | Default-tell checks | All pass except the known gaps, and the SSH checks fail against stock Cowrie |
| 9 | Latency | Gating adds under 20 ms at p95 per input on every protocol, measured over the scripted sessions |
| 10 | Pipeline | No dead letters and no `unknown` event classes |

## 7. Order of work

| Week | Critical path | Alongside |
| --- | --- | --- |
| 3 | Contract v1 and policy service (1.2); gate network and extended containment test; schema mappings for the new sources | Reference image, `make profile-ref` and the tell checks, all failing against stock Cowrie (1.3) |
| 4 | Cowrie fork changes (1.1); HTTP decoy (1.4); Redis and MySQL decoys (1.5), each against the contract | Profile generator (1.3) |
| 5 | Honeytokens (1.6); sessioniser (1.7); artifact store (1.8) | Gate 1 tests; dashboard panels for the new protocols |

1.2 comes first because 1.1, 1.4 and 1.5 all code against its contract. The three weeks assume the 3–4 people the build plan assumes. With fewer, the decoys in week 4 run in sequence, and phase 1 stretches by about a week per missing person.

**Schema changes.**
- New event IDs: `cowrie.fs.change`, the HTTP, Redis and MySQL decoy events, `policy.decision` from the service, and `token.triggered`.
- The database decoys need an OCSF class. Pick it from OCSF 1.9's Application Activity category when writing the mapper, and check the class UID against the 1.9 schema rather than from memory.
- Redis and MySQL share the existing source `db-decoy`, and `protocol` tells them apart.

## 8. Known gaps carried to phase 3

| Gap | Why it stays |
| --- | --- |
| HASSH-server differs from every real OpenSSH | Twisted implements none of chacha20-poly1305, AES-GCM, ETM MACs, sntrup761 or strict KEX (S3). Decision D12 settles this in phase 3: either a real OpenSSH front end, or accepting the limit. |
| Cowrie rejects an `SSH-2.2` client; its error lines end in LF | Transport code; same decision |
| Redis `HELLO 3` (RESP3) | Rare in attack traffic; answered with an error, a tell that is listed |
| MySQL prepared statements | Rare in attack traffic; answered with a MariaDB error |
| Malformed HTTP request lines | h11 rejects them differently from nginx; measured in the tell checks and listed |
| Profile-dependent commands Cowrie lacks (`lscpu`, `ss`, `free`) | Pre-rendered per profile in phase 3 (S2). Until then they get "command not found". |

## 9. Out of scope

The LLM responder, the bandit and any learned policy, PostgreSQL, `plant_token` and `escalate`, pre-rendered commands, the high-interaction sandbox, and any internet exposure.
