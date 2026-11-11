# Phase 0 spikes

Three week-1 experiments from [the build plan](../docs/01-build-plan.md#4-risk-spikes-week-1). Run on 11 November 2026, Apple M4 with 16 GB, Docker Desktop 29.4, Cowrie 3.1.6 (`ea9513e`).

| Spike | Question | Answer |
| --- | --- | --- |
| S1 | Can a Cowrie fork consult a policy service before every command? | **Yes.** 2.4 ms added per command, fails open, Cowrie's own test suite stays green. |
| S2 | LLM latency on the M4 | **Too slow for live answers.** 12.5 tokens/s; median 8.6 s per command with prompt caching; 0 of 150 under 1.5 s. The model server takes about 9 GB. |
| S3 | Does Cowrie still fail the Bitter Harvest probes? | **The padding tell is fixed; a stronger one remains.** One passive look at the algorithm list identifies a Twisted-based decoy. |

## S1 · Cowrie policy gate

**Patch:** [`s1-cowrie-gate/mirage-gate.patch`](s1-cowrie-gate/mirage-gate.patch), against Cowrie v3.1.6.

| File | Change |
| --- | --- |
| `src/cowrie/mirage_gate.py` | New. All gate logic: HTTP client, decision handling, placeholder command, TCP_NODELAY helper. |
| `src/cowrie/shell/honeypot.py` | 9 lines. `runCommand` hands the expanded argv to the gate instead of `_run_expanded`. |
| `src/cowrie/shell/session.py` | 4 lines. TCP_NODELAY when a pty is allocated. |
| `src/cowrie/core/eventids.py`, `docs/OUTPUT.rst` | Register and document `cowrie.policy.decision`. Cowrie's own test enforces both. |
| `src/cowrie/test/test_mirage_gate.py` | New. 24 tests. |

**Results**

- Cowrie's suite: 1,628 tests, all pass except 4 that need optional output-plugin libraries (MongoDB, Redis, RethinkDB, RabbitMQ) not installed locally; CI installs them.
- With the gate disabled the code path is a direct call to the original `_run_expanded`.
- Every simple command is gated after expansion, including each pipeline stage, loop bodies and command substitutions.
- `sudo X` and `busybox X` are gated once as a whole argv; the inner command is not gated separately. Acceptable: the policy sees the full argv.
- Over real SSH and HTTP (`run_e2e.py`, [`result.json`](s1-cowrie-gate/result.json)): stock Cowrie 5.1 ms median per command, gated 7.6 ms. The policy call itself is 0.8 ms median, 1.3 ms p95.
- Policy slower than the deadline (200 ms in the spike): falls back to stock behaviour at 208 ms. Policy service stopped: the shell keeps working.

**Problems found and fixed on the way**

| Problem | Effect | Fix |
| --- | --- | --- |
| A line typed while a decision was pending ran immediately | Commands could run out of order | A placeholder command sits on Cowrie's command stack while the decision is pending, so input queues and Ctrl-C cancels, as for any running command |
| Docker resolves service names to IPv6 first | 300 ms per new connection to an IPv4-only service (Twisted's happy-eyeballs delay) | The policy service must listen dual-stack |
| Pooled keep-alive connections closed by the server | Every other request failed; Twisted does not retry a POST | Gate's own pool drops idle connections after 2 s, below a typical server keep-alive, and retries once on a stale connection |
| Python `http.server` writes headers and body separately | 40 ms per decision (Nagle plus delayed ACK) | The policy service must disable Nagle (uvicorn does by default) |
| Cowrie never sets TCP_NODELAY; OpenSSH does on pty sessions | Any output written in a later reactor turn waits about 40 ms for the client's ACK | Set TCP_NODELAY when a pty is allocated, as OpenSSH does |

The last row also matters outside the gate: Cowrie's timing differs from OpenSSH's for any asynchronously answered command (`wget`, `curl`) today.

**Policy service requirements for phase 1**, from the above: listen on IPv4 and IPv6, HTTP/1.1 keep-alive with an idle timeout above 2 s, TCP_NODELAY, answer well inside the deadline (target 50 ms).

## S2 · Local LLM latency

**Setup.** `unsloth/Qwen3.5-9B-GGUF`, Q4_K_M (5.68 GB, Apache-2.0, SHA-256 verified), the model HydraPoT ran locally. `llama-server` b11429 natively on macOS with Metal, 4 slots × 4,096 tokens, thinking off ([`s2-llm-latency/serve.sh`](s2-llm-latency/serve.sh)). The MIRAGE Docker stack was running throughout.

**Method** ([`bench.py`](s2-llm-latency/bench.py)). 50 commands the emulator does not implement. The system prompt holds a persona and the session state, about 440 tokens. Output is constrained to the JSON schema `{stdout, stderr, exit_code}` and capped at 400 tokens, with temperature 0.2. Three conditions: prompt cache off, cache on, and four concurrent sessions. Raw results: [`result.json`](s2-llm-latency/result.json); every output: [`outputs.jsonl`](s2-llm-latency/outputs.jsonl).

| | Cache off | Cache on | 4 in parallel |
| --- | --- | --- | --- |
| Time to first token, p50 | 4.9 s | 0.48 s | 0.96 s |
| Total per command, p50 | 12.0 s | 8.6 s | 14.4 s |
| Total per command, p95 | 43.8 s | 39.1 s | 65.1 s |
| Under 1.5 s | 0 / 50 | 0 / 50 | 0 / 50 |
| Generation, tokens/s per stream | 12.5 | 12.5 | 6.6 |
| Output tokens, p50 | 91 | 96 | 83 |
| Hit the 400-token cap | 8 | 9 | 7 |

- **Generation dominates.** The prompt cache works (426 of 443 prompt tokens reused, first token at 0.48 s), but it saves only the prompt, so total time drops from 12.0 s to 8.6 s.
- **Long outputs are hopeless live.** `lscpu`, `/proc/cpuinfo`, `ps aux`, `dmesg` and `cat /etc/hosts` ran past 400 tokens, 30–40 s each. All 24 non-JSON replies were these truncated ones; the schema constraint itself never failed.
- **Parallel sessions share one memory bus.** Four streams raised total throughput about 1.7× but halved each stream. One laptop serves one live LLM session acceptably, not several.
- **Memory.** Stopping the server raised free memory from 19% to 77% of 16 GB, about 9 GB, with macOS swapping while it ran. Process RSS showed only 0.9 GB, because GPU-mapped weights and the KV cache are not counted there. An 8–9B model plus the stack fills this laptop.

**Quality, read by hand.** Hostname, kernel, disk and memory matched the state, blocked egress failed believably, and missing tools got the right `command not found` with exit code 127. None of the 150 replies mentioned being an AI or a honeypot. Three answers a careful attacker would catch:

- `cat /etc/shadow` as root returned "Permission denied", but root can read it.
- `which python3 gcc perl` used RHEL's message format and exit code 0. Debian's `which` prints nothing and exits 1, and Debian always ships perl.
- `ss -tlnp` printed `netstat`'s header.

**Output format** ([`format_compare.json`](s2-llm-latency/format_compare.json), 12 commands). Raw terminal text plus an exit-code marker used 62% fewer tokens than JSON (median 2.2 s against 5.8 s; `nproc` took 8 tokens instead of 61). It was less faithful, though. It said `w`, `hostnamectl` and `mysql` were not installed on a Debian host that the state says runs systemd and MariaDB, and it garbled `uptime`. The structure costs time and buys accuracy.

**What this changes** (architecture §5, AI/ML design §5)

1. **Pre-render, don't generate live.** Most commands the emulator lacks (`lscpu`, `free`, `df`, `ss`, `cat /etc/hosts`) depend only on the host profile. Render them once per profile, offline and with any model, check them, and serve them as Cowrie text commands: instant, and identical across sessions, as a real host's would be. The live LLM handles only commands that are genuinely novel.
2. **Stream when the LLM does answer.** The first token arrives in about 0.5 s with the cache. Stream stdout as it is generated, so the response is a slow-printing command rather than a 9-second silence. This needs a format whose stdout can stream, such as the raw form with a fidelity check, or JSON with stdout first.
3. **Run the live model on the Linux host's GPU in phase 3.** On this laptop it takes about 9 GB and one session at a time.
4. **Fidelity needs tests, not trust.** Three wrong answers in 50 is enough to give the game away. The pre-rendered outputs get a check against a real Debian container, the same way S3 compares Cowrie with real OpenSSH.

## S3 · SSH transport probes

**Tool:** [`../eval/probes/ssh_probes.py`](../eval/probes/ssh_probes.py), stdlib only. Compared Cowrie 3.1.6 (stock and gated) against `openssh-server` from Debian 12, the build Cowrie's default banner claims (`OpenSSH_9.2p1 Debian-2+deb12u…`). Raw output: [`s3-transport/result.json`](s3-transport/result.json).

| Probe | OpenSSH 9.2p1 | Cowrie 3.1.6 | Tell? |
| --- | --- | --- | --- |
| KEXINIT padding (Bitter Harvest) | zeroed | zeroed | **No.** Fixed upstream since the paper. |
| KEXINIT before client identification | no | no | No |
| Server algorithm list (HASSH-server) | `425d29fe…` | `6fa2f18e…` | **Yes**, passively, from one packet |
| Client claims `SSH-2.2` | accepted, key exchange continues | `Protocol major versions differ.` and close | **Yes** |
| Error line endings | CRLF, or none | LF | Yes |
| Gated vs stock Cowrie | — | identical | The gate adds no transport tell |

**What the algorithm list shows.** Cowrie offers algorithms OpenSSH 9.2p1 does not (CBC ciphers, 3DES, CAST, `hmac-md5`, `zlib`, the `ssh-rsa` host-key algorithm) and two that 9.2p1 could not have: `mlkem768x25519-sha256` (OpenSSH 9.9) and `ext-info-s` (9.6). It lacks chacha20-poly1305, AES-GCM, the ETM and UMAC MACs, sntrup761, group14/16/18 SHA-2 key exchanges, and the strict-KEX marker Debian backported for Terrapin.

**What config can and cannot fix.** Cowrie's `[ssh] ciphers`, `macs` and `compression` can remove the extras. The key-exchange list is not configurable, and Twisted 26.10 implements none of the missing algorithms. So no Cowrie configuration matches any real OpenSSH release. This is the transport-level limit decision D12 anticipated, but the tell is the algorithm set, not the padding the paper described.

**Consequence for the plan.** Phase 1 trims the configurable extras (cheap, removes the most obvious anachronisms). The phase 3 decision is between terminating SSH on a real OpenSSH front end and handing the session to the emulation, or accepting that a passive observer can identify the decoy. See decision D12 in the build plan.
