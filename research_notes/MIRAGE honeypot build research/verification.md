# MIRAGE build plan: primary-source verification

Checked 2026-11-11. Every row was verified by opening the primary source named in the URL column (arXiv API + PDF text, Zenodo API, GitHub API / source at HEAD, PyPI, attack.mitre.org). Nothing here is from snippets or memory.

Source snapshots used:
- cowrie/cowrie `main` @ `ea9513e` (commit 2026-11-06)
- apache/caldera `master` @ `cb8d6a8` (commit 2026-08-27)
- flwrlabs/flower `main` @ `2f53925` (commit 2026-11-11)

## Verdict table

| # | Claim | Verdict | URL opened | Evidence |
|---|---|---|---|---|
| 1 | arXiv 2610.27722 = "HydraPoT", routes commands to Cowrie / local Qwen / cloud model, shared state dict, 72.6% fewer tokens, public code | CONFIRMED (two precisions) | https://arxiv.org/abs/2610.27722 , https://github.com/Kamolchanok-Saengtong/HydraPoT | Title "HydraPoT: A Configurable Multi-Agent Framework for Cost-Aware LLM-Assisted Honeypots"; Saengtong, Saengyingyongwattana, Janpuangtong, Rattanavipanon; AINTEC 2026. Code repo is MIT. 72.6% is a reduction in *cloud-processed* tokens (cost 3.7x lower, $1.98 to $0.54). See note 1. |
| 2a | 2606.27990 AdvancedShelLM, worker/manager verifier, JSON filesystem | CONFIRMED; code only via anonymised link | https://arxiv.org/abs/2606.27990 | "AdvancedShelLM: A Stateful Multi-Agent LLM Honeypot for SSH Deception" (Sladić, Alibalić, Valeros, Catania, Garcia). Worker drafts, Manager verifies, shared JSON filesystem. Code footnote points to `anonymous.4open.science/r/AdvancedShelLM-946B`; no `stratosphereips/AdvancedShelLM` repo exists (404). |
| 2b | 2605.29963 Honeyval | CONFIRMED; code public | https://arxiv.org/abs/2605.29963 , https://github.com/google-research/honeyval | "Honeyval: A Comprehensive Evaluation Framework for LLM-powered HTTP Honeypots" (Vero et al.). Note it is HTTP, not SSH. Repo Apache-2.0. |
| 2c | 2611.12386 "Say Shibboleth" | CONFIRMED; code NOT public | https://arxiv.org/abs/2611.12386 , https://github.com/SayShibboleth/Shibboleth | "Say Shibboleth: Fingerprinting the LLMs and Harnesses Behind Agentic Attacks" (Pasquini, Reworr, Ateniese, Bhatt, Epp), submitted 2026-11-09, v0.1. The repo the paper links is empty (GitHub API: "This repository is empty"), no licence. |
| 2d | 2510.06975 VelLMes | CONFIRMED; code public | https://arxiv.org/abs/2510.06975 , https://github.com/stratosphereips/VelLMes-AI-Deception-Framework | "VelLMes: A high-interaction AI-based deception framework" (Sladić et al.). Repo GPL-2.0, last push 2025-02-18. |
| 2e | 2509.01463 LLMHoney | CONFIRMED; no code link | https://arxiv.org/abs/2509.01463 | "LLMHoney: A Real-Time SSH Honeypot with Large Language Model-Driven Dynamic Response Generation" (Pranjay Malhotra). Paper text contains no repository URL; no author repo found. Treat as code not public. |
| 2f | 2406.01882 HoneyGPT | CONFIRMED; code public (not linked from arXiv) | https://arxiv.org/abs/2406.01882 , https://github.com/zyw-286/HoneyGPT | "HoneyGPT: Breaking the Trilemma in Terminal Honeypots with Large Language Model" (Wang et al.). arXiv PDF has no code link, but a repo created 2026-06-09 ties itself to the Computer Networks 2026 journal version (DOI 10.1016/j.comnet.2026.112223), built on Cowrie, README badge says BSD-3-Clause (GitHub reports licence as "Other"). |
| 3a | Zenodo 21260400 = July 2026 Cowrie corpus, ~160 instances, ~38M sessions, CC BY 4.0 | CONFIRMED | https://zenodo.org/api/records/21260400 | "Deployment of 160 Cowrie SSH honeypot instances across four distinct configurations", published 2026-07-08, licence cc-by-4.0, open. 50 days, 14 countries, 211M events, 38M sessions, 214k source IPs, 1,770 file artifacts. |
| 3b | CyberLab honeynet dataset Zenodo 3687527 and licence | CONFIRMED | https://zenodo.org/api/records/3687527 | "CyberLab honeynet dataset" (Sedlar et al.), published 2020-02-29, licence cc-by-4.0, open. Cowrie 1.6.0 / 2.0.2, ~50 nodes, May 2019 to Feb 2020. |
| 4 | Cowrie internals | See section below | https://github.com/cowrie/cowrie (HEAD ea9513e) | Notes written against older Cowrie will be wrong: the shell was rewritten (Lark grammar, Deferred-driven trampoline). |
| 5 | Caldera canonical repo is apache/caldera, Apache-2.0, latest release, v2 routes, event-log fields | CONFIRMED | https://github.com/apache/caldera , https://raw.githubusercontent.com/apache/caldera/master/app/api/v2/handlers/operation_api.py , .../app/objects/c_operation.py | `mitre/caldera` redirects to `apache/caldera`; Apache-2.0; latest release 5.3.0, 2025-04-24 (no newer tag). Routes and fields in note 5. |
| 6 | ATT&CK current version / Defense Evasion split | CONFIRMED | https://attack.mitre.org/resources/versions/ , https://attack.mitre.org/resources/updates/updates-april-2026/ , https://attack.mitre.org/tactics/enterprise/ | Current is v20.1; site lists v20 as live from 2026-10-13. Split happened in v19 (2026-04-28): Stealth = TA0005 (reuses the old Defense Evasion ID), Defense Impairment = TA0112. Enterprise now has 15 tactics. See note 6 for a date discrepancy. |
| 7 | MinIO community repo archived | CONFIRMED | https://github.com/minio/minio (GitHub API) | `archived: true`, AGPL-3.0, last push 2026-04-24. |
| 8 | Flower version; SecAgg+ vs Message API; DP preview | CONFIRMED | https://pypi.org/pypi/flwr/json , https://github.com/flwrlabs/flower (framework/py/flwr/server/workflow/secure_aggregation/secaggplus_workflow.py, framework/docs/source/how-to-use-differential-privacy.rst) | flwr 1.43.0 (2026-11-04). SecAgg+ is legacy-workflow only. DP docs still carry the preview warning. Repo is now `flwrlabs/flower` (`adap/flower` redirects). See note 8. |
| 9 | HoneyLLM effective vs scanning fraction; "99.2%" | CORRECTED | https://www.cse.psu.edu/~sxz16/papers/HoneyGPT.pdf , https://arxiv.org/abs/2510.25939 | HoneyLLM says ~9.8% of sessions were effective (2,672 for GPT-3.5 Turbo), i.e. ~90.2% scanning. "99.2%" does not appear anywhere in the paper. The SoK attributes 99.2% to this paper (its ref [52]); that figure is not supported by the source. See note 9. |
| 10 | Kuzu repo archived in 2025 | CONFIRMED | https://github.com/kuzudb/kuzu (GitHub API) | `archived: true`, MIT, last push 2025-10-10. |
| 11 | LogPrécis labels, sessions, HF IDs, licences | CONFIRMED (licences only added today) | https://arxiv.org/abs/2307.08309 , https://github.com/SmartData-Polito/logprecis , https://huggingface.co/SmartDataPolito | 7 labels; 360 labelled sessions; models `SmartDataPolito/logprecis` and `SmartDataPolito/SecureShellBert`; code+models Apache-2.0, data CC BY 4.0. See note 11. |
| 12 | "Sweet Danger of Sugar" ET-BERT per-flow vs per-packet | CONFIRMED (numbers in note 12) | https://arxiv.org/abs/2507.16438 | Full title "The Sweet Danger of Sugar: Debunking Representation Learning for Encrypted Traffic Classification" (Zhao et al.). TLS-120 unfrozen: 97.4 AC / 96.8 F1 per-packet vs 28.0 / 21.5 per-flow. |

## Notes

### 1. HydraPoT
- Three agents in the case study: Cowrie (official Docker image), local `unsloth/Qwen3.5-9B-GGUF` (Q5_K_M, RTX 4060), cloud DeepSeek-V4 Flash. The cloud model is DeepSeek, not an OpenAI/Anthropic model; GPT-5 is used only as the LLM-as-judge.
- Shared state is a per-session `SYSTEM_STATE` dictionary, "the authoritative shared state for all agents", tracking six categories (cwd, files with metadata, and others).
- Routing is by a configurable complexity policy with five levels F0 to F4.
- Runtime overhead claim is "less than 5%".

### 4. Cowrie at HEAD (ea9513e)

Paths are under `src/cowrie/`. Raw URL pattern: `https://raw.githubusercontent.com/cowrie/cowrie/main/src/cowrie/...`

**(a) Resolve and execute**
- Resolve name to class: `HoneyPotBaseProtocol.getCommand(cmd, paths, cwd)`, `shell/protocol.py:246`. Order: `self.commands` dict, then PATH lookup in the fake fs, then txtcmds (operator `txtcmds_path`, then bundled), then `scriptcmd` for any regular file.
- Execute: `HoneyPotBaseProtocol.call_command(pp, cmd, *args)`, `shell/protocol.py:312` (instantiates the class, pushes on `cmdstack`, calls `obj.start()`). Interactive override at `shell/protocol.py:547`.
- The caller of both is `HoneyPotShell._run_expanded`, `shell/honeypot.py:1154`: `getCommand` call at line 1212, `call_command` at line 1264.
- Upstream chain: `lineReceived` (362) -> `_feed_line` (374, emits `cowrie.command.input` at 387) -> `_advance` trampoline (671) -> `runCommand` (932) -> `Deferred.fromCoroutine(self.bashparser.evaluate(command))` with `addCallback(self._run_expanded)` (991-993).

**(b) Command not found today**
`shell/honeypot.py:1215-1239`: dispatches event `cowrie.command.failed` ("Command not found: ..."), writes `command_not_found_message()` (line 1266: `-bash: X: command not found`, or "Is a directory" / "No such file or directory" for path-like names; `exec: X: not found` under `exec`), sets `last_exit_code = 127`, then `_advance()`. There is no LLM fallback in the shell backend.

**(c) Where protocols are instantiated / minimal fork surface**
- SSH: `shell/session.py:88-93` (`openShell` -> `HoneyPotInteractiveProtocol`) and `shell/session.py:107-112` (`execCommand` -> `HoneyPotExecProtocol`), each wrapped in `insults.LoggingServerProtocol`. Adapter registered in `shell/avatar.py:84`.
- Telnet: `shell/telnet.py:91`.
- Shell objects: `shell/protocol.py:420` (exec) and `:497` (interactive) create `HoneyPotShell`.
- Backend selection is NOT in `ssh/factory.py` (that only switches proxy vs non-proxy auth/transport, lines 54 and 118). It is in `src/twisted/plugins/cowrie_plugin.py:200-213` (SSH) and `:233-240` (Telnet): `[honeypot] backend` = `shell` or `proxy` -> `cowrie.shell.realm.HoneyPotRealm`; `llm` -> `cowrie.llm.realm.HoneyPotRealm`.
- Minimal set of files to touch: `shell/honeypot.py` only, for both features. Put the policy gate between `evaluate` and `_run_expanded` (line 991-993) or at the top of `_run_expanded`, and replace the not-found branch at 1215-1239 with an LLM call. Optionally `shell/protocol.py` (`getCommand`/`call_command`) if the gate should also cover commands launched by other commands: `sudo.py:98/127`, `busybox.py:81` and `shell/command.py:228` (`exec_command`) call these directly and bypass `_run_expanded`. Pipelines and subshells run each stage in a child `HoneyPotShell`, so they do pass through `_run_expanded`.
- `cowrie/llm/` is a separate, parallel backend (own avatar, realm, session, server, protocol) that sends every line to the LLM. It has no fake filesystem (`llm/server.py` has no `fs`) and keeps only the last 10 history lines (`llm/protocol.py:289`). It is not a fallback for the shell backend. Reusable piece: `llm/llm.py` `LLMClient.get_response(prompt) -> Deferred[str]` (line 258, Twisted `Agent`, OpenAI-compatible `/v1/chat/completions`, config section `[llm]`).

**(d) Async without blocking the reactor**
Yes. Dispatch is already Deferred-driven: `runCommand` attaches `_run_expanded` as a callback to the expansion Deferred, and `_advance` is documented to handle a command that "pauses on a Deferred (e.g. wget)" and resumes later via `resume()`. Existing patterns:
- `commands/sleep.py:109`: `self.callLater(_time, self.exit)` (`HoneyPotCommand.callLater`, `shell/command.py:138`, wraps `reactor.callLater` and cancels on exit).
- `commands/wget.py:169` and `commands/curl.py:218`: `@inlineCallbacks def start`, `treq` Deferreds, `self.exit()` in callbacks.
- `llm/protocol.py:292`: `d = self.llm_client.get_response(prompt); d.addCallback(...)`.
A command stays on `cmdstack` until it calls `exit()` (`shell/command.py:174`), which hands the status to the shell and calls `resume()`. So an external policy call must be a non-blocking Twisted client (treq / Agent) returning a Deferred; a blocking `requests` call would stall all sessions.

**(e) Fake filesystem exposure**
- `CowrieServer.fs` (`shell/server.py:36`), created per session by `initFileSystem` (line 54, called from `shell/session.py:81`); exposed as `protocol.fs` (`shell/protocol.py:72`).
- Class `HoneyPotFilesystem`, `shell/fs.py:119`. Tree loaded from pickle by `core/honeyfs.py` `get_tree()` (line 95): `[shell] filesystem` if set, else bundled `data/fs.pickle`; cached for the process.
- Copy-on-write: the base tree is shared until `_ensure_private_fs()` (`fs.py:162`) deep-copies on first mutation. Changes are per-session, in memory, and not persisted.
- No change-event hook exists. All mutations go through a small set of methods (`mkfile` 359, `mkdir` 386, `open`/`write`/`close` 489-532, `rmdir` 571, `chmod` 597, `chown` 604, `remove` 614, `symlink` 629, `rename` 632, `update_size` 677), so a state manager can wrap or subclass them. Reads: `exists`, `isfile`, `isdir`, `listdir`, `stat`, `file_contents` (307), `resolve_path` (188).
- cwd lives on the shell object, not the fs: `HoneyPotShell.cwd` (`honeypot.py:122/140`), set by `cd` at `commands/fs.py:406`; reach it as `protocol.cmdstack[0].cwd`.

**(f) JA4 / FoxIO code**
- Vendored in `src/cowrie/vendor/ja4/`: `ja4h.py`, `ja4x.py`, `ja4ssh.py` and `README.md` are `LicenseRef-FoxIO-1.1`; `common.py` is `BSD-3-Clause AND LicenseRef-FoxIO-1.1`; `ja4.py` is BSD-3-Clause. Licence text in `LICENSES/LicenseRef-FoxIO-1.1.txt` (non-commercial use only; hosted/managed service use excluded).
- Only runtime import of the vendor dir: `core/fingerprint.py:28` imports `GREASE_TABLE, TLS_MAPPER, sha_encode` from `vendor/ja4/common.py`. `fingerprint.py` itself is tagged BSD-3-Clause but its `generate_ja4h` (line 307) says it uses "FoxIO's logic".
- Call sites: `ssh/forwarding.py` (`FakeForwardingChannel.dataReceived`, ~line 131-160) and `ssh_proxy/protocols/port_forward.py:31-85`. Events `cowrie.direct-tcpip.ja4` / `.ja4h`.
- No dedicated config switch: `cowrie.cfg.dist` contains no `ja4` option. Indirect disable for the shell backend: `[ssh] forwarding = false` removes the `direct-tcpip` channel (`shell/avatar.py:55`), so the fingerprint code never runs, but the module is still imported. For clean licensing a fork has to delete `vendor/ja4/`, `core/fingerprint.py` and the two call sites.
- Cowrie's own licence is BSD-3-Clause (`pyproject.toml:13`); GitHub reports NOASSERTION because of the mixed licences.

### 5. Caldera
- Routes from `operation_api.py:29-30` (app mounted under `/api/v2`):
  - `POST /api/v2/operations/{id}/report`
  - `POST /api/v2/operations/{id}/event-logs`
  Both are POST, not GET. Body schema `OperationOutputRequestSchema` (`enable_agent_output`).
- Event-log record (`c_operation.py:388-401`, `_convert_link_to_event_log`): `command`, `plaintext_command`, `delegated_timestamp`, `collected_timestamp`, `finished_timestamp`, `status`, `platform`, `executor`, `pid`, `agent_metadata`, `ability_metadata`, `operation_metadata`, `attack_metadata`, plus `output` when requested.
- ATT&CK fields: `attack_metadata.tactic`, `attack_metadata.technique_name`, `attack_metadata.technique_id` (`c_operation.py:563-566`).
- Report steps use different names: `attack.{tactic,technique_name,technique_id}`, timestamps `delegated` and `run` (`c_operation.py:321-335`).
- Caldera ability tactics are free-text strings from ability YAML; nothing in this code maps them to the v19+ Stealth / Defense Impairment names.

### 6. ATT&CK
- attack.mitre.org/resources/versions lists: v20.1 "October 13, 2026 - current"; v19.2 April 28 to October 12, 2026; v18.1 October 28, 2025 to April 27, 2026.
- Discrepancy: the `mitre-attack/attack-stix-data` GitHub releases for v20.0 and v20.1 are both stamped 2026-11-05. The website date is the official release date; the STIX bundle tag is later. Not resolved further.
- Any tagger trained on pre-v19 labels (e.g. LogPrécis "Defense Evasion") needs a mapping to TA0005 Stealth / TA0112 Defense Impairment.

### 8. Flower
- `SecAggPlusWorkflow.__call__` raises `TypeError` unless `context` is a `LegacyContext` (`secaggplus_workflow.py:185-187`); `DefaultWorkflow` has the same check. There is no SecAgg code under `flwr/serverapp/` (the Message-API strategies) or `flwr/clientapp/`.
- Client side `secaggplus_mod` (`flwr/client/mod/secure_aggregation/secaggplus_mod.py:131`) takes a `Message` but converts through `flwr.compat.common.recorddict_compat` (`recorddict_to_fitres`, line 169), i.e. legacy FitIns/FitRes payloads.
- The legacy `ServerApp(server=..., config=..., strategy=...)` constructor path that produces a `LegacyContext` emits a deprecation warning (`serverapp/server_app.py:128-131`).
- Conclusion: SecAgg+ works only with the legacy workflow API and legacy `flwr.server.strategy` strategies, not with `flwr.serverapp.strategy` (FedAvg, DP wrappers, etc.).
- DP: `how-to-use-differential-privacy.rst:45-49`: "Differential Privacy in Flower is in a preview phase." Message-API DP strategies do exist (`serverapp/strategy/dp_fixed_clipping.py`, `dp_adaptive_clipping.py`).

### 9. HoneyLLM
- Paper: Guan, Cao, Zhu, "HoneyLLM: Enabling Shell Honeypots with Large Language Models", IEEE CNS 2024. Three-week deployment, May 2024.
- Text: "only 2,672 attack sessions (approximately 9.8% of total attack sessions) were unique and considered effective." Table II: effective sessions / average length: GPT-3.5 Turbo 2672 / 4.37; GPT-4o 2763 / 5.83; Claude-3 Haiku 2797 / 5.36; Cowrie-only 2386 / 2.96.
- "90.2%" appears in the paper only as an offline success rate, unrelated to traffic share. "99.2%" appears nowhere.
- SoK 2510.25939 (v4), section 4.2.1: "Guan et al. [52] ... 99.2% of all honeypot activity consisted of simple scanning scripts." The 2.96 and 5.83 figures in the same sentence are correct; 99.2% is not in the cited paper. Use ~90% and cite HoneyLLM directly.

### 11. LogPrécis
- Labels (7): Execution, Persistence, Discovery, Impact, Defense Evasion, Harmless, Other.
- 360 labelled sessions (from HaaS), split 60/20/20.
- HF: `SmartDataPolito/logprecis` (token-classification) and `SmartDataPolito/SecureShellBert` (fill-mask), both tagged apache-2.0. No datasets under that HF org.
- GitHub `SmartData-Polito/logprecis`: `LICENSE` Apache-2.0 (code and models), `LICENSE-DATA` CC BY 4.0 (annotations, curation, splits). These files were added in a commit dated 2026-11-11 ("Add licensing ..."); before today the repo had no licence file.
- README caveat: the CC BY licence covers only the authors' annotations, not the underlying HaaS session content, which stays under HaaS Terms of Use (not an open-data licence).

### 12. Sweet Danger of Sugar: ET-BERT (accuracy / macro F1, %)

| Task | Encoder | Per-flow split | Per-packet split |
|---|---|---|---|
| VPN-app (16) | frozen | 59.2 / 43.7 | 69.5 / 64.7 |
| VPN-app (16) | unfrozen | 82.8 / 69.7 | 96.8 / 97.0 |
| TLS-120 | frozen | 10.9 / 6.7 | 17.5 / 10.2 |
| TLS-120 | unfrozen | 28.0 / 21.5 | 97.4 / 96.8 |

Source: Tables 4, 5 and 6. Table 6 also shows per-packet TLS-120 without pre-training at 97.1 / 96.4 (pre-training "mostly useless") and 19.5 / 15.4 when SeqNo/AckNo/timestamps are removed from test only.

## Not verified / limits
- AdvancedShelLM code: the anonymised 4open.science link was not opened; contents and licence unknown.
- LLMHoney: absence of a repo is based on the paper text plus one GitHub search, not an exhaustive search.
- HoneyGPT repo licence: taken from the README badge; the LICENSE file itself was not read.
- ATT&CK v20 date discrepancy (website 2026-10-13 vs STIX tag 2026-11-05) left open.
