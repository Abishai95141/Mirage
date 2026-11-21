# Phase 3 working context

A running record of phase 3: where the work stands, what was decided and why, what was found,
and what is waiting on a person. It is updated as the work goes, not at the end. The design is
in [the phase 3 spec](06-phase-3-spec.md); this file does not repeat it.

Started 17 November 2026, when the instruction changed from one approved step at a time to
"develop the entire phase end to end" without stopping for approval.

## Rules that hold throughout

- Commit only when asked. Everything since `b8dea51` is uncommitted; the lab host's copy
  (`~/mirage`, by `tools/lab-host/sync.sh`) is the only second copy.
- `.env` values never appear in chat, logs or commits.
- Nothing faces the internet except the showcase link the owner opened. Decoys stay internal.
- Other projects' containers and the lab host's unrelated services are left alone.
- Scenario and catalogue command text is written by the separate content tool from a brief
  (`docs/handoffs/`). It is never printed or quoted here.
- A large download is named, with its size, before it is fetched.
- Root steps on the lab host are the owner's (`tools/lab-host/install-runtimes.sh`).
- A small sample runs through every step before any long run.
- The depth test half is read once, by the harness, for Gate 3.

## Where things run

| What | Where |
| --- | --- |
| Editing, unit tests, lint | The laptop (`uv run pytest -q`, `make lint`). Docker is not running there. |
| The stack, the lab, integration tests | The lab host, `ssh abishai@192.168.29.130`, repo copy `~/mirage` |
| Fork tests | A throwaway container of `mirage/cowrie:dev` on the lab host, changed files mounted |
| The model | `data/models/Qwen3.5-9B-Q4_K_M.gguf` on the laptop, `llama-server` native. Not on the lab host. |

## Status by step (spec section 7)

| Step | Work | State |
| --- | --- | --- |
| 1, 1b | Depth scenarios, arms, baseline; RL survey and four checks | Done |
| 2 | Fidelity check, inventory, hardware classes, render library, patches 0008 to 0010 | Done, measured on the lab host |
| 2 | Demo 3's brief | Done (`docs/handoffs/phase-3-demo-3.md`) |
| 2 | Demo 3's scenarios | Waiting on the content tool |
| 3 | Probe suite (`make probe`): tells, transport, emulator, timing, library; known-gaps file | Built, first run done on the lab host |
| 3 | Emulator and transport fixes the suite's first run asked for (fork patches 0011 to 0016) | Built and measured |
| 3 | Rebase of the reference image onto an installed system (found by the suite) | Not started; a known limit and three listed gaps until it is |
| 3 | Fleet group (a second decoy from another seed, `cowrie-fleet`) | Built |
| 3 | CI job for the suite (`.github/workflows/probe-suite.yml`) | Written; cannot be run until something is pushed |
| 3 | Spike S4 (OpenSSH front end) | Put after step 5: it blocks nothing in steps 4 to 8, and the depth test rests on those |
| 4 | Contract v2 in the schema; rules v2, the v2 mask, budgets and context version 3 in the policy | Built, unit-tested (37 new tests) |
| 4 | Responder service (`responder/`): `/v1/respond`, state manager, command classes, output filter, decoder, cache, backends (`replay`, `llama`), prompt, record log; the injection set (`eval/probes/injection.yaml`, 20 inputs) | Built, unit-tested (about 300 tests; every budget, every reply kind, resync, Ctrl-C, replay) |
| 4 | Fork patch 0017: the session's journal, the applier, the view sent with a request | Built; 60 tests in the image, the applier against direct mutator calls on 150 random sessions |
| 4 | File commands held to the reference host (same patch): mkdir, rmdir, cp, mv, rm, touch, ln, chmod, chown, chgrp, tee, find, cut, xargs, readlink, realpath, basename, dirname, checksums, seq, tac, rev, nl, printenv, mktemp | Built; 105 recorded command lines answer byte for byte as the reference host did. Not yet in a built image, so the probe suite has not seen them |
| 4 | Fork patch 0018: gate contract v2 in the shell (`respond`, `plant_token`, `supports` from background health checks, tier `absent`) and the respond client | Built; 33 tests in the image. Every ending of an answer is covered: answered, fallback, cut, cancelled, resync |
| 4 | Fork patch 0019: a password change holds for the source that made it; `passwd` and `chpasswd` as Debian 12's | Built; 16 tests in the image |
| 4 | The series on a clean clone of Cowrie v3.1.6 (the CI job, rehearsed on the lab host) | 1,913 tests pass with patches 0001 to 0019 |
| 4 | Repository side: tier `absent`; mappings for the four new decoy events and the responder's record (`Source.RESPONDER`); Vector and normaliser routes; responder image and service; networks `mirage_respond` and `mirage_llm`; rules v2 as the stack's default; checksum table built into the decoy image (5,974 files); `token_paths` in the decoy's configuration | Built; unit tests 1,297 |
| 4 | End-to-end tests on the lab host (`tests/integration/test_respond.py`, with a scripted stand-in for the model server; containment extended to the two new networks) | **`make itest`: 74 of 74**, among them the 12 respond tests (answer with all three records joined on the request, cache, pipe and redirection, operations applied before output, rejected operations, a refused line, a late first line, Ctrl-C in under 0.5 s with the responder told, typed-ahead order, resync after a restart, model server stopped, responder stopped) and containment for the responder |
| 4 | The fingerprint suite on the image with patches 0017 to 0019 (`make probe`) | **331 pass, 0 fail, 10 known gaps, 0 stale.** 69 new probes of file commands, checksums, `find`, `xargs`, `getconf`; 7 checks that a password change holds for its source and only for it |
| 4 | Gate 3 tests 4 and 5 against a live model; `make llm-record`; replay of real recordings | Step 5 |
| 4b | **Shell syntax** (fork patch 0020, "the shell reads bash"): every parameter expansion short of arrays, brace expansion, `$'...'`, `[[ ]]`, `(( ))`, `for ((;;))`, `!`, `NAME+=`; the builtins scripts use (`local`, `return`, `shift`, `let`, `declare`, `readonly`, `export`, `unset`, `eval`, `source`, `builtin`, `command`, `cd -`, `pushd`, `alias`, `hash`, `trap`, `shopt`, `set -o`); bash's own variables in `set` / `declare -p` / `readonly`; functions printed in bash's layout; bash 5.2's errors and which of them end a line; background commands (`cmd &`), which stock Cowrie did not run | Built. 234 lines of bash recorded on the reference host; the shell answers 229 the same (it was 6 of the first 27), and the 5 that differ are named in the test (arrays; `exec` file descriptors with PIPESTATUS, pipefail and `set -x`; three the stock test tree cannot run). In the image: 1,968 fork tests, none failing but the image's own 18. 64 new probes in `eval/probes/commands.yaml` (259 in all); **the live run is recorded in the log below** |
| 4b | Read permission for a user who is not root in stock commands (`cat /etc/shadow`, `cd /root`) | Not started; the new file commands enforce modes, the stock readers do not |
| 4b | Stock Cowrie's fixed texts (`top`, `killall`, `locate`, the editors) | Not started |
| 5 | The model server as a service of the stack: `llama` (profile `llm`), llama.cpp's own CUDA server image, on `mirage_llm` only, read-only, the model file its one volume; `make llm-up`, `llm-up-cpu`, `llm-down`, `llm-status` | **Running on the lab host's GPU** (the owner ran the root script on 17 Nov): 6.27 GB of the card's 8, four slots |
| 5 | The responder primes every slot with the fixed part of the prompt before it reports healthy | Built after the first live sample (see Findings); 2 tests |
| 5 | `make llm-bench` (`eval/probes/llm_bench.py`, `eval/probes/llm_commands.yaml`, 63 commands; 55 since 18 Nov, when `getent` and `tty` went to the emulator) | **Run.** [The write-up](experiments/phase-3/llm-bench.md): first byte 0.59 s and whole answer 0.81 s at the median (0.97 s and 1.50 s with four sessions at once); 58 of 63 answered by the model, **32 pass the fidelity check, 13 are the real host's answer line for line** |
| 5 | Prompt version 3 (the program is installed; do not answer with nothing; bare arguments are not listed as missing files; modes as octal digits) | Built from reading the model's raw answers against its prompts; unit-tested |
| 5 | `make llm-inject` (`mirage_responder.inject`) | **Run live: 20 hostile inputs, 17 answered in character, 3 aborted by the responder's checks, none broke a rule** |
| 5 | `make llm-record-on` / `-off` / `-save`: the live backend writes recordings on its own volume | Built and used to read the prompts; no recordings are committed yet |
| 5 | Model comparison (9B against about 4B: `unsloth/Qwen3.5-4B-GGUF`, Q4_K_M, 2.74 GB, Apache-2.0, checksum as published) | **Run.** Same state, same evening: the 9B answers 53 of the 58 commands that reach it, 29 pass, 12 are the real host's; the 4B answers 44, 20 pass, 7 are the real host's, and misses deadlines more often though it generates at 80 tokens/s against 44. **The 9B stays.** [Write-up](experiments/phase-3/llm-bench.md) |
| 5b | **Fine-tuning** (asked for by the owner, 17 Nov; not in the spec): a 4B model trained on what the reference host really prints, to beat the stock 9B on commands it was not trained on | **Done, 18 Nov; the stock 9B stays.** [The write-up](experiments/phase-3/lora-v1.md). 2,210 labelled rows, a rank-16 LoRA of `Qwen/Qwen3.5-4B` trained on a Kaggle T4 in 3 h 10 min, served as the stock 4-bit file with the adapter beside it. Held-out: 42 of 162 and 76 of 382 the real host's answer (stock 9B: 5 and 27). Bench: a tie (11 of 47 against 10 of 45), faster, 3.9 GB against 6.3, and **worse on state-changing commands** (2 of 10 against 5 of 9: no training row changes a file, and the model stopped proposing operations). No second round: see Decisions |
| 5 | A session asked the same thing in the same state is told the same (`Session.said`) | Built; 3 tests. Covers the classes the cache never keeps |
| 5 | Promotion (spec 3.2b): `make render-candidates` (the responder's cache to `rendered/promoted.yaml`), `render-record`, `render-library` (entries, and the cached answers to evict), `make llm-evict` | Built and run once: of 20 cached stateless answers, 2 were the real host's and 18 were evicted. 5 commands became library entries; 15 were left, each with its reason in `promoted.yaml` |
| 5 | `getent`, `tty`, `ss` in the emulator (fork patch 0021, `mirage_netutils.py`): `getent` from the session's own `/etc` files, `tty` from whether the session has a terminal, `ss` from the deployment's sockets and the session's own connection, naming the processes `ps` shows | **Built and deployed, 18 Nov.** 25 fork tests, 15 of them recorded command lines reproduced byte for byte (piped, and on terminals 60 to 200 columns wide) plus a real guest's four. Sockets come from two new records: `hardware/sockets.tsv` (a real Debian 12 guest) and `reference/sockets.tsv` (`record-sockets.sh`); the generator joins them to the process list (`processes.json`, key `sockets`). Not emulated, declined to the responder: other socket families (`ss -x`, bare `ss -ln`), per-socket details (`-e -i -m -o`), host names no file holds |
| 5 | Temperature 0 | **Tried, 18 Nov; not adopted.** With four requests at once a repeat with the same seed is the same for 147 of 200 rows at temperature 0 and 127 at 0.2; one at a time it is 100 of 100 at either. The difference between repeats comes from the server batching requests, not from sampling. The session's memo and the cache are what make repeats agree ([write-up](experiments/phase-3/llm-bench.md), "The same command twice") |
| 5 | The consistency probe group (`eval/probes/consistency.py`, group `consistency` of `make probe`): a command asked twice in one login and again in a second login answers the same; what a file-changing command reported agrees with what the emulator's commands then see | **Built, 18 Nov; 27 checks, 8 unit tests.** Against the live model its first run found the decoy contradicting itself between logins, from two causes, both fixed (see Findings): the policy's budget counted grants (patch 0022 and the policy), and a failed answer was not remembered for its program (the responder's standings) |
| 5 | Replay of real recordings (`make llm-record`, `eval/recordings/`) | Not started. Needed by CI and the laptop for arm C and demo 3a, not by the lab host, which has the live model |
| 5 | Spike S2's three wrong answers as fixed probes (`s2-*` in `eval/probes/commands.yaml`) | All three answered by the emulator now; `emulator.s2-ss-header` is out of the known-gaps file (18 Nov). 22 more probes hold `getent`, `tty` and `ss` to the reference host |
| 6 | `plant_token`, campaign, learned policy | Not started |
| 7 | Tagger v1 | Not started |
| 8 | Demo 3a, depth comparison, Gate 3 tests 1 to 11 | Not started |
| 9 | Sandbox, Caldera, demo 3b | Not started. No longer blocked: the owner installed the `runsc` and `nvidia` runtimes on the lab host on 17 Nov |

## Waiting on a person

| What | Who | Blocks |
| --- | --- | --- |
| Demo 3's scenarios, written from the brief | The owner, with the content tool | Demo 3a (Gate 3 test 10), demo 3b |
| Review of `decoys/profiles/rendered/REVIEW.md` (12 entries a class now: 5 are new, promoted from the model's answers) and of `rendered/promoted.yaml` (why 15 were left) | The owner | Spec 3.2a step 4 |
| Commit | The owner | Nothing; it is a risk, not a blocker |

## Decisions

| Date | Decision | Why |
| --- | --- | --- |
| 17 Nov | Demo 3's procedures are a third catalogue set, in no split | Both existing sets are frozen by hash |
| 17 Nov | Demo 3's planted credential: account `dbbackup`, in `~/.my.cnf` of the session's account | A conventional path; the scenario needs a fixed contract before `plant_token` exists |
| 17 Nov | The tagger's serving index will hold demo 3's procedures (default, spec section 11) | Rules v2 read `last_tactic` by exact match in that index |
| 17 Nov | The suite compares the decoy with a live reference host (arm R) in one run, from a container on the lab network; it announces documentation-range sources | Timing and behaviour need one vantage point; a lab-range source would look like a simulated actor to the label join |
| 17 Nov | An emulated command may decline options it does not implement; the gate then reports tier `none` | A partial emulation should hand the rest to the responder, not print something a real host would not |
| 17 Nov | The gate's tier is `none` for a program whose file exists and that nothing emulates | It was "emulated", which would have kept such commands from the responder under rules v2. Changes the meaning of `known` for those commands from phase 2's data on |
| 17 Nov | `dpkg` is not emulated until the reference image is rebased | Its database would contradict the process list |
| 17 Nov | The profile mints the decoy's SSH host keys from its seed, in OpenSSH's own file format written by hand | The files `cat` shows must be the keys the server presents; a library's writer puts random numbers in the file, which would break one-seed-one-profile. RSA takes seconds in Python, so minted keys are cached under `build/cache/hostkeys` |
| 17 Nov | Spike S4 is moved after step 5 | It decides D12 and nothing in steps 4 to 8 waits on it |
| 17 Nov | Tier `none` no longer covers a command that is not on the host: that becomes a tier of its own (`absent`), and only `none` (a program that is there, which nothing emulates, or options an emulated command declines) is offered to the responder | "command not found" is the right answer for a program the image does not have, and the emulator already gives it. A model asked instead might print output for a program `which` says is not there |
| 17 Nov | Whether a command is streamed or held is decided by its class, and a held answer carries its stdout in `end` | See Findings: nothing may be shown before the operations are applied |
| 17 Nov | The fork checks operations with code of its own, held to the contract by one shared file of 123 cases (`schema/tests/ops_cases.json`, copied into the patch; a repo test compares the two) | The decoy image does not carry `mirage_schema` or pydantic |
| 17 Nov | The decoy refuses to rename a directory by an answer, and treats a link as not writable by one | The checks look through an overlay by path; moving a subtree in it is where a mistake would hide. An emulated `mv` still does it |
| 17 Nov | Commands whose answer is a function of their input are emulated, not generated: the file commands, `find`, `cut`, `xargs`, checksums and the rest of patch 0017 | A computed answer is right, instant, free and the same every time. The responder is for what cannot be computed |
| 17 Nov | Rules v2 are the stack's default rule set (`POLICY_RULESET`, compose) | Towards a decoy that offers no v2 action they are phase 2's allow-all, and the SSH decoy offers `respond` only while a responder is healthy. With the default `replay` backend and no recording, a `respond` is an abort and the emulator answers |
| 17 Nov | The responder is given a directory of the profile with one file in it (`build/profile/responder/`) | The rest of the profile holds the decoys' passwords and the tokens' values, and the service may hold no secret but its own token |
| 17 Nov | The integration tests drive the whole path with a scripted stand-in for the model server (`mirage_responder.stub`, compose profile `stub`) | It exercises decoy, policy, responder and the `llama` backend's streaming on a machine with no GPU, with answers the tests chose. It is not a model and is never part of a deployment |
| 17 Nov | Shell syntax is its own step (4b), after step 4's fork patches | It does not block the responder path; it does bear on Gate 3's depth test, so it is before step 8 |
| 17 Nov | The shell's syntax work is held to recordings of real bash, not to what I remember of bash | The first unit tests I wrote from memory were wrong in four places (single quotes inside `"${v:-'x'}"`, what a bad substitution discards, `[[ a == ]]`, `declare -A`). Every expectation was then recorded on the reference host, in five batches; each batch was written to find what still differed |
| 17 Nov | `[[ ]]`, `(( ))`, `for ((;;))` and `!` are rewritten, before parsing, into commands with random names made at start-up | Inside them `<`, `&&`, `(` mean something else than in a command, so the grammar cannot read them. The names are never typed, never shown, and the policy is not asked about them |
| 17 Nov | A malformed `[[ ]]` is refused when the line is read, with bash's one message, and nothing of that line runs | That is what bash 5.2 does (recorded); an error at run time would have let the commands before it on the line run |
| 17 Nov | An expansion bash refuses, and an assignment to a read-only variable, drop the rest of their input line: the queue carries a mark at each line's end, and continuations that put state back (a call's variables, a group's redirections) can be unwound without running | Recorded: the next line runs with status 1; inside a sourced file or an `eval` only that text's line is dropped; inside a function the whole calling line is |
| 17 Nov | Arrays stay a known limit; `declare -a` / `-A` succeed and keep the attribute | bash prints nothing for them, and an error bash never prints is a worse tell than a missing feature. The same for options the shell records and does not act on (`set -e`, `pipefail`, `nullglob`): `set -o` and `shopt` show them as set |
| 17 Nov | A login shell's functions are those its own `/etc/profile.d/*.sh` define, read when first needed | On the reference host `set` ends with gawk's six; the decoy's filesystem has the same file. Read lazily so that a login costs nothing |
| 17 Nov | Arithmetic errors use bash 5.2's wording ("syntax error: operand expected"), not 5.3's ("arithmetic syntax error") that upstream Cowrie had | The decoy says it is 5.2.15 |
| 17 Nov | The model is served on the Linux host, in a container, never on the laptop | The owner said so ("use the linux machine for the model") when I started a server on the laptop. It is also what the spec's topology has: the model server on an internal network with no route out |
| 17 Nov | The server runs with reasoning off, flash attention on, four slots sharing a context of 16,384 tokens | Spike S2's settings; with reasoning on, a thinking model spends its token budget before the answer starts |
| 17 Nov | The bench logs in afresh for each command and announces a new documentation address each time; each pass starts from an empty cache (the cache file on the container's tmpfs) | A login is a session with a token budget and a source has one for the day: the bench is not an attacker to slow down. And what is timed must be the model, not the cache; the cache's own time is taken from a second request in the same login |
| 17 Nov | The bench's command list leaves out what the reference image does not have (python3, file, strings, hexdump, column, crontab: checked on the reference host) and what a container answers differently from the persona (systemctl, ip, uname -r) | The decoy calls the first kind not found, correctly, and never asks the model; for the second there is no truth to hold an answer to |
| 17 Nov | The live injection check runs inside the responder's container as a process of its own, not over the network | Only the SSH decoy may reach the responder's port (a containment test says so), and many hostile inputs name programs the decoy would call not found and never send on |
| 17 Nov | The smaller model for the comparison is the same family one size down (Qwen3.5-4B, same quantisation, same publisher) | So that the comparison is of size and nothing else |
| 17 Nov | A session's own answers are kept for that session, by command and state fingerprint, when they changed nothing | The cache keeps only two classes; a model asked again does not repeat itself; and after an answer that changed something the fingerprint is another, so nothing stale can be served |
| 17 Nov | A promoted command becomes an entry only if its answer is a fact of the image. Left out, each with its reason in `promoted.yaml`: `getent` (a function of the deployment's own files), `chage -l USER` and `lastlog` (the deployment's accounts and the session's own login), `locale` (the session's variables, which a client may send), `dpkg` and `apt-cache` (the earlier decision: not from the container's database until the image is rebased) | The record container answered `chage -l caleb` with "user does not exist" and `lastlog -u root` with "Never logged in": true of it, false of the decoy. A fixed text that contradicts the decoy's own files is worse than a model's guess |
| 17 Nov | The record step runs each command with no locale variable set, as a session over SSH has none | It set `LC_ALL=C`, which `locale` prints |
| 17 Nov | Fine-tuning is a plain 16-bit LoRA of the 4B model (rank 16, all projection layers, loss on the answer only, the model's own chat template with thinking off), merged and converted to the Q4_K_M file the stack serves | Unsloth's Qwen3.5 guide advises against 4-bit training for this family; the answer is 60 tokens after a prompt of 880, so the loss must be on the answer; a wrong template is the commonest cause of a worse exported model |
| 17 Nov | Training runs on a Kaggle T4 (16 GB), everything else on the lab host. The owner approved the upload ("Yes, use Kaggle; first do small batches and short time test to make sure that everything works") | 16-bit LoRA of the 4B needs about 10 GB by Unsloth's figure and the lab host's card has 8; the 9B needs 22 and fits nowhere free. What is uploaded: the training rows, as a private dataset, and the training script; nothing of `.env`, no attacker data |
| 17 Nov | No row holds a password hash or a private key, the labelling host's own included | The set leaves the machine, and a model shown a hash learns to print one |
| 17 Nov | The training script is a plain loop on torch, transformers and peft, with no trainer library | Fewer versions to agree with each other on a machine whose image I cannot see beforehand; the trial is what tells |
| 17 Nov | The training answers are recorded from the reference host, never written by a model; only the commands and the identities are generated | The model's job is to be indistinguishable from a real server. The owner asked what is synthetic: the questions, not the answers |
| 17 Nov | Held out of training: a tenth of whole programs, a tenth of the invocations of the rest, and every command of the bench. The bar for adopting a tuned model: more answers that are the real host's than the stock 9B gives, on the held-out sets | A model that has seen the test is not measured by it |
| 17 Nov | Step 4b's widening stops with patch 0020: what the live probes still find is fixed if it is small, and listed as a known gap if not | The step took most of a day against a plan of an hour; some of what was fixed (`shopt`'s table, `trap -l`, function printing) is rarely run. The user asked what was taking so long, and was right to |
| 17 Nov | The process list comes from the hardware class's record plus the reference image's record of the services; command lines of services are their systemd units' | No invented processes; the reference container starts services by hand |
| 18 Nov | **No more fine-tuning; the effort goes to deterministic answers.** The model stays as the last rung only, served by the stock 9B; the tuned adapter is kept and not used; no second training round. What the tail gets wrong moves to the emulator (code that computes from the session's state) or the render library (recorded real output). Whether the model rung stays on at all is decided by the depth comparison at Gate 3 | The owner asked, on seeing the result, whether tuning a model, or a model at all, is right, and proposed matching inputs to real outputs. Most of that is what the numbers say: the emulator already answers about 98% of the corpus sample's commands, exactly; the model, stock or tuned, gives the real host's answer for about one in four of the rest. A pattern alone cannot answer what depends on the session (`ss` must agree with `ps`), which is why it is the emulator and not a table of outputs |

## Findings

- 17 Nov. **The sessioniser failed on every batch that touched a large actor, and left
  sessions with two actor IDs.** Found by `make itest` (demo 2 failed, reproducibly). The lab
  had run for three days with one seed, so one planted credential had been read by hundreds
  of sessions; each use of it tied its session to all of them; the actor grew to thousands of
  sessions. From then on a batch that touched it asked ClickHouse about all of them in one
  URL, which no longer fitted (`httpx.InvalidURL`). The batch failed after its links were
  written, was delivered again with nothing left to link, and the summaries kept their old
  actor IDs. Four fixes (`pipeline/`): query parameters travel in a form body, and a caller
  with a longer list is refused before anything is sent; summaries are recomputed in parts
  that never cut a logical session in two (the old chunking could have written half
  summaries); a merge recomputes only the side whose actor ID changes, not the whole actor;
  and whenever state is rebuilt from the store, summaries whose actor ID disagrees with the
  stored links are rewritten. On the lab host the last one repaired **764 summaries** at its
  first start. Demo 2 passes again. *Not changed, and a known cost:* each use of a credential
  still links to every earlier exposure of it, so links grow with the square of lab runs
  (55,060 on the lab host). A long-lived deployment wants a window on that.
- 17 Nov. **Two panels of the actors dashboard had no row limit** and timed out on the same
  large actor (`test_dashboards`). They show the 1,000 most recent sessions and the 1,000
  strongest links now.
- 17 Nov. **`make itest` on the lab host after those fixes: 58 of 59, then the dashboard
  test alone 14 of 14.** A full run with everything of step 4 is still owed.
- 17 Nov. **A held answer must arrive whole.** While writing the decoy's applier: the
  responder sent a state-changing answer's lines as `out` records and its operations in
  `end`. A decoy that printed the lines and then refused the operations would have shown an
  answer whose effects never happened. A command that may change anything is now sent with no
  `out` record at all: `end` carries its stdout with its operations, and the decoy applies
  first. Streaming is for commands that only read, which never carry operations.
- 17 Nov. **The journal's replay test found that `cp` changed the tree without reporting
  it.** Stock Cowrie's `cp` copied nodes directly; `rmdir` went round the filesystem's own
  mutator; neither produced a `cowrie.fs.change`, so phase 2's file-activity data never
  contained them. Looking further at the commands that change the tree: `mkdir -p x` made a
  directory called `-p`; `echo x > /tmp` **replaced the directory `/tmp` with a file**;
  `chown` did nothing; there was no `ln`; `find` knew three tests and exited 0 for a missing
  path; `cut -c1-10` did not cut; and a user who was not root could write anywhere. The probe
  suite had not seen any of it: its list had three commands that write and none with an
  option. Added 56 probes of file commands (40 failed on the image as it was), recorded what
  the reference host answers to 117 command lines, and rewrote the commands against that
  recording. The recording is in the fork's tests; 105 of its lines are compared byte for
  byte and all pass.
- 17 Nov. **A probe of mine deleted `/tmp` on the reference container** (`rmdir -p
  /tmp/pf/a` climbs to `/tmp` once it is empty). The container is thrown away after each run,
  and the affected records were taken again; the committed probe list uses relative paths for
  that case. Worth knowing: the reference host really runs every probe.
- 17 Nov. **The emulated shell is far from bash.** Recorded 27 lines of ordinary shell
  syntax on the reference host; 6 answer the same on the decoy. `${X:-default}` is a *syntax
  error*, as is any array; `[[ ]]`, `(( ))`, `let`, `local`, `return`, `shift`, `readonly`,
  `declare`, `eval`, `source`, `builtin`, `pushd` are "command not found"; brace expansion,
  `$'...'`, `~user`, `!` negation, `until`, C-style `for`, `&`, `wait`, `trap`, `alias`,
  `set -x` and `PIPESTATUS` are missing. A responder cannot cover this: the shell fails
  before any command runs. The recording is kept (scratchpad `ref/mirage_shell_reference.jsonl`,
  remade by `ref/capture.sh` with `ref/shell_commands.txt`). It is its own piece of work
  (4b above), and the depth test's held-out scenarios lean on it.
- 17 Nov. **The decoy's first command after a start was never offered to the responder.** The
  health checks that decide `supports` began at the first command, so that command was sent
  with `respond` unlisted. Found by the first end-to-end run (the test's command was the
  decoy's first). They begin when the SSH service starts.
- 17 Nov. **A timing check on a line of five commands measures how many commands it has.**
  Every command costs the decoy a round trip to the policy service (about 2 ms on the lab
  host). `timing.f-cp` failed once in three suite runs on a busy host (43.7 ms against 10.2;
  22 ms measured alone) and passed alone. The timed copy is a line of two commands now; the
  five-command lines are still compared for what they print.
- 17 Nov. **`md5sum /bin/ls` on the decoy is the reference host's own.** The image carries
  the real checksums of 5,974 files whose bytes the tree does not hold; the probe compares
  `md5sum`, `sha1sum` and `sha256sum` of real programs with the live reference host and they
  agree.
- 17 Nov. **Stock Cowrie's fixed texts are tells of their own.** `getconf` answered "32" to
  everything (word size, page size, processor count) on a host that says it is amd64; it is
  emulated now. `top` prints a `vim` error (`E82: Cannot allocate any buffer`), `killall`
  prints "no process found" whatever it is given. Found when an integration test expected the
  responder to answer `getconf` and the emulator answered first. The rest of the fixed texts
  go on step 4b's list.
- 17 Nov. **The checksum programs need real bytes.** The emulated tree holds names and sizes
  of the image's programs, not their contents, so `md5sum /bin/ls` could only invent an
  answer, and Debian's real checksum is public. They answer from a table of the image's real
  checksums where the deployment has one (`[mirage] file_hashes`, to be written by
  `build_fs.py`), hash what a session wrote, and decline otherwise.
- 17 Nov. **Stock Cowrie's shell did not run a background command: `echo hi &` printed
  "hi &".** The `&` reached the command as an argument (`sleep 5 &` was "invalid time
  interval"). Found by a probe added for step 4b, not by the syntax work itself. It is what
  attackers' one-liners end with. Fixed in patch 0020: the `&` ends the command, which runs
  to its end where it stands; `$!`, `wait PID` and a login shell's job lines are bash's. A
  command that really takes time (`sleep 30 &`) still holds the shell for that time.
- 17 Nov. **What I remembered of bash was wrong often enough to matter.** Of the first 35
  unit tests written from memory, four asserted things bash does not do. Recording every
  expectation on the reference host (six batches, 234 lines kept) then found about forty
  differences in the shell that no test from memory would have: `set` listing 7 variables
  where bash lists 39; a malformed `[[ ]]` letting the rest of its line run; a bad
  substitution not dropping its line; errors inside a function defined in a `-c` string
  labelled "bash:" where bash 5.2 says "environment:"; `$(( 1 << 4 ))` read as a
  here-document; arithmetic errors in bash 5.3's words on a host that says 5.2.
- 17 Nov. **Which errors end what, as recorded** (bash 5.2, a shell that is not
  interactive): a syntax error or a malformed `[[ ]]` ends the shell at that line, nothing
  of the line having run; a refused expansion (`${v!x}`, `$((1/0))`) or an assignment to a
  read-only variable drops the rest of the line and goes on with the next, status 1;
  `${v:?}` ends the shell with status 127; inside a sourced file or an `eval` the drop
  stops at that text's own line; in a pipeline stage it stops at the stage. A login shell
  drops the line and prompts again in every case.
- 17 Nov. **A slot that has not read the prompt cannot answer in time.** The first live
  sample: 1 of 8 answers came from the model. Reading the 900-token prompt takes a cold slot
  1.8 s on this GPU, the first line may take 1.5 s, and the server has four slots, so the
  first answer on each was a fallback. The responder now has every slot read the fixed part
  once, all at the same moment, and is not healthy until they have; the same eight commands
  were then all answered, first line in 0.5 to 0.7 s.
- 17 Nov. **The model is fast enough and right one time in five.** [The bench](experiments/phase-3/llm-bench.md):
  of 58 answers, 32 have the real answer's shape and 13 are the real answer. Three causes
  were in our prompt and are fixed (they raised how many commands get an answer, from 42 of 59
  to 58 of 63, not how many are right). What is left is what a 9B model knows of Debian's
  tools: versions it was not given, formats it half remembers, sums it cannot compute.
  27 of 31 stateless answers were wrong, and every one of those commands could be recorded
  from the reference container instead.
- 17 Nov. **The cache makes a wrong answer permanent, and the model does not repeat itself.**
  `locale` was answered wrongly once and served from the cache thereafter. And of 20
  commands sent to the model twice with the same seed, 8 came back different. Both are tells
  of their own; neither is fixed yet.
- 17 Nov. **Recording into the repository's folder failed silently into fallbacks.** The
  service's user may not write there. Recordings go to the responder's own volume now and are
  copied out, and a recording that cannot be written no longer costs the session its answer.
- 17 Nov. **Fine-tuning, as researched** (a sub-agent's report, sources checked by it, 17 Nov):
  Unsloth's Qwen3.5 guide (unsloth.ai/docs/models/qwen3.5/fine-tune) says transformers v5 is
  required, 4-bit training is not recommended for the family, and 16-bit LoRA takes 10 GB
  for the 4B and 22 GB for the 9B. Kaggle (kaggle.com/docs/notebooks, /docs/efficient-gpu-usage):
  T4 x2 or P100, about 30 GPU hours a week, 12 hours a session, 20 GB of saved output; a
  notebook can be pushed and run through the API with a private dataset attached; its TPU
  page covers TensorFlow only. TRL's `assistant_only_loss` and Unsloth's
  `train_on_responses_only` put the loss on the answer. Export: merge, llama.cpp's
  `convert_hf_to_gguf.py`, `llama-quantize`; a pre-tokenizer bug with a tuned Qwen3.5-4B was
  reported in May 2026 and said to be fixed, so the untouched base is converted first as a
  control. Dataset size: over 1,000 rows preferable; 1,000 curated have matched 50,000
  synthetic. Not verified by anyone: memory and speed for this model at our prompt length.
- 17 Nov. **What training costs on a T4, measured**: 3.7 s a row with gradient checkpointing,
  so 1,500 rows for two epochs is about three hours, inside one 12-hour session and a
  tenth of the week's quota. Memory leaves 2.7 GB spare: no room for a batch of two.
- 17 Nov. **A label in two is a row.** Of the first 2,163 labels, 677 said what the same
  program had already said twice (a wrong option gets "Try '--help'" from most programs),
  167 were longer than an answer may be, 68 differed between runs, 58 held a time of day,
  41 changed the host. The whole run of 4,655 will give about 2,300 rows, some 1,500 of them
  for training: under the 3,000 I told the owner. More rows need more kinds of command
  (more seeds; commands that change files), not more options of the same programs.
- 17 Nov. **How the tuning set is made** (`eval/tune/`). Candidates: hand-written seeds, and
  for every program the decoy does not emulate and that is safe to run, its `--version`, its
  `--help` when short, an option it does not have, and each option its own help lists, alone
  and with a small file. Labels: each candidate three times as root on a throwaway reference
  container with no network; a command that changes a watched file or leaves something
  behind is marked and the host replaced (4 of 80 in the trial: `pwck -s`, `split -x`,
  `mariadb-access`). With each label goes the file view the decoy would send, read from the
  same host. Rows: the responder's own prompt code, one of four identities, the labelling
  host's name replaced; left out are answers that name the container (`runcon` printed
  "docker-default"), hold a time of day, differ between runs, or are longer than an answer
  may be; a program gets at most 24 rows and no answer more than twice. Splits by hash of
  the program. To rebuild: `python -m eval.tune.candidates`, `.label`, `.build` (their
  docstrings give the arguments; the help texts and the decoy's command list they read are
  in `~/mirage-scratch/tune/` on the lab host, made by `collect_help.sh` and
  `list_emulated.py` there, which are not in the repository yet).
- 17 Nov. **Most "stateless" commands are not stateless about the deployment.** The first
  promotion run made 20 entries from the model's cached answers; reading them against the
  decoy's own files left 5. `getent`, `chage`, `lastlog` answer from the host's accounts and
  logins, `locale` from the session's variables. The class table calls them stateless
  because they do not depend on what the session *did*; a fixed text needs more than that:
  an answer that is the image's alone. Those commands are the emulator's.
- 17 Nov. **An integration test raced the decoy's health check.** It stopped the model
  server and ran one command, expecting a recorded fallback. But the responder reports
  unhealthy while its model server is down, and the decoy checks every 5 s, so in about one
  full run in two the decoy had already stopped asking: the session saw the same emulator
  answer and no fallback was recorded. The test now kills the server just after a check is
  known to have passed, and tries again when the policy was not asked for `respond`. The
  product was right both ways; the next test covers the other way.
- 17 Nov. **A parse costs milliseconds, and a `[[ ]]` made eight of them.** The first live
  timing of a line with two `[[ ]]` was 36.8 ms against the reference's 4.8: each operand
  was parsed as a word. An operand with nothing to expand is now its own text, and parsed
  words are kept for the process; the same line then passed the timing check.
- 17 Nov. **Known limits of the shell after patch 0020**: arrays; file descriptors opened
  by `exec`, `PIPESTATUS`, and the options that change execution (`set -e`, `pipefail`,
  `set -x`, `nullglob`: recorded and shown, not acted on); history expansion in a login
  shell (`!x` is "event not found" in bash); a background command that takes real time;
  `$BASHPID` in a subshell; the message for a quote left open inside `"${...}"`.

- 17 Nov. The render library moves the dev-half depth result from 29 to 39 of 139 steps and
  covers 0 of the 55 wrongly answered commands in the held-out half. Gate 3's depth test will
  be decided by state and shell behaviour, not by the library.
- 17 Nov. Stock Cowrie writes an exec channel's stderr as stdout (fixed, patch 0010).

- 17 Nov. **The decoy takes 200 to 280 ms to answer `ssh host command`; the real host takes 4
  to 10 ms.** Found by the suite's timing group on its first run. Cause: with a contents
  directory configured, the fork (upstream code) deep-copies the whole filesystem tree and
  walks that directory for every session, and every exec request is a session. Inside
  Cowrie the command itself takes 4 ms. Fix: patch 0011 marks the shared tree once.
- 17 Nov. The suite's first run: transport 11 of 23 checks fail (the algorithm lists, the
  `SSH-2.2` reply, error line endings); emulator 17 of 79 fail (`ls` with no terminal prints
  columns, no glob expansion, `id -u`, `env`, `wc FILE`, `who`, `ps` headers, and `sort`,
  `stat`, `dpkg`, `type`, `command` missing).
- 17 Nov. **The gate's `tier` called a program the emulator does not have "emulated"**
  whenever its file exists in the decoy's filesystem (`stat`, `sort`, `dpkg`), because the
  lookup returns a stand-in that prints "cannot execute binary file". Under rules v2 those
  would never have reached the responder. Fixed with the emulator patches: such a program is
  tier `none`.
- 17 Nov. The reference image has no cron, so `crontab -l` is "command not found" there
  while the decoy answers it. Listed as a known gap; the fix is to give the image cron.

- 17 Nov. **Third suite run, after patches 0011 to 0014: 227 of 240 checks pass.** Timing:
  all 11 pass; the decoy answers in 8 to 25 ms (was 200 to 280), the real host in 5 to 14.
  The three causes were: the per-session tree copy and directory walk (200 ms), Nagle with
  delayed ACK on every connection without a pty (40 ms), and a whole-tree copy on a
  session's first write (137 ms for 50,712 nodes; now only the path written is copied).
  Emulator: 120 of 126; left are `ps` (3), `dpkg` (2) and `crontab -l` (the reference image
  has no cron). Transport: 17 of 23; left are the algorithm lists and HASSH, which only an
  OpenSSH front end (spike S4) can change.
- 17 Nov. Stock Cowrie's `createfs` records where a symbolic link ends up, not what it says:
  `/bin -> /usr/bin` where a real host shows `/bin -> usr/bin`. The builder now gives 596
  links their real text, and the fork resolves a relative link from its own directory
  (upstream resolved every one from the root).
- 17 Nov. The decoy told every session it was `192.168.0.1`: Cowrie's fallback when it finds
  no route out, which a contained decoy never has. The profile's address is now set.

- 17 Nov. **Stock Cowrie's exec sessions end because it answers out of order.** With no
  policy round trip, the command runs inside the exec request, so output, exit status and
  the channel's close go out before the reply to the request. paramiko reports "Channel
  closed". The fleet group found it on a decoy with the gate off; patch 0016 starts the
  command on the next turn. This settles the depth baseline's open question about arm A.
- 17 Nov. **The reference image is a container image and it shows.** No init system, kernel
  package or cron in the decoy's files and package list, while its process list (now from the
  hardware class's record of a booted machine) shows systemd. `dpkg` is deliberately not
  emulated until the image is rebased; it and `crontab -l` are listed gaps.
- 17 Nov. The fork's CI job, rehearsed on a clean clone of v3.1.6 on the lab host
  (`~/mirage-scratch/ci-fork.sh`): 1,804 tests pass with patches 0001 to 0016. This closes
  the item left open since patches 0009 and 0010.

- 17 Nov. **The fleet group's first run found three things.** The decoy's host public key
  files were empty (the image's sizes, no contents) while the server presented keys Cowrie
  made up at start; `/proc/sys/kernel/random/boot_id` did not exist; `ip addr` is not
  answered (left to the responder: the inventory has no count for it). Fixed: the profile
  mints the three host keys from its seed (`mirage_profiles.hostkeys`), the server serves
  from the very files `cat` shows, and five files of `/proc/sys/kernel` are written from
  facts the profile already holds. The rest of `/proc/sys` is absent (the classes did not
  record it).

- 17 Nov. **Fourth suite run, with host keys and the fleet group: 254 pass, 0 fail, 10 known
  gaps, 0 stale** (264 checks). Unit tests: 848 pass. `make itest` on the lab host was
  started after it (log `build/logs/itest-step3.log`).

### `ss`, `getent`, `tty`: what the recordings showed (18 Nov)

- **The reference container is not a good witness for `ss`.** It lists Docker's own resolver
  (`127.0.0.11`, a five-digit port, which widens a column on every line), and root there may
  not read another user's `/proc/PID/fd`, so MariaDB, Redis and nginx's workers are shown
  with no process. Two records replace it. A real guest (the hardware capture, booted once
  more with `ss` in its list) gives the machine's own sockets: the resolver's five, the DHCP
  client's, sshd's. The reference services' sockets are recorded from a privileged exec
  (`reference/record-sockets.sh`), which shows what a real host's root sees.
- **Holders are listed newest first** (`("nginx",pid=37,...),...,("nginx",pid=22,...)`, the
  master last). Recorded, not assumed.
- **The table's layout is one rule** (iproute2's `render_calc_width`): each column as wide as
  its longest cell; on a terminal the spare width is shared out among the columns of each
  screen line, the remainder going to the rightmost. Written from that rule, the decoy's
  output matched all 15 recorded command lines at the first comparison, at 60, 80, 100 and
  200 columns. The header's spacing therefore differs between hosts with different
  sockets, and `ss -tlnp | head -1` cannot be compared exactly with the container: the probe
  compares its words, and the rows both hosts have are compared exactly.
- **A state asked for by name drops the State column** (`ss -tn state established`); `-l`
  does not (it is two states).
- **`getent hosts` lists the IPv6 loopback as `127.0.0.1`** and passes over every other IPv6
  line; asked for `localhost` it gives `::1`. Both are the files backend's ways and both are
  emulated. `ahosts localhost` on a real guest gives `::1` then `127.0.0.1`; the container
  gives `127.0.0.1` twice (it has no IPv6 address); the decoy answers as the guest.
- **The decoy's tree has no `/etc/services`, `/etc/protocols` or `/etc/networks`** (the
  reference image has no `netbase`; every installed Debian has). So `getent services ssh`
  finds nothing and `ss -tl` prints port numbers where a real guest prints `ssh` and
  `domain`. The commands read the tree and will be right when the tree is: one more item
  for the reference image's rebase.
- **The emulator's list behind the render inventory was two days stale**: 43 commands the
  decoy has had since patches 0017 to 0021 were still counted as missing. Regenerated from
  the image; the inventory went from 81 wrongly answered lab commands to 69, and the
  library from 12 entries a class to 11 (`ss -tln` is the emulator's now).
- Found in passing and parked: the emulator's `cat` has no `-A`. The session's own row in
  `ss -s` adds one socket to the recorded total; a real sshd session holds a few more.
  Port 5355 (the resolver's) is listed as on a real guest and is not open from outside.

### The decoy contradicted itself between logins (18 Nov, found by the consistency group)

The first run of the consistency group against the live model: `redis-cli --version` and
`cksum /etc/hostname` "cannot execute binary file" in one login and answer in the next.
Two causes.

1. **The policy's budget counted grants, not tokens.** It may grant a session 3,000 output
   tokens and calls nothing to learn what was spent, so it counted each `respond` as the
   answer's ceiling, 400. The median answer uses about 50 and a cached one none: a session
   was cut off from the responder after seven answers, whatever they cost, and the next
   unknown program was the emulator's "cannot execute". The same cut-off would have capped
   what arm C can show in the depth comparison and starved the exploration of `respond`
   in step 6. **Fixed:** the decoy now tells the gate what the session's answers have used
   (`respond_spent`, fork patch 0022; a new optional field of the decide request), and the
   policy charges that, to the session and to its source. A decoy that does not report is
   charged its grants, as before. The responder still enforces the real limits itself.
2. **A failed answer was forgotten.** An answer that misses its deadline (or is cut at the
   token limit, or refused by a check) leaves the emulator's fallback, which says the
   program itself cannot run. The next request for that program then succeeded.
   **Fixed in the responder:** the first thing a deployment says about a program decides
   where it stands (`cache.STANDINGS`). After a failure with nothing shown, the program is
   refused for everyone for a week (`RESPONDER_REFUSAL_S`); after a success it is never
   refused. `make llm-standings` lists them, `make llm-forgive` clears them (after a model
   or prompt change). `replay` keeps none: a recording is an answer to one exact request.

3. **Every channel of a login had its own file system** (stock Cowrie). A directory made
   by one exec request was gone for the next request of the same connection, and a file
   put by SFTP was never there for the shell. **Fixed in fork patch 0023:** the file system
   is made once for a connection, and the change journal, how far the responder has been
   sent it, and the count of tokens belong to the connection too. Another connection still
   starts from the image: what a source made is not there when it logs in again (a known
   tell of every Cowrie; holding it for the source, as a changed password is held, is the
   next step and is not built).
4. **The model reported file changes it had not made.** With the budget fixed the
   round-trip checks reached the model, and one of them failed in every run, a different
   one each time: `truncate` made a directory, `install` made nothing, each with exit
   status 0. **Fixed by taking the commands away from the model (fork patch 0024):**
   `unlink`, `link`, `truncate`, `install` and `shred` are the emulator's, held to 69
   recorded command lines (63 compared byte for byte in the fork's tests, 6 that need the
   reference image's own files or `od` covered by direct tests).
5. **Stock `cat` was not cat** (found while checking the above): it ended every file with
   a newline whether it had one (`printf abc > f; cat f | wc -c` said 4), took `-A -b -E
   -s -T -v` and did nothing, numbered with two spaces for cat's tab, and read any file
   for any user. Replaced in the same patch, from 12 recorded lines; a file the user may
   not read is refused (the first of step 4b's "stock readers" to enforce modes).

What is left, and known: a program that answered first and fails later is told "cannot
execute" that once (nothing truthful is cheaper), and so is every new program once a
session has really used its 3,000 tokens. Both are rare now and both are tells.

## Plan for step 4 (written before starting, 17 Nov)

In this order, each with tests before the next:

1. **Schema** (`schema/`): contract v2 in `mirage_schema.policy` (actions `respond`,
   `plant_token`, `escalate`; `supports`; `tier`; `budget`, `ops`, `sandbox` on the decision);
   the state operations a model or the policy may propose (`mirage_schema.ops`: the eleven
   kinds, validation, caps); the responder API's records (`mirage_schema.respond`).
2. **Policy** (`policy/`): rule conditions on the context (tier, inputs so far, last tactic,
   actor class, token planted); a v2 rule set; the mask additions of spec 3.3; never an
   action outside `supports`; `respond` carries a budget. `plant_token`'s reserve and the
   classifier in the policy process (R15) belong to step 6 and are stubbed by the mask
   (masked until a reserve exists).
3. **Responder** (`responder/`, new package and image): `/v1/respond` over newline-delimited
   JSON; the state manager; command classes; the output filter; operation validation;
   budgets; the SQLite cache; the `replay` backend and the recording format; its record log.
4. **Fork**: the change journal, the applier, the `respond` client (streams lines, keeps the
   placeholder, Ctrl-C), a credential change that holds for its source, health checks that
   decide `supports`.
5. **Together** on the lab host: compose services and networks (`mirage_llm`), containment
   test extended, Gate 3 tests 1, 4 and 5 as far as `replay` allows.

## Working notes (for picking the work up again)

- **The Mac's scratch folder does not survive a restart** (it was emptied on 18 Nov). The
  fork's working copy is rebuilt from the repository: `tools/fork-worktree.sh DEST
  [SOURCE]` (one commit a patch, branch `mirage`; a lab host's clean clone works as SOURCE
  and needs no download). Recordings of the reference host are on the lab host
  (`~/mirage-scratch/out/`), the tuned adapter and the held-out scores too
  (`~/mirage/data/models/adapter-v1/`, `~/mirage/build/tune/scores/`).
- The showcase's public link has been open since the morning of 18 Nov (the owner's). A
  `make up` on the lab host restarts the decoy the console talks to: a visitor's terminal
  reconnects.

- The suite runs inside the lab network: `make probe [PROBE_ARGS="--groups emulator --samples 5"]`
  on the lab host; `make probe-report` prints the last JSON report. It brings arm R up and
  removes it.
- What the real host answers to about 140 ordinary commands is recorded in the scratchpad
  (`ref/ref.jsonl`, with `ref/show.py PREFIX`) and on the lab host
  (`~/mirage-scratch/out/ref.jsonl`). It is the model for the emulator fixes. It is not in
  the repository; `~/mirage-scratch/ref_capture.py` and `ref_commands.txt` remake it.
- Fork tests: `rsync -a --delete src/ abishai@192.168.29.130:mirage-scratch/cowrie-src/`, copy the
  list of changed files to `~/mirage-scratch/changed.txt`, then `bash ~/mirage-scratch/forktest.sh
  cowrie.test.<module>` (or `discover -s src` for everything; 18 failures there are the
  deployment image's own, see the memory note).
- Hardware classes hold a real booted Debian 12 machine's `ps aux` and `ps -ef` (87 lines).
  The decoy's process list is to be built from that record plus the profile's services.
- What the reference host answers to file commands and shell syntax is recorded with
  `bash ~/mirage-scratch/capture.sh COMMANDS_FILE OUT_NAME` on the lab host (it starts arm R,
  runs `ref_capture.py` in the probe image, stops arm R). The command lists are in the
  scratchpad (`ref/file_commands*.txt`, `ref/shell_commands.txt`). The file recording is in
  the fork (`src/cowrie/test/mirage_file_reference.jsonl`) and so in patch 0017.
- `bash ~/mirage-scratch/time_cmds.sh lab-edge:2222 'cmd' ['cmd' ...]` on the lab host gives
  the median time of single command lines on the decoy (twelve exec requests each).
- The respond tests bring up a scripted model server themselves (`--profile stub`) and put
  the responder back on `replay` afterwards. To drive it by hand:
  `RESPONDER_BACKEND=llama-dev RESPONDER_LLM_URL=http://llm-stub:8080 docker compose --env-file
  .env -f compose/docker-compose.yml --profile stub up -d llm-stub responder`.
- The fork's reference test runs each recorded line through `run_exec` (an exec channel, as
  the recording was made) and compares stdout and stderr. Lines that read the image's own
  files are skipped there, by a list with reasons; the probe suite covers those live.
- Shell recordings: `ref/shell_commands{,2,3,4,5}.txt` in the scratchpad (one line each, `<NL>`
  for a newline inside a line), recorded with `capture.sh`; `ref/merge_ref.py`-style merge
  (`merge_ref.py` in the scratchpad) adds the lines whose answer does not depend on the host
  to `src/cowrie/test/mirage_shell_reference.jsonl`. An interactive login shell is recorded
  with `bash ~/mirage-scratch/capture_i.sh COMMANDS_FILE OUT_NAME` (`ref_shell.py`).
- `adhoc.sh FILE` in the scratchpad runs lines (`.txt`) through the emulated shell inside the
  decoy image and prints what it says, or compares a recording (`.jsonl`) and prints only
  the differences. It is how each fix was checked before the whole suite was run.
- Fork working copy: scratchpad `cowrie-dev`, branch `mirage`, one commit a patch. Export
  with `git format-patch -N --zero-commit -o decoys/ssh/patches --start-number K <base>`,
  then set line 2 of each new patch to `From: MIRAGE <noreply@anthropic.com>`.

## Log

- **17 Nov.** Render library, serving patch 0009, patch 0010, live probe (32 of 32 on the lab
  host). Demo 3's brief, the demo catalogue set in the lint and the split check. 698 unit
  tests pass, lint clean. Context file started.
- **17 Nov, later.** Step 4, service side: the responder package and its tests, the
  injection set, contract additions (`End.stdout`, strict integers in operations, the shared
  cases). The pipeline's sessioniser and the actors dashboard, after `make itest` found them
  failing on three days of lab data. Fork patch 0017 (state, and the file commands). Unit
  tests: 1,154 before the last additions to the schema and responder; lint clean. Nothing is
  committed.
- **17 Nov, evening.** Step 4 is built end to end and measured on the lab host: fork patches
  0018 and 0019, the repository side (mappings, Vector, responder image, two networks, rules
  v2 as default, checksum table), the end-to-end tests. `make itest` 74 of 74; `make probe`
  331 pass, 0 fail, 10 known gaps. Unit tests 1,297. Next: step 4b (shell syntax, read
  permissions, stock fixed texts), then step 5 (the live model). Nothing is committed.
- **17 Nov, night.** Step 4b's shell work: fork patch 0020 ("the shell reads bash"), held
  to 234 recorded lines of real bash (229 the same, 5 named gaps), 64 new live probes.
  On the lab host: fork tests in the image 1,968 with none failing but the image's own 18;
  the series on a clean clone 1,968 pass; `make probe` **396 pass, 0 fail, 10 known gaps**;
  unit tests 1,456. `make itest`: 72 of 74 in a run made while the host was pulling the model
  server's image and receiving the model, then 73 of 74 in a quiet run. The one that failed
  both times, `test_with_the_model_server_stopped...`, was a race in the test itself (see
  Findings); rewritten, it passed three runs of three, and a whole quiet run later that
  evening was 74 of 74. The other two items of 4b (read permission for a user who is not root in
  the stock readers; stock fixed texts) are not started and stay on the list. Next: step 5
  (the live model). Nothing is committed.
- **17 Nov, late.** Step 5 begun on the lab host's GPU, after the owner ran the root script:
  the model server in the stack, the warm-up, the bench (three full runs), two prompt
  revisions, the injection set live, recordings. Results in
  `docs/experiments/phase-3/llm-bench.md`. Unit tests 1,463, lint clean. The model server
  is left running (`make llm-down` stops it and puts the responder back on recorded answers).
  Not done in step 5: the model comparison, eviction and promotion, repeats that agree, the
  consistency probes. Then, with the responder back on recorded answers for the length of
  the runs: **`make itest` 74 of 74** (a whole quiet run, with the rewritten test), and
  **`make probe` 398 pass, 1 fail, 10 known gaps**. The one failure is new and real: of spike
  S2's three wrong answers, written as probes this evening, `ss -tlnp` is still wrong (the
  library has `ss -tln`, nothing emulates `ss`, the decoy falls back). It is in the
  known-gaps file with its owner, and Gate 3's test 7 needs it closed, not listed. The other
  two (`cat /etc/shadow` as root, `which` with several names) pass. The responder is on the
  live model again. Nothing is committed.
- **18 Nov, early.** Step 5's emulator items, while the fine-tuning run trains on Kaggle
  (started 23:13 on the 17th, about three hours). Fork patch 0021, "getent, tty and ss": new
  module `mirage_netutils.py`, 25 tests, the fork suite 1,993 tests with only the image's
  own 18 failures. Two new records behind `ss` (a real guest's sockets, the reference
  services' sockets with their holders) and the generator's `sockets` key; see Findings.
  The render library's emulator list regenerated from the image (`make render-emulated`,
  new), inventory and library rebuilt, `ss -tln` out of the library, `ss -ant` out of the
  exclusions. The model bench's list is 55 commands now (eight went to the emulator).
  Deployed to the lab host and tried live: `ss -tnp` names the session's own sshd by the
  number `ps -ef` gives it. **`make probe`: 429 pass, 2 fail, 10 known gaps on the first
  run; both failures were faults in two of the new probes** (one compared the whole
  listener list with the container's, which differs by design; one used `ps -o`, which the
  decoy's `ps` declines). With those two rewritten the emulator group is 281 pass, 0 fail,
  3 known gaps, and `emulator.s2-ss-header` is closed: Gate 3 test 7's three checks are all
  the emulator's now. Unit tests 1,337 pass (225 deselected, as before), lint clean.
  Nothing is committed.
- **18 Nov, 02:15.** The stock 9B measured again on the 55-command list, as the baseline the
  tuned model will be held to (`build/llm/9b-55/` on the lab host): one at a time, 45
  answered by the model (5 by the library, 4 over the token limit, 1 refused operation), 24
  pass the check, 10 are the real host's; first byte 715 ms and whole answer 912 ms at the
  median. Four at once: 44 answered, 22 pass, 11 the same; 1,326 ms and 1,733 ms. **The
  first attempt was not a measurement**: started minutes after a rebuild, with the host's
  disk still busy, the responder's health check timed out, the decoy stopped asking, and
  the pass reported "6 pass the check" with 47 of 55 answered by the emulator. The report
  now says so in words and exits 2 when the emulator answered more than half of a pass
  (`llm_bench.not_asked`, one test). New in the repository: `eval/tune/collect_help.sh`,
  `eval/tune/score_adapter.sh`, and `make tune-set`, `make tune-score NAME=`, `make
  render-emulated`. Training on Kaggle is past three hours and still running.
- **18 Nov, 02:45.** The training run ended at 02:26 (360 steps, validation loss 0.85 to
  0.41). Adapter converted and served (`make tune-score NAME=v1`), held-out sets scored,
  bench and injection set run on the tuned model, then the stock 9B put back
  (`make llm-up`). Results and the decision in `docs/experiments/phase-3/lora-v1.md`; the
  training events in `lora-v1-train.jsonl` beside it. Step 5b is closed. Next in step 5:
  replay of real recordings, the responder-consistency probes, temperature 0; then step 6.
- **18 Nov, 03:00.** Temperature 0 tried with a new option of the scorer (`--twice`,
  `--temperature`; one test): it does not make repeats agree, the batching of concurrent
  requests is what differs. Setting unchanged. The stock 9B is serving. Unit tests and lint
  clean; nothing committed.
- **18 Nov, afternoon.** The owner asked whether the phase 2 showcase commands still work:
  `make showcase-preview`, `make showcase-check` (0 problems) and the demo run (3 sessions,
  18 steps, 2 skipped, no errors) do; the public link and the password command were left to
  the owner. Then the consistency group, the last probe group of step 5, and what its first
  live run found (Findings). The policy's budget fix needed a field in the decide request
  and fork patch 0022. Unit tests 1,354, lint clean. Nothing is committed.
- **18 Nov, evening.** Fork patches 0022 (the gate is told what was spent), 0023 (one login
  is one host) and 0024 (five file commands and `cat`); the fork suite is 2,009 tests with
  the image's own 18 failures. The responder keeps where a program stands. The model
  bench's list is 57 commands: six more went to the emulator, and eight still in the
  model's tail were added so that every class keeps at least eight (`pinky`, `dircolors`,
  `ptx`, `fmt`, `csplit`, `openssl genrsa`, `openssl rand`, `savelog`; all checked to be on
  the reference image). `make render-emulated` now
  writes the fixed-text list too (its first version dropped it and broke the inventory;
  regenerated from the image: 171 commands, 23 fixed texts; inventory 42 entries, 67
  wrongly answered lab commands). 16 new emulator probes. Nothing is committed.
- **18 Nov, night.** Redeployed with patches 0022 to 0024 and the responder's standings.
  `make probe`, groups emulator and consistency, against the live model: **324 pass, 0
  fail, 3 known gaps** (the 16 new probes of `cat`, `truncate`, `install`, `link`,
  `unlink` and `shred` answer exactly as the reference host; all 27 consistency checks
  pass). The whole suite and `make itest` are running on the lab host
  (`~/mirage-scratch/full-check.sh`, results in `probe-full.log` and `itest.log` there).
- **18 Nov, late.** The whole of `make probe` with the live model serving: **474 pass, 0
  fail, 10 known gaps, 0 stale.** `make itest`: 70 of 75 on the first run. The five that
  failed were the responder's own tests asking for `install` (the emulator's since patch
  0024) and `locale -a` (the render library's since the promotion of 17 Nov); they now ask
  for `mkfifo`, `ssh-keygen` and `locale -m`, the stand-in's script with them, and every
  test starts with the standings forgiven. `tests/integration/test_respond.py` again: 13 of
  13, one of them new (a program that fell back once is refused for the next login until
  forgiven). The live 9B is serving. Step 5 is done but for the replay recordings, which
  only CI and the laptop need. Next: step 6.
- **20 Nov.** The lab host restarted (the owner's machine). The core stack came back by
  itself; the model server and the showcase did not, as designed. **The model server could
  not start**: the host booted kernel 7.0.0-43, for which no NVIDIA module package is
  installed (the module's meta package is still at 6.17.0-29). Fix written for the owner to
  run, since it needs root: `sudo bash tools/lab-host/gpu-driver.sh` (installs
  `linux-modules-nvidia-595-open-7.0.0-43-generic`, 8 MB, and loads it). Until then the
  responder is on recorded answers (`make llm-down`). Checked after the restart, without the
  model: `make showcase-preview` and `make showcase-check` (0 problems), the demo run (3
  sessions, 20 steps, none skipped, no errors), every command of the new showcase list on
  the decoy, and `make probe` (474 pass, 0 fail, 10 known gaps). The order to show things
  in, with phase 3's, is in `docs/08-showcase.md` ("The order, with phase 3 in it"). The
  owner asked for the services to be stopped afterwards: `make showcase-down` and `make
  down` (data kept; `make up` starts the stack again).

