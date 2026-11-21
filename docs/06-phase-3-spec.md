# Phase 3 specification · Adaptation and the LLM responder

Status: draft for review · 14 November 2026, revised 15 November 2026 after Gate 2 passed (what changed: R2, R15, R21, the new R23, 3.0, 3.3, 3.7, and sections 7 and 9 to 12), and again the same day from the survey R23 asked for (3.3, R12, Gate 3 test 9, and sections 7, 9 and 11). Nothing in this phase is built; section 12 lists what it starts from.
Parent: [build plan, phase 3](01-build-plan.md#phase-3--adaptation-and-the-llm-responder-56-weeks) · Companion docs: [architecture](02-architecture.md) · [AI/ML design](03-ai-ml-design.md) · [phase 1 spec](04-phase-1-spec.md) · [phase 2 spec](05-phase-2-spec.md) · [spike results](../spikes/README.md)

Phase 3 makes the decoys answer more like the host they claim to be, and lets a learned policy choose how they answer. It adds four things:

- answers for commands the emulator lacks: pre-rendered from the profile first, a local LLM for what is left;
- a state manager, so that a generated answer and the emulator agree about the session;
- three policy actions (`respond`, `plant_token`, `escalate`) and a learned policy that is tested against the rules in randomised lab sessions once it has passed an offline screen;
- on a Linux host, a sandbox where an escalated session runs for real, and Caldera to label what happens there.

Gate 3 (section 6) is the only exit criterion.

Four parts of this phase can go wrong without any test failing:

- **The headline comparison.** Gate 3 asks whether the adaptive stack draws more techniques out of a session than stock Cowrie. The attacker in that comparison is our own script. If its success checks are written to match what our responder prints, or the responder is tuned on the scenarios it is scored on, the number measures agreement with ourselves.
- **Generated output.** A wrong answer from a model looks exactly like a right one. Spike S2 found three in fifty.
- **Session state.** A model can report that a file was written while the emulator's filesystem does not have it. The next `ls` gives the decoy away.
- **The logged probabilities, again.** Phase 2's logs hold five actions. An estimator asked about a sixth returns a number anyway.

Section 5 and the acceptance lines in section 4 exist to make those four failures loud.

## 1. Decisions this spec makes

Each is a default; say so if you disagree.

| # | Gap | Decision |
| --- | --- | --- |
| R1 | Demo 3 is defined nowhere in the repository. The build plan names it, and the technical report's version uses parts that arrive in phase 4. | Defined here for what phases 0 to 3 contain (section 4, 3.8). It has two parts: 3a runs on the laptop and in CI, 3b needs the Linux host. |
| R2 | Gate 3 mixes work that needs a Linux host with a GPU (the sandbox, Caldera, the live model's real numbers) with work that does not. A lab host exists since 14 November 2026 (Ubuntu 24.04, an 8 GB GPU, KVM), but its GPU container runtime and its sandbox runtime need root steps that have not been run (3.0). | The gate has a core part (tests 1 to 11) and a host part (tests 12 to 14). Phase 4 depends on nothing in the host part, so it may start when the core passes. `escalate` stays masked everywhere until the host part passes. |
| R3 | The architecture draws the policy service calling the responder. The policy service answers in milliseconds and calls nothing (phase 2, Q12); the model takes seconds. | The policy returns a new action, `respond`. The decoy then calls the responder itself, with its own longer deadline, and streams the reply. The gate stays fast, and both hops fail open (section 3). |
| R4 | "Pre-rendered" was specified as Cowrie text commands. A text command ignores its arguments, cannot return a non-zero exit code, and answers instantly. | A render library in the profile: entries keyed by normalised argv, each with stdout, stderr, an exit code and a response time taken from the reference host. A small fork patch serves it inside the decoy, so it still works with the policy service and the responder both down. |
| R5 | Which commands to pre-render. A list made by reading the test scenarios would score well and generalise to nothing. | The inventory comes from data that is not the test set: the most frequent failed commands in the Zenodo seed sample and in dev-split lab runs, ranked by volume. Coverage is reported as a share of that volume (section 5). |
| R6 | A profile is per deployment. Rendering with a model per deployment would put unreviewed model output on every sensor. | Outputs are rendered once per hardware class (a few believable VPS shapes), checked, reviewed by a person and committed as templates with slots. The profile generator fills the slots (hostname, addresses, machine-id, sizes) from the seed. No model runs at deployment time. |
| R7 | Who owns session state. The published LLM shells keep all of it beside the model. Cowrie already has a per-session filesystem and working directory. | Cowrie remains the only owner of the filesystem and the working directory. The state manager owns what Cowrie lacks (started processes, environment changes, facts already asserted) and keeps a mirror of the filesystem changes. A model never changes state: it proposes operations, the state manager validates them, and the fork applies them through the same mutators an emulated command uses (3.1). |
| R8 | Streaming (S2: first token in 0.5 s, whole answer in 8.6 s) conflicts with checking an answer before the attacker sees it. | Output is released one complete line at a time, each line through the output filter. Stateless and state-reading answers stream. State-changing answers are buffered: they are short, and their operations must be validated and applied before anything prints. A failure mid-stream ends the command as if it had been killed, and is counted (3.2). |
| R9 | S2's JSON format was the more accurate one but could not stream. Raw text streamed but invented facts. | JSON with `stdout` as its first field. The responder decodes that string as tokens arrive and treats the rest (`stderr`, `exit_code`, `ops`) as a trailer. |
| R10 | The laptop cannot run the model in a container (Docker has no Metal), and a container that can reach the host breaks the containment rule. CI has no GPU and cannot hold a 5.7 GB model. | Three backends behind one interface. `replay` serves recorded answers; it is what CI uses and the laptop's default, and a request with no recording is an error, so a changed scenario forces a new recording. `llama` talks to a `llama-server` container on an internal network (the Linux host). `llama-dev` talks to the Mac's native server and exists only under a compose profile that refuses to start beside a published edge (section 2). |
| R11 | Phase 2's rules allow everything. Beating them would be a low bar for a learned policy, and the headline comparison needs a deterministic adaptive stack. | Rules v2: `respond` for an unknown command from a session that is not a scanner, `plant_token` once after the first credential-seeking input, never `escalate` on the laptop. This is the baseline the bandit must beat, and the policy the capture range and the demos use. |
| R12 | Phase 2's explore logs contain five actions and say nothing about the three new ones. | A new exploration campaign with `respond` and `plant_token` added, logged under a new policy version (`escalate` is decided by rule and is not explored, R23). The estimators gain a support check and refuse a target policy that puts weight where the log has none (3.3). |
| R13 | "Bandit goes live in the lab." The capture range must stay unexplored for labels and demos, and the explore range must keep the behaviour policy for data. | The explore range is split. 198.19.0.0/17 keeps the exploring behaviour policy. 198.19.128.0/17 is the `act` range, where the learned policy acts. The rules act on every address outside the lab ranges for the whole phase. |
| R14 | `plant_token` (deferred by phase 2, Q11) needs a token mid-session, but the pipeline's matcher only knows tokens the profile generator minted. | The generator mints a reserve of unplanted tokens for each deployment. `plant_token` plants one from the reserve as a state operation. Nothing is minted at decision time. |
| R15 | The bandit's context should include the actor class, but the policy service calls nothing. | The event-level classifier from 2.3 is loaded read-only as a model file in the policy process and scored on the features the service already tracks per session. It is a random forest saved as plain JSON and predicted by the project's own code (`classifier.Forest`), which moves to `mirage_schema` so the policy service and the offline code share one implementation, as the bandit's arithmetic already does. The latency test of Gate 1 must still pass. |
| R16 | D12: Cowrie's algorithm list identifies it from one passive packet, and no configuration fixes that (S3). | A time-boxed spike, S4, puts a real OpenSSH in front and hands its sessions to Cowrie (3.4). Adopt the front end if every check of the spike passes; otherwise the gap stays listed. Patching Twisted Conch is rejected: it means implementing five algorithm families in a library we do not own, and again at each OpenSSH release. |
| R17 | How a session reaches the sandbox part-way through. Handing the raw terminal to a real shell drops the gate and the capture model. | Command proxy first: after `escalate`, Cowrie keeps the terminal and sends each line to a persistent shell in the sandbox, so every line still gets a decision and a command event. Handing over the raw terminal, which full-screen programs need, is a later step and a listed gap (3.5). |
| R18 | gVisor needs no KVM and runs in CI, but a program inside can tell: the kernel version, `/proc` and the boot log are gVisor's own. | The broker takes the OCI runtime as configuration. gVisor is the default and what CI tests. A microVM runtime is used where the host has KVM. Userland tells are covered by installing the render library's outputs in the sandbox image; kernel-level self-identification under gVisor is a known gap (section 8). |
| R19 | Host eBPF sensors (D15) cannot see inside gVisor or a microVM. | Sandbox telemetry comes from three places that do not depend on the runtime: the command proxy (every line and its output), the filesystem difference at session end (new files hashed into the artifact store), and the sinkhole's log. Process tracing from the runtime's own monitoring is added where it exists; Caldera's labels need it (3.6). |
| R20 | The simulated attacker's success checks decide the headline number. | Every check must hold on a real Debian host. Each depth scenario is first run against the reference container, and a step whose check fails there is a broken step, not a hard one (section 5). |
| R21 | The encoder for tagger v1 would be fine-tuned on about 120 training procedures. Phase 2 already measured a linear model on character n-grams: 0.360 on dev against the chosen retrieval tagger's 0.405. | Tagger v1's candidate is a fine-tuned encoder, with the linear model kept as the cheap comparison. It is promoted only if it beats the phase 2 tagger (0.212 on the held-out split). Not winning is a valid result and is reported (3.7). |
| R23 | The learned policy of 3.3 was specified by carrying phase 2's design forward: a contextual bandit, ε-greedy logging, Vowpal Wabbit, three estimators. Phase 2 found no learner that beats the rules, and nothing in this repository surveyed what is known about reinforcement learning for deception. | A written survey came first ([docs/research/deception-rl.md](research/deception-rl.md), 15 November 2026). 3.3 is revised from it. Three of its changes were matters of scope and were agreed the same day: a sequential policy stays out of scope, `escalate` is decided by rule, and a randomised comparison of whole sessions decides whether a learned policy passes, with the offline estimate as the screen before it. |
| R22 | The build plan's responder is not tied to a protocol. Scanners are about 90% of traffic and most of it is HTTP path sweeps. | Generation is SSH-only for Gate 3. The HTTP decoy gets the response cache deferred from phase 1, filled offline for commonly probed paths; no live model answers HTTP. Redis and MySQL stay deterministic. |

## 2. Topology

```
                              mirage_gate (internal)
 decoys ──1 decide───► policy                      answers in milliseconds, calls nothing
        ──2 respond──► responder ──► llama-server   mirage_llm (internal)
        ──3 exec─────► sandbox-broker ──► sandbox, sinkhole   mirage_sandbox (internal, Linux host)

 lab only, Linux host (profile lab-hi):
 caldera ──► a lab sandbox running its agent ──► event log ──► adapter ──► sim.groundtruth
```

- **`mirage_gate`** gains two services. From a decoy, exactly three destinations are reachable: the policy port, the responder port and the broker port. The containment test of Gate 1 is extended to say so. Only the SSH decoy holds tokens for the responder and the broker.
- **`mirage_llm`** is `internal: true` and holds the responder and `llama-server` only. The model server has no other network, no volume but its read-only model file, and no egress. The responder is on `mirage_gate` and `mirage_llm` and nothing else: it cannot reach the pipeline, the decoy network or the internet.
- **Profile `llm-dev` (laptop only).** The responder is attached to one ordinary bridge network so it can reach the Mac's native `llama-server`. Compose refuses the profile when the real edge publishes a port, the same rule as the `lab` profile. Without the profile, a test asserts that no container on `mirage_gate` has a route to the host.
- **`mirage_sandbox`** is `internal: true` and exists only on the Linux host. It holds sandboxes and the sinkhole. It shares no network with the decoys, the gate, the pipeline or the lab.
- **The broker** is on `mirage_gate` and reaches the container runtime through a socket proxy that allows only the calls it needs (create from a fixed image, attach, remove). Image, runtime, limits and network are fixed in the broker's configuration and are never taken from a request.
- **Profile `lab-hi` (Linux host, on demand).** Caldera and one lab sandbox on their own internal network. Caldera's own documentation says it must not be exposed; it never runs on a sensor, and it needs about 8 GB.
- **Comparison arms.** `lab-edge` gains one port per arm of section 5: stock Cowrie and the reference host. The runner still has one target, `lab-edge`, and its target check does not change.
- **Logs.** As in phase 1, nothing sends telemetry over the network. The responder, the broker and the sinkhole write JSON lines to volumes that Vector tails. The schema gains the sources `responder` and `sandbox`.

## 3. Gate contract v2 and the answer ladder

Contract v2 extends [contract v1](04-phase-1-spec.md#3-gate-contract-v1). Every v1 field keeps its meaning.

```
POST /v1/decide
{ ...v1 fields,
  "supports": ["respond", "plant_token", "escalate"],   // v2 actions this decoy implements
  "tier": "emulated" | "rendered" | "none" | "absent"   // what the decoy would answer with if allowed
}
→ { ...v1 fields,
    "action": v1 actions | "respond" | "plant_token" | "escalate",
    "budget":  {"max_tokens", "deadline_ms"},           // respond only
    "ops":     [ ... ],                                 // plant_token only: validated state operations
    "sandbox": "<broker session>"                       // escalate only
}
```

The policy never returns an action the request did not list in `supports`, so the HTTP, Redis and MySQL decoys, which send no `supports`, keep receiving v1 actions only.

`tier` is `none` for a program that is on the host and that nothing of the decoy's answers for (or an emulated command given options it declines), and `absent` for a program that is not on the host at all. The second is not a case for the responder: "command not found" is the true answer and the shell gives it (decided 17 November 2026; before that both were `none`). `supports` is what the decoy can carry out *now*: the SSH decoy lists `respond` only while the responder passed its last background health check and the session's change journal is complete, and lists nothing once the journal has overflowed.

| Action | Meaning (SSH only in this phase) | If it cannot be carried out |
| --- | --- | --- |
| `respond` | Ask the responder to answer this input. Masked unless `tier` is `none`. | The emulator's own answer, with a recorded fallback and its reason |
| `plant_token` | Apply `ops` (create one file holding a reserve token), then run the command as `allow` | `allow`; the token returns to the reserve |
| `escalate` | Move the session to a sandbox: this line and every later one runs there | `allow` in the emulator |

**The answer ladder.** An input is answered by the first rung that applies.

| Rung | Answers | Where it runs | Target response time |
| --- | --- | --- | --- |
| 0 · Policy | `fake_success`, `fake_error`, `delay`, `terminate` | Policy service | Gate budget (under 20 ms added at p95) |
| 1 · Emulator | Commands Cowrie implements | Decoy | As the reference host, by command class (3.4) |
| 2 · Render library | Profile-dependent commands the emulator lacks | Decoy, from profile files | The reference's measured time for that command |
| 3 · Cache | An earlier generated answer for the same profile, command and state | Responder | Under 50 ms |
| 4 · Live model | Commands nothing above knows | Responder and `llama-server` | First line within 1.5 s; reported, not gated (section 6, test 6) |
| 5 · Sandbox | Every line of an escalated session | Sandbox, Linux host | Real |
| Fallback | Whatever stock Cowrie would have printed | Decoy | — |

**Responder API.** `POST /v1/respond`, bearer token, newline-delimited JSON in both directions.

- Request: the decide request's identifiers, the input line and argv, user, cwd, the environment changes, the filesystem changes since the responder's last view of the session (with a sequence number), a slice of the filesystem around the paths the command names (types, sizes, modes, and the first 1 KiB of small text files), and the budget from the decision.
- Reply: `out` records (one complete line each), then one `end` record with `stderr`, `exit_code`, `ops`, the rung that answered, token counts and timings; or one `abort` record with a reason.
- **Streamed or held** (added 17 November 2026). A command whose class only reads is streamed: its lines go out as `out` records while the model is still writing, and its `end` carries no operations. Any other command is held: no `out` record is sent, and `end` carries the whole of stdout together with the operations, so that the decoy applies the operations first and shows nothing if it refuses them. An `end` with operations after `out` records is a breach; the decoy applies nothing and stops the answer there.
- **After output has been shown** an answer cannot be replaced by the emulator's. If it stops then (a refused line, a deadline, a lost connection) the command ends there with status 1, and the decoy records it as `cut` with the reason.
- A sequence number the responder does not expect gets a `resync` reply, and the decoy sends its whole change journal once. The responder may lose all its memory at any time without the decoy noticing more than one slower answer.

**Failure semantics.** Unchanged in kind from v1 and extended to the new hops: a missing, late, unauthorised or malformed reply from the responder or the broker means the emulator's answer, and the decoy records a fallback with its reason. A decoy never waits on the responder past the decision's deadline, and never on the broker past its own timeout. With all three services stopped, the decoy behaves as it does at the end of phase 2, plus the render library.

**Records.** Each `respond` produces a decoy event (what was printed, and any fallback) and a responder record (rung, prompt and output token counts, time to first line, total time, operations proposed and applied, filter hits), joined on `request_id`. Each escalation produces a broker record of the sandbox's creation, hydration and destruction.

## 4. Work packages

### 3.0 Prerequisites

- **Gate 2.** Passed on 15 November 2026 on the lab host ([phase 2 spec, section 12](05-phase-2-spec.md)); `phase-2` is to be merged before phase 3 branches from it.
- **What phase 2 left for this phase.** Keystroke statistics, the three learner families and the retrieval tagger are built. Three results change what follows:
  - No learned policy beats the rules (doubly robust difference −0.164, interval −0.509 to +0.107), so 3.3 starts from a negative result, not from a working learner.
  - The tagger gets 0.212 on commands it has not seen, and the reward computed from its labels inherits that. The lab's ground-truth reward stays the one used for selection.
  - The policy service's `last_tactic` still comes from the starter rules, which know only harmless discovery commands and fire on about one input in seven. The learned tagger cannot be called from the policy service (it calls nothing, and the embedding takes longer than the gate's budget). 3.3 has to say what the context reads instead.
- **Root steps on the lab host.** Containers there cannot use the GPU until the NVIDIA container toolkit is installed, and there is no sandbox runtime until gVisor is. Both are installed by `tools/lab-host/install-runtimes.sh`, which a person runs with `sudo`. The first is needed at step 5 of section 7, the second at step 9.
- **Depth scenarios.** Written from [a handoff brief](handoffs/phase-3-depth-scenarios.md) by the same separate tool as the phase 2 catalogue. Frozen, and split into dev and test, before any responder work (section 5). Three things this needs that phase 2 did not have:
  - *A second split.* The phase 2 split is frozen on its set of procedure IDs, so a new procedure cannot join it without a new freeze. Depth procedures go in their own catalogue files and get their own split file (`eval/split-depth.yaml`, dev and test only); the phase 2 check ignores them, and the content check runs across both so that a depth procedure cannot duplicate a phase 2 training procedure.
  - *The inputs really run.* On arm R every input executes in a real container. The brief adds safety rules for that, and the lint has to enforce what it can of them before any scenario is run there.
  - *A reference image that has what the checks need.* The image today is a minimal Debian with the four services. Each tool a scenario asks for beyond it is a decision: add it to the image because such a host plausibly has it, or drop the step.
  - *Where this stands (15 November 2026).* Written: 118 procedures in eight catalogue files and 24 scenarios, all SSH, each meeting the brief's structure (nine or more steps, every step checked, a fallback route, four or more techniques over three or more tactics). The catalogue now holds two sets with their own hashes (`mirage_lab.models`), so the phase 2 split and the frozen dataset are untouched by depth files. The depth split exists and is `provisional`: twelve scenarios in each half, dealt as six groups of scenarios that share procedures. That puts whole themes on one side (dev: credentials, fingerprinting, processes, the service stack; test: covering tracks, egress, file handling, credential rotation), so the test half is new themes as well as new commands. Four procedures carried a technique ID that v20.1 revokes and were relabelled from the pinned index. 
  - *Arm R and the first run on it (15 November 2026).* The lint now holds every depth procedure to run-safety rules (nothing that exhausts a resource, touches a raw device or the kernel, reaches for the container's boundary, stops the host or names a literal address outside the reserved ranges), and the runner applies them again to each rendered input before it goes to a real host. Arm R is the reference image with the profile's accounts, web root and identity files (`lab/arm-r`), behind an edge of its own on the lab network so that the runner's isolation check is unchanged. It is alone on a network with no route and no address on the lab machine, held to one CPU, 512 MB and 256 processes, and recreated for every scenario (`make lab-arm ARM=r`). `make arm-r-check` proves the containment from inside before anything is sent: the edge answers, and the internet, the lab machine, every Docker gateway, the policy service and the store do not. All 24 scenarios were then run there. Fourteen of 27 sessions passed every check. The rest failed on seven procedures. One needed a tool the slim image lacks (`kmod`, added to the arm's image; that scenario now passes). Six are not repaired: `d-log-make` and `d-temp-make` write into a directory that no step makes, which an emulator lets through and a real host does not (the one directory-making procedure makes a different directory, so adding it did not help); `d-shadow-after` trips bash's history expansion in an interactive shell and passes over an exec channel; and `d-debincnf-cred`, `d-pwd-holds` and `d-tar-www` print nothing where their check expects a marker. Repairing them means changing command text, which is the content writer's part. A first trial of arms A and B on two scenarios shows the comparison's shape (arm R passes all steps of both; the phase 2 stack 6 of 11 and 8 of 13), and one thing to settle: stock Cowrie closed the channel on the exec scenario, and whether that is its stock behaviour is not yet checked. Those four things were open at the first run and are now done; see the next item.
  - *Repaired, rerun, frozen (15 November 2026).* The six procedures were repaired by the content writer from [a note that names each one and what it must do, with no command text](handoffs/phase-3-depth-repairs.md). The arm's image gained one capability a root shell on a real host has and Docker's default set lacks (setting a file's immutable flag), confined to the container's own files and cleared before the container goes. All 24 scenarios were then run again on arm R: 27 of 27 sessions pass every check, 280 of 280 steps. The depth split is `frozen` at that catalogue.
- **Demo 3** is written after the render inventory exists (step 2 of section 7): its first part has to use commands from that inventory, so it cannot be written at step 1 as an earlier draft of this spec said. It gets its own brief.
  - *The brief is written (17 November 2026):* [docs/handoffs/phase-3-demo-3.md](handoffs/phase-3-demo-3.md). Both catalogue sets were frozen by then, so demo 3's procedures are a third set (`lab/catalogue/9*-demo-*.yaml`), hashed apart from the other two and in no split: the lint accepts that for this set alone, refuses a scenario that mixes sets, and holds the set to the run-safety rules, since 3b's lines run in a sandbox. `python -m eval.split check` lists any demo procedure that is near-identical to a held-out one. The scenarios themselves are the content writer's and are not written yet. What the brief had to fix about parts that are not built is listed in 3.8.
- **Baseline.** The arms that exist today (stock Cowrie, the phase 2 stack, the reference host) are measured on the depth scenarios and the result is committed. That is the "before" number.
  - *Measured (15 November 2026):* [the depth baseline](experiments/phase-3/depth-baseline.md). Steps that succeed: the reference host 280 of 280, stock Cowrie 69 (25%), the phase 2 stack 87 (31%). Two things in it change what comes next. The stack's lead over stock Cowrie comes from ten sessions that stock Cowrie's connection ended at the first exec; on the other seventeen stock Cowrie is ahead, 69 of 180 against 56, and the stack is behind it in five sessions (all of covering tracks, and the second session of two rotation scenarios). And whether the exec ending is stock Cowrie's behaviour towards every client, or only towards the runner's, is not confirmed; until it is, arm A is compared on the seventeen sessions.
  - *The five sessions, explained (16 November 2026).* Three were a defect: the decoy's filesystem is built from an image, so `/dev` was empty and `/dev/null` did not exist. Fixed in the builder, with a default-tell check; the stack then scores 96 of 280 (34%), which is the baseline phase 3 starts from, and matches stock Cowrie on covering tracks. `/proc` (one file) and `/sys` (empty) have the same cause and are not fixed here: what they hold depends on the machine, so they are part of step 2's hardware classes, and the probe lists them as known gaps until then. The other two were missing depth: a password change is answered as done and not honoured at the next login (stock Cowrie passes only because it accepts any root password). That is a requirement on the state manager (3.1): **a credential change made in a session holds for that actor's later logins.** Every arm's run now keeps what a failed check saw (`make arm-failed`), and the stack's 42 remaining failures, grouped by what the decoy answered, start step 2's inventory.
- **Fork.** Check upstream Cowrie before adding patches. The pin is v3.1.6 and the build plan says to rebase monthly.
- **Workspace.** New packages `responder/` (service, state manager, cache, backends) and `sandbox/` (broker, sinkhole, image). The Caldera adapter goes in `lab/`. Probes stay in `eval/probes/`.

### 3.1 State manager

`responder/src/mirage_responder/state.py`, and fork patches continuing the series from 0010.

**In the fork**

| Change | Acceptance |
| --- | --- |
| A per-session change journal: the filesystem operations already emitted as `cowrie.fs.change`, plus working-directory and environment changes, kept in memory with a sequence number | Replaying the journal onto a fresh filesystem reproduces the session's. It is capped in operations and bytes; a session over the cap stops listing `respond` and `escalate` in `supports`. |
| A credential change holds for the source that made it: after a password change is answered as done, that source's later logins to the account succeed with the new password and fail with the old one (required by the depth baseline, 16 November 2026: the decoy said the change was done and then refused the new password) | The second sessions of the two rotation scenarios log in on the stack. Another source is still refused the new password, and the default-tell checks on random passwords still pass. |
| An applier that takes validated operations and calls the existing mutators | Each applied operation emits the same `cowrie.fs.change` event an emulated command would. An answer's operations apply all together or not at all. |
| The `respond` client: non-blocking, streams lines to the terminal, and keeps a placeholder on the command stack as the gate does | S1's ordering tests pass with a slow responder: typed-ahead input queues behind the answer. Ctrl-C stops the output within 100 ms and tells the responder. |
| Health checks of the responder and the broker in the background | `supports` lists `respond` only while the responder answered its last check, and `escalate` only while the broker reported a free sandbox. The policy service therefore learns availability without calling anything. |

**In the responder**

- **Held per session:** profile ID, user, working directory, environment changes, the mirror of the filesystem changes, processes the session started, facts earlier answers asserted (a bounded list, for example that a package is absent), and tokens spent. In memory only, dropped an hour after the last request, with a cap on live sessions.
- **Operations a model may propose:** `mkdir`, `write` (content up to 4 KiB), `remove`, `rename`, `chmod`, `chown`, `cd`, `setenv`, `unsetenv`, `proc_start`, `proc_end`. At most eight per answer.
- **Validation:** paths absolute and normalised; the parent exists; the session's user has permission; nothing under `/proc`, `/sys` or `/dev`; never a path holding a planted honeytoken; sizes and the session's total within caps.
- **Command classes** (`responder/classes.yaml`): stateless, state-reading, state-changing, volatile, interactive, network. A command not in the table is treated as state-changing, the cautious case: buffered and never cached.
- **State fingerprint** for the cache key: for a stateless command, the profile alone; for a state-reading one, the profile, the working directory, the relevant environment and a digest of the filesystem entries under the paths the command names.

**Acceptance**

- Round trips, each run twice: once with the changing step answered through the responder and the reading step by the emulator, once the other way round. A created file is listed. A removed file is gone. `cd` then `pwd`. `chmod` then a long listing. A variable set, then echoed.
- Property test: random sequences of valid operations give the same filesystem through the applier as through direct mutator calls.
- A relative path, a missing parent, a protected path, a ninth operation and an oversize write each reject the whole answer. Nothing is applied and a fallback is recorded.
- The responder restarted mid-session answers the next request correctly after one resync.

**Must not:** write to Cowrie's filesystem except through the applier; read the pipeline or any store but its own.

### 3.2 LLM responder

Three parts, in the order they are built. The first needs no live model and removes the most common tell.

**a. Render library**

- **Inventory** (R5). `make render-inventory` ranks failed commands, by normalised argv, in the Zenodo seed sample and in dev-split lab runs. The inventory file is committed. The target is the entries that cover 80% of the failed-command volume (a default).
- **Hardware classes** (R6). Three to start, in `decoys/profiles/hardware/*.yaml`: CPU model and count, memory, disk, virtualisation, interface names. Each is internally consistent and consistent with the kernel the profile claims.
  - *Recorded, not written (decided 16 November 2026).* A class is what Debian 12 says about itself when booted on that virtual hardware: `make hardware-capture` boots Debian's own cloud image in a throwaway KVM machine with no network, and records the kernel's files, the trees under `/dev`, `/proc` and `/sys`, and the output of the reporting commands. `make hardware` turns a record into the committed class, replacing the recorded machine's own values (host name, machine and boot IDs, network card and IP addresses, file-system IDs) with slots the profile fills. No model drafts anything a class says, which is stricter than the default in section 11 asked for. The classes can only be machines the lab host's CPU can host under KVM: three AMD EPYC shapes today. An Intel class needs an Intel host.
- **Rendering.** `mirage-profile render-library`, per distribution, hardware class and command:
  1. Run the command in the reference container to get the true format, exit code and time.
  2. Where the output depends on hardware the container does not have, it is taken from the hardware class's record (above). A model drafts an entry only where neither the container nor a class's record can give it; none has needed one so far.
  3. The fidelity check (section 5) compares the draft with the reference output.
  4. A person reviews the difference.
  5. The result is committed under `decoys/profiles/rendered/debian-12/<class>/` as a template with slots, an exit code and the measured time. Entries that do not depend on the class are in `debian-12/any/`.
- **Serving.** A fork patch (0009) looks the command up in the deployment's library before Cowrie's own lookup of text files and before "command not found". An entry answers only when all of this holds: the emulator has no command class of that name (rung 1 comes first); the word typed resolves, through `PATH` or as a path, to the entry's program, and that file is still as installed (not removed, not overwritten, still executable); the arguments are exactly the entry's; and the caller is one the entry answers, since some answers are root's alone. It prints the entry on the stream it was recorded on, after one of the times measured for it, and sets the exit code. The gate sees `tier: rendered` and `known: true`; any other arguments fall through to what the decoy did before.
- **What changes by the second.** No entry holds such a value: an answer that names the caller's own connection or a process ID is not a fixed answer and is left out (`rendered/excluded.yaml`, with the reason). The files under `/proc` that move are generated on each read by the same patch: `/proc/uptime` was Cowrie's already, `/proc/loadavg` agrees with what `uptime` prints, and `/proc/stat` is the class's record of its counters at the end of boot, carried forward to the uptime the decoy reports.

Acceptance:

- Every committed entry passes the fidelity check. There is no "gap" state for an entry: it passes or it is absent.
- One profile and seed give a byte-identical library. Two seeds of one class differ in the slots and nowhere else. Two classes differ in the hardware facts.
- With the policy service and the responder stopped, inventory commands are still answered.
- Coverage is reported as a share of failed-command volume, on the corpus and on the held-out depth scenarios separately.

Where this stands (16 November 2026):

- **The fidelity check** is built (`mirage_profiles.fidelity`) and tested on the kinds of output it has to judge.
- **The inventory** is built and committed (`make render-inventory`, `decoys/profiles/rendered/inventory.yaml`). It cuts each shell line into simple commands and sorts them by what the decoy does with them. Its data are thin: the corpus sample on disk is 850 input lines, of which 56 commands are answered wrongly, and the lab's non-test procedures add 81. Of that volume, commands that only report and have nothing left open (what a library can answer) are a third of the corpus's and a quarter of the lab's. The rest is shell syntax the emulator's shell lacks, files the attacker brings and runs, and tools that need arguments or state (`redis-cli`, `mysql`, `getent` with a key). **The 80% target cannot be met by a render library alone on this data**; the number is reported as it is, and the remainder belongs to the emulator audit (3.4), the state manager (3.1) and the responder.
- **Three hardware classes** are recorded and committed, and a profile claims one by seed. The decoy's `/proc`, `/sys`, `/dev` and `/boot` are the class's, and `lscpu`, `nproc`, `df`, `mount`, `dmesg`, `lsblk`, `blkid`, `findmnt` and `arch` print what the class recorded, through Cowrie's own fixed-text mechanism. That mechanism cannot tell one argument from another (`df` and `df -h` print the same), set an exit code or write to stderr, which is what the serving patch below is for.
- **A leak in stock Cowrie, found by the new checks and fixed in the fork (patch 0008):** its `free` read the real `/proc/meminfo`, so every decoy showed the memory of the machine hosting it.

Where this stands (17 November 2026): built, and measured on the lab host.

- **The library holds seven commands for each class.** `lscpu`, `nproc` and `df -h` are each class's own record. `ss -tln`, `nginx -v`, `nginx -t` and `sshd -t` are what a container of the reference image printed (`make render-record`: a throwaway container with no network, each command five times as root and once as an account with no privileges). `make render-library` builds the committed entries and [the review file](../decoys/profiles/rendered/REVIEW.md), which shows every answer whole. **The review (step 4) is a person's and is not done.**
- **Two inventory commands are left out,** each with one count: `ss -ant` (its answer lists the caller's own connection, and a real `ss` sets each column's width by its longest address) and `lsof -i -nP` (its answer names process IDs, which would have to agree with `ps`, and the decoy's `ps` is still stock Cowrie's list). Both need the emulator, not a file.
- **Who is answered.** An answer is given to any user where the unprivileged run printed the same as root's (`ss -tln`, `nginx -v` and the three class commands), and to root alone where it did not (`nginx -t`, `sshd -t`).
- **The check is applied to what a deployment will print.** Rendering a profile fills each entry with the deployment's values and holds it against its record; an entry that fails stops the render. The same check runs in the unit tests for every committed entry, and against the running decoy (`eval/probes/render_library.py`): 32 of 32 checks pass on the lab host, among them every entry byte for byte with its exit code and stream, and again with the policy service stopped.
- **Coverage, as a share of wrongly answered volume:** corpus sample 18 of 56 (32%); lab procedures outside every test split 17 of 81 (21%); **held-out depth scenarios 0 of 55.** Of those 55, only 3 are commands a library could answer at all. The held-out half is other themes (covering tracks, egress, file handling, credential rotation), and what the decoy gets wrong there is state and shell behaviour, not missing reports. The render library will not move Gate 3's depth test by itself.
- **A second defect in stock Cowrie, found by the live check and fixed in the fork (patch 0010):** on an exec channel with no pty it wrote a command's stderr as ordinary output, so every error of every command arrived on stdout. A real server sends it as SSH's stderr stream (`ssh host cmd 2>/dev/null` hides it). The default-tell probe checks it, and stock Cowrie fails that check.
- **Depth, dev half only:** 39 of 139 steps succeed with the library, against 29 before, and 24 techniques reached against 16 ([the write-up](experiments/phase-3/depth-baseline.md)). Three of twelve sessions moved, all in the service-stack theme. The test half was not run.
- **Demo 3:** [the brief](handoffs/phase-3-demo-3.md) is written. The scenarios, which close step 2, are the content writer's and are not written.

**b. Responder service**

FastAPI, `POST /v1/respond`. One request passes through: class lookup, cache, backend, incremental decoding, output filter, operation validation, reply.

- **Refused classes.** Interactive programs and outbound network clients are never generated (architecture §5). The responder replies `abort` and the decoy falls back; the render library holds believable failures for the common ones.
- **Prompt.** A fixed part per profile (persona, distribution, hardware class) comes first, so the server's prompt cache keeps it (S2: 426 of 443 prompt tokens reused). Then the state slice. Then the input, in one delimited field, the only place attacker text appears.
- **Output.** A JSON schema per request (R9), at most 400 output tokens, temperature 0.2. The sampling seed is derived from the deployment, the normalised command and the state fingerprint, so a repeat that misses the cache still gives the same answer.
- **Output filter**, per line: no text from the prompt; none of the marker words the lab lint already lists; no control characters but tab and newline; a line-length cap. A hit aborts the answer and logs which rule fired.
- **Budgets** (defaults, revised from part c's measurements): input line up to 1 KiB; 400 output tokens per answer; 3,000 per session; 15,000 per source address per day; one answer at a time on the laptop and four on the host; first line within 1.5 s; whole answer within 10 s. On any limit the reply is `abort` and the decoy answers as the emulator would.
- **Cache.** SQLite on the responder's volume. The key is the profile ID, the normalised command and the state fingerprint. Only stateless and state-reading answers that completed and passed the filter are stored. Entries carry the model and prompt versions, and a change of either invalidates them.
- **Promotion.** `make render-candidates` lists the commands the live model answered most often. They go through part a's check and review and move into the library. A cached answer that fails the offline fidelity check is evicted and listed.
- **Backends** (R10): `replay`, `llama`, `llama-dev`. `make llm-record` runs lab scenarios against a live backend and writes recordings to `eval/recordings/`, keyed by a hash of the whole request.

Acceptance:

- Contract tests for every reply kind, for resync and for Ctrl-C.
- Each budget has a test that crosses it and finds a recorded fallback with the right reason.
- The injection set (`eval/probes/injection.yaml`, a fixed file of hostile inputs: asking for the prompt, asking for a change of persona, asking for operations outside the vocabulary or over the caps). Against the live model, no reply contains prompt text or a marker word and no invalid operation is applied. The share of aborted answers is reported: an abort is safe, and it is also a small tell.
- `replay` is deterministic and fails on a request it has no recording for.
- With the model server stopped, every `respond` falls back inside the deadline.

**Must not:** call anything but its backend; hold a secret other than its own bearer token; give the model a tool; put in a prompt anything the session's user could not read on the decoy; send any input to a model outside the machine (the build plan's default, unchanged).

**c. Live model**

- `make llm-bench` repeats S2's method through the whole path (decoy, responder, model), on the laptop and on the host: time to first line and total time by command class, tokens, memory, and four sessions at once on the host.
- **Model comparison.** The 9B model already on disk against one of about 4B (the next comparison the AI/ML design names), on a fixed set of 50 commands that are in neither the library nor the recordings. Fidelity decides first, speed second: a faster model that is caught more often is not an improvement.
- **Live fidelity.** A sample of answers given in lab runs is checked offline against the reference host, and the pass rate is reported with Gate 3.

### 3.3 Bandit goes live in the lab

Revised on 15 November 2026 from [the survey](research/deception-rl.md) (R23), whose section 4 gives the reason for each change. The numbers marked as defaults come from its arithmetic on phase 2's decision log.

- **What is learned, and what is claimed.** A contextual bandit on reward-to-go. That is one step of improvement on rules v2, and every result says so: it estimates "leave the rules once, then follow them". The value of the learned policy acting through a whole session is measured only by the randomised comparison below. A sequential policy is out of scope (section 9); the survey's section 5 says what would bring it back.
- **First, on phase 2's frozen decisions** (`eval/datasets/gate2/decisions.parquet`, train and dev sessions only; its test sessions have been read once). Four checks, done on 15 November 2026 and written up in [docs/experiments/phase-3/rl-checks.md](experiments/phase-3/rl-checks.md). What they found: answers do change what follows (a fake error makes a session 11 points less likely to go on), but with phase 2's five actions no answer raises the reward in any context, so there was nothing for a learner to win; careful learners lose less and none gains; the exit penalty is mostly coincidence for the mild answers; and 27% of the file reward was for content already captured. The checks were:
  1. *Closed loop.* Given the context, does the next input, or whether the session goes on, depend on the action that was taken? If it does not, no policy can gain on that traffic, and results on those scenarios are not read as evidence about attackers that react.
  2. *Imitation.* The learner reproduces the rule from the log.
  3. *Conservative learners* at several support thresholds, judged as the offline screen below judges them.
  4. *The reward's loopholes*: one file counted in many sessions, and a policy that never leaves `allow`.
- **Rules v2** (R11). Rules gain conditions on the context: inputs so far, last tactic, `tier`, actor class. A v2 rule set joins `policy/src/mirage_policy/rulesets/`. Phase 2's allow-all set stays as an arm of section 5. **`escalate` is decided here, by rule, for the session.** It is never offered to the learned policy and never explored: it is close to irreversible, and each action kept out of exploration returns effective sample.
- **Context additions:** `tier`; the actor class and its confidence (R15); the responder budget left, in buckets; whether a token has been planted in this session; the previous action; whether this session has already been given a non-allow answer. `last_tactic` no longer comes from the starter rules, which fire on about one input in seven: it is an exact-match lookup of the normalised input in the tagger's index, a file loaded read-only, with a miss reported as unknown. Availability of the responder and the sandbox arrives in `supports`.
- **Mask additions**

  | Action | Allowed only when |
  | --- | --- |
  | `respond` | The request lists it; `tier` is `none`; the session and the source address have budget left |
  | `plant_token` | The request lists it; the reserve holds a token; none was planted in this session |
  | `escalate` | Rules v2 only. The request lists it; the deployment's host tests have passed (a flag set by hand); the session has at least three inputs (a default); the actor class is not `scanner`; the source is a lab address, until the exposure checklist says otherwise |
  | After `escalate` | Only `allow`, `delay` and `terminate`: a faked answer would contradict a real shell |
  | `terminate` | Not on the first input (unchanged) |

  The **eligible set** of a decision is what the mask leaves, without `escalate`. Exploration and the learned policy choose only inside it, and it is logged with the decision.
- **Reward v2** (`intel/reward.py`; v1 stays computable for comparison). Phase 2's terms, plus −0.002 per generated output token and −1 per escalation (defaults). Four fixes:
  - a captured file is paid once per content hash across the whole campaign, not once per session;
  - a token the policy itself planted in the session is a separate component, paid +1 where a token the attacker found unaided is paid +3 (a default), so the policy is not paid in full for something it placed;
  - the −2 for a session that ends right after a non-allow action stays as a component, and every result is also given without it: a session's end is a weak sign of detection, since most scripted sessions end at the same command whatever the decoy answers;
  - every result gives the components as a vector beside the scalar.

  In the lab the reward is also computed from ground truth, and the difference reported, as before.
- **Exploration campaign** (R12). In 198.19.0.0/17 the behaviour policy is rules v2 with ε = 0.3 over the eligible set. The exploration share is not spread evenly: two thirds of it goes to `respond` and `plant_token` where they are eligible, and the four older actions share the rest (a default). The checks above showed the older actions only cost on scripted traffic, and a learned policy can win only through the new ones; the older ones keep a floor so that they stay measurable where attackers react differently. About 1,200 sessions (a default: with up to seven eligible actions, that makes an improvement of 0.2 per decision detectable for a policy that leaves the rule on about a seventh of decisions). Before the campaign, a fifth of the scenario groups is set aside by seed for selection. The calibration checks of Gate 2 test 8 are run again on these logs. The scenarios are phase 2's and the dev half of the depth scenarios, never the depth test half.
- **Join health under exploration.** In phase 2's explore run eleven steps did not join cleanly, and each turned out to be an explored action at work: a `fake_error` on the statement a MySQL driver sends while connecting made the runner report a failed login the decoy had accepted, and a `terminate` closed a Redis connection before the next command was sent. The join learns both cases from the applied decisions: a step that follows a `terminate` on its connection is `not_delivered`, and a step whose own decisions include an altering action is `altered`. Both are counted and reported apart. Any other `no_event` or `mismatch` in the explore or act range fails the campaign, as it does in the capture range.
- **Training.** Offline. A small learner that leaves the rule's action only where the data support it, with the support threshold as the dial: phase 2's per-context table with a threshold, and a linear model that leaves the rule only when the lower end of its estimate is above the rule's. Vowpal Wabbit stays as a comparison. The learner and its threshold are chosen on phase 2's decisions and on the selection fifth, and named in writing before the rest is read. The model file is loaded read-only. No online updates in this phase.
- **Offline screen** (was "off-policy gate"), on the four fifths not used for selection, cross-fitted by scenario group so that every session is scored by a model that did not see it. All three must hold:
  1. The support check passes: the target puts no weight on an action the log gave zero probability in that context.
  2. The effective sample size is at least 200 (a default). It is reported per decision and per session, with the share of all weight carried by the ten heaviest sessions.
  3. The doubly robust estimate of the candidate's value minus rules v2's, computed as one difference per session, has a 95% interval above zero under the session bootstrap and under an exact interval, and the wider of the two decides. The inverse-propensity and self-normalised estimates agree in sign. The candidate and the rules are scored with the same exploration share: phase 2 scored the rules without it, which charged every learned policy 0.08 per decision before its choices were looked at. The same difference against the phase 2 rules is reported.

  Passing the screen allows the randomised comparison and nothing more.
- **The deciding test** (was "acting"). In 198.19.128.0/17 (R13) whole sessions are randomised between rules v2 and the frozen candidate, paired by scenario and seed, 500 sessions in each arm (a default: enough to detect a difference of 0.2 in a session's value). Both arms keep ε = 0.1 over the eligible set and log exact probabilities, so the logs stay usable. The candidate passes if the difference in mean session value has a 95% interval above zero, bootstrapped over scenarios; the component vector and the result without the −2 are given beside it.
- **Does the screen predict the test?** For every candidate that reaches the act range the offline estimate and the randomised result are reported side by side. On real traffic there will be no randomised arm, so this is the only measure of how far the screen can be trusted there.

**Must not:** act on an address outside the lab ranges under any setting; choose a masked action; explore or learn `escalate`; call anything from the policy service; update a model online; name a candidate after the evaluation sessions have been read.

### 3.4 Fingerprint regression suite

`eval/probes/`, `make probe`, and a CI job `probe-suite` that runs on every release tag and on changes under `decoys/`, `responder/` and `policy/`.

| Group | Checks |
| --- | --- |
| Default tells | Phase 1's 32 checks, unchanged |
| Transport | S3's probes as checks: KEXINIT padding, no KEXINIT before identification, HASSH-server against the reference, the `SSH-2.2` client, error line endings |
| Emulator fidelity | A fixed list of ordinary commands run on the decoy and on the reference host and compared by the fidelity check. It includes the two Cowrie behaviours phase 1 found: `ls` over several directories prints no headers, and globs are not expanded. |
| Responder consistency | S2's three wrong answers as fixed checks. The same cacheable command twice gives the same answer. The state round trips of 3.1. |
| Response time | By command class, the decoy against the reference host, measured from inside the lab network in one run so that network cost cancels. Thirty samples each. Pass when the decoy's median is within a factor of two of the reference's, or within 30 ms of it (defaults). The live-model rung is measured and reported, not gated. |
| Fleet | Two deployments with different seeds differ where two real hosts differ, and agree where two real hosts of one image agree |

**Known gaps** live in `eval/probes/known_gaps.yaml`: a check ID, a reason and the decision that owns it. A failing check that is not listed fails the run. A listed check that passes also fails the run until its entry is removed, so the list cannot go stale.

**Emulator fixes.** The fidelity group's failures are ranked by how often the command appears in the corpus. Cheap ones are fixed in the fork, output-only ones move to the render library, and the rest are listed.

**Where this stands (17 November 2026):** the suite is built and has been run on the lab host; the responder-consistency group waits for the responder, and spike S4 is not run.

- **How it runs.** `make probe` starts a real reference host (arm R) and a second decoy from another seed, and runs the suite from a container on the lab network, where the decoy and the reference host are each one proxy away. Everything that needs a real host is compared in that one run, from that one place. The prober announces a documentation-range source, so the label join never takes it for a simulated actor. The report is JSON (`make probe-report`).
- **Six groups, 264 checks; 254 pass and 10 are listed gaps** (17 November 2026, lab host). Default tells (51), transport (23: S3's probes, decoy against reference, item by item), emulator fidelity (126 ordinary commands, each sent to both hosts), response time (11 timed commands, 30 runs each on both hosts, alternately), the render library (32) and the fleet (24: what two deployments must differ in and agree on, asked of two running decoys).
- **The fidelity check alone is too loose for an emulator.** It passes `ls -l` with dates in another format and `id nobody` with the wrong group. So a command in the list may also be `exact` (the two answers are the same line for line once numbers, dates and addresses are masked: 81 of the 126) or name patterns the two must agree on. The reference host carries the decoy's own profile, which is what makes line-for-line comparison possible.
- **What the first run found, and what was done.** Each is a fork patch (0011 to 0016) with tests; the fork's CI job, rehearsed on a clean clone of the pinned release, passes all its tests with the series applied.

  | Found | Cause | Now |
  | --- | --- | --- |
  | `ssh host command` took 200 to 280 ms; the real host takes 5 to 14 | Upstream Cowrie, with a contents directory set, deep-copies the whole filesystem tree and walks that directory for every session; an exec request is a session | The marked tree is made once and shared (0011) |
  | A further 40 ms on every command without a pty | Nagle with delayed ACK: the emulator answers in several writes | `TCP_NODELAY` on every connection (0014) |
  | A session's first write took 137 ms more | The whole tree (50,712 nodes) was copied | Only the path written is copied; a session owns exactly the nodes it can change (0014) |
  | An exec request's output and close came before the reply to the request | The command ran inside the request. The policy gate's round trip had hidden it; it is what stock Cowrie does, and why its exec sessions ended in the depth baseline | The command starts on the next turn (0016); a default-tell check holds it |
  | `SSH-2.2` refused; error lines ended in LF, or had a line ending where OpenSSH has none | Twisted's version list; Cowrie's strings | As OpenSSH 9.2p1 (0012) |
  | `ls` printed columns with no terminal, no header for several directories, ISO dates, link count 1, no total | Stock `ls` | Rewritten from the real host's answers (0013) |
  | `*`, `?` and `[...]` were not expanded; `~` neither | Upstream leaves it to each command | The shell expands them (0013) |
  | `id -u`, `wc FILE`, `who`, `env`, `which`, `grep -c` and most of `grep` were wrong; `sort`, `stat`, `type`, `command -v` did not exist | Stock commands | Rewritten or added (0013, 0014) |
  | `ps` printed one fixed list on every decoy, with a `mysqld`, under headers no `ps` has | Stock `ps` | The deployment's own list: the hardware class's record of a booted machine, plus the profile's services with the figures recorded on the reference image, plus the session's own processes; procps's formats (0015) |
  | `bin -> /usr/bin` where a real host shows `bin -> usr/bin` | Cowrie's `createfs` records where a link ends up | The builder gives 596 links their own text; the fork reads a relative link from its own directory (0014, 0015) |
  | Every session was told the host's address was `192.168.0.1` | Cowrie's fallback when it finds no route out, which a contained decoy never has | The profile's address is set |
  | The host public key files had the image's sizes and nothing in them, and the server presented keys made up at start | The image's key files are secrets and were left out; Cowrie generates its own | The profile mints the three keys from its seed, the server serves from the files `cat` shows, and a default-tell check holds the two together |
| `/proc/sys/kernel/random/boot_id` did not exist | The hardware classes did not record `/proc/sys` | Five files of `/proc/sys/kernel` are written from facts the profile holds; the rest of `/proc/sys` is still absent |
| The gate called a program "emulated" whenever its file existed, though nothing emulated it | The lookup returns a stand-in that prints "cannot execute binary file" | Tier `none`, so that rules v2 can send it to the responder (0013). A command may also *decline* options it does not implement, with the same effect. |

- **Measured after the fixes:** response time, the decoy's median against the reference's, by class: built-in 8 to 10 ms against 5; file read 10 to 12 against 5 to 6; listing 13 against 8; write 23 against 7; render library 16 to 25 against 9 to 14; a missing command 12 against 6. All eleven are inside the rule (a factor of two, or 30 ms).
- **Known gaps, ten, in the file:** the seven algorithm-list and HASSH checks (only an OpenSSH front end can change them: S4), and three that come from one cause, below.
- **The reference image is a container image, and it shows.** The decoy's files and package list come from `debian:bookworm-slim` with the four services: no init system, no kernel package, no cron. Its process list now comes from a booted machine and shows systemd. `dpkg -l` beside `ps`, or `ls /lib/systemd`, shows the difference. So `dpkg` is deliberately not emulated yet (it would put the two side by side), `crontab -l` cannot be checked (the real host has none), and both are listed as gaps owned by **the reference image's rebase onto an installed system**, which is new work this step found and has not done.

**Spike S4 · OpenSSH front end** (R16; three days; result written to `spikes/README.md`).

A container holding Debian's own `openssh-server`, the reference's package, and no shell or interpreter. It terminates SSH, so everything on the wire up to authentication is OpenSSH's. An authentication module checks passwords against the profile's user database and logs every attempt (user, password, source address and port). Each accepted session is forced into a small static relay, which connects to Cowrie over an internal network, sends the client's real address in a PROXY header, and carries the shell, the exec request or the SFTP subsystem through. Cowrie trusts the relay as it trusts the edge today.

The front end is adopted only if all of these pass:

1. HASSH-server, the `SSH-2.2` probe and the error line endings equal the reference's.
2. Every password attempt is captured with user, password and source, and a failed attempt takes the time the reference takes.
3. Shell, exec and SFTP sessions reach Cowrie, every input has one decision, and the TTY log replays.
4. Window resizing and Ctrl-C work, and added keystroke latency is under 5 ms at p95.
5. The client's own fingerprint is still recorded.
6. There is no path to a real shell: the image has none, and forwarding, agent, X11, tunnels, user environment and rc files are each refused by a test that tries them.
7. Gate 1 passes through the front end.

If it is adopted, a compose service `ssh-front` becomes work package 3.4b and the transport entries leave the known gaps. If not, the failing check is recorded and the gap stays. Either way D12 is closed.

### 3.5 High-interaction escalation (Linux host)

`sandbox/` (broker, sinkhole, image) and a fork patch for the command proxy.

- **Image.** The reference Debian image plus the profile's rendered files: the same users, hostname, file contents and planted tokens as the emulated host. The render library's outputs are installed for commands whose real output would contradict the profile (R18). Built per deployment by the profile generator. It holds no secret other than honeytokens.
- **Lifecycle.** On `escalate` the decoy calls the broker with the session's change journal. The broker creates a sandbox from the image, replays the journal (files, working directory, environment), starts a persistent shell as the session's user and returns a reference. One sandbox per source address. It is destroyed when the SSH session ends, at its lifetime or at its idle limit, and is never reused.
- **Limits** (defaults): 1 CPU, 512 MB of memory, 256 processes, a 512 MB writable layer, 20 minutes of life, 5 minutes idle, two sandboxes at once per host. No capability beyond the runtime's default set, and raw sockets removed; no host mount; no device.
- **Network.** `mirage_sandbox` only. DNS resolves every name to the sinkhole. The sinkhole accepts TCP on every port, records the destination the program intended and the first 4 KiB it sent, answers HTTP with a fixed inert body, and forwards nothing.
- **Command proxy** (R17). After `escalate`, each line, already gated, goes to the broker, and its output streams back. Cowrie's TTY log continues. The unit of decision becomes the line, not the simple command, and the event says so.
- **Telemetry** (R19). Command events as before, marked `tier: sandbox`. At destruction the broker lists what changed in the writable layer: each new or changed regular file becomes a `file_activity` event and goes to the artifact store under its existing rules (named by hash, mode 0400, size caps, never executed). Sinkhole records become `network_activity` events carrying the session ID.

**Acceptance** (Gate 3 test 12):

- Containment, with a positive control. From inside a sandbox the sinkhole answers. The gate, core, decoy and lab networks, the host, the cloud metadata address and the internet do not.
- Limits. A process flood, a memory hog, a disk fill and a busy loop each stop at their limit while the host and a second sandbox stay responsive.
- Hydration. Files created before escalation are present with their contents, modes and owners. The working directory and environment carry over. Hostname and users match the profile.
- Reset. After the session no container, volume or endpoint remains, and a second session from the same address starts clean.
- Broker input. A malformed journal, an oversize one and a path that escapes the root are each refused, and nothing is created.
- Mask. `escalate` is never returned with no sandbox free, for a scanner, before the third input, or with the host flag unset.
- Capture. Every line after escalation has one decision and one command event. The difference listing found a test file. The sinkhole recorded a test connection's intended destination.

The same tests are meant to run in CI under gVisor, which needs no KVM. Step 7 of section 7 confirms that on GitHub's runners before anything depends on it.

**Must not:** forward any packet out of `mirage_sandbox`; take an image, a limit or a network from a request; keep a sandbox after its session; run on a host where these tests have not passed; be reachable from any decoy but the SSH decoy.

### 3.6 Caldera in the lab (Linux host)

- **Server.** apache/caldera 5.3.0, pinned, on the `lab-hi` profile, started on demand.
- **Target.** A lab sandbox with the image and runtime of 3.5, on the `lab-hi` network instead of `mirage_sandbox`. Caldera's agent runs in it and can reach the Caldera server and nothing else.
- **Operations.** Stock Linux abilities from Caldera's own library, selected by ID in `lab/caldera/abilities.yaml`. The file is an allowlist: each entry has been reviewed as harmless in a sandbox with no egress. It holds IDs only; no ability text is copied into this repository.
- **Adapter** (`lab/src/mirage_lab/caldera.py`). After an operation it fetches the event log and writes one ground-truth step record per link: the technique ID from `attack_metadata`; the tactic derived from the technique through the pinned ATT&CK v20.1 file, because Caldera's tactic strings are free text and predate the v19 split; times from the delegated and finished timestamps; the status; the hash of the executed command; source `caldera`.
- **Join.** The phase 2 join, with the sandbox's process-trace events as the captured side and the same health rule: zero `no_event` and zero `mismatch`. If the runtime offers no process tracing on the host, 3.6 is blocked and says so. Joining Caldera's record to itself would prove nothing.
- **Split.** An ability is a procedure. Abilities are assigned to train, dev and test in `eval/split.yaml` by ID and pass the same content check.

**Acceptance** (Gate 3 test 13): an operation of at least ten abilities converts with every link accounted for as ran, failed or skipped; join health is zero; no ability outside the allowlist ran; Caldera is unreachable from every network but `lab-hi`.

### 3.7 Tagger v1

- **Incumbent.** The phase 2 tagger as it stands at Gate 2: nearest neighbour over the training procedures and Atomic Red Team's Linux tests, embedded with SecureShellBert. Held-out technique micro-F1 0.212 (0.067 to 0.346); the figure it was selected on was 0.405.
- **Candidates** (R21). A small encoder (110 to 150 million parameters, from the candidates in the AI/ML design, licence checked at download), fine-tuned for the techniques that have training procedures. The linear model on character n-grams that phase 2 measured (0.360 on dev) is rerun as the cheap comparison. Phase 2's experiment found that more labelled procedures helped more than any change of model, so the data line below matters more than the candidate.
- **Data.** The `steps` table's train split and the Atomic Red Team text, plus Caldera's train-side steps once 3.6 exists. Dev sets the abstention threshold and stops training. Test is read only by the harness, and it has now been read once for the incumbent: a candidate chosen by looking at it is not a held-out result.
- **As a system.** The candidate alone against the incumbent alone. Phase 2 measured the starter rules in front of the model and they made it worse, so they are not a layer; that comparison is rerun only if offensive rules are added.
- **Reported.** The table of 2.4 (micro- and macro-F1, exact and with sub-techniques folded, abstention, by source, unseen techniques apart), with intervals. The encoder is trained from five seeds and the mean and spread are given, because fine-tuning on this little data is unstable.
- **Promotion.** A candidate replaces the incumbent only if the system's held-out micro-F1 is higher by more than the interval and per-session tactic precision does not fall. Otherwise the incumbent stays and the report says by how much the candidate lost.
- **Serving.** A promoted model runs in the tagger worker. The policy service's in-process rules do not change (phase 2, Q12).

### 3.8 Demo 3

Scenarios in `lab/scenarios/demo/`, in capture mode, under rules v2.

| Part | The simulated attacker | Asserted |
| --- | --- | --- |
| 3a · Hands-on intruder (laptop and CI, `replay` backend) | Logs in over SSH with a guessed password and works at human pace. Surveys the host with commands from the render inventory. Runs one command nothing but the model can answer. Writes a file with a command the emulator lacks, then lists it and reads it back with emulated ones. Looks for credentials, finds the file the policy plants, and later uses that credential on MySQL from a second address. | No inventory command gets "command not found". One decision per input and no fallbacks. At least one answer from each of the render library and the responder, each with its record. The written file is listed and read back. A `plant_token` decision, an exposure of that token, then `token.triggered`; both sessions under one actor. The tactic set fixed when the scenario is loaded against ATT&CK v20.1. One alert naming both sessions. |
| 3b · Escalation (Linux host) | The same intruder carries on. The policy escalates once the session has shown hands-on behaviour. The intruder writes an inert script from the catalogue onto the host, line by line, and runs it; it writes a file and tries one outbound connection to a documentation address. | An escalation record. A file created before escalation exists in the sandbox. Every later line has a decision and a command event. The script's file is an indexed artifact. The sinkhole recorded the intended destination, and nothing left `mirage_sandbox`. The sandbox is gone when the session ends. |

**What the brief fixes** (17 November 2026). The scenarios are written from [a brief](handoffs/phase-3-demo-3.md) before most of what they exercise exists, so the brief had to settle these, and the steps that build them have to honour them:

- **A set of its own, in no split** (3.0). Its steps are neither training nor evaluation data.
- **Two inputs go to the model and no others** (steps 4 and 5). Under rules v2 every unknown command is sent to the responder, and `replay` fails on a request it has no recording for. So every line of 3a but two is one simple command that the emulator or the render library answers, and the two are recorded once the scenario's text is final. Every slot of that session is pinned, because a recording is keyed on the whole request.
- **What is planted, and where** (step 6). The reserve holds a database credential for an account named `dbbackup`, which the MySQL decoy accepts from the start and which may read the customer table. `plant_token` writes it as a MariaDB client option file in the home directory of the session's account (`/root/.my.cnf` in the demo), a conventional path that an intruder looks at unprompted. It is not planted where the session has already listed the directory: a file that appears between two listings is a tell. The scenario keeps out of that directory until after its first credential-seeking input, and that input is not itself the read of the file, so the demo holds whether the file is written before the triggering command is answered or after.
- **Rules v2 must recognise the demo's credential search** (steps 4 and 6). `last_tactic` is an exact match in the tagger's index, and procedures in no split are not in that index. The default (section 11): the serving index takes the demo set in, as it already holds the phase 2 demos' procedures, and the tagger that is evaluated is still built from the frozen dataset alone. The same choice decides whether the tactic assertion can pass.
- **3b's script is typed, not uploaded.** An `upload` procedure sends random bytes, which cannot run.
- **When the escalation comes** (step 9). The mask forbids it before the third input. 3b creates its first file within its first two inputs, and its script starts at the eighth input at the earliest, so on the host rules v2 must escalate a hands-on session between its third input and its seventh.
- **What is checked on a real host.** 3a's first session up to the credential search, and all of 3b, are run against the reference container before the recordings are made, as the depth scenarios were. The steps that depend on the planted file cannot be.

## 5. What the two measurements mean

Most of Gate 3 rests on two measurements. Both are easy to make look good.

### The fidelity check

One tool, used three times: on render-library entries (3.2a), on the emulator (3.4) and on a sample of live answers (3.2c). It compares a candidate output with what the reference host printed for the same command.

1. The exit codes are equal.
2. The same streams are used: output on stdout, stderr, both or neither.
3. After masking variable fields, the outputs have the same shape. The mask is the normaliser the split's content check already uses (addresses, hosts, hex strings, numbers, generated names), extended with dates and sizes. For `key: value` output, the same keys in the same order. For a table, the same header and column count. For an error, or any answer that is a message on stderr alone, the same text. For free text, the same line count within a tolerance.
4. Facts the profile fixes agree with the profile (hostname, distribution, kernel, users), and facts the hardware class fixes agree with the class.

It compares structure, not text. It can say an answer has the wrong shape. It cannot say that a well-shaped answer is true: rule 4 covers the facts we know, and nothing covers the rest. That is why a person reviews every library entry, and why live answers are sampled and their pass rate reported rather than assumed.

The commands run on the reference host for this check are the ordinary administrative commands of the inventory and the probe list. Each runs in a throwaway reference container with no egress.

### The technique-depth comparison

1. **Depth scenarios.** Scenarios in which later steps depend on what earlier ones printed, through the `expect` and `on_fail` reactions phase 2 built. At least 24 (a default), written from the handoff brief, split into dev and test by procedure under the rules of [phase 2, section 5](05-phase-2-spec.md#5-what-held-out-means). The test half is frozen before responder work starts and is read only by the harness.
2. **Checks must hold on a real host** (R20). Every depth scenario is run against arm R before the freeze. A step whose check fails there is fixed or removed.
3. **Arms.** The same scenarios and seeds on each.

   | Arm | What answers |
   | --- | --- |
   | A · Stock Cowrie | Unpatched Cowrie with its stock configuration, the negative control Gate 1 already uses |
   | B · Phase 2 stack | The fork, the profile, the allow-all rules |
   | C · Adaptive, rules v2 | Render library and responder under rules v2 (`replay` in CI; the live model for the reported run) |
   | D · Adaptive, learned policy | As C, with the learned policy acting; only if it passed the offline screen and the randomised comparison |
   | R · Reference host | A real Debian container from the reference image, recreated for every scenario, on an internal network. The ceiling. |

4. **Metric.** Per session, the number of distinct ground-truth techniques among the steps the runner recorded as succeeded. It comes from the runner's own records, so it is measured the same way on every arm, including the two that have no gate and no label join. Also reported: steps succeeded per session, the step at which each session ended, and each arm's mean as a share of arm R's.
5. **Statistics.** Paired by scenario and seed, bootstrapped over scenarios, with a 95% interval on the mean difference.
6. **Leak guards.**
   - Every render-library entry names its inventory source: a count in the corpus sample, in dev-split runs, or both. An entry with neither fails the build, so the library cannot be filled from the test scenarios (R5).
   - The prompt, the class table and the library are versioned, and the result names all three. A change to any of them after test results have been seen is a new run, and both runs are reported.
   - Recordings for the test half are made once, after the freeze.
   - The phase 2 lint still applies to every input.

**What this does not show.** The attacker is our script and its reactions are our model of an attacker. Arm R is a ceiling for our scenarios, not for realism. A better number here means our scripted attacker got further, which is necessary for the claim that real attackers will and is not evidence of it. That needs real traffic, which needs the external sensor.

## 6. Gate 3

Tests 1 to 11 are the core. Tests 12 to 14 need the Linux host (R2).

| # | Test | Asserts |
| --- | --- | --- |
| 1 | Contract v2 and failure | Each new action is carried out on SSH. With the responder stopped, slow, over budget or replying nonsense, the emulator answers and a fallback is recorded; the same for the broker. A decoy that sends no `supports` never receives a v2 action. |
| 2 | Containment, extended | From a decoy only the three gate ports answer. The responder reaches only its backend. The model server has no egress. Without `llm-dev`, nothing on the gate network has a route to the host. `llm-dev` and `lab` refuse to start beside a published edge. |
| 3 | Render library | Every entry passes the fidelity check and names its inventory source. Output is byte-identical per seed. Inventory commands are answered with the policy service and the responder stopped. Coverage is reported on the corpus and on the held-out scenarios. |
| 4 | State | 3.1's round trips, property test and rejection cases. Over the lab runs behind this gate's numbers, zero state disagreements: no applied operation whose effect the emulator's filesystem does not show. |
| 5 | Responder safety | Every budget is enforced. The injection set yields no prompt text, no marker word and no invalid operation. `replay` is deterministic and fails on an unrecorded request. |
| 6 | Live model, reported | Median and p95 time to first line and total time, by command class. Tokens and cost per session. Share of inputs answered by each rung. Cache hit rate. Live fidelity rate. The model comparison. Measured on the laptop, and on the host when test 14 runs. |
| 7 | Probe suite | Every check passes or is in the known-gaps file, and no listed gap passes. S2's three errors pass as checks. The response-time checks pass for the emulator and render-library rungs. |
| 8 | Depth | On the held-out depth scenarios, arm C minus arm A has a 95% interval above zero. Arms B, D (if it exists) and R are reported. Every scenario's checks pass on arm R. |
| 9 | Bandit | The campaign reaches its size and passes the calibration checks of Gate 2 test 8 for the new action set. The candidate was named before its evaluation sessions were read, and the offline screen's three conditions hold. In randomised sessions in the act range the learned policy is better than rules v2 by more than its interval. The screen's estimate is reported beside that result. No masked action was taken, `escalate` was chosen only by rule, and only the rules acted outside the lab ranges. |
| 10 | Demo 3a, live in CI | The assertions of 3.8 |
| 11 | Earlier gates, and tagger v1 | Gates 1 and 2 pass with phase 3 running, including the 20 ms gating latency (responder time is measured apart). Tagger v1 is reported against the incumbent on the held-out split, and promoted only if it won. |
| 12 | Sandbox (host) | 3.5's acceptance list |
| 13 | Caldera (host) | 3.6's acceptance |
| 14 | Demo 3b and host numbers (host) | The assertions of 3.8. Test 6's numbers measured on the host's GPU. |

Notes:

- Test 6 and the tagger half of test 11 report; they set no threshold. A latency target chosen now would be a guess, and the build plan's Gate 3 asks for the numbers, not for a value.
- "Cost per session" is output tokens, and GPU seconds multiplied by the host's hourly price where it has one.
- Test 9 asks the learned policy to pass the offline screen and then to beat rules v2 in randomised sessions (decided 15 November 2026, from the survey). If it does not, the gate does not pass on this test until the policy improves or the test is consciously changed, with the result written down either way. Not beating the rules is the common result in the published work and is a finding, not a failure to hide.
- Test 8 compares rules v2, not the bandit, with stock Cowrie, so the headline does not depend on test 9.

## 7. Order of work

| Step | Work | Why here |
| --- | --- | --- |
| 1 | 3.0: `phase-2` merged; the handoff brief; the depth split and the lint's run-safety rules; depth scenarios written, checked on arm R and frozen; arms A, B and R on `lab-edge`; the baseline committed | The "before" number and the frozen test must exist before anything is tuned |
| 1b | The survey of 3.3 (R23) and its four checks on phase 2's frozen decisions: both done (15 November 2026) | They needed nothing from this phase, and they decide where step 6's exploration goes |
| 2 | The fidelity check; the inventory; hardware classes; the render library and its fork patch (3.2a); then demo 3's brief and scenarios | The largest gain for the least risk, and it needs no live model (S2's first conclusion) |
| 3 | The probe groups that need no responder: transport, emulator fidelity, response time, fleet; the known-gaps file; spike S4 (3.4) | The emulator audit feeds the library and the fork fixes. D12 closes early, so 3.4b is scheduled or dropped. |
| 4 | Contract v2; the journal, the applier and the `respond` client in the fork; the state manager; the responder on `replay`; rules v2 (3.1, 3.2b) | The service and its safety tests are built against recordings before a live model is in the path |
| 5 | The live backend and `llm-dev`; the bench and the model comparison; recordings, cache and promotion (3.2c); the responder-consistency probes | Needs step 4's service |
| 6 | Reserve tokens and `plant_token`; context and mask additions; reward v2; the campaign; training; the offline screen; the randomised comparison in the act range (3.3) | `respond` must exist before it can be explored. Needs step 1b. |
| 7 | Tagger v1 (3.7) | Independent of the responder; any time after Gate 2's frozen dataset |
| 8 | Demo 3a; the depth comparison; tests 1 to 11 | |
| 9 | Host: confirm gVisor on CI runners; broker, sinkhole, image and command proxy (3.5); Caldera (3.6); demo 3b; host numbers; tests 12 to 14 | Needs the Linux host. The parts of 3.5 that CI can test may start at step 4. |

The build plan's five to six weeks assumed three or four people. Steps 1 to 8 are the core. Step 9 waits for the host and does not hold them up.

## 8. Known limits

| Limit | Consequence |
| --- | --- |
| The attacker in section 5 is our script | The depth number shows our scripted attacker gets further. Whether real attackers stay longer or reveal more needs real traffic. |
| The fidelity check compares shape | A well-formed wrong fact passes unless the profile or the hardware class fixes that fact. Review and sampling cover the rest, imperfectly. |
| A library entry is an exact argv | `ss -tln` is answered and `ss -ltn` is not, though a real `ss` prints the same for both. Each form needs its own record. |
| A library entry was recorded with no terminal | `ss` spreads its columns over the terminal's width. In a window wider than 80 columns a real `ss -tln` is wider than the decoy's. |
| `/proc/stat` after boot is a model | The class recorded its counters at the end of boot. What is added for the time since (nearly all idle, a quiet machine's interrupt rate) is our figures for an idle server, not a record of one. |
| The reference image is a container image | It has no init system, kernel package or cron, while the decoy claims to be a booted server and its process list says so. Found by the fingerprint suite (3.4); the rebase of the image onto an installed system is not done. |
| Processor time in `ps` is a model | Each daemon's time since boot is a steady rate we chose for an idle server, as `/proc/stat` is. The services' memory figures were recorded in the reference container, on the lab machine's kernel. |
| `TCP_NODELAY` on every connection | It removes a 40 ms stall per command. OpenSSH sets it only with a pty, so a packet capture can show smaller segments than sshd would send. Timing was the larger tell. |
| The decoy's boot time has two sources | `uptime` and `/proc` count from Cowrie's own start less a random offset; the nodes in `/dev` are dated from the profile's boot time. The two disagree, and the profile's boot time can fall before the build date of the kernel it claims. Not fixed here. |
| A live answer takes seconds | The model rung is slower than any real command it stands in for. Streaming makes it look like a slow command, not a fast one. The defence is that the rung should be rare, and the share of inputs it answers is reported. |
| The cache repeats a wrong answer consistently | Chosen on purpose: an inconsistent host is the bigger tell. The offline check and the promotion loop are how wrong entries leave. |
| gVisor identifies itself to a program that looks at the kernel | An attacker who checks will know the escalated host is sandboxed (R18). A microVM with the distribution's own kernel removes this where the host has KVM. |
| The command proxy cannot run full-screen programs | Editors and pagers fail in an escalated session as they do in the emulator. Handing over the raw terminal is later work. |
| The offline estimate is a one-step claim | It says what leaving the rules once is worth, not what the learned policy is worth over a session. The randomised comparison measures that, and only in the lab; on real traffic the offline estimate will stand alone, which is why 3.3 reports how well it predicted the randomised result. |
| Off-policy and on-policy results both come from the lab | The bandit is shown to beat the rules against our scenarios' reactions. Rules act on all real traffic through this phase. |
| Caldera's agent runs inside the sandbox, not through a decoy | Its labels describe host telemetry. They help the tagger and test the sandbox's sensors; they say nothing about decoy sessions. |
| Tagger v1 has little data | It may not beat rules plus retrieval, and the gate allows for that (R21) |
| One author still writes the scenarios, their checks and the responder's prompts | Mitigated by the freeze, by arm R and by the corpus-driven inventory; not removed |
| If S4 fails, HASSH-server remains a passive tell | It stays in the known-gaps file and in any claim about detectability (D12) |

## 9. Out of scope

Live generation for HTTP, Redis or MySQL (R22); PostgreSQL; fine-tuning the responder's model; sending attacker input to any model outside the machine; a learned policy acting on non-lab traffic; online updates to the bandit; a sequential (Q-learning) policy and the Gymnasium replay environment of the AI/ML design: logs of this size cannot evaluate one, and [the survey](research/deception-rl.md) (section 5) says what brings it back, which is attackers that react (phase 4's agents) and about ten times the sessions; a learned or explored `escalate`; handing the raw terminal to the sandbox; Windows sandboxes; running captured files anywhere but the session that produced them; prompt-injection classifiers and LLM-agent detection (phase 4); campaign correlation (phase 4); internet exposure, which still waits for the build plan's checklist and a named person.

## 10. Downloads and new dependencies

Nothing here is fetched until approved.

| Item | Size | Licence | Needed for |
| --- | --- | --- | --- |
| Qwen3.5-9B, Q4_K_M | 5.68 GB. On the laptop's disk (S2); not on the lab host, which has to fetch it for the `llama` backend | Apache-2.0 | 3.2 |
| NVIDIA container toolkit | Small (apt packages) | Apache-2.0 | 3.2 on the lab host; installed by `tools/lab-host/install-runtimes.sh`, with `sudo` |
| `llama-server` (llama.cpp) | Installed natively for S2; a GPU container image on the host | MIT | 3.2 |
| A model of about 4B parameters, GGUF, 4-bit | about 2.5 to 3 GB | To be confirmed at download; permissive only | 3.2c |
| An encoder for tagger v1 | about 0.5 GB, unless one of the four embedding models phase 2 fetched to the lab host is used | To be confirmed at download; permissive only | 3.7 |
| torch, transformers | Fetched in phase 2: a research environment on the lab host, with a CUDA build beside it (`make gpu-env`) | BSD, Apache-2.0 | 3.7 |
| gVisor (`runsc`) | about 50 MB (estimate) | Apache-2.0 | 3.5, Linux only; installed by the same script |
| Whatever the survey of 3.3 shortlists (off-policy or offline-RL libraries) | Not known yet | Permissive only | 3.3 |
| A microVM runtime (Kata Containers) | Optional | Apache-2.0 | 3.5, where the host has KVM |
| apache/caldera 5.3.0, full image | Several GB (estimate); about 8 GB of memory to run | Apache-2.0 | 3.6 |
| `openssh-server` from Debian 12 | Already in the reference image | BSD-style | Spike S4 |

The policy image gains no library for the classifier: the forest is plain JSON, scored by shared code (R15). On the laptop the stack and the model do not fit comfortably together ([architecture §9](02-architecture.md#9-memory-budget-on-the-16-gb-laptop)): live development there uses one model slot and no other heavy job, and Caldera never runs on it.

## 11. Decisions needed from you

| Decision | Default if you say nothing |
| --- | --- |
| The lab host's root steps: run `tools/lab-host/install-runtimes.sh` with `sudo` (the NVIDIA container toolkit and gVisor; it restarts Docker) | Until it is run, the core (tests 1 to 11) is built with the model on the laptop or run natively on the host. Tests 12 to 14 stay open and `escalate` stays masked. The host is a desktop on a home network and stays unexposed; a hosted machine would need its provider's written permission for security research. |
| The survey's three scope changes (R23) | Decided on 15 November 2026: all three accepted. |
| D12: run spike S4, and adopt the OpenSSH front end if all seven checks pass | Yes |
| Generation for SSH only in this phase (R22) | As written |
| May a hosted model draft render-library entries? Those prompts hold no attacker input. | No. The local model drafts them; it is slow, and offline that does not matter. |
| Sandbox runtime (R18) | gVisor, and a microVM where the host has KVM |
| The budget and limit numbers in 3.2, 3.3 and 3.5 | As written, revised from measurements |
| Depth scenarios and demo 3 written by the separate tool from a brief, as the phase 2 catalogue was | Yes |
| Demo 3's procedures are in no split. May the tagger's serving index hold them, so that rules v2 recognise the demo's credential search and the demo's tactics can be asserted on the tagger's labels? | Yes, as it holds the phase 2 demos' procedures. The tagger that is evaluated is built from the frozen dataset alone. The alternative is to assert demo 3's tactics on the ground truth and report the tagger's labels beside them. |
| The planted credential of demo 3: the account `dbbackup`, in a MariaDB client option file in the home directory of the session's account | As written (3.8) |
| Gate 3 test 9 requires the learned policy to beat phase 2's rules offline | As written |
| A new line in the build plan's exposure checklist: `escalate` is masked on an exposed sensor until test 12 has passed on that host and a named person has agreed to attacker code running there | Proposed here; not added to the build plan until you agree |
| The downloads in section 10 | Asked again, item by item, when each is first needed |

## 12. Starting point (15 November 2026)

Nothing in this spec is built. This is what it starts from.

| Part | State | Where |
| --- | --- | --- |
| Gate hook and contract v1 | Built. Adds 2.4 ms per command and fails open (S1). | `decoys/ssh/patches/`, `policy/` |
| Filesystem change events | Built in phase 1. The change journal of 3.1 extends them. | `decoys/ssh/patches/0003-…` |
| Model and server | Qwen3.5-9B on the laptop's disk, not yet on the lab host. `llama-server` measured natively on the laptop: 12.5 tokens/s, median 8.6 s per command, about 9 GB (S2). | `data/models/`, `spikes/s2-llm-latency/` |
| Reference host | A Debian 12 image running the four real services, and the facts extracted from it | `decoys/profiles/reference/` |
| Probes | 32 default-tell checks and S3's transport probes; one known gap (HASSH-server) | `eval/probes/` |
| Lab | The runner with reactions, the PROXY relay, four protocol drivers, the label join, 205 procedures, 58 scenarios (8 human-paced twins and 16 generated for coverage among them), a recorder for a real person's session, a frozen split | `lab/`, `eval/split.yaml` |
| Lab host | Ubuntu 24.04, an 8 GB GPU, KVM. The whole stack runs there; PyTorch's CUDA build works from a host environment. Containers cannot use the GPU and there is no sandbox runtime until the root steps of 3.0 are run. | `make gpu-env`, `tools/lab-host/` |
| Frozen dataset and harness | 390 sessions, 1,704 steps and 5,181 logged decisions from one clean collection, with a committed baseline that CI re-scores without a model or a running stack | `eval/datasets/gate2/`, `eval/baselines/gate2.json`, `intel/src/mirage_intel/harness.py` |
| Bandit | Exploring policy with logged probabilities, context (verb classes included), mask, reward-to-go, three estimators, three learner families, and a shadow policy inside the service. No learner beats the rules: −0.164 (−0.509 to +0.107) on held-out sessions. | `policy/src/mirage_policy/{explore,shadow}.py`, `intel/src/mirage_intel/{reward,ope,policylearn}.py`, [the experiment](experiments/phase-2/bandit.md) |
| Classifier | The rule "never held access is a scanner", then a random forest saved as JSON: 0.994 on held-out scenario groups, 0.902 without keystrokes. The human class is the typing generator. | `intel/src/mirage_intel/classifier.py`, [the experiment](experiments/phase-2/classifier.md) |
| Tagger | Nearest neighbour over training procedures and Atomic Red Team, served by a worker: 0.212 on held-out procedures. The starter rules feed only session alerts and the policy's `last_tactic`. | `intel/src/mirage_intel/{tagserve,tag_worker}.py`, [the experiment](experiments/phase-2/tagger.md) |
| Open from phase 2 | No recording of a real person. The tagger is weak on commands it has not seen. The test split has no explicit negative. Eleven of 5,182 explore-run steps did not join cleanly; all were caused by an explored `fake_error` or `terminate`, which was found by hand because the join cannot yet tell that from a capture fault (3.3). The frozen dataset was collected with two lab defects since fixed: one training procedure never ran, and 80 of 354 wrong password guesses were never sent because the driver's list held passwords the decoy accepts. Its labels are true, but the next collection is the first without them. CI on GitHub fails intermittently on one check: on a four-core runner the gate's p95 was 22.1 ms against 20 ms on one run and under it on the next, because phase 2's background workers and the queries they trigger take the cores; the lab host passes. Gate 3 test 11 needs that settled. | [phase 2 spec, section 12](05-phase-2-spec.md) |
