# Handoff: the Phase 3 depth scenarios

This is a prompt for the model that writes the offensive content, as
[the phase 2 catalogue brief](phase-2-catalogue.md) was. It defines what a depth scenario is,
the formats, and the rules the content must follow. It does not contain the commands.

The formats are the ones phase 2 built and nothing here changes them: read the catalogue and
scenario formats, the lint's hard rules and the content-safety rules in that brief first. They
all still apply. Validate with `uv run mirage-lab lint lab/scenarios`; it must report zero
problems.

## What the scenarios are for

[Phase 3](../06-phase-3-spec.md) asks one headline question: does a simulated attacker get
further into a decoy that answers like the host it claims to be than into stock Cowrie? "Further"
is counted per session as the number of distinct techniques among the steps that succeeded.

That only means something if getting further depends on the answers. So a depth scenario is a
script whose later steps depend on what earlier ones printed. It checks each answer the way a
careful attacker's tooling does, and it gives up when the host stops making sense.

The same scenarios run, unchanged, against five targets: stock Cowrie, the phase 2 decoy, the
phase 3 decoy under two policies, and a real Debian 12 container (the reference host, the
ceiling). **You are writing against the real host.** You will never see the phase 3 responder,
its prompt or its library of prepared answers, and you must not ask for them: a check written
to match what our own decoy prints would measure agreement with ourselves.

## What to produce

1. **`lab/catalogue/9*-depth-*.yaml`**: the new procedures these scenarios need, in new files.
   Do not edit or remove an existing procedure: the phase 2 split is frozen on their IDs.
2. **`lab/scenarios/depth/*.yaml`**: at least 24 depth scenarios, all SSH.

Do **not** assign a split and do not edit `eval/split.yaml`. The scenarios are divided into a
dev half and a test half afterwards, and the test half is then frozen and read only by the
evaluation harness.

Demo 3 is not part of this brief. It needs the list of commands the phase 3 decoy prepares
answers for, which does not exist yet; it gets its own brief.

## What makes a scenario a depth scenario

- **A chain.** At least eight steps, of which at least five are *gates*: a step with an
  `expect` (or `expect_status` on the `exec` channel) whose failure changes what happens next,
  through `on_fail: leave`, `on_fail: {goto: …}` or by using up the actor's `patience`.
- **Dependence on earlier output.** At least three gates must check something an earlier step
  caused or revealed, not just that a command exists. The kinds that matter:
  - *state*: something written, created, started or changed earlier is there later (a file is
    listed and read back with its content, a directory change holds, a variable set earlier
    is still set, a started process is listed);
  - *consistency*: a fact printed twice by different commands agrees (the host name, the
    kernel, the users, the address, the amount of memory or disk);
  - *exit status*: a command that must fail on a real host fails, and one that must succeed
    succeeds (`exec` channel);
  - *shape*: the output has the structure the real tool prints (a header and columns, `key:
    value` lines), checked loosely enough to hold across machines.
- **Several techniques.** At least four distinct techniques over at least three tactics, placed
  so that later techniques sit behind earlier gates. A scenario where every technique appears
  in the first three steps measures nothing.
- **A plausible attacker.** `scripted_bot` or `human` actors with `patience` between 1 and 3.
  Low patience is the point: an attacker who meets two wrong answers leaves.
- **Different routes.** Use `goto` so that a scenario has a fallback path where a real attacker
  would have one. Do not build a scenario that can only end one way.

Across the set: every tactic the phase 2 catalogue covers should appear behind a gate in at
least two scenarios; no two scenarios should be the same chain with different slot values.

## Rules for the checks

- **Every check must hold on a stock Debian 12 host.** Each scenario is run against the
  reference container before anything else. A step whose check fails there is a broken step
  and is fixed or removed; it is never kept as a "hard" one.
- **Check structure, not exact text.** Write `expect` patterns that a real Debian 12 host
  satisfies on any hardware and at any time: no version numbers beyond what Debian 12 fixes,
  no dates, no sizes, no addresses, no host names. The deployment's host name, users and
  addresses differ per installation and are not known to you.
- **Do not write a check from Cowrie's behaviour**, in either direction: not one that passes
  because Cowrie prints a known string, and not one built to fail on a known Cowrie gap.
  Write what a real host does and let the targets differ on their own.
- **A check may only use what the session itself produced** or what any Debian 12 host has.
  Use `capture` with `password_from` as phase 2's second demo does when a later session needs
  a value an earlier one read.

## What the real host has

The reference container is `debian:bookworm-slim` with `openssh-server`, `nginx`,
`redis-server`, `mariadb-server`, `procps` and `iproute2`, and the files a deployment's
profile renders into it. It has no compiler, no package downloads and **no network egress**:
every outbound connection fails, and a scenario may rely on that failure.

If a scenario needs a tool that image lacks, do not work around it. Name the tool in a comment
at the top of the scenario file. The owner decides whether the reference image gains it, and
it must be something a small Debian web-and-database server plausibly has installed.

## Safety: these inputs really run

In phase 2 nothing was executed: the decoys are emulators. Here every input also runs as root
in a real, throwaway container. It has no egress, tight limits on CPU, memory, processes and
disk, and is destroyed after each scenario. The content-safety rules of the phase 2 brief still
hold, and these are added:

- Nothing that tries to leave the container or reach its host: no kernel exploits, no
  container-escape techniques, no attempts on the runtime's sockets or device files.
- Nothing whose purpose is to exhaust a resource: no process floods, no filling of disks or
  memory, no busy loops.
- Nothing that needs a real remote party to mean anything. Network targets are slot values
  (documentation ranges and reserved names) and the connection is expected to fail.
- Files that stand for tools or malware are random bytes or a harmless script from the
  catalogue. Nothing here is working malware, a working exploit or a real credential.
- A step may change the container freely otherwise (write files, add entries, stop a
  service): it is thrown away. Say in a comment when a step is meant to break something a
  later gate then observes.

## Splitting, and what it asks of you

The halves are made by procedure: two scenarios that share a procedure land in the same half.
So share a depth procedure only between scenarios that belong together, and never use a
procedure from the phase 2 catalogue in a depth scenario (it may be a training procedure).
Leave `login.procedure` unset, so that logins do not tie every scenario to one procedure.

Keep the procedures of one scenario thematically narrow, as before. Aim for two halves that
each cover the tactics above; the owner's tooling does the assignment and will report a
scenario set that cannot be divided.

## When done

`uv run mirage-lab lint lab/scenarios` is clean. The owner then runs every scenario against
the reference container and returns the list of steps whose checks failed there. Fix or remove
those, and only those. After that the split is made, the test half is frozen, and the
"before" numbers are measured on stock Cowrie and the phase 2 decoy.
