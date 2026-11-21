# Experiment: how deep the decoys go today (the depth baseline)

15 November 2026 · [phase 3 spec 3.0, "Baseline"](../../06-phase-3-spec.md) and section 5 · run on the lab host with `make lab-arm ARM=r`, `ARM=a` and `ARM=b`, read with `make arm-report`

## Question

Phase 3 claims it will make the SSH decoy hold up further into an attack. That needs a number from before any of it is built. The same 24 depth scenarios (118 procedures, every step with a check of what came back) are run against three targets:

| Arm | What it is |
| --- | --- |
| R | The reference host: a real Debian 12 container made to look like the profile's host. Inputs really run |
| A | Stock Cowrie 3.1.6, its own configuration, no MIRAGE code |
| B | The stack as it is today: Cowrie with the MIRAGE patches, the profile's filesystem, the policy gate |

A step succeeds when the check on its output passes. A scenario stops sending steps once a route through it is closed, so a failed check early costs every step behind it.

## Result

One run each, seed 1, one session at a time, pauses at a fifth of their written length, 27 sessions (three scenarios have two).

| | R: real host | A: stock Cowrie | B: today's stack |
| --- | --- | --- | --- |
| Steps that succeeded | 280 of 280 | 69 of 280 (25%) | 87 of 280 (31%) |
| Techniques carried out | 153 of 153 | 44 of 153 (29%) | 57 of 153 (37%) |
| Sessions with every check passing | 27 of 27 | 2 of 27 | 2 of 27 |
| Sessions whose connection ended early | 0 | 10 | 0 |

By half of the frozen split:

| | R | A | B |
| --- | --- | --- | --- |
| dev (12 scenarios) | 139 of 139 | 14 of 139 (10%) | 29 of 139 (21%) |
| test (12 scenarios, 15 sessions) | 141 of 141 | 55 of 141 (39%) | 58 of 141 (41%) |

By theme, steps that succeeded:

| Theme | Half | R | A | B |
| --- | --- | --- | --- | --- |
| Covering tracks | test | 40 of 40 | 21 | 12 |
| Credentials | dev | 30 of 30 | 7 | 15 |
| Egress | test | 32 of 32 | 0 | 18 |
| File handling | test | 39 of 39 | 18 | 18 |
| Fingerprinting | dev | 35 of 35 | 2 | 9 |
| Processes | dev | 36 of 36 | 5 | 5 |
| Credential rotation | test | 30 of 30 | 16 | 10 |
| The service stack | dev | 38 of 38 | 0 | 0 |

## What it says

1. **The yardstick is sound.** A real host passes every check of every scenario. No check asks for something a Debian server does not do, which is the condition the spec sets for freezing (R20). The depth split is frozen at this catalogue (`eval/split-depth.yaml`, status `frozen`).

2. **Both decoys stop early.** A scripted attacker gets through a quarter to a third of what it gets through on a real host. Nothing in the service-stack theme works on either.

3. **Today's stack is not deeper than stock Cowrie where the two can be compared.** Its lead in the totals comes from ten sessions in which stock Cowrie's connection ended at the first command sent over an exec channel. On those ten, stock scores 0 of 100 and today's stack 31 of 100. On the other seventeen, stock Cowrie is ahead: 69 of 180 (38%) against 56 of 180 (31%).

   | | A | B |
   | --- | --- | --- |
   | The 17 sessions stock Cowrie carried through | 69 of 180 | 56 of 180 |
   | The 10 sessions it ended at the first exec | 0 of 100 | 31 of 100 |

   Today's stack is behind stock Cowrie in five sessions: all three covering-tracks scenarios (12 steps against 21), and the second session of two rotation scenarios, where it scores 0 of 6 twice and stock scores 5 and 3. It is ahead in nine, seven of them among the ten above.

4. **The halves differ in difficulty.** Dev is much harder than test for both decoys. An improvement has to be read within a half, before against after, never as one half against the other.

## What is and is not established

- **The exec ending.** In the diagnostic run, stock Cowrie's own log shows the command received, found, run with exit code 0 and the channel closed, while the runner's client reports the channel closed without a result for that same step. So stock Cowrie did answer and our client did not accept the answer. The likely cause is the order of two messages (the channel's close arriving before the reply to the request), which the patched build would avoid because its policy gate answers first. That cause is not confirmed. Until it is, the ten sessions measure how stock Cowrie and this client get on, not how much of a host stock Cowrie imitates, and the fair comparison between A and B is the seventeen-session row. An attacker using OpenSSH's own client may see no such failure.
- **Why today's stack was behind in five sessions is now known.** See the next section. One cause was a defect and is fixed; the other is missing depth and stays in the baseline.
- **One run.** Each arm was run once with one seed. The scenarios are scripted and the arms mostly deterministic, but no interval is claimed for these numbers. Gate 3's test 8 needs an interval and gets it from repeated runs of the arms that exist then.
- **A scripted attacker.** The numbers say how far our scripts get. They do not say how long a person or a real bot would stay (spec section 10).

## The five sessions, explained (16 November 2026)

To see what the decoy answered where a check failed, every arm's run now keeps that answer (`make arm-failed ARM=<name>`; the input is not kept). The five scenarios were run again on both decoys that way, into record folders of their own.

**Covering tracks, three sessions: a defect, fixed.** The stack's decoy said `/dev/null` does not exist. Its filesystem is built by walking the reference image's root, and in an image the directories the kernel fills at run time are empty. Compared with stock Cowrie's tree:

| | The stack's tree | Stock Cowrie's |
| --- | --- | --- |
| `/dev` | empty | 15 entries |
| `/proc` | `version` only | 59 entries |
| `/sys` | empty | 9 directories, about 17,500 entries |

The builder (`decoys/ssh/build_fs.py`) now adds the entries every Linux system has in `/dev`, dated at the profile's last boot, and the default-tell probe checks them. A machine's own devices (disks, consoles) are not added: they depend on the hardware, like the contents of `/proc` and `/sys`, and come with the hardware classes of step 2. Until then the probe reports `/proc/cpuinfo`, `/proc/meminfo` and an empty `/sys` as known gaps.

**Rotation, the second session of two scenarios: missing depth, not fixed.** In these scenarios the attacker changes root's password in one session and logs in with the new one in the next. The stack's decoy answers the change as done and then refuses the new password, because it accepts only the passwords its profile lists. Stock Cowrie passes for the wrong reason: it accepts any password for root. In one of the two scenarios its first session had ended early, the attacker had no new password, and it was let in with an empty one. A real host passes because the change is real. Making a password change hold for the actor who made it is state the decoy does not keep yet; it is a requirement for the state manager (spec 3.1).

**The stack measured again with the defect fixed** (same seed, same scenarios, 16 November):

| | A: stock Cowrie | B: as found | B: with `/dev` |
| --- | --- | --- | --- |
| Steps that succeeded | 69 of 280 (25%) | 87 (31%) | 96 (34%) |
| Techniques carried out | 44 of 153 | 57 | 60 |
| The 17 sessions stock Cowrie carried through | 69 of 180 | 56 | 65 |
| The 10 sessions it ended at the first exec | 0 of 100 | 31 | 31 |
| Covering tracks | 21 of 40 | 12 | 21 |
| Test half | 55 of 141 | 58 | 67 |
| Dev half | 14 of 139 | 29 | 29 |

The baseline for phase 3 is the last column: 96 of 280. The three covering-tracks sessions now score exactly what stock Cowrie scores. On the seventeen comparable sessions the stack is 4 steps behind stock, all of it the two rotation sessions (8 behind there, 4 ahead in two credential scenarios).

**What the decoy says where it still fails.** After the fix the stack fails 42 checks in 26 procedures. By what it answered:

| What the decoy answered | Failed checks | Procedures |
| --- | --- | --- |
| "cannot execute binary file" (running a file it was given or a tool it has no emulation for) | 17 | 10 |
| Nothing at all | 17 | 12 |
| An option taken for a file name (`mkdir -p` makes a directory called `-p`) | 3 | 1 |
| An answer of the wrong shape (`sleep … &` read as a bad interval; an outbound `ssh` that shows a host-key prompt with a fixed fingerprint) | 4 | 2 |
| An option it does not know | 1 | 1 |

Stock Cowrie answers the same way on these: they are the emulator's limits, not the stack's. This list is the start of step 2's inventory.

## Hardware classes: giveaways fixed, the score unchanged (16 November 2026)

Step 2 gave the decoy a hardware class: a machine recorded from Debian 12 on real virtual hardware, whose `/proc`, `/sys`, `/dev` and `/boot` the decoy now shows, with `lscpu`, `nproc`, `df` and six more reporting commands printing what that machine printed. The default-tell probe gained twelve checks that these tell one story; all pass on the lab host (45 pass, 0 fail, 1 known gap). One of them found that stock Cowrie's `free` shows the memory of the machine the honeypot runs on; that is fixed in the fork.

The depth scenarios were run again on the stack with its class: **96 of 280, the same as before, session for session.** The scenarios do not fail where the hardware classes help. On the dev half, this is what stops each session at its first failed check:

| What the decoy did | Sessions it stops | Themes |
| --- | --- | --- |
| Printed nothing for a tool it lacks (`ss`, `nginx`, `mysql`, a package query, a user lookup) | 9 of 12 | credentials, fingerprinting, the service stack |
| Read `sleep … &` as a bad interval: its shell has no background jobs | 2 of 12 | processes |
| "cannot execute binary file" for a tool that is in its file tree and not emulated | 1 of 12 | processes |

So the next gain on this measure is in answering the missing tools, which is the render library's serving patch and its entries from the reference container, and in the shell's background jobs, which is emulator work. The hardware classes were needed for what the probe measures and for consistency; they were never going to move this number, and it did not.

## The render library: the first gain, on the dev half only (17 November 2026)

The render library and its serving patch are built ([spec 3.2a](../../06-phase-3-spec.md)): seven commands answered from what real hosts printed. The twelve dev scenarios were run again on the stack with it (`make lab-arm ARM=b ARM_OUT=b-lib ONLY=<scenario>`, library versions as in `build/profile/host.json`). **The test half was not run**: it is read once, for Gate 3, and a look now would make every later change to the library a second run to report.

| Dev half, 12 sessions | Before (hardware classes) | With the render library |
| --- | --- | --- |
| Steps that succeed, of 139 | 29 (21%) | **39 (28%)** |
| Distinct techniques reached, summed over sessions | 16 | **24** |
| Sessions that changed | | 3 of 12 |

The three sessions that moved are the service-stack theme, which is where the library's reference-container entries are:

| Scenario | Steps before | Steps after | Techniques after, of possible | What stops it now |
| --- | --- | --- | --- | --- |
| `depth-stack-listen` | 0 of 13 | 7 | 5 of 7 | A web-server file check prints nothing |
| `depth-stack-web` | 0 of 13 | 2 | 2 of 9 | A check of the site's page prints nothing |
| `depth-stack-db` | 0 of 12 | 1 | 1 of 9 | The database client prints nothing |

The other nine sessions are unchanged, step for step. None of them stops on a command the inventory marks as a library's to answer.

**What stops the dev half now.** Twenty checks fail, in fourteen procedures. By what the decoy answered:

| What the decoy answered | Procedures | What it needs |
| --- | --- | --- |
| Nothing at all (the database and Redis clients, a package query, a user lookup, a file search, a job list, checks of web files) | 10 | Tools that take arguments or read state: the emulator audit (3.4), the state manager (3.1) and the responder |
| "cannot execute binary file" (`stat`, `vmstat`: in the file tree, not emulated) | 3 | `stat` reads the file system, so it is emulator work; `vmstat` changes by the second |
| `sleep … &` read as a bad interval | 1 | Background jobs in the emulator's shell |

**What this says about the plan.** The gain is real and small, and it is where the inventory said it would be. The library's coverage of the held-out half's wrongly answered commands is 0 of 55 (only 3 of them are a library's to answer at all), so the same library should be expected to move the test half very little. Gate 3's depth test will be decided by state and shell behaviour: the credential change that must hold, background jobs, and tools that read the file system.

## What is kept

The runner's records for the three arms are on the lab host's `arm-out` volume, apart from the lab's own, so the label join never sees them. `make arm-report ARM=a` (or `b`, `r`) prints the table's source; `make arm-failed ARM=r` prints the checks that failed on an arm with what the host answered (none on R).
