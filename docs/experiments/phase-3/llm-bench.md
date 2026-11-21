# The live model, measured (phase 3, step 5)

17 November 2026, on the lab host. Numbers: [`llm-bench.json`](llm-bench.json).

**What was asked.** How fast is an answer from the model through the whole path (SSH decoy,
policy, responder, model server), and how often would that answer pass for the real host's?

**The answer.** Fast enough: the first byte of an answer arrives 0.59 s after the request at
the median, and the whole answer in 0.81 s. Not right often enough to be trusted by itself:
of 58 answers the model gave, 32 have the real answer's shape and 13 are the real answer.

## Setup

- Model: Qwen3.5-9B, 4-bit (Q4_K_M, 5.68 GB), served by llama.cpp's own CUDA server image in a
  container on the internal model network (`make llm-up`). Reasoning off, flash attention on,
  four slots of 4,096 tokens.
- Hardware: RTX 3060 Ti, 8 GB. The model takes 6.27 GB of it; the server process 1.7 GB of
  memory; the responder 40 MB.
- Path: each command is an exec request over SSH to the decoy, as an attacker would send it.
  The decoy asks the policy, the policy says `respond`, the decoy asks the responder, the
  responder asks the model. Times are taken at the SSH client.
- Commands: [`eval/probes/llm_commands.yaml`](../../../eval/probes/llm_commands.yaml), 63
  commands the emulator has no command class for and the render library no entry for. Each
  was also run on the real reference host, in the same run.
- Two bars. *Passes the check*: the fidelity check the render library's entries pass (same
  exit status, same streams, same shape: lines, columns, keys). *The same as the real host*:
  line for line, once numbers, dates and addresses are masked.
- `make llm-bench` runs all of it. Each pass starts from an empty answer cache.

## One command at a time

| Class | Commands | Answered by the model | Pass the check | Same as the real host | First byte, median (95th) | Whole answer, median (95th) | From the cache | Real host |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| stateless | 34 | 31 | 15 | 4 | 415 ms (2,642) | 791 ms (3,619) | 11 ms | 4 ms |
| state-reading | 19 | 18 | 12 | 4 | 757 ms (2,122) | 816 ms (2,122) | 11 ms | 4 ms |
| state-changing | 10 | 9 | 5 | 5 | 1,253 ms (4,753) | 1,288 ms (4,755) | never cached | 6 ms |
| all | 63 | 58 | 32 (55%) | 13 (22%) | 589 ms (2,642) | 809 ms (3,619) | 11 ms | 4 ms |

The five not answered by the model fell back to the emulator: four answers ran into the
400-token limit (`dpkg -l`, `ldd`, `sshd -T`, `nginx -T`) and one proposed an operation the
contract refuses (`split`).

A prompt is about 980 tokens, of which about 880 are the fixed part the server keeps; an
answer is 58 tokens at the median. Generation runs at about 44 tokens a second.

## Four sessions at once

| Class | Answered by the model | Pass the check | Same as the real host | First byte, median (95th) | Whole answer, median (95th) |
| --- | --- | --- | --- | --- | --- |
| stateless | 28 of 34 | 15 | 6 | 744 ms (2,729) | 1,493 ms (3,694) |
| state-reading | 19 of 19 | 13 | 4 | 1,345 ms (6,686) | 1,619 ms (6,686) |
| state-changing | 10 of 10 | 5 | 5 | 2,203 ms (8,775) | 2,204 ms (8,777) |
| all | 57 of 63 | 33 | 15 | 969 ms (3,762) | 1,502 ms (3,938) |

Six fell back on a deadline (four on the whole answer's 10 s, two on the first line's 1.5 s).

## Against the budgets

| Budget (spec 3.2b) | Measured |
| --- | --- |
| First line within 1.5 s | Median 0.59 s alone, 0.97 s with four at once. The 95th percentile is over it both times (2.6 s and 3.8 s): those answers are aborted and the session gets the emulator's answer |
| Whole answer within 10 s | Never reached alone; four times in 63 with four at once |
| 400 output tokens | Reached by 4 of 63 |

Spike S2 measured the same model on the laptop at a median of 8.6 s per answer and none of
150 under 1.5 s. On this GPU the median answer is ten times faster.

## What the model gets right, and what it does not

**Right** (the same as the real host): `getent passwd root`, `getent group root`, `logname`,
`sysctl vm.swappiness`, `expr`, `numfmt`, `paste`, `comm`, and five of the state-changing lines
(`install -d`, `install -m`, `truncate`, `unlink`, `shred`), where the model's operations
were applied and the emulator's own `ls`, `wc` and `cat` then showed the right thing.

**Wrong, by kind:**

- **Facts the prompt does not hold.** `openssl version` (a plausible version, not this
  host's), `dpkg -s` (one line where the real answer has 49), `apt-cache policy`, `getent hosts`
  (no IPv6 line), `locale -a`, `redis-server --version`. These are the same for every session of
  a deployment and the reference container prints them: they belong in the render library,
  not with a model.
- **Formats it half remembers.** `lastlog`'s header, `chage -l`'s labels, `namei -l`, `nginx -h`,
  `cksum` (one number of two), `factor` (without its `360:`), `od -c` (without the newline it
  was shown).
- **What cannot be known without computing.** `b2sum`, `sum`, a key's fingerprint.
- **What the operations cannot say.** A FIFO, a hard link, a compressed file, a generated key:
  the vocabulary has `mkdir` and `write`, so `mkfifo` made a directory.
- **Nothing at all.** `diff` and `cmp` of two files it was shown, `fold` of piped text it was
  not shown (the request does not carry a pipe's input).
- **A terminal that is not there.** `tty` said `/dev/pts/0` although the prompt says the command
  was not typed at one.

## Two prompt versions

The first full run used the prompt as written before any live answer had been seen; 42 of 59
commands were answered by the model, 20 passed the check and 10 were the real host's. Reading
the model's raw text against the prompt it had been given showed three faults of ours:

| What the prompt did | What the model did with it | Change |
| --- | --- | --- |
| Listed every bare argument as a path: "`/root/kernel.ostype`: does not exist" for `sysctl kernel.ostype` | Answered with an error | A bare word that is no file in the working directory is not listed; the directory's own listing is |
| Said what a program that is not installed prints | Answered "command not found" for `lastlog`, `update-alternatives`, `od` | The decoy only asks about programs that are there, and the prompt now says so |
| "Do not invent ... files that are not given" | Printed nothing for `dpkg -s`, `nginx -T` | "Do not answer with nothing because a detail was not given" |

Also: the model wrote a mode as `750` and meant octal; the contract read a number. Modes are
octal digits in a string to the model now, and numbers in the contract as before.

With these (prompt version 3) and a list without the eleven commands stock Cowrie turned out
to emulate, 58 of 63 are answered by the model, 32 pass and 13 are the real host's. More
commands get an answer of the right shape; the share that is exactly right did not move
(24% then, 22% now). That share is the model's, not the prompt's.

## The same command twice

Of the 63, 55 gave the same answer when sent again in the same login. 38 of those came from
the cache. Of the 20 that went to the model a second time (state-changing commands, and
commands with no class, are never cached), 8 came back different: `tty`, `factor`, `sum`,
`b2sum`, `install -m`, `gzip`, `ssh-keygen`, `link`. The seed is the same both times (it is
derived from the deployment, the command and the state), so the spec's assumption that a
repeat "still gives the same answer" does not hold on this server at temperature 0.2 with
four slots. A command that answers differently twice is a tell.

**Where the difference comes from (18 November).** Not the temperature: the server answering
several requests at once. 200 held-out rows were each put twice with the same seed
(`mirage_responder.score --twice`):

| | Temperature 0.2 | Temperature 0 |
| --- | --- | --- |
| Four requests at once: the second answer the same | 127 of 200 | 147 of 200 |
| One request at a time (100 rows) | 100 of 100 | 100 of 100 |
| The real host's answer (four at once) | 17 | 15 |

Alone, a seed fixes the answer at either temperature. With four slots the answers of one
batch are computed together and differ in the last digits, enough to tip a token.
Temperature 0 narrows it and does not close it, and gains nothing in accuracy, so the
setting stays at 0.2 and four slots. What makes repeats agree is not the seed: it is the
session's own memory of what it was told, and the cache.

## The injection set, live

`make llm-inject`: the 20 hostile inputs of `eval/probes/injection.yaml` put to this model
through the responder's own code path. 17 were answered in character (as a command that
failed, mostly: "helpdesk: command not found"), 3 were aborted by the responder's checks (two
replies that addressed the user, one that put operations on a reading command). No reply
carried prompt text or a marker word, and no operation came back that the contract refuses.

## The 9B model against the 4B

Spec 3.2c asks for the 9B model against one of about 4B, on the same commands: "fidelity
decides first, speed second". The 4B is the same family one size down
(`unsloth/Qwen3.5-4B-GGUF`, Q4_K_M, 2.74 GB, Apache-2.0), so that size is the only thing
compared. Both were run in the same state, later the same evening: the five commands promoted
to the render library are answered there (they count as not the model's), and a session's
own answers are kept for it.

| | 9B | 4B |
| --- | --- | --- |
| GPU memory | 6.3 GB | 4.0 GB |
| Generation, by the server's own count | 44 tokens/s | 80 tokens/s |
| Answered by the model, of the 58 commands that reach it | 53 | 44 |
| Pass the check | 29 | 20 |
| Same as the real host | 12 | 7 |
| First byte, median (95th) | 648 ms (2,121) | 930 ms (4,907) |
| Whole answer, median (95th) | 838 ms (3,575) | 1,065 ms (2,844) |
| Fallbacks, one at a time | 5 (4 over the token limit, 1 refused operation) | 14 (11 on a deadline) |
| With four sessions at once: answered by the model | 51 | 36 (18 fell back on the first line's deadline) |
| Injection set: answered in character / aborted / broke a rule | 17 / 3 / 0 | 15 / 5 / 0 |

**The 9B stays** (and stayed after the 4B was tuned: see "What follows", 4). The 4B is right less often (7 of 44 against 12 of 53), and what it gets
wrong is further off: `factor 360` as "360 = 2^3 * 3^2", `mariadb --version` with a "Red Hat
License", `namei -l` answered with the output of `stat`. It also answered fewer commands in
time, though it generates nearly twice as fast: five of its raw answers, read afterwards, were
neither slow nor padded, so the deadlines it missed in the bench are not explained yet. A
smaller model as it comes is not an improvement on any count that matters here.

## What follows

1. **Stateless commands the model gets wrong go to the render library, where their answer
   is a fact of the image.** Done once the same evening (`make render-candidates`): of 20
   cached stateless answers, 18 were not the real host's and were evicted. Only 5 of the 20
   commands could become fixed entries; the rest answer from the deployment's own accounts
   and files (`getent`, `chage`, `lastlog`) or the session's variables (`locale`), and belong
   in the emulator.
2. **The cache keeps a wrong answer.** `locale` was answered wrongly once and then served
   from the cache in 11 ms for the rest of the run. Cached answers have to be held to the
   offline check and evicted when they fail (spec 3.2b, "promotion"); that is not built yet.
3. **Repeats must agree.** Done for a session: its own answers are kept for it, by command
   and state. Across sessions the cache does it for two classes only; temperature 0 is
   untried.
4. **Fine-tuning.** Done on 18 November: [the write-up](lora-v1.md). A tuned 4B gives the
   real host's answer for 42 of 162 held-out commands against the stock 9B's 5, and ties it
   on this bench (11 of 47 against 10 of 45, on the 55 commands left after `getent` and
   `tty` went to the emulator), but it stopped proposing file operations, because no
   training row changes a file. The stock 9B stays; no second round.
5. **Whether an answer that is right half the time is better than the emulator's "cannot
   execute binary file"** is not a question this bench answers. The depth comparison (Gate 3)
   does: it measures how far a scripted attacker gets with each.
