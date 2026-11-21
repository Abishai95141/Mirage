# A 4B model tuned on the reference host's answers (phase 3, step 5b)

17 and 18 November 2026. Training log: [`lora-v1-train.jsonl`](lora-v1-train.jsonl). The
owner asked for this experiment; it is not in the spec.

**What was asked.** Does a 4B model, trained on what the reference host really prints, beat
the stock 9B model on commands it was not trained on?

**The answer.** On the held-out rows, clearly: about one answer in four is the real host's,
against one in thirty. On the bench of realistic commands, no: it ties the 9B on answers
(11 of 47 the real host's against 10 of 45) and is worse on commands that change files,
because nothing in the training set changes a file. **The stock 9B stays as the serving
model, and there is no second round**: the tail the model answers is small, and what the
decoy gets wrong there is better moved to the emulator and the render library, where the
answer is exact.

## What was trained

- Base: `Qwen/Qwen3.5-4B`, full precision. A 16-bit LoRA, rank 16, on every projection of the
  language model (128 modules, 21 M parameters), loss on the answer only, the prompt
  rendered by the model's own chat template with thinking off, as the stack serves it.
- Data (`make tune-set`): 4,655 candidate commands of 278 programs the decoy has no
  emulation for, each run three times on a throwaway reference host; 2,210 kept. Train
  1,443 rows of 203 programs; validation 223; held out 162 invocations of trained programs
  and 382 rows of programs never trained on. Most rows are one option of a program, with or
  without a small file (`option`), or an option it does not have (`misuse`); 241 commands
  were written by hand (`seed`). Every row is a read-only command.
- Run: Kaggle, one T4, 2 epochs (360 steps of 8 rows), 3 h 12 min, peak 12.7 GB.
  Validation loss 0.85 before, 0.53, 0.44, 0.42 and 0.41 at the end: still falling slowly.
- Served as the stock 4-bit base with the adapter beside it (`convert_lora_to_gguf.py`, a
  42 MB file, `--lora`; `make tune-score NAME=v1`). No merged model.

## Held-out rows: the real host's answer, exactly

Standard output, standard error and exit status all equal. Scored through the responder's
own request path.

| | Stock 9B | Stock 4B | Tuned 4B |
| --- | --- | --- | --- |
| Other invocations of trained programs (162) | 5 | 2 | **42** |
| Programs never trained on (382) | 27 | 15 | **76** |

By where the row came from, tuned 4B against stock 9B:

| Kind of row | Trained programs | Unseen programs |
| --- | --- | --- |
| An option the program does not have | 9 of 14 (9B: 1) | 19 of 33 (9B: 5) |
| One of its options | 29 of 107 (9B: 4) | 43 of 229 (9B: 13) |
| `--version` | 4 of 18 (9B: 0) | 7 of 35 (9B: 0) |
| `--help` | 0 of 12 (9B: 0) | 0 of 23 (9B: 0) |
| Written by hand | 0 of 11 (9B: 0) | **7 of 62 (9B: 9)** |

The gain is in how Debian's tools refuse and report: the words of an option error, the
`Try '... --help'` line, exit statuses. On hand-written commands for programs it has not
seen, the kind an attacker types, the tuned model is no better than the stock 9B. A help
text is never reproduced by either: it is a fixed text and belongs in the render library.

## The bench: 55 realistic commands through the whole path

The same evening, the same state, the 55 commands of `eval/probes/llm_commands.yaml` (63
before `getent` and `tty` went to the emulator). One command at a time:

| | Stock 9B | Tuned 4B |
| --- | --- | --- |
| Answered by the model | 45 | 47 |
| Pass the fidelity check | 24 | 22 |
| Same as the real host | 10 | 11 |
| of the 26 stateless | 1 of 18 answered | 3 of 19 |
| of the 19 state-reading | 4 of 18 | 6 of 18 |
| of the 10 state-changing | **5 of 9** | **2 of 10** |
| First byte, median | 715 ms | 663 ms |
| Whole answer, median | 912 ms | 718 ms |
| Four sessions at once: answered, whole answer | 44, 1,733 ms | 46, 1,174 ms |
| GPU memory | 6.3 GB | 3.9 GB |
| Injection set: in character / aborted / broke a rule | 17 / 3 / 0 | 18 / 2 / 0 |

**Why it is worse where files change.** Across the ten state-changing commands the stock
9B proposed 26 file operations; the tuned model proposed 5. Every training row is a
read-only command whose answer ends `"ops": []`, so the model learned that nothing ever
changes. `install`, `truncate`, `gzip`, `link` and `shred` were answered as errors or as
done with nothing done. That is a fault of the set, not of the method, and the fix is
known (label state-changing commands by the difference they leave on the host).

## Decision

- **The stock 9B keeps serving.** The bar set beforehand, more real-host answers than the 9B
  on held-out rows, is met; the bench shows a regression the held-out rows could not see,
  on the class where a wrong answer leaves the session's files inconsistent. The adapter is
  kept (`data/models/adapter-v1/` on the lab host; `LLAMA_LORA=`), and so is everything that
  made it.
- **No second round now.** With state-changing rows and more hand-written commands a tuned
  4B would likely pass the 9B at half the memory and three quarters of the time. But in the
  corpus sample the decoy's own emulator already answers about 98% of what is sent, and
  the model, tuned or not, is exactly right on about one answer in four of the rest. Each
  command moved to the emulator or the library is right every time. That is where the
  work goes; whether the model rung stays on at all is for the depth comparison (Gate 3)
  to say.
- **What the experiment leaves behind that is used:** the labelling pipeline (it is how
  any fixed answer can be checked against a real host in bulk), the held-out sets as a
  regression measure for any model, and the scorer.
