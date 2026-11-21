"""Train a LoRA adapter on the tuning set (phase 3, step 5b), on one GPU.

One file with no imports from this repository, so that it runs as a Kaggle script kernel
exactly as it runs anywhere else:

    python train_lora.py --data DIR --out DIR [--max-train 200 --max-steps 40 ...]

On Kaggle it finds its data under /kaggle/input and writes to /kaggle/working, and takes
its settings from the JSON file ``run.json`` in the dataset (the same names as the options
below), so that one kernel serves the short trial and the real run.

What it does, and why this way (docs/phase-3-context.md, "Fine-tuning, as researched"):

- A plain 16-bit LoRA on every projection layer of the language model. The publisher of the
  build the stack serves advises against 4-bit training for this family.
- The loss is on the answer alone. A row is 850 tokens of prompt and 60 of answer; with the
  loss on everything the model would be trained to recite the prompt.
- The prompt is rendered by the model's own chat template with thinking off, which is how
  the stack serves it: the answer begins right after the empty think block.
- It measures what nobody publishes for this model at this prompt length: peak GPU memory
  and steps a second. And it ends by generating answers for held-out rows and counting how
  many are the real host's, byte for byte, before and after training.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import subprocess
import sys
import time
from pathlib import Path

ON_KAGGLE = Path("/kaggle/working").is_dir()
TARGETS = ("q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj")


def settings() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="Qwen/Qwen3.5-4B")
    ap.add_argument("--data", type=Path, default=None, help="train.jsonl and val.jsonl")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--max-train", type=int, default=0, help="0: every row")
    ap.add_argument("--max-val", type=int, default=64)
    ap.add_argument("--epochs", type=float, default=2.0)
    ap.add_argument("--max-steps", type=int, default=0, help="optimizer steps; 0: by epochs")
    ap.add_argument("--accumulate", type=int, default=8, help="rows to one optimizer step")
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--max-len", type=int, default=1536, help="tokens; a longer row is left out")
    ap.add_argument("--generate", type=int, default=12, help="held-out rows answered at the end")
    ap.add_argument("--time-limit-s", type=int, default=0, help="stop training after this long")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args([] if ON_KAGGLE else None)
    if ON_KAGGLE:
        found = sorted(Path("/kaggle/input").rglob("train.jsonl"))
        if not found:
            raise SystemExit("no train.jsonl under /kaggle/input")
        args.data, args.out = found[0].parent, Path("/kaggle/working")
        given = args.data / "run.json"
        if given.exists():
            for key, value in json.loads(given.read_text()).items():
                setattr(args, key.replace("-", "_"), value)
    if args.data is None or args.out is None:
        raise SystemExit("--data and --out are needed")
    return args


def say(**facts: object) -> None:
    print(json.dumps(facts), flush=True)


def rows_of(path: Path, limit: int, rng: random.Random) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    rng.shuffle(rows)
    return rows[:limit] if limit else rows


def main() -> None:
    args = settings()
    if ON_KAGGLE:
        # The family needs a recent transformers; what the image carries is not said anywhere.
        pip = [sys.executable, "-m", "pip"]
        subprocess.run(
            [*pip, "install", "-q", "-U", "transformers", "peft", "accelerate"], check=True
        )
        # The image's torchao is older than the adapter library accepts, and the library
        # refuses to make any adapter while it is there (found by the first trial).
        subprocess.run([*pip, "uninstall", "-q", "-y", "torchao"], check=False)
    import peft
    import torch
    import transformers
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForCausalLM, AutoModelForImageTextToText, AutoTokenizer

    rng = random.Random(args.seed)
    torch.manual_seed(args.seed)
    device = torch.device("cuda:0")
    gpu = torch.cuda.get_device_name(0)
    say(
        event="start",
        gpu=gpu,
        gpu_gb=round(torch.cuda.get_device_properties(0).total_memory / 2**30, 1),
        torch=torch.__version__,
        transformers=transformers.__version__,
        peft=peft.__version__,
        settings={k: str(v) for k, v in vars(args).items()},
    )

    tok = AutoTokenizer.from_pretrained(args.base)
    end = "<|im_end|>"

    def encode(row: dict) -> tuple[list[int], list[int]] | None:
        """(input ids, labels): the prompt as the stack serves it, then the answer."""
        prompt = tok.apply_chat_template(
            row["messages"], add_generation_prompt=True, enable_thinking=False, tokenize=False
        )
        head = tok(prompt, add_special_tokens=False)["input_ids"]
        tail = tok(row["answer"] + end, add_special_tokens=False)["input_ids"]
        if len(head) + len(tail) > args.max_len:
            return None
        return head + tail, [-100] * len(head) + tail

    train_rows = rows_of(args.data / "train.jsonl", args.max_train, rng)
    val_rows = rows_of(args.data / "val.jsonl", args.max_val, rng)
    train = [e for e in map(encode, train_rows) if e is not None]
    val = [(r, e) for r, e in ((r, encode(r)) for r in val_rows) if e is not None]
    shown = tok.apply_chat_template(
        train_rows[0]["messages"], add_generation_prompt=True, enable_thinking=False, tokenize=False
    )
    lengths = sorted(len(ids) for ids, _ in train)
    say(
        event="data",
        train=len(train),
        train_left_out=len(train_rows) - len(train),
        val=len(val),
        tokens_median=lengths[len(lengths) // 2],
        tokens_max=lengths[-1],
        prompt_ends=shown[-60:],
        answer_starts=train_rows[0]["answer"][:60],
    )

    # Half precision on a card without bfloat16 (a T4), bfloat16 where there is one.
    dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() and "T4" not in gpu else torch.float16
    began = time.time()
    model = None
    for loader in (AutoModelForCausalLM, AutoModelForImageTextToText):
        # The family is published as one model with a vision tower; which class takes its
        # text half depends on the library's version, so both are tried and the log says.
        try:
            model = loader.from_pretrained(args.base, dtype=dtype)
            break
        except (ValueError, KeyError, TypeError, OSError) as exc:
            say(event="loader_refused", loader=loader.__name__, why=str(exc)[:300])
    if model is None:
        raise SystemExit("no loader took the base model")
    model.to(device)
    say(
        event="loaded",
        seconds=round(time.time() - began),
        cls=type(model).__name__,
        dtype=str(dtype),
        gpu_gb=round(torch.cuda.memory_allocated() / 2**30, 2),
    )

    def answer(row: dict, limit: int = 200) -> str:
        prompt = tok.apply_chat_template(
            row["messages"], add_generation_prompt=True, enable_thinking=False, tokenize=False
        )
        ids = tok(prompt, add_special_tokens=False, return_tensors="pt")["input_ids"].to(device)
        with torch.no_grad(), torch.autocast("cuda", dtype=dtype):
            out = model.generate(ids, max_new_tokens=limit, do_sample=False)
        return tok.decode(out[0, ids.shape[1] :], skip_special_tokens=True).strip()

    def exact(rows: list[dict]) -> tuple[int, list[dict]]:
        right, samples = 0, []
        model.eval()
        for row in rows:
            said = answer(row)
            same = said == row["answer"]
            right += same
            if len(samples) < 4:
                samples.append(
                    {
                        "cmd": row["cmd"],
                        "same": same,
                        "said": said[:300],
                        "real": row["answer"][:300],
                    }
                )
        return right, samples

    held = [r for r, _ in val][: args.generate]
    before, samples = exact(held) if held else (0, [])
    say(event="before", exact=before, of=len(held), samples=samples)

    # Adapters on the language model's projections only: the family carries a vision tower.
    names = [
        name
        for name, module in model.named_modules()
        if isinstance(module, torch.nn.Linear)
        and name.rsplit(".", 1)[-1] in TARGETS
        and "vis" not in name.lower()
    ]
    model = get_peft_model(
        model,
        LoraConfig(
            r=args.rank,
            lora_alpha=args.rank,
            lora_dropout=0.0,
            target_modules=names,
            task_type="CAUSAL_LM",
        ),
    )
    if hasattr(model, "gradient_checkpointing_enable"):
        model.gradient_checkpointing_enable()
    if hasattr(model, "enable_input_require_grads"):
        # With checkpointing and frozen embeddings, nothing entering the first block asks
        # for a gradient, and the adapters behind it would get none.
        model.enable_input_require_grads()
    model.config.use_cache = False
    trainable = [p for p in model.parameters() if p.requires_grad]
    say(
        event="adapters",
        modules=len(names),
        trainable_millions=round(sum(p.numel() for p in trainable) / 1e6, 2),
        adapter_dtype=str(trainable[0].dtype),
    )

    def loss_of(ids: list[int], labels: list[int]) -> torch.Tensor:
        x = torch.tensor([ids], device=device)
        y = torch.tensor([labels], device=device)
        with torch.autocast("cuda", dtype=dtype):
            return model(input_ids=x, labels=y).loss

    def val_loss() -> float:
        model.eval()
        with torch.no_grad():
            losses = [loss_of(*e).item() for _, e in val]
        model.train()
        return round(sum(losses) / max(1, len(losses)), 4)

    steps = args.max_steps or math.ceil(len(train) * args.epochs / args.accumulate)
    opt = torch.optim.AdamW(trainable, lr=args.lr, weight_decay=0.01)
    warm = max(1, steps // 20)
    sched = torch.optim.lr_scheduler.LambdaLR(
        opt,
        lambda s: (s + 1) / warm if s < warm else max(0.0, (steps - s) / max(1, steps - warm)),
    )
    scaler = torch.amp.GradScaler("cuda", enabled=dtype == torch.float16)
    say(event="val", step=0, loss=val_loss())
    torch.cuda.reset_peak_memory_stats()
    model.train()
    order: list[int] = []
    began = time.time()
    seen = 0
    for step in range(1, steps + 1):
        total = 0.0
        for _ in range(args.accumulate):
            if not order:
                order = list(range(len(train)))
                rng.shuffle(order)
            loss = loss_of(*train[order.pop()]) / args.accumulate
            scaler.scale(loss).backward()
            total += loss.item()
            seen += 1
        scaler.unscale_(opt)
        torch.nn.utils.clip_grad_norm_(trainable, 1.0)
        scaler.step(opt)
        scaler.update()
        opt.zero_grad(set_to_none=True)
        sched.step()
        took = time.time() - began
        if step == 1 or step % 10 == 0 or step == steps:
            say(
                event="step",
                step=step,
                of=steps,
                loss=round(total, 4),
                rows_a_second=round(seen / took, 2),
                peak_gpu_gb=round(torch.cuda.max_memory_allocated() / 2**30, 2),
            )
        if step % 100 == 0 or step == steps:
            say(event="val", step=step, loss=val_loss())
        if args.time_limit_s and took > args.time_limit_s:
            say(event="stopped", why="time limit", step=step)
            break

    after, samples = exact(held) if held else (0, [])
    say(event="after", exact=after, of=len(held), before=before, samples=samples)
    out = args.out / "adapter"
    model.save_pretrained(out)
    tok.save_pretrained(out)
    size = sum(f.stat().st_size for f in out.rglob("*") if f.is_file())
    say(event="saved", where=str(out), megabytes=round(size / 2**20, 1))
    (args.out / "done.json").write_text(
        json.dumps({"exact_before": before, "exact_after": after, "of": len(held)})
    )
    if ON_KAGGLE:
        os.sync()


if __name__ == "__main__":
    main()
