#!/usr/bin/env bash
# Spike S2: run llama-server natively on macOS (Metal), bound to loopback only.
# Decoys cannot reach it: the decoy network has no route to the host (containment tests).
set -euo pipefail
cd "$(dirname "$0")/../.."
PORT="${LLM_PORT:-8090}"
MODEL="${MODEL:-data/models/Qwen3.5-9B-Q4_K_M.gguf}"

# -np 4 / -c 16384: four concurrent sessions with 4096 tokens of context each.
# --reasoning off: no hidden thinking tokens; every token generated is terminal output.
exec llama-server \
  -m "$MODEL" \
  --host 127.0.0.1 --port "$PORT" \
  -ngl 99 -fa on \
  -c 16384 -np 4 \
  --reasoning off \
  --no-mmproj \
  --cache-ram 2048 \
  --metrics \
  --no-webui
