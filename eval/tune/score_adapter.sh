#!/bin/bash
# Serve a trained adapter beside the stock 4B file and hold it to the held-out rows
# (phase 3, step 5b). On the Linux host, from the repository:
#
#   bash eval/tune/score_adapter.sh NAME
#
# data/models/adapter-NAME/ holds what training saved (adapter_model.safetensors and its
# config). The adapter is turned into a GGUF file by llama.cpp's own script, the model server
# is started with the stock 4-bit base and the adapter beside it (no merge), and both
# held-out sets of build/tune/set are scored through the responder's own request path.
# Results: build/tune/scores/NAME-<set>.json. The tuned model is left serving.
set -euo pipefail
name="$1"
base_dir="${BASE_DIR:-Qwen3.5-4B}"
base_gguf="${BASE_GGUF:-Qwen3.5-4B-Q4_K_M.gguf}"
models="$PWD/data/models"
adapter="adapter-$name"
compose="docker compose --env-file .env -f compose/docker-compose.yml --profile llm"
[ -f "$models/$adapter/adapter_model.safetensors" ] || { echo "no adapter in $models/$adapter"; exit 1; }

if [ ! -f "$models/$adapter/$adapter.gguf" ]; then
  docker rm -f mirage-lora-convert >/dev/null 2>&1 || true
  docker create --name mirage-lora-convert --network none -v "$models:/models" \
    --entrypoint python3 ghcr.io/ggml-org/llama.cpp:full /app/convert_lora_to_gguf.py \
    --base "/models/$base_dir" --outfile "/models/$adapter/$adapter.gguf" --outtype f16 \
    "/models/$adapter" >/dev/null
  docker start -a mirage-lora-convert 2>&1 | tail -3
  docker rm -f mirage-lora-convert >/dev/null
fi
ls -la "$models/$adapter/$adapter.gguf"

make llm-down >/dev/null 2>&1 || true
LLAMA_MODEL_FILE="$base_gguf" LLAMA_LORA="$adapter/$adapter.gguf" \
  make llm-up LLM_MODEL_NAME="qwen3.5-4b-lora-$name" >/dev/null 2>&1 || true
make llm-status
$compose exec -T llama sh -c 'command -v curl >/dev/null && curl -s localhost:8080/lora-adapters' || true
echo

mkdir -p build/tune/scores
for split in test_invocations test_programs; do
  $compose exec -T responder python -m mirage_responder.score --samples 6 \
    < "build/tune/set/$split.jsonl" > "build/tune/scores/$name-$split.json" \
    2> "build/tune/scores/$name-$split.err"
  python3 - "build/tune/scores/$name-$split.json" "$split" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(sys.argv[2], {k: v for k, v in d.items() if not isinstance(v, (list, dict))})
PY
done
