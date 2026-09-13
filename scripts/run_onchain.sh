#!/usr/bin/env bash
# Run the on-chain L2 suite at ExploitGym scale.
#
# Defaults: 1259 on-chain tasks, 50 parallel agent containers, 6h agent budget.
# Each agent container is capped at 2g / 1 CPU so 50 fit on a ~121g host.
# Override any value via environment variables, e.g.:
#
#   API_KEY=... CONCURRENCY=30 TIMEOUT=4h ./scripts/run_onchain.sh
#
set -euo pipefail

cd "$(dirname "$0")/.."

MODEL="${MODEL:-deepseek/deepseek-v4.1-flash}"
API_BASE="${API_BASE:-https://api.360.cn}"
API_KEY="${API_KEY:-${GLM_API_KEY:-}}"
CONCURRENCY="${CONCURRENCY:-50}"
TIMEOUT="${TIMEOUT:-6h}"
VERIFY_TIMEOUT="${VERIFY_TIMEOUT:-5m}"
MEM="${MEM:-2g}"
CPUS="${CPUS:-1000000000}"          # 1 CPU per container
TASKS="${TASKS:-data/task_ids/onchain.txt}"
OUT="${OUT:-/tmp/opencode/onchain_run}"
AGENT_IMAGE="${AGENT_IMAGE:-protocolbench/agent:latest}"

if [[ -z "$API_KEY" ]]; then
  echo "ERROR: set API_KEY (or GLM_API_KEY)" >&2
  exit 2
fi
if [[ ! -f "$TASKS" ]]; then
  echo "ERROR: task list not found: $TASKS" >&2
  exit 2
fi

N=$(grep -cve '^\s*$' "$TASKS")
echo "on-chain run: tasks=$N concurrency=$CONCURRENCY timeout=$TIMEOUT mem=$MEM model=$MODEL"

PYTHONPATH=src .venv/bin/python run_protocol.py \
  --model "$MODEL" \
  --api-key "$API_KEY" \
  --api-base-url "$API_BASE" \
  --protocols "$TASKS" \
  --concurrency "$CONCURRENCY" \
  --timeout "$TIMEOUT" \
  --verify-timeout "$VERIFY_TIMEOUT" \
  --mem-limit "$MEM" \
  --nano-cpus "$CPUS" \
  --agent-image "$AGENT_IMAGE" \
  --out-dir "$OUT" \
  "$@"
