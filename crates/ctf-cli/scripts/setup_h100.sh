#!/bin/bash
# ─── Option 1: H100 server — serve Qwen2.5-72B via vLLM ─────────────────────
# Chạy trên server H100 (SSH vào server rồi chạy script này)
# Yêu cầu: CUDA 12.x, Python 3.10+
#
# Usage:
#   ssh user@h100-server
#   bash setup_h100.sh
#   # Sau đó trên máy local:
#   export ANTHROPIC_BASE_URL=http://<h100-ip>:8000
#   export ANTHROPIC_API_KEY=dummy
#   ctf --challenge ~/ctf/chall --model Qwen/Qwen2.5-72B-Instruct

set -e

MODEL="${MODEL:-Qwen/Qwen2.5-72B-Instruct}"
PORT="${PORT:-8000}"
GPU_MEM="${GPU_MEM:-0.90}"  # 90% VRAM utilization

echo "==> Installing vLLM..."
pip install vllm --quiet

echo "==> Starting vLLM server: $MODEL on port $PORT"
echo "    (First run sẽ download model ~144GB, có thể mất 10-20 phút)"
echo ""

python -m vllm.entrypoints.openai.api_server \
    --model "$MODEL" \
    --port "$PORT" \
    --host 0.0.0.0 \
    --gpu-memory-utilization "$GPU_MEM" \
    --max-model-len 32768 \
    --served-model-name "$(basename $MODEL)" \
    --trust-remote-code \
    --dtype bfloat16

# ─── Thay model khác ──────────────────────────────────────────────────────────
# DeepSeek-R1-Distill-32B (reasoning, 2xH100):
#   MODEL=deepseek-ai/DeepSeek-R1-Distill-Qwen-32B bash setup_h100.sh
#
# Llama-3.3-70B (nhanh hơn, 2xH100):
#   MODEL=meta-llama/Llama-3.3-70B-Instruct bash setup_h100.sh
#
# DeepSeek-R1-671B (mạnh nhất, cần 4xH100):
#   MODEL=deepseek-ai/DeepSeek-R1 GPU_MEM=0.95 bash setup_h100.sh
