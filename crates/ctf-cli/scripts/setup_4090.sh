#!/bin/bash
# ─── Option 2: RTX 4090 (24GB VRAM) — Ollama + LiteLLM proxy ────────────────
# Chạy trên máy có RTX 4090
# Yêu cầu: NVIDIA driver 525+, Docker (optional)
#
# Usage:
#   bash setup_4090.sh
#   # Terminal khác:
#   export ANTHROPIC_BASE_URL=http://localhost:4000
#   export ANTHROPIC_API_KEY=dummy
#   ctf --challenge ~/ctf/chall --model qwen-32b

set -e

MODEL="${MODEL:-qwen2.5:32b}"   # ~20GB Q4, vừa 4090
LITELLM_PORT="${LITELLM_PORT:-4000}"
OLLAMA_PORT="${OLLAMA_PORT:-11434}"

# ── Cài Ollama nếu chưa có ───────────────────────────────────────────────────
if ! command -v ollama &>/dev/null; then
    echo "==> Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
fi

# ── Start Ollama ─────────────────────────────────────────────────────────────
echo "==> Starting Ollama..."
ollama serve &>/tmp/ollama.log &
OLLAMA_PID=$!
sleep 3

# ── Pull model ───────────────────────────────────────────────────────────────
echo "==> Pulling model: $MODEL (lần đầu ~20GB, có thể mất vài phút)..."
ollama pull "$MODEL"

echo "==> Model ready. Testing..."
ollama run "$MODEL" "say: ready" --nowordwrap 2>/dev/null | head -3

# ── Cài LiteLLM nếu chưa có ─────────────────────────────────────────────────
if ! command -v litellm &>/dev/null; then
    echo "==> Installing LiteLLM..."
    pip install "litellm[proxy]" --quiet
fi

# ── Tạo LiteLLM config ───────────────────────────────────────────────────────
LITELLM_CONFIG="/tmp/litellm_4090.yaml"
cat > "$LITELLM_CONFIG" <<EOF
model_list:
  - model_name: qwen-32b
    litellm_params:
      model: ollama/qwen2.5:32b
      api_base: http://localhost:${OLLAMA_PORT}

  - model_name: qwen-14b
    litellm_params:
      model: ollama/qwen2.5:14b
      api_base: http://localhost:${OLLAMA_PORT}

  - model_name: deepseek-r1
    litellm_params:
      model: ollama/deepseek-r1:14b
      api_base: http://localhost:${OLLAMA_PORT}

  - model_name: llama3
    litellm_params:
      model: ollama/llama3.3:70b
      api_base: http://localhost:${OLLAMA_PORT}

litellm_settings:
  drop_params: true
  request_timeout: 600
EOF

# ── Start LiteLLM proxy ───────────────────────────────────────────────────────
echo ""
echo "==> Starting LiteLLM proxy on port $LITELLM_PORT..."
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Trên terminal khác, chạy:"
echo ""
echo "  export ANTHROPIC_BASE_URL=http://localhost:$LITELLM_PORT"
echo "  export ANTHROPIC_API_KEY=dummy"
echo "  ctf --challenge ~/ctf/chall --model qwen-32b"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

litellm --config "$LITELLM_CONFIG" --port "$LITELLM_PORT"
