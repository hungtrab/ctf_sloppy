#!/bin/bash
# ─── Option 3: Máy đểu (4GB VRAM / CPU) — OpenRouter free tier ───────────────
# Không đủ VRAM để chạy model lớn → dùng OpenRouter free models qua LiteLLM
# Yêu cầu: Python 3.8+, tài khoản OpenRouter (free)
#
# Đăng ký key tại: https://openrouter.ai/keys
#
# Usage:
#   export OPENROUTER_API_KEY=sk-or-v1-xxxxx
#   bash setup_lowend.sh
#   # Terminal khác:
#   export ANTHROPIC_BASE_URL=http://localhost:4000
#   export ANTHROPIC_API_KEY=dummy
#   ctf --challenge ~/ctf/chall --model gemini-flash

set -e

LITELLM_PORT="${LITELLM_PORT:-4000}"

if [ -z "$OPENROUTER_API_KEY" ]; then
    echo "ERROR: Set OPENROUTER_API_KEY trước khi chạy script"
    echo "  export OPENROUTER_API_KEY=sk-or-v1-xxxxx"
    exit 1
fi

# ── Cài LiteLLM ──────────────────────────────────────────────────────────────
if ! command -v litellm &>/dev/null; then
    echo "==> Installing LiteLLM..."
    pip install "litellm[proxy]" --quiet
fi

# ── Tạo config với các free model ────────────────────────────────────────────
LITELLM_CONFIG="/tmp/litellm_lowend.yaml"
cat > "$LITELLM_CONFIG" <<EOF
model_list:
  # Free models — không tốn credit (rate limit thấp hơn)
  - model_name: gemini-flash
    litellm_params:
      model: openrouter/google/gemini-2.0-flash-exp:free
      api_key: ${OPENROUTER_API_KEY}

  - model_name: llama4-maverick
    litellm_params:
      model: openrouter/meta-llama/llama-4-maverick:free
      api_key: ${OPENROUTER_API_KEY}

  - model_name: deepseek-r1-free
    litellm_params:
      model: openrouter/deepseek/deepseek-r1:free
      api_key: ${OPENROUTER_API_KEY}

  - model_name: qwen-free
    litellm_params:
      model: openrouter/qwen/qwen-2.5-72b-instruct:free
      api_key: ${OPENROUTER_API_KEY}

  # Paid models (rẻ, ~\$0.1-0.5/1M tokens)
  - model_name: deepseek-r1
    litellm_params:
      model: openrouter/deepseek/deepseek-r1
      api_key: ${OPENROUTER_API_KEY}

  - model_name: qwen-72b
    litellm_params:
      model: openrouter/qwen/qwen-2.5-72b-instruct
      api_key: ${OPENROUTER_API_KEY}

litellm_settings:
  drop_params: true
  request_timeout: 300
  # Tự fallback sang model khác nếu bị rate limit
  fallbacks:
    - gemini-flash: ["llama4-maverick", "deepseek-r1-free"]
EOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Models available (free):"
echo "    gemini-flash     — Google Gemini 2.0 Flash"
echo "    llama4-maverick  — Meta Llama 4 Maverick"
echo "    deepseek-r1-free — DeepSeek R1 (reasoning)"
echo "    qwen-free        — Qwen 2.5 72B"
echo ""
echo "  Trên terminal khác:"
echo "  export ANTHROPIC_BASE_URL=http://localhost:$LITELLM_PORT"
echo "  export ANTHROPIC_API_KEY=dummy"
echo "  ctf --challenge ~/ctf/chall --model gemini-flash"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

litellm --config "$LITELLM_CONFIG" --port "$LITELLM_PORT"
