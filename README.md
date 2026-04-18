# CTF Solver CLI

Terminal agent tự động giải CTF, dùng LLM (Claude hoặc OpenAI-compatible).

---

## Cài đặt

### Yêu cầu

- Linux (x86_64 hoặc arm64)
- Rust ≥ 1.80 (script tự cài nếu chưa có)
- `notify-send` để nhận desktop notification (tuỳ chọn)
  ```
  sudo apt install libnotify-bin
  ```

### Cài nhanh

```bash
git clone <repo>
cd ctf-solver-release
./install.sh
```

Script sẽ build và copy binary `ctf` vào `~/.local/bin/`.

---

## Cấu hình API

### Dùng Claude (Anthropic)

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Dùng OpenAI-compatible (vLLM, LiteLLM, proxy...)

```bash
export OPENAI_BASE_URL="https://your-proxy.example.com"
export OPENAI_API_KEY="your-key"
```

Khi `OPENAI_BASE_URL` được set, tool tự động chuyển sang chế độ OpenAI.

---

## Cách dùng

### Cú pháp cơ bản

```
ctf [OPTIONS] --challenge <thư_mục>
```

### Options

| Flag | Mô tả |
|------|-------|
| `--challenge <dir>`, `-c <dir>` | Thư mục chứa challenge (bắt buộc) |
| `--model <name>`, `-m <name>` | Model LLM (mặc định: `claude-opus-4-6`) |
| `--category <cat>` | Ghi đè category (`pwn`, `rev`, `web`, `crypto`, `forensics`, `misc`, `osint`) |
| `--api openai\|anthropic` | Chọn backend API thủ công |
| `--resume <file>`, `-r <file>` | Resume session từ file cụ thể |
| `--notify`, `-n` | Bật desktop notification khi agent xong |
| `--help`, `-h` | Hiện trợ giúp |
| `--version`, `-V` | Hiện version |

### Model aliases

| Alias | Model thực |
|-------|-----------|
| `opus` | claude-opus-4-6 |
| `sonnet` | claude-sonnet-4-6 |
| `haiku` | claude-haiku-4-5-20251001 |

---

## Ví dụ

```bash
# Giải challenge pwn với Claude (auto-detect từ file ELF)
ctf --challenge ~/ctf/bksec/pwn/vuln

# Chỉ định category và model
ctf --challenge ~/ctf/web/sqli --category web --model sonnet

# Dùng OpenAI proxy (ví dụ Gemini qua LiteLLM)
OPENAI_BASE_URL=https://proxy.example.com \
OPENAI_API_KEY=sk-xxx \
ctf --challenge ~/ctf/rev/crackme --api openai --model gemini-2.5-pro

# Bật notification + resume session cũ
ctf --notify --challenge ~/ctf/crypto/aes --resume ~/ctf/crypto/aes/.ctf-session.json
```

---

## Lệnh trong session

Gõ trong prompt `[category] >` khi đang chạy:

| Lệnh | Mô tả |
|------|-------|
| `/hint` | Để agent tự bắt đầu hoặc gợi ý tiếp |
| `/submit <flag>` | Kiểm tra flag |
| `/notes` | Xem ghi chú challenge |
| `/files` | Liệt kê file trong `files/` |
| `/status` | Thống kê token, số messages |
| `/cost` | Ước tính chi phí API |
| `/compact` | Nén session (giải phóng token) |
| `/reset` | Xoá toàn bộ lịch sử, bắt đầu lại |
| `/category <cat>` | Đổi category đang active |
| `/notify` | Bật/tắt desktop notification |
| `/export` | Export lịch sử chat ra file text |
| `/help` | Hiện danh sách lệnh |
| `/exit`, `/quit` | Lưu session và thoát |
| `Ctrl+O` | Xem toàn bộ lịch sử session |
| `Ctrl+C` | Dừng agent đang chạy, quay về prompt |
| `Ctrl+D` | Thoát |

---

## Cấu trúc thư mục challenge

Tool tự tạo nếu chưa có:

```
my-challenge/
├── files/          ← để file challenge vào đây (binary, pcap, ảnh...)
├── notes.md        ← ghi chú tự động, agent có thể ghi vào
└── .ctf-session.json  ← session được auto-save (resume tự động)
```

---

## Session & Resume

- Session được **tự động save** sau mỗi lượt.
- Lần sau chạy lại cùng thư mục → tự động resume:
  ```bash
  ctf --challenge ~/ctf/pwn/vuln   # tiếp tục từ lần trước
  ```
- Muốn bắt đầu lại từ đầu: `/reset` hoặc xoá `.ctf-session.json`.

---

## Biến môi trường

| Biến | Mô tả |
|------|-------|
| `ANTHROPIC_API_KEY` | API key Anthropic |
| `ANTHROPIC_BASE_URL` | Custom base URL cho Anthropic API |
| `OPENAI_BASE_URL` | Base URL cho OpenAI-compatible server |
| `OPENAI_API_KEY` | API key cho OpenAI-compatible server |
| `ANTHROPIC_MAX_TOKENS` | Override max tokens (mặc định 8192 cho non-Claude models) |
