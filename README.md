# CTF Solver CLI

Terminal agent tự động giải CTF. Hỗ trợ Claude (Anthropic), ChatGPT (OpenAI OAuth — không cần API key riêng), và bất kỳ OpenAI-compatible endpoint nào (Gemini, Groq, vLLM, Ollama...).

---

## Yêu cầu

- Linux (x86_64)
- Rust ≥ 1.80 — install script tự cài nếu chưa có
- `notify-send` để bật desktop notification (tuỳ chọn): `sudo apt install libnotify-bin`
- `ffplay` / `paplay` / `cvlc` để bật âm thanh (tuỳ chọn): `sudo apt install ffmpeg`

---

## Cài đặt

```bash
git clone <repo-url>
cd ctf-solver-release
./install.sh
```

Script tự build release binary và copy vào `~/.local/bin/ctf`. Kiểm tra:

```bash
ctf --version
ctf --help
```

---

## Cài CTF skill references (tuỳ chọn, khuyến nghị)

Clone bộ technique reference vào `~/.local/share/ctf-skills`. Agent sẽ tự đọc file kỹ thuật phù hợp với category của challenge:

```bash
git clone https://github.com/ljagiello/ctf-skills ~/.local/share/ctf-skills
```

Cập nhật định kỳ:

```bash
git -C ~/.local/share/ctf-skills pull
```

---

## Cấu hình API

Khi khởi chạy, wizard sẽ hỏi chọn chế độ. Có thể cấu hình sẵn bằng env var để wizard tự detect và skip bước hỏi.

### Chế độ 1 — OpenAI / ChatGPT account (OAuth, không cần API key riêng)

Đăng nhập một lần, credentials lưu ở `~/.config/ctf-solver/openai-credentials.json`:

```bash
ctf login
```

Mở browser → đăng nhập ChatGPT → tự động lưu token. Sau đó dùng bình thường:

```bash
ctf ./my-challenge --model gpt-4o
```

Token hết hạn sẽ tự refresh. Để xóa: `ctf logout`.

### Chế độ 2 — Anthropic API key

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Chế độ 3 — OpenAI API key

```bash
export OPENAI_API_KEY="sk-..."
```

### Chế độ 4 — Custom endpoint (Gemini, Groq, vLLM, LiteLLM...)

```bash
# Gemini qua Google AI Studio (miễn phí, lấy key tại aistudio.google.com/apikey)
export OPENAI_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"
export OPENAI_API_KEY="AIza..."

# Groq (miễn phí, nhanh)
export OPENAI_BASE_URL="https://api.groq.com/openai"
export OPENAI_API_KEY="gsk_..."

# Local vLLM / Ollama
export OPENAI_BASE_URL="http://localhost:8000"
export OPENAI_API_KEY="dummy"
```

File `crates/ctf-cli/litellm_config.yaml` là ví dụ config LiteLLM proxy — dùng nếu muốn routing nhiều model qua một endpoint.

---

## Startup wizard

Mỗi khi chạy `ctf <challenge>`, tool hiện wizard 4 bước:

```
 ╭──────────────────────────────────────────────────────╮
 │   ⚡  CTF Solver  v0.1.0                              │
 ╰──────────────────────────────────────────────────────╯

   Challenge   heap-overflow
   Directory   /home/user/ctf/heap-overflow
   Files       2 file(s)
   ⚠  The agent will have full read/write access to this directory.

  Allow? [y]/n:                         ← Bước 1: xác nhận workspace

  Category detected:  💥  pwn           ← Bước 2: xác nhận / đổi category
  Category [pwn] (Enter to confirm, type to change):

  Flag format not set — choose:         ← Bước 3: chọn flag format
    1)  FLAG{...}
    2)  picoCTF{...}
    3)  HTB{...}
    ...
  Flag format [1]:

  API mode:                             ← Bước 4: chọn backend
    1)  OpenAI / ChatGPT account  (OAuth — no key needed)
    2)  API key  (Anthropic · OpenAI · custom endpoint)
  Mode [1]:
```

**Hành vi:**
- Bước 2 bị skip nếu `category.txt` đã tồn tại hoặc `--category` được truyền
- Bước 3 bị skip nếu `flag_format.txt` đã tồn tại — lần chọn đầu tiên tự lưu lại
- Bước 4 bị skip nếu `--api` được truyền
- Danh sách flag format chỉnh sửa tại `~/.config/ctf-solver/flag-formats.txt`

---

## Cú pháp

```
ctf <challenge-dir> [OPTIONS]
ctf login          # đăng nhập OpenAI OAuth (ChatGPT account)
ctf logout         # xóa OpenAI credentials
```

### Options

| Flag | Mô tả |
|------|-------|
| `--challenge <dir>`, `-c <dir>` | Thư mục challenge (bắt buộc) |
| `--model <name>`, `-m <name>` | Model (mặc định: `claude-opus-4-6`) |
| `--category <cat>` | Override category (`pwn` `web` `crypto` `rev` `forensics` `misc` `osint` `network`) |
| `--api openai\|anthropic` | Chọn backend API thủ công, bỏ qua wizard |
| `--resume <file>`, `-r <file>` | Resume session từ file cụ thể |
| `--notify`, `-n` | Bật desktop notification + âm thanh khi agent xong |
| `--help`, `-h` | Hiện trợ giúp |
| `--version`, `-V` | Hiện version |

### Model aliases

| Alias | Model |
|-------|-------|
| `opus` | claude-opus-4-6 |
| `sonnet` | claude-sonnet-4-6 |
| `haiku` | claude-haiku-4-5-20251001 |
| Tên khác | dùng nguyên, ví dụ `gpt-4o`, `gemini-2.5-flash` |

---

## Cấu trúc thư mục challenge

Tool tự tạo các thư mục khi khởi chạy:

```
my-challenge/
├── files/              ← BẮT BUỘC: để file challenge vào đây
├── tmp/                ← agent dùng cho file tạm (không phải /tmp hệ thống)
├── self/               ← ghi chú riêng của bạn, agent KHÔNG đọc/ghi
├── desc.txt            ← mô tả challenge (tuỳ chọn)
├── category.txt        ← override category (tuỳ chọn)
├── flag_format.txt     ← ví dụ: picoCTF{...}
├── notes.md            ← agent tự tạo và ghi findings
├── writeup.md          ← tạo bởi lệnh /writeup
└── .ctf-session.json   ← session auto-save (resume tự động)
```

> Khi gõ `ctf .`, tool tự detect tên thư mục thật (không để là `.`).

---

## Slash commands trong REPL

| Lệnh | Mô tả |
|------|-------|
| `/hint` | Để agent tự bắt đầu (session mới) hoặc xin gợi ý tiếp |
| `/submit <flag>` | Kiểm tra format flag trước khi submit |
| `/notes` | Xem `notes.md` |
| `/files` | Liệt kê file trong `files/` kèm size |
| `/writeup` | Agent tự viết writeup chi tiết → lưu vào `writeup.md` |
| `/status` | Thống kê token, turns, model |
| `/cost` | Token usage chi tiết (input/output/cache) |
| `/compact` | Force-compact session để giải phóng token |
| `/reset` | Xóa toàn bộ session, giữ challenge context |
| `/category <cat>` | Đổi category đang active |
| `/notify` | Bật/tắt notification + âm thanh |
| `/export [path]` | Export transcript ra file text |
| `/help` | Hiện danh sách lệnh |
| `/exit`, `/quit` | Lưu session và thoát |

**Phím tắt:**

| Phím | Chức năng |
|------|-----------|
| `Tab` | Autocomplete slash command |
| `↑` / `↓` | Lịch sử prompt |
| `Ctrl+O` | Xem toàn bộ lịch sử session |
| `Ctrl+C` | Dừng agent đang chạy, quay về REPL |
| `Ctrl+D` | Thoát |

---

## Notification và âm thanh

Bật với `--notify` / `-n` hoặc gõ `/notify` trong REPL.

Khi agent hoàn thành một turn:
- Desktop notification qua `notify-send`
- Âm thanh — tự detect sound file từ hệ thống lần đầu

Thay đổi âm thanh tại `~/.config/ctf-solver/sound.txt`:

```bash
# Xem file được chọn tự động
cat ~/.config/ctf-solver/sound.txt

# Đổi sang file khác (hỗ trợ wav, ogg, mp3, flac...)
echo "/path/to/sound.wav" > ~/.config/ctf-solver/sound.txt

# Tắt âm thanh
echo "none" > ~/.config/ctf-solver/sound.txt
```

---

## Config files

Tất cả config người dùng lưu tại `~/.config/ctf-solver/`:

| File | Mô tả |
|------|-------|
| `flag-formats.txt` | Danh sách flag format (mỗi dòng một format, `#` là comment) |
| `sound.txt` | Đường dẫn sound file (`none` để tắt) |
| `openai-credentials.json` | OAuth token từ `ctf login` |

---

## Session

- Session được **tự động save** sau mỗi lượt agent
- Chạy lại cùng thư mục → tự động resume session cũ
- Bắt đầu lại từ đầu: `/reset` trong REPL, hoặc xóa `.ctf-session.json`

---

## Biến môi trường

| Biến | Mô tả |
|------|-------|
| `ANTHROPIC_API_KEY` | API key Anthropic |
| `ANTHROPIC_BASE_URL` | Custom base URL cho Anthropic / LiteLLM proxy |
| `OPENAI_API_KEY` | API key OpenAI hoặc provider khác |
| `OPENAI_BASE_URL` | Base URL cho OpenAI-compatible server |
| `ANTHROPIC_MAX_TOKENS` | Override max tokens (mặc định tự detect theo model) |
| `CTF_SKILLS_DIR` | Override path đến ctf-skills repo (mặc định `~/.local/share/ctf-skills`) |
