# CTF Solver — Hướng dẫn sử dụng

Terminal app giải CTF tự động, chạy trực tiếp trên máy, dùng LLM tự host qua LiteLLM proxy.

---

## Mục lục

1. [Cài đặt](#1-cài-đặt)
2. [Cấu hình LLM](#2-cấu-hình-llm)
3. [Chuẩn bị challenge](#3-chuẩn-bị-challenge)
4. [Khởi chạy](#4-khởi-chạy)
5. [Slash commands trong REPL](#5-slash-commands-trong-repl)
6. [Tự động phát hiện flag](#6-tự-động-phát-hiện-flag)
7. [Quản lý session](#7-quản-lý-session)
8. [Token optimization](#8-token-optimization)
9. [Từng category một](#9-từng-category-một)
10. [Workflow thực tế từng bước](#10-workflow-thực-tế-từng-bước)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Cài đặt

### Build từ source

```bash
# Cần Rust stable mới nhất
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Build release binary
cd /path/to/claw-code/rust
cargo build --release --bin ctf

# Copy ra PATH
cp target/release/ctf ~/.local/bin/ctf
# hoặc
sudo cp target/release/ctf /usr/local/bin/ctf
```

### Kiểm tra

```bash
ctf --version
# ctf-solver 0.1.0

ctf --help
```

---

## 2. Cấu hình LLM

Tool dùng biến môi trường để kết nối tới LLM. Có 2 trường hợp:

### Trường hợp A — Anthropic API trực tiếp

```bash
export ANTHROPIC_API_KEY="sk-ant-api03-..."
# Không cần ANTHROPIC_BASE_URL, dùng endpoint mặc định
```

### Trường hợp B — LLM tự host qua LiteLLM (khuyến nghị cho nội bộ)

LiteLLM đóng vai proxy, nhận Anthropic API format từ tool, chuyển sang OpenAI-compatible format cho vLLM/Ollama.

**Bước 1 — Cài LiteLLM:**
```bash
pip install litellm[proxy]
```

**Bước 2 — Tạo config:**
```yaml
# ~/litellm-config.yaml
model_list:
  - model_name: claude-opus-4-6        # tên giả để tool nhận ra
    litellm_params:
      model: openai/qwen2.5-coder-32b  # model thực trên vLLM
      api_base: http://localhost:8000   # địa chỉ vLLM/Ollama server
      api_key: "none"

  - model_name: claude-sonnet-4-6
    litellm_params:
      model: openai/qwen2.5-coder-32b
      api_base: http://localhost:8000
      api_key: "none"

litellm_settings:
  drop_params: true   # bỏ các params Anthropic-specific mà OpenAI không hiểu
```

**Bước 3 — Chạy proxy:**
```bash
litellm --config ~/litellm-config.yaml --port 4000
```

**Bước 4 — Set env cho tool:**
```bash
export ANTHROPIC_BASE_URL=http://localhost:4000
export ANTHROPIC_API_KEY=fake-key   # LiteLLM không verify key
```

**Gợi ý model cho CTF:**
| Model | Ưu điểm | Dùng cho |
|-------|---------|----------|
| Qwen2.5-Coder-32B | Reasoning code tốt, context 32k | pwn, rev, crypto |
| DeepSeek-Coder-V2 | Tool calling mạnh | tất cả |
| Llama-3.1-70B | Cân bằng | misc, web |

> Model cần hỗ trợ **function calling / tool use** natively. Kiểm tra docs của model trước khi dùng.

---

## 3. Chuẩn bị challenge

### Cấu trúc thư mục

```
challenges/
└── tên-challenge/
    ├── files/             ← BẮT BUỘC: chứa các file challenge
    │   ├── vuln            ← binary ELF, source code, pcap, image...
    │   └── libc.so.6       ← thêm libc nếu cần
    ├── description.txt    ← đề bài (tùy chọn, nhưng nên có)
    ├── category.txt       ← một trong: pwn web crypto rev forensics misc osint network
    ├── flag_format.txt    ← ví dụ: picoCTF{...}  (mặc định: FLAG{...})
    └── notes.md           ← tool tự tạo, ghi findings vào đây
```

### Ví dụ tạo nhanh

```bash
# Tạo cấu trúc cho một pwn challenge
mkdir -p challenges/heap-overflow/files
cp ~/ctf/binaries/vuln challenges/heap-overflow/files/
cp ~/ctf/binaries/libc.so.6 challenges/heap-overflow/files/

echo "Buffer overflow in read(). PIE disabled. nc chall.example.com 9001" \
  > challenges/heap-overflow/description.txt

echo "pwn" > challenges/heap-overflow/category.txt
echo "CTF{...}" > challenges/heap-overflow/flag_format.txt
```

### Auto-detection category

Nếu không có `category.txt`, tool tự detect dựa trên:

| Dấu hiệu | Category được detect |
|----------|---------------------|
| File `.pcap` / `.pcapng` trong `files/` | network |
| File ELF binary + không có từ khóa reverse | pwn |
| Từ khóa "overflow", "heap", "rop" trong description | pwn |
| Từ khóa "sql", "xss", "lfi", "http" | web |
| Từ khóa "rsa", "aes", "cipher", "encrypt" | crypto |
| Từ khóa "reverse", "disassem", "decompil" | rev |
| Từ khóa "steganograph", "forensic", "volatility" | forensics |
| Không match gì | misc |

---

## 4. Khởi chạy

### Cú pháp cơ bản

```bash
# Cách 1 — đường dẫn trực tiếp
ctf challenges/heap-overflow/

# Cách 2 — flag --challenge
ctf --challenge challenges/heap-overflow/

# Cách 3 — chỉ định model (sonnet nhanh và rẻ hơn)
ctf challenges/web-sqli/ --model sonnet

# Cách 4 — override category nếu auto-detect sai
ctf challenges/weird-binary/ --category rev

# Cách 5 — tiếp tục session cũ
ctf challenges/heap-overflow/ --resume challenges/heap-overflow/.ctf-session.json
```

### Banner khi khởi động

```
 ██████╗████████╗███████╗
██╔════╝╚══██╔══╝██╔════╝
██║        ██║   █████╗
██║        ██║   ██╔══╝
╚██████╗   ██║   ██║
 ╚═════╝   ╚═╝   ╚═╝    Solver

  Challenge   heap-overflow
  Category    💥 pwn
  Flag fmt    CTF{...}
  Model       claude-opus-4-6
  Directory   /home/user/challenges/heap-overflow
  Session     /home/user/challenges/heap-overflow/.ctf-session.json

  Permissions: NONE (allow-all)  Sandbox: OFF  Compact: 50k tokens

  /hint  /submit <flag>  /notes  /files  /reset  /help
```

**Chú ý 3 dòng màu cuối banner:**
- `Permissions: NONE (allow-all)` — tất cả tool calls đều được approve tự động, không hỏi
- `Sandbox: OFF` — bash chạy trực tiếp, không bị namespace/filesystem isolation
- `Compact: 50k tokens` — session tự compact khi vượt 50k input tokens

Sau khi banner hiển thị, agent **tự động bắt đầu** kiểm tra `files/` và exploit. Không cần gõ gì thêm.

---

## 5. Slash commands trong REPL

Gõ vào prompt khi agent đang chờ. Dùng **Tab** để autocomplete.

### `/hint`

Yêu cầu agent gợi ý mà không giải thẳng. Hữu ích khi agent bị stuck hoặc bạn muốn học.

```
[pwn] > /hint
```

Agent sẽ trả lời kiểu:
> "Hãy chú ý đến khoảng cách giữa buffer và saved RIP. Thử đo offset bằng cyclic pattern."

### `/submit <flag>`

Kiểm tra format của flag trước khi submit lên platform.

```
[pwn] > /submit CTF{h34p_0v3rfl0w_ez}
```

Output:
```
╔══════════════════════════════════════════╗
║  CTF{h34p_0v3rfl0w_ez}                  ║
╚══════════════════════════════════════════╝

Flag format looks correct. Submit it on the CTF platform.
```

Nếu sai format:
```
[pwn] > /submit wrong_flag
Flag format mismatch.
  Expected format: CTF{...}
  Submitted:       wrong_flag
```

### `/notes`

Xem file `notes.md` trong thư mục challenge. Agent tự append findings vào đây.

```
[pwn] > /notes
```

### `/files`

Liệt kê file trong `files/` kèm size.

```
[pwn] > /files
Files in /home/user/challenges/heap-overflow/files
       4096 bytes  libc.so.6
      13456 bytes  vuln
```

### `/reset`

Xóa session hiện tại, giữ nguyên challenge context và system prompt. Dùng khi agent bị loop hoặc đi sai hướng hoàn toàn.

```
[pwn] > /reset
Resetting session (challenge context preserved)...
Session cleared. Starting fresh on 'heap-overflow'.
```

Agent sẽ bắt đầu lại từ đầu với `files/` và description.

### `/category <name>`

Chuyển category trong session. Note: system prompt chỉ update sau `/reset`.

```
[pwn] > /category rev
Category switched to: 🔍 rev
Note: system prompt update takes effect on next /reset
```

### `/status`

Xem token usage và thông tin session hiện tại.

```
[pwn] > /status
Status
  Model        claude-opus-4-6
  Category     💥 pwn
  Messages     24
  Turns        8
  Input tokens 18432
  Output tokens 3201
  Auto-compact threshold  50000 tokens
  Compact preserve        2 messages
```

### `/compact`

Force-compact conversation. Xóa hết message cũ, chỉ giữ 2 message gần nhất + summary. Dùng khi session dài và muốn tiết kiệm token.

```
[pwn] > /compact
Compacted: removed 20 messages, kept 3.
```

> **Lưu ý:** Tool đã cài auto-compact ở 50k tokens. `/compact` là để force compact thủ công bất kỳ lúc nào.

### `/cost`

Xem token usage chi tiết.

```
[pwn] > /cost
Cost
  Input tokens   18432
  Output tokens  3201
  Cache create   0
  Cache read     0
  Total tokens   21633
```

### `/export [path]`

Export toàn bộ transcript ra file txt.

```
[pwn] > /export
# Saved tại challenges/heap-overflow/heap-overflow-export.txt

[pwn] > /export /tmp/my-writeup.txt
# Saved tại /tmp/my-writeup.txt
```

### `/exit` hoặc `/quit`

Thoát và tự động save session.

```
[pwn] > /exit
Session saved to /home/user/challenges/heap-overflow/.ctf-session.json
```

---

## 6. Tự động phát hiện flag

Sau mỗi lần agent chạy tool, output được scan bằng regex:

```
[A-Za-z0-9_\-]+\{[^}]{1,200}\}
```

Ngoài ra còn các pattern cụ thể: `FLAG{...}`, `CTF{...}`, `picoCTF{...}`, v.v. (tự động từ `flag_format.txt`).

Khi tìm thấy, terminal hiển thị:

```
╔══════════════════════════════════════════╗
║         CTF{h34p_0v3rfl0w_3z}           ║
╚══════════════════════════════════════════╝
```

Đồng thời append vào `notes.md`:

```markdown
## FLAG FOUND
```
CTF{h34p_0v3rfl0w_3z}
```
```

---

## 7. Quản lý session

### Auto-resume

Mỗi challenge có file session riêng: `<challenge-dir>/.ctf-session.json`.

Khi chạy lại cùng challenge, tool **tự động load session cũ**:

```bash
ctf challenges/heap-overflow/
# → Tự load .ctf-session.json nếu tồn tại
```

### Resume từ file khác

```bash
ctf challenges/heap-overflow/ --resume challenges/heap-overflow/.ctf-session.json
```

### Xóa session và bắt đầu lại

Cách 1 — dùng `/reset` trong REPL (giữ challenge context).

Cách 2 — xóa file session:
```bash
rm challenges/heap-overflow/.ctf-session.json
ctf challenges/heap-overflow/   # fresh session
```

### Export writeup

```
[pwn] > /export
```

File txt chứa toàn bộ lịch sử user/assistant/tool. Dùng làm writeup thô.

---

## 8. Token optimization

Tool có 3 cơ chế tiết kiệm token, đặc biệt quan trọng khi dùng LLM tự host có rate limit:

### Auto-compaction (50k threshold)

Khi input tokens vượt 50,000, session tự compact:
- Tóm tắt các message cũ thành 1 system message ngắn
- Giữ nguyên 2 message gần nhất
- Tiếp tục solving mà không mất context quan trọng

```
[auto-compacted: removed 18 messages]
```

### Force compact (`/compact`)

Compact thủ công bất kỳ lúc nào. Giữ 2 message cuối, xóa hết còn lại.

### Output truncation

Tool executor tự truncate output dài hơn 4,000 ký tự:
```
…[truncated, 152304 chars total]
```

Agent vẫn nhận được phần quan trọng đầu output (hexdump, disassembly, etc.).

### Gợi ý khi dùng LLM nhỏ (≤7B params)

- Dùng model `--model sonnet` (thực ra map sang model bạn config trong LiteLLM)
- Set `max_tokens` thấp hơn trong LiteLLM config nếu bị OOM
- Chạy `/compact` sau mỗi 10 turns để session luôn gọn

---

## 9. Từng category một

### PWN (Binary Exploitation)

```bash
# Setup
mkdir -p challenges/pwn-chall/files
cp vuln challenges/pwn-chall/files/
echo "Stack buffer overflow. nc host 9001" > challenges/pwn-chall/description.txt
echo "pwn" > challenges/pwn-chall/category.txt
echo "FLAG{...}" > challenges/pwn-chall/flag_format.txt

# Chạy
ctf challenges/pwn-chall/
```

Agent sẽ:
1. `checksec vuln` → xem mitigations
2. `file vuln` + `strings vuln` → recon
3. Phân tích với GDB/pwndbg hoặc `objdump -d`
4. Xây dựng payload với pwntools
5. Nếu remote: `p = remote('host', 9001)` — nhớ thêm host/port vào description

> **Tip:** Thêm thông tin địa chỉ remote vào `description.txt`:
> ```
> Buffer overflow challenge. Remote: nc chall.example.com 9001
> libc version: Ubuntu GLIBC 2.35
> ```

### Web

```bash
mkdir -p challenges/web-sqli/files
echo "Login page at http://localhost:8080. SQLi somewhere." > challenges/web-sqli/description.txt
echo "web" > challenges/web-sqli/category.txt

ctf challenges/web-sqli/
```

Nếu challenge cần kết nối tới server đang chạy (Docker, VPN), đảm bảo:
- Server accessible từ máy chạy tool
- Địa chỉ URL trong `description.txt`

### Crypto

```bash
mkdir -p challenges/rsa-small-e/files
cp cipher.txt public.pem challenges/rsa-small-e/files/
echo "RSA with e=3. Decrypt cipher.txt" > challenges/rsa-small-e/description.txt
echo "crypto" > challenges/rsa-small-e/category.txt

ctf challenges/rsa-small-e/
```

Agent tự install thêm Python libs nếu cần (`pip install pycryptodome sympy z3-solver`).

### Forensics / Steganography

```bash
mkdir -p challenges/hidden-image/files
cp suspicious.png challenges/hidden-image/files/
echo "Something is hidden in this image." > challenges/hidden-image/description.txt
echo "forensics" > challenges/hidden-image/category.txt

ctf challenges/hidden-image/
```

### Reverse Engineering

```bash
mkdir -p challenges/crackme/files
cp crackme.exe challenges/crackme/files/
echo "Find the correct password. Windows PE binary." > challenges/crackme/description.txt
echo "rev" > challenges/crackme/category.txt

ctf challenges/crackme/
```

> Với PE binary trên Linux: agent sẽ dùng `wine` nếu có, hoặc phân tích tĩnh với `radare2`.

---

## 10. Workflow thực tế từng bước

### Ví dụ hoàn chỉnh: picoCTF heap challenge

**Bước 1 — Chuẩn bị**

```bash
mkdir -p ~/ctf/picoctf2025/heap-ez/files
cp ~/Downloads/heap_ez ~/ctf/picoctf2025/heap-ez/files/

cat > ~/ctf/picoctf2025/heap-ez/description.txt << 'EOF'
Heap challenge with UAF vulnerability.
Binary: heap_ez
Remote: nc mercury.picoctf.net 12345
Libc version: 2.31
EOF

echo "pwn" > ~/ctf/picoctf2025/heap-ez/category.txt
echo "picoCTF{...}" > ~/ctf/picoctf2025/heap-ez/flag_format.txt
```

**Bước 2 — Set env**

```bash
export ANTHROPIC_BASE_URL=http://localhost:4000   # LiteLLM proxy
export ANTHROPIC_API_KEY=fake
```

**Bước 3 — Khởi chạy**

```bash
ctf ~/ctf/picoctf2025/heap-ez/
```

**Bước 4 — Quan sát agent làm việc**

Agent tự động:
```
⚡ bash  checksec heap_ez
⚡ bash  file heap_ez && strings heap_ez | grep -i flag
⚡ bash  gdb -batch -ex "run" -ex "bt" ./heap_ez
...
⚡ bash  python3 exploit.py
```

**Bước 5 — Nếu agent bị stuck**

```
[pwn] > /hint
```

Hoặc cung cấp thêm context:
```
[pwn] > The binary uses tcache. Focus on UAF after free().
```

**Bước 6 — Flag được tìm thấy**

```
╔════════════════════════════════════════╗
║  picoCTF{h34p_4ll0c_m4g1c_a1b2c3d4}  ║
╚════════════════════════════════════════╝
```

**Bước 7 — Kiểm tra format và submit**

```
[pwn] > /submit picoCTF{h34p_4ll0c_m4g1c_a1b2c3d4}
Flag format looks correct. Submit it on the CTF platform.
```

**Bước 8 — Export writeup**

```
[pwn] > /export ~/ctf/picoctf2025/heap-ez/writeup.txt
[pwn] > /exit
```

---

## 11. Troubleshooting

### `401 Unauthorized` khi dùng LiteLLM

```
error: anthropic api returned 401 Unauthorized
```

Kiểm tra:
```bash
# LiteLLM proxy có đang chạy không?
curl http://localhost:4000/health

# Model name trong LiteLLM config có khớp với model tool đang dùng không?
# Tool dùng: claude-opus-4-6 (default)
# Phải có entry "model_name: claude-opus-4-6" trong config
```

### Agent không dùng tool, chỉ text

Model không hỗ trợ function calling. Chuyển sang model có tool support:
```yaml
# litellm-config.yaml
litellm_params:
  model: openai/qwen2.5-coder-32b  # model có tool calling
```

### Session bị loop, agent lặp lại cùng một hành động

```
[pwn] > /reset
```

Sau đó cung cấp gợi ý hướng đi:
```
[pwn] > Approach from a different angle. Focus on heap metadata corruption.
```

### Output quá dài, terminal bị flood

Agent tự truncate output ở 4,000 ký tự. Nếu vẫn bị flood, thêm vào prompt:
```
[pwn] > Keep all bash output under 50 lines. Use head/tail to truncate.
```

### Challenge cần network (nc, curl tới target)

Đảm bảo target accessible:
```bash
# Test trước khi chạy ctf
nc -zv chall.example.com 9001
curl -v http://web-chall.example.com:8080/
```

Nếu cần VPN/proxy, set trước khi chạy:
```bash
export http_proxy=http://proxy:8080
export https_proxy=http://proxy:8080
ctf challenges/web-chall/
```

### `pwntools` / `pycryptodome` chưa có

Agent tự chạy `pip install` khi cần. Nếu bị lỗi permission:
```bash
pip install --user pwntools pycryptodome sympy z3-solver ROPgadget
```

### Muốn xem lại toàn bộ session

```
[pwn] > /export
cat challenges/heap-overflow/heap-overflow-export.txt
```

### Muốn chạy không interactive (batch mode)

Hiện tại tool chỉ hỗ trợ interactive REPL. Để automate, có thể pipe input:
```bash
echo "" | ctf challenges/simple-pwn/   # Khởi động, để agent tự chạy, Ctrl+C để dừng
```

---

## Tóm tắt quick reference

```
# Khởi chạy
ctf <challenge-dir>
ctf <challenge-dir> --model sonnet
ctf <challenge-dir> --category web

# Trong REPL
/hint            → gợi ý
/submit <flag>   → kiểm tra format
/notes           → xem notes.md
/files           → liệt kê files
/reset           → bắt đầu lại
/compact         → giải phóng token
/status          → xem usage
/cost            → xem token
/export          → export transcript
/exit            → thoát

# Env vars
ANTHROPIC_API_KEY=<key>
ANTHROPIC_BASE_URL=http://localhost:4000   # LiteLLM proxy

# Challenge directory
files/           ← challenge files (BẮT BUỘC)
description.txt  ← đề bài
category.txt     ← pwn|web|crypto|rev|forensics|misc|osint|network
flag_format.txt  ← picoCTF{...}
```
