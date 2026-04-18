#!/usr/bin/env bash
set -e

# ── CTF Solver — install script ──────────────────────────────────────────────

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

info()  { echo -e "${GREEN}▶${RESET} $*"; }
warn()  { echo -e "${YELLOW}⚠${RESET}  $*"; }
error() { echo -e "${RED}✘${RESET}  $*" >&2; exit 1; }

# ── 1. Check Rust ─────────────────────────────────────────────────────────────
if ! command -v cargo &>/dev/null; then
    warn "Rust not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
fi

RUST_VER=$(rustc --version | awk '{print $2}')
info "Rust $RUST_VER found"

# ── 2. Build ──────────────────────────────────────────────────────────────────
info "Building ctf (release)..."
cargo build --release -p ctf-cli

# ── 3. Install binary ─────────────────────────────────────────────────────────
INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR"

# Use mv via tmp to handle "text file busy" on Linux
cp target/release/ctf /tmp/ctf_install_tmp
mv /tmp/ctf_install_tmp "$INSTALL_DIR/ctf"
chmod +x "$INSTALL_DIR/ctf"

info "Installed to $INSTALL_DIR/ctf"

# ── 4. PATH check ─────────────────────────────────────────────────────────────
if ! echo "$PATH" | tr ':' '\n' | grep -q "$INSTALL_DIR"; then
    warn "$INSTALL_DIR is not in your PATH."
    echo "Add this to your ~/.bashrc or ~/.zshrc:"
    echo ""
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
fi

# ── 5. Optional: notify-send ──────────────────────────────────────────────────
if ! command -v notify-send &>/dev/null; then
    warn "notify-send not found — desktop notifications won't work."
    echo "Install with: sudo apt install libnotify-bin"
fi

echo ""
echo -e "${BOLD}${GREEN}✔ Done!${RESET} Run: ctf --help"
