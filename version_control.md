# Version control — basics (do not forget)

Read before any commit/push. There are TWO separate git repos in this tree.

## The two repos

| Path on disk          | `origin` remote                | Role                              | Layout |
|-----------------------|--------------------------------|-----------------------------------|--------|
| `./rust/`             | `instructkr/claw-code`         | upstream leaked base — **do NOT push** | `rust/crates/...` |
| `./ctf-solver-release/` | `hungtrab/ctf_sloppy`        | **our publish mirror** — push here | `crates/...` (root) |

- Active development happens in `./rust/` (the big, current workspace).
- `./ctf-solver-release/` is the published clean mirror (Rust workspace at the
  repo root, plus `README.md` + `install.sh`). Its histories are unrelated to
  `instructkr/claw-code`, so don't try to merge them.

## Publishing to ctf_sloppy (full sync)

The two trees diverge, so publish by syncing `./rust/` into the mirror's root
layout, then pushing a branch:

```bash
cd ctf-solver-release
git checkout -b sync/<topic>
rm -rf crates Cargo.toml Cargo.lock
cp -a ../rust/crates ./crates
cp -a ../rust/Cargo.toml ../rust/Cargo.lock .
cp -a ../version_control.md .
find crates -type d -name target -prune -exec rm -rf {} +   # safety
cargo build --release            # never push code that doesn't build
git add -A
git commit && git push -u origin sync/<topic>               # then open a PR
```

Preserve the mirror's own `README.md`, `install.sh`, `.gitignore`.
Always push a branch + PR; never force onto `main`.

## NEVER push (big / generated / sensitive)

- `test/` — CTF challenge corpus, ~2 GB of binaries. Not ours to publish.
- `openclaw/`, `feynman/`, `pi/`, `bad_UI_picture/` — large / unrelated.
- `ctf-solver-release/target/`, `rust/target/` — build output (gitignored).
- `note_*.md` (e.g. `note_30_6_codex.md`) — contain infra details
  (server hostnames, SSH usernames). Treat as secret.
- `writeups/` — unverified / manually-tainted candidate flags.
- Any credentials: passwords, API keys, OAuth tokens, `auth.json`,
  `.ctf-session.json`, SSH details. Never in a commit, never in a log.

## Staging discipline

- Never `git add -A` in `./rust/` (untracked junk + secrets live there).
  `git add -A` is only safe inside `ctf-solver-release/` (clean mirror).
- In `./rust/`: stage explicitly — `git add -u rust/` plus new source files
  by name. Then verify `git diff --cached --name-only` has no binaries/secrets.

## Gate + commits

- Keep green before pushing: `cargo fmt`,
  `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- Conventional commits: `feat(scope):`, `fix:`, `chore(scope):`, `sync:`.
- End commit messages with the Co-Authored-By trailer.
