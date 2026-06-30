# Version control — basics (do not forget)

Quick rules for committing/pushing this working tree. Read before any commit/push.

## Push target

- **Push to `hungtrab/ctf_sloppy`** — remote name `sloppy`
  (`https://github.com/hungtrab/ctf_sloppy`).
- **Do NOT push to `origin`** (`instructkr/claw-code`) — that is the upstream
  leaked base, not ours.
- Always branch off before committing on `main`; push the branch, don't force
  onto someone else's `main`.

## What to push (ours, small, code)

- `rust/` — the Rust workspace (CLI + runtime + crates). Keep the gate green
  before pushing: `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`.
- `scripts/` — benchmark/util scripts (review for hardcoded local paths first).
- `version_control.md`, other small docs.

## What to NEVER push (big / generated / sensitive)

- `test/` — CTF challenge corpus, ~2 GB of binaries. Huge; not ours to publish.
- `openclaw/`, `ctf-solver-release/`, `feynman/`, `pi/`, `bad_UI_picture/` —
  large and/or unrelated artifacts.
- `note_30_6_codex.md` and any `*note*` — contain infrastructure details
  (server hostnames, SSH usernames). Treat as secret.
- `writeups/` — unverified / manually-tainted candidate flags.
- Any credentials: passwords, API keys, OAuth tokens, `auth.json`,
  `.ctf-session.json`, SSH details. Never in a commit, never in a log.
- Build output: `rust/target/` (already gitignored).

## Staging discipline

- Never `git add -A` / `git add .` here — too much untracked junk and secrets.
- Stage explicitly:
  - `git add -u rust/` for tracked modifications,
  - `git add <new source files>` by name.
- Before committing, sanity-check: `git diff --cached --name-only` should be
  all `rust/` (or other reviewed paths) and contain no binaries/secrets.

## Commits

- Conventional commits: `feat(scope):`, `fix:`, `chore(scope):`.
- End commit messages with the Co-Authored-By trailer when applicable.
