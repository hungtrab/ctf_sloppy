// CTF Solver — terminal app built on claw-code runtime
// Security layers removed, PermissionMode::Allow, sandbox disabled, aggressive compaction.
mod challenge;
mod flag;
mod prompt;

// ── re-export TUI infrastructure from runtime (copied inline below) ──────────
mod input;
mod render;

use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Set by the SIGINT handler while an agent turn is running.
/// CtfApiClient::stream() checks this and aborts early if true.
static AGENT_INTERRUPTED: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

fn agent_interrupted() -> &'static Arc<AtomicBool> {
    AGENT_INTERRUPTED.get_or_init(|| Arc::new(AtomicBool::new(false)))
}

/// Global registry of background process PIDs spawned by the agent.
/// Killed on ctf CLI exit so they don't linger after a crash.
static BACKGROUND_PIDS: std::sync::OnceLock<Arc<Mutex<Vec<u32>>>> = std::sync::OnceLock::new();

fn background_pids() -> &'static Arc<Mutex<Vec<u32>>> {
    BACKGROUND_PIDS.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
}

fn kill_background_pids() {
    if let Ok(pids) = background_pids().lock() {
        for &pid in pids.iter() {
            #[cfg(unix)]
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status();
        }
    }
}

/// Spawns a lightweight monitor thread that watches AGENT_INTERRUPTED.
/// When set, sends SIGKILL to all child processes so the running bash command
/// dies immediately instead of waiting for it to react to the terminal SIGINT.
fn spawn_interrupt_monitor() {
    let our_pid = std::process::id().to_string();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if agent_interrupted().load(Ordering::Relaxed) {
                // Kill all children of this process immediately.
                // pkill -KILL -P <pid> sends SIGKILL to every child process.
                let _ = std::process::Command::new("pkill")
                    .args(["-KILL", "-P", &our_pid])
                    .output();
            }
        }
    });
}

use api::{
    resolve_startup_auth_source, AnthropicClient, ContentBlockDelta, InputContentBlock,
    InputMessage, MessageRequest, OutputContentBlock, StreamEvent as ApiStreamEvent, ToolChoice,
    ToolDefinition, ToolResultContentBlock,
};
use challenge::{Category, Challenge};
use flag::{render_flag_found, FlagExtractor};
use prompt::ctf_system_prompt;
use render::{MarkdownStreamState, Spinner, TerminalRenderer};
#[allow(unused_imports)]
use std::io::Write as _;
use runtime::{
    compact_session, generate_pkce_pair, generate_state,
    ApiClient, ApiRequest, AssistantEvent, CompactionConfig, ConfigLoader,
    ContentBlock, ConversationMessage, ConversationRuntime, MessageRole, OAuthAuthorizationRequest,
    OAuthConfig, OAuthTokenSet, PermissionMode, PermissionPolicy, RuntimeError, Session,
    TokenUsage, ToolError, ToolExecutor, parse_oauth_callback_query,
};
use serde_json::{json, Value};
use tools::{execute_tool, mvp_tool_specs};

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_MODEL: &str = "claude-opus-4-6";
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Auto-compact at 50k input tokens instead of the default 200k.
/// CTF sessions are task-focused — old recon data becomes noise quickly.
const CTF_AUTO_COMPACT_THRESHOLD: u32 = 50_000;

/// Keep only last 2 messages when doing /compact (vs default 4).
const CTF_COMPACT_PRESERVE: usize = 2;

const OPENAI_OAUTH_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const OPENAI_OAUTH_CALLBACK_PORT: u16 = 1455;
const OPENAI_DEFAULT_BASE_URL: &str = "https://api.openai.com";

/// Built-in flag format list — written to the user config file on first run.
const FLAG_FORMATS_DEFAULT: &str = "\
FLAG{...}
picoCTF{...}
HTB{...}
DUCTF{...}
DiceCTF{...}
CTF{...}
LACTF{...}
uiuctf{...}
sekai{...}
glacier{...}
flag{...}
";

/// Path to the user-editable flag formats config file.
fn flag_formats_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
    PathBuf::from(home).join(".config/ctf-solver/flag-formats.txt")
}

/// Load flag formats from the config file, creating it with defaults if absent.
fn load_flag_formats() -> Vec<String> {
    let path = flag_formats_config_path();
    if !path.exists() {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&path, FLAG_FORMATS_DEFAULT);
    }
    fs::read_to_string(&path)
        .unwrap_or_else(|_| FLAG_FORMATS_DEFAULT.to_string())
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

fn max_tokens_for_model(model: &str) -> u32 {
    if model.contains("opus") {
        32_000
    } else if model.starts_with("claude") {
        64_000
    } else {
        // Local/vLLM models (e.g. Qwen, Llama) have smaller context windows.
        // Use a conservative default; override with ANTHROPIC_MAX_TOKENS env var.
        std::env::var("ANTHROPIC_MAX_TOKENS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8_192)
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

fn main() {
    spawn_interrupt_monitor();
    let result = run();
    kill_background_pids();
    if let Err(e) = result {
        eprintln!("error: {e}\n\nRun `ctf --help` for usage.");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--help") | Some("-h") | None => {
            print_help();
            return Ok(());
        }
        Some("--version") | Some("-V") => {
            println!("ctf-solver {VERSION}");
            return Ok(());
        }
        Some("login") => {
            run_openai_login()?;
            return Ok(());
        }
        Some("logout") => {
            clear_openai_oauth()?;
            println!("OpenAI credentials cleared.");
            return Ok(());
        }
        _ => {}
    }

    let (challenge_dir, model, category_override, resume_path, mut api_mode, notify) = parse_args(&args)?;
    let mut challenge = Challenge::load(&challenge_dir);
    let category_was_overridden = category_override.is_some();
    if let Some(cat) = category_override {
        challenge = challenge.with_category(cat);
    }

    // Set CWD to challenge dir so relative paths (./files, ./tmp, ./notes.md) work correctly.
    std::env::set_current_dir(&challenge.dir)?;

    // Ensure files/, tmp/, and self/ exist before showing the startup screen.
    fs::create_dir_all(challenge.dir.join("files"))?;
    fs::create_dir_all(challenge.dir.join("tmp"))?;
    fs::create_dir_all(challenge.dir.join("self"))?;

    // Startup wizard — confirms permission, category, flag format, and API mode.
    if !startup_confirm(&mut challenge, category_was_overridden, &mut api_mode)? {
        return Ok(());
    }

    // Create notes.md after category is finalised.
    let notes_path = challenge.dir.join("notes.md");
    if !notes_path.exists() {
        fs::write(
            &notes_path,
            format!("# {}\n\nCategory: {}\nFlag format: {}\n\n## Notes\n\n",
                challenge.name, challenge.category.as_str(), challenge.flag_format),
        )?;
    }

    run_repl(challenge, model, resume_path, api_mode, notify)
}

/// Which API backend to use. Auto-detected from env vars unless overridden with --api.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ApiMode {
    /// Use Anthropic Messages API (/v1/messages). Default when ANTHROPIC_BASE_URL/KEY is set.
    Anthropic,
    /// Use OpenAI Chat Completions API (/v1/chat/completions). Use when pointing at vLLM/Ollama.
    OpenAi,
}

fn parse_args(
    args: &[String],
) -> Result<(PathBuf, String, Option<Category>, Option<PathBuf>, Option<ApiMode>, bool), Box<dyn std::error::Error>> {
    let mut challenge_dir: Option<PathBuf> = None;
    let mut model = DEFAULT_MODEL.to_string();
    let mut category_override: Option<Category> = None;
    let mut resume_path: Option<PathBuf> = None;
    let mut api_mode: Option<ApiMode> = None;
    let mut notify = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--challenge" | "-c" => {
                i += 1;
                challenge_dir = Some(PathBuf::from(
                    args.get(i).ok_or("--challenge requires a path")?,
                ));
            }
            "--model" | "-m" => {
                i += 1;
                model = resolve_model_alias(
                    args.get(i).ok_or("--model requires a value")?,
                ).to_string();
            }
            "--category" => {
                i += 1;
                let cat_str = args.get(i).ok_or("--category requires a value")?;
                category_override = Some(
                    Category::from_str(cat_str)
                        .ok_or_else(|| format!("unknown category: {cat_str}"))?,
                );
            }
            "--resume" | "-r" => {
                i += 1;
                resume_path = Some(PathBuf::from(
                    args.get(i).ok_or("--resume requires a session path")?,
                ));
            }
            "--api" => {
                i += 1;
                api_mode = Some(match args.get(i).map(String::as_str) {
                    Some("openai") => ApiMode::OpenAi,
                    Some("anthropic") => ApiMode::Anthropic,
                    other => return Err(format!(
                        "--api requires 'openai' or 'anthropic', got: {}",
                        other.unwrap_or("<missing>")
                    ).into()),
                });
            }
            "--notify" | "-n" => { notify = true; }
            other if other.starts_with('-') => {
                return Err(format!("unknown flag: {other}").into());
            }
            path => {
                challenge_dir = Some(PathBuf::from(path));
            }
        }
        i += 1;
    }

    let dir = challenge_dir.ok_or(
        "usage: ctf --challenge <dir> [--model <name>] [--category <cat>] [--resume <session>]",
    )?;
    Ok((dir, model, category_override, resume_path, api_mode, notify))
}

fn resolve_model_alias(alias: &str) -> &str {
    match alias {
        "opus"   => "claude-opus-4-6",
        "sonnet" => "claude-sonnet-4-6",
        "haiku"  => "claude-haiku-4-5-20251001",
        other    => other,
    }
}

// ─── Startup wizard ───────────────────────────────────────────────────────────

/// Four-step interactive wizard shown before the REPL:
///   1. Workspace permission confirmation
///   2. Category (ask only if not explicitly set)
///   3. Flag format picker (ask only if flag_format.txt doesn't exist)
///   4. API mode  (OpenAI OAuth  vs  API key — skip if --api flag was passed)
/// Returns false if the user wants to abort.
fn startup_confirm(
    challenge: &mut Challenge,
    category_was_overridden: bool,
    api_mode_out: &mut Option<ApiMode>,
) -> Result<bool, Box<dyn std::error::Error>> {
    use io::IsTerminal as _;

    if !io::stdin().is_terminal() {
        return Ok(true);
    }

    let files_count = fs::read_dir(challenge.dir.join("files"))
        .map(|rd| rd.filter_map(|e| e.ok()).filter(|e| e.path().is_file()).count())
        .unwrap_or(0);

    // ── Header ────────────────────────────────────────────────────────────────
    println!();
    println!(" \x1b[1m\x1b[38;5;46m╭──────────────────────────────────────────────────────╮\x1b[0m");
    println!(" \x1b[1m\x1b[38;5;46m│\x1b[0m   \x1b[1m⚡  CTF Solver\x1b[0m  \x1b[2mv{VERSION}\x1b[0m                            \x1b[1m\x1b[38;5;46m│\x1b[0m");
    println!(" \x1b[1m\x1b[38;5;46m╰──────────────────────────────────────────────────────╯\x1b[0m");
    println!();
    println!("   \x1b[2mChallenge\x1b[0m   \x1b[1m{}\x1b[0m", challenge.name);
    println!("   \x1b[2mDirectory\x1b[0m   \x1b[1m\x1b[33m{}\x1b[0m", challenge.dir.display());
    println!("   \x1b[2mFiles\x1b[0m       {}", if files_count == 0 {
        "\x1b[33m0 — add challenge files to ./files/\x1b[0m".to_string()
    } else {
        format!("{files_count} file(s)")
    });
    println!();
    println!("   \x1b[33m⚠\x1b[0m  The agent will have full read/write access to this directory.");
    println!();

    // ── Step 1: workspace permission ──────────────────────────────────────────
    if !prompt_yn("  Allow? [y]/n: ")? {
        println!();
        return Ok(false);
    }
    println!();

    // ── Step 2: category (skip if explicitly set via file or --category flag) ─
    let has_category_file = challenge.dir.join("category.txt").exists();
    if !has_category_file && !category_was_overridden {
        println!("  \x1b[2mCategory detected:\x1b[0m  {}  \x1b[1m{}\x1b[0m",
            challenge.category.emoji(), challenge.category.as_str());
        println!("  \x1b[2mpwn · web · crypto · rev · forensics · misc · osint · network\x1b[0m");
        println!();

        let default_cat = challenge.category.as_str();
        loop {
            print!("  Category [{default_cat}] (Enter to confirm, type to change): ");
            let _ = io::stdout().flush();
            let Some(line) = read_line() else { return Ok(false) };
            match line.trim() {
                "" => break,
                s => match Category::from_str(s) {
                    Some(c) => {
                        challenge.category = c;
                        // Persist so future runs skip this prompt.
                        let _ = fs::write(challenge.dir.join("category.txt"), c.as_str());
                        println!("  \x1b[38;5;46m✓\x1b[0m  {}  {}", c.emoji(), c.as_str());
                        break;
                    }
                    None => println!("  \x1b[31m✗  Unknown: '{s}'\x1b[0m"),
                },
            }
        }
        println!();
    }

    // ── Step 3: flag format (skip if flag_format.txt already exists) ──────────
    let flag_format_path = challenge.dir.join("flag_format.txt");
    if !flag_format_path.exists() {
        let formats = load_flag_formats();
        let config_path = flag_formats_config_path();
        println!("  \x1b[2mFlag format not set — choose from list or type custom:\x1b[0m");
        println!("  \x1b[2m(edit {})\x1b[0m", config_path.display());
        println!();
        for (i, fmt) in formats.iter().enumerate() {
            println!("    \x1b[2m{:2})\x1b[0m  \x1b[36m{fmt}\x1b[0m", i + 1);
        }
        println!("     \x1b[2m*)\x1b[0m  type a custom format  \x1b[2me.g. myctf{{...}}\x1b[0m");
        println!();

        loop {
            print!("  Flag format [1]: ");
            let _ = io::stdout().flush();
            let Some(line) = read_line() else { return Ok(false) };
            let trimmed = line.trim();

            let chosen: Option<String> = if trimmed.is_empty() {
                formats.first().cloned()
            } else if let Ok(n) = trimmed.parse::<usize>() {
                if n >= 1 && n <= formats.len() {
                    Some(formats[n - 1].clone())
                } else {
                    println!("  \x1b[31m✗  Choose 1–{}, or type a custom format\x1b[0m", formats.len());
                    None
                }
            } else if trimmed.contains('{') {
                Some(trimmed.to_string())
            } else {
                println!("  \x1b[31m✗  Enter a number or a format containing '{{', e.g. FLAG{{...}}\x1b[0m");
                None
            };

            if let Some(fmt) = chosen {
                challenge.flag_format = fmt.clone();
                let _ = fs::write(&flag_format_path, &fmt);
                println!("  \x1b[38;5;46m✓\x1b[0m  \x1b[36m{fmt}\x1b[0m");
                println!();
                break;
            }
        }
    }

    // ── Step 4: API mode (skip if --api was passed explicitly) ───────────────
    if api_mode_out.is_none() {
        let has_oauth      = openai_credentials_path().exists();
        let has_anth_key   = std::env::var("ANTHROPIC_API_KEY").is_ok()
                             || std::env::var("ANTHROPIC_AUTH_TOKEN").is_ok();
        let has_openai_key = std::env::var("OPENAI_API_KEY").is_ok()
                             || std::env::var("OPENAI_BASE_URL").is_ok();

        // Default selection based on what's already configured
        let default_choice: u8 = if has_oauth { 1 } else { 2 };

        println!("  \x1b[2mAPI mode:\x1b[0m");
        println!("    \x1b[2m1)\x1b[0m  OpenAI / ChatGPT account  \x1b[2m(OAuth — no key needed)\x1b[0m");
        println!("    \x1b[2m2)\x1b[0m  API key  \x1b[2m(Anthropic · OpenAI · custom endpoint)\x1b[0m");
        println!();

        let choice: u8 = loop {
            print!("  Mode [{}]: ", default_choice);
            let _ = io::stdout().flush();
            let Some(line) = read_line() else { return Ok(false) };
            match line.trim() {
                "" => break default_choice,
                "1" => break 1,
                "2" => break 2,
                _ => println!("  \x1b[31m✗  Enter 1 or 2\x1b[0m"),
            }
        };

        println!();

        match choice {
            // ── OpenAI OAuth ──────────────────────────────────────────────────
            1 => {
                *api_mode_out = Some(ApiMode::OpenAi);
                if has_oauth {
                    println!("  \x1b[38;5;46m✓\x1b[0m  Already logged in. Using saved credentials.");
                } else {
                    println!("  Opening browser for OpenAI authentication...");
                    println!();
                    run_openai_login()?;
                }
            }
            // ── API key ───────────────────────────────────────────────────────
            _ => {
                if has_anth_key {
                    println!("  \x1b[38;5;46m✓\x1b[0m  ANTHROPIC_API_KEY detected.");
                    *api_mode_out = Some(ApiMode::Anthropic);
                } else if has_openai_key {
                    println!("  \x1b[38;5;46m✓\x1b[0m  OPENAI_API_KEY / OPENAI_BASE_URL detected.");
                    *api_mode_out = Some(ApiMode::OpenAi);
                } else {
                    // Nothing configured — ask provider + key
                    println!("  \x1b[2mProvider:\x1b[0m");
                    println!("    \x1b[2m1)\x1b[0m  Anthropic   \x1b[2m(claude-opus-4-6, sonnet, haiku)\x1b[0m");
                    println!("    \x1b[2m2)\x1b[0m  OpenAI      \x1b[2m(gpt-4o, gpt-4o-mini)\x1b[0m");
                    println!("    \x1b[2m3)\x1b[0m  Custom      \x1b[2m(Gemini, Groq, vLLM, Ollama...)\x1b[0m");
                    println!();

                    let provider: u8 = loop {
                        print!("  Provider [1]: ");
                        let _ = io::stdout().flush();
                        let Some(line) = read_line() else { return Ok(false) };
                        match line.trim() {
                            "" | "1" => break 1,
                            "2"      => break 2,
                            "3"      => break 3,
                            _ => println!("  \x1b[31m✗  Enter 1, 2, or 3\x1b[0m"),
                        }
                    };

                    print!("  API key: ");
                    let _ = io::stdout().flush();
                    let Some(key_line) = read_line() else { return Ok(false) };
                    let key = key_line.trim().to_string();
                    if key.is_empty() {
                        println!("  \x1b[33m⚠  No key entered — you may get auth errors.\x1b[0m");
                    }

                    match provider {
                        1 => {
                            std::env::set_var("ANTHROPIC_API_KEY", &key);
                            *api_mode_out = Some(ApiMode::Anthropic);
                            println!("  \x1b[38;5;46m✓\x1b[0m  Anthropic key set for this session.");
                        }
                        2 => {
                            std::env::set_var("OPENAI_API_KEY", &key);
                            *api_mode_out = Some(ApiMode::OpenAi);
                            println!("  \x1b[38;5;46m✓\x1b[0m  OpenAI key set for this session.");
                        }
                        _ => {
                            print!("  Base URL \x1b[2m(e.g. https://api.groq.com/openai)\x1b[0m: ");
                            let _ = io::stdout().flush();
                            let Some(url_line) = read_line() else { return Ok(false) };
                            let base_url = url_line.trim().to_string();
                            std::env::set_var("OPENAI_API_KEY", &key);
                            if !base_url.is_empty() {
                                std::env::set_var("OPENAI_BASE_URL", &base_url);
                            }
                            *api_mode_out = Some(ApiMode::OpenAi);
                            println!("  \x1b[38;5;46m✓\x1b[0m  Custom endpoint set for this session.");
                        }
                    }
                }
            }
        }
        println!();
    }

    Ok(true)
}

/// Read a single line from stdin. Returns None on EOF or error.
fn read_line() -> Option<String> {
    let mut s = String::new();
    match io::stdin().read_line(&mut s) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(s),
    }
}

/// Set the terminal window/tab title using OSC 0 escape sequence.
/// Works in xterm, iTerm2, GNOME Terminal, Windows Terminal, tmux, etc.
fn set_terminal_title(title: &str) {
    // OSC 0 sets both icon name and window title; BEL terminates.
    print!("\x1b]0;{title}\x07");
    let _ = io::stdout().flush();
}

/// Reset the terminal title to blank so the shell can take over again on exit.
fn reset_terminal_title() {
    print!("\x1b]0;\x07");
    let _ = io::stdout().flush();
}

/// Prompt a yes/no question. Empty input and 'y' both mean yes.
fn prompt_yn(prompt: &str) -> io::Result<bool> {
    loop {
        print!("{prompt}");
        let _ = io::stdout().flush();
        let line = read_line()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))?;
        match line.trim().to_lowercase().as_str() {
            "" | "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("  Please type y or n."),
        }
    }
}

// ─── OpenAI OAuth ─────────────────────────────────────────────────────────────

fn openai_oauth_config() -> OAuthConfig {
    OAuthConfig {
        client_id: OPENAI_OAUTH_CLIENT_ID.to_string(),
        authorize_url: "https://auth.openai.com/oauth/authorize".to_string(),
        token_url: "https://auth.openai.com/oauth/token".to_string(),
        callback_port: Some(OPENAI_OAUTH_CALLBACK_PORT),
        manual_redirect_url: None,
        scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "offline_access".to_string(),
            "api.connectors.read".to_string(),
            "api.connectors.invoke".to_string(),
        ],
    }
}

fn openai_credentials_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
    PathBuf::from(home).join(".config/ctf-solver/openai-credentials.json")
}

fn load_openai_oauth() -> Option<OAuthTokenSet> {
    let raw = fs::read_to_string(openai_credentials_path()).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    Some(OAuthTokenSet {
        access_token: v["access_token"].as_str()?.to_string(),
        refresh_token: v["refresh_token"].as_str().map(String::from),
        expires_at: v["expires_at"].as_u64(),
        scopes: v["scopes"].as_array()
            .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
            .unwrap_or_default(),
    })
}

fn save_openai_oauth(token: &OAuthTokenSet) -> io::Result<()> {
    let path = openai_credentials_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::json!({
        "access_token": token.access_token,
        "refresh_token": token.refresh_token,
        "expires_at": token.expires_at,
        "scopes": token.scopes,
    });
    let rendered = serde_json::to_string_pretty(&json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(&path, format!("{rendered}\n"))
}

fn clear_openai_oauth() -> io::Result<()> {
    let path = openai_credentials_path();
    if path.exists() { fs::remove_file(path)?; }
    Ok(())
}

/// Load saved OpenAI OAuth token and refresh it if expired.
/// Returns the access_token string ready to use as Bearer, or None.
fn resolve_openai_auth() -> Option<String> {
    let token = load_openai_oauth()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?.as_secs();

    // Valid token — use directly.
    if token.expires_at.map_or(true, |exp| exp > now) {
        return Some(token.access_token);
    }

    // Expired — try to refresh.
    let refresh_token = token.refresh_token.clone()?;
    let token_url = openai_oauth_config().token_url;
    let client_id = OPENAI_OAUTH_CLIENT_ID.to_string();
    let scopes = token.scopes.clone();

    eprintln!("\x1b[2m[auth] OpenAI token expired — refreshing...\x1b[0m");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;

    rt.block_on(async move {
        let http = reqwest::Client::new();
        let resp = http.post(&token_url)
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", &client_id),
                ("refresh_token", &refresh_token),
            ])
            .send().await.ok()?;

        if !resp.status().is_success() { return None; }
        let json: serde_json::Value = resp.json().await.ok()?;

        let access_token = json["access_token"].as_str()?.to_string();
        let new_refresh = json["refresh_token"].as_str()
            .map(String::from)
            .or(Some(refresh_token));
        let expires_at = json["expires_in"].as_u64().map(|s| now + s);

        let refreshed = OAuthTokenSet { access_token: access_token.clone(), refresh_token: new_refresh, expires_at, scopes };
        let _ = save_openai_oauth(&refreshed);
        Some(access_token)
    })
}

/// Run the OpenAI OAuth PKCE login flow, save token on success.
fn run_openai_login() -> Result<(), Box<dyn std::error::Error>> {
    let config = openai_oauth_config();
    let redirect_uri = format!("http://localhost:{}/auth/callback", OPENAI_OAUTH_CALLBACK_PORT);
    let pkce = generate_pkce_pair()?;
    let state = generate_state()?;

    let authorize_url = OAuthAuthorizationRequest::from_config(
        &config, redirect_uri.clone(), state.clone(), &pkce,
    )
    .with_extra_param("id_token_add_organizations", "true")
    .with_extra_param("codex_cli_simplified_flow", "true")
    .build_url();

    println!("Starting OpenAI login...");
    println!("Listening on {redirect_uri}");

    if let Err(e) = open_browser_url(&authorize_url) {
        eprintln!("warning: could not open browser: {e}");
        println!("Open this URL manually:\n{authorize_url}");
    }

    // Catch the OAuth callback on localhost:1455/auth/callback
    let listener = TcpListener::bind(("127.0.0.1", OPENAI_OAUTH_CALLBACK_PORT))
        .map_err(|e| format!("could not bind port {OPENAI_OAUTH_CALLBACK_PORT}: {e}"))?;
    let (mut stream, _) = listener.accept()?;
    let mut buf = [0u8; 4096];
    let n = {
        use std::io::Read;
        stream.read(&mut buf)?
    };
    let request = String::from_utf8_lossy(&buf[..n]);
    let request_line = request.lines().next().ok_or("empty callback request")?;
    let target = request_line.split_whitespace().nth(1).ok_or("missing target")?;

    // OpenAI redirects to /auth/callback (not /callback like Anthropic)
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != "/auth/callback" {
        return Err(format!("unexpected callback path: {path}").into());
    }
    let callback = parse_oauth_callback_query(query)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let body = if callback.error.is_some() {
        "OpenAI login failed. You can close this window."
    } else {
        "OpenAI login succeeded. You can close this window."
    };
    let http_resp = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(), body
    );
    stream.write_all(http_resp.as_bytes())?;
    drop(stream);

    if let Some(err) = callback.error {
        let desc = callback.error_description.unwrap_or_else(|| "auth failed".to_string());
        return Err(format!("{err}: {desc}").into());
    }
    let code = callback.code.ok_or("callback missing authorization code")?;
    let returned_state = callback.state.ok_or("callback missing state")?;
    if returned_state != state {
        return Err("OAuth state mismatch — possible CSRF attack".into());
    }

    // Exchange authorization code for tokens
    let token_url = config.token_url.clone();
    let client_id = config.client_id.clone();
    let verifier = pkce.verifier.clone();
    let redirect_uri_clone = redirect_uri.clone();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let token = rt.block_on(async move {
        let http = reqwest::Client::new();
        let resp = http.post(&token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", &redirect_uri_clone),
                ("client_id", &client_id),
                ("code_verifier", &verifier),
            ])
            .send().await
            .map_err(|e| format!("token exchange request failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("token exchange failed {status}: {text}"));
        }

        let json: serde_json::Value = resp.json().await
            .map_err(|e| format!("token parse failed: {e}"))?;

        let access_token = json["access_token"].as_str()
            .ok_or("missing access_token")?.to_string();
        let refresh_token = json["refresh_token"].as_str().map(String::from);
        let scope = json["scope"].as_str().unwrap_or("").to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_secs();
        let expires_at = json["expires_in"].as_u64().map(|s| now + s);

        Ok(OAuthTokenSet {
            access_token,
            refresh_token,
            expires_at,
            scopes: scope.split_whitespace().map(String::from).collect(),
        })
    })?;

    save_openai_oauth(&token)?;
    println!("Login complete. Credentials saved to {}", openai_credentials_path().display());
    println!("Run `ctf <challenge> --model gpt-4o` to start solving.");
    Ok(())
}

fn open_browser_url(url: &str) -> io::Result<()> {
    let cmds: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("open", &[])]
    } else if cfg!(target_os = "windows") {
        &[("cmd", &["/C", "start", ""])]
    } else {
        &[("xdg-open", &[]), ("sensible-browser", &[])]
    };
    for (prog, prefix_args) in cmds {
        let mut cmd = std::process::Command::new(prog);
        cmd.args(*prefix_args).arg(url);
        match cmd.spawn() {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "no browser opener found"))
}

fn print_help() {
    println!(
        "ctf-solver {VERSION} — autonomous CTF challenge solver

USAGE
  ctf --challenge <dir> [OPTIONS]
  ctf <dir>             # shorthand
  ctf login             # log in with OpenAI account (OAuth)
  ctf logout            # clear saved OpenAI credentials

OPTIONS
  --challenge, -c <dir>       Challenge directory (must contain files/ subdir)
  --model, -m <name>          Model alias: opus (default), sonnet, haiku
  --api <openai|anthropic>    Force API backend (default: auto-detect from env vars)
                              openai    → /v1/chat/completions (vLLM, Ollama, etc.)
                              anthropic → /v1/messages (Claude, LiteLLM proxy)
  --category <cat>            Override auto-detected category
                              (pwn|web|crypto|rev|forensics|misc|osint|network)
  --resume, -r <session>      Resume a previous session
  --version, -V               Print version
  --help, -h                  Show this help

SLASH COMMANDS (in REPL)
  /hint                Nudge the agent without revealing the full solution
  /submit <flag>       Verify flag against the challenge flag_format
  /notes               Show the challenge notes.md
  /files               List files in the challenge files/ directory
  /reset               Clear session, keep challenge context
  /category <cat>      Switch category mid-session
  /status              Token usage and session info
  /compact             Force-compact conversation history
  /cost                Show token usage
  /export [path]       Export session transcript
  /help                Show this help
  /exit, /quit         Exit

ENVIRONMENT
  ANTHROPIC_BASE_URL   Base URL for Anthropic/LiteLLM proxy
  ANTHROPIC_API_KEY    API key (can be 'dummy' for local servers)
  OPENAI_BASE_URL      Base URL for OpenAI-compatible server (auto-selects --api openai)
  OPENAI_API_KEY       API key for OpenAI-compatible server (default: 'dummy')

CHALLENGE DIRECTORY LAYOUT
  <dir>/
    files/             Challenge binaries, source, pcap, images...
    self/              Your private notes — agent cannot read this folder
    desc.txt           Challenge description (optional)
    category.txt       Single-word category override (optional)
    flag_format.txt    e.g. picoCTF{{...}} (optional, default FLAG{{...}})
    notes.md           Auto-created, agent appends findings here"
    );
}

// ─── REPL ─────────────────────────────────────────────────────────────────────

fn run_repl(
    challenge: Challenge,
    model: String,
    resume_path: Option<PathBuf>,
    api_mode: Option<ApiMode>,
    notify: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let session_path = challenge.dir.join(".ctf-session.json");

    let session = if let Some(ref path) = resume_path {
        Session::load_from_path(path)?
    } else if session_path.exists() {
        Session::load_from_path(&session_path).unwrap_or_default()
    } else {
        Session::new()
    };

    let flag_extractor = FlagExtractor::new(&challenge.flag_format);
    let system_prompt = build_system_prompt(&challenge)?;

    let mut cli = CtfCli::new(
        challenge.clone(),
        model,
        session,
        system_prompt,
        session_path,
        flag_extractor,
        api_mode,
        notify,
    )?;

    // Slash command completions
    let completions = vec![
        "/hint".to_string(), "/submit".to_string(), "/notes".to_string(),
        "/files".to_string(), "/reset".to_string(), "/category".to_string(),
        "/status".to_string(), "/compact".to_string(), "/cost".to_string(),
        "/export".to_string(), "/writeup".to_string(), "/help".to_string(), "/exit".to_string(),
    ];
    let mut editor = input::LineEditor::new(
        format!("\x1b[38;5;46m[{}]\x1b[0m > ", challenge.category.as_str()),
        completions,
    );

    // Set terminal title to challenge name so it's visible in the tab/taskbar.
    set_terminal_title(&format!("⚡ {} [{}]", challenge.name, challenge.category.as_str()));

    println!("{}", cli.banner());

    if cli.runtime.session().messages.is_empty() {
        println!(
            "\x1b[90mChallenge loaded. Type a message to start, or \x1b[0m\x1b[1m/hint\x1b[0m\x1b[90m to let the agent begin automatically.\x1b[0m\n"
        );
    } else {
        let msg_count = cli.runtime.session().messages.len();
        println!(
            "\x1b[90mSession resumed ({} messages). Last exchanges:\x1b[0m\n",
            msg_count
        );
        print_session_tail(cli.runtime.session(), 6, 6);
        println!();
    }

    loop {
        match editor.read_line()? {
            input::ReadOutcome::ShowHistory => {
                let msg_count = cli.runtime.session().messages.len();
                if msg_count == 0 {
                    println!("\x1b[2m(no history yet)\x1b[0m");
                } else {
                    println!("\x1b[90m── Full session history ({msg_count} messages) ──\x1b[0m\n");
                    print_session_tail(cli.runtime.session(), usize::MAX, usize::MAX);
                    println!("\x1b[90m────────────────────────────────────────\x1b[0m");
                }
                continue;
            }
            input::ReadOutcome::Submit(raw) => {
                let trimmed = raw.trim().to_string();
                if trimmed.is_empty() {
                    continue;
                }
                if matches!(trimmed.as_str(), "/exit" | "/quit") {
                    cli.persist()?;
                    println!("Session saved to {}", cli.session_path.display());
                    break;
                }

                if trimmed.starts_with('/') {
                    cli.handle_slash(&trimmed)?;
                    continue;
                }

                editor.push_history(raw);
                cli.run_turn(&trimmed)?;
            }
            input::ReadOutcome::Cancel => {}
            input::ReadOutcome::Exit => {
                cli.persist()?;
                break;
            }
        }
    }

    reset_terminal_title();
    Ok(())
}

// ─── CtfCli struct ────────────────────────────────────────────────────────────

struct CtfCli {
    challenge: Challenge,
    model: String,
    runtime: ConversationRuntime<CtfApiClient, CtfToolExecutor>,
    session_path: PathBuf,
    flag_extractor: FlagExtractor,
    system_prompt: Vec<String>,
    api_mode: Option<ApiMode>,
    notify: bool,
}

impl CtfCli {
    fn new(
        challenge: Challenge,
        model: String,
        session: Session,
        system_prompt: Vec<String>,
        session_path: PathBuf,
        flag_extractor: FlagExtractor,
        api_mode: Option<ApiMode>,
        notify: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let api_client = CtfApiClient::new(model.clone(), api_mode)?;
        let tool_executor = CtfToolExecutor::new();

        // ── SECURITY LAYERS REMOVED ──────────────────────────────────────────
        // PermissionMode::Allow bypasses every permission check (permissions.rs:97).
        // None prompter means no interactive approval prompts ever fire.
        let permission_policy = PermissionPolicy::new(PermissionMode::Allow);

        let runtime = ConversationRuntime::new(
            session,
            api_client,
            tool_executor,
            permission_policy,
            system_prompt.clone(),
        )
        // ── TOKEN OPTIMISATION ───────────────────────────────────────────────
        // Compact at 50k input tokens, not the default 200k.
        // CTF sessions are goal-directed; old recon is noise after exploitation begins.
        .with_auto_compaction_input_tokens_threshold(CTF_AUTO_COMPACT_THRESHOLD);

        Ok(Self { challenge, model, runtime, session_path, flag_extractor, system_prompt, api_mode, notify })
    }

    fn banner(&self) -> String {
        let cwd = env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        format!(
            "\x1b[38;5;46m\
 ██████╗████████╗███████╗\n\
██╔════╝╚══██╔══╝██╔════╝\n\
██║        ██║   █████╗  \n\
██║        ██║   ██╔══╝  \n\
╚██████╗   ██║   ██║     \n\
 ╚═════╝   ╚═╝   ╚═╝\x1b[0m \x1b[38;5;208mSolver\x1b[0m\n\n\
  \x1b[2mChallenge\x1b[0m   {name}\n\
  \x1b[2mCategory\x1b[0m    {emoji} {cat}\n\
  \x1b[2mFlag fmt\x1b[0m    {flag_fmt}\n\
  \x1b[2mModel\x1b[0m       {model}\n\
  \x1b[2mDirectory\x1b[0m   {dir}\n\
  \x1b[2mSession\x1b[0m     {sess}\n\n\
  \x1b[38;5;196mPermissions: NONE (allow-all)\x1b[0m  \
\x1b[38;5;208mSandbox: OFF\x1b[0m  \
\x1b[38;5;226mCompact: 50k tokens\x1b[0m\n\n\
  /hint  /submit <flag>  /notes  /files  /writeup  /reset  /help",
            name     = self.challenge.name,
            emoji    = self.challenge.category.emoji(),
            cat      = self.challenge.category.as_str(),
            flag_fmt = self.challenge.flag_format,
            model    = self.model,
            dir      = cwd,
            sess     = self.session_path.display(),
        )
    }

    fn run_turn(&mut self, input: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut spinner = Spinner::new();
        let mut stdout = io::stdout();
        spinner.tick(
            &format!("🔍 Solving [{}]...", self.challenge.category.as_str()),
            TerminalRenderer::new().color_theme(),
            &mut stdout,
        )?;

        // ── SIGINT handler: Ctrl+C sets flag so stream() aborts after current call ──
        let flag = agent_interrupted();
        flag.store(false, Ordering::Relaxed);
        // signal-hook registers safely (no unsafe). Only registered once; repeated
        // calls to register() with the same signal + Arc are no-ops in signal-hook.
        let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(flag));

        // ── No prompter = zero approval dialogs ──────────────────────────────
        let mut result = self.runtime.run_turn(input, None);

        // 413 / 524 → session too large; auto-compact and retry once
        if let Err(ref e) = result {
            let emsg = e.to_string();
            if emsg.contains("413") || emsg.contains("524") {
                spinner.tick("⚡ context too large — compacting session and retrying...",
                    TerminalRenderer::new().color_theme(), &mut stdout)?;
                let compacted = compact_session(
                    self.runtime.session(),
                    CompactionConfig {
                        preserve_recent_messages: CTF_COMPACT_PRESERVE,
                        max_estimated_tokens: 0,
                    },
                );
                let removed = compacted.removed_message_count;
                let api_client = CtfApiClient::new(self.model.clone(), self.api_mode)?;
                self.runtime = ConversationRuntime::new(
                    compacted.compacted_session,
                    api_client,
                    CtfToolExecutor::new(),
                    PermissionPolicy::new(PermissionMode::Allow),
                    self.system_prompt.clone(),
                )
                .with_auto_compaction_input_tokens_threshold(CTF_AUTO_COMPACT_THRESHOLD);
                eprintln!("\x1b[2m[compact] removed {removed} messages, retrying\x1b[0m");
                result = self.runtime.run_turn(input, None);
            }
        }

        let interrupted = flag.swap(false, Ordering::Relaxed);

        match result {
            Ok(summary) => {
                spinner.finish("✅ Done", TerminalRenderer::new().color_theme(), &mut stdout)?;
                println!();

                if let Some(compact_event) = summary.auto_compaction {
                    println!(
                        "\x1b[2m[auto-compacted: removed {} messages]\x1b[0m",
                        compact_event.removed_message_count
                    );
                }

                // Scan all tool outputs for flags
                let tool_outputs: Vec<String> = summary
                    .tool_results
                    .iter()
                    .flat_map(|msg| msg.blocks.iter())
                    .filter_map(|block| match block {
                        ContentBlock::ToolResult { output, .. } => Some(output.clone()),
                        _ => None,
                    })
                    .collect();

                // Also scan assistant text
                let assistant_texts: Vec<String> = summary
                    .assistant_messages
                    .iter()
                    .flat_map(|msg| msg.blocks.iter())
                    .filter_map(|block| match block {
                        ContentBlock::Text { text } => Some(text.clone()),
                        _ => None,
                    })
                    .collect();

                let all_outputs: Vec<String> = tool_outputs
                    .into_iter()
                    .chain(assistant_texts.into_iter())
                    .collect();

                if let Some(flag) = self.flag_extractor.scan_outputs(&all_outputs) {
                    println!("{}", render_flag_found(&flag));
                    // Append to notes.md
                    let notes = self.challenge.dir.join("notes.md");
                    let _ = fs::OpenOptions::new()
                        .append(true)
                        .open(&notes)
                        .and_then(|mut f| writeln!(f, "\n## FLAG FOUND\n```\n{flag}\n```\n"));
                }

                self.persist()?;
                if self.notify {
                    send_desktop_notification(&self.challenge.name, "Agent finished");
                    play_sound();
                }
                Ok(())
            }
            Err(error) => {
                if interrupted || error.to_string().contains("interrupted") {
                    spinner.finish("⏸ Paused", TerminalRenderer::new().color_theme(), &mut stdout)?;
                    println!("\n\x1b[33mAgent paused. Session saved. Continue with your next message.\x1b[0m\n");
                } else {
                    spinner.fail("❌ Failed", TerminalRenderer::new().color_theme(), &mut stdout)?;
                    eprintln!("\n\x1b[31merror: {error}\x1b[0m");
                    eprintln!("\x1b[33mSession saved. You can retry or continue with a new message.\x1b[0m\n");
                }
                // Always persist — the runtime may have completed some tool calls
                // before the failure, so partial progress is worth keeping.
                let _ = self.persist();
                Ok(())
            }
        }
    }

    fn handle_slash(&mut self, input: &str) -> Result<(), Box<dyn std::error::Error>> {
        let (cmd, rest) = input
            .trim_start_matches('/')
            .split_once(char::is_whitespace)
            .map(|(c, r)| (c, r.trim()))
            .unwrap_or((input.trim_start_matches('/'), ""));

        match cmd {
            "hint" => {
                if self.runtime.session().messages.is_empty() {
                    // Fresh session — kick off autonomous solve
                    let init = format!(
                        "Start solving the CTF challenge '{}' (category: {}). \
                         Examine the files in {}/files/ and begin your exploitation approach.",
                        self.challenge.name,
                        self.challenge.category.as_str(),
                        self.challenge.dir.display(),
                    );
                    self.run_turn(&init)?;
                } else {
                    self.run_turn(
                        "Give me a specific hint about this challenge without fully solving it. \
                         Point me toward the right approach or a key observation I might have missed.",
                    )?;
                }
            }
            "submit" => {
                if rest.is_empty() {
                    println!("Usage: /submit <flag>");
                } else {
                    self.verify_flag(rest);
                }
            }
            "notes" => {
                let path = self.challenge.dir.join("notes.md");
                match fs::read_to_string(&path) {
                    Ok(content) => println!("{content}"),
                    Err(_) => println!("(no notes yet — {})", path.display()),
                }
            }
            "files" => {
                let files_dir = self.challenge.dir.join("files");
                match fs::read_dir(&files_dir) {
                    Ok(entries) => {
                        println!("Files in {}", files_dir.display());
                        for entry in entries.filter_map(|e| e.ok()) {
                            let meta = entry.metadata().ok();
                            let size = meta.map(|m| m.len()).unwrap_or(0);
                            println!("  {:>10} bytes  {}", size, entry.file_name().to_string_lossy());
                        }
                    }
                    Err(_) => println!("files/ directory not found"),
                }
            }
            "reset" => {
                println!("Resetting session (challenge context preserved)...");
                let system_prompt = build_system_prompt(&self.challenge)?;
                let api_client = CtfApiClient::new(self.model.clone(), self.api_mode)?;
                let tool_executor = CtfToolExecutor::new();
                self.runtime = ConversationRuntime::new(
                    Session::new(),
                    api_client,
                    tool_executor,
                    PermissionPolicy::new(PermissionMode::Allow),
                    system_prompt.clone(),
                )
                .with_auto_compaction_input_tokens_threshold(CTF_AUTO_COMPACT_THRESHOLD);
                self.system_prompt = system_prompt;
                self.persist()?;
                println!("Session cleared. Starting fresh on '{}'.", self.challenge.name);
            }
            "category" => {
                if rest.is_empty() {
                    println!("Current category: {} {}", self.challenge.category.emoji(), self.challenge.category.as_str());
                    println!("Usage: /category <pwn|web|crypto|rev|forensics|misc|osint|network>");
                } else if let Some(cat) = Category::from_str(rest) {
                    self.challenge = self.challenge.clone().with_category(cat);
                    println!("Category switched to: {} {}", cat.emoji(), cat.as_str());
                    println!("Note: system prompt update takes effect on next /reset");
                } else {
                    println!("Unknown category: {rest}");
                }
            }
            "status" => {
                let usage = self.runtime.usage();
                let cumulative = usage.cumulative_usage();
                println!(
                    "Status\n  Model        {}\n  Category     {} {}\n  Messages     {}\n  Turns        {}\n  Input tokens {}\n  Output tokens {}\n  Auto-compact threshold  {} tokens\n  Compact preserve        {} messages",
                    self.model,
                    self.challenge.category.emoji(),
                    self.challenge.category.as_str(),
                    self.runtime.session().messages.len(),
                    usage.turns(),
                    cumulative.input_tokens,
                    cumulative.output_tokens,
                    CTF_AUTO_COMPACT_THRESHOLD,
                    CTF_COMPACT_PRESERVE,
                );
            }
            "compact" => {
                // Aggressive: keep only last CTF_COMPACT_PRESERVE messages
                let result = compact_session(
                    self.runtime.session(),
                    CompactionConfig {
                        preserve_recent_messages: CTF_COMPACT_PRESERVE,
                        max_estimated_tokens: 0, // force compact regardless of size
                    },
                );
                let removed = result.removed_message_count;
                let kept = result.compacted_session.messages.len();
                let api_client = CtfApiClient::new(self.model.clone(), self.api_mode)?;
                let tool_executor = CtfToolExecutor::new();
                self.runtime = ConversationRuntime::new(
                    result.compacted_session,
                    api_client,
                    tool_executor,
                    PermissionPolicy::new(PermissionMode::Allow),
                    self.system_prompt.clone(),
                )
                .with_auto_compaction_input_tokens_threshold(CTF_AUTO_COMPACT_THRESHOLD);
                self.persist()?;
                println!("Compacted: removed {removed} messages, kept {kept}.");
            }
            "cost" => {
                let u = self.runtime.usage().cumulative_usage();
                println!(
                    "Cost\n  Input tokens   {}\n  Output tokens  {}\n  Cache create   {}\n  Cache read     {}\n  Total tokens   {}",
                    u.input_tokens, u.output_tokens,
                    u.cache_creation_input_tokens, u.cache_read_input_tokens,
                    u.total_tokens(),
                );
            }
            "export" => {
                let path = if rest.is_empty() {
                    self.challenge.dir.join(format!("{}-export.txt", self.challenge.name))
                } else {
                    PathBuf::from(rest)
                };
                let content = render_export(self.runtime.session());
                fs::write(&path, &content)?;
                println!("Exported {} messages to {}", self.runtime.session().messages.len(), path.display());
            }
            "notify" => {
                self.notify = !self.notify;
                if self.notify {
                    println!("\x1b[32m🔔 Desktop notifications ON\x1b[0m");
                    send_desktop_notification(&self.challenge.name, "Notifications enabled");
                } else {
                    println!("\x1b[33m🔕 Desktop notifications OFF\x1b[0m");
                }
            }
            "writeup" => {
                let output_path = self.challenge.dir.join("writeup.md");
                let prompt = format!(
                    r#"Write a thorough CTF writeup for the challenge '{}' (category: {}, flag format: {}).

Save the writeup to `./writeup.md` using bash.

The writeup must be in English and follow this structure:

# {name} — CTF Writeup

## Challenge Overview
- **Category**: {cat}
- **Flag format**: {flag_fmt}
- Brief description and what kind of vulnerability/technique is involved.

## Initial Reconnaissance
Walk through every observation made during the initial triage:
file types, strings, metadata, network ports, source code review — whatever
applied. Explain *why* each observation matters.

## Analysis
Step-by-step breakdown of the full analysis. For each step:
- What you observed or tried
- What the result told you
- How it led to the next step
Do not skip failed attempts if they led somewhere; they are part of the story.

## Exploitation / Solution
Detailed explanation of the final approach:
- The vulnerability or logic flaw exploited
- Why it works (conceptual explanation)
- The exact sequence of actions taken

## Reproduction Guide
Provide a complete, self-contained guide to reproduce the flag from scratch.
Prefer Python scripts or pwntools/requests/Crypto code over raw CLI one-liners.
Include every command or script needed, with comments explaining each part.
A reader with no prior context should be able to follow this section alone and
get the flag.

## Flag
```
FLAG HERE
```

## Key Takeaways
1-3 bullet points: what technique or concept this challenge demonstrates.

---

Write the file now using bash, then confirm the path."#,
                    self.challenge.name,
                    self.challenge.category.as_str(),
                    self.challenge.flag_format,
                    name = self.challenge.name,
                    cat = self.challenge.category.as_str(),
                    flag_fmt = self.challenge.flag_format,
                );
                println!("\x1b[2mGenerating writeup → {}\x1b[0m\n", output_path.display());
                self.run_turn(&prompt)?;
            }
            "help" => print_repl_help(),
            _ => println!("Unknown command: /{cmd}  — type /help"),
        }
        Ok(())
    }

    fn verify_flag(&self, submitted: &str) {
        // Simple format check: does it look like the expected pattern?
        let prefix = self.challenge.flag_format
            .trim_end_matches("{...}")
            .trim_end_matches('{');
        let submitted_lower = submitted.to_lowercase();
        let prefix_lower = prefix.to_lowercase();

        if submitted_lower.starts_with(&prefix_lower) && submitted.contains('{') && submitted.ends_with('}') {
            println!("{}", render_flag_found(submitted));
            println!("\x1b[38;5;46mFlag format looks correct. Submit it on the CTF platform.\x1b[0m");
        } else {
            println!("\x1b[38;5;196mFlag format mismatch.\x1b[0m");
            println!("  Expected format: {}", self.challenge.flag_format);
            println!("  Submitted:       {submitted}");
        }
    }

    fn persist(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.runtime.session().save_to_path(&self.session_path)?;
        Ok(())
    }
}

fn print_repl_help() {
    println!(
        "CTF Solver commands
  /hint                 Ask for a nudge without full solution
  /submit <flag>        Verify flag format
  /notes                Show notes.md
  /files                List challenge files
  /reset                Clear session, keep challenge context
  /category <name>      Show/switch category
  /status               Session info and token usage
  /compact              Force-compact conversation history
  /cost                 Token usage breakdown
  /export [path]        Export transcript
  /writeup              Generate a detailed writeup and save to writeup.md
  /help                 This help
  /exit, /quit          Exit and save session

  Up/Down               Navigate prompt history
  Ctrl-C                Clear input (exit if empty)
  Shift+Enter           Insert newline"
    );
}

// ─── System prompt builder ────────────────────────────────────────────────────

fn build_system_prompt(
    challenge: &Challenge,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let ctf_prompt = ctf_system_prompt(challenge);

    // Also load project CLAUDE.md if present, but put CTF prompt first
    let cwd = env::current_dir()?;
    let mut sections = vec![ctf_prompt];

    if let Ok(config_sections) = runtime::load_system_prompt(
        cwd,
        "2026-04-07",
        env::consts::OS,
        "unknown",
    ) {
        sections.extend(config_sections);
    }

    Ok(sections)
}

// ─── CTF API client ──────────────────────────────────────────────────────────
// Supports two backends:
//   1. Anthropic (default) — set ANTHROPIC_BASE_URL to point at LiteLLM or Claude
//   2. OpenAI-compatible   — set OPENAI_BASE_URL to point directly at vLLM/Ollama/etc.
//
// Detection:
//   OPENAI_BASE_URL set  → OpenAI mode (direct /v1/chat/completions, no LiteLLM needed)
//   otherwise            → Anthropic mode (existing behaviour)

enum ApiBackend {
    Anthropic(AnthropicClient),
    OpenAi { base_url: String, api_key: String, http: reqwest::Client },
}

struct CtfApiClient {
    tokio_rt: tokio::runtime::Runtime,
    backend: ApiBackend,
    model: String,
}

impl CtfApiClient {
    fn new(model: String, mode_override: Option<ApiMode>) -> Result<Self, Box<dyn std::error::Error>> {
        let tokio_rt = tokio::runtime::Runtime::new()?;

        // Resolve effective mode:
        //   1. --api flag (mode_override) takes priority
        //   2. OPENAI_BASE_URL / OPENAI_API_KEY env vars → OpenAI mode
        //   3. Saved OpenAI OAuth credentials → OpenAI mode
        //   4. fallback → Anthropic mode
        let effective_mode = mode_override.unwrap_or_else(|| {
            if std::env::var("OPENAI_BASE_URL").is_ok()
                || std::env::var("OPENAI_API_KEY").is_ok()
                || openai_credentials_path().exists()
            {
                ApiMode::OpenAi
            } else {
                ApiMode::Anthropic
            }
        });

        let backend = match effective_mode {
            ApiMode::OpenAi => {
                let base_url = std::env::var("OPENAI_BASE_URL")
                    .unwrap_or_else(|_| OPENAI_DEFAULT_BASE_URL.to_string());
                let api_key = std::env::var("OPENAI_API_KEY")
                    .ok()
                    .or_else(resolve_openai_auth)
                    .unwrap_or_else(|| "dummy".to_string());
                let http = reqwest::Client::new();
                eprintln!("\x1b[2m[api] OpenAI mode → {base_url}\x1b[0m");
                ApiBackend::OpenAi { base_url, api_key, http }
            }
            ApiMode::Anthropic => {
                let auth = resolve_startup_auth_source(|| {
                    let cwd = env::current_dir().map_err(api::ApiError::from)?;
                    let config = ConfigLoader::default_for(&cwd).load().map_err(|e| {
                        api::ApiError::Auth(format!("config load failed: {e}"))
                    })?;
                    Ok(config.oauth().cloned())
                })?;
                ApiBackend::Anthropic(
                    AnthropicClient::from_auth(auth).with_base_url(api::read_base_url())
                )
            }
        };

        Ok(Self { tokio_rt, backend, model })
    }
}

impl ApiClient for CtfApiClient {
    fn stream(&mut self, request: ApiRequest) -> Result<Vec<AssistantEvent>, RuntimeError> {
        if agent_interrupted().load(Ordering::Relaxed) {
            return Err(RuntimeError::new("interrupted"));
        }
        match &self.backend {
            ApiBackend::OpenAi { .. } => self.stream_openai(request),
            ApiBackend::Anthropic(_) => self.stream_anthropic(request),
        }
    }
}

impl CtfApiClient {
    fn stream_anthropic(&mut self, request: ApiRequest) -> Result<Vec<AssistantEvent>, RuntimeError> {
        let tool_defs: Vec<ToolDefinition> = ctf_tool_specs()
            .into_iter()
            .map(|spec| ToolDefinition {
                name: spec.name.to_string(),
                description: Some(spec.description.to_string()),
                input_schema: spec.input_schema,
            })
            .collect();

        let message_request = MessageRequest {
            model: self.model.clone(),
            max_tokens: max_tokens_for_model(&self.model),
            messages: convert_messages(&request.messages),
            system: (!request.system_prompt.is_empty())
                .then(|| request.system_prompt.join("\n\n")),
            tools: Some(tool_defs),
            tool_choice: Some(ToolChoice::Auto),
            stream: true,
        };

        let client = match &self.backend {
            ApiBackend::Anthropic(c) => c.clone(),
            _ => unreachable!(),
        };

        self.tokio_rt.block_on(async {
            let mut stream = client
                .stream_message(&message_request)
                .await
                .map_err(|e| RuntimeError::new(e.to_string()))?;

            let renderer = TerminalRenderer::new();
            let mut markdown_state = MarkdownStreamState::default();
            let mut stdout = io::stdout();
            let mut events: Vec<AssistantEvent> = Vec::new();
            let mut pending_tool: Option<(String, String, String)> = None;
            let mut saw_stop = false;

            while let Some(event) = stream
                .next_event()
                .await
                .map_err(|e| RuntimeError::new(e.to_string()))?
            {
                match event {
                    ApiStreamEvent::MessageStart(start) => {
                        events.push(AssistantEvent::Usage(TokenUsage {
                            input_tokens: start.message.usage.input_tokens,
                            output_tokens: start.message.usage.output_tokens,
                            cache_creation_input_tokens: start.message.usage.cache_creation_input_tokens,
                            cache_read_input_tokens: start.message.usage.cache_read_input_tokens,
                        }));
                    }
                    ApiStreamEvent::ContentBlockStart(start) => {
                        if let OutputContentBlock::ToolUse { id, name, .. } = start.content_block {
                            pending_tool = Some((id, name, String::new()));
                        }
                    }
                    ApiStreamEvent::ContentBlockDelta(delta_event) => {
                        match delta_event.delta {
                            ContentBlockDelta::TextDelta { text } => {
                                if !text.is_empty() {
                                    if let Some(rendered) = markdown_state.push(&renderer, &text) {
                                        write!(stdout, "{rendered}")
                                            .and_then(|()| stdout.flush())
                                            .map_err(|e| RuntimeError::new(e.to_string()))?;
                                    }
                                    events.push(AssistantEvent::TextDelta(text));
                                }
                            }
                            ContentBlockDelta::InputJsonDelta { partial_json } => {
                                if let Some((_, _, ref mut input)) = pending_tool {
                                    input.push_str(&partial_json);
                                }
                            }
                            // Ignore thinking/signature deltas from reasoning models
                            ContentBlockDelta::ThinkingDelta { .. }
                            | ContentBlockDelta::SignatureDelta { .. } => {}
                        }
                    }
                    ApiStreamEvent::ContentBlockStop(_) => {
                        if let Some(rendered) = markdown_state.flush(&renderer) {
                            write!(stdout, "{rendered}")
                                .and_then(|()| stdout.flush())
                                .map_err(|e| RuntimeError::new(e.to_string()))?;
                        }
                        if let Some((id, name, input)) = pending_tool.take() {
                            // Render tool call header inline
                            let display = format_ctf_tool_call(&name, &input);
                            write!(stdout, "\n{display}\n")
                                .and_then(|()| stdout.flush())
                                .map_err(|e| RuntimeError::new(e.to_string()))?;
                            events.push(AssistantEvent::ToolUse { id, name, input });
                        }
                    }
                    ApiStreamEvent::MessageDelta(delta_event) => {
                        events.push(AssistantEvent::Usage(TokenUsage {
                            input_tokens: delta_event.usage.input_tokens,
                            output_tokens: delta_event.usage.output_tokens,
                            cache_creation_input_tokens: 0,
                            cache_read_input_tokens: 0,
                        }));
                    }
                    ApiStreamEvent::MessageStop(_) => {
                        saw_stop = true;
                        if let Some(rendered) = markdown_state.flush(&renderer) {
                            write!(stdout, "{rendered}")
                                .and_then(|()| stdout.flush())
                                .map_err(|e| RuntimeError::new(e.to_string()))?;
                        }
                        events.push(AssistantEvent::MessageStop);
                    }
                }
            }

            if !saw_stop
                && events.iter().any(|e| {
                    matches!(e, AssistantEvent::TextDelta(t) if !t.is_empty())
                        || matches!(e, AssistantEvent::ToolUse { .. })
                })
            {
                events.push(AssistantEvent::MessageStop);
            }

            Ok(events)
        })
    }

    #[allow(clippy::too_many_lines)]
    fn stream_openai(&mut self, request: ApiRequest) -> Result<Vec<AssistantEvent>, RuntimeError> {
        let (base_url, api_key, http) = match &self.backend {
            ApiBackend::OpenAi { base_url, api_key, http } => {
                (base_url.clone(), api_key.clone(), http.clone())
            }
            _ => unreachable!(),
        };

        // Normalise base_url: strip trailing slash, ensure no double /v1
        let base = base_url.trim_end_matches('/');
        let endpoint = if base.ends_with("/v1") {
            format!("{base}/chat/completions")
        } else {
            format!("{base}/v1/chat/completions")
        };

        let tools_json: Vec<Value> = ctf_tool_specs()
            .into_iter()
            .map(|spec| json!({
                "type": "function",
                "function": {
                    "name": spec.name,
                    "description": spec.description,
                    "parameters": spec.input_schema,
                }
            }))
            .collect();

        let mut messages = Vec::new();
        if !request.system_prompt.is_empty() {
            messages.push(json!({
                "role": "system",
                "content": request.system_prompt.join("\n\n"),
            }));
        }
        messages.extend(convert_messages_openai(&request.messages));

        let body = json!({
            "model": self.model,
            "messages": messages,
            "tools": tools_json,
            "tool_choice": "auto",
            "max_tokens": max_tokens_for_model(&self.model),
            "stream": true,
        });

        self.tokio_rt.block_on(async {
            use futures_util::StreamExt;
            let mut last_err = String::new();

            for attempt in 0..3u32 {
                if attempt > 0 {
                    let wait = std::time::Duration::from_secs(2u64.pow(attempt));
                    eprintln!("\x1b[2m[api] retrying in {}s (attempt {}/3)...\x1b[0m", wait.as_secs(), attempt + 1);
                    tokio::time::sleep(wait).await;
                }

                let resp = match http.post(&endpoint).bearer_auth(&api_key).json(&body).send().await {
                    Err(e) => { last_err = format!("openai request failed: {e}"); continue; }
                    Ok(r) => r,
                };

                let status = resp.status();
                // Transient server/gateway errors → retry
                if matches!(status.as_u16(), 502 | 503 | 504 | 520 | 521 | 522 | 523 | 524) {
                    let text = resp.text().await.unwrap_or_default();
                    last_err = format!("openai api returned {status}: {text}");
                    continue;
                }
                if !status.is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    return Err(RuntimeError::new(format!("openai api returned {status}: {text}")));
                }

                let renderer = TerminalRenderer::new();
                let mut markdown_state = MarkdownStreamState::default();
                let mut stdout = io::stdout();
                let mut events: Vec<AssistantEvent> = Vec::new();

                let mut pending_tools: std::collections::HashMap<usize, (String, String, String)> =
                    std::collections::HashMap::new();

                let bytes = resp.bytes_stream();
                let mut buf = String::new();
                let mut stream_err: Option<String> = None;

                tokio::pin!(bytes);
                'stream: while let Some(chunk) = bytes.next().await {
                    let chunk = match chunk {
                        Ok(c) => c,
                        Err(e) => { stream_err = Some(e.to_string()); break 'stream; }
                    };
                    buf.push_str(&String::from_utf8_lossy(&chunk));

                // Process complete lines
                while let Some(pos) = buf.find('\n') {
                    let line = buf[..pos].trim_end_matches('\r').to_string();
                    buf = buf[pos + 1..].to_string();

                    if line.is_empty() || line == ":" {
                        continue;
                    }
                    let data = if let Some(d) = line.strip_prefix("data: ") { d } else { continue };
                    if data == "[DONE]" {
                        break;
                    }

                    let chunk_val: Value = match serde_json::from_str(data) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    // Usage (some providers send it in stream)
                    if let Some(usage) = chunk_val.get("usage").filter(|u| !u.is_null()) {
                        let input_tokens = usage.get("prompt_tokens")
                            .and_then(Value::as_u64).unwrap_or(0) as u32;
                        let output_tokens = usage.get("completion_tokens")
                            .and_then(Value::as_u64).unwrap_or(0) as u32;
                        if input_tokens > 0 || output_tokens > 0 {
                            events.push(AssistantEvent::Usage(TokenUsage {
                                input_tokens,
                                output_tokens,
                                cache_creation_input_tokens: 0,
                                cache_read_input_tokens: 0,
                            }));
                        }
                    }

                    let choices = match chunk_val.get("choices").and_then(Value::as_array) {
                        Some(c) => c.clone(),
                        None => continue,
                    };

                    for choice in &choices {
                        let delta = match choice.get("delta") {
                            Some(d) => d,
                            None => continue,
                        };

                        // Text content
                        if let Some(text) = delta.get("content").and_then(Value::as_str) {
                            if !text.is_empty() {
                                if let Some(rendered) = markdown_state.push(&renderer, text) {
                                    write!(stdout, "{rendered}")
                                        .and_then(|()| stdout.flush())
                                        .map_err(|e| RuntimeError::new(e.to_string()))?;
                                }
                                events.push(AssistantEvent::TextDelta(text.to_string()));
                            }
                        }

                        // Tool call deltas
                        if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
                            for tc in tool_calls {
                                let idx = tc.get("index")
                                    .and_then(Value::as_u64).unwrap_or(0) as usize;
                                let entry = pending_tools.entry(idx)
                                    .or_insert_with(|| (String::new(), String::new(), String::new()));

                                if let Some(id) = tc.get("id").and_then(Value::as_str) {
                                    if !id.is_empty() { entry.0 = id.to_string(); }
                                }
                                if let Some(func) = tc.get("function") {
                                    if let Some(name) = func.get("name").and_then(Value::as_str) {
                                        if !name.is_empty() { entry.1 = name.to_string(); }
                                    }
                                    if let Some(args) = func.get("arguments").and_then(Value::as_str) {
                                        entry.2.push_str(args);
                                    }
                                }
                            }
                        }

                        // Finish reason — flush any pending tool calls
                        if choice.get("finish_reason").and_then(Value::as_str)
                            .map(|r| r == "tool_calls" || r == "stop")
                            .unwrap_or(false)
                        {
                            if let Some(rendered) = markdown_state.flush(&renderer) {
                                write!(stdout, "{rendered}")
                                    .and_then(|()| stdout.flush())
                                    .map_err(|e| RuntimeError::new(e.to_string()))?;
                            }
                            let mut sorted_tools: Vec<_> = pending_tools.drain().collect();
                            sorted_tools.sort_by_key(|(i, _)| *i);
                            for (_, (id, name, input)) in sorted_tools {
                                if !name.is_empty() {
                                    let display = format_ctf_tool_call(&name, &input);
                                    write!(stdout, "\n{display}\n")
                                        .and_then(|()| stdout.flush())
                                        .map_err(|e| RuntimeError::new(e.to_string()))?;
                                    events.push(AssistantEvent::ToolUse { id, name, input });
                                }
                            }
                            events.push(AssistantEvent::MessageStop);
                        }
                    }
                }
            }

            // Flush remaining markdown
                if let Some(rendered) = markdown_state.flush(&renderer) {
                    write!(stdout, "{rendered}")
                        .and_then(|()| stdout.flush())
                        .map_err(|e| RuntimeError::new(e.to_string()))?;
                }

                // Stream dropped mid-way → retry
                if let Some(e) = stream_err {
                    last_err = format!("error decoding response body: {e}");
                    // Print a visible break so the user knows the previous output was partial.
                    eprintln!("\x1b[2m[api] stream interrupted — retrying...\x1b[0m");
                    continue;
                }

                // Emit stop if not yet emitted
                if !events.iter().any(|e| matches!(e, AssistantEvent::MessageStop)) {
                    if events.iter().any(|e| {
                        matches!(e, AssistantEvent::TextDelta(t) if !t.is_empty())
                            || matches!(e, AssistantEvent::ToolUse { .. })
                    }) {
                        events.push(AssistantEvent::MessageStop);
                    }
                }

                return Ok(events);
            }

            Err(RuntimeError::new(last_err))
        })
    }
}

// ─── CTF-specific tool implementations ───────────────────────────────────────

fn sh(cmd: &str) -> String {
    std::process::Command::new("sh")
        .args(["-c", cmd])
        .output()
        .map(|o| {
            let out = String::from_utf8_lossy(&o.stdout);
            let err = String::from_utf8_lossy(&o.stderr);
            if out.trim().is_empty() { err.into_owned() } else { out.into_owned() }
        })
        .unwrap_or_default()
}

/// All-in-one binary fingerprint: file + checksec + strings + ldd + arch.
fn ctf_binary_recon(path: &str) -> Result<String, String> {
    // Sanitise path for shell use
    let esc = path.replace('\'', "'\\''");
    let mut out = String::new();

    out.push_str(&format!("=== file ===\n{}\n", sh(&format!("file '{esc}'"))));

    let checksec = sh(&format!("checksec --file='{esc}' 2>/dev/null || checksec --binary='{esc}' 2>/dev/null"));
    if !checksec.trim().is_empty() {
        out.push_str(&format!("=== checksec ===\n{checksec}\n"));
    } else {
        // Fallback: read ELF flags manually with readelf
        let readelf = sh(&format!("readelf -W -d '{esc}' 2>/dev/null | grep -E 'BIND_NOW|RELRO|FLAGS'"));
        let header  = sh(&format!("readelf -h '{esc}' 2>/dev/null | grep -E 'Class|Machine|Type'"));
        out.push_str(&format!("=== readelf (no checksec) ===\n{header}{readelf}\n"));
    }

    out.push_str(&format!("=== ldd ===\n{}\n", sh(&format!("ldd '{esc}' 2>/dev/null || echo '(not dynamic ELF)'"))));

    let strings = sh(&format!("strings -n8 '{esc}' 2>/dev/null | head -60"));
    out.push_str(&format!("=== strings (first 60) ===\n{strings}\n"));

    Ok(out.trim_end().to_string())
}

/// Decompile a function using radare2 (r2). Falls back to objdump disassembly.
fn ctf_decompile(path: &str, function: &str) -> Result<String, String> {
    let esc  = path.replace('\'', "'\\''");
    let func = function.replace('\'', "");

    // radare2: try multiple name conventions (sym.func, func, import.func)
    let r2_cmd = format!(
        "r2 -A -q -c 'pdf @ sym.{func} 2>/dev/null; pdf @ {func} 2>/dev/null' '{esc}' 2>/dev/null | head -300"
    );
    let r2_out = sh(&r2_cmd);
    if !r2_out.trim().is_empty() && !r2_out.contains("Cannot find function") {
        return Ok(format!("=== radare2: {func} ===\n{r2_out}"));
    }

    // Fallback: objdump
    let objdump_cmd = format!(
        "objdump -d -M intel '{esc}' 2>/dev/null \
         | awk '/<{func}[>@]/ {{f=1}} f {{print; lines++; if (/^$/ && lines>5) exit}}' \
         | head -200"
    );
    let objdump_out = sh(&objdump_cmd);
    if !objdump_out.trim().is_empty() {
        return Ok(format!("=== objdump: {func} ===\n{objdump_out}"));
    }

    Err(format!(
        "Could not decompile '{func}' in '{path}'. \
         Is radare2 installed? (apt install radare2). \
         Try: binary_recon to list available symbols first."
    ))
}

// ─── Sound notification ───────────────────────────────────────────────────────

fn sound_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
    PathBuf::from(home).join(".config/ctf-solver/sound.txt")
}

/// System sound files tried in order on first run to find a usable default.
const CANDIDATE_SOUNDS: &[&str] = &[
    "/usr/share/sounds/Yaru/stereo/complete.oga",
    "/usr/share/sounds/freedesktop/stereo/complete.oga",
    "/usr/share/sounds/ubuntu/stereo/message-new-instant.ogg",
    "/usr/share/sounds/Yaru/stereo/message.oga",
    "/usr/share/sounds/sound-icons/prompt.wav",
    "/usr/share/sounds/speech-dispatcher/dummy-message.wav",
];

/// Load the configured sound path.
/// On first run, auto-detect a system sound and save it to the config file.
/// Returns None if sound is disabled ("none") or no sound is found.
fn load_sound_path() -> Option<String> {
    let cfg = sound_config_path();

    if cfg.exists() {
        let raw = fs::read_to_string(&cfg).ok()?;
        // Strip comment lines, take first non-empty line
        let path = raw
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .find(|l| !l.trim().is_empty())
            .map(str::trim)
            .unwrap_or("")
            .to_string();
        return if path.eq_ignore_ascii_case("none") || path.is_empty() {
            None
        } else {
            Some(path)
        };
    }

    // First run — find a usable sound file from system defaults
    let found = CANDIDATE_SOUNDS
        .iter()
        .find(|&&p| std::path::Path::new(p).exists())
        .map(|&p| p.to_string());

    // Persist the choice (or "none") so the user can see and edit it
    if let Some(parent) = cfg.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let content = format!(
        "# CTF Solver — notification sound\n\
         # Set to the path of any audio file, or 'none' to disable.\n\
         # Players tried: ffplay, paplay, cvlc, aplay\n\
         {}\n",
        found.as_deref().unwrap_or("none")
    );
    let _ = fs::write(&cfg, content);

    found
}

/// Play the configured notification sound in the background (non-blocking).
/// Tries multiple players until one succeeds.
fn play_sound() {
    let Some(path) = load_sound_path() else { return };

    // (program, args-before-file)
    let players: &[(&str, &[&str])] = &[
        ("ffplay",  &["-nodisp", "-autoexit", "-loglevel", "quiet"]),
        ("paplay",  &[]),
        ("cvlc",    &["--play-and-exit", "--quiet", "--no-interact"]),
        ("aplay",   &["-q"]),
        ("mpv",     &["--no-video", "--really-quiet"]),
    ];

    for (prog, pre_args) in players {
        let mut cmd = std::process::Command::new(prog);
        cmd.args(*pre_args).arg(&path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        match cmd.spawn() {
            Ok(_) => return, // fire-and-forget
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => continue,
        }
    }
}

fn send_desktop_notification(challenge: &str, body: &str) {
    let result = std::process::Command::new("notify-send")
        .args(["--app-name=CTF Solver", "--icon=utilities-terminal",
               "--urgency=normal", &format!("CTF · {challenge}"), body])
        .output();
    match result {
        Ok(out) if out.status.success() => {
            eprintln!("\x1b[2m[notify] sent ok\x1b[0m");
        }
        Ok(out) => {
            eprintln!("\x1b[33m[notify] exit {:?}: {}\x1b[0m",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim());
        }
        Err(e) => {
            eprintln!("\x1b[31m[notify] failed to spawn notify-send: {e}\x1b[0m");
        }
    }
}

fn format_ctf_tool_call(name: &str, input: &str) -> String {
    let parsed: Value = serde_json::from_str(input).unwrap_or(Value::String(input.to_string()));
    match name {
        "bash" => {
            let cmd = parsed.get("command").and_then(Value::as_str).unwrap_or(input);
            format!("\x1b[38;5;220m⚡ bash\x1b[0m \x1b[2m{}\x1b[0m", cmd.lines().next().unwrap_or(cmd))
        }
        "read_file" => {
            let path = parsed.get("path").and_then(Value::as_str).unwrap_or("?");
            format!("\x1b[38;5;75m📄 read_file\x1b[0m \x1b[2m{path}\x1b[0m")
        }
        "write_file" => {
            let path = parsed.get("path").and_then(Value::as_str).unwrap_or("?");
            format!("\x1b[38;5;208m✏️  write_file\x1b[0m \x1b[2m{path}\x1b[0m")
        }
        "glob_search" => {
            let pat = parsed.get("pattern").and_then(Value::as_str).unwrap_or("?");
            format!("\x1b[38;5;147m🔎 glob_search\x1b[0m \x1b[2m{pat}\x1b[0m")
        }
        "grep_search" => {
            let pat = parsed.get("pattern").and_then(Value::as_str).unwrap_or("?");
            format!("\x1b[38;5;147m🔍 grep_search\x1b[0m \x1b[2m{pat}\x1b[0m")
        }
        "binary_recon" => {
            let path = parsed.get("path").and_then(Value::as_str).unwrap_or("?");
            format!("\x1b[38;5;196m🔬 binary_recon\x1b[0m \x1b[2m{path}\x1b[0m")
        }
        "decompile" => {
            let path = parsed.get("path").and_then(Value::as_str).unwrap_or("?");
            let func = parsed.get("function").and_then(Value::as_str).unwrap_or("main");
            format!("\x1b[38;5;213m🧩 decompile\x1b[0m \x1b[2m{path}:{func}\x1b[0m")
        }
        "REPL" => {
            let lang = parsed.get("language").and_then(Value::as_str).unwrap_or("?");
            let code = parsed.get("code").and_then(Value::as_str).unwrap_or("");
            format!("\x1b[38;5;83m🐍 REPL[{lang}]\x1b[0m \x1b[2m{}\x1b[0m",
                code.lines().next().unwrap_or(""))
        }
        "WebFetch" => {
            let url = parsed.get("url").and_then(Value::as_str).unwrap_or("?");
            format!("\x1b[38;5;75m🌐 WebFetch\x1b[0m \x1b[2m{url}\x1b[0m")
        }
        _ => format!("\x1b[2m[{name}]\x1b[0m"),
    }
}

// ─── CTF Tool Executor ────────────────────────────────────────────────────────
// Extends the standard tool executor with:
//   1. Bash sandbox disabled by default — injects dangerouslyDisableSandbox:true
//   2. Terminal rendering of tool outputs
//   3. Flag detection highlighted inline

struct CtfToolExecutor {
    renderer: TerminalRenderer,
}

impl CtfToolExecutor {
    fn new() -> Self {
        Self { renderer: TerminalRenderer::new() }
    }

    /// Patch bash input JSON to disable sandbox globally.
    /// This maps to bash.rs:sandbox_status_for_input() → SandboxConfig.resolve_request(Some(false), ...)
    fn patch_bash_input(input: &Value) -> Value {
        let mut patched = input.clone();
        if let Some(obj) = patched.as_object_mut() {
            // dangerouslyDisableSandbox: true → enabled=false path in sandbox_status_for_input
            obj.insert("dangerouslyDisableSandbox".to_string(), json!(true));
            // Also disable namespace and network restrictions for full tool access
            obj.insert("namespaceRestrictions".to_string(), json!(false));
            obj.insert("isolateNetwork".to_string(), json!(false));
        }
        patched
    }
}

impl ToolExecutor for CtfToolExecutor {
    fn execute(&mut self, tool_name: &str, input: &str) -> Result<String, ToolError> {
        let parsed: Value = serde_json::from_str(input)
            .map_err(|e| ToolError::new(format!("bad tool input JSON: {e}")))?;

        // Patch bash inputs to disable sandbox
        let effective_input = if tool_name == "bash" {
            Self::patch_bash_input(&parsed)
        } else {
            parsed
        };

        let mut stdout = io::stdout();

        // Print compact tool call header (no internal sandbox params)
        let call_display = format_ctf_tool_call(tool_name, input);
        let _ = writeln!(stdout, "{call_display}");
        let _ = stdout.flush();

        // CTF-specific tools handled before delegating to the shared executor
        let result = match tool_name {
            "binary_recon" => {
                let path = effective_input.get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ToolError::new("binary_recon requires 'path'"))?;
                ctf_binary_recon(path).map_err(ToolError::new)
            }
            "decompile" => {
                let path = effective_input.get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ToolError::new("decompile requires 'path'"))?;
                let func = effective_input.get("function")
                    .and_then(Value::as_str)
                    .unwrap_or("main");
                ctf_decompile(path, func).map_err(ToolError::new)
            }
            _ => execute_tool(tool_name, &effective_input).map_err(ToolError::new),
        };

        match result {
            Ok(output) => {
                // Track background PIDs so we can kill them on exit
                if tool_name == "bash" {
                    if let Ok(v) = serde_json::from_str::<Value>(&output) {
                        if let Some(pid_str) = v.get("background_task_id").and_then(Value::as_str) {
                            if let Ok(pid) = pid_str.parse::<u32>() {
                                if let Ok(mut pids) = background_pids().lock() {
                                    pids.push(pid);
                                }
                            }
                        }
                    }
                }

                // Truncate long outputs: max 60 lines or 2000 chars
                let display = truncate_output_lines(&output, 60, 2_000);
                let md = format!("\n```\n{display}\n```\n");
                let _ = self.renderer.stream_markdown(&md, &mut stdout);
                Ok(output)
            }
            Err(err) => {
                let md = format!("\n\x1b[31m✘ {err}\x1b[0m\n");
                let _ = write!(stdout, "{md}");
                let _ = stdout.flush();
                Err(err)
            }
        }
    }
}

fn truncate_output_lines(s: &str, max_lines: usize, max_chars: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    let total_lines = lines.len();
    let total_chars = s.chars().count();

    // Truncate by lines first
    let (content, truncated_by_lines) = if total_lines > max_lines {
        (lines[..max_lines].join("\n"), true)
    } else {
        (s.to_string(), false)
    };

    // Then truncate by chars
    let (content, truncated_by_chars) = if content.chars().count() > max_chars {
        let c: String = content.chars().take(max_chars).collect();
        (c, true)
    } else {
        (content, false)
    };

    if truncated_by_lines || truncated_by_chars {
        format!("{content}\n…[truncated: {total_lines} lines, {total_chars} chars total]")
    } else {
        content
    }
}

// ─── Message conversion (Anthropic API types) ─────────────────────────────────

fn convert_messages(messages: &[ConversationMessage]) -> Vec<InputMessage> {
    messages
        .iter()
        .filter_map(|msg| {
            let role = match msg.role {
                MessageRole::System | MessageRole::User | MessageRole::Tool => "user",
                MessageRole::Assistant => "assistant",
            };
            let content: Vec<InputContentBlock> = msg
                .blocks
                .iter()
                .filter_map(|block| match block {
                    ContentBlock::Text { text } => {
                        Some(InputContentBlock::Text { text: text.clone() })
                    }
                    ContentBlock::ToolUse { id, name, input } => {
                        Some(InputContentBlock::ToolUse {
                            id: id.clone(),
                            name: name.clone(),
                            input: serde_json::from_str(input).unwrap_or(json!({})),
                        })
                    }
                    ContentBlock::ToolResult { tool_use_id, output, is_error, .. } => {
                        Some(InputContentBlock::ToolResult {
                            tool_use_id: tool_use_id.clone(),
                            content: vec![ToolResultContentBlock::Text { text: truncate_tool_output(output) }],
                            is_error: *is_error,
                        })
                    }
                })
                .collect();
            if content.is_empty() {
                None
            } else {
                Some(InputMessage { role: role.to_string(), content })
            }
        })
        .collect()
}

// ─── CTF tool specs ───────────────────────────────────────────────────────────
// Pruned subset of mvp_tool_specs() + two CTF-specific additions.
// Sending fewer, relevant tools reduces model confusion and saves context tokens.

fn ctf_tool_specs() -> Vec<tools::ToolSpec> {
    // Keep only tools relevant to CTF work; drop Todo, Skill, Agent, Config, etc.
    let keep: &[&str] = &[
        "bash", "read_file", "write_file", "edit_file",
        "glob_search", "grep_search", "WebFetch", "WebSearch",
        "REPL", "Sleep", "SendUserMessage",
    ];

    let mut specs: Vec<tools::ToolSpec> = mvp_tool_specs()
        .into_iter()
        .filter(|s| keep.contains(&s.name))
        .collect();

    // ── binary_recon ─────────────────────────────────────────────────────────
    // One call instead of 4-5 bash calls: file + checksec + strings + ldd + arch.
    specs.push(tools::ToolSpec {
        name: "binary_recon",
        description: "All-in-one binary fingerprint: file type, ELF security flags (NX/PIE/canary/RELRO), \
                       linked libraries, architecture, and a strings preview. Use this as the first step \
                       on any binary before running GDB or writing an exploit.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Path to the binary file" }
            },
            "required": ["path"],
            "additionalProperties": false
        }),
        required_permission: runtime::PermissionMode::ReadOnly,
    });

    // ── decompile ─────────────────────────────────────────────────────────────
    // Runs radare2 (or objdump fallback) to get pseudocode for a function.
    specs.push(tools::ToolSpec {
        name: "decompile",
        description: "Decompile a specific function in a binary using radare2 (r2). \
                       Returns assembly + pseudocode. Use for rev/pwn to understand logic \
                       without manually reading objdump output.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "path":     { "type": "string", "description": "Path to the binary" },
                "function": { "type": "string", "description": "Function name (e.g. 'main', 'vuln'). Default: main" }
            },
            "required": ["path"],
            "additionalProperties": false
        }),
        required_permission: runtime::PermissionMode::ReadOnly,
    });

    specs
}

/// Convert runtime messages to OpenAI chat format.
/// Key differences from Anthropic:
///   - Tool results → separate messages with role="tool"
///   - Tool calls   → "tool_calls" array in assistant message
/// OpenAI API rejects tool outputs longer than 10 MB. Cap at 200 KB of UTF-8 chars.
const MAX_TOOL_OUTPUT_CHARS: usize = 200_000;

fn truncate_tool_output(s: &str) -> String {
    let total_chars = s.chars().count();
    if total_chars <= MAX_TOOL_OUTPUT_CHARS {
        return s.to_string();
    }
    let keep = MAX_TOOL_OUTPUT_CHARS.saturating_sub(80);
    // Collect up to `keep` chars safely, avoiding mid-codepoint byte slices.
    let truncated: String = s.chars().take(keep).collect();
    format!(
        "{truncated}\n\n[... output truncated: {total_chars} chars total, showing first {keep} chars ...]",
    )
}

fn convert_messages_openai(messages: &[ConversationMessage]) -> Vec<Value> {
    // Collect all tool_call IDs that actually exist in assistant messages.
    // After compaction, some tool_results may reference IDs whose assistant
    // tool_use was removed — OpenAI rejects these as orphaned.
    let valid_tool_ids: std::collections::HashSet<String> = messages
        .iter()
        .filter(|m| m.role == MessageRole::Assistant)
        .flat_map(|m| m.blocks.iter())
        .filter_map(|b| match b {
            ContentBlock::ToolUse { id, .. } => Some(id.clone()),
            _ => None,
        })
        .collect();

    let mut out = Vec::new();
    for msg in messages {
        match msg.role {
            MessageRole::Assistant => {
                let mut text = String::new();
                let mut tool_calls: Vec<Value> = Vec::new();
                for block in &msg.blocks {
                    match block {
                        ContentBlock::Text { text: t } => text.push_str(t),
                        ContentBlock::ToolUse { id, name, input } => {
                            tool_calls.push(json!({
                                "id": id,
                                "type": "function",
                                "function": { "name": name, "arguments": input },
                            }));
                        }
                        _ => {}
                    }
                }
                let mut obj = serde_json::Map::new();
                obj.insert("role".into(), json!("assistant"));
                obj.insert("content".into(), if text.is_empty() { json!(null) } else { json!(text) });
                if !tool_calls.is_empty() {
                    obj.insert("tool_calls".into(), json!(tool_calls));
                }
                out.push(Value::Object(obj));
            }
            MessageRole::System | MessageRole::User | MessageRole::Tool => {
                let mut text_parts = Vec::new();
                let mut tool_results = Vec::new();
                for block in &msg.blocks {
                    match block {
                        ContentBlock::Text { text } => text_parts.push(text.clone()),
                        ContentBlock::ToolResult { tool_use_id, output, .. } => {
                            // Skip orphaned tool results (tool_use was removed by compaction)
                            if valid_tool_ids.contains(tool_use_id) {
                                tool_results.push((tool_use_id.clone(), output.clone()));
                            }
                        }
                        _ => {}
                    }
                }
                if !text_parts.is_empty() {
                    out.push(json!({ "role": "user", "content": text_parts.join("\n") }));
                }
                for (tool_call_id, content) in tool_results {
                    let content = truncate_tool_output(&content);
                    out.push(json!({ "role": "tool", "tool_call_id": tool_call_id, "content": content }));
                }
            }
        }
    }
    out
}

/// Print the last `n` non-tool messages from the session as a compact chat replay.
/// Print session history.
/// `n` = max number of messages to show (use `usize::MAX` for all).
/// `max_lines_per_msg` = max lines per assistant message (`usize::MAX` for full).
fn print_session_tail(session: &Session, n: usize, max_lines_per_msg: usize) {
    let renderer = TerminalRenderer::new();

    let exchanges: Vec<_> = session.messages.iter()
        .filter(|m| matches!(m.role, MessageRole::User | MessageRole::Assistant))
        .collect();

    let start = exchanges.len().saturating_sub(n);
    for msg in &exchanges[start..] {
        match msg.role {
            MessageRole::User => {
                for block in &msg.blocks {
                    if let ContentBlock::Text { text } = block {
                        let trimmed = text.trim();
                        if !trimmed.is_empty() {
                            // Show first line only for user messages (usually short)
                            println!("\x1b[38;5;246m  you › \x1b[0m\x1b[2m{}\x1b[0m",
                                trimmed.lines().next().unwrap_or("").chars().take(120).collect::<String>());
                        }
                    }
                }
            }
            MessageRole::Assistant => {
                let mut text = String::new();
                let mut tool_names: Vec<String> = Vec::new();
                for block in &msg.blocks {
                    match block {
                        ContentBlock::Text { text: t } if !t.trim().is_empty() => text.push_str(t),
                        ContentBlock::ToolUse { name, .. } => tool_names.push(name.clone()),
                        _ => {}
                    }
                }
                if !tool_names.is_empty() {
                    println!("\x1b[38;5;220m  agent › \x1b[2m[{}]\x1b[0m",
                        tool_names.join(", "));
                }
                if !text.trim().is_empty() {
                    let rendered = renderer.markdown_to_ansi(text.trim());
                    let lines: Vec<&str> = rendered.lines().collect();
                    let show = lines.len().min(max_lines_per_msg);
                    for line in &lines[..show] {
                        println!("    {line}");
                    }
                    if lines.len() > show {
                        println!("    \x1b[2m… ({} more lines)\x1b[0m", lines.len() - show);
                    }
                }
            }
            _ => {}
        }
    }
}

fn render_export(session: &Session) -> String {
    let mut out = String::new();
    for msg in &session.messages {
        let role = match msg.role {
            MessageRole::System => "system",
            MessageRole::User => "user",
            MessageRole::Assistant => "assistant",
            MessageRole::Tool => "tool",
        };
        for block in &msg.blocks {
            let text = match block {
                ContentBlock::Text { text } => text.clone(),
                ContentBlock::ToolUse { name, input, .. } => {
                    format!("[tool_use: {name}({input})]")
                }
                ContentBlock::ToolResult { tool_name, output, .. } => {
                    format!("[tool_result: {tool_name}] {output}")
                }
            };
            out.push_str(&format!("[{role}] {text}\n"));
        }
    }
    out
}
