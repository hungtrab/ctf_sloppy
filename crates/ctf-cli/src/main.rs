// CTF Solver — terminal app built on claw-code runtime
// Security layers removed, PermissionMode::Allow, sandbox disabled, aggressive compaction.
mod auth;
mod challenge;
mod ctfd;
mod flag;
mod knowledge;
mod mcp_tools;
mod prompt;

// ── re-export TUI infrastructure from runtime (copied inline below) ──────────
mod input;
mod render;

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// Set by the SIGINT handler while an agent turn is running.
/// `CtfApiClient::stream()` checks this and aborts early if true.
static AGENT_INTERRUPTED: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

fn agent_interrupted() -> &'static Arc<AtomicBool> {
    AGENT_INTERRUPTED.get_or_init(|| Arc::new(AtomicBool::new(false)))
}

/// PID of the currently-streaming bash/REPL command, if any. Set by
/// `run_bash_streaming` and `PythonRepl::execute` while they're waiting on output.
static RUNNING_CMD_PID: std::sync::OnceLock<Mutex<Option<u32>>> = std::sync::OnceLock::new();

fn running_cmd_pid() -> &'static Mutex<Option<u32>> {
    RUNNING_CMD_PID.get_or_init(|| Mutex::new(None))
}

/// Set by `spawn_interrupt_monitor` when Ctrl+C kills the currently-running
/// command (instead of aborting the whole turn). Consumed by
/// `run_bash_streaming`/`PythonRepl::execute` to report the interruption to
/// the agent so it can adapt and continue the turn.
static CMD_INTERRUPTED: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

fn cmd_interrupted() -> &'static Arc<AtomicBool> {
    CMD_INTERRUPTED.get_or_init(|| Arc::new(AtomicBool::new(false)))
}

/// Kill a specific command and its direct children with SIGKILL.
/// Deliberately targets only this PID (and `pkill -P <pid>` for its direct
/// children) — never a process-group/negative PID, which can broadcast to
/// the calling shell's own session and log the user out.
fn kill_process_group(pid: u32) {
    let _ = std::process::Command::new("pkill")
        .args(["-KILL", "-P", &pid.to_string()])
        .output();
    let _ = std::process::Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .output();
}

/// Toggled by Ctrl+O. When set, bash/tool output panels show full output
/// instead of the truncated preview.
static VERBOSE_OUTPUT: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

fn verbose_output() -> &'static Arc<AtomicBool> {
    VERBOSE_OUTPUT.get_or_init(|| Arc::new(AtomicBool::new(false)))
}

/// MCP servers configured in `~/.claude.json` (e.g. `GhidraMCP`), discovered
/// once and shared across `CtfToolExecutor` instances (which get recreated on
/// /reset, /compact, model switches, etc.).
static MCP_TOOLSET: std::sync::OnceLock<Mutex<Option<mcp_tools::McpToolset>>> =
    std::sync::OnceLock::new();

fn mcp_toolset() -> &'static Mutex<Option<mcp_tools::McpToolset>> {
    MCP_TOOLSET.get_or_init(|| Mutex::new(mcp_tools::load()))
}

/// Tool specs for any MCP servers discovered at startup.
fn mcp_tool_specs() -> Vec<tools::ToolSpec> {
    mcp_toolset()
        .lock()
        .unwrap()
        .as_ref()
        .map(mcp_tools::tool_specs)
        .unwrap_or_default()
}

/// Global registry of background process PIDs spawned by the agent.
/// Killed on ctf CLI exit so they don't linger after a crash.
static BACKGROUND_PIDS: std::sync::OnceLock<Arc<Mutex<Vec<u32>>>> = std::sync::OnceLock::new();

fn background_pids() -> &'static Arc<Mutex<Vec<u32>>> {
    BACKGROUND_PIDS.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
}

fn kill_background_pids() {
    if let Ok(mut pids) = background_pids().lock() {
        for &pid in pids.iter() {
            #[cfg(unix)]
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status();
        }
        pids.clear();
    }
}

/// Spawns a lightweight monitor thread that watches `AGENT_INTERRUPTED`.
/// When set, sends SIGKILL to all child processes so the running bash command
/// dies immediately instead of waiting for it to react to the terminal SIGINT.
fn spawn_interrupt_monitor() {
    let our_pid = std::process::id().to_string();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if agent_interrupted().load(Ordering::Relaxed) {
                // If a bash/REPL command is currently streaming, kill just that
                // command's process group and let the turn continue — the agent
                // sees the interruption as a tool result and can adapt.
                let running_pid = running_cmd_pid().lock().unwrap().take();
                if let Some(pid) = running_pid {
                    kill_process_group(pid);
                    cmd_interrupted().store(true, Ordering::Relaxed);
                    agent_interrupted().store(false, Ordering::Relaxed);
                    continue;
                }
                // Otherwise: kill all children of this process immediately.
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
use prompt::{ctf_system_prompt, plan_system_prompt, replan_system_prompt};
use regex::Regex;
use render::{MarkdownStreamState, Spinner, TerminalRenderer};
use runtime::{
    compact_session, ApiClient, ApiRequest, AssistantEvent, CompactionConfig, ConfigLoader,
    ContentBlock, ConversationMessage, ConversationRuntime, MessageRole, PermissionMode,
    PermissionPolicy, RuntimeError, Session, TokenUsage, ToolError, ToolExecutor,
};
use serde_json::{json, Value};
#[allow(unused_imports)]
use std::io::Write as _;
use tools::{execute_tool, mvp_tool_specs};

// ─── Terminal color palette (matches feynman Pi theme) ────────────────────────

const C_RESET: &str = "\x1b[0m";
const C_BOLD: &str = "\x1b[1m";
const C_DIM: &str = "\x1b[2m";
const C_TEAL: &str = "\x1b[38;2;127;187;179m";
const C_SAGE: &str = "\x1b[38;2;167;192;128m";
const C_ASH: &str = "\x1b[38;2;133;146;137m";
const C_INK: &str = "\x1b[38;2;211;198;170m";
const C_STONE: &str = "\x1b[38;2;157;169;160m";
const C_DARK_ASH: &str = "\x1b[38;2;92;106;114m";
const C_ROSE: &str = "\x1b[38;2;230;126;128m";

// Background fills for pi-style tool cards (Everforest — feynman.json).
const BG_TOOL_SUCCESS: &str = "\x1b[48;2;47;59;50m"; // successBg #2f3b32
const BG_TOOL_ERROR: &str = "\x1b[48;2;59;49;53m"; // errorBg   #3b3135
const BG_PANEL: &str = "\x1b[48;2;55;66;71m"; // panel/userMessageBg #374247

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_MODEL: &str = "claude-opus-4-6";
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Auto-compact at 50k input tokens instead of the default 200k.
/// CTF sessions are task-focused — old recon data becomes noise quickly.
const CTF_AUTO_COMPACT_THRESHOLD: u32 = 50_000;

/// Keep only last 2 messages when doing /compact (vs default 4).
const CTF_COMPACT_PRESERVE: usize = 2;

const OPENAI_DEFAULT_BASE_URL: &str = "https://api.openai.com";
const CTF_FILE_PREVIEW_BUDGET: usize = 8_000;
const CTF_FILE_PREVIEW_PER_FILE: usize = 2_000;
const CTF_MAX_FALLBACK_CODE_BYTES: usize = 16_384;

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
    // Allow explicit override via env var for any model
    if let Some(v) = std::env::var("ANTHROPIC_MAX_TOKENS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return v;
    }
    if model.contains("opus") {
        return 32_000;
    }
    if model.starts_with("claude") {
        return 64_000;
    }
    // GPT-5.5 / 5.5-pro: 128K output window
    if model.starts_with("gpt-5.5") {
        return 65_536;
    }
    // GPT-5.4 series: reasoning model with large output budget
    if model.starts_with("gpt-5.4") || model.starts_with("gpt-5.2") {
        return 32_768;
    }
    // GPT-5 / 5-mini
    if model.starts_with("gpt-5") {
        return 32_768;
    }
    // o-series and codex: need headroom for hidden reasoning tokens
    if is_reasoning_model(model) {
        return 32_768;
    }
    // GPT-4.x and gpt-4o
    if model.starts_with("gpt-4") {
        return 16_384;
    }
    // Local/vLLM/Ollama (incl. reasoning models served via llama.cpp): give
    // enough headroom that a long chain-of-thought can finish and still emit a
    // final answer / tool call, instead of being truncated with empty content.
    16_384
}

/// Returns true for models that:
///   1. Use `max_completion_tokens` instead of `max_tokens`
///   2. Perform internal chain-of-thought / reasoning before responding
///
/// As of 2026, this includes all o-series, codex, and gpt-5.4+ which `OpenAI`
/// classifies as "reasoning models" and which reject the legacy `max_tokens` param.
fn is_reasoning_model(model: &str) -> bool {
    model.starts_with("o1")
        || model.starts_with("o3")
        || model.starts_with("o4")
        || model.starts_with("codex")
        || model.starts_with("gpt-5.4")  // first mainline reasoning GPT
        || model.starts_with("gpt-5.5") // gpt-5.5, gpt-5.5-pro
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
        Some("--help" | "-h") | None => {
            print_help();
            return Ok(());
        }
        Some("--version" | "-V") => {
            println!("ctf-solver {VERSION}");
            return Ok(());
        }
        Some("login") => {
            auth::handle_login(&args[1..])?;
            return Ok(());
        }
        Some("logout") => {
            auth::handle_logout(&args[1..])?;
            return Ok(());
        }
        Some("model") => {
            auth::handle_model_cmd(&args[1..])?;
            return Ok(());
        }
        Some("ctfd") => {
            ctfd::handle_cli(&args[1..])?;
            return Ok(());
        }
        _ => {}
    }

    let (
        challenge_dir,
        model,
        category_override,
        resume_path,
        mut api_mode,
        notify,
        plan_model_override,
    ) = parse_args(&args)?;
    let mut challenge = Challenge::load(&challenge_dir);
    let category_was_overridden = category_override.is_some();
    if let Some(cat) = category_override {
        challenge = challenge.with_category(cat);
    }

    // Set CWD to challenge dir so relative paths (./files, ./tmp, ./notes.md) work correctly.
    std::env::set_current_dir(&challenge.dir)?;

    // Ensure files/, tmp/, self/, and logs/ exist before showing the startup screen.
    fs::create_dir_all(challenge.dir.join("files"))?;
    fs::create_dir_all(challenge.dir.join("tmp"))?;
    fs::create_dir_all(challenge.dir.join("self"))?;
    fs::create_dir_all(challenge.dir.join("logs"))?;

    // Startup wizard — confirms permission, category, flag format, and API mode.
    if !startup_confirm(&mut challenge, category_was_overridden, &mut api_mode)? {
        return Ok(());
    }

    // Create notes.md after category is finalised.
    let notes_path = challenge.dir.join("notes.md");
    if !notes_path.exists() {
        fs::write(
            &notes_path,
            format!(
                "# {name}\n\n\
                 ## Challenge Info\n\
                 - Category: {cat}\n\
                 - Flag format: {fmt}\n\n\
                 ## Recon Findings\n\
                 <!-- Run /plan to auto-populate, or manually add observations here -->\n\n\
                 ## Hypotheses\n\
                 <!-- - [ ] hypothesis — rationale\n\
                      - [x] hypothesis — FAILED: reason -->\n\n\
                 ## Exploit Attempts\n\
                 <!-- Append each attempt and its result -->\n\n\
                 ## Validation\n\
                 <!-- Record PoC execution results confirming the flag -->\n\n\
                 ## Notes\n\n\
                 ## FLAG\n\
                 <!-- Final flag -->\n",
                name = challenge.name,
                cat = challenge.category.as_str(),
                fmt = challenge.flag_format,
            ),
        )?;
    }

    let plan_model = plan_model_override.unwrap_or_else(|| default_plan_model(&model));
    run_repl(challenge, model, plan_model, resume_path, api_mode, notify)
}

/// Which API backend to use. Auto-detected from env vars unless overridden with --api.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ApiMode {
    /// Use Anthropic Messages API (/v1/messages). Default when `ANTHROPIC_BASE_URL/KEY` is set.
    Anthropic,
    /// Use `OpenAI` Chat Completions API (/v1/chat/completions). Use when pointing at vLLM/Ollama.
    OpenAi,
}

/// Parsed CLI arguments: challenge dir, model, category override, resume path,
/// API-mode override, notify flag, and optional plan-model override.
type ParsedArgs = (
    PathBuf,
    String,
    Option<Category>,
    Option<PathBuf>,
    Option<ApiMode>,
    bool,
    Option<String>,
);

fn parse_args(args: &[String]) -> Result<ParsedArgs, Box<dyn std::error::Error>> {
    let mut challenge_dir: Option<PathBuf> = None;
    let mut model = DEFAULT_MODEL.to_string();
    let mut plan_model_override: Option<String> = None;
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
                model =
                    resolve_model_alias(args.get(i).ok_or("--model requires a value")?).to_string();
            }
            "--plan-model" => {
                i += 1;
                plan_model_override = Some(
                    resolve_model_alias(args.get(i).ok_or("--plan-model requires a value")?)
                        .to_string(),
                );
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
                    other => {
                        return Err(format!(
                            "--api requires 'openai' or 'anthropic', got: {}",
                            other.unwrap_or("<missing>")
                        )
                        .into())
                    }
                });
            }
            "--notify" | "-n" => {
                notify = true;
            }
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
        "usage: ctf --challenge <dir> [--model <name>] [--plan-model <name>] [--category <cat>] [--resume <session>]",
    )?;
    Ok((
        dir,
        model,
        category_override,
        resume_path,
        api_mode,
        notify,
        plan_model_override,
    ))
}

fn resolve_model_alias(alias: &str) -> &str {
    match alias {
        // Claude
        "opus" => "claude-opus-4-6",
        "sonnet" => "claude-sonnet-4-6",
        "haiku" => "claude-haiku-4-5-20251001",
        // OpenAI reasoning
        "codex" => "codex-mini-latest",
        "o3" => "o3",
        "o3pro" => "o3-pro",
        "o4" | "o4mini" => "o4-mini",
        // GPT-5 series
        "gpt5" => "gpt-5",
        "gpt5mini" => "gpt-5-mini",
        "gpt52" => "gpt-5.2",
        "gpt54" => "gpt-5.4",
        "gpt54mini" => "gpt-5.4-mini",
        "gpt55" => "gpt-5.5",
        "gpt55pro" => "gpt-5.5-pro",
        // GPT-4.x
        "gpt4" => "gpt-4.1",
        "gpt4mini" => "gpt-4.1-mini",
        "gpt4o" => "gpt-4o",
        other => other,
    }
}

/// Auto-select a cheaper/faster model for the one-shot /plan phase.
/// Saves cost without hurting plan quality (planning = reading + writing, not reasoning).
fn default_plan_model(model: &str) -> String {
    if model.contains("opus") {
        return "claude-sonnet-4-6".to_string();
    }
    // GPT-5 series → mini/cheaper variant for planning
    if model == "gpt-5.5-pro" || model == "gpt-5.5" {
        return "gpt-5.5".to_string();
    }
    if model.starts_with("gpt-5.4") {
        return "gpt-5.4-mini".to_string();
    }
    if model == "gpt-5.2" || model == "gpt-5" {
        return "gpt-5-mini".to_string();
    }
    // OpenAI large models → mini equivalent
    if model == "gpt-4o" || model.starts_with("gpt-4o-20") {
        return "gpt-4o-mini".to_string();
    }
    if model == "gpt-4.1" {
        return "gpt-4.1-mini".to_string();
    }
    if model.starts_with("o3") || model.starts_with("o4") {
        return "gpt-4o-mini".to_string();
    }
    if model.starts_with("codex") {
        return model.to_string();
    }
    // Already cheap, local, or unknown → use same
    model.to_string()
}

fn session_has_tool_results(runtime: &ConversationRuntime<CtfApiClient, CtfToolExecutor>) -> bool {
    runtime
        .session()
        .messages
        .iter()
        .any(|message| message.role == MessageRole::Tool)
}

fn messages_slice_has_tool_results(messages: &[ConversationMessage]) -> bool {
    messages
        .iter()
        .any(|message| message.role == MessageRole::Tool)
}

fn prepend_notes(notes: &str, input: &str) -> String {
    if notes.trim().is_empty() {
        return input.to_string();
    }
    format!(
        "[Context was compacted. Your full investigation progress from notes.md:]\n\n\
         {notes}\n\n\
         ---\n\n\
         {input}"
    )
}

fn escape_invalid_regex_braces(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len());
    let mut i = 0usize;

    while i < chars.len() {
        match chars[i] {
            '\\' => {
                out.push(chars[i]);
                if let Some(next) = chars.get(i + 1) {
                    out.push(*next);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            '{' => {
                if let Some(end) = valid_regex_quantifier_end(&chars, i + 1) {
                    for ch in &chars[i..=end] {
                        out.push(*ch);
                    }
                    i = end + 1;
                } else {
                    out.push_str(r"\{");
                    i += 1;
                }
            }
            '}' => {
                out.push_str(r"\}");
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }

    out
}

fn normalize_descending_regex_ranges(pattern: &str) -> String {
    let range = Regex::new(r"\{([0-9]+),([0-9]+)\}").expect("valid range regex");
    range
        .replace_all(pattern, |caps: &regex::Captures<'_>| {
            let left = caps
                .get(1)
                .and_then(|m| m.as_str().parse::<u64>().ok())
                .unwrap_or(0);
            let right = caps
                .get(2)
                .and_then(|m| m.as_str().parse::<u64>().ok())
                .unwrap_or(0);
            if left > right {
                format!("{{{right},{left}}}")
            } else {
                caps.get(0).map_or("", |m| m.as_str()).to_string()
            }
        })
        .into_owned()
}

fn valid_regex_quantifier_end(chars: &[char], mut i: usize) -> Option<usize> {
    let start = i;
    while matches!(chars.get(i), Some(ch) if ch.is_ascii_digit()) {
        i += 1;
    }
    if i == start {
        return None;
    }
    if matches!(chars.get(i), Some(',')) {
        i += 1;
        while matches!(chars.get(i), Some(ch) if ch.is_ascii_digit()) {
            i += 1;
        }
    }
    matches!(chars.get(i), Some('}')).then_some(i)
}

fn bash_syntax_error(command: &str) -> Option<String> {
    let output = std::process::Command::new("bash")
        .args(["-n", "-c", command])
        .output()
        .ok()?;
    if output.status.success() {
        return None;
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let message = stderr
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(3)
        .collect::<Vec<_>>()
        .join("; ");
    Some(if message.is_empty() {
        "bash syntax check failed".to_string()
    } else {
        message
    })
}

fn normalize_tool_timeout_ms(raw: u64) -> u64 {
    if raw < 1_000 {
        raw.saturating_mul(1_000)
    } else {
        raw
    }
}

fn challenge_files_manifest(challenge: &Challenge) -> String {
    let files_dir = challenge.dir.join("files");
    let mut entries: Vec<String> = fs::read_dir(&files_dir)
        .ok()
        .into_iter()
        .flat_map(|rd| rd.filter_map(std::result::Result::ok))
        .filter_map(|entry| {
            let meta = entry.metadata().ok()?;
            let kind = if meta.is_dir() { "dir" } else { "file" };
            let size = meta.len();
            Some(format!(
                "- ./files/{} ({kind}, {size} bytes)",
                entry.file_name().to_string_lossy()
            ))
        })
        .collect();
    entries.sort();

    if entries.is_empty() {
        "- ./files/ is empty".to_string()
    } else {
        entries.join("\n")
    }
}

fn challenge_files_preview(challenge: &Challenge) -> String {
    let files_dir = challenge.dir.join("files");
    let mut entries: Vec<_> = fs::read_dir(&files_dir)
        .ok()
        .into_iter()
        .flat_map(|rd| rd.filter_map(std::result::Result::ok))
        .filter(|entry| entry.metadata().is_ok_and(|m| m.is_file()))
        .collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);

    let mut out = String::new();
    let mut remaining = CTF_FILE_PREVIEW_BUDGET;
    for entry in entries {
        if remaining == 0 {
            break;
        }
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        if bytes.contains(&0) {
            continue;
        }

        let take = bytes.len().min(CTF_FILE_PREVIEW_PER_FILE).min(remaining);
        let text = String::from_utf8_lossy(&bytes[..take]);
        out.push_str(&format!(
            "\n--- ./files/{name} ({} bytes, preview {} bytes) ---\n{text}\n",
            bytes.len(),
            take
        ));
        if bytes.len() > take {
            out.push_str("[truncated]\n");
        }
        remaining = remaining.saturating_sub(take);
    }

    if out.trim().is_empty() {
        "(no small text-file preview available; use tools to inspect files)".to_string()
    } else {
        out
    }
}

fn top_level_challenge_file_names(challenge: &Challenge) -> Vec<String> {
    let files_dir = challenge.dir.join("files");
    let mut names: Vec<String> = fs::read_dir(&files_dir)
        .ok()
        .into_iter()
        .flat_map(|rd| rd.filter_map(std::result::Result::ok))
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    names
}

// ─── Startup wizard ───────────────────────────────────────────────────────────

/// Four-step interactive wizard shown before the REPL:
///   1. Workspace permission confirmation
///   2. Category (ask only if not explicitly set)
///   3. Flag format picker (ask only if `flag_format.txt` doesn't exist)
///   4. API mode  (`OpenAI` OAuth  vs  API key — skip if --api flag was passed)
///
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
        .map(|rd| {
            rd.filter_map(std::result::Result::ok)
                .filter(|e| e.path().is_file())
                .count()
        })
        .unwrap_or(0);

    // ── Header ────────────────────────────────────────────────────────────────
    let inner = 53usize;
    let border: String = "─".repeat(inner + 2);
    println!();
    println!(" {C_DARK_ASH}{C_BOLD}┌{border}┐{C_RESET}");
    println!(" {C_DARK_ASH}{C_BOLD}│{C_RESET} {C_TEAL}{C_BOLD}⚡  CTF Solver{C_RESET}  {C_DIM}v{VERSION}{C_RESET}{pad} {C_DARK_ASH}{C_BOLD}│{C_RESET}",
        pad = " ".repeat(inner.saturating_sub(16)));
    println!(" {C_DARK_ASH}{C_BOLD}├{border}┤{C_RESET}");
    let files_str = if files_count == 0 {
        format!("{C_STONE}0 — add challenge files to ./files/{C_RESET}")
    } else {
        format!("{files_count} file(s)")
    };
    println!(
        " {C_DARK_ASH}{C_BOLD}│{C_RESET} {C_ASH}Challenge:{C_RESET} {C_INK}{C_BOLD}{}{C_RESET}",
        challenge.name
    );
    println!(
        " {C_DARK_ASH}{C_BOLD}│{C_RESET} {C_ASH}Directory:{C_RESET} {C_INK}{}{C_RESET}",
        challenge.dir.display()
    );
    println!(" {C_DARK_ASH}{C_BOLD}│{C_RESET} {C_ASH}Files:    {C_RESET} {files_str}");
    println!(" {C_DARK_ASH}{C_BOLD}└{border}┘{C_RESET}");
    println!();
    println!(
        "   {C_STONE}⚠  The agent will have full read/write access to this directory.{C_RESET}"
    );
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
        println!(
            "  {C_ASH}Category detected:{C_RESET}  {}  {C_BOLD}{}{C_RESET}",
            challenge.category.emoji(),
            challenge.category.as_str()
        );
        println!(
            "  {C_DARK_ASH}pwn · web · crypto · rev · forensics · misc · osint · network{C_RESET}"
        );
        println!();

        let default_cat = challenge.category.as_str();
        loop {
            print!("  Category [{default_cat}] (Enter to confirm, type to change): ");
            let _ = io::stdout().flush();
            let Some(line) = read_line() else {
                return Ok(false);
            };
            match line.trim() {
                "" => break,
                s => match Category::from_str(s) {
                    Some(c) => {
                        challenge.category = c;
                        // Persist so future runs skip this prompt.
                        let _ = fs::write(challenge.dir.join("category.txt"), c.as_str());
                        println!("  {C_SAGE}✓{C_RESET}  {}  {}", c.emoji(), c.as_str());
                        break;
                    }
                    None => println!("  {C_ROSE}✗  Unknown: '{s}'{C_RESET}"),
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
        println!("  {C_ASH}Flag format not set — choose from list or type custom:{C_RESET}");
        println!("  {C_DARK_ASH}(edit {}){C_RESET}", config_path.display());
        println!();
        for (i, fmt) in formats.iter().enumerate() {
            println!(
                "    {C_DARK_ASH}{:2}){C_RESET}  {C_TEAL}{fmt}{C_RESET}",
                i + 1
            );
        }
        println!(
            "     {C_DARK_ASH}*){C_RESET}  type a custom format  {C_DIM}e.g. myctf{{...}}{C_RESET}"
        );
        println!();

        loop {
            print!("  Flag format [1]: ");
            let _ = io::stdout().flush();
            let Some(line) = read_line() else {
                return Ok(false);
            };
            let trimmed = line.trim();

            let chosen: Option<String> = if trimmed.is_empty() {
                formats.first().cloned()
            } else if let Ok(n) = trimmed.parse::<usize>() {
                if n >= 1 && n <= formats.len() {
                    Some(formats[n - 1].clone())
                } else {
                    println!(
                        "  {C_ROSE}✗  Choose 1–{}, or type a custom format{C_RESET}",
                        formats.len()
                    );
                    None
                }
            } else if trimmed.contains('{') {
                Some(trimmed.to_string())
            } else {
                println!("  {C_ROSE}✗  Enter a number or a format containing '{{', e.g. FLAG{{...}}{C_RESET}");
                None
            };

            if let Some(fmt) = chosen {
                challenge.flag_format.clone_from(&fmt);
                let _ = fs::write(&flag_format_path, &fmt);
                println!("  {C_SAGE}✓{C_RESET}  {C_TEAL}{fmt}{C_RESET}");
                println!();
                break;
            }
        }
    }

    // ── Step 4: API mode (skip if --api was passed explicitly) ───────────────
    if api_mode_out.is_none() {
        let storage = auth::AuthStorage::load();
        let has_oauth = matches!(storage.get("openai"), Some(auth::Credential::OAuth { .. }));
        let has_anth_key = std::env::var("ANTHROPIC_API_KEY").is_ok()
            || std::env::var("ANTHROPIC_AUTH_TOKEN").is_ok()
            || storage.has("anthropic");
        let has_openai_key = std::env::var("OPENAI_API_KEY").is_ok()
            || std::env::var("OPENAI_BASE_URL").is_ok()
            || matches!(storage.get("openai"), Some(auth::Credential::ApiKey { .. }));

        // Default selection based on what's already configured. Anthropic key
        // and "nothing configured" both default to API-key mode (2).
        let default_choice: u8 = if has_oauth || has_openai_key { 1 } else { 2 };

        println!("  {C_ASH}◆ API mode:{C_RESET}");
        println!("    {C_DARK_ASH}1){C_RESET}  OpenAI / ChatGPT account  {C_DIM}(OAuth — no key needed){C_RESET}");
        println!("    {C_DARK_ASH}2){C_RESET}  API key  {C_DIM}(Anthropic · OpenAI · custom endpoint){C_RESET}");
        println!();

        let choice: u8 = loop {
            print!("  Mode [{default_choice}]: ");
            let _ = io::stdout().flush();
            let Some(line) = read_line() else {
                return Ok(false);
            };
            match line.trim() {
                "" => break default_choice,
                "1" => break 1,
                "2" => break 2,
                _ => println!("  {C_ROSE}✗  Enter 1 or 2{C_RESET}"),
            }
        };

        println!();

        match choice {
            // ── OpenAI OAuth ──────────────────────────────────────────────────
            1 => {
                *api_mode_out = Some(ApiMode::OpenAi);
                if has_oauth && (std::env::var("OPENAI_API_KEY").is_ok()) {
                    println!("  {C_STONE}⚠  OPENAI_API_KEY is set — it will override OAuth credentials.{C_RESET}");
                    println!("  {C_DIM}  Unset OPENAI_API_KEY to use your ChatGPT account instead.{C_RESET}");
                } else if has_oauth {
                    println!("  {C_SAGE}✓{C_RESET}  Using saved OAuth credentials.");
                } else if has_openai_key {
                    println!("  {C_SAGE}✓{C_RESET}  Using saved OpenAI API key.");
                } else {
                    println!("  {C_ASH}Opening browser for OpenAI authentication...{C_RESET}");
                    println!();
                    run_openai_login()?;
                }
            }
            // ── API key ───────────────────────────────────────────────────────
            _ => {
                if has_anth_key {
                    println!("  {C_SAGE}✓{C_RESET}  ANTHROPIC_API_KEY detected.");
                    *api_mode_out = Some(ApiMode::Anthropic);
                } else if has_openai_key {
                    println!("  {C_SAGE}✓{C_RESET}  OPENAI_API_KEY / OPENAI_BASE_URL detected.");
                    *api_mode_out = Some(ApiMode::OpenAi);
                } else {
                    // Nothing configured — ask provider + key
                    println!("  {C_ASH}◆ Provider:{C_RESET}");
                    println!("    {C_DARK_ASH}1){C_RESET}  Anthropic   {C_DIM}(claude-opus-4-6, sonnet, haiku){C_RESET}");
                    println!("    {C_DARK_ASH}2){C_RESET}  OpenAI      {C_DIM}(gpt-4o, gpt-4o-mini){C_RESET}");
                    println!("    {C_DARK_ASH}3){C_RESET}  Custom      {C_DIM}(Gemini, Groq, vLLM, Ollama...){C_RESET}");
                    println!();

                    let provider: u8 = loop {
                        print!("  Provider [1]: ");
                        let _ = io::stdout().flush();
                        let Some(line) = read_line() else {
                            return Ok(false);
                        };
                        match line.trim() {
                            "" | "1" => break 1,
                            "2" => break 2,
                            "3" => break 3,
                            _ => println!("  {C_ROSE}✗  Enter 1, 2, or 3{C_RESET}"),
                        }
                    };

                    print!("  API key: ");
                    let _ = io::stdout().flush();
                    let Some(key_line) = read_line() else {
                        return Ok(false);
                    };
                    let key = key_line.trim().to_string();
                    if key.is_empty() {
                        println!(
                            "  {C_STONE}⚠  No key entered — you may get auth errors.{C_RESET}"
                        );
                    }

                    match provider {
                        1 => {
                            std::env::set_var("ANTHROPIC_API_KEY", &key);
                            *api_mode_out = Some(ApiMode::Anthropic);
                            println!("  {C_SAGE}✓{C_RESET}  Anthropic key set for this session.");
                        }
                        2 => {
                            std::env::set_var("OPENAI_API_KEY", &key);
                            *api_mode_out = Some(ApiMode::OpenAi);
                            println!("  {C_SAGE}✓{C_RESET}  OpenAI key set for this session.");
                        }
                        _ => {
                            print!(
                                "  Base URL {C_DIM}(e.g. https://api.groq.com/openai){C_RESET}: "
                            );
                            let _ = io::stdout().flush();
                            let Some(url_line) = read_line() else {
                                return Ok(false);
                            };
                            let base_url = url_line.trim().to_string();
                            std::env::set_var("OPENAI_API_KEY", &key);
                            if !base_url.is_empty() {
                                std::env::set_var("OPENAI_BASE_URL", &base_url);
                            }
                            *api_mode_out = Some(ApiMode::OpenAi);
                            println!("  {C_SAGE}✓{C_RESET}  Custom endpoint set for this session.");
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

/// Prints a one-line status for whether a CTF skill reference and any MCP
/// servers were loaded for this session, so the user can see at a glance
/// whether those integrations are active.
fn print_environment_status(category: Category) {
    match prompt::skill_status(category) {
        Some((path, bytes)) => {
            println!(
                "{C_SAGE}✓{C_RESET} Skill loaded: {C_INK}{}{C_RESET} ({}, {})",
                category.as_str(),
                path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("SKILL.md"),
                format_bytes(bytes)
            );
        }
        None => {
            println!(
                "{C_DIM}✗ No skill reference for category '{}'{C_RESET}",
                category.as_str()
            );
        }
    }

    let servers = mcp_toolset()
        .lock()
        .unwrap()
        .as_ref()
        .map(mcp_tools::server_summary)
        .unwrap_or_default();

    if servers.is_empty() {
        let configured = mcp_tools::configured_servers();
        if configured.is_empty() {
            println!("{C_DIM}✗ No MCP servers configured{C_RESET}");
        } else {
            println!(
                "{C_DIM}✗ MCP configured but unreachable: {}{C_RESET} (is the backing app running?)",
                configured.join(", ")
            );
        }
    } else {
        let summary = servers
            .iter()
            .map(|(name, count)| format!("{name} ({count} tools)"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("{C_SAGE}✓{C_RESET} MCP: {C_INK}{summary}{C_RESET}");
    }
    println!();
}

/// Format a byte count as a human-readable string (e.g. "1.2K", "340B").
fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else {
        format!("{:.1}K", bytes as f64 / 1024.0)
    }
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
        let line =
            read_line().ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))?;
        match line.trim().to_lowercase().as_str() {
            "" | "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("  Please type y or n."),
        }
    }
}

// ─── OpenAI OAuth (delegated to auth module) ──────────────────────────────────

/// Resolve the `OpenAI` bearer token from auth.json (with auto-refresh).
fn resolve_openai_auth() -> Option<String> {
    let mut storage = auth::AuthStorage::load();
    storage.resolve_token("openai")
}

// placeholder to keep the rest of the code compiling until we remove callers below
async fn do_oauth_refresh_compat(
    _token_url: &str,
    refresh_token: &str,
    now_secs: u64,
    scopes: &[String],
) -> Option<String> {
    let cred = auth::refresh_oauth_token(
        "openai",
        "https://auth.openai.com/oauth/token",
        refresh_token,
        now_secs,
        scopes,
    )
    .await?;
    match cred {
        auth::Credential::OAuth { access_token, .. } => Some(access_token),
        auth::Credential::ApiKey { .. } => None,
    }
}

// kept only to satisfy the mid-stream 401 handler until it's updated
fn load_openai_oauth_for_refresh() -> Option<(String, Vec<String>)> {
    let storage = auth::AuthStorage::load();
    match storage.get("openai")?.clone() {
        auth::Credential::OAuth {
            refresh_token: Some(rt),
            scopes,
            ..
        } => Some((rt, scopes)),
        auth::Credential::OAuth { .. } | auth::Credential::ApiKey { .. } => None,
    }
}

fn run_openai_login() -> Result<(), Box<dyn std::error::Error>> {
    let mut storage = auth::AuthStorage::load();
    auth::run_openai_oauth_login(&mut storage)
}

// ─── dead code kept for remaining references ──────────────────────────────────
// These will be removed once the startup_confirm wizard is updated too.

#[allow(dead_code)]
fn openai_credentials_path() -> PathBuf {
    auth::auth_path()
}

#[allow(dead_code)]
async fn do_oauth_refresh(
    token_url: &str,
    refresh_token: &str,
    now_secs: u64,
    scopes: &[String],
) -> Option<String> {
    do_oauth_refresh_compat(token_url, refresh_token, now_secs, scopes).await
}

// placeholder that open_browser_url still compiles via auth module
#[allow(dead_code)]
fn open_browser_url(url: &str) -> io::Result<()> {
    auth::open_browser_url(url)
}

fn print_help() {
    println!(
        "ctf-solver {VERSION} — autonomous CTF challenge solver

USAGE
  ctf --challenge <dir> [OPTIONS]
  ctf <dir>                   # shorthand
  ctf login                   # authenticate (OAuth or API key)
  ctf login openai            # OpenAI ChatGPT Plus (OAuth)
  ctf login --key openai      # OpenAI Platform API key
  ctf login anthropic         # Anthropic API key
  ctf logout [provider]       # remove saved credentials
  ctf model                   # list configured providers + available models
  ctf model set <spec>        # set default model  (e.g. openai/gpt-4o)
  ctf ctfd <cmd>              # CTFd list/info/pull/submit

OPTIONS
  --challenge, -c <dir>       Challenge directory (must contain files/ subdir)
  --model, -m <name>          Model alias or provider/model (e.g. opus, openai/gpt-4o)
  --plan-model <name>         Model for /plan analyst agent (default: auto cheaper)
                              opus → sonnet, gpt-4o → gpt-4o-mini, gpt-4.1 → gpt-4.1-mini
  --api <openai|anthropic>    Force API backend (default: auto-detect)
  --category <cat>            Override auto-detected category
                              (pwn|web|crypto|rev|forensics|misc|osint|network)
  --resume, -r <session>      Resume a previous session
  --version, -V               Print version
  --help, -h                  Show this help

SLASH COMMANDS (in REPL)
  /hint                Nudge the agent without revealing the full solution
  /plan                Analyst agent: triage files and write investigation plan to notes.md
  /submit <flag>       Verify flag against the challenge flag_format
  /notes               Show the challenge notes.md
  /files               List files in the challenge files/ directory
  /reset               Clear session, keep challenge context
  /category <cat>      Switch category mid-session
  /status              Token usage and session info
  /compact             Force-compact conversation history
  /cost                Show token usage
  /export [path]       Export session transcript
  /ctfd <cmd>          CTFd list/info/pull/submit
  /help                Show this help
  /exit, /quit         Exit

AUTHENTICATION
  Backend is auto-detected unless --api is passed. Resolution order
  (first match wins):
    1. --api <openai|anthropic>                     explicit override
    2. OPENAI_BASE_URL or OPENAI_API_KEY set        -> OpenAI-compatible
    3. ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN    -> Anthropic
    4. saved `ctf login`, then settings.json default_provider
    5. fallback                                     -> Anthropic

  Anthropic credentials:
    ANTHROPIC_API_KEY     sent as the x-api-key header
    ANTHROPIC_AUTH_TOKEN  sent as Authorization: Bearer (OAuth-style token)
    both set              both headers are sent (e.g. proxy + bearer)
    neither set           falls back to OAuth saved by `ctf login`
                          (auto-refreshed when expired)

  OpenAI-compatible credentials:
    OPENAI_API_KEY        Bearer key for the server
    saved login           `ctf login openai` (ChatGPT OAuth) or
                          `ctf login --key openai` (platform API key)
    neither set           defaults to 'dummy' (local servers that ignore auth)

  Examples:
    ANTHROPIC_API_KEY=sk-ant-... ctf ./chal -m opus
    ctf login openai && ctf ./chal -m gpt-4o              # ChatGPT OAuth, no key
    OPENAI_BASE_URL=http://127.0.0.1:11434/v1 ctf ./chal -m qwen   # local Ollama
    ANTHROPIC_BASE_URL=http://litellm:4000 ANTHROPIC_API_KEY=dummy ctf ./chal

ENVIRONMENT
  Anthropic backend (Claude API, LiteLLM, or any Claude-compatible proxy):
    ANTHROPIC_API_KEY     API key -> x-api-key header (may be 'dummy' for proxies)
    ANTHROPIC_AUTH_TOKEN  OAuth/bearer token -> Authorization: Bearer
    ANTHROPIC_BASE_URL    Override endpoint (default: official Anthropic API)
    ANTHROPIC_MAX_TOKENS  Cap on output tokens per response
  OpenAI-compatible backend (OpenAI, vLLM, Ollama, Groq, Gemini proxy, ...):
    OPENAI_API_KEY        Bearer key (default: 'dummy'; fine for local servers)
    OPENAI_BASE_URL       Endpoint, e.g. http://127.0.0.1:11434/v1
                          (setting either OPENAI_* var auto-selects --api openai)
  CTFd integration:
    CTFD_URL              Base URL for CTFd integration
    CTFD_TOKEN            CTFd access token
    CTFD_FLAG_FORMAT      Optional flag format when pulling from CTFd

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
    plan_model: String,
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
    let system_prompt = build_system_prompt(&challenge, api_mode)?;

    let mut cli = CtfCli::new(
        challenge.clone(),
        model,
        plan_model,
        session,
        system_prompt,
        session_path,
        flag_extractor,
        api_mode,
        notify,
    )?;

    // Slash command list shown in the interactive / picker.
    let slash_commands: Vec<(String, String)> = vec![
        (
            "/auto",
            "Autonomous loop until flag/caps: /auto [min] [--max-turns N] [--max-tokens N]",
        ),
        ("/hint", "Let the agent start or ask for a hint"),
        (
            "/plan",
            "Analyst agent: triage files and build investigation plan",
        ),
        (
            "/vuln",
            "Search CVEs and public exploits relevant to this challenge (no writeups)",
        ),
        ("/submit", "Check flag format before submitting"),
        ("/notes", "View notes.md"),
        ("/files", "List files in files/ with sizes"),
        ("/writeup", "Generate a detailed writeup → writeup.md"),
        ("/status", "Session stats: turns, tokens, model"),
        ("/cost", "Detailed token usage breakdown"),
        ("/compact", "Force-compact session to free tokens"),
        ("/reset", "Clear session, keep challenge context"),
        ("/category", "Change the active category"),
        ("/notify", "Toggle desktop notification + sound"),
        ("/export", "Export transcript to a text file"),
        (
            "/replay",
            "Show auto-generated replay script (logs/replay.sh)",
        ),
        ("/model", "Show or switch the active model mid-session"),
        (
            "/kb",
            "Vulnerability knowledge base: overview, capture, stats, search",
        ),
        ("/help", "Show the command list"),
        ("/exit", "Save session and exit"),
    ]
    .into_iter()
    .map(|(a, b)| (a.to_string(), b.to_string()))
    .collect();

    let mut editor = input::LineEditor::new(
        format!(
            "{C_TEAL}[{}]{C_RESET} {C_DARK_ASH}❯{C_RESET} ",
            challenge.category.as_str()
        ),
        slash_commands,
    );

    // Set terminal title to challenge name so it's visible in the tab/taskbar.
    set_terminal_title(&format!(
        "⚡ {} [{}]",
        challenge.name,
        challenge.category.as_str()
    ));

    println!("{}", cli.banner());
    print_environment_status(challenge.category);

    if cli.runtime.session().messages.is_empty() {
        println!(
            "{C_ASH}Challenge loaded. Type a message to start, or {C_RESET}{C_TEAL}{C_BOLD}/hint{C_RESET}{C_ASH} to let the agent begin automatically.{C_RESET}\n"
        );
    } else {
        let msg_count = cli.runtime.session().messages.len();
        println!("{C_ASH}Session resumed ({msg_count} messages). Last exchanges:{C_RESET}\n");
        print_session_tail(cli.runtime.session(), 6, 6);
        println!();
    }

    loop {
        match editor.read_line()? {
            input::ReadOutcome::ToggleVerboseOutput => {
                let now = !verbose_output().load(Ordering::Relaxed);
                verbose_output().store(now, Ordering::Relaxed);
                if now {
                    println!("{C_DIM}Full output mode: ON  (Ctrl+O to hide full bash/tool output again){C_RESET}");
                } else {
                    println!("{C_DIM}Full output mode: OFF (back to truncated bash/tool output){C_RESET}");
                }
            }
            input::ReadOutcome::ShowFullHistory => {
                let msg_count = cli.runtime.session().messages.len();
                println!("{C_ASH}Full session history ({msg_count} messages):{C_RESET}\n");
                print_session_tail(cli.runtime.session(), usize::MAX, usize::MAX);
                println!();
            }
            input::ReadOutcome::Submit(raw) => {
                let trimmed = raw.trim().to_string();
                if trimmed.is_empty() {
                    continue;
                }
                if matches!(trimmed.as_str(), "/exit" | "/quit") {
                    cli.persist()?;
                    println!(
                        "{C_ASH}Session saved to {}{C_RESET}",
                        cli.session_path.display()
                    );
                    break;
                }

                if trimmed.starts_with('/') {
                    input::print_separator();
                    cli.handle_slash(&trimmed)?;
                    continue;
                }

                // Echo the user's message as a distinct panel card (pi-style),
                // so prompt input and agent output are clearly separated.
                print!("{}", render_user_card(&trimmed));
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
    plan_model: String,
    runtime: ConversationRuntime<CtfApiClient, CtfToolExecutor>,
    session_path: PathBuf,
    log_path: PathBuf,
    started_at: u64,
    flag_extractor: FlagExtractor,
    system_prompt: Vec<String>,
    api_mode: Option<ApiMode>,
    notify: bool,
    notes_inject_pending: bool,
    kb_auto_captured: bool,
}

impl CtfCli {
    fn new(
        challenge: Challenge,
        model: String,
        plan_model: String,
        session: Session,
        system_prompt: Vec<String>,
        session_path: PathBuf,
        flag_extractor: FlagExtractor,
        api_mode: Option<ApiMode>,
        notify: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let api_client = CtfApiClient::new(model.clone(), api_mode)?;
        let tool_executor = CtfToolExecutor::new(&challenge);

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

        // Per-run log file: logs/<timestamp>.txt — created immediately on launch.
        let started_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let logs_dir = challenge.dir.join("logs");
        fs::create_dir_all(&logs_dir)?;
        let log_path = new_log_path(&logs_dir);

        let cli = Self {
            challenge,
            model,
            plan_model,
            runtime,
            session_path,
            log_path,
            started_at,
            flag_extractor,
            system_prompt,
            api_mode,
            notify,
            notes_inject_pending: false,
            kb_auto_captured: false,
        };
        // Write header immediately so the file exists even before the first agent turn.
        let _ = fs::write(&cli.log_path, cli.render_log());
        Ok(cli)
    }

    fn banner(&self) -> String {
        let inner = 53usize;
        let border: String = "─".repeat(inner + 2);
        let cwd = env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        let panel_row = |label: &str, value: &str| -> String {
            let content = format!("{C_ASH}{label:<11}{C_RESET} {C_INK}{value}{C_RESET}");
            format!(" {C_DARK_ASH}{C_BOLD}│{C_RESET} {content}")
        };

        format!(
            "\n\
{C_TEAL}{C_BOLD}\
 ██████╗████████╗███████╗\n\
██╔════╝╚══██╔══╝██╔════╝\n\
██║        ██║   █████╗  \n\
██║        ██║   ██╔══╝  \n\
╚██████╗   ██║   ██║     \n\
 ╚═════╝   ╚═╝   ╚═╝{C_RESET} {C_SAGE}{C_BOLD}Solver{C_RESET}\n\n\
 {C_DARK_ASH}{C_BOLD}┌{border}┐{C_RESET}\n\
{ch}\n\
{cat}\n\
{flag}\n\
{model}\n\
{plan}\n\
{dir}\n\
{sess}\n\
 {C_DARK_ASH}{C_BOLD}└{border}┘{C_RESET}\n\n\
  {C_ROSE}allow-all{C_RESET} · {C_STONE}no sandbox{C_RESET} · {C_ASH}compact 50k{C_RESET}\n\n\
  {C_DARK_ASH}/auto [min]  /hint  /plan  /submit <flag>  /notes  /files  /reset  /help{C_RESET}",
            border = border,
            ch = panel_row("Challenge", &self.challenge.name),
            cat = panel_row(
                "Category",
                &format!(
                    "{} {}",
                    self.challenge.category.emoji(),
                    self.challenge.category.as_str()
                )
            ),
            flag = panel_row("Flag fmt", &self.challenge.flag_format),
            model = panel_row("Model", &self.model),
            plan = panel_row("Plan model", &self.plan_model),
            dir = panel_row("Directory", &cwd),
            sess = panel_row("Session", &self.session_path.display().to_string()),
        )
    }

    fn maybe_inject_notes(&mut self, input: &str) -> String {
        if !self.notes_inject_pending {
            return input.to_string();
        }
        self.notes_inject_pending = false;
        let notes = fs::read_to_string(self.challenge.dir.join("notes.md")).unwrap_or_default();
        prepend_notes(&notes, input)
    }

    fn run_turn(&mut self, raw_input: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(candidate) = self.run_turn_impl(raw_input, true)? {
            self.verify_and_record_flag(&candidate)?;
        }
        Ok(())
    }

    /// Like `run_turn` but Ctrl+C does NOT interrupt the API stream mid-turn.
    /// Used by auto mode so turns always complete before the loop checks stop conditions.
    /// Returns true if a flag was declared, verified, and recorded this turn.
    fn run_turn_no_interrupt(
        &mut self,
        raw_input: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match self.run_turn_impl(raw_input, false)? {
            Some(candidate) => self.verify_and_record_flag(&candidate),
            None => Ok(false),
        }
    }

    /// Record a flag the agent declared with "FLAG: <value>".
    ///
    /// There is intentionally no in-agent "verification" round: the real judge
    /// is the platform / checker (`CTFd`, nc service, web form) or, for offline
    /// benchmarks, the ground-truth scorer — not the model re-checking its own
    /// work. The old self-verification ceremony wasted turns and produced both
    /// false negatives (rejecting a correct, statically-derived flag) and false
    /// positives (accepting a wrong flag the model "confirmed" with a buggy
    /// solver). So we accept the declared candidate, record it, and let the
    /// external oracle decide correctness.
    // Result is retained so a future real-checker submission (CTFd/nc) can
    // propagate errors; today it always succeeds.
    #[allow(clippy::unnecessary_wraps)]
    fn verify_and_record_flag(
        &mut self,
        candidate: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        println!("{}", render_flag_found(candidate));
        let notes = self.challenge.dir.join("notes.md");
        let _ = fs::OpenOptions::new()
            .append(true)
            .open(&notes)
            .and_then(|mut f| writeln!(f, "\n## FLAG FOUND\n```\n{candidate}\n```\n"));

        // Auto-capture only writes a review candidate. Do not promote model-written
        // knowledge into trusted long-term KB without an explicit user action.
        if !self.kb_auto_captured && !knowledge::is_solved(&self.challenge.name) {
            self.kb_auto_captured = true;
            let capture_path = self.challenge.dir.join("logs/kb_candidate.json");
            println!("{C_DIM}Auto-capturing vulnerability candidate for review…{C_RESET}");
            let prompt = knowledge::auto_capture_prompt(&capture_path, candidate);
            if self.run_turn_impl(&prompt, false).is_ok() {
                if capture_path.exists() {
                    println!(
                        "{C_SAGE}✓ KB candidate saved for review:{C_RESET} {}",
                        capture_path.display()
                    );
                    println!("{C_DIM}Review it, then run /kb promote to add it to long-term KB.{C_RESET}");
                } else {
                    println!("{C_ROSE}KB candidate file was not written.{C_RESET}");
                }
            } else {
                println!("{C_ROSE}KB candidate capture turn failed.{C_RESET}");
            }
        }

        Ok(true)
    }

    /// Runs one turn. Returns `Some(candidate)` if the agent declared
    /// "FLAG: <candidate>" this turn — unverified; the caller is responsible
    /// for verifying before treating it as found.
    fn run_turn_impl(
        &mut self,
        raw_input: &str,
        hook_sigint: bool,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let input = self.maybe_inject_notes(raw_input);
        let input = input.as_str();

        let mut spinner = Spinner::new();
        let mut stdout = io::stdout();
        spinner.tick(
            &format!(
                "{C_TEAL}Solving [{}]…{C_RESET}",
                self.challenge.category.as_str()
            ),
            TerminalRenderer::new().color_theme(),
            &mut stdout,
        )?;

        let flag = agent_interrupted();
        flag.store(false, Ordering::Relaxed);
        if hook_sigint {
            // Normal mode: Ctrl+C aborts the current API stream immediately.
            let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(flag));
        }
        // In auto mode (hook_sigint=false) we skip this registration so Ctrl+C
        // only sets the auto loop's stop_flag — the current turn runs to completion.

        // ── No prompter = zero approval dialogs ──────────────────────────────
        let mut result = self.runtime.run_turn(input, None);

        // Session too large for the model's context window → compact and retry.
        // 413/524: proxy/gateway limits. `exceed_context_size` / "exceeds the
        // available context": llama.cpp (local models) rejecting a request that
        // outgrew its `-c` window — common on small-context local servers once
        // the base prompt + accumulated turns pass the limit. Without this, the
        // agent hammers the same over-limit request every turn and the whole run
        // dies (observed: a 286KB-file rev challenge failing 20 turns straight).
        if let Err(ref e) = result {
            let emsg = e.to_string();
            if emsg.contains("413")
                || emsg.contains("524")
                || emsg.contains("exceed_context_size")
                || emsg.contains("exceeds the available context")
            {
                spinner.tick(
                    "⚡ context too large — compacting session and retrying...",
                    TerminalRenderer::new().color_theme(),
                    &mut stdout,
                )?;
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
                    CtfToolExecutor::new(&self.challenge),
                    PermissionPolicy::new(PermissionMode::Allow),
                    self.system_prompt.clone(),
                )
                .with_auto_compaction_input_tokens_threshold(CTF_AUTO_COMPACT_THRESHOLD);
                eprintln!("{C_DIM}[compact] removed {removed} messages, retrying{C_RESET}");
                // Inject notes so the agent knows where it left off after compaction.
                let notes =
                    fs::read_to_string(self.challenge.dir.join("notes.md")).unwrap_or_default();
                let retry_input = prepend_notes(&notes, raw_input);
                result = self.runtime.run_turn(&retry_input, None);
            }
        }

        let interrupted = flag.swap(false, Ordering::Relaxed);

        match result {
            Ok(summary) => {
                spinner.finish(
                    &format!("{C_SAGE}✓ Done{C_RESET}"),
                    TerminalRenderer::new().color_theme(),
                    &mut stdout,
                )?;
                println!();

                if let Some(compact_event) = summary.auto_compaction {
                    // Inject notes.md into the next turn so the agent resumes with full context.
                    self.notes_inject_pending = true;
                    println!(
                        "{C_DIM}[auto-compacted: removed {} messages — notes.md will be injected on next turn]{C_RESET}",
                        compact_event.removed_message_count
                    );
                }

                // Only treat the flag as found when the agent explicitly
                // declares "FLAG: <value>" in its response — the convention
                // the system prompt requires after its VALIDATE phase.
                // Scanning raw tool output (e.g. `strings` dumps) instead
                // causes false positives on decoy flag-shaped strings that
                // CTF binaries commonly embed as bait. The candidate is
                // returned unverified; the caller runs a verification turn
                // before recording it (banner/notes.md/KB).
                let assistant_text: String = summary
                    .assistant_messages
                    .iter()
                    .flat_map(|msg| msg.blocks.iter())
                    .filter_map(|block| match block {
                        ContentBlock::Text { text } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n");

                let candidate = self.flag_extractor.scan_declared(&assistant_text);
                let candidate = if candidate.is_some() && !session_has_tool_results(&self.runtime) {
                    println!(
                        "{C_STONE}⚠ Ignoring declared flag until a tool/checker has produced evidence.{C_RESET}"
                    );
                    None
                } else {
                    candidate
                };

                self.persist()?;
                // Kill any background processes the agent left running this turn.
                kill_background_pids();
                if self.notify {
                    send_desktop_notification(&self.challenge.name, "Agent finished");
                    play_sound();
                }
                Ok(candidate)
            }
            Err(error) => {
                if interrupted || error.to_string().contains("interrupted") {
                    spinner.finish(
                        &format!("{C_STONE}⏸ Paused{C_RESET}"),
                        TerminalRenderer::new().color_theme(),
                        &mut stdout,
                    )?;
                    println!("\n{C_STONE}Agent paused. Session saved. Continue with your next message.{C_RESET}\n");
                } else {
                    spinner.fail(
                        &format!("{C_ROSE}✗ Failed{C_RESET}"),
                        TerminalRenderer::new().color_theme(),
                        &mut stdout,
                    )?;
                    eprintln!("\n{C_ROSE}error: {error}{C_RESET}");
                    eprintln!("{C_STONE}Session saved. You can retry or continue with a new message.{C_RESET}\n");
                }
                let _ = self.persist();
                kill_background_pids();
                Ok(None)
            }
        }
    }

    fn handle_slash(&mut self, input: &str) -> Result<(), Box<dyn std::error::Error>> {
        let (cmd, rest) = input
            .trim_start_matches('/')
            .split_once(char::is_whitespace)
            .map_or((input.trim_start_matches('/'), ""), |(c, r)| (c, r.trim()));

        match cmd {
            "auto" => {
                // /auto [minutes] [--max-turns N] [--max-tokens N]
                let mut minutes: u64 = 30;
                let mut max_turns: u32 = 40;
                let mut max_tokens: u64 = 2_000_000;
                let mut it = rest.split_whitespace();
                while let Some(tok) = it.next() {
                    match tok {
                        "--max-turns" => {
                            if let Some(v) = it.next().and_then(|s| s.parse().ok()) {
                                max_turns = v;
                            }
                        }
                        "--max-tokens" => {
                            if let Some(v) = it.next().and_then(|s| s.parse().ok()) {
                                max_tokens = v;
                            }
                        }
                        other => {
                            if let Ok(v) = other.parse::<u64>() {
                                minutes = v;
                            }
                        }
                    }
                }
                self.run_auto_loop(minutes, max_turns, max_tokens)?;
            }
            "plan" => {
                let notes_path = self.challenge.dir.join("notes.md");
                let notes_content = fs::read_to_string(&notes_path).unwrap_or_default();
                let is_replan = notes_content.contains("- [x]");

                let (plan_prompt, turn_input, mode_label) = if is_replan {
                    println!("{C_STONE}⚠  Failed hypotheses detected — switching to replan mode{C_RESET}");
                    println!("\x1b[2mAnalyst reads conversation log + notes, proposes new attack vectors\x1b[0m\n");

                    // Extract the tail of the session transcript for the pivot analyst.
                    // Cap at ~20 KB to stay well within the plan model's context.
                    let full_transcript = render_export(
                        self.runtime.session(),
                        "────────────────────────────────────────────────────────────",
                    );
                    let session_tail = if full_transcript.len() > 20_000 {
                        let cut = full_transcript.len() - 20_000;
                        let cut = full_transcript[cut..]
                            .find('\n')
                            .map_or(cut, |i| cut + i + 1);
                        format!(
                            "[...earlier turns omitted...]\n\n{}",
                            &full_transcript[cut..]
                        )
                    } else {
                        full_transcript
                    };

                    let prompt =
                        replan_system_prompt(&self.challenge, &notes_content, &session_tail);
                    let input = format!(
                        "Analyse the failed hypotheses and solver log, then update {notes} with new attack vectors now.",
                        notes = notes_path.display(),
                    );
                    (prompt, input, "Replan complete")
                } else {
                    println!("\x1b[2mLaunching analyst agent — triaging files and building investigation plan...\x1b[0m");
                    println!(
                        "\x1b[2m(Fresh context window; your current session is unchanged)\x1b[0m\n"
                    );
                    let prompt = plan_system_prompt(&self.challenge);
                    let input = format!(
                        "Triage the challenge. Files are in {files}/. Write the investigation plan to {notes} now.",
                        files = self.challenge.dir.join("files").display(),
                        notes = notes_path.display(),
                    );
                    (prompt, input, "Investigation plan written to notes.md")
                };

                let api_client = CtfApiClient::new(self.plan_model.clone(), self.api_mode)?;
                let mut planner = ConversationRuntime::new(
                    Session::new(),
                    api_client,
                    CtfToolExecutor::new(&self.challenge),
                    PermissionPolicy::new(PermissionMode::Allow),
                    plan_prompt,
                )
                .with_auto_compaction_input_tokens_threshold(CTF_AUTO_COMPACT_THRESHOLD);

                let ok = match planner.run_turn(&turn_input, None) {
                    Ok(_) => true,
                    Err(ref e) if e.to_string().contains("no content") => true,
                    Err(e) => {
                        eprintln!("\n{C_ROSE}Planning agent error: {e}{C_RESET}\n");
                        false
                    }
                };
                if ok {
                    println!("\n{C_SAGE}✓ {mode_label}{C_RESET}");
                    println!("{C_DIM}Use /notes to view · /hint to continue solving{C_RESET}\n");
                }
            }
            "vuln" => {
                let query = if rest.is_empty() {
                    "the challenge files and any identified software, library, or protocol versions"
                        .to_string()
                } else {
                    rest.to_string()
                };
                let msg = format!(
                    "Research public CVEs and known exploits relevant to {query}. \
                     Use bash to search vulnerability databases — for example:\n\
                     - `curl -s 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<name+version>&resultsPerPage=5'`\n\
                     - `searchsploit <keyword>` (if installed)\n\
                     - Search ExploitDB or oss-fuzz reports as needed.\n\
                     Focus on CVEs with public PoC code or working exploits. \
                     Do NOT search for CTF writeups or challenge-specific solutions — only general vulnerability information.\n\
                     Summarize relevant CVEs (ID, CVSS, description, PoC link) in notes.md under a \
                     '## CVE Research' section using bash, then give me a brief text summary."
                );
                self.run_turn(&msg)?;
            }
            "hint" => {
                if self.runtime.session().messages.is_empty() {
                    // Fresh session — kick off autonomous solve
                    let init = format!(
                        "Start solving the CTF challenge '{}' (category: {}). \
                         Examine the files in {}/files/ and begin your exploitation approach.\n\
                         Actual files:\n{}\n\
                         Small text-file preview:\n{}\n\
                         Use these exact paths and data; do not infer filenames or ciphertext from the challenge name.",
                        self.challenge.name,
                        self.challenge.category.as_str(),
                        self.challenge.dir.display(),
                        challenge_files_manifest(&self.challenge),
                        challenge_files_preview(&self.challenge),
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
            "ctfd" => {
                ctfd::handle_repl(&self.challenge.dir, rest)?;
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
                        for entry in entries.filter_map(std::result::Result::ok) {
                            let meta = entry.metadata().ok();
                            let size = meta.map_or(0, |m| m.len());
                            println!(
                                "  {:>10} bytes  {}",
                                size,
                                entry.file_name().to_string_lossy()
                            );
                        }
                    }
                    Err(_) => println!("files/ directory not found"),
                }
            }
            "reset" => {
                println!("Resetting session (challenge context preserved)...");
                let system_prompt = build_system_prompt(&self.challenge, self.api_mode)?;
                let api_client = CtfApiClient::new(self.model.clone(), self.api_mode)?;
                let tool_executor = CtfToolExecutor::new(&self.challenge);
                self.runtime = ConversationRuntime::new(
                    Session::new(),
                    api_client,
                    tool_executor,
                    PermissionPolicy::new(PermissionMode::Allow),
                    system_prompt.clone(),
                )
                .with_auto_compaction_input_tokens_threshold(CTF_AUTO_COMPACT_THRESHOLD);
                self.system_prompt = system_prompt;
                self.kb_auto_captured = false;
                self.persist()?;
                println!(
                    "Session cleared. Starting fresh on '{}'.",
                    self.challenge.name
                );
            }
            "category" => {
                if rest.is_empty() {
                    println!(
                        "Current category: {} {}",
                        self.challenge.category.emoji(),
                        self.challenge.category.as_str()
                    );
                    println!("Usage: /category <pwn|web|crypto|rev|forensics|misc|osint|network>");
                } else if let Some(cat) = Category::from_str(rest) {
                    self.challenge = self.challenge.clone().with_category(cat);
                    println!(
                        "{C_SAGE}✓{C_RESET}  Category switched to: {} {}",
                        cat.emoji(),
                        cat.as_str()
                    );
                    println!(
                        "{C_DIM}Note: system prompt update takes effect on next /reset{C_RESET}"
                    );
                } else {
                    println!("Unknown category: {rest}");
                }
            }
            "status" => {
                let usage = self.runtime.usage();
                let cumulative = usage.cumulative_usage();
                println!(
                    "\n{C_TEAL}{C_BOLD}◆ Status{C_RESET}\n\
                     {C_ASH}  Model        {C_RESET}{C_INK}{}{C_RESET}\n\
                     {C_ASH}  Category     {C_RESET}{} {}\n\
                     {C_ASH}  Messages     {C_RESET}{}\n\
                     {C_ASH}  Turns        {C_RESET}{}\n\
                     {C_ASH}  Input tok    {C_RESET}{}\n\
                     {C_ASH}  Output tok   {C_RESET}{}\n\
                     {C_DIM}  Compact threshold  {} tok · keep {} messages{C_RESET}",
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
                let tool_executor = CtfToolExecutor::new(&self.challenge);
                self.runtime = ConversationRuntime::new(
                    result.compacted_session,
                    api_client,
                    tool_executor,
                    PermissionPolicy::new(PermissionMode::Allow),
                    self.system_prompt.clone(),
                )
                .with_auto_compaction_input_tokens_threshold(CTF_AUTO_COMPACT_THRESHOLD);
                self.notes_inject_pending = true;
                self.persist()?;
                println!("{C_SAGE}✓ Compacted{C_RESET}  removed {removed} messages, kept {kept}. Notes.md injected on next turn.");
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
                    self.challenge
                        .dir
                        .join(format!("{}-export.txt", self.challenge.name))
                } else {
                    PathBuf::from(rest)
                };
                let thin = "─".repeat(60);
                let content = render_export(self.runtime.session(), &thin);
                fs::write(&path, &content)?;
                println!(
                    "{C_SAGE}✓ Exported{C_RESET}  {} messages → {}",
                    self.runtime.session().messages.len(),
                    path.display()
                );
            }
            "notify" => {
                self.notify = !self.notify;
                if self.notify {
                    println!("{C_SAGE}🔔 Desktop notifications ON{C_RESET}");
                    send_desktop_notification(&self.challenge.name, "Notifications enabled");
                } else {
                    println!("{C_STONE}🔕 Desktop notifications OFF{C_RESET}");
                }
            }
            "writeup" => {
                let output_path = self.challenge.dir.join("writeup.md");
                let prompt = format!(
                    r"Write a thorough CTF writeup for the challenge '{}' (category: {}, flag format: {}).

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

Write the file now using bash, then confirm the path.",
                    self.challenge.name,
                    self.challenge.category.as_str(),
                    self.challenge.flag_format,
                    name = self.challenge.name,
                    cat = self.challenge.category.as_str(),
                    flag_fmt = self.challenge.flag_format,
                );
                println!(
                    "\x1b[2mGenerating writeup → {}\x1b[0m\n",
                    output_path.display()
                );
                self.run_turn(&prompt)?;
            }
            "model" => {
                if rest.is_empty() {
                    println!("Model       {}", self.model);
                    println!("Plan model  {}", self.plan_model);
                    println!();
                    println!("\x1b[2mUsage: /model <name>       switch main model (session preserved)\x1b[0m");
                    println!("\x1b[2m       /model plan <name>   switch plan model only\x1b[0m");
                    println!("\x1b[2mAliases: opus · sonnet · haiku · gpt-4o · gpt-4o-mini · gpt-4.1 · gpt-4.1-mini\x1b[0m");
                } else if let Some(plan_name) = rest.strip_prefix("plan ").map(str::trim) {
                    let new_plan = resolve_model_alias(plan_name).to_string();
                    let old = self.plan_model.clone();
                    self.plan_model.clone_from(&new_plan);
                    println!("{C_SAGE}✓ Plan model switched{C_RESET}  {old} → {C_BOLD}{new_plan}{C_RESET}");
                } else {
                    let new_model = resolve_model_alias(rest).to_string();
                    let old = self.model.clone();
                    // Rebuild runtime with new model — preserve session and system prompt.
                    let session = self.runtime.session().clone();
                    match CtfApiClient::new(new_model.clone(), self.api_mode) {
                        Ok(api_client) => {
                            self.runtime = ConversationRuntime::new(
                                session,
                                api_client,
                                CtfToolExecutor::new(&self.challenge),
                                PermissionPolicy::new(PermissionMode::Allow),
                                self.system_prompt.clone(),
                            )
                            .with_auto_compaction_input_tokens_threshold(
                                CTF_AUTO_COMPACT_THRESHOLD,
                            );
                            self.model.clone_from(&new_model);
                            println!("{C_SAGE}✓ Model switched{C_RESET}  {old} → {C_BOLD}{new_model}{C_RESET}");
                            println!(
                                "{C_DIM}(session preserved; Python REPL state reset){C_RESET}"
                            );
                        }
                        Err(e) => {
                            println!("{C_ROSE}✗ Failed to switch model: {e}{C_RESET}");
                        }
                    }
                }
            }
            "replay" => {
                let path = self.challenge.dir.join("logs/replay.sh");
                match fs::read_to_string(&path) {
                    Ok(content) => {
                        println!("\x1b[2m{}\x1b[0m", path.display());
                        println!("{content}");
                    }
                    Err(_) => println!("(no replay log yet — run a bash command first)"),
                }
            }
            "kb" => self.handle_kb(rest)?,
            "help" => print_repl_help(),
            _ => println!("Unknown command: /{cmd}  — type /help"),
        }
        Ok(())
    }

    /// Reads a `kb_capture.json` file written by the agent (via /kb capture or
    /// the post-flag auto-capture prompt) and saves it as a `KbEntry`.
    fn process_kb_capture_file(&mut self, capture_path: &Path) {
        if let Ok(raw) = fs::read_to_string(capture_path) {
            // Strip possible markdown code fences the agent may have wrapped it in
            let json_str = strip_code_fences(&raw);
            match serde_json::from_str::<serde_json::Value>(json_str) {
                Ok(v) => {
                    let vulns: Vec<String> = v["vulns"]
                        .as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .filter_map(|x| x.as_str().map(std::string::ToString::to_string))
                        .collect();
                    let description = v["description"].as_str().unwrap_or("").to_string();
                    let snippets: Vec<(String, String)> = v["snippets"]
                        .as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .filter_map(|s| {
                            let label = s["label"].as_str()?.to_string();
                            let code = s["code"].as_str()?.to_string();
                            Some((label, code))
                        })
                        .collect();
                    let tags: Vec<String> = v["tags"]
                        .as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .filter_map(|x| x.as_str().map(std::string::ToString::to_string))
                        .collect();
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let owasp: Vec<String> = v["owasp"]
                        .as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .filter_map(|x| x.as_str().map(std::string::ToString::to_string))
                        .collect();
                    let indicators: Vec<String> = v["indicators"]
                        .as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .filter_map(|x| x.as_str().map(std::string::ToString::to_string))
                        .collect();
                    let solved = v["solved"].as_bool().unwrap_or(false);
                    let flag = v["flag"].as_str().map(std::string::ToString::to_string);
                    let mut entry = knowledge::KbEntry {
                        id: knowledge::generate_id(&self.challenge.name, ts),
                        timestamp: ts,
                        challenge: self.challenge.name.clone(),
                        category: self.challenge.category.as_str().to_string(),
                        vulns,
                        description,
                        snippets,
                        tags,
                        owasp,
                        indicators,
                        solved,
                        flag,
                    };
                    entry.auto_owasp();
                    match knowledge::add_entry(entry) {
                        Ok(id) => {
                            let _ = fs::remove_file(capture_path);
                            println!(
                                "\n{C_SAGE}✓ Captured{C_RESET}  {} → {id}",
                                self.challenge.name
                            );
                            println!(
                                "{C_DIM}Use /kb to view the knowledge base overview.{C_RESET}"
                            );
                        }
                        Err(e) => println!("{C_ROSE}✗ Failed to save: {e}{C_RESET}"),
                    }
                }
                Err(e) => {
                    println!("{C_ROSE}✗ Could not parse capture JSON: {e}{C_RESET}");
                    println!("{C_DIM}File kept at {}{C_RESET}", capture_path.display());
                }
            }
        } else {
            println!(
                "{C_ROSE}✗ Agent did not write {}{C_RESET}",
                capture_path.display()
            );
            println!("{C_DIM}Try /kb add <vuln> | <description> for a manual entry.{C_RESET}");
        }
    }

    fn handle_kb(&mut self, rest: &str) -> Result<(), Box<dyn std::error::Error>> {
        let (sub, arg) = rest
            .split_once(char::is_whitespace)
            .map_or((rest.trim(), ""), |(s, a)| (s.trim(), a.trim()));

        match sub {
            "" => print!("{}", knowledge::render_overview()),
            "stats" => print!("{}", knowledge::render_stats()),
            "list" => print!(
                "{}",
                knowledge::render_list(if arg.is_empty() { None } else { Some(arg) })
            ),
            "search" => {
                if arg.is_empty() {
                    println!("Usage: /kb search <term>");
                } else {
                    print!("{}", knowledge::render_search(arg));
                }
            }
            "show" => {
                if arg.is_empty() {
                    println!("Usage: /kb show <challenge-name>");
                } else {
                    print!("{}", knowledge::render_show(arg));
                }
            }
            "add" => {
                if arg.is_empty() {
                    println!("Usage: /kb add <vuln1>, <vuln2> | <description>");
                    println!("  Example: /kb add RSA small exponent e=3 | Broadcast attack with Hastad's theorem");
                    return Ok(());
                }
                let (vulns_part, desc_part) = arg
                    .split_once('|')
                    .map_or((arg, ""), |(v, d)| (v.trim(), d.trim()));
                let vulns: Vec<String> = vulns_part
                    .split(',')
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect();
                if vulns.is_empty() {
                    println!("No vulnerabilities specified.");
                    return Ok(());
                }
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let mut entry = knowledge::KbEntry {
                    id: knowledge::generate_id(&self.challenge.name, ts),
                    timestamp: ts,
                    challenge: self.challenge.name.clone(),
                    category: self.challenge.category.as_str().to_string(),
                    vulns,
                    description: desc_part.to_string(),
                    snippets: vec![],
                    tags: vec![],
                    owasp: vec![],
                    indicators: vec![],
                    solved: false,
                    flag: None,
                };
                entry.auto_owasp();
                match knowledge::add_entry(entry) {
                    Ok(id) => println!("{C_SAGE}✓ Saved{C_RESET}  {} → {id}", self.challenge.name),
                    Err(e) => println!("{C_ROSE}✗ Failed to save: {e}{C_RESET}"),
                }
            }
            "capture" => {
                let capture_path = self.challenge.dir.join("logs/kb_capture.json");
                println!("{C_DIM}Asking agent to analyze and capture vulnerability…{C_RESET}\n");
                let prompt = knowledge::capture_prompt(&capture_path);
                self.run_turn(&prompt)?;
                self.process_kb_capture_file(&capture_path);
            }
            "promote" => {
                let capture_path = if arg.is_empty() {
                    self.challenge.dir.join("logs/kb_candidate.json")
                } else {
                    PathBuf::from(arg)
                };
                self.process_kb_capture_file(&capture_path);
            }
            "cheatsheet" => {
                println!("{}", knowledge::full_cheatsheet());
            }
            _ => {
                println!(
                    "Unknown kb subcommand: '{sub}'\n\
                     \n\
                     /kb               Overview: category chart, top vulns, recent\n\
                     /kb capture       Agent analyzes session and records to KB\n\
                     /kb add <v> | <d> Quick manual entry (comma-separated vulns | description)\n\
                     /kb list [cat]    List all entries (optionally filter by category)\n\
                     /kb search <term> Search across challenges, vulns, tags, descriptions\n\
                     /kb show <name>   Show full entry with description and code snippets\n\
                     /kb stats         Full visualization: bar charts, tag cloud, timeline\n\
                     /kb promote [p]   Promote reviewed logs/kb_candidate.json to KB\n\
                     /kb cheatsheet    Full KB cheatsheet grouped by category and vulnerability"
                );
            }
        }
        Ok(())
    }

    fn verify_flag(&self, submitted: &str) {
        if ctfd::has_metadata(&self.challenge.dir) {
            match ctfd::submit_flag_for_challenge(&self.challenge.dir, submitted) {
                Ok(()) => return,
                Err(e) => {
                    println!("{C_ROSE}CTFd submit failed: {e}{C_RESET}");
                    println!("{C_STONE}Falling back to local format check.{C_RESET}");
                }
            }
        }

        // Simple format check: does it look like the expected pattern?
        let prefix = self
            .challenge
            .flag_format
            .trim_end_matches("{...}")
            .trim_end_matches('{');
        let submitted_lower = submitted.to_lowercase();
        let prefix_lower = prefix.to_lowercase();

        if submitted_lower.starts_with(&prefix_lower)
            && submitted.contains('{')
            && submitted.ends_with('}')
        {
            println!("{}", render_flag_found(submitted));
            println!("{C_SAGE}Flag format looks correct. Submit it on the CTF platform.{C_RESET}");
        } else {
            println!("{C_ROSE}Flag format mismatch.{C_RESET}");
            println!("  Expected format: {}", self.challenge.flag_format);
            println!("  Submitted:       {submitted}");
        }
    }

    /// Autonomous loop: keep running turns until flag found, time limit hit, or Ctrl+C.
    ///
    /// Stop logic (checked AFTER each turn completes, not during):
    ///   • Flag found → stop immediately after detecting it
    ///   • Time limit exceeded → finish the current turn, then stop
    ///   • Ctrl+C (first press) → finish the current turn, then pause
    ///   • Ctrl+C (second press within 3 s) → also sets `agent_interrupted` → hard abort turn
    fn run_auto_loop(
        &mut self,
        limit_minutes: u64,
        max_turns: u32,
        max_tokens: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::time::{Duration, Instant};

        let limit = Duration::from_secs(limit_minutes * 60);
        let start = Instant::now();
        let mut turn = 0u32;

        // ── Signal handling ───────────────────────────────────────────────────
        // pause_flag: set by first Ctrl+C → finish current turn then stop.
        // agent_interrupted(): set by second Ctrl+C within 3s → hard abort.
        let pause_flag = Arc::new(AtomicBool::new(false));
        {
            let pf = Arc::clone(&pause_flag);
            let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, pf);
        }
        // Track the time of the first Ctrl+C so we know when "3s window" expires.
        let first_sigint_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
        {
            // Spawn a thread that watches pause_flag and promotes to hard interrupt
            // if it's pressed again within 3 s.
            let pf = Arc::clone(&pause_flag);
            let first_at = Arc::clone(&first_sigint_at);
            let ai = Arc::clone(agent_interrupted());
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(100));
                    if pf.load(Ordering::Relaxed) {
                        let mut guard = first_at.lock().unwrap();
                        match *guard {
                            None => {
                                // First press: record timestamp, show hint.
                                *guard = Some(Instant::now());
                                eprintln!(
                                    "\n{C_STONE}⏸  Auto: will pause after this turn finishes.{C_RESET}\
                                     {C_DIM}  Ctrl+C again within 3s to abort immediately.{C_RESET}"
                                );
                                // Clear pause_flag so we detect the NEXT press.
                                pf.store(false, Ordering::Relaxed);
                            }
                            Some(first) => {
                                if first.elapsed() <= Duration::from_secs(3) {
                                    // Second press within 3 s → hard interrupt.
                                    ai.store(true, Ordering::Relaxed);
                                    eprintln!("\n{C_ROSE}⚡ Hard abort requested.{C_RESET}");
                                }
                                // Reset regardless.
                                *guard = None;
                                pf.store(false, Ordering::Relaxed);
                            }
                        }
                    }
                }
            });
        }

        println!(
            "\n{C_TEAL}{C_BOLD}◆ Auto mode{C_RESET}  {C_DIM}caps: {limit_minutes}min · {max_turns} turns · {}k tokens{C_RESET}  \
             {C_DARK_ASH}Ctrl+C = pause after turn  ·  Ctrl+C×2 = abort now{C_RESET}\n",
            max_tokens / 1000,
        );

        let first_prompt = if self.runtime.session().messages.is_empty() {
            format!(
                "Begin solving this CTF challenge. Analyse the files, identify the vulnerability, \
                 and exploit it to retrieve the flag. Work methodically and document your findings.\n\
                 First call `challenge_recon` to gather safe evidence from ./files only; if it \
                 reports an archive, call `extract_archive` before custom shell commands.\n\
                 Actual files:\n{}\n\
                 Small text-file preview:\n{}\n\
                 Use these exact paths and data under ./files; do not infer filenames, keys, or ciphertext from the challenge name.",
                challenge_files_manifest(&self.challenge),
                challenge_files_preview(&self.challenge),
            )
        } else {
            "Continue solving. Review what you have done, identify the next logical step, \
             and execute it."
                .to_string()
        };

        let continuations = [
            "Continue. What is the next step?",
            "Keep going. Execute your next planned action.",
            "Progress. Try the next approach.",
            "Continue working toward the flag.",
            "What do you need to do next? Go ahead.",
        ];

        let mut prompts = std::iter::once(first_prompt).chain(
            continuations
                .iter()
                .cycle()
                .map(std::string::ToString::to_string),
        );
        let mut force_tool_next_turn = false;

        let elapsed_fmt = |d: Duration| {
            let s = d.as_secs();
            if s < 60 {
                format!("{s}s")
            } else {
                format!("{}m{}s", s / 60, s % 60)
            }
        };

        loop {
            // ── Pre-turn: only start a new turn if we are within limits ───────
            let elapsed = start.elapsed();
            if elapsed >= limit {
                println!(
                    "\n{C_STONE}⏰ Time limit ({limit_minutes} min) reached after {turn} turns.{C_RESET}\n\
                     {C_DIM}Type a message or `/auto {limit_minutes}` to continue.{C_RESET}\n"
                );
                break;
            }
            if turn >= max_turns {
                println!(
                    "\n{C_STONE}🛑 Turn cap ({max_turns}) reached.{C_RESET}\n\
                     {C_DIM}Raise it with `/auto {limit_minutes} --max-turns N` to continue.{C_RESET}\n"
                );
                break;
            }
            let used_tokens = u64::from(self.runtime.usage().cumulative_usage().total_tokens());
            if used_tokens >= max_tokens {
                println!(
                    "\n{C_STONE}💸 Token cap ({}k) reached after {turn} turns ({}k used).{C_RESET}\n\
                     {C_DIM}Raise it with `/auto {limit_minutes} --max-tokens N` to continue.{C_RESET}\n",
                    max_tokens / 1000, used_tokens / 1000,
                );
                break;
            }
            // Check if first Ctrl+C was already registered (first_sigint_at set).
            let pause_requested =
                first_sigint_at.lock().unwrap().is_some() || pause_flag.load(Ordering::Relaxed);
            if pause_requested {
                let ef = elapsed_fmt(elapsed);
                println!(
                    "\n{C_STONE}⏸  Auto mode paused after {turn} turns ({ef}).{C_RESET}\n\
                     {C_DIM}Type a message or `/auto` to resume.{C_RESET}\n"
                );
                // Reset both flags.
                *first_sigint_at.lock().unwrap() = None;
                pause_flag.store(false, Ordering::Relaxed);
                agent_interrupted().store(false, Ordering::Relaxed);
                break;
            }

            // ── Start turn ────────────────────────────────────────────────────
            turn += 1;
            let remaining = limit.saturating_sub(elapsed);
            let rem_s = remaining.as_secs();
            let rem_fmt = if rem_s < 60 {
                format!("{rem_s}s left")
            } else {
                format!("{}m left", rem_s / 60)
            };
            println!(
                "\x1b[2m── turn {turn} · {} · {rem_fmt} ───────────────────────\x1b[0m",
                elapsed_fmt(elapsed)
            );

            let prompt = if force_tool_next_turn {
                force_tool_next_turn = false;
                format!(
                    "Your previous auto turn did not call any tool, so no evidence was gathered. \
                     This turn MUST call at least one tool before any explanation. Prefer the \
                     `challenge_recon` tool with max_files=120. If an archive is shown, call \
                     `extract_archive` on that ./files archive next instead of writing unzip shell.\n\
                     Actual files:\n{}\n\
                     Small text-file preview:\n{}",
                    challenge_files_manifest(&self.challenge),
                    challenge_files_preview(&self.challenge),
                )
            } else {
                prompts.next().unwrap()
            };
            let before_turn_messages = self.runtime.session().messages.len();

            // run_turn_no_interrupt: Ctrl+C does NOT abort the API stream.
            // The turn always runs to completion; stop is evaluated after.
            // It runs an internal verification turn and only returns true once
            // the flag has been confirmed (and recorded to notes.md/KB).
            let verified = self.run_turn_no_interrupt(&prompt)?;
            if verified {
                turn += 1; // account for the internal verification turn
                let ef = elapsed_fmt(start.elapsed());
                println!(
                    "\n{C_SAGE}{C_BOLD}🎉 Flag verified in {turn} turns ({ef}). Auto mode complete.{C_RESET}\n"
                );
                break;
            }
            let used_tool_this_turn = messages_slice_has_tool_results(
                &self.runtime.session().messages[before_turn_messages..],
            );
            if !used_tool_this_turn {
                force_tool_next_turn = true;
                println!(
                    "{C_STONE}⚠ Auto turn produced no tool result; next turn will force tool-backed recon.{C_RESET}"
                );
            }
        }

        Ok(())
    }

    fn persist(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.runtime.session().save_to_path(&self.session_path)?;
        let _ = fs::write(&self.log_path, self.render_log());
        Ok(())
    }

    fn render_log(&self) -> String {
        let divider = "═".repeat(60);
        let thin = "─".repeat(60);
        let mode_label = match self.api_mode {
            Some(ApiMode::OpenAi) => "openai",
            Some(ApiMode::Anthropic) | None => "anthropic",
        };
        let header = format!(
            "{divider}\n\
             CTF Solver — Session Log\n\
             {divider}\n\
             Challenge : {name}\n\
             Category  : {cat}\n\
             Model     : {model}\n\
             API mode  : {mode}\n\
             Started   : {ts} UTC\n\
             {divider}\n\n",
            name = self.challenge.name,
            cat = self.challenge.category.as_str(),
            model = self.model,
            mode = mode_label,
            ts = utc_datetime_str(self.started_at).replace('_', " "),
        );
        let transcript = render_export(self.runtime.session(), &thin);
        if transcript.is_empty() {
            header
        } else {
            format!("{header}{transcript}")
        }
    }
}

fn print_repl_help() {
    println!(
        "CTF Solver commands
  /hint                 Ask for a nudge without full solution
  /plan                 Analyst agent: triage files, build investigation plan in notes.md
  /vuln [keyword]       Search CVEs and public exploits (no writeups)
  /submit <flag>        Verify flag format
  /notes                Show notes.md
  /files                List challenge files
  /reset                Clear session, keep challenge context
  /category <name>      Show/switch category
  /status               Session info and token usage
  /compact              Force-compact conversation history
  /cost                 Token usage breakdown
  /export [path]        Export transcript
  /ctfd <cmd>           CTFd list/info/pull/submit
  /replay               Show auto-generated replay script (logs/replay.sh)
  /model [name]         Show or switch the active model (session preserved)
  /writeup              Generate a detailed writeup and save to writeup.md
  /kb                   Vulnerability knowledge base overview
  /kb capture           Agent records current challenge's vulnerabilities to KB
  /kb promote [path]    Promote reviewed logs/kb_candidate.json to KB
  /kb add <v> | <d>     Quick manual KB entry (comma-separated vulns | description)
  /kb list [cat]        List KB entries (filter by category: crypto, pwn, web…)
  /kb search <term>     Search KB by keyword
  /kb show <challenge>  Show full KB entry with code snippets
  /kb stats             Full visualization: bar charts, tag cloud, timeline
  /kb cheatsheet        Full cheatsheet grouped by category and vulnerability
  /help                 This help
  /exit, /quit          Exit and save session

  Up/Down               Navigate prompt history
  Ctrl-C                Clear input (exit if empty)
  Ctrl-O                Toggle full bash/tool output mode
  Ctrl-E                Show full session history
  Shift+Enter           Insert newline"
    );
}

// ─── System prompt builder ────────────────────────────────────────────────────

fn build_system_prompt(
    challenge: &Challenge,
    api_mode: Option<ApiMode>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // Mirror the same auto-detection as CtfApiClient::new so the prompt
    // always matches the actual backend even when api_mode is None.
    let openai_backend = match api_mode {
        Some(ApiMode::OpenAi) => true,
        Some(ApiMode::Anthropic) => false,
        None => {
            let storage = auth::AuthStorage::load();
            std::env::var("OPENAI_BASE_URL").is_ok()
                || std::env::var("OPENAI_API_KEY").is_ok()
                || storage.has("openai")
        }
    };
    let ctf_prompt = ctf_system_prompt(challenge, openai_backend);

    // Also load project CLAUDE.md if present, but put CTF prompt first
    let cwd = env::current_dir()?;
    let mut sections = vec![ctf_prompt];

    // Inject KB cheatsheet for this category so agent benefits from past experience
    if let Some(sheet) = knowledge::cheatsheet_for_category(challenge.category.as_str()) {
        sections.push(sheet);
    }

    if let Ok(config_sections) =
        runtime::load_system_prompt(cwd, "2026-04-07", env::consts::OS, "unknown")
    {
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
    OpenAi {
        base_url: String,
        api_key: String,
        is_oauth: bool,
        http: reqwest::Client,
    },
}

struct CtfApiClient {
    tokio_rt: tokio::runtime::Runtime,
    backend: ApiBackend,
    model: String,
}

impl CtfApiClient {
    fn new(
        model: String,
        mode_override: Option<ApiMode>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let tokio_rt = tokio::runtime::Runtime::new()?;

        // Apply API keys from auth.json to env vars (only if not already set).
        let storage = auth::AuthStorage::load();
        storage.apply_env_vars();

        // Resolve effective mode:
        //   1. --api flag (mode_override) takes priority
        //   2. OPENAI_BASE_URL / OPENAI_API_KEY env vars → OpenAI mode
        //   3. settings.json default_provider
        //   4. auth.json: openai entry → OpenAI, anthropic entry → Anthropic
        //   5. fallback → Anthropic mode
        let effective_mode = mode_override.unwrap_or_else(|| {
            if std::env::var("OPENAI_BASE_URL").is_ok() || std::env::var("OPENAI_API_KEY").is_ok() {
                return ApiMode::OpenAi;
            }
            if std::env::var("ANTHROPIC_API_KEY").is_ok()
                || std::env::var("ANTHROPIC_AUTH_TOKEN").is_ok()
            {
                return ApiMode::Anthropic;
            }
            // Check settings.json for a configured default.
            let settings = auth::CtfSettings::load();
            match settings.default_provider.as_deref() {
                Some("openai") => return ApiMode::OpenAi,
                Some("anthropic") => return ApiMode::Anthropic,
                _ => {}
            }
            // Fall back to first entry in auth.json.
            if storage.has("openai") {
                return ApiMode::OpenAi;
            }
            if storage.has("anthropic") {
                return ApiMode::Anthropic;
            }
            ApiMode::Anthropic
        });

        let backend = match effective_mode {
            ApiMode::OpenAi => {
                let base_url = std::env::var("OPENAI_BASE_URL")
                    .unwrap_or_else(|_| OPENAI_DEFAULT_BASE_URL.to_string());
                let env_key = std::env::var("OPENAI_API_KEY").ok();
                let is_oauth = env_key.is_none()
                    && matches!(storage.get("openai"), Some(auth::Credential::OAuth { .. }));
                let api_key = env_key
                    .or_else(resolve_openai_auth)
                    .unwrap_or_else(|| "dummy".to_string());
                let http = reqwest::Client::new();
                eprintln!("\x1b[2m[api] OpenAI mode → {base_url}\x1b[0m");
                ApiBackend::OpenAi {
                    base_url,
                    api_key,
                    is_oauth,
                    http,
                }
            }
            ApiMode::Anthropic => {
                let auth = resolve_startup_auth_source(|| {
                    let cwd = env::current_dir().map_err(api::ApiError::from)?;
                    let config = ConfigLoader::default_for(&cwd)
                        .load()
                        .map_err(|e| api::ApiError::Auth(format!("config load failed: {e}")))?;
                    Ok(config.oauth().cloned())
                })?;
                ApiBackend::Anthropic(
                    AnthropicClient::from_auth(auth).with_base_url(api::read_base_url()),
                )
            }
        };

        Ok(Self {
            tokio_rt,
            backend,
            model,
        })
    }
}

/// Strips `<think>...</think>` reasoning blocks that some models (e.g.
/// Qwen-derived Qwythos) emit as plain text over the `OpenAI` chat backend,
/// where the reasoning is *not* delivered in a structured field. Without this,
/// the chain-of-thought leaks into the visible transcript, pollutes the
/// conversation history fed back to the model, and gets mistaken for a flag
/// candidate when the model "thinks out loud" about the flag format.
///
/// Handles tags split across streaming chunks (via `carry`). Some models begin
/// in reasoning mode and emit a closing `</think>` with no opening tag; when
/// that happens `drop_preceding` is set so the caller can discard text that was
/// already streamed before the close.
#[derive(Default)]
struct ThinkFilter {
    in_think: bool,
    saw_open: bool,
    carry: String,
    /// One-shot signal: an unmatched `</think>` just closed implicit leading
    /// reasoning, so any text accumulated before it should be dropped.
    drop_preceding: bool,
}

impl ThinkFilter {
    /// Feed one streaming text delta; returns only the visible (non-reasoning)
    /// portion. A trailing partial tag is buffered and resolved on the next call.
    fn push(&mut self, chunk: &str) -> String {
        let mut data = std::mem::take(&mut self.carry);
        data.push_str(chunk);
        let mut out = String::new();
        let mut s = data.as_str();
        loop {
            let Some(pos) = s.find('<') else {
                if !self.in_think {
                    out.push_str(s);
                }
                break;
            };
            let (before, rest) = s.split_at(pos);
            if !self.in_think {
                out.push_str(before);
            }
            if let Some(r) = rest.strip_prefix("<think>") {
                self.in_think = true;
                self.saw_open = true;
                s = r;
            } else if let Some(r) = rest.strip_prefix("</think>") {
                if !self.saw_open {
                    // Closing tag with no matching open: the model started in
                    // reasoning mode, so everything emitted so far was thinking.
                    self.drop_preceding = true;
                    self.saw_open = true;
                    out.clear();
                }
                self.in_think = false;
                s = r;
            } else if "<think>".starts_with(rest) || "</think>".starts_with(rest) {
                // Partial tag at the tail — buffer until the next chunk completes it.
                self.carry = rest.to_string();
                break;
            } else {
                // A lone '<' that is not a think tag — keep it if visible.
                if !self.in_think {
                    out.push('<');
                }
                s = &rest[1..];
            }
        }
        out
    }
}

/// Models that only work on /v1/responses (not /v1/chat/completions).
fn needs_responses_api(model: &str) -> bool {
    model.starts_with("codex")
}

/// Animated "thinking" spinner shown while waiting for the first token of a
/// response — runs on its own thread so it keeps spinning during the
/// (sometimes long) gap before any output arrives, so the user can tell the
/// agent is alive and not stuck.
struct ThinkingSpinner {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ThinkingSpinner {
    fn start(label: String) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        let theme = *TerminalRenderer::new().color_theme();
        let handle = std::thread::spawn(move || {
            let mut spinner = Spinner::new();
            let mut out = io::stdout();
            while !stop_clone.load(Ordering::Relaxed) {
                let _ = spinner.tick(&label, &theme, &mut out);
                std::thread::sleep(std::time::Duration::from_millis(120));
            }
            let _ = crossterm::execute!(
                out,
                crossterm::cursor::MoveToColumn(0),
                crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine)
            );
            let _ = out.flush();
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }

    /// Stop the ticker and wait for it to clear its line before any further
    /// output is written, to avoid interleaving with the ticker's redraws.
    fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for ThinkingSpinner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl ApiClient for CtfApiClient {
    fn stream(&mut self, request: ApiRequest) -> Result<Vec<AssistantEvent>, RuntimeError> {
        if agent_interrupted().load(Ordering::Relaxed) {
            return Err(RuntimeError::new("interrupted"));
        }
        match &self.backend {
            // OAuth users (ChatGPT Plus) → always use chatgpt.com/backend-api/codex/responses,
            // same as feynman/pi-coding-agent. API-key users → use standard endpoints.
            ApiBackend::OpenAi { is_oauth, .. } => {
                if *is_oauth || needs_responses_api(&self.model) {
                    self.stream_responses_api(request)
                } else {
                    self.stream_openai(request)
                }
            }
            ApiBackend::Anthropic(_) => self.stream_anthropic(request),
        }
    }
}

impl CtfApiClient {
    fn stream_anthropic(
        &mut self,
        request: ApiRequest,
    ) -> Result<Vec<AssistantEvent>, RuntimeError> {
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
            system: (!request.system_prompt.is_empty()).then(|| request.system_prompt.join("\n\n")),
            tools: Some(tool_defs),
            tool_choice: Some(ToolChoice::Auto),
            stream: true,
        };

        let client = match &self.backend {
            ApiBackend::Anthropic(c) => c.clone(),
            ApiBackend::OpenAi { .. } => unreachable!(),
        };

        self.tokio_rt.block_on(async {
            let mut stream = client
                .stream_message(&message_request)
                .await
                .map_err(|e| RuntimeError::new(e.to_string()))?;
            // A Ctrl+C pressed while the request was retrying (e.g. rate-limit
            // backoff inside the api client) shouldn't carry forward as a
            // hard-abort now that we have a live stream to process.
            agent_interrupted().store(false, Ordering::Relaxed);

            let renderer = TerminalRenderer::new();
            let mut markdown_state = MarkdownStreamState::default();
            let mut stdout = io::stdout();
            let mut events: Vec<AssistantEvent> = Vec::new();
            let mut pending_tool: Option<(String, String, String)> = None;
            let mut saw_stop = false;
            let mut printed_label = false;
            let mut thinking = Some(ThinkingSpinner::start(format!(
                "{C_TEAL}Thinking…{C_RESET}"
            )));

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
                            cache_creation_input_tokens: start
                                .message
                                .usage
                                .cache_creation_input_tokens,
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
                                    if !printed_label {
                                        printed_label = true;
                                        if let Some(t) = thinking.take() {
                                            t.stop();
                                        }
                                        write!(stdout, "{}", assistant_label())
                                            .and_then(|()| stdout.flush())
                                            .map_err(|e| RuntimeError::new(e.to_string()))?;
                                    }
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
                            if let Some(t) = thinking.take() {
                                t.stop();
                            }
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
                    // Converted into an `Err` by `SseParser`/`parse_frame` before
                    // it ever reaches `next_event`'s `Ok(Some(_))` path.
                    ApiStreamEvent::Error(_) => unreachable!("stream errors are surfaced as Err"),
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
        let (base_url, stored_key, is_oauth, http) = match &self.backend {
            ApiBackend::OpenAi {
                base_url,
                api_key,
                is_oauth,
                http,
            } => (base_url.clone(), api_key.clone(), *is_oauth, http.clone()),
            ApiBackend::Anthropic(_) => unreachable!(),
        };

        // Proactive refresh: if using OAuth, re-resolve the token before every
        // request so a mid-session expiry is caught without needing a 401 first.
        let api_key = if is_oauth {
            resolve_openai_auth().unwrap_or(stored_key)
        } else {
            stored_key
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
            .map(|spec| {
                json!({
                    "type": "function",
                    "function": {
                        "name": spec.name,
                        "description": spec.description,
                        "parameters": spec.input_schema,
                    }
                })
            })
            .collect();

        let mut messages = Vec::new();
        if !request.system_prompt.is_empty() {
            messages.push(json!({
                "role": "system",
                "content": request.system_prompt.join("\n\n"),
            }));
        }
        messages.extend(convert_messages_openai(&request.messages));

        // Use max_completion_tokens universally — OpenAI now prefers it for all models.
        // GPT-5.x actively rejects max_tokens; o-series always required max_completion_tokens.
        let max_tok = max_tokens_for_model(&self.model);
        let body = json!({
            "model": self.model,
            "messages": messages,
            "tools": tools_json,
            "tool_choice": "auto",
            "max_completion_tokens": max_tok,
            "stream": true,
        });

        self.tokio_rt.block_on(async {
            use futures_util::StreamExt;
            let mut last_err = String::new();
            let mut api_key = api_key;
            let mut token_refreshed = false;

            for attempt in 0..5u32 {
                if attempt > 0 {
                    let wait = std::time::Duration::from_secs(2u64.pow(attempt - 1));
                    eprintln!("\x1b[2m[api] retrying in {}s (attempt {}/5)...\x1b[0m", wait.as_secs(), attempt + 1);
                    tokio::time::sleep(wait).await;
                    // A Ctrl+C pressed while waiting out a transient/rate-limit
                    // backoff shouldn't carry forward as a hard-abort once the
                    // retry actually starts doing real work.
                    agent_interrupted().store(false, Ordering::Relaxed);
                }

                let resp = match http.post(&endpoint).bearer_auth(&api_key).json(&body).send().await {
                    Err(e) => { last_err = format!("openai request failed: {e}"); continue; }
                    Ok(r) => r,
                };

                let status = resp.status();
                // Transient server/gateway errors → retry
                // 500 internal_error and 529 overloaded are also transient on OpenAI.
                if matches!(status.as_u16(), 500 | 502 | 503 | 504 | 520 | 521 | 522 | 523 | 524 | 529) {
                    let text = resp.text().await.unwrap_or_default();
                    last_err = format!("openai api returned {status}: {text}");
                    continue;
                }
                // 429 rate-limited → respect Retry-After header then retry
                if status.as_u16() == 429 {
                    let retry_after = resp.headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(10);
                    let text = resp.text().await.unwrap_or_default();
                    last_err = format!("openai api returned {status}: {text}");
                    let wait = retry_after.min(120); // cap at 2 min
                    eprintln!("{C_STONE}[api] rate limited (429) — waiting {wait}s…{C_RESET}");
                    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                    agent_interrupted().store(false, Ordering::Relaxed);
                    continue;
                }
                // 401 with OAuth → try refreshing token once, then retry immediately.
                if status.as_u16() == 401 && is_oauth && !token_refreshed {
                    let body_text = resp.text().await.unwrap_or_default();
                    eprintln!("{C_STONE}[auth] 401 received — refreshing OAuth token…{C_RESET}");
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    if let Some((rt, scopes)) = load_openai_oauth_for_refresh() {
                        if let Some(new_cred) = auth::refresh_oauth_token(
                            "openai", "https://auth.openai.com/oauth/token", &rt, now, &scopes,
                        ).await {
                            if let auth::Credential::OAuth { ref access_token, .. } = new_cred {
                                api_key.clone_from(access_token);
                            }
                            let mut st = auth::AuthStorage::load();
                            st.set("openai", new_cred);
                            let _ = st.save();
                            token_refreshed = true;
                            eprintln!("{C_DIM}[auth] Retrying with refreshed token…{C_RESET}");
                            continue; // retry immediately, no sleep
                        }
                    }
                    // Refresh unavailable or failed — surface the original 401.
                    eprintln!("{C_ROSE}[auth] Could not refresh token. Run `ctf login` to re-authenticate.{C_RESET}");
                    return Err(RuntimeError::new(format!("openai api returned {status}: {body_text}")));
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
                let mut printed_label = false;
                let mut assistant_text = String::new();
                let mut reasoning_text = String::new();
                let mut fallback_tools_emitted = false;
                let mut think_filter = ThinkFilter::default();
                let mut thinking = Some(ThinkingSpinner::start(format!("{C_TEAL}Thinking…{C_RESET}")));

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
                    let Some(data) = line.strip_prefix("data: ") else { continue };
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
                        let Some(delta) = choice.get("delta") else {
                            continue;
                        };

                        // Text content — strip <think> reasoning before it
                        // reaches the transcript, history, or flag extraction.
                        if let Some(text) = delta.get("content").and_then(Value::as_str) {
                            if !text.is_empty() {
                                let visible = think_filter.push(text);
                                if think_filter.drop_preceding {
                                    // Implicit leading reasoning just closed:
                                    // discard everything streamed before it.
                                    think_filter.drop_preceding = false;
                                    assistant_text.clear();
                                    events.retain(|e| {
                                        !matches!(e, AssistantEvent::TextDelta(_))
                                    });
                                    markdown_state = MarkdownStreamState::default();
                                }
                                if !visible.is_empty() {
                                    assistant_text.push_str(&visible);
                                    if !printed_label {
                                        printed_label = true;
                                        if let Some(t) = thinking.take() { t.stop(); }
                                        write!(stdout, "{}", assistant_label())
                                            .and_then(|()| stdout.flush())
                                            .map_err(|e| RuntimeError::new(e.to_string()))?;
                                    }
                                    if let Some(rendered) =
                                        markdown_state.push(&renderer, &visible)
                                    {
                                        write!(stdout, "{rendered}")
                                            .and_then(|()| stdout.flush())
                                            .map_err(|e| RuntimeError::new(e.to_string()))?;
                                    }
                                    events.push(AssistantEvent::TextDelta(visible));
                                }
                            }
                        }

                        // Reasoning models (deepseek-style, served via llama.cpp)
                        // stream chain-of-thought in a separate `reasoning_content`
                        // field. Capture it so a turn that produced only reasoning
                        // (empty `content`) can still recover its intended tool call.
                        if let Some(rc) = delta
                            .get("reasoning_content")
                            .and_then(Value::as_str)
                            .or_else(|| delta.get("reasoning").and_then(Value::as_str))
                        {
                            reasoning_text.push_str(rc);
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

                        // Finish reason — flush any pending tool calls. "length"
                        // (generation hit max_tokens) is treated as a clean stop
                        // so the turn's content is kept instead of being dropped
                        // as an unterminated stream.
                        if choice.get("finish_reason").and_then(Value::as_str)
                            .is_some_and(|r| r == "tool_calls" || r == "stop" || r == "length")
                        {
                            if let Some(t) = thinking.take() { t.stop(); }
                            if let Some(rendered) = markdown_state.flush(&renderer) {
                                write!(stdout, "{rendered}")
                                    .and_then(|()| stdout.flush())
                                    .map_err(|e| RuntimeError::new(e.to_string()))?;
                            }
                            let mut sorted_tools: Vec<_> = pending_tools.drain().collect();
                            sorted_tools.sort_by_key(|(i, _)| *i);
                            let has_native_tools = !sorted_tools.is_empty();
                            for (_, (id, name, input)) in sorted_tools {
                                if !name.is_empty() {
                                    let display = format_ctf_tool_call(&name, &input);
                                    write!(stdout, "\n{display}\n")
                                        .and_then(|()| stdout.flush())
                                        .map_err(|e| RuntimeError::new(e.to_string()))?;
                                    events.push(AssistantEvent::ToolUse { id, name, input });
                                }
                            }
                            if !has_native_tools && !fallback_tools_emitted {
                                let mut fallback_tools =
                                    fallback_tool_calls_from_text(&assistant_text);
                                // Reasoning models sometimes settle on the next
                                // action only inside their hidden reasoning, leaving
                                // `content` empty. Rather than burn the turn, recover
                                // the intended call from the reasoning as a last resort.
                                if fallback_tools.is_empty()
                                    && assistant_text.trim().is_empty()
                                    && !reasoning_text.trim().is_empty()
                                {
                                    fallback_tools = fallback_tool_calls_from_text(&reasoning_text);
                                }
                                for (idx, tool) in fallback_tools.into_iter().enumerate() {
                                    let display = format_ctf_tool_call(&tool.name, &tool.input);
                                    write!(stdout, "\n{display}\n")
                                        .and_then(|()| stdout.flush())
                                        .map_err(|e| RuntimeError::new(e.to_string()))?;
                                    events.push(AssistantEvent::ToolUse {
                                        id: format!("fallback_tool_{idx}"),
                                        name: tool.name,
                                        input: tool.input,
                                    });
                                }
                                fallback_tools_emitted = true;
                            }
                            if !events.iter().any(|e| {
                                matches!(e, AssistantEvent::TextDelta(t) if !t.is_empty())
                                    || matches!(e, AssistantEvent::ToolUse { .. })
                            }) {
                                events.push(AssistantEvent::TextDelta(
                                    "(empty response)".to_string(),
                                ));
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
                if !events.iter().any(|e| matches!(e, AssistantEvent::MessageStop))
                    && events.iter().any(|e| {
                        matches!(e, AssistantEvent::TextDelta(t) if !t.is_empty())
                            || matches!(e, AssistantEvent::ToolUse { .. })
                    }) {
                        events.push(AssistantEvent::MessageStop);
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
            if out.trim().is_empty() {
                err.into_owned()
            } else {
                out.into_owned()
            }
        })
        .unwrap_or_default()
}

fn sh_in_dir(cwd: &Path, cmd: &str) -> String {
    std::process::Command::new("sh")
        .current_dir(cwd)
        .args(["-c", cmd])
        .output()
        .map(|o| {
            let out = String::from_utf8_lossy(&o.stdout);
            let err = String::from_utf8_lossy(&o.stderr);
            if out.trim().is_empty() {
                err.into_owned()
            } else {
                out.into_owned()
            }
        })
        .unwrap_or_default()
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn relative_files(path: &Path) -> Option<String> {
    let mut comps = path.components();
    let first = comps.next()?.as_os_str().to_string_lossy();
    if first != "files" {
        return None;
    }
    Some(format!("./{}", path.to_string_lossy()))
}

fn collect_regular_files(root: &Path, max: usize) -> Vec<PathBuf> {
    fn visit(dir: &Path, out: &mut Vec<PathBuf>, max: usize) {
        if out.len() >= max {
            return;
        }
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
        entries.sort_by_key(std::fs::DirEntry::path);
        for entry in entries {
            if out.len() >= max {
                break;
            }
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                visit(&path, out, max);
            } else if meta.is_file() {
                out.push(path);
            }
        }
    }

    let mut out = Vec::new();
    visit(root, &mut out, max);
    out
}

fn recon_file_priority(path: &Path) -> u8 {
    let s = path.to_string_lossy().to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name == "main.jsbundle" {
        0
    } else if s.contains(".app/hermeschallenge") && !s.contains("/frameworks/") {
        1
    } else if name == "info.plist" && s.contains(".app/") && !s.contains("/frameworks/") {
        2
    } else if archive_kind(path).is_some() {
        3
    } else if s.contains("/frameworks/") {
        8
    } else {
        5
    }
}

fn noisy_vendor_framework(path: &Path) -> bool {
    let s = path.to_string_lossy().to_ascii_lowercase();
    s.contains("/frameworks/react.framework/")
        || s.contains("/frameworks/reactnativedependencies.framework/")
        || s.contains("/frameworks/hermes.framework/")
        || s.contains("/frameworks/hermesvm.framework/")
}

fn likely_text_file(path: &Path, size: u64) -> bool {
    if size > 96 * 1024 {
        return false;
    }
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "txt"
            | "md"
            | "py"
            | "sage"
            | "js"
            | "ts"
            | "json"
            | "yml"
            | "yaml"
            | "toml"
            | "ini"
            | "env"
            | "c"
            | "h"
            | "cpp"
            | "hpp"
            | "rs"
            | "go"
            | "java"
            | "php"
            | "html"
            | "css"
            | "sh"
            | "sql"
            | "xml"
    ) || path.file_name().and_then(|s| s.to_str()) == Some(".env")
}

// `name` is lowercased below, so the `ends_with` extension checks are already
// case-insensitive; the lint's case-sensitivity warning does not apply.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn archive_kind(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if name.ends_with(".zip") {
        Some("zip")
    } else if name.ends_with(".7z") {
        Some("7z")
    } else if name.ends_with(".tar")
        || name.ends_with(".tar.gz")
        || name.ends_with(".tgz")
        || name.ends_with(".tar.xz")
        || name.ends_with(".txz")
    {
        Some("tar")
    } else {
        None
    }
}

fn ctf_challenge_recon(challenge_dir: &Path, max_files: usize) -> String {
    let files_dir = challenge_dir.join("files");
    let mut out = String::new();
    let mut files = collect_regular_files(&files_dir, 1_000);
    files.sort_by_key(|path| {
        (
            recon_file_priority(path),
            path.to_string_lossy().to_string(),
        )
    });
    files.truncate(max_files.clamp(1, 300));

    out.push_str("=== files ===\n");
    if files.is_empty() {
        out.push_str("./files/ is empty\n");
        return out;
    }

    for path in &files {
        let rel = path.strip_prefix(challenge_dir).unwrap_or(path);
        let size = path.metadata().map_or(0, |m| m.len());
        out.push_str(&format!("- ./{} ({} bytes)\n", rel.display(), size));
    }

    out.push_str("\n=== file types ===\n");
    for path in &files {
        let rel = path.strip_prefix(challenge_dir).unwrap_or(path);
        if let Some(arg) = relative_files(rel) {
            out.push_str(&sh_in_dir(
                challenge_dir,
                &format!("file {}", shell_quote(&arg)),
            ));
        }
    }

    out.push_str("\n=== app-level mobile focus ===\n");
    for path in &files {
        if recon_file_priority(path) > 2 {
            continue;
        }
        let rel = path.strip_prefix(challenge_dir).unwrap_or(path);
        let Some(arg) = relative_files(rel) else {
            continue;
        };
        let quoted = shell_quote(&arg);
        out.push_str(&format!("--- {arg} ---\n"));
        out.push_str(&sh_in_dir(challenge_dir, &format!("file {quoted}")));
        let focus_hits = sh_in_dir(
            challenge_dir,
            &format!(
                "(grep -aInE 'FLAG|BKSEC|flag|secret|token|password|admin|http|api|key|verify|check|decode|base64|xor|crypto' {quoted} 2>/dev/null || strings -a -n 5 {quoted} 2>/dev/null | grep -Ei 'FLAG|BKSEC|flag|secret|token|password|admin|http|api|key|verify|check|decode|base64|xor|crypto') | head -120"
            ),
        );
        if !focus_hits.trim().is_empty() {
            out.push_str(&focus_hits);
            out.push('\n');
        }
    }

    out.push_str("\n=== archive listings ===\n");
    for path in &files {
        let rel = path.strip_prefix(challenge_dir).unwrap_or(path);
        let Some(kind) = archive_kind(rel) else {
            continue;
        };
        let Some(arg) = relative_files(rel) else {
            continue;
        };
        out.push_str(&format!("--- {arg} ({kind}) ---\n"));
        let quoted = shell_quote(&arg);
        let listing = match kind {
            "zip" => sh_in_dir(
                challenge_dir,
                &format!("unzip -l {quoted} 2>&1 | head -120"),
            ),
            "7z" => sh_in_dir(challenge_dir, &format!("7z l {quoted} 2>&1 | head -160")),
            "tar" => sh_in_dir(challenge_dir, &format!("tar -tf {quoted} 2>&1 | head -120")),
            _ => String::new(),
        };
        out.push_str(&listing);
        out.push('\n');
    }

    out.push_str("\n=== interesting strings / grep hits ===\n");
    let interesting = "(flag|ctf|secret|password|passwd|token|jwt|jwks|hmac|key|admin|debug|api|http|BKSEC|hacktheon|picoCTF|HTB|ENO)";
    for path in &files {
        if noisy_vendor_framework(path) && recon_file_priority(path) > 2 {
            continue;
        }
        let rel = path.strip_prefix(challenge_dir).unwrap_or(path);
        let Some(arg) = relative_files(rel) else {
            continue;
        };
        let quoted = shell_quote(&arg);
        let hits = if likely_text_file(path, path.metadata().map_or(0, |m| m.len())) {
            sh_in_dir(
                challenge_dir,
                &format!(
                    "grep -InE {pat} {file} 2>/dev/null | head -40",
                    pat = shell_quote(interesting),
                    file = quoted,
                ),
            )
        } else {
            sh_in_dir(
                challenge_dir,
                &format!(
                    "strings -a -n 5 {file} 2>/dev/null | grep -Ei {pat} | head -40",
                    file = quoted,
                    pat = shell_quote(interesting),
                ),
            )
        };
        if !hits.trim().is_empty() {
            out.push_str(&format!("--- {arg} ---\n{hits}\n"));
        }
    }

    out.push_str("\n=== small text previews ===\n");
    for path in &files {
        let size = path.metadata().map_or(0, |m| m.len());
        if !likely_text_file(path, size) {
            continue;
        }
        let rel = path.strip_prefix(challenge_dir).unwrap_or(path);
        let Some(arg) = relative_files(rel) else {
            continue;
        };
        out.push_str(&format!("--- {arg} ---\n"));
        out.push_str(&sh_in_dir(
            challenge_dir,
            &format!("sed -n '1,120p' {} 2>/dev/null", shell_quote(&arg)),
        ));
        out.push('\n');
    }

    truncate_output_lines(&out, 400, 40_000)
}

fn safe_tmp_extract_dir(path: &str, requested: Option<&str>) -> Result<String, String> {
    if let Some(dir) = requested {
        let clean = dir.trim();
        if clean.starts_with("./tmp/") || clean.starts_with("tmp/") {
            return Ok(clean.trim_start_matches("./").to_string());
        }
        return Err("output_dir must be under ./tmp/".to_string());
    }

    let stem = Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("archive")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    Ok(format!("tmp/extract/{stem}"))
}

fn ctf_extract_archive(
    challenge_dir: &Path,
    path: &str,
    output_dir: Option<&str>,
) -> Result<String, String> {
    let rel_path = path.trim_start_matches("./");
    if !rel_path.starts_with("files/") {
        return Err("archive path must point under ./files/".to_string());
    }
    let kind = archive_kind(Path::new(rel_path))
        .ok_or_else(|| "unsupported archive type; expected .zip, .7z, or .tar*".to_string())?;
    let out_dir = safe_tmp_extract_dir(rel_path, output_dir)?;
    fs::create_dir_all(challenge_dir.join(&out_dir)).map_err(|e| e.to_string())?;

    let archive = shell_quote(&format!("./{rel_path}"));
    let dest = shell_quote(&format!("./{out_dir}"));
    let result = match kind {
        "zip" => sh_in_dir(
            challenge_dir,
            &format!("unzip -q -o {archive} -d {dest} 2>&1"),
        ),
        "7z" => sh_in_dir(challenge_dir, &format!("7z x -y -o{dest} {archive} 2>&1")),
        "tar" => sh_in_dir(challenge_dir, &format!("tar -xf {archive} -C {dest} 2>&1")),
        _ => unreachable!(),
    };
    let listing = sh_in_dir(
        challenge_dir,
        &format!("find {dest} -maxdepth 3 -type f -print | sort | head -200"),
    );
    Ok(format!(
        "Extracted {path} to ./{out_dir}\n{result}\n=== extracted files ===\n{listing}"
    ))
}

/// All-in-one binary fingerprint: file + checksec + strings + ldd + arch.
fn ctf_binary_recon(path: &str) -> String {
    // Sanitise path for shell use
    let esc = path.replace('\'', "'\\''");
    let mut out = String::new();

    let file_out = sh(&format!("file '{esc}'"));
    out.push_str(&format!("=== file ===\n{file_out}\n"));

    let checksec = sh(&format!(
        "checksec --file='{esc}' 2>/dev/null || checksec --binary='{esc}' 2>/dev/null"
    ));
    if checksec.trim().is_empty() {
        // Fallback: read ELF flags manually with readelf
        let readelf = sh(&format!(
            "readelf -W -d '{esc}' 2>/dev/null | grep -E 'BIND_NOW|RELRO|FLAGS'"
        ));
        let header = sh(&format!(
            "readelf -h '{esc}' 2>/dev/null | grep -E 'Class|Machine|Type'"
        ));
        out.push_str(&format!(
            "=== readelf (no checksec) ===\n{header}{readelf}\n"
        ));
    } else {
        out.push_str(&format!("=== checksec ===\n{checksec}\n"));
    }

    out.push_str(&format!(
        "=== ldd ===\n{}\n",
        sh(&format!(
            "ldd '{esc}' 2>/dev/null || echo '(not dynamic ELF)'"
        ))
    ));

    let strings = sh(&format!("strings -n8 '{esc}' 2>/dev/null | head -60"));
    out.push_str(&format!("=== strings (first 60) ===\n{strings}\n"));

    if file_out.contains("ELF") {
        // Imports expose libc calls (strcmp/memcmp/system/...) that reveal the
        // logic even when the binary is stripped of its own symbols.
        let imports = sh(&format!("rabin2 -i '{esc}' 2>/dev/null | head -40"));
        if !imports.trim().is_empty() {
            out.push_str(&format!("=== imports (rabin2) ===\n{imports}\n"));
        }

        // radare2 auto-analysis. On a stripped binary r2 often cannot label
        // `main`, so first recover the function list, then disassemble the entry
        // stub plus the largest recovered function (the heuristic "main": the
        // real logic is almost always the biggest non-library function).
        // `timeout` guards against analysis hangs on large/obfuscated binaries.
        let afl = sh(&format!(
            "timeout 60 r2 -e scr.color=0 -A -q -c afl '{esc}' 2>/dev/null"
        ));
        // afl columns: <addr> <nbbs> <size> [-> <realsz>] <name>
        let biggest = afl
            .lines()
            .filter_map(|l| {
                let mut it = l.split_whitespace();
                let addr = it.next()?;
                let _nbbs = it.next()?;
                let size: u64 = it.next()?.parse().ok()?;
                addr.starts_with("0x").then(|| (size, addr.to_string()))
            })
            .max_by_key(|(size, _)| *size)
            .map(|(_, addr)| addr);
        let target = biggest.as_deref().unwrap_or("entry0");
        let disasm = sh(&format!(
            "timeout 60 r2 -e scr.color=0 -A -q -c \
             '?e ==== disasm main (if symbolised) ====; pdf @ main; \
              ?e ==== disasm entry0 ====; pdf @ entry0; \
              ?e ==== disasm largest fn ({target}, likely main) ====; pdf @ {target}' \
             '{esc}' 2>/dev/null | head -400"
        ));
        if afl.trim().is_empty() && disasm.trim().is_empty() {
            out.push_str(
                "=== disasm ===\n(radare2 produced no output — install r2, or use \
                 the `decompile` tool / `objdump -d` via bash)\n",
            );
        } else {
            if !disasm.trim().is_empty() {
                out.push_str(&format!(
                    "=== r2 disasm (entry0 + largest fn) ===\n{disasm}\n"
                ));
            }
            let afl_preview = afl.lines().take(50).collect::<Vec<_>>().join("\n");
            out.push_str(&format!(
                "=== functions (afl; use `decompile <name>` to dig in) ===\n{afl_preview}\n"
            ));
        }
    } else {
        // Non-ELF inputs (firmware blobs, packed containers, raw `data` files):
        // a hexdump exposes magic bytes, offsets, and embedded structure that
        // `file`/`strings` alone miss.
        let hexdump = sh(&format!("xxd '{esc}' 2>/dev/null | head -40"));
        if !hexdump.trim().is_empty() {
            out.push_str(&format!("=== hexdump (first 40 lines) ===\n{hexdump}\n"));
        }
    }

    out.trim_end().to_string()
}

/// Decompile a function using radare2 (r2). Falls back to objdump disassembly.
fn ctf_decompile(path: &str, function: &str) -> Result<String, String> {
    let esc = path.replace('\'', "'\\''");
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
            .map_or("", str::trim)
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
    let Some(path) = load_sound_path() else {
        return;
    };

    // (program, args-before-file)
    let players: &[(&str, &[&str])] = &[
        ("ffplay", &["-nodisp", "-autoexit", "-loglevel", "quiet"]),
        ("paplay", &[]),
        ("cvlc", &["--play-and-exit", "--quiet", "--no-interact"]),
        ("aplay", &["-q"]),
        ("mpv", &["--no-video", "--really-quiet"]),
    ];

    for (prog, pre_args) in players {
        let mut cmd = std::process::Command::new(prog);
        cmd.args(*pre_args)
            .arg(&path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // Detach from ctf's process group so it can't receive SIGTTOU back.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        // Fire-and-forget; on failure, try the next opener.
        if cmd.spawn().is_ok() {
            return;
        }
    }
}

fn send_desktop_notification(challenge: &str, body: &str) {
    let mut cmd = std::process::Command::new("notify-send");
    cmd.args([
        "--app-name=CTF Solver",
        "--icon=utilities-terminal",
        "--urgency=normal",
        &format!("CTF · {challenge}"),
        body,
    ])
    .stdin(std::process::Stdio::null());
    // Detach from ctf's process group so terminal ownership stays with ctf.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let result = cmd.output();
    match result {
        Ok(out) if out.status.success() => {
            eprintln!("{C_DIM}[notify] sent ok{C_RESET}");
        }
        Ok(out) => {
            eprintln!(
                "{C_STONE}[notify] exit {:?}: {}{C_RESET}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) => {
            eprintln!("{C_ROSE}[notify] failed to spawn notify-send: {e}{C_RESET}");
        }
    }
}

fn format_ctf_tool_call(name: &str, input: &str) -> String {
    let parsed: Value = serde_json::from_str(input).unwrap_or(Value::String(input.to_string()));
    match name {
        "bash" => {
            let cmd = parsed
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or(input);
            let first_line = cmd.lines().next().unwrap_or(cmd).trim();
            let tw = crossterm::terminal::size()
                .map(|(w, _)| w as usize)
                .unwrap_or(80);
            let max_len = tw.saturating_sub(12);
            let display = if first_line.len() > max_len {
                format!("{}…", &first_line[..max_len])
            } else {
                first_line.to_string()
            };
            format!("{C_TEAL}●{C_RESET} {C_BOLD}Bash{C_RESET}({display})")
        }
        "read_file" => {
            let path = parsed.get("path").and_then(Value::as_str).unwrap_or("?");
            format!("{C_TEAL}📄 read_file{C_RESET} {C_DIM}{path}{C_RESET}")
        }
        "write_file" => {
            let path = parsed.get("path").and_then(Value::as_str).unwrap_or("?");
            format!("{C_SAGE}✏️  write_file{C_RESET} {C_DIM}{path}{C_RESET}")
        }
        "glob_search" => {
            let pat = parsed.get("pattern").and_then(Value::as_str).unwrap_or("?");
            format!("{C_ASH}🔎 glob_search{C_RESET} {C_DIM}{pat}{C_RESET}")
        }
        "grep_search" => {
            let pat = parsed.get("pattern").and_then(Value::as_str).unwrap_or("?");
            format!("{C_ASH}🔍 grep_search{C_RESET} {C_DIM}{pat}{C_RESET}")
        }
        "challenge_recon" => {
            format!("{C_STONE}🧭 challenge_recon{C_RESET}")
        }
        "extract_archive" => {
            let path = parsed.get("path").and_then(Value::as_str).unwrap_or("?");
            format!("{C_STONE}📦 extract_archive{C_RESET} {C_DIM}{path}{C_RESET}")
        }
        "binary_recon" => {
            let path = parsed.get("path").and_then(Value::as_str).unwrap_or("?");
            format!("{C_STONE}🔬 binary_recon{C_RESET} {C_DIM}{path}{C_RESET}")
        }
        "decompile" => {
            let path = parsed.get("path").and_then(Value::as_str).unwrap_or("?");
            let func = parsed
                .get("function")
                .and_then(Value::as_str)
                .unwrap_or("main");
            format!("{C_INK}🧩 decompile{C_RESET} {C_DIM}{path}:{func}{C_RESET}")
        }
        "REPL" => {
            let lang = parsed
                .get("language")
                .and_then(Value::as_str)
                .unwrap_or("?");
            let code = parsed.get("code").and_then(Value::as_str).unwrap_or("");
            format!(
                "{C_SAGE}🐍 REPL[{lang}]{C_RESET} {C_DIM}{}{C_RESET}",
                code.lines().next().unwrap_or("")
            )
        }
        "WebFetch" => {
            let url = parsed.get("url").and_then(Value::as_str).unwrap_or("?");
            format!("{C_TEAL}🌐 WebFetch{C_RESET} {C_DIM}{url}{C_RESET}")
        }
        _ => format!("\x1b[2m[{name}]\x1b[0m"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FallbackToolCall {
    name: String,
    input: String,
}

fn fallback_tool_calls_from_text(text: &str) -> Vec<FallbackToolCall> {
    let mut calls = Vec::new();

    calls.extend(tagged_json_tool_calls(text, "tool"));
    calls.extend(tagged_json_tool_calls(text, "tool_call"));
    calls.extend(tool_code_parameter_arg_calls(text));
    calls.extend(html_comment_tool_calls(text));
    calls.extend(name_parameters_tool_calls(text));
    calls.extend(run_directive_tool_calls(text));
    calls.extend(invoke_tool_calls(text));
    calls.extend(fenced_tool_calls(text));
    calls.extend(natural_language_tool_calls(text));

    dedupe_fallback_tool_calls(calls)
}

/// Known CTF tool names — used to validate fallback-parsed calls so a malformed
/// blob can't invent a bogus tool name that just wastes a turn on an error.
fn is_known_ctf_tool(name: &str) -> bool {
    matches!(
        name,
        "challenge_recon"
            | "binary_recon"
            | "extract_archive"
            | "grep_search"
            | "glob_search"
            | "read_file"
            | "write_file"
            | "decompile"
            | "bash"
            | "REPL"
            | "kb_search"
            | "kb_read"
            | "kb_add"
    )
}

/// Extract the first balanced `{...}` substring (handles nested braces and
/// braces inside double-quoted strings). Returns the object including braces.
fn extract_balanced_braces(text: &str) -> Option<String> {
    let start = text.find('{')?;
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_str {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[start..=i].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// Some models hide tool calls inside an HTML comment as an action envelope,
/// e.g. `<!-- {"action":"call_tool","tool":"bash","arguments":{...}} -->`.
fn html_comment_tool_calls(text: &str) -> Vec<FallbackToolCall> {
    let mut calls = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("<!--") {
        let after = &rest[start + "<!--".len()..];
        let Some(end) = after.find("-->") else {
            break;
        };
        let body = after[..end].trim();
        rest = &after[end + "-->".len()..];
        if let Some(call) = parse_json_tool_call(body) {
            if is_known_ctf_tool(&call.name) {
                calls.push(call);
            }
        }
    }
    calls
}

/// Parse `name="grep_search", parameters={...}` style bodies (seen inside
/// `<tool_code>` blocks emitted by some models) — not valid JSON on their own,
/// so the two fields are pulled out directly.
fn name_parameters_tool_calls(text: &str) -> Vec<FallbackToolCall> {
    let mut calls = Vec::new();
    let norm = normalize_smart_quotes(text);
    let name_re = Regex::new(r#"name\s*=\s*"([a-zA-Z_]+)""#).expect("valid name= regex");
    for caps in name_re.captures_iter(&norm) {
        let whole = caps.get(0).expect("match 0");
        let name = caps.get(1).expect("group 1").as_str().to_string();
        if !is_known_ctf_tool(&name) {
            continue;
        }
        let after = &norm[whole.end()..];
        let mut input = String::from("{}");
        if let Some(pidx) = after.find("parameters") {
            if let Some(obj) = extract_balanced_braces(&after[pidx..]) {
                if let Some(value) = parse_loose_json_value(&obj) {
                    input = normalize_tool_arguments(value);
                }
            }
        }
        if name == "challenge_recon" {
            if input == "{}" {
                input = json!({ "max_files": 120 }).to_string();
            }
        } else if input == "{}" {
            // Arg-taking tools with no recovered parameters would just error.
            continue;
        }
        calls.push(FallbackToolCall { name, input });
    }
    calls
}

fn natural_language_tool_calls(text: &str) -> Vec<FallbackToolCall> {
    let mut calls = Vec::new();
    let lower = text.to_ascii_lowercase();

    let wants_challenge_recon =
        Regex::new(r"(?i)\b(?:call|invoke|use|run|execute)\s+(?:the\s+)?`?challenge_recon`?")
            .expect("valid challenge_recon intent regex");
    if wants_challenge_recon.is_match(text) {
        calls.push(FallbackToolCall {
            name: "challenge_recon".to_string(),
            input: json!({ "max_files": 120 }).to_string(),
        });
    }

    let extract_intent =
        Regex::new(r"(?i)\b(?:call|invoke|use|run|execute)\s+(?:the\s+)?`?extract_archive`?")
            .expect("valid extract intent regex");
    if extract_intent.is_match(text) || lower.contains("extract_archive") {
        let path_re = Regex::new(r#"(?i)(?:path\s*[:=]\s*)?`?(\./files/[^\s`'"<>;,)]*)`?"#)
            .expect("valid archive path regex");
        if let Some(caps) = path_re.captures(text) {
            if let Some(path) = caps.get(1).map(|m| m.as_str()) {
                let path = path.trim_end_matches(['.', ':']);
                if archive_kind(Path::new(path.trim_start_matches("./"))).is_some() {
                    calls.push(FallbackToolCall {
                        name: "extract_archive".to_string(),
                        input: json!({ "path": path }).to_string(),
                    });
                }
            }
        }
    }

    let binary_recon_intent =
        Regex::new(r"(?i)\b(?:call|invoke|use|run|execute)\s+(?:the\s+)?`?binary_recon`?")
            .expect("valid binary_recon intent regex");
    if binary_recon_intent.is_match(text) {
        let path_re = Regex::new(r#"`?(\./(?:files|tmp)/[^\s`'"<>;,)]*)`?"#)
            .expect("valid binary path regex");
        if let Some(caps) = path_re.captures(text) {
            if let Some(path) = caps.get(1).map(|m| m.as_str()) {
                calls.push(FallbackToolCall {
                    name: "binary_recon".to_string(),
                    input: json!({ "path": path }).to_string(),
                });
            }
        }
    }

    calls
}

fn tagged_json_tool_calls(text: &str, tag: &str) -> Vec<FallbackToolCall> {
    let mut calls = Vec::new();
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut rest = text;

    while let Some(start) = rest.find(&open) {
        let after_open = &rest[start + open.len()..];
        let Some(end) = after_open.find(&close) else {
            break;
        };
        let raw = after_open[..end].trim();
        if let Some(call) = parse_json_tool_call(raw) {
            calls.push(call);
        }
        rest = &after_open[end + close.len()..];
    }

    calls
}

fn invoke_tool_calls(text: &str) -> Vec<FallbackToolCall> {
    let invoke_re =
        Regex::new(r#"(?s)<invoke\s+name=["']([^"']+)["'][^>]*>(.*?)</(?:invoke|function)>"#)
            .expect("valid invoke regex");
    let mut calls = Vec::new();

    for cap in invoke_re.captures_iter(text) {
        let name = cap.get(1).map_or("", |m| m.as_str()).trim();
        let body = cap.get(2).map_or("", |m| m.as_str()).trim();
        if body.is_empty() || body.len() > CTF_MAX_FALLBACK_CODE_BYTES {
            continue;
        }
        match name {
            "bash" => calls.push(FallbackToolCall {
                name: "bash".to_string(),
                input: json!({ "command": body, "timeout": 120 }).to_string(),
            }),
            "challenge_recon" => calls.push(FallbackToolCall {
                name: "challenge_recon".to_string(),
                input: json!({ "max_files": 120 }).to_string(),
            }),
            "extract_archive" => {
                let params = parse_invoke_parameter_tags(body);
                let path = parse_assignment_arg(body, "path")
                    .or_else(|| params.get("path").cloned())
                    .or_else(|| parse_first_path_like(body, "./files/"));
                if let Some(path) = path {
                    let output_dir = parse_assignment_arg(body, "output_dir");
                    let input = match output_dir {
                        Some(output_dir) => {
                            json!({ "path": path, "output_dir": output_dir })
                        }
                        None => json!({ "path": path }),
                    };
                    calls.push(FallbackToolCall {
                        name: "extract_archive".to_string(),
                        input: input.to_string(),
                    });
                }
            }
            "grep_search" => {
                let params = parse_invoke_parameter_tags(body);
                let pattern = params
                    .get("pattern")
                    .cloned()
                    .or_else(|| parse_assignment_arg(body, "pattern"))
                    .or_else(|| parse_named_string_arg(body, "pattern"));
                if let Some(pattern) = pattern {
                    let pattern = normalize_grepish_parameter_pattern(&pattern);
                    let path = params
                        .get("path")
                        .cloned()
                        .or_else(|| {
                            params
                                .get("glob")
                                .filter(|value| value.as_str() != "true")
                                .cloned()
                        })
                        .or_else(|| parse_assignment_arg(body, "path"))
                        .or_else(|| parse_named_string_arg(body, "path"))
                        .or_else(|| parse_first_path_like(body, "./"))
                        .unwrap_or_else(|| ".".to_string());
                    calls.push(FallbackToolCall {
                        name: "grep_search".to_string(),
                        input: json!({ "pattern": pattern, "path": path }).to_string(),
                    });
                }
            }
            "glob_search" => {
                let params = parse_invoke_parameter_tags(body);
                let pattern = params
                    .get("pattern")
                    .cloned()
                    .or_else(|| parse_assignment_arg(body, "pattern"))
                    .or_else(|| parse_named_string_arg(body, "pattern"));
                if let Some(pattern) = pattern {
                    let path = params
                        .get("path")
                        .cloned()
                        .or_else(|| {
                            params
                                .get("glob")
                                .filter(|value| value.as_str() != "true")
                                .cloned()
                        })
                        .or_else(|| parse_assignment_arg(body, "path"))
                        .or_else(|| parse_named_string_arg(body, "path"))
                        .or_else(|| parse_first_path_like(body, "./"))
                        .unwrap_or_else(|| ".".to_string());
                    calls.push(FallbackToolCall {
                        name: "glob_search".to_string(),
                        input: json!({ "pattern": pattern, "path": path }).to_string(),
                    });
                }
            }
            "read_file" => {
                let params = parse_invoke_parameter_tags(body);
                if let Some(path) = parse_assignment_arg(body, "path")
                    .or_else(|| parse_first_path_like(body, "./"))
                    .or_else(|| params.get("path").cloned())
                {
                    calls.push(FallbackToolCall {
                        name: "read_file".to_string(),
                        input: json!({ "path": path }).to_string(),
                    });
                }
            }
            "binary_recon" => {
                let params = parse_invoke_parameter_tags(body);
                if let Some(path) = parse_assignment_arg(body, "path")
                    .or_else(|| parse_first_path_like(body, "./"))
                    .or_else(|| params.get("path").cloned())
                {
                    calls.push(FallbackToolCall {
                        name: "binary_recon".to_string(),
                        input: json!({ "path": path }).to_string(),
                    });
                }
            }
            _ => {}
        }
    }

    calls
}

fn parse_invoke_parameter_tags(text: &str) -> std::collections::HashMap<String, String> {
    let parameter_re =
        Regex::new(r"(?s)<parameter=([A-Za-z_][A-Za-z0-9_-]*)>\s*(.*?)\s*</parameter>")
            .expect("valid parameter tag regex");
    parameter_re
        .captures_iter(text)
        .filter_map(|cap| {
            let key = cap.get(1)?.as_str().trim().to_ascii_lowercase();
            let value = cap.get(2)?.as_str().trim().to_string();
            (!value.is_empty()).then_some((key, normalize_shell_markup(&value)))
        })
        .collect()
}

fn normalize_grepish_parameter_pattern(pattern: &str) -> String {
    let trimmed = pattern.trim();
    let fixed_literal = Regex::new(r#"^-F\s+(?:"([^"]+)"|'([^']+)'|(\S+))(?:\s+-i)?$"#)
        .expect("valid fixed grep pattern regex");
    if let Some(caps) = fixed_literal.captures(trimmed) {
        let literal = (1..=3)
            .find_map(|idx| caps.get(idx).map(|m| m.as_str()))
            .unwrap_or(trimmed);
        let escaped = regex::escape(literal);
        if trimmed.contains("-i") {
            format!("(?i){escaped}")
        } else {
            escaped
        }
    } else {
        trimmed.to_string()
    }
}

fn parse_assignment_arg(text: &str, name: &str) -> Option<String> {
    let re = Regex::new(&format!(
        r#"(?i)\b{}\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s<>]+))"#,
        regex::escape(name)
    ))
    .ok()?;
    let caps = re.captures(text)?;
    for idx in 1..=3 {
        if let Some(value) = caps.get(idx).map(|m| m.as_str()) {
            return Some(value.trim_end_matches(['.', ',', ';']).to_string());
        }
    }
    None
}

fn parse_first_path_like(text: &str, prefix: &str) -> Option<String> {
    let re = Regex::new(&format!(r#"`?({}[^\s`'"<>;,)]*)`?"#, regex::escape(prefix))).ok()?;
    let caps = re.captures(text)?;
    caps.get(1)
        .map(|m| m.as_str().trim_end_matches(['.', ',', ';']).to_string())
}

fn fenced_tool_calls(text: &str) -> Vec<FallbackToolCall> {
    let fence_re =
        Regex::new(r"(?s)```([A-Za-z0-9_-]*)\s*\n(.*?)```").expect("valid fenced-code regex");
    let mut calls = Vec::new();

    for cap in fence_re.captures_iter(text) {
        let language = cap
            .get(1)
            .map_or("", |m| m.as_str())
            .trim()
            .to_ascii_lowercase();
        let body = cap.get(2).map_or("", |m| m.as_str()).trim();
        if body.is_empty() {
            continue;
        }
        if body.len() > CTF_MAX_FALLBACK_CODE_BYTES {
            continue;
        }
        if contains_placeholder_code(body) {
            continue;
        }

        match language.as_str() {
            "json" => {
                if let Some(call) = parse_json_tool_call(body) {
                    calls.push(call);
                }
            }
            "bash" | "sh" | "shell" | "zsh" => {
                calls.extend(shell_fence_tool_calls(body));
            }
            "python" | "py" => {
                calls.push(repl_tool_call("python", body));
            }
            _ => {}
        }
    }

    calls
}

fn contains_placeholder_code(body: &str) -> bool {
    body.contains("= ...")
        || body.contains("... #")
        || body.contains("<value>")
        || body.contains("<flag>")
        || body.contains("TODO")
}

fn parse_json_tool_call(raw: &str) -> Option<FallbackToolCall> {
    let cleaned = raw
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();
    let value: Value = serde_json::from_str(cleaned).ok()?;

    // Accept `name`, or the `tool` key used by `{"action":"call_tool","tool":…}`
    // envelopes some models emit.
    if let Some(name) = value
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| value.get("tool").and_then(Value::as_str))
    {
        let args = value
            .get("arguments")
            .or_else(|| value.get("parameters"))
            .or_else(|| value.get("input"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        return Some(FallbackToolCall {
            name: name.to_string(),
            input: normalize_tool_arguments(args),
        });
    }

    let function = value.get("function")?;
    let name = function.get("name").and_then(Value::as_str)?;
    let args = function
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    Some(FallbackToolCall {
        name: name.to_string(),
        input: normalize_tool_arguments(args),
    })
}

fn run_directive_tool_calls(text: &str) -> Vec<FallbackToolCall> {
    let mut calls = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let Some(raw_command) = trimmed.strip_prefix("$run ") else {
            continue;
        };
        let command = normalize_shell_markup(raw_command).trim().to_string();
        if command.is_empty() || command.len() > CTF_MAX_FALLBACK_CODE_BYTES {
            continue;
        }
        if let Some(call) = command_tool_call(&command) {
            calls.push(call);
        } else {
            calls.push(FallbackToolCall {
                name: "bash".to_string(),
                input: json!({ "command": command, "timeout": 120 }).to_string(),
            });
        }
    }
    calls
}

fn command_tool_call(command: &str) -> Option<FallbackToolCall> {
    let mut parts = command.split_whitespace();
    let name = parts.next()?;
    match name {
        "glob_search" => {
            let pattern = parse_assignment_arg(command, "pattern")
                .or_else(|| parse_named_string_arg(command, "pattern"))?;
            let path = parse_assignment_arg(command, "path")
                .or_else(|| parse_named_string_arg(command, "path"))
                .or_else(|| parse_first_path_like(command, "./"))
                .or_else(|| parse_first_shell_path(command))
                .unwrap_or_else(|| ".".to_string());
            Some(FallbackToolCall {
                name: "glob_search".to_string(),
                input: json!({ "pattern": pattern, "path": path }).to_string(),
            })
        }
        "grep_search" => {
            let pattern = parse_assignment_arg(command, "pattern")
                .or_else(|| parse_named_string_arg(command, "pattern"))?;
            let path = parse_assignment_arg(command, "path")
                .or_else(|| parse_named_string_arg(command, "path"))
                .or_else(|| parse_first_path_like(command, "./"))
                .or_else(|| parse_first_shell_path(command))
                .unwrap_or_else(|| ".".to_string());
            Some(FallbackToolCall {
                name: "grep_search".to_string(),
                input: json!({ "pattern": pattern, "path": path }).to_string(),
            })
        }
        "challenge_recon" => Some(FallbackToolCall {
            name: "challenge_recon".to_string(),
            input: json!({ "max_files": 120 }).to_string(),
        }),
        "extract_archive" => {
            let path = parse_assignment_arg(command, "path")
                .or_else(|| parse_named_string_arg(command, "path"))
                .or_else(|| parse_first_path_like(command, "./files/"))?;
            Some(FallbackToolCall {
                name: "extract_archive".to_string(),
                input: json!({ "path": path }).to_string(),
            })
        }
        "binary_recon" => {
            let path = parse_assignment_arg(command, "path")
                .or_else(|| parse_named_string_arg(command, "path"))
                .or_else(|| parse_first_path_like(command, "./"))?;
            Some(FallbackToolCall {
                name: "binary_recon".to_string(),
                input: json!({ "path": path }).to_string(),
            })
        }
        _ => None,
    }
}

fn normalize_shell_markup(text: &str) -> String {
    normalize_smart_quotes(text)
        .chars()
        .map(|ch| match ch {
            '–' | '—' | '−' => '-',
            other => other,
        })
        .collect()
}

fn parse_first_shell_path(text: &str) -> Option<String> {
    text.split_whitespace()
        .map(|part| part.trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`' | ',' | ';')))
        .find(|part| part.starts_with("./") || part.starts_with("../") || part.starts_with('/'))
        .map(str::to_string)
}

fn tool_code_parameter_arg_calls(text: &str) -> Vec<FallbackToolCall> {
    let mut calls = Vec::new();
    let open = "<tool_code>";
    let close = "</tool_code>";
    let args_open = "<parameter_args>";
    let args_close = "</parameter_args>";
    let mut rest = text;

    while let Some(start) = rest.find(open) {
        let after_open = &rest[start + open.len()..];
        let Some(end) = after_open.find(close) else {
            break;
        };
        let name = after_open[..end].trim();
        let after_name = &after_open[end + close.len()..];
        let mut input = json!({}).to_string();

        if let Some(after_args_open) = after_name.trim_start().strip_prefix(args_open) {
            let raw_args = if let Some(args_end) = after_args_open.find(args_close) {
                &after_args_open[..args_end]
            } else {
                after_args_open.lines().next().unwrap_or("")
            };
            if let Some(value) = parse_loose_json_value(raw_args) {
                input = normalize_tool_arguments(value);
            }
        }

        match name {
            "challenge_recon" => {
                if input == "{}" {
                    input = json!({ "max_files": 120 }).to_string();
                }
                calls.push(FallbackToolCall {
                    name: "challenge_recon".to_string(),
                    input,
                });
            }
            "extract_archive" | "grep_search" | "glob_search" | "read_file" | "binary_recon"
            | "decompile" | "bash" => {
                if input != "{}" {
                    calls.push(FallbackToolCall {
                        name: name.to_string(),
                        input,
                    });
                }
            }
            _ => {}
        }

        rest = after_name;
    }

    calls
}

fn parse_loose_json_value(raw: &str) -> Option<Value> {
    let cleaned = normalize_smart_quotes(raw)
        .trim()
        .trim_end_matches(['`', ';'])
        .trim()
        .to_string();
    if cleaned.is_empty() {
        return None;
    }

    serde_json::from_str(&cleaned)
        .ok()
        .or_else(|| serde_json::from_str(&escape_invalid_json_string_escapes(&cleaned)).ok())
        .or_else(|| parse_loose_object_fields(&cleaned))
}

fn normalize_smart_quotes(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '“' | '”' | '„' | '‟' => '"',
            '‘' | '’' | '‚' | '‛' => '\'',
            other => other,
        })
        .collect()
}

fn escape_invalid_json_string_escapes(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    let mut in_string = false;

    while i < chars.len() {
        let ch = chars[i];
        if ch == '"' {
            in_string = !in_string;
            out.push(ch);
            i += 1;
            continue;
        }
        if in_string && ch == '\\' {
            out.push('\\');
            if let Some(next) = chars.get(i + 1) {
                if matches!(next, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' | 'u') {
                    out.push(*next);
                } else {
                    out.push('\\');
                    out.push(*next);
                }
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        out.push(ch);
        i += 1;
    }

    out
}

fn parse_loose_object_fields(cleaned: &str) -> Option<Value> {
    let mut object = serde_json::Map::new();
    for key in ["path", "pattern", "glob", "function", "command"] {
        if let Some(value) = loose_field_value(cleaned, key) {
            object.insert(key.to_string(), json!(value));
        }
    }
    (!object.is_empty()).then_some(Value::Object(object))
}

fn loose_field_value(text: &str, key: &str) -> Option<String> {
    let key = regex::escape(key);
    let key_re = Regex::new(&format!(r#"(?is)(?:"{key}"|'{key}'|{key})\s*:\s*"#)).ok()?;
    let mat = key_re.find(text)?;
    let rest = text[mat.end()..].trim_start();
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let value_start = quote.len_utf8();
    let rest_value = &rest[value_start..];

    for separator in [
        r#", "path""#,
        r#", "pattern""#,
        r#", "glob""#,
        r#", "function""#,
    ] {
        if let Some(end) = rest_value.find(separator) {
            return Some(rest_value[..end].trim_end_matches(quote).to_string());
        }
    }

    let mut escaped = false;
    let mut out = String::new();
    for ch in rest_value.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            out.push(ch);
            continue;
        }
        if ch == quote {
            return Some(out);
        }
        if ch == '}' {
            return Some(out.trim_end_matches(quote).to_string());
        }
        out.push(ch);
    }
    (!out.is_empty()).then_some(out.trim_end_matches(quote).to_string())
}

fn normalize_tool_arguments(args: Value) -> String {
    if let Some(raw) = args.as_str() {
        raw.to_string()
    } else {
        args.to_string()
    }
}

fn shell_fence_tool_calls(body: &str) -> Vec<FallbackToolCall> {
    let mut calls = Vec::new();
    let mut shell_lines = Vec::new();

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            shell_lines.push(line.to_string());
            continue;
        }
        if let Some(call) = pseudo_function_tool_call(trimmed) {
            flush_shell_lines(&mut shell_lines, &mut calls);
            calls.push(call);
        } else {
            shell_lines.push(line.to_string());
        }
    }

    flush_shell_lines(&mut shell_lines, &mut calls);
    calls
}

fn flush_shell_lines(shell_lines: &mut Vec<String>, calls: &mut Vec<FallbackToolCall>) {
    let command = shell_lines.join("\n").trim().to_string();
    shell_lines.clear();
    if command.is_empty() {
        return;
    }
    calls.push(FallbackToolCall {
        name: "bash".to_string(),
        input: json!({
            "command": command,
            "timeout": 120
        })
        .to_string(),
    });
}

fn pseudo_function_tool_call(line: &str) -> Option<FallbackToolCall> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    if close <= open {
        return None;
    }
    let name = line[..open].trim();
    let args = &line[open + 1..close];
    match name {
        "read_file" => {
            let path = parse_named_string_arg(args, "path")?;
            Some(FallbackToolCall {
                name: "read_file".to_string(),
                input: json!({ "path": path }).to_string(),
            })
        }
        "write_file" => {
            let path = parse_named_string_arg(args, "path")?;
            let content = parse_named_string_arg(args, "content").unwrap_or_default();
            Some(FallbackToolCall {
                name: "write_file".to_string(),
                input: json!({ "path": path, "content": content }).to_string(),
            })
        }
        "grep_search" => {
            let pattern = parse_named_string_arg(args, "pattern")?;
            let path = parse_named_string_arg(args, "path").unwrap_or_else(|| ".".to_string());
            Some(FallbackToolCall {
                name: "grep_search".to_string(),
                input: json!({ "pattern": pattern, "path": path }).to_string(),
            })
        }
        "glob_search" => {
            let pattern = parse_named_string_arg(args, "pattern")?;
            let path = parse_named_string_arg(args, "path").unwrap_or_else(|| ".".to_string());
            Some(FallbackToolCall {
                name: "glob_search".to_string(),
                input: json!({ "pattern": pattern, "path": path }).to_string(),
            })
        }
        "challenge_recon" => {
            let max_files = parse_named_u64_arg(args, "max_files").unwrap_or(120);
            Some(FallbackToolCall {
                name: "challenge_recon".to_string(),
                input: json!({ "max_files": max_files }).to_string(),
            })
        }
        "extract_archive" => {
            let path = parse_named_string_arg(args, "path")?;
            let output_dir = parse_named_string_arg(args, "output_dir");
            let input = match output_dir {
                Some(output_dir) => json!({ "path": path, "output_dir": output_dir }),
                None => json!({ "path": path }),
            };
            Some(FallbackToolCall {
                name: "extract_archive".to_string(),
                input: input.to_string(),
            })
        }
        "binary_recon" => {
            let path = parse_named_string_arg(args, "path")?;
            Some(FallbackToolCall {
                name: "binary_recon".to_string(),
                input: json!({ "path": path }).to_string(),
            })
        }
        "decompile" => {
            let path = parse_named_string_arg(args, "path")?;
            let function =
                parse_named_string_arg(args, "function").unwrap_or_else(|| "main".to_string());
            Some(FallbackToolCall {
                name: "decompile".to_string(),
                input: json!({ "path": path, "function": function }).to_string(),
            })
        }
        _ => None,
    }
}

fn parse_named_string_arg(args: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    let start = args.find(&needle)? + needle.len();
    let rest = args[start..].trim_start();
    let mut chars = rest.char_indices();
    let (_, quote) = chars.next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }

    let mut value = String::new();
    let mut escaped = false;
    for (_, ch) in chars {
        if escaped {
            value.push(match ch {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                other => other,
            });
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == quote {
            return Some(value);
        }
        value.push(ch);
    }

    None
}

fn parse_named_u64_arg(args: &str, name: &str) -> Option<u64> {
    let needle = format!("{name}=");
    let start = args.find(&needle)? + needle.len();
    let rest = args[start..].trim_start();
    let value = rest
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    value.parse().ok()
}

fn repl_tool_call(language: &str, code: &str) -> FallbackToolCall {
    FallbackToolCall {
        name: "REPL".to_string(),
        input: json!({
            "language": language,
            "code": code,
            "timeout_ms": 120_000
        })
        .to_string(),
    }
}

fn dedupe_fallback_tool_calls(calls: Vec<FallbackToolCall>) -> Vec<FallbackToolCall> {
    let mut deduped = Vec::new();
    for call in calls {
        if !deduped
            .iter()
            .any(|existing: &FallbackToolCall| existing == &call)
        {
            deduped.push(call);
        }
    }
    deduped
}

// ─── Persistent Python REPL ───────────────────────────────────────────────────
// Runs a long-lived python3 subprocess; variables and imports persist between calls.
// Communication: send code + "__END_CODE__" sentinel → read lines until "__REPL_DONE__".

const PYTHON_REPL_SERVER: &str = r"import sys, traceback
sys.stderr = sys.stdout
ns = {}
while True:
    lines = []
    for raw in sys.stdin:
        if raw.rstrip('\n') == '__END_CODE__':
            break
        lines.append(raw)
    code = ''.join(lines)
    if code.strip():
        try:
            exec(compile(code, '<repl>', 'exec'), ns)
        except SystemExit:
            break
        except BaseException:
            traceback.print_exc()
    sys.stdout.write('__REPL_DONE__\n')
    sys.stdout.flush()
";

struct PythonRepl {
    child: std::process::Child,
    stdin: io::BufWriter<std::process::ChildStdin>,
    rx: mpsc::Receiver<String>,
}

impl PythonRepl {
    fn start() -> Result<Self, String> {
        let work_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let script = work_dir.join("tmp/_ctf_repl.py");
        fs::write(&script, PYTHON_REPL_SERVER)
            .map_err(|e| format!("REPL: failed to write server script: {e}"))?;

        let mut cmd = std::process::Command::new("python3");
        cmd.arg("-u")
            .arg(&script)
            .current_dir(&work_dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("REPL: python3 failed to start: {e}"))?;

        let stdin = io::BufWriter::new(child.stdin.take().unwrap());
        let child_stdout = child.stdout.take().unwrap();

        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            use std::io::BufRead;
            let mut reader = io::BufReader::new(child_stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if tx.send(line.clone()).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self { child, stdin, rx })
    }

    /// Run `code` in the persistent REPL, streaming output live in a panel
    /// (like the bash tool). If no new output arrives for `timeout_ms`, the
    /// command is treated as stuck/hung and an error is returned to the agent
    /// so it knows the run didn't finish cleanly.
    fn execute(&mut self, code: &str, timeout_ms: u64) -> Result<String, String> {
        use std::time::{Duration, Instant};

        write!(self.stdin, "{code}\n__END_CODE__\n").map_err(|e| format!("REPL write: {e}"))?;
        self.stdin.flush().map_err(|e| format!("REPL flush: {e}"))?;

        let idle_timeout = Duration::from_millis(timeout_ms);
        let start = Instant::now();
        let mut last_activity = start;
        let mut output = String::new();
        let mut all_lines: Vec<String> = Vec::new();

        let is_tty = crossterm::terminal::size().is_ok();
        let max_visible = if verbose_output().load(Ordering::Relaxed) {
            usize::MAX
        } else {
            12
        };
        let mut stdout = io::stdout();
        let mut panel_rows: u16 = 0;
        let mut done = false;
        let mut timed_out = false;
        let mut interrupted = false;

        *running_cmd_pid().lock().unwrap() = Some(self.child.id());
        cmd_interrupted().store(false, Ordering::Relaxed);

        loop {
            match self.rx.recv_timeout(Duration::from_millis(80)) {
                Ok(line) => {
                    last_activity = Instant::now();
                    if line.trim_end_matches('\n') == "__REPL_DONE__" {
                        done = true;
                    } else {
                        if !is_tty {
                            let _ = write!(stdout, "{line}");
                        }
                        all_lines.push(line.trim_end_matches('\n').to_string());
                        output.push_str(&line);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if last_activity.elapsed() >= idle_timeout {
                        timed_out = true;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    *running_cmd_pid().lock().unwrap() = None;
                    return Err("Python REPL process exited unexpectedly".to_string());
                }
            }

            if cmd_interrupted().swap(false, Ordering::Relaxed) {
                interrupted = true;
            }

            let state = if interrupted {
                BashPanelState::Interrupted
            } else if timed_out {
                BashPanelState::Timeout
            } else if done {
                BashPanelState::Done
            } else {
                BashPanelState::Running
            };

            if is_tty {
                panel_rows = render_bash_panel(
                    &mut stdout,
                    "REPL",
                    code,
                    &all_lines,
                    start.elapsed(),
                    panel_rows,
                    state,
                    max_visible,
                );
            }

            if done || timed_out || interrupted {
                break;
            }
        }

        *running_cmd_pid().lock().unwrap() = None;

        if interrupted {
            return Err(
                "Python REPL: command was interrupted by the user (Ctrl+C). \
                 The REPL session has been killed and will restart on the next call."
                    .to_string(),
            );
        }

        if timed_out {
            return Err(format!(
                "Python REPL: no output for {timeout_ms}ms — command appears stuck/hung. \
                 The REPL session has been killed and will restart on the next call. \
                 Use bash for long-running or background processes."
            ));
        }
        let _ = stdout.flush();
        Ok(output)
    }
}

impl Drop for PythonRepl {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

// ─── CTF Tool Executor ────────────────────────────────────────────────────────
// Extends the standard tool executor with:
//   1. Bash sandbox disabled by default — injects dangerouslyDisableSandbox:true
//   2. Terminal rendering of tool outputs
//   3. Flag detection highlighted inline
//   4. Persistent Python REPL session

// ─── Live bash streaming ──────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum BashPanelState {
    Running,
    Done,
    Timeout,
    Interrupted,
}

/// Format elapsed duration: 47ms / 5.2s / 2m 34s
fn bash_elapsed_fmt(d: std::time::Duration) -> String {
    let ms = d.as_millis();
    if ms < 1_000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", d.as_secs_f64())
    } else {
        let s = d.as_secs();
        format!("{}m {}s", s / 60, s % 60)
    }
}

/// Redraw the live bash output panel in-place.
/// Returns the number of rows now on screen (for next call's `prev_rows`).
fn render_bash_panel(
    stdout: &mut impl io::Write,
    label: &str,
    command: &str,
    lines: &[String],
    elapsed: std::time::Duration,
    prev_rows: u16,
    state: BashPanelState,
    max_visible: usize,
) -> u16 {
    if prev_rows > 0 {
        let _ = write!(stdout, "\x1b[{prev_rows}A\x1b[0J");
    }

    let tw = crossterm::terminal::size()
        .map(|(w, _)| w as usize)
        .unwrap_or(120);
    let elapsed_str = bash_elapsed_fmt(elapsed);
    let mut rows: u16 = 0;

    // ── Header: ● Bash(cmd)  ▸ 1.2s  ────────────────────────────────────────
    {
        let status_part = match state {
            BashPanelState::Running => format!("  {C_DARK_ASH}▸ {elapsed_str}{C_RESET}"),
            BashPanelState::Done => format!("  {C_DARK_ASH}{elapsed_str}{C_RESET}"),
            BashPanelState::Timeout => format!("  {C_ROSE}⏱ timed out {elapsed_str}{C_RESET}"),
            BashPanelState::Interrupted => {
                format!("  {C_ROSE}⏹ interrupted {elapsed_str}{C_RESET}")
            }
        };
        let first_line = command.lines().next().unwrap_or(command).trim();
        let max_cmd = tw.saturating_sub(status_part.len().min(tw / 3) + 12);
        let cmd_display = if first_line.len() > max_cmd {
            format!("{}…", &first_line[..max_cmd])
        } else {
            first_line.to_string()
        };
        let _ = writeln!(
            stdout,
            "{C_TEAL}●{C_RESET} {C_BOLD}{label}{C_RESET}({cmd_display}){status_part}"
        );
        rows += 1;
    }

    // ── Output lines ─────────────────────────────────────────────────────────
    let total = lines.len();
    let omitted = total.saturating_sub(max_visible);
    let visible = &lines[total.saturating_sub(max_visible)..];
    let max_line_len = tw.saturating_sub(4);

    if omitted > 0 {
        let _ = writeln!(
            stdout,
            "{C_DARK_ASH}│  … {omitted} earlier line{}{C_RESET}",
            if omitted == 1 { "" } else { "s" }
        );
        rows += 1;
    }

    for line in visible {
        // Strip ANSI from the line length check but keep them in display
        let stripped_len = strip_ansi_len(line);
        let display = if stripped_len > max_line_len {
            truncate_ansi(line, max_line_len)
        } else {
            line.clone()
        };
        let _ = writeln!(stdout, "{C_DARK_ASH}│{C_RESET}  {display}");
        rows += 1;
    }

    // ── Footer ───────────────────────────────────────────────────────────────
    match state {
        BashPanelState::Running => {} // timer is in header
        BashPanelState::Done => {
            let pl = if total == 1 { "line" } else { "lines" };
            let _ = writeln!(stdout, "{C_DARK_ASH}└─ {total} {pl}{C_RESET}");
            rows += 1;
        }
        BashPanelState::Timeout => {
            let _ = writeln!(
                stdout,
                "{C_ROSE}└─ killed · {total} lines collected{C_RESET}"
            );
            rows += 1;
        }
        BashPanelState::Interrupted => {
            let _ = writeln!(
                stdout,
                "{C_ROSE}└─ stopped by user · {total} lines collected{C_RESET}"
            );
            rows += 1;
        }
    }

    let _ = stdout.flush();
    rows
}

fn strip_ansi_len(s: &str) -> usize {
    let mut len = 0;
    let mut in_esc = false;
    for c in s.chars() {
        if in_esc {
            if c == 'm' {
                in_esc = false;
            }
        } else if c == '\x1b' {
            in_esc = true;
        } else {
            len += 1;
        }
    }
    len
}

fn truncate_ansi(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut visible = 0;
    let mut in_esc = false;
    let mut esc_buf = String::new();
    for c in s.chars() {
        if in_esc {
            esc_buf.push(c);
            if c == 'm' {
                out.push('\x1b');
                out.push_str(&esc_buf);
                esc_buf.clear();
                in_esc = false;
            }
        } else if c == '\x1b' {
            in_esc = true;
            esc_buf.clear();
        } else {
            if visible >= max_chars {
                out.push('…');
                break;
            }
            out.push(c);
            visible += 1;
        }
    }
    out
}

/// Run a bash command with live streaming terminal output.
/// Shows a `│ lines` panel that updates in-place; returns full output for the LLM.
fn run_bash_streaming(command: &str, timeout_ms: u64) -> Result<String, String> {
    use std::io::BufRead;
    use std::time::{Duration, Instant};

    let start = Instant::now();
    let timeout_dur = Duration::from_millis(timeout_ms);

    let mut cmd = std::process::Command::new("bash");
    cmd.args(["-lc", command])
        // PYTHONUNBUFFERED: prevents Python from buffering stdout when piped,
        // so we see print() output even when the process is killed mid-run.
        .env("PYTHONUNBUFFERED", "1")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;

    let child_pid = child.id();
    if let Ok(mut pids) = background_pids().lock() {
        pids.push(child_pid);
    }
    *running_cmd_pid().lock().unwrap() = Some(child_pid);
    cmd_interrupted().store(false, Ordering::Relaxed);

    let (tx, rx) = mpsc::channel::<String>();
    let child_out = child.stdout.take().unwrap();
    let child_err = child.stderr.take().unwrap();
    let tx_out = tx.clone();

    let out_t = std::thread::spawn(move || {
        for line in std::io::BufReader::new(child_out)
            .lines()
            .map_while(Result::ok)
        {
            let _ = tx_out.send(line);
        }
    });
    let err_t = std::thread::spawn(move || {
        for line in std::io::BufReader::new(child_err)
            .lines()
            .map_while(Result::ok)
        {
            let _ = tx.send(line);
        }
    });

    let is_tty = crossterm::terminal::size().is_ok();
    // Max bash/tool output lines shown in the live panel before truncating.
    let max_visible = if verbose_output().load(Ordering::Relaxed) {
        usize::MAX
    } else {
        12
    };
    let mut all_lines: Vec<String> = Vec::new();
    let mut panel_rows: u16 = 0;
    let mut stdout = io::stdout();
    let mut timed_out = false;
    let mut interrupted = false;
    let mut last_line_count = 0usize;

    'render: loop {
        for line in rx.try_iter() {
            all_lines.push(line);
        }

        let elapsed = start.elapsed();

        if elapsed >= timeout_dur {
            timed_out = true;
            kill_process_group(child_pid);
            let _ = child.kill();
        }

        if cmd_interrupted().swap(false, Ordering::Relaxed) {
            interrupted = true;
        }

        let threads_done = out_t.is_finished() && err_t.is_finished();

        if threads_done {
            for line in rx.try_iter() {
                all_lines.push(line);
            }
        }

        let has_new = all_lines.len() != last_line_count;
        last_line_count = all_lines.len();

        let panel_state = if interrupted {
            BashPanelState::Interrupted
        } else if timed_out {
            BashPanelState::Timeout
        } else if threads_done {
            BashPanelState::Done
        } else {
            BashPanelState::Running
        };

        if is_tty {
            // Re-render every tick: timer updates even when no output arrives.
            panel_rows = render_bash_panel(
                &mut stdout,
                "Bash",
                command,
                &all_lines,
                elapsed,
                panel_rows,
                panel_state,
                max_visible,
            );
        } else if has_new {
            for line in &all_lines[last_line_count.saturating_sub(all_lines.len())..] {
                let _ = writeln!(stdout, "{line}");
            }
        }

        if threads_done || timed_out || interrupted {
            break 'render;
        }
        std::thread::sleep(Duration::from_millis(80));
    }

    *running_cmd_pid().lock().unwrap() = None;
    let _ = out_t.join();
    let _ = err_t.join();
    if let Ok(mut pids) = background_pids().lock() {
        pids.retain(|&p| p != child_pid);
    }
    let _ = child.wait();

    if interrupted {
        let elapsed_str = bash_elapsed_fmt(start.elapsed());
        // Give reader threads a moment to flush any last bytes after kill.
        std::thread::sleep(std::time::Duration::from_millis(200));
        for line in rx.try_iter() {
            all_lines.push(line);
        }
        let partial = all_lines.join("\n");
        let notice = format!(
            "[INTERRUPTED BY USER after {elapsed_str} — process was killed]\n\
             [Partial output ({} lines):]\n{}",
            all_lines.len(),
            partial
        );
        return Ok(notice);
    }

    if timed_out {
        let elapsed_str = bash_elapsed_fmt(start.elapsed());
        // Give reader threads a moment to flush any last bytes after kill.
        std::thread::sleep(std::time::Duration::from_millis(200));
        for line in rx.try_iter() {
            all_lines.push(line);
        }
        let partial = all_lines.join("\n");
        // Return as Ok so the LLM gets the partial output and can adapt.
        // The timeout notice tells it what happened so it can try a different approach.
        let notice = format!(
            "[TIMEOUT after {elapsed_str} — process was killed]\n\
             [Partial output ({} lines):]\n{}",
            all_lines.len(),
            partial
        );
        return Ok(notice);
    }
    Ok(all_lines.join("\n"))
}

struct CtfToolExecutor {
    python_repl: Option<PythonRepl>,
    challenge_name: String,
    challenge_dir: PathBuf,
    challenge_file_names: Vec<String>,
}

/// Sites that overwhelmingly host CTF writeups/solutions rather than general
/// vulnerability research material.
const WRITEUP_HOST_DENYLIST: &[&str] = &[
    "ctftime.org",
    "ctf-wiki",
    "ctfwriteups",
    "writeups",
    "write-up",
    "write-ups",
    "medium.com",
    "0xdf",
    "github.io",
];

impl CtfToolExecutor {
    fn new(challenge: &Challenge) -> Self {
        Self {
            python_repl: None,
            challenge_name: challenge.name.clone(),
            challenge_dir: challenge.dir.clone(),
            challenge_file_names: top_level_challenge_file_names(challenge),
        }
    }

    /// Returns Some(reason) if a WebSearch/WebFetch call looks like an attempt
    /// to find a writeup/solution for this specific challenge rather than
    /// general vulnerability research — which the system prompt forbids.
    fn writeup_search_violation(&self, tool_name: &str, input: &Value) -> Option<String> {
        if self.challenge_name.trim().is_empty() {
            return None;
        }
        let name_lower = self.challenge_name.to_lowercase();
        // Require at least 4 chars so we don't false-positive on tiny/generic names.
        if name_lower.len() < 4 {
            return None;
        }

        let haystack = match tool_name {
            "WebSearch" => input
                .get("query")
                .and_then(Value::as_str)
                .map(str::to_lowercase),
            "WebFetch" => input
                .get("url")
                .and_then(Value::as_str)
                .map(str::to_lowercase)
                .or_else(|| {
                    input
                        .get("prompt")
                        .and_then(Value::as_str)
                        .map(str::to_lowercase)
                }),
            _ => None,
        }?;

        let mentions_challenge = haystack.contains(&name_lower);
        let mentions_writeup_term = haystack.contains("writeup")
            || haystack.contains("write-up")
            || haystack.contains("walkthrough")
            || haystack.contains("solution");
        let on_writeup_host = WRITEUP_HOST_DENYLIST.iter().any(|h| haystack.contains(h));

        if mentions_challenge && (mentions_writeup_term || on_writeup_host) {
            return Some(format!(
                "Blocked: this {tool_name} query/URL appears to target a writeup or solution \
                 for THIS challenge ('{}'), which is forbidden. Solve it yourself using the \
                 provided files and your own analysis. Web search remains allowed for general \
                 CVE/vulnerability research not tied to this challenge's name.",
                self.challenge_name
            ));
        }
        if on_writeup_host && mentions_writeup_term {
            return Some(format!(
                "Blocked: this {tool_name} call targets a writeup/solution site, which is \
                 forbidden for CTF challenges. Solve it yourself using the provided files \
                 and your own analysis. Web search remains allowed for general CVE/vulnerability \
                 research."
            ));
        }
        None
    }

    /// Patch bash input JSON to disable sandbox globally.
    /// This maps to `bash.rs:sandbox_status_for_input()` → `SandboxConfig.resolve_request(Some(false)`, ...)
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

    fn normalize_grep_search_input(input: &mut Value) -> Vec<String> {
        let mut notes = Vec::new();
        let Some(pattern) = input
            .get("pattern")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            return notes;
        };

        if Regex::new(&pattern).is_ok() || !pattern.contains('{') {
            return notes;
        }

        let range_fixed = normalize_descending_regex_ranges(&pattern);
        if range_fixed != pattern && Regex::new(&range_fixed).is_ok() {
            if let Some(obj) = input.as_object_mut() {
                obj.insert("pattern".to_string(), json!(range_fixed));
            }
            notes.push("rewrote descending grep_search regex repetition range".to_string());
            return notes;
        }

        let escaped = escape_invalid_regex_braces(&pattern);
        if escaped != pattern && Regex::new(&escaped).is_ok() {
            if let Some(obj) = input.as_object_mut() {
                obj.insert("pattern".to_string(), json!(escaped));
            }
            notes.push(
                "escaped literal `{`/`}` characters in invalid grep_search regex".to_string(),
            );
        }
        notes
    }

    fn destructive_notes_write_violation(&self, tool_name: &str, input: &Value) -> Option<String> {
        if tool_name != "write_file" {
            return None;
        }
        let path = input.get("path").and_then(Value::as_str)?;
        let target = if Path::new(path).is_absolute() {
            PathBuf::from(path)
        } else {
            self.challenge_dir.join(path)
        };
        let notes = self.challenge_dir.join("notes.md");
        if target != notes || !notes.exists() {
            return None;
        }

        Some(
            "Blocked: write_file would replace the workspace notes.md and may destroy its \
             section structure. Preserve the existing structure: append findings with bash \
             (`printf ... >> notes.md`) or use edit_file for a narrow section edit."
                .to_string(),
        )
    }

    fn local_file_webfetch_violation(tool_name: &str, input: &Value) -> Option<String> {
        if tool_name != "WebFetch" {
            return None;
        }
        let url = input.get("url").and_then(Value::as_str)?;
        if url.starts_with("./")
            || url.starts_with("../")
            || url.starts_with('/')
            || url.starts_with("files/")
        {
            return Some(
                "WebFetch is only for http(s) URLs. For local challenge files, use read_file or \
                 bash with paths from ./files/."
                    .to_string(),
            );
        }
        None
    }

    fn normalize_bash_command(&self, command: &str) -> (String, Vec<String>) {
        let mut normalized = command.replace("\r\n", "\n").replace("files./", "files/");
        let mut notes = Vec::new();

        let bad_redirect = Regex::new(r"2>\s*&\s*true\b").expect("valid redirect regex");
        if bad_redirect.is_match(&normalized) {
            normalized = bad_redirect
                .replace_all(&normalized, "2>/dev/null || true")
                .into_owned();
            notes.push("fixed invalid `2>& true` redirect".to_string());
        }

        let bad_redirect_devnull =
            Regex::new(r"2>\s*&\s*/dev/null\b").expect("valid redirect regex");
        if bad_redirect_devnull.is_match(&normalized) {
            normalized = bad_redirect_devnull
                .replace_all(&normalized, "2>/dev/null")
                .into_owned();
            notes.push("fixed invalid `2>& /dev/null` redirect".to_string());
        }

        let missing_devnull_slash =
            Regex::new(r"(?P<redir>(?:^|[\s;|&])\d?>)\s*dev/null\b").expect("valid devnull regex");
        if missing_devnull_slash.is_match(&normalized) {
            normalized = missing_devnull_slash
                .replace_all(&normalized, "${redir}/dev/null")
                .into_owned();
            notes.push("fixed `dev/null` redirect path".to_string());
        }

        let bad_stderr_to_high_fd =
            Regex::new(r"2>\s*&\s*[3-9]\b").expect("valid high fd redirect regex");
        if bad_stderr_to_high_fd.is_match(&normalized) {
            normalized = bad_stderr_to_high_fd
                .replace_all(&normalized, "2>&1")
                .into_owned();
            notes.push("rewrote stderr redirect to unopened high fd".to_string());
        }

        let high_fd_dup = Regex::new(r"\s+[3-9]>\s*&\s*[12]\b").expect("valid high fd dup regex");
        if high_fd_dup.is_match(&normalized) {
            normalized = high_fd_dup.replace_all(&normalized, "").into_owned();
            notes.push("removed unused high-fd duplication".to_string());
        }

        let redundant_stdin_dup =
            Regex::new(r"\s+<\s*&\s*[01]\b").expect("valid fd duplication regex");
        if redundant_stdin_dup.is_match(&normalized) {
            normalized = redundant_stdin_dup
                .replace_all(&normalized, "")
                .into_owned();
            notes.push("removed unsafe stdin fd duplication".to_string());
        }

        let empty_head_arg =
            Regex::new(r#"\b(head\s+-[cn]\s+\d+)\s+""\s+"#).expect("valid head regex");
        if empty_head_arg.is_match(&normalized) {
            normalized = empty_head_arg.replace_all(&normalized, "$1 ").into_owned();
            notes.push("removed stray empty argument after `head`".to_string());
        }

        let strings_file_then_t =
            Regex::new(r"\bstrings\s+(?P<path>(?:\./)?files/[^\s;|&]+)\s+-t\b")
                .expect("valid strings -t regex");
        if strings_file_then_t.is_match(&normalized) {
            normalized = strings_file_then_t
                .replace_all(&normalized, "strings -t x ${path}")
                .into_owned();
            notes.push("fixed `strings` offset option syntax".to_string());
        }

        let strings_bad_t_x_digits =
            Regex::new(r"\bstrings(?P<opts>(?:\s+-[A-Za-z]+)*)\s+-t\s+x\d+\b")
                .expect("valid strings -t xN regex");
        if strings_bad_t_x_digits.is_match(&normalized) {
            normalized = strings_bad_t_x_digits
                .replace_all(&normalized, "strings${opts} -t x")
                .into_owned();
            notes.push("rewrote invalid `strings -t xN` radix option".to_string());
        }

        let strings_bad_tf = Regex::new(r"\bstrings(?P<opts>(?:\s+-[A-Za-z]+)*)\s+-tf\b")
            .expect("valid strings -tf regex");
        if strings_bad_tf.is_match(&normalized) {
            normalized = strings_bad_tf
                .replace_all(&normalized, "strings${opts} -t x")
                .into_owned();
            notes.push("rewrote invalid `strings -tf` option".to_string());
        }

        let fgrep_extended =
            Regex::new(r"\bfgrep(\s+-[A-Za-z]*E[A-Za-z]*)").expect("valid fgrep regex");
        if fgrep_extended.is_match(&normalized) {
            normalized = fgrep_extended
                .replace_all(&normalized, "grep$1")
                .into_owned();
            notes.push("rewrote conflicting `fgrep -E` to `grep -E`".to_string());
        }

        let sort_u_typo = Regex::new(r"\bsortU\b").expect("valid sort typo regex");
        if sort_u_typo.is_match(&normalized) {
            normalized = sort_u_typo.replace_all(&normalized, "sort -u").into_owned();
            notes.push("rewrote `sortU` typo to `sort -u`".to_string());
        }

        let dd_offset = Regex::new(r"\boffset=").expect("valid dd offset regex");
        if dd_offset.is_match(&normalized) {
            normalized = dd_offset.replace_all(&normalized, "skip=").into_owned();
            notes.push("rewrote dd `offset=` to `skip=`".to_string());
        }

        let unzip_from_tmp = Regex::new(
            r"\bcd\s+\.?/tmp/(?P<dir>[^;&|]+)\s*&&\s*unzip\s+(?P<quiet>-q\s+)?\.\./files/(?P<archive>[^\s;|&]+)",
        )
        .expect("valid unzip tmp regex");
        if unzip_from_tmp.is_match(&normalized) {
            normalized =
                unzip_from_tmp
                    .replace_all(&normalized, |caps: &regex::Captures<'_>| {
                        let quiet = caps.name("quiet").map_or("", |m| m.as_str());
                        let dir = caps.name("dir").map_or("", |m| m.as_str()).trim();
                        let archive = caps.name("archive").map_or("", |m| m.as_str()).trim();
                        format!(
                            "mkdir -p ./tmp/{dir} && unzip {quiet}./files/{archive} -d ./tmp/{dir}",
                        )
                    })
                    .into_owned();
            notes.push("rewrote unzip from ./tmp with wrong ../files path".to_string());
        }

        let mut file_names = self.challenge_file_names.clone();
        file_names.sort_by_key(|name| std::cmp::Reverse(name.len()));
        for name in file_names {
            let guessed = format!("./{name}");
            let actual = format!("./files/{name}");
            if normalized.contains(&guessed) && !normalized.contains(&actual) {
                normalized = normalized.replace(&guessed, &actual);
                notes.push(format!("rewrote `{guessed}` to `{actual}`"));
            }
            for bad in [
                format!("/dev/char/{name}"),
                format!("/dev/character/{name}"),
            ] {
                if normalized.contains(&bad) {
                    normalized = normalized.replace(&bad, &actual);
                    notes.push(format!("rewrote hallucinated `{bad}` to `{actual}`"));
                }
            }
        }

        let absolute_files_dot = format!("{}/files./", self.challenge_dir.display());
        let absolute_files = format!("{}/files/", self.challenge_dir.display());
        if normalized.contains(&absolute_files_dot) {
            normalized = normalized.replace(&absolute_files_dot, &absolute_files);
            notes.push("fixed absolute `files./` path".to_string());
        }

        let recursive_grep = Regex::new(
            r#"\bgrep(?P<prefix>(?:\s+(?:--[A-Za-z0-9_-]+(?:=(?:"[^"]*"|'[^']*'|\S+))?|-{1,2}[A-Za-z0-9_=:-]+))*?)\s+(?P<recursive>-[A-Za-z]*[rR][A-Za-z]*|--recursive)\b"#,
        )
            .expect("valid grep regex");
        if recursive_grep.is_match(&normalized) && !normalized.contains(".ctf-session.json") {
            let grep_excludes = "--exclude='.ctf-session.json' --exclude='notes.md' \
                 --exclude='writeup.md' --exclude='replay.sh' --exclude-dir='logs'";
            let include_arg = Regex::new(r#"--include(?:=|\s+)(?:"[^"]*"|'[^']*'|\S+)"#)
                .expect("valid grep include regex");
            if include_arg.is_match(&normalized) {
                normalized = include_arg
                    .replace_all(&normalized, |caps: &regex::Captures<'_>| {
                        format!("{} {grep_excludes}", &caps[0])
                    })
                    .into_owned();
            } else {
                normalized = recursive_grep
                    .replace_all(&normalized, |caps: &regex::Captures<'_>| {
                        format!("{} {grep_excludes}", &caps[0])
                    })
                    .into_owned();
            }
            notes.push("excluded internal session/log files from recursive grep".to_string());
        }

        (normalized, notes)
    }

    fn malformed_bash_command_reason(&self, command: &str) -> Option<String> {
        let trimmed = command.trim_start();
        if trimmed.starts_with('-') {
            return Some(
                "Command starts with an option, not an executable. Start bash commands with a \
                 real program name such as `binwalk`, `grep`, `python3`, `7z`, or `file`."
                    .to_string(),
            );
        }
        if command.contains("PIPE_FD") {
            return Some(
                "Command references PIPE_FD, but the harness does not provide that variable. \
                 Use a normal pipeline, command substitution, or a temporary file instead."
                    .to_string(),
            );
        }
        if command.contains("${files") || command.contains("$files") {
            return Some(
                "Command references an undefined `files` shell variable. Use literal paths from \
                 the manifest, e.g. `./files/<name>`, and write temporary output under `./tmp/`."
                    .to_string(),
            );
        }
        if command.contains("$TMP") {
            return Some(
                "Command references an undefined `TMP` shell variable. Use the challenge \
                 workspace temp directory explicitly: `./tmp/<name>`."
                    .to_string(),
            );
        }
        if command.contains("stddate") {
            return Some(
                "`stddate` is not an available command. Use `date -u +%Y-%m-%dT%H:%M:%SZ` \
                 if a timestamp is actually needed."
                    .to_string(),
            );
        }
        if command.contains("$()") {
            return Some(
                "Command contains an empty command substitution `$()`. Remove it or replace it \
                 with a real command such as `date -u +%s`."
                    .to_string(),
            );
        }
        let workspace_root_find =
            Regex::new(r"\bfind\s+\.\s+-type\s+f\b").expect("valid root find regex");
        if workspace_root_find.is_match(command) {
            return Some(
                "Do not enumerate the whole solver workspace with `find . -type f`; that reads \
                 notes.md/logs/session artifacts. Enumerate challenge inputs with \
                 `find ./files -type f` instead."
                    .to_string(),
            );
        }
        let unbounded_generator = Regex::new(
            r"(?m)(?:^|[;&|]\s*)(?:python3?|bash|sh)\s+(?:\./)?files/(?:gen|generate|generator)[^ \n;|&]*\.(?:py|sh)\b",
        )
        .expect("valid generator regex");
        if unbounded_generator.is_match(command) && !command.contains("timeout ") {
            return Some(
                "This runs a challenge-provided generator script without an explicit timeout. \
                 Inspect the script first; if you only need a probe, rerun with `timeout 10s ...` \
                 and keep large outputs under ./tmp/ instead of notes.md."
                    .to_string(),
            );
        }
        let tool_called_as_shell = Regex::new(
            r"(?m)(?:^|[;&|]\s*)(challenge_recon|extract_archive|binary_recon|decompile|grep_search|glob_search|read_file|write_file|edit_file|kb_search|kb_read|kb_add|WebSearch|WebFetch|SendUserMessage)(?:\s|\()",
        )
        .expect("valid tool-as-shell regex");
        if let Some(caps) = tool_called_as_shell.captures(command) {
            let tool = caps.get(1).map_or("tool API", |m| m.as_str());
            return Some(format!(
                "`{tool}` is an agent tool/API, not a shell executable. Call it as a real tool \
                 with JSON input, or use an equivalent normal shell command."
            ));
        }
        let read_path_as_identifier = Regex::new(r"(?m)(?:^|[;&|]\s*)read\s+(?:\.?/|/)[^\s;|&]+")
            .expect("valid malformed read regex");
        if read_path_as_identifier.is_match(command) {
            return Some(
                "`read` assigns shell variables and cannot read from a file path argument. Use \
                 `cat`, `strings`, `grep`, `python3`, or `read_file` for local files."
                    .to_string(),
            );
        }
        let unavailable_command = Regex::new(r"\b(findstr|rfd|ltrace|strscan|dmp\.exe)\b")
            .expect("valid unavailable command regex");
        if let Some(caps) = unavailable_command.captures(command) {
            let tool = caps.get(1).map_or("that command", |m| m.as_str());
            return Some(format!(
                "`{tool}` is not available in this Linux environment. Use `grep`/`rg` for text \
                 search and `find` for file traversal."
            ));
        }
        let unavailable_re_tool = Regex::new(
            r"(?m)(?:^|[;&|]\s*)(rncat|jsr|jm|rbin2|hermesc?|hbc(?:tool)?|hbc-disassembler)(?:\s|$)",
        )
            .expect("valid unavailable reverse tool regex");
        if let Some(caps) = unavailable_re_tool.captures(command) {
            let tool = caps.get(1).map_or("that command", |m| m.as_str());
            return Some(format!(
                "`{tool}` is not installed in this environment. For React Native/Hermes iOS \
                 bundles, use available static tools: `challenge_recon`, `strings -a`, `grep -a`, \
                 `xxd`, `file`, and `rabin2`/`r2` only on real Mach-O binaries."
            ));
        }
        let xxd_directory_arg = Regex::new(r"\bxxd\s+\.\s+").expect("valid xxd dir regex");
        if xxd_directory_arg.is_match(command) {
            return Some(
                "`xxd . ...` passes the workspace directory as the input file. Put options first \
                 and then the exact file path, e.g. `xxd -g 1 -c 16 ./files/<path>`."
                    .to_string(),
            );
        }
        let base64_directory = Regex::new(r"\bbase64\s+(?:-[A-Za-z]*d[A-Za-z]*\s+)?\.(?:\s|$)")
            .expect("valid base64 dir regex");
        if base64_directory.is_match(command) {
            return Some(
                "`base64` was pointed at the workspace directory. Use an exact file path, and do \
                 not base64-decode binary plist/Hermes files unless a previous tool output shows \
                 the file actually contains base64 text."
                    .to_string(),
            );
        }
        let rabin2_head_typo =
            Regex::new(r"\brabin2\s+[^\n;|&]*\bhead-c\b").expect("valid rabin2 typo regex");
        if rabin2_head_typo.is_match(command) {
            return Some(
                "`head-c` is not a rabin2 input file. Run `rabin2 -z ./files/<binary>` and pipe \
                 the output to `head -c` or `head -n` separately."
                    .to_string(),
            );
        }
        let sed_insert_typo =
            Regex::new(r"(?m)(?:^|[;&|]\s*)sed\s+i(?:\s|$)").expect("valid sed typo regex");
        if sed_insert_typo.is_match(command) {
            return Some(
                "`sed i` is invalid sed syntax. If you only need a marker, use `printf` or \
                 `echo`; do not build complex sed one-liners for notes.md."
                    .to_string(),
            );
        }
        let raw_binary_to_notes = Regex::new(r"\bcat\s+(?:\./)?files/[^ \n;|&]+\s*>\s*notes\.md\b")
            .expect("valid notes dump regex");
        if raw_binary_to_notes.is_match(command) {
            return Some(
                "Do not dump raw challenge binaries into notes.md. Write concise text findings \
                 to notes.md, and put extracted binary data under `./tmp/`."
                    .to_string(),
            );
        }
        let notes_overwrite =
            Regex::new(r"(?m)(^|[^>])>\s*(?:\./)?notes\.md\b").expect("valid notes overwrite");
        let absolute_notes_overwrite = Regex::new(&format!(
            r"(?m)(^|[^>])>\s*{}",
            regex::escape(&self.challenge_dir.join("notes.md").display().to_string())
        ))
        .expect("valid absolute notes overwrite");
        if notes_overwrite.is_match(command) || absolute_notes_overwrite.is_match(command) {
            return Some(
                "Do not overwrite notes.md with `> notes.md`; it destroys the existing section \
                 structure. Append findings with `>> notes.md` or edit a narrow section."
                    .to_string(),
            );
        }
        let notes_csh_overwrite = Regex::new(r"(?m)(?:^|[;&|]\s*)(?:>&|&>)\s*(?:\./)?notes\.md\b")
            .expect("valid csh notes overwrite");
        let absolute_notes_csh_overwrite = Regex::new(&format!(
            r"(?m)(?:^|[;&|]\s*)(?:>&|&>)\s*{}",
            regex::escape(&self.challenge_dir.join("notes.md").display().to_string())
        ))
        .expect("valid absolute csh notes overwrite");
        if notes_csh_overwrite.is_match(command) || absolute_notes_csh_overwrite.is_match(command) {
            return Some(
                "Do not overwrite notes.md with `>& notes.md` or `&> notes.md`; it destroys the \
                 existing section structure. Append findings with `>> notes.md` or edit a narrow \
                 section."
                    .to_string(),
            );
        }
        let notes_inside_files = Regex::new(r#">\s*(?:\./)?files/[^\s'"<>;|&]*notes\.md\b"#)
            .expect("valid files notes regex");
        if notes_inside_files.is_match(command) {
            return Some(
                "Do not write solver notes under ./files/. Challenge inputs must stay read-only; \
                 append concise findings to the workspace-level notes.md instead."
                    .to_string(),
            );
        }
        let unrelated_solver_path = Regex::new(
            r#"(?:/usr/local/share|/home/[^/\s]+/\.local/share)/codenames-ctf-solver[^\s'"<>;|&)]*|/tmp/runs(?:/|$)"#,
        )
        .expect("valid unrelated path regex");
        if let Some(hit) = unrelated_solver_path.find(command) {
            return Some(format!(
                "Command references `{}`, which is not part of the current challenge workspace. \
                 Use only the manifest paths under ./files/ and scratch output under ./tmp/.",
                hit.as_str()
            ));
        }
        let tmp_bench_path = Regex::new(r#"/tmp/claw-ctf-(?:bench|agent)-[^\s'"<>;|&)]+"#)
            .expect("valid tmp path regex");
        for hit in tmp_bench_path.find_iter(command) {
            let path = hit.as_str();
            if !path.starts_with(&self.challenge_dir.to_string_lossy().to_string()) {
                return Some(format!(
                    "Command references `{path}`, which is outside the current challenge workspace. \
                     Use relative paths like `./files/<name>`, `./tmp/<name>`, or the current \
                     workspace path `{}`.",
                    self.challenge_dir.display()
                ));
            }
        }
        let any_tmp_path = Regex::new(r#"/tmp(?:/[^\s'"<>;|&)]*)?"#).expect("valid tmp regex");
        for hit in any_tmp_path.find_iter(command) {
            let path = hit.as_str();
            if !path.starts_with(&self.challenge_dir.to_string_lossy().to_string()) {
                return Some(format!(
                    "Command references `{path}`, which is outside the current challenge \
                     workspace. Use `./tmp/<name>` for scratch data and `./files/<name>` for \
                     challenge inputs; do not `cd /tmp` or invent `/tmp/extract` paths."
                ));
            }
        }
        let relative_bench_path =
            Regex::new(r#"(^|[\s'"(<>;|&])(?:\./)?tmp/claw-ctf-(?:bench|agent)-[^\s'"<>;|&)]+"#)
                .expect("valid relative bench path regex");
        if let Some(hit) = relative_bench_path.find(command) {
            return Some(format!(
                "Command references `{}`, a guessed benchmark path under ./tmp. Use the actual \
                 challenge paths: `./files/<name>` for inputs and `./tmp/<name>` for scratch output.",
                hit.as_str().trim()
            ));
        }
        let hallucinated_tool =
            Regex::new(r"\b(check-file-types|7zip-list|pathglob)\b").expect("valid tool regex");
        if let Some(caps) = hallucinated_tool.captures(command) {
            let tool = caps.get(1).map_or("that command", |m| m.as_str());
            return Some(format!(
                "`{tool}` is not an available command. Use `file`, `7z l`, `7z x -o./tmp/<dir>`, `binwalk`, or `strings` instead."
            ));
        }
        let checksec_archive = Regex::new(
            r"\bchecksec\b[^\n;|&]*(?:\.7z|\.zip|\.rar|\.tar|\.gz|\.xz|\.zst|\.png|\.jpe?g|\.gif|\.pcap|\.pdf|\.c|\.py|\.sh|\.js|\.html|\.php|\.txt|\.md|\.json|\.ya?ml)\b",
        )
        .expect("valid checksec archive regex");
        if checksec_archive.is_match(command) || command.contains("checksec -e PIE") {
            return Some(
                "`checksec` is only useful for ELF executables. This command is pointing it at \
                 an archive/non-ELF or treating `PIE` as a filename. Run `file` first; for .7z \
                 archives use `7z l`, `7z x -o./tmp/<dir>`, `binwalk`, or targeted `strings`."
                    .to_string(),
            );
        }
        if let Some(error) = bash_syntax_error(command) {
            return Some(format!(
                "Bash syntax check failed before execution: {error}. Rewrite the command with \
                 balanced quotes/braces or split it into simpler commands."
            ));
        }
        None
    }
}

impl ToolExecutor for CtfToolExecutor {
    fn execute(&mut self, tool_name: &str, input: &str) -> Result<String, ToolError> {
        let parsed: Value = serde_json::from_str(input)
            .map_err(|e| ToolError::new(format!("bad tool input JSON: {e}")))?;

        let mut effective_input = if tool_name == "bash" {
            Self::patch_bash_input(&parsed)
        } else {
            parsed
        };
        let mut bash_normalization_notes = Vec::new();
        let mut tool_normalization_notes = Vec::new();
        if tool_name == "bash" {
            let original_command = effective_input
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if !original_command.is_empty() {
                let (normalized_command, notes) = self.normalize_bash_command(&original_command);
                if normalized_command != original_command {
                    if let Some(obj) = effective_input.as_object_mut() {
                        obj.insert("command".to_string(), json!(normalized_command));
                    }
                    bash_normalization_notes = notes;
                }
            }
        } else if tool_name == "grep_search" {
            tool_normalization_notes = Self::normalize_grep_search_input(&mut effective_input);
        }

        // Block writeup/solution searches for this specific challenge —
        // an agent that finds the answer online hasn't actually solved it.
        if let Some(reason) = self.writeup_search_violation(tool_name, &effective_input) {
            return Err(ToolError::new(reason));
        }
        if let Some(reason) = Self::local_file_webfetch_violation(tool_name, &effective_input) {
            return Err(ToolError::new(reason));
        }
        if let Some(reason) = self.destructive_notes_write_violation(tool_name, &effective_input) {
            return Err(ToolError::new(reason));
        }

        let mut stdout = io::stdout();

        // ── Bash: live streaming panel ────────────────────────────────────────
        if tool_name == "bash" {
            let command = effective_input
                .get("command")
                .and_then(Value::as_str)
                .ok_or_else(|| ToolError::new("bash requires 'command'"))?;
            if let Some(reason) = self.malformed_bash_command_reason(command) {
                return Ok(format!(
                    "[ctf harness rejected malformed bash command]\n{reason}\nRewrite the command and run it again."
                ));
            }
            let timeout_ms = effective_input
                .get("timeout")
                .and_then(serde_json::Value::as_u64)
                .map_or(120_000, normalize_tool_timeout_ms);

            // Erase the ● Bash(cmd) line printed during streaming —
            // the panel will re-render it with a live elapsed timer.
            if crossterm::terminal::size().is_ok() {
                let _ = write!(stdout, "\x1b[1A\x1b[0J");
                let _ = stdout.flush();
            }

            return match run_bash_streaming(command, timeout_ms) {
                Ok(output) => {
                    append_to_replay("bash", &effective_input);
                    let normalized_output = if bash_normalization_notes.is_empty() {
                        output
                    } else {
                        format!(
                            "[ctf harness normalized malformed bash command before execution]\n- {}\n{}",
                            bash_normalization_notes.join("\n- "),
                            output
                        )
                    };
                    let api_output = truncate_output_lines(&normalized_output, 200, 15_000);
                    Ok(api_output)
                }
                Err(e) => {
                    let _ = writeln!(stdout, "{C_ROSE}✗  {e}{C_RESET}");
                    Err(ToolError::new(e))
                }
            };
        }

        // ── REPL (python): live streaming panel ─────────────────────────────────
        if tool_name == "REPL" {
            let lang = effective_input
                .get("language")
                .and_then(Value::as_str)
                .unwrap_or("python");
            if lang.to_ascii_lowercase().starts_with("py") {
                let code = effective_input
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let timeout_ms = effective_input
                    .get("timeout_ms")
                    .and_then(Value::as_u64)
                    .map_or(30_000, normalize_tool_timeout_ms);

                // Erase the ● REPL[...] line printed during streaming —
                // the panel will re-render it with a live elapsed timer.
                if crossterm::terminal::size().is_ok() {
                    let _ = write!(stdout, "\x1b[1A\x1b[0J");
                    let _ = stdout.flush();
                }

                if self.python_repl.is_none() {
                    match PythonRepl::start() {
                        Ok(r) => {
                            self.python_repl = Some(r);
                        }
                        Err(e) => return Err(ToolError::new(format!("Python REPL: {e}"))),
                    }
                }

                return match self.python_repl.as_mut().unwrap().execute(code, timeout_ms) {
                    Ok(output) => {
                        append_to_replay("REPL", &effective_input);
                        let api_output = truncate_output_lines(&output, 200, 15_000);
                        Ok(api_output)
                    }
                    Err(e) => {
                        self.python_repl = None;
                        let _ = writeln!(stdout, "{C_ROSE}✗  {e}{C_RESET}");
                        Err(ToolError::new(e))
                    }
                };
            }
        }

        // ── All other tools: header + execute + code-block output ─────────────
        // (Announce was already shown during streaming; print it again only for
        //  non-bash tools so they have a visible header before their output.)
        let call_display = format_ctf_tool_call(tool_name, input);
        let _ = writeln!(stdout, "{call_display}");
        let _ = stdout.flush();

        let result = match tool_name {
            name if mcp_tools::is_mcp_tool(name) => {
                let mut guard = mcp_toolset().lock().unwrap();
                match guard.as_mut() {
                    Some(toolset) => {
                        mcp_tools::call(toolset, name, &effective_input).map_err(ToolError::new)
                    }
                    None => Err(ToolError::new(format!(
                        "MCP server unavailable for tool `{name}`"
                    ))),
                }
            }
            "binary_recon" => {
                let path = effective_input
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ToolError::new("binary_recon requires 'path'"))?;
                Ok(ctf_binary_recon(path))
            }
            "decompile" => {
                let path = effective_input
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ToolError::new("decompile requires 'path'"))?;
                let func = effective_input
                    .get("function")
                    .and_then(Value::as_str)
                    .unwrap_or("main");
                ctf_decompile(path, func).map_err(ToolError::new)
            }
            "challenge_recon" => {
                let max_files = effective_input
                    .get("max_files")
                    .and_then(Value::as_u64)
                    .map_or(120usize, |n| n as usize);
                Ok(ctf_challenge_recon(&self.challenge_dir, max_files))
            }
            "extract_archive" => {
                let path = effective_input
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ToolError::new("extract_archive requires 'path'"))?;
                let output_dir = effective_input.get("output_dir").and_then(Value::as_str);
                ctf_extract_archive(&self.challenge_dir, path, output_dir).map_err(ToolError::new)
            }
            "kb_search" => {
                let query = effective_input
                    .get("query")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ToolError::new("kb_search requires 'query'"))?;
                let category = effective_input.get("category").and_then(Value::as_str);
                let top_k = effective_input
                    .get("top_k")
                    .and_then(Value::as_u64)
                    .map_or(5, |n| n as usize);
                Ok(knowledge::kb_search(query, category, top_k))
            }
            "kb_read" => {
                let id = effective_input
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ToolError::new("kb_read requires 'id'"))?;
                Ok(knowledge::kb_read(id))
            }
            "kb_add" => {
                let category = effective_input
                    .get("category")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ToolError::new("kb_add requires 'category'"))?;
                let what_worked = effective_input
                    .get("what_worked")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ToolError::new("kb_add requires 'what_worked'"))?;
                let what_failed = effective_input
                    .get("what_failed")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let session_ref = effective_input
                    .get("session_ref")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let confidence = effective_input
                    .get("confidence")
                    .and_then(Value::as_str)
                    .unwrap_or("medium");
                let fingerprint = effective_input
                    .get("fingerprint")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let tags = effective_input
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                knowledge::kb_add(
                    category,
                    fingerprint,
                    what_worked,
                    what_failed,
                    tags,
                    session_ref,
                    confidence,
                )
                .map(|id| format!("Recorded learned entry {id}"))
                .map_err(ToolError::new)
            }
            // Non-python REPL languages (the python case is handled above with
            // live streaming and returns early).
            _ => execute_tool(tool_name, &effective_input).map_err(ToolError::new),
        };

        match result {
            Ok(output) => {
                if tool_name == "REPL" {
                    append_to_replay(tool_name, &effective_input);
                }
                let normalized_output = if tool_normalization_notes.is_empty() {
                    output
                } else {
                    format!(
                        "[ctf harness normalized malformed tool input before execution]\n- {}\n{}",
                        tool_normalization_notes.join("\n- "),
                        output
                    )
                };
                let api_output = truncate_output_lines(&normalized_output, 200, 15_000);
                let display = if verbose_output().load(Ordering::Relaxed) {
                    normalized_output.clone()
                } else {
                    truncate_output_lines(&normalized_output, 60, 2_000)
                };
                let _ = write!(stdout, "{}", render_tool_card(&display, false));
                let _ = stdout.flush();
                Ok(api_output)
            }
            Err(err) => {
                let _ = write!(stdout, "{}", render_tool_card(&format!("✗ {err}"), true));
                let _ = stdout.flush();
                Err(err)
            }
        }
    }
}

/// Render a pi-style full-width background card: every line padded to the
/// terminal width, one space of left padding (paddingX=1), and a blank padded
/// row top and bottom (paddingY=1) — like pi's Box component.
fn render_card(body: &str, bg: &str, fg: &str) -> String {
    let width = crossterm::terminal::size()
        .map(|(w, _)| w as usize)
        .unwrap_or(80);
    let pad_line = |content: &str| -> String {
        let visible = strip_ansi_len(content);
        let fill = width.saturating_sub(visible + 1);
        format!("{bg}{fg} {content}{}{C_RESET}", " ".repeat(fill))
    };
    let mut out = String::from("\n");
    out.push_str(&pad_line("")); // top padding row
    out.push('\n');
    for line in body.lines() {
        out.push_str(&pad_line(line));
        out.push('\n');
    }
    out.push_str(&pad_line("")); // bottom padding row
    out.push('\n');
    out
}

/// Tool output card: green bg on success, red bg on error (feynman toolSuccessBg/toolErrorBg).
fn render_tool_card(body: &str, is_error: bool) -> String {
    let bg = if is_error {
        BG_TOOL_ERROR
    } else {
        BG_TOOL_SUCCESS
    };
    render_card(body, bg, "\x1b[38;2;157;169;160m") // toolOutput = stone
}

/// User message card on the panel background (feynman userMessageBg), text = ink.
fn render_user_card(body: &str) -> String {
    render_card(body, BG_PANEL, "\x1b[38;2;211;198;170m") // ink
}

/// Subtle label printed once before the assistant's prose, so it reads as a
/// distinct block from the tool cards that follow.
fn assistant_label() -> String {
    format!("\n{C_TEAL}{C_BOLD}●{C_RESET} {C_ASH}assistant{C_RESET}\n")
}

/// Append a successful tool call to logs/replay.sh so the session is reproducible.
/// bash commands are appended verbatim; Python REPL blocks are wrapped in a heredoc.
fn append_to_replay(tool_name: &str, input: &Value) {
    let path = std::path::Path::new("logs/replay.sh");

    let entry = match tool_name {
        "bash" => {
            let cmd = input.get("command").and_then(Value::as_str).unwrap_or("");
            if cmd.trim().is_empty() {
                return;
            }
            format!("{cmd}\n")
        }
        "REPL" => {
            let code = input.get("code").and_then(Value::as_str).unwrap_or("");
            let lang = input
                .get("language")
                .and_then(Value::as_str)
                .unwrap_or("python");
            if code.trim().is_empty() {
                return;
            }
            match lang.to_ascii_lowercase().as_str() {
                "python" | "py" => format!("python3 - << 'PYEOF'\n{code}\nPYEOF\n"),
                _ => format!("# REPL[{lang}]\n{code}\n"),
            }
        }
        _ => return,
    };

    let needs_header = !path.exists();
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
        if needs_header {
            let ts = utc_datetime_str(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            );
            let header = format!(
                "#!/bin/bash\n# CTF Solver — Replay Script\n# {ts} UTC\n# Run: bash ./logs/replay.sh\nset -e\n\n"
            );
            let _ = f.write_all(header.as_bytes());
        }
        let _ = f.write_all(entry.as_bytes());
        let _ = f.write_all(b"\n");
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
                .map(|block| match block {
                    ContentBlock::Text { text } => InputContentBlock::Text { text: text.clone() },
                    ContentBlock::ToolUse { id, name, input } => InputContentBlock::ToolUse {
                        id: id.clone(),
                        name: name.clone(),
                        input: serde_json::from_str(input).unwrap_or(json!({})),
                    },
                    ContentBlock::ToolResult {
                        tool_use_id,
                        output,
                        is_error,
                        ..
                    } => InputContentBlock::ToolResult {
                        tool_use_id: tool_use_id.clone(),
                        content: vec![ToolResultContentBlock::Text {
                            text: truncate_tool_output(output),
                        }],
                        is_error: *is_error,
                    },
                })
                .collect();
            if content.is_empty() {
                None
            } else {
                Some(InputMessage {
                    role: role.to_string(),
                    content,
                })
            }
        })
        .collect()
}

// ─── CTF tool specs ───────────────────────────────────────────────────────────
// Pruned subset of mvp_tool_specs() + two CTF-specific additions.
// Sending fewer, relevant tools reduces model confusion and saves context tokens.

fn ctf_tool_specs() -> Vec<tools::ToolSpec> {
    // Keep only tools relevant to CTF work; drop Todo, Skill, Agent, Config, etc.
    // REPL is excluded here and replaced with a CTF-optimised stateful version below.
    let keep: &[&str] = &[
        "bash",
        "read_file",
        "write_file",
        "edit_file",
        "glob_search",
        "grep_search",
        "WebFetch",
        "WebSearch",
        "Sleep",
        "SendUserMessage",
    ];

    let mut specs: Vec<tools::ToolSpec> = mvp_tool_specs()
        .into_iter()
        .filter(|s| keep.contains(&s.name))
        .collect();

    // ── REPL (CTF-optimised, stateful Python) ────────────────────────────────
    // Override the generic mvp description: emphasise persistent state and CTF libs.
    specs.push(tools::ToolSpec {
        name: "REPL",
        description: "Execute Python in a persistent session — variables, imports, and \
                      functions survive between calls. Use for: crypto attacks \
                      (pycryptodome, z3-solver, gmpy2), pwntools exploit scripting, \
                      iterative RSA/DH analysis, and any multi-step computation. \
                      Prefer REPL over bash for Python. \
                      Languages: python/py (stateful persistent), js/node, bash (stateless).",
        input_schema: json!({
            "type": "object",
            "properties": {
                "code":       { "type": "string" },
                "language":   { "type": "string", "default": "python" },
                "timeout_ms": { "type": "integer", "minimum": 1 }
            },
            "required": ["code", "language"],
            "additionalProperties": false
        }),
        required_permission: runtime::PermissionMode::DangerFullAccess,
    });

    // ── challenge_recon ──────────────────────────────────────────────────────
    // Low-friction first step for smaller local models: one clean tool call
    // instead of fragile shell pipelines that accidentally read solver logs.
    specs.push(tools::ToolSpec {
        name: "challenge_recon",
        description: "CTF-safe first-step recon over ./files only: lists files, runs file(1), \
                      lists archives, extracts interesting strings/grep hits, and previews small \
                      text/source files while excluding solver notes/log/session artifacts. Use \
                      this as the first tool call in auto mode before writing custom shell.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "max_files": { "type": "integer", "minimum": 1, "maximum": 300, "default": 120 }
            },
            "additionalProperties": false
        }),
        required_permission: runtime::PermissionMode::ReadOnly,
    });

    // ── extract_archive ──────────────────────────────────────────────────────
    specs.push(tools::ToolSpec {
        name: "extract_archive",
        description: "Safely extract an archive from ./files into ./tmp/extract/<name> and list \
                      extracted files. Supports .zip, .7z, and .tar* archives. Use this instead \
                      of writing fragile `cd ./tmp && unzip ../files/...` shell commands.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Archive path under ./files, e.g. ./files/chals.zip" },
                "output_dir": { "type": "string", "description": "Optional destination under ./tmp/" }
            },
            "required": ["path"],
            "additionalProperties": false
        }),
        required_permission: runtime::PermissionMode::WorkspaceWrite,
    });

    // ── binary_recon ─────────────────────────────────────────────────────────
    // One call instead of 4-5 bash calls: file + checksec + strings + ldd + arch.
    specs.push(tools::ToolSpec {
        name: "binary_recon",
        description: "All-in-one binary fingerprint AND disassembly. For ELF files: file type, security \
                       flags (NX/PIE/canary/RELRO), linked libraries, strings preview, imports (libc \
                       calls), plus radare2 disassembly of `main` and `entry0` and the recovered \
                       function list — works on stripped binaries. For non-ELF/data files (firmware, \
                       packed containers): adds a hexdump of the header. Use this as the FIRST step on \
                       any binary; read the disassembly here before reaching for the `decompile` tool.",
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

    // ── kb_search / kb_read ───────────────────────────────────────────────────
    // Lets the agent recall solved-challenge KB entries and indexed writeup/
    // reference notes by keyword/technique, instead of re-crawling the web
    // every time. kb_search returns only summaries + ids (token-cheap);
    // kb_read fetches the full markdown for a matched id.
    specs.push(tools::ToolSpec {
        name: "kb_search",
        description: "Search the local knowledge base for prior solved challenges and indexed \
                       writeup/reference notes matching a keyword or technique (e.g. 'padding \
                       oracle', 'format string', 'jwt none algorithm'). Check here before using \
                       WebSearch — relevant notes from past runs may already be saved. Returns \
                       summaries and ids only — use kb_read(id) to fetch the full note. \
                       To add new notes: after researching a technique via WebSearch/WebFetch, \
                       write a markdown summary to \
                       ~/.local/share/ctf-skills/writeups/<category>/<slug>.md and append a JSON \
                       line (id, source, category, title, tags, techniques, primitives, \
                       difficulty, summary, trigger_signals, path, url, year, quality) to \
                       ~/.local/share/ctf-skills/writeups/_index.jsonl so future searches find it.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Keyword or technique to search for" },
                "category": { "type": "string", "description": "Optional: restrict writeup/reference results to this category" },
                "top_k": { "type": "integer", "minimum": 1, "description": "Max writeup/reference results (default 5)" }
            },
            "required": ["query"],
            "additionalProperties": false
        }),
        required_permission: runtime::PermissionMode::ReadOnly,
    });

    specs.push(tools::ToolSpec {
        name: "kb_read",
        description: "Fetch the full markdown content of a writeup/reference note by its `id` \
                       (as returned by kb_search). Call this after kb_search surfaces a \
                       relevant entry.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "description": "Entry id from kb_search results" }
            },
            "required": ["id"],
            "additionalProperties": false
        }),
        required_permission: runtime::PermissionMode::ReadOnly,
    });

    specs.push(tools::ToolSpec {
        name: "kb_add",
        description: "Record a reusable pattern from this session to the local learned-knowledge \
                       base (kb_search will surface it in future sessions). Call this after \
                       solving a challenge (or hitting a dead end worth remembering) — record \
                       both what worked and what failed, since avoiding known dead ends is as \
                       valuable as repeating what worked. Keep entries short and generic \
                       (the reusable pattern, not this challenge's specific flag/values).",
        input_schema: json!({
            "type": "object",
            "properties": {
                "category": { "type": "string", "description": "Challenge category, e.g. 'pwn', 'crypto'" },
                "fingerprint": {
                    "type": "array", "items": { "type": "string" },
                    "description": "Recognition signals for when this pattern applies, e.g. ['64-bit', 'no canary', 'win() present']"
                },
                "what_worked": { "type": "string", "description": "The technique/approach that succeeded" },
                "what_failed": { "type": "string", "description": "Approaches that were tried and did NOT work (optional but encouraged)" },
                "tags": { "type": "array", "items": { "type": "string" }, "description": "Searchable keywords" },
                "session_ref": { "type": "string", "description": "Challenge name or identifier for this session" },
                "confidence": { "type": "string", "description": "'high', 'medium', or 'low'" }
            },
            "required": ["category", "what_worked"],
            "additionalProperties": false
        }),
        required_permission: runtime::PermissionMode::ReadOnly,
    });

    // ── MCP servers (e.g. GhidraMCP) configured in ~/.claude.json ──────────────
    specs.extend(mcp_tool_specs());

    specs
}

/// Convert runtime messages to `OpenAI` chat format.
/// Key differences from Anthropic:
///   - Tool results → separate messages with role="tool"
///   - Tool calls   → "`tool_calls`" array in assistant message
///
/// `OpenAI` API rejects tool outputs longer than 10 MB. Cap at 200 KB of UTF-8 chars.
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
                        ContentBlock::ToolResult { .. } => {}
                    }
                }
                let mut obj = serde_json::Map::new();
                obj.insert("role".into(), json!("assistant"));
                obj.insert(
                    "content".into(),
                    if text.is_empty() {
                        json!(null)
                    } else {
                        json!(text)
                    },
                );
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
                        ContentBlock::ToolResult {
                            tool_use_id,
                            output,
                            ..
                        } => {
                            // Skip orphaned tool results (tool_use was removed by compaction)
                            if valid_tool_ids.contains(tool_use_id) {
                                tool_results.push((tool_use_id.clone(), output.clone()));
                            }
                        }
                        ContentBlock::ToolUse { .. } => {}
                    }
                }
                if !text_parts.is_empty() {
                    out.push(json!({ "role": "user", "content": text_parts.join("\n") }));
                }
                for (tool_call_id, content) in tool_results {
                    let content = truncate_tool_output(&content);
                    out.push(
                        json!({ "role": "tool", "tool_call_id": tool_call_id, "content": content }),
                    );
                }
            }
        }
    }
    out
}

/// Convert session messages to the Responses API `input` array format.
///
/// Wire format (from codex-rs source):
///   - Each message → `{"type":"message","role":"...","content":[{"type":"input_text"|"output_text","text":"..."}]}`
///   - Function calls from assistant → top-level `{"type":"function_call","call_id":"...","name":"...","arguments":"..."}`
///     (no `id` field — codex-rs `skip_serializes` it; sending it causes 422/500)
///   - Tool results → top-level `{"type":"function_call_output","call_id":"...","output":"..."}`
///   - System prompt → `{"role":"system","content":[{"type":"input_text","text":"..."}]}`
fn convert_messages_responses(
    system_prompt: &[String],
    messages: &[ConversationMessage],
) -> Vec<Value> {
    let valid_tool_ids: std::collections::HashSet<String> = messages
        .iter()
        .filter(|m| m.role == MessageRole::Assistant)
        .flat_map(|m| m.blocks.iter())
        .filter_map(|b| match b {
            ContentBlock::ToolUse { id, .. } => Some(id.clone()),
            _ => None,
        })
        .collect();

    let mut input: Vec<Value> = Vec::new();

    // System prompt — wrapped as a message with input_text content
    if !system_prompt.is_empty() {
        let text = system_prompt.join("\n\n");
        input.push(json!({
            "type": "message",
            "role": "system",
            "content": [{"type": "input_text", "text": text}]
        }));
    }

    for msg in messages {
        match msg.role {
            MessageRole::System => {}
            MessageRole::User | MessageRole::Tool => {
                let mut text_parts: Vec<String> = Vec::new();
                let mut tool_outputs: Vec<(String, String)> = Vec::new();
                for block in &msg.blocks {
                    match block {
                        ContentBlock::Text { text } => text_parts.push(text.clone()),
                        ContentBlock::ToolResult {
                            tool_use_id,
                            output,
                            ..
                        } => {
                            if valid_tool_ids.contains(tool_use_id) {
                                tool_outputs
                                    .push((tool_use_id.clone(), truncate_tool_output(output)));
                            }
                        }
                        ContentBlock::ToolUse { .. } => {}
                    }
                }
                if !text_parts.is_empty() {
                    let text = text_parts.join("\n");
                    input.push(json!({
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": text}]
                    }));
                }
                // Tool results are top-level function_call_output items (not inside a message)
                for (call_id, output) in tool_outputs {
                    input.push(json!({
                        "type": "function_call_output",
                        "call_id": call_id,
                        "output": output
                    }));
                }
            }
            MessageRole::Assistant => {
                let mut text = String::new();
                let mut func_calls: Vec<(String, String, String)> = Vec::new();
                for block in &msg.blocks {
                    match block {
                        ContentBlock::Text { text: t } => text.push_str(t),
                        ContentBlock::ToolUse {
                            id,
                            name,
                            input: inp,
                        } => {
                            func_calls.push((id.clone(), name.clone(), inp.clone()));
                        }
                        ContentBlock::ToolResult { .. } => {}
                    }
                }
                if !text.is_empty() {
                    input.push(json!({
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": text}]
                    }));
                }
                // Function calls are top-level items — no `id` field (skip_serializing in codex-rs)
                for (call_id, name, args) in func_calls {
                    input.push(json!({
                        "type": "function_call",
                        "call_id": call_id,
                        "name": name,
                        "arguments": args,
                    }));
                }
            }
        }
    }
    input
}

/// Decode the `chatgpt_account_id` from the JWT access token.
/// The token is a standard JWT; we base64-decode the payload (middle part) and
/// read the nested claim at "<https://api.openai.com/auth".chatgpt_account_id>.
fn extract_chatgpt_account_id(token: &str) -> Option<String> {
    let payload_b64 = token.split('.').nth(1)?;
    // JWT uses URL-safe base64 without padding — add padding back.
    let pad = (4 - payload_b64.len() % 4) % 4;
    let padded = format!("{}{}", payload_b64, "=".repeat(pad));
    let decoded = base64_decode_url(&padded);
    let v: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    v["https://api.openai.com/auth"]["chatgpt_account_id"]
        .as_str()
        .map(String::from)
}

fn base64_decode_url(s: &str) -> Vec<u8> {
    // URL-safe base64: replace - with + and _ with /
    let standard = s.replace('-', "+").replace('_', "/");
    // Simple base64 decode without external crate
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let decode_char =
        |c: u8| -> Option<u8> { alphabet.iter().position(|&a| a == c).map(|p| p as u8) };
    let bytes: Vec<u8> = standard.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let vals: Vec<u8> = chunk.iter().filter_map(|&b| decode_char(b)).collect();
        if vals.len() >= 2 {
            out.push((vals[0] << 2) | (vals[1] >> 4));
        }
        if vals.len() >= 3 {
            out.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if vals.len() >= 4 {
            out.push((vals[2] << 6) | vals[3]);
        }
    }
    out
}

/// Same as `convert_messages_responses` but skips system prompt —
/// system prompt goes in the "instructions" field of the Codex request body.
fn convert_messages_responses_nosystem(messages: &[ConversationMessage]) -> Vec<Value> {
    convert_messages_responses(&[], messages)
}

impl CtfToolExecutor {} // marker — stream_responses_api is added on CtfApiClient below

impl CtfApiClient {
    /// Call chatgpt.com/backend-api/codex/responses — same endpoint feynman uses.
    /// Key differences from api.openai.com/v1/responses:
    ///   - URL: chatgpt.com/backend-api/codex/responses
    ///   - Headers: chatgpt-account-id, originator, OpenAI-Beta: responses=experimental
    ///   - Body: system prompt goes in "instructions" field, NOT in "input" array
    ///   - Tools: strict: null (not strict mode)
    fn stream_responses_api(
        &mut self,
        request: ApiRequest,
    ) -> Result<Vec<AssistantEvent>, RuntimeError> {
        let (base_url, stored_key, is_oauth, http) = match &self.backend {
            ApiBackend::OpenAi {
                base_url,
                api_key,
                is_oauth,
                http,
            } => (base_url.clone(), api_key.clone(), *is_oauth, http.clone()),
            ApiBackend::Anthropic(_) => unreachable!(),
        };

        let api_key = if is_oauth {
            resolve_openai_auth().unwrap_or(stored_key)
        } else {
            stored_key
        };

        // Use chatgpt.com backend (same as feynman/pi-coding-agent).
        // Falls back to OPENAI_BASE_URL if set for custom deployments.
        let endpoint = {
            let base = base_url.trim_end_matches('/');
            if base == "https://api.openai.com" || base.is_empty() {
                "https://chatgpt.com/backend-api/codex/responses".to_string()
            } else if base.ends_with("/codex/responses") {
                base.to_string()
            } else if base.ends_with("/codex") {
                format!("{base}/responses")
            } else {
                format!("{base}/codex/responses")
            }
        };

        // Extract chatgpt_account_id from JWT — required by chatgpt.com backend.
        let account_id =
            extract_chatgpt_account_id(&api_key).unwrap_or_else(|| "unknown".to_string());

        // Tools: flat format, strict: null (NOT strict: true like api.openai.com).
        let tools_json: Vec<Value> = ctf_tool_specs()
            .into_iter()
            .map(|spec| {
                json!({
                    "type": "function",
                    "name": spec.name,
                    "description": spec.description,
                    "parameters": spec.input_schema,
                })
            })
            .collect();

        // System prompt → "instructions" field; conversation messages → "input".
        // feynman passes includeSystemPrompt: false to convertResponsesMessages.
        let instructions = request.system_prompt.join("\n\n");
        let input = convert_messages_responses_nosystem(&request.messages);

        let body = json!({
            "model": self.model,
            "store": false,
            "stream": true,
            "instructions": instructions,
            "input": input,
            "text": { "verbosity": "low" },
            "include": ["reasoning.encrypted_content"],
            "tool_choice": "auto",
            "parallel_tool_calls": true,
            "tools": tools_json,
        });

        eprintln!(
            "\x1b[2m[api] Codex → {endpoint} (account: {}...)\x1b[0m",
            &account_id[..account_id.len().min(8)]
        );

        self.tokio_rt.block_on(async {
            use futures_util::StreamExt;
            let mut last_err = String::new();

            for attempt in 0..5u32 {
                if attempt > 0 {
                    let wait = std::time::Duration::from_secs(2u64.pow(attempt - 1));
                    eprintln!(
                        "\x1b[2m[api] retrying in {}s ({}/5)...\x1b[0m",
                        wait.as_secs(),
                        attempt + 1
                    );
                    tokio::time::sleep(wait).await;
                    // A Ctrl+C pressed while waiting out a transient/rate-limit
                    // backoff shouldn't carry forward as a hard-abort once the
                    // retry actually starts doing real work.
                    agent_interrupted().store(false, Ordering::Relaxed);
                }

                let resp = match http
                    .post(&endpoint)
                    .header("Authorization", format!("Bearer {api_key}"))
                    .header("chatgpt-account-id", &account_id)
                    .header("originator", "pi")
                    .header("OpenAI-Beta", "responses=experimental")
                    .header("accept", "text/event-stream")
                    .header("content-type", "application/json")
                    .json(&body)
                    .send()
                    .await
                {
                    Err(e) => {
                        last_err = format!("request failed: {e}");
                        continue;
                    }
                    Ok(r) => r,
                };

                let status = resp.status();
                if matches!(status.as_u16(), 500 | 502 | 503 | 504 | 529) {
                    let text = resp.text().await.unwrap_or_default();
                    last_err = format!("server error {status}: {text}");
                    continue;
                }
                if status.as_u16() == 429 {
                    let retry_secs = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(10)
                        .min(120);
                    let text = resp.text().await.unwrap_or_default();
                    last_err = format!("{status}: {text}");
                    eprintln!("{C_STONE}[api] rate limited — waiting {retry_secs}s…{C_RESET}");
                    tokio::time::sleep(std::time::Duration::from_secs(retry_secs)).await;
                    agent_interrupted().store(false, Ordering::Relaxed);
                    continue;
                }
                if !status.is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    return Err(RuntimeError::new(format!(
                        "responses api returned {status}: {text}"
                    )));
                }

                // ── Parse Responses API SSE stream ──────────────────────────────
                let mut events: Vec<AssistantEvent> = Vec::new();
                let mut stream = resp.bytes_stream();
                let mut buf = String::new();
                // Track the in-progress function call (only one at a time for our use case)
                let mut pending_call: Option<(String, String)> = None; // (call_id, name)
                let mut thinking = Some(ThinkingSpinner::start(format!(
                    "{C_TEAL}Thinking…{C_RESET}"
                )));

                'sse: while let Some(chunk) = stream.next().await {
                    let chunk = match chunk {
                        Ok(c) => c,
                        Err(e) => {
                            last_err = format!("stream read: {e}");
                            break 'sse;
                        }
                    };
                    buf.push_str(&String::from_utf8_lossy(&chunk));

                    while let Some(nl) = buf.find('\n') {
                        let line = buf[..nl].trim().to_string();
                        buf = buf[nl + 1..].to_string();

                        if line.is_empty() || line.starts_with(':') {
                            continue;
                        }
                        let Some(data) = line.strip_prefix("data: ") else {
                            continue;
                        };
                        if data == "[DONE]" {
                            break 'sse;
                        }

                        let val: Value = match serde_json::from_str(data) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };

                        match val["type"].as_str().unwrap_or("") {
                            // ── Text streaming ────────────────────────────────────
                            "response.output_text.delta" => {
                                if let Some(delta) = val["delta"].as_str() {
                                    if !delta.is_empty() {
                                        if let Some(t) = thinking.take() {
                                            t.stop();
                                        }
                                    }
                                    events.push(AssistantEvent::TextDelta(delta.to_string()));
                                }
                            }
                            // Older content_part format (kept for compatibility)
                            "response.content_part.delta" => {
                                if val["delta"]["type"].as_str() == Some("text") {
                                    if let Some(text) = val["delta"]["text"].as_str() {
                                        if !text.is_empty() {
                                            if let Some(t) = thinking.take() {
                                                t.stop();
                                            }
                                        }
                                        events.push(AssistantEvent::TextDelta(text.to_string()));
                                    }
                                }
                            }
                            // ── Function call lifecycle ───────────────────────────
                            // Step 1: item announced (name known, args empty)
                            "response.output_item.added" => {
                                let item = &val["item"];
                                if item["type"].as_str() == Some("function_call") {
                                    let call_id = item["call_id"]
                                        .as_str()
                                        .or_else(|| item["id"].as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let name = item["name"].as_str().unwrap_or("").to_string();
                                    pending_call = Some((call_id, name));
                                }
                            }
                            // Step 2: arguments complete — emit ToolUse
                            "response.function_call_arguments.done" => {
                                if let Some((call_id, name)) = pending_call.take() {
                                    if let Some(t) = thinking.take() {
                                        t.stop();
                                    }
                                    let args =
                                        val["arguments"].as_str().unwrap_or("{}").to_string();
                                    let mut stdout = io::stdout();
                                    let display = format_ctf_tool_call(&name, &args);
                                    let _ = writeln!(stdout, "\n{display}");
                                    let _ = stdout.flush();
                                    events.push(AssistantEvent::ToolUse {
                                        id: call_id,
                                        name,
                                        input: args,
                                    });
                                }
                            }
                            // Fallback: item done carries complete function call
                            "response.output_item.done" => {
                                let item = &val["item"];
                                if item["type"].as_str() == Some("function_call")
                                    && pending_call.is_some()
                                {
                                    if let Some(t) = thinking.take() {
                                        t.stop();
                                    }
                                    let (call_id, name) = pending_call.take().unwrap();
                                    let args =
                                        item["arguments"].as_str().unwrap_or("{}").to_string();
                                    let mut stdout = io::stdout();
                                    let display = format_ctf_tool_call(&name, &args);
                                    let _ = writeln!(stdout, "\n{display}");
                                    let _ = stdout.flush();
                                    events.push(AssistantEvent::ToolUse {
                                        id: call_id,
                                        name,
                                        input: args,
                                    });
                                }
                            }
                            // ── Usage + completion ────────────────────────────────
                            "response.completed" => {
                                let usage = &val["response"]["usage"];
                                events.push(AssistantEvent::Usage(TokenUsage {
                                    input_tokens: usage["input_tokens"].as_u64().unwrap_or(0)
                                        as u32,
                                    output_tokens: usage["output_tokens"].as_u64().unwrap_or(0)
                                        as u32,
                                    cache_creation_input_tokens: 0,
                                    cache_read_input_tokens: 0,
                                }));
                                events.push(AssistantEvent::MessageStop);
                            }
                            "response.failed" | "response.incomplete" => {
                                let msg = val["response"]["error"]["message"]
                                    .as_str()
                                    .unwrap_or("response failed")
                                    .to_string();
                                last_err = msg;
                                break 'sse;
                            }
                            _ => {}
                        }
                    }
                }

                if !events
                    .iter()
                    .any(|e| matches!(e, AssistantEvent::MessageStop))
                {
                    if events.iter().any(|e| {
                        matches!(
                            e,
                            AssistantEvent::TextDelta(_) | AssistantEvent::ToolUse { .. }
                        )
                    }) {
                        events.push(AssistantEvent::MessageStop);
                    } else {
                        last_err = if last_err.is_empty() {
                            "empty response".to_string()
                        } else {
                            last_err
                        };
                        continue;
                    }
                }

                return Ok(events);
            }

            Err(RuntimeError::new(format!("responses api: {last_err}")))
        })
    }
}

/// Print the last `n` non-tool messages from the session as a compact chat replay.
/// Print session history.
/// `n` = max number of messages to show (use `usize::MAX` for all).
/// `max_lines_per_msg` = max lines per assistant message (`usize::MAX` for full).
// `renderer` (the markdown renderer) vs `rendered` (its string output) are
// distinct despite the one-character difference.
#[allow(clippy::similar_names)]
fn print_session_tail(session: &Session, n: usize, max_lines_per_msg: usize) {
    let renderer = TerminalRenderer::new();

    let exchanges: Vec<_> = session
        .messages
        .iter()
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
                            println!(
                                "{C_STONE}  you ›{C_RESET} {C_DIM}{}{C_RESET}",
                                trimmed
                                    .lines()
                                    .next()
                                    .unwrap_or("")
                                    .chars()
                                    .take(120)
                                    .collect::<String>()
                            );
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
                    println!(
                        "{C_TEAL}  agent ›{C_RESET} {C_DIM}[{}]{C_RESET}",
                        tool_names.join(", ")
                    );
                }
                if !text.trim().is_empty() {
                    let rendered = renderer.markdown_to_ansi(text.trim());
                    let lines: Vec<&str> = rendered.lines().collect();
                    let show = lines.len().min(max_lines_per_msg);
                    for line in &lines[..show] {
                        println!("    {line}");
                    }
                    if lines.len() > show {
                        println!("    {C_DIM}… ({} more lines){C_RESET}", lines.len() - show);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Returns a unique `logs/<timestamp>.txt` path for the current run.
/// The timestamp is UTC: `YYYY-MM-DD_HH-MM-SS`.
fn new_log_path(logs_dir: &Path) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = format!("{}.txt", utc_datetime_str(ts));
    // Guard against sub-second collisions (unlikely but safe).
    let base = logs_dir.join(&name);
    if !base.exists() {
        return base;
    }
    for n in 2u32.. {
        let p = logs_dir.join(format!("{}_{n}.txt", utc_datetime_str(ts)));
        if !p.exists() {
            return p;
        }
    }
    base
}

/// Format a Unix timestamp (seconds, UTC) as `YYYY-MM-DD_HH-MM-SS`.
fn utc_datetime_str(ts: u64) -> String {
    let sec = ts % 60;
    let min = (ts / 60) % 60;
    let hour = (ts / 3600) % 24;
    let days = ts / 86400; // days since 1970-01-01

    let (year, doy) = {
        let mut y = 1970u64;
        let mut rem = days;
        loop {
            let dy = if y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400)) {
                366
            } else {
                365
            };
            if rem < dy {
                break (y, rem);
            }
            rem -= dy;
            y += 1;
        }
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days: [u64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let (month, day) = {
        let mut rem = doy;
        let mut m = 1u64;
        for &md in &month_days {
            if rem < md {
                break;
            }
            rem -= md;
            m += 1;
        }
        (m, rem + 1)
    };
    format!("{year:04}-{month:02}-{day:02}_{hour:02}-{min:02}-{sec:02}")
}

/// Ensure a JSON Schema is valid for Responses API `strict: true` mode:
///   1. Add `additionalProperties: false` if absent
///   2. Strip property names with special characters (dashes, etc.) —
///      these cause 500/422 in strict mode validation
///   3. Also remove them from `required` if they were there
#[allow(dead_code)]
fn sanitize_schema_for_strict(mut schema: Value) -> Value {
    let Some(obj) = schema.as_object_mut() else {
        return schema;
    };

    // Ensure additionalProperties: false
    obj.entry("additionalProperties").or_insert(json!(false));

    // Collect bad property names (anything not alphanumeric or underscore)
    let bad_keys: Vec<String> = obj
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|props| {
            props
                .keys()
                .filter(|k| k.chars().any(|c| !c.is_alphanumeric() && c != '_'))
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    if !bad_keys.is_empty() {
        if let Some(props) = obj.get_mut("properties").and_then(|p| p.as_object_mut()) {
            for key in &bad_keys {
                props.remove(key);
            }
        }
        // Remove from required too
        if let Some(req) = obj.get_mut("required").and_then(|r| r.as_array_mut()) {
            req.retain(|v| !bad_keys.iter().any(|k| v.as_str() == Some(k)));
        }
    }

    schema
}

fn strip_code_fences(s: &str) -> &str {
    let s = s.trim();
    // Strip ```json ... ``` or ``` ... ```
    if let Some(inner) = s.strip_prefix("```") {
        let after_lang = inner
            .trim_start_matches(|c: char| c.is_alphabetic())
            .trim_start_matches('\n');
        if let Some(body) = after_lang.strip_suffix("```") {
            return body.trim();
        }
    }
    s
}

fn render_export(session: &Session, divider: &str) -> String {
    let mut out = String::new();
    let mut turn = 0usize;

    for msg in &session.messages {
        match msg.role {
            MessageRole::System => {}
            MessageRole::User => {
                let texts: Vec<&str> = msg
                    .blocks
                    .iter()
                    .filter_map(|b| {
                        if let ContentBlock::Text { text } = b {
                            Some(text.as_str())
                        } else {
                            None
                        }
                    })
                    .collect();
                let joined = texts.join("\n").trim().to_string();
                if joined.is_empty() {
                    continue;
                }
                turn += 1;
                out.push_str(&format!(
                    "\n{divider}\n[Turn {turn}] YOU\n{divider}\n{joined}\n"
                ));
            }
            MessageRole::Assistant => {
                out.push_str(&format!("\n{divider}\n[Turn {turn}] AGENT\n{divider}\n"));
                for block in &msg.blocks {
                    match block {
                        ContentBlock::Text { text } if !text.trim().is_empty() => {
                            out.push_str(text.trim());
                            out.push('\n');
                        }
                        ContentBlock::ToolUse { name, input, .. } => {
                            let args: Value = serde_json::from_str(input).unwrap_or(Value::Null);
                            out.push_str(&format!("\n  ▶ {name}"));
                            match name.as_str() {
                                "bash" => {
                                    if let Some(cmd) = args.get("command").and_then(Value::as_str) {
                                        out.push_str(&format!("\n    $ {}\n", cmd.trim()));
                                    }
                                }
                                "read_file" | "write_file" => {
                                    if let Some(p) = args.get("path").and_then(Value::as_str) {
                                        out.push_str(&format!("  {p}\n"));
                                    }
                                }
                                _ => {
                                    out.push_str(&format!("  {input}\n"));
                                }
                            }
                        }
                        ContentBlock::ToolResult {
                            tool_name, output, ..
                        } => {
                            let preview: String =
                                output.lines().take(20).collect::<Vec<_>>().join("\n");
                            let extra = output.lines().count().saturating_sub(20);
                            out.push_str(&format!(
                                "  ◀ {tool_name}\n    {}",
                                preview.replace('\n', "\n    ")
                            ));
                            if extra > 0 {
                                out.push_str(&format!("\n    … ({extra} more lines)"));
                            }
                            out.push('\n');
                        }
                        // Empty-text Text blocks (the guarded arm above skips them).
                        ContentBlock::Text { .. } => {}
                    }
                }
            }
            MessageRole::Tool => {
                for block in &msg.blocks {
                    if let ContentBlock::ToolResult {
                        tool_name, output, ..
                    } = block
                    {
                        let preview: String =
                            output.lines().take(20).collect::<Vec<_>>().join("\n");
                        let extra = output.lines().count().saturating_sub(20);
                        out.push_str(&format!(
                            "  ◀ {tool_name}\n    {}",
                            preview.replace('\n', "\n    ")
                        ));
                        if extra > 0 {
                            out.push_str(&format!("\n    … ({extra} more lines)"));
                        }
                        out.push('\n');
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn think_filter_all(f: &mut ThinkFilter, chunks: &[&str]) -> String {
        chunks.iter().map(|c| f.push(c)).collect()
    }

    #[test]
    fn parses_html_comment_action_tool_call() {
        let calls = fallback_tool_calls_from_text(
            r#"<!-- {"action":"call_tool","tool":"bash","arguments":{"command":"ls"}} -->"#,
        );
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "bash");
        assert!(calls[0].input.contains("\"command\""));
    }

    #[test]
    fn parses_html_comment_challenge_recon() {
        let calls = fallback_tool_calls_from_text(
            r#"<!-- {"action":"call_tool","tool":"challenge_recon","arguments":{}} -->"#,
        );
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "challenge_recon");
    }

    #[test]
    fn parses_tool_code_name_parameters_body() {
        // The exact malformed shape Qwythos emits (with curly smart quotes).
        let calls = fallback_tool_calls_from_text(
            "<tool_code>\nname=\u{201c}grep_search\u{201d}, parameters={\u{201c}pattern\u{201d}:\u{201c}flag\u{201d},\u{201c}path\u{201d}:\u{201c}./files\u{201d}}\n</tool_code>",
        );
        assert!(calls.iter().any(|c| c.name == "grep_search"
            && c.input.contains("flag")
            && c.input.contains("./files")));
    }

    #[test]
    fn html_comment_rejects_unknown_tool() {
        let calls = fallback_tool_calls_from_text(
            r#"<!-- {"action":"call_tool","tool":"not_a_real_tool","arguments":{}} -->"#,
        );
        assert!(calls.is_empty());
    }

    #[test]
    fn think_filter_strips_inline_block() {
        let mut f = ThinkFilter::default();
        assert_eq!(
            f.push("before <think>secret reasoning</think> after"),
            "before  after"
        );
    }

    #[test]
    fn think_filter_handles_tag_split_across_chunks() {
        let mut f = ThinkFilter::default();
        // Tags arrive split mid-token across deltas.
        let out = think_filter_all(&mut f, &["vis<thi", "nk>hidden<", "/think>tail"]);
        assert_eq!(out, "vistail");
    }

    #[test]
    fn think_filter_drops_implicit_leading_reasoning() {
        let mut f = ThinkFilter::default();
        // Model begins in reasoning mode: no opening tag, only a closing one.
        let pre = f.push("planning the attack...");
        assert_eq!(pre, "planning the attack...");
        let post = f.push("</think>FLAG: real answer");
        assert!(f.drop_preceding, "should request dropping pre-close text");
        assert_eq!(post, "FLAG: real answer");
    }

    #[test]
    fn think_filter_preserves_non_tag_angle_brackets() {
        let mut f = ThinkFilter::default();
        assert_eq!(f.push("a < b && c <html>"), "a < b && c <html>");
    }

    fn green_executor() -> CtfToolExecutor {
        CtfToolExecutor {
            python_repl: None,
            challenge_name: "Green".to_string(),
            challenge_dir: PathBuf::from("/tmp/bench/work/Green"),
            challenge_file_names: vec!["GreenGoblin.7z".to_string()],
        }
    }

    #[test]
    fn normalizes_qwythos_bad_redirect_and_missing_files_prefix() {
        let executor = green_executor();
        let (command, notes) = executor.normalize_bash_command(
            r"head -c 10 ./GreenGoblin.7z > /dev/null 2>& true
file ./GreenGoblin.7z > /dev/null 2>& true;",
        );

        assert!(command.contains("./files/GreenGoblin.7z"));
        assert!(!command.contains("2>& true"));
        assert!(command.contains("2>/dev/null || true"));
        assert!(!notes.is_empty());
    }

    #[test]
    fn normalizes_qwythos_files_dot_and_empty_head_arg() {
        let executor = green_executor();
        let (command, _) = executor.normalize_bash_command(
            r#"head -c 150 "" /tmp/bench/work/Green/files./GreenGoblin.7z 2>/dev/null | cat -v"#,
        );

        assert!(command.contains("/tmp/bench/work/Green/files/GreenGoblin.7z"));
        assert!(!command.contains(r#"150 "" "#));
        assert!(!command.contains("files./"));
    }

    #[test]
    fn rejects_qwythos_bare_option_as_bash_command() {
        let executor = green_executor();
        let reason = executor.malformed_bash_command_reason("-cfd -t all ./files/GreenGoblin.7z");

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("executable"));
    }

    #[test]
    fn recursive_grep_excludes_solver_artifacts_after_include() {
        let executor = green_executor();
        let (command, notes) =
            executor.normalize_bash_command(r#"grep -r "FLAG" . --include="*"; true"#);

        assert!(command.contains(r#"--include="*" --exclude='.ctf-session.json'"#));
        assert!(command.contains("--exclude-dir='logs'; true"));
        assert!(notes
            .iter()
            .any(|note| note.contains("internal session/log files")));
    }

    #[test]
    fn recursive_grep_excludes_all_occurrences() {
        let executor = green_executor();
        let (command, _) = executor.normalize_bash_command(r"grep -R foo .; grep -R bar .");

        assert_eq!(command.matches("--exclude-dir='logs'").count(), 2);
    }

    #[test]
    fn non_recursive_grep_does_not_get_artifact_excludes_from_path_text() {
        let executor = green_executor();
        let (command, notes) = executor.normalize_bash_command(
            r"grep -oa 'flag{[^}]*\}' ./files/chals/Payload/HermesChallenge.app/main.jsbundle | head -c 2000",
        );

        assert!(!command.contains("--exclude='.ctf-session.json'"));
        assert!(notes
            .iter()
            .all(|note| !note.contains("internal session/log files")));
    }

    #[test]
    fn normalizes_qwythos_fd_duplication_and_devnull_path() {
        let executor = green_executor();
        let (command, notes) = executor.normalize_bash_command(
            r#"while IFS= read -r fname; do echo "$fname"; done <&1 >dev/null 2>dev/null"#,
        );

        assert!(!command.contains("<&1"));
        assert!(command.contains(">/dev/null"));
        assert!(command.contains("2>/dev/null"));
        assert!(notes
            .iter()
            .any(|note| note.contains("stdin fd duplication")));
    }

    #[test]
    fn normalizes_qwythos_bad_fd_and_linux_typos() {
        let executor = green_executor();
        let (command, notes) = executor.normalize_bash_command(
            r#"strings ./files/GreenGoblin.7z -t | fgrep -iE "flag|key" | sortU 7>&1 2>&5; dd if=/dev/char/GreenGoblin.7z bs=1 count=8 offset=64"#,
        );

        assert!(command.contains("strings -t x ./files/GreenGoblin.7z"));
        assert!(command.contains(r#"grep -iE "flag|key""#));
        assert!(command.contains("sort -u"));
        assert!(!command.contains("7>&1"));
        assert!(command.contains("2>&1"));
        assert!(command.contains("if=./files/GreenGoblin.7z"));
        assert!(command.contains("skip=64"));
        assert!(!notes.is_empty());
    }

    #[test]
    fn normalizes_qwythos_bad_strings_radix_options() {
        let executor = green_executor();
        let (command, notes) = executor.normalize_bash_command(
            r"strings -a -t x20 -n 4 ./files/chals/Payload/HermesChallenge.app/main.jsbundle; strings -tf ./tmp/debug/main.jsbundle",
        );

        assert!(command.contains("strings -a -t x -n 4"));
        assert!(command.contains("strings -t x ./tmp/debug/main.jsbundle"));
        assert!(notes.iter().any(|note| note.contains("strings -t xN")));
        assert!(notes.iter().any(|note| note.contains("strings -tf")));
    }

    #[test]
    fn normalizes_unzip_from_tmp_wrong_relative_files_path() {
        let executor = green_executor();
        let (command, notes) =
            executor.normalize_bash_command(r"cd ./tmp/unpack && unzip -q ../files/chals.zip");

        assert_eq!(
            command,
            "mkdir -p ./tmp/unpack && unzip -q ./files/chals.zip -d ./tmp/unpack"
        );
        assert!(notes.iter().any(|note| note.contains("rewrote unzip")));
    }

    #[test]
    fn rejects_qwythos_pipe_fd_hallucination() {
        let executor = green_executor();
        let reason =
            executor.malformed_bash_command_reason(r#"cat /dev/fd$(cat - <<< "$PIPE_FD") | head"#);

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("PIPE_FD"));
    }

    #[test]
    fn rejects_qwythos_checksec_on_archive() {
        let executor = green_executor();
        let reason = executor.malformed_bash_command_reason(
            r"file ./files/GreenGoblin.7z; checksec -e PIE -a ./files/GreenGoblin.7z",
        );

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("ELF"));
    }

    #[test]
    fn rejects_qwythos_hallucinated_shell_tools() {
        let executor = green_executor();
        let reason = executor.malformed_bash_command_reason(
            r"7z l ./files/GreenGoblin.7z; check-file-types ./files/GreenGoblin.7z; pathglob '*.plist'",
        );

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("not an available command"));
    }

    #[test]
    fn rejects_qwythos_undefined_path_variables() {
        let executor = green_executor();
        let files_reason =
            executor.malformed_bash_command_reason(r#"file "${files/GreenGoblin.*},/dev/null""#);
        let tmp_reason = executor.malformed_bash_command_reason(r#"strings "$TMP" | head"#);

        assert!(files_reason.is_some());
        assert!(files_reason.unwrap().contains("undefined `files`"));
        assert!(tmp_reason.is_some());
        assert!(tmp_reason.unwrap().contains("undefined `TMP`"));
    }

    #[test]
    fn rejects_qwythos_fake_date_and_empty_substitution() {
        let executor = green_executor();
        let date_reason = executor.malformed_bash_command_reason(r#"echo "$(stddate)""#);
        let empty_reason = executor.malformed_bash_command_reason(r#"echo "count: $()""#);

        assert!(date_reason.is_some());
        assert!(date_reason.unwrap().contains("not an available command"));
        assert!(empty_reason.is_some());
        assert!(empty_reason.unwrap().contains("empty command substitution"));
    }

    #[test]
    fn rejects_qwythos_binary_dump_to_notes() {
        let executor = green_executor();
        let reason = executor.malformed_bash_command_reason(r"cat files/GreenGoblin.7z > notes.md");

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("raw challenge binaries"));
    }

    #[test]
    fn rejects_qwythos_wrong_benchmark_workspace_path() {
        let executor = green_executor();
        let reason = executor.malformed_bash_command_reason(
            r"tail -c +1 files/GreenGoblin.7z >/tmp/claw-ctf-bench-qwythos32-fix4-Green/tmp/raw",
        );

        assert!(reason.is_some());
        assert!(reason
            .unwrap()
            .contains("outside the current challenge workspace"));
    }

    #[test]
    fn rejects_qwythos_guessed_relative_benchmark_path() {
        let executor = green_executor();
        let reason = executor.malformed_bash_command_reason(
            r#"grep -ri "FLAG{" ./tmp/claw-ctf-bench-qwythos32-fix5-Green/work/files"#,
        );

        assert!(reason.is_some());
    }

    #[test]
    fn rejects_qwythos_wrong_agent_workspace_path() {
        let executor = green_executor();
        let reason = executor.malformed_bash_command_reason(
            r"strings /tmp/claw-ctf-agent-unsolved-q8/work/Green/files/GreenGoblin.7z | head",
        );

        assert!(reason.is_some());
        assert!(reason
            .unwrap()
            .contains("outside the current challenge workspace"));
    }

    #[test]
    fn rejects_qwythos_generic_tmp_paths_outside_workspace() {
        let executor = green_executor();
        let reason =
            executor.malformed_bash_command_reason(r"cd /tmp && rm -rf extract2; mkdir extract2");
        let current_tmp = CtfToolExecutor {
            python_repl: None,
            challenge_name: "Green".to_string(),
            challenge_dir: PathBuf::from("/tmp/bench/work/Green"),
            challenge_file_names: vec![],
        }
        .malformed_bash_command_reason(r"ls /tmp/bench/work/Green/tmp");

        assert!(reason.is_some());
        assert!(reason
            .unwrap()
            .contains("outside the current challenge workspace"));
        assert!(current_tmp.is_none());
    }

    #[test]
    fn allows_current_agent_workspace_absolute_path() {
        let executor = CtfToolExecutor {
            python_repl: None,
            challenge_name: "Green".to_string(),
            challenge_dir: PathBuf::from("/tmp/claw-ctf-agent-rerun-fix1/work/ttv2026/crypto/LSFR"),
            challenge_file_names: vec!["gen.py".to_string()],
        };
        let reason = executor.malformed_bash_command_reason(
            r"python3 /tmp/claw-ctf-agent-rerun-fix1/work/ttv2026/crypto/LSFR/files/gen.py",
        );

        assert!(reason.is_none());
    }

    #[test]
    fn rejects_qwythos_unavailable_linux_commands() {
        let executor = green_executor();
        let findstr_reason =
            executor.malformed_bash_command_reason(r#"findstr /spin "flag" ./files/*"#);
        let rfd_reason = executor.malformed_bash_command_reason(r"rfd -a flag ./files");
        let ltrace_reason =
            executor.malformed_bash_command_reason(r"ltrace ./files/GreenGoblin.7z");

        assert!(findstr_reason.is_some());
        assert!(findstr_reason.unwrap().contains("not available"));
        assert!(rfd_reason.is_some());
        assert!(rfd_reason.unwrap().contains("not available"));
        assert!(ltrace_reason.is_some());
        assert!(ltrace_reason.unwrap().contains("not available"));
    }

    #[test]
    fn rejects_qwythos_tool_api_as_shell_command() {
        let executor = green_executor();
        let reason = executor.malformed_bash_command_reason(r"binary_recon ./files/a.out");

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("not a shell executable"));
    }

    #[test]
    fn rejects_unbounded_challenge_generator() {
        let executor = green_executor();
        let reason = executor.malformed_bash_command_reason(
            r"python3 ./files/gen.py 2>&1 | tee ./tmp/gen_out.txt >> notes.md",
        );
        let timed_reason =
            executor.malformed_bash_command_reason(r"timeout 10s python3 ./files/gen.py");

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("without an explicit timeout"));
        assert!(timed_reason.is_none());
    }

    #[test]
    fn rejects_workspace_root_find() {
        let executor = green_executor();
        let reason = executor.malformed_bash_command_reason(r"find . -type f -print");
        let files_reason = executor.malformed_bash_command_reason(r"find ./files -type f -print");

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("find ./files -type f"));
        assert!(files_reason.is_none());
    }

    #[test]
    fn rejects_notes_write_file_overwrite() {
        let dir = std::env::temp_dir().join(format!("ctf-cli-notes-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("files")).unwrap();
        fs::write(dir.join("notes.md"), "# Green\n\n## Challenge Info\n").unwrap();
        let executor = CtfToolExecutor {
            python_repl: None,
            challenge_name: "Green".to_string(),
            challenge_dir: dir.clone(),
            challenge_file_names: vec![],
        };
        let reason = executor.destructive_notes_write_violation(
            "write_file",
            &json!({"path": "./notes.md", "content": "## Recon Findings\n"}),
        );
        let _ = fs::remove_dir_all(&dir);

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("replace the workspace notes.md"));
    }

    #[test]
    fn rejects_webfetch_for_local_files() {
        let reason = CtfToolExecutor::local_file_webfetch_violation(
            "WebFetch",
            &json!({"url": "./files/docker-compose.yml"}),
        );

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("only for http"));
    }

    #[test]
    fn challenge_recon_reads_files_only() {
        let dir = std::env::temp_dir().join(format!("ctf-cli-recon-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("files")).unwrap();
        fs::write(
            dir.join("files/app.py"),
            "SECRET_TOKEN='abc'\nprint('hi')\n",
        )
        .unwrap();
        fs::write(dir.join("notes.md"), "FLAG{solver-artifact}\n").unwrap();

        let out = ctf_challenge_recon(&dir, 20);
        let _ = fs::remove_dir_all(&dir);

        assert!(out.contains("./files/app.py"));
        assert!(out.contains("SECRET_TOKEN"));
        assert!(!out.contains("solver-artifact"));
    }

    #[test]
    fn challenge_recon_prioritizes_mobile_app_files() {
        let dir =
            std::env::temp_dir().join(format!("ctf-cli-mobile-recon-test-{}", std::process::id()));
        let app = dir.join("files/chals/Payload/HermesChallenge.app");
        let framework = app.join("Frameworks/React.framework");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&framework).unwrap();
        fs::write(
            app.join("main.jsbundle"),
            "const secret='FLAG{from_bundle}'\n",
        )
        .unwrap();
        fs::write(
            app.join("Info.plist"),
            "<plist><key>CFBundleName</key></plist>\n",
        )
        .unwrap();
        fs::write(framework.join("React"), "FLAG{vendor_noise}\n").unwrap();

        let out = ctf_challenge_recon(&dir, 20);
        let _ = fs::remove_dir_all(&dir);

        assert!(out.find("main.jsbundle").unwrap() < out.find("React.framework").unwrap());
        assert!(out.contains("FLAG{from_bundle}"));
        assert!(!out.contains("FLAG{vendor_noise}"));
    }

    #[test]
    fn extract_archive_rejects_non_files_path() {
        let dir = std::env::temp_dir().join(format!("ctf-cli-extract-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("files")).unwrap();

        let err = ctf_extract_archive(&dir, "./notes.zip", None).unwrap_err();
        let _ = fs::remove_dir_all(&dir);

        assert!(err.contains("under ./files"));
    }

    #[test]
    fn parses_new_tool_pseudo_calls() {
        let recon = pseudo_function_tool_call("challenge_recon(max_files=42)").unwrap();
        let extract =
            pseudo_function_tool_call("extract_archive(path='./files/chals.zip')").unwrap();

        assert_eq!(recon.name, "challenge_recon");
        assert!(recon.input.contains("42"));
        assert_eq!(extract.name, "extract_archive");
        assert!(extract.input.contains("chals.zip"));
    }

    #[test]
    fn parses_natural_language_recon_intent() {
        let calls = natural_language_tool_calls(
            "Action: invoke challenge_recon on ./files before custom shell.",
        );

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "challenge_recon");
    }

    #[test]
    fn parses_natural_language_extract_intent() {
        let calls =
            natural_language_tool_calls("Next call extract_archive path=./files/chals.zip.");

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "extract_archive");
        assert!(calls[0].input.contains("./files/chals.zip"));
    }

    #[test]
    fn parses_invoke_bash_and_extract_tags() {
        let calls = invoke_tool_calls(
            r#"<invoke name="bash">echo hi</invoke>
<invoke name="extract_archive">path=./files/chals.zip output_dir=./tmp/chals</invoke>"#,
        );

        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].name, "bash");
        assert!(calls[0].input.contains("echo hi"));
        assert_eq!(calls[1].name, "extract_archive");
        assert!(calls[1].input.contains("./files/chals.zip"));
        assert!(calls[1].input.contains("./tmp/chals"));
    }

    #[test]
    fn parses_invoke_parameter_tags_for_grep_search() {
        let calls = invoke_tool_calls(
            r#"<invoke name="grep_search">
<parameter=glob>
./files/chals/Payload/HermesChallenge.app/main.jsbundle
</parameter>
<parameter=pattern>
-F 'flag{' -i
</parameter>
</function>"#,
        );

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "grep_search");
        let input: Value = serde_json::from_str(&calls[0].input).unwrap();
        assert_eq!(
            input.get("pattern").and_then(Value::as_str).unwrap(),
            r"(?i)flag\{"
        );
        assert_eq!(
            input.get("path").and_then(Value::as_str).unwrap(),
            "./files/chals/Payload/HermesChallenge.app/main.jsbundle"
        );
    }

    #[test]
    fn parses_qwythos_tool_code_parameter_args() {
        let calls = fallback_tool_calls_from_text(
            r#"<tool_code>grep_search</tool_code><parameter_args>{"path": "./files/app.plist", "pattern": "\"STRING[0-9]+\":\s*\"[^\"]{18,5}\"|passcode"}</parameter_args>"#,
        );

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "grep_search");
        assert!(calls[0].input.contains("./files/app.plist"));
        assert!(calls[0].input.contains("18,5"));
    }

    #[test]
    fn parses_qwythos_smart_quote_parameter_args() {
        let calls = fallback_tool_calls_from_text(
            "<tool_code>grep_search</tool_code><parameter_args>{\"path\": \"./files/app.plist\", \"pattern\": \"passcode|Flag\\s+value\"}",
        );

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "grep_search");
        assert!(calls[0].input.contains("passcode"));
        assert!(calls[0].input.contains("./files/app.plist"));
    }

    #[test]
    fn parses_qwythos_run_directive_as_bash() {
        let calls = fallback_tool_calls_from_text(
            "$run strings ./files/chals/Payload/HermesChallenge.app/* 2>/dev/null | grep -i flag\\|secret\n<parameter=description>probe</parameter>",
        );

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "bash");
        assert!(calls[0].input.contains("strings ./files/chals"));
        assert!(calls[0].input.contains("grep -i"));
    }

    #[test]
    fn parses_qwythos_run_directive_tool_command() {
        let calls = fallback_tool_calls_from_text(
            "$run glob_search pattern='*.log' /tmp/claw-ctf-agent-rerun/work/ttv2026/rev/iphone/files/chals",
        );

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "glob_search");
        assert!(calls[0].input.contains("*.log"));
        assert!(calls[0].input.contains("/tmp/claw-ctf-agent-rerun"));
    }

    #[test]
    fn rejects_bash_notes_overwrite_redirect() {
        let executor = green_executor();
        let reason = executor.malformed_bash_command_reason(r": > notes.md");
        let append_reason = executor.malformed_bash_command_reason(r"echo ok >> notes.md");
        let absolute_append =
            executor.malformed_bash_command_reason(r"echo ok >> /tmp/bench/work/Green/notes.md");

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("Do not overwrite notes.md"));
        assert!(append_reason.is_none());
        assert!(absolute_append.is_none());
    }

    #[test]
    fn rejects_qwythos_csh_style_notes_overwrite_redirect() {
        let executor = green_executor();
        let reason =
            executor.malformed_bash_command_reason(r#">& notes.md echo "--- iOS STATIC ---""#);
        let absolute = executor.malformed_bash_command_reason(
            r#"&> /tmp/bench/work/Green/notes.md echo "--- iOS STATIC ---""#,
        );

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("Do not overwrite notes.md"));
        assert!(absolute.is_some());
    }

    #[test]
    fn rejects_qwythos_strscan_and_read_path() {
        let executor = green_executor();
        let strscan_reason =
            executor.malformed_bash_command_reason(r"strscan -f -i chals.zip ./files");
        let read_reason =
            executor.malformed_bash_command_reason(r"read ./tmp/strscan --text ./files/chals.zip");

        assert!(strscan_reason.is_some());
        assert!(strscan_reason.unwrap().contains("not available"));
        assert!(read_reason.is_some());
        assert!(read_reason
            .unwrap()
            .contains("cannot read from a file path"));
    }

    #[test]
    fn rejects_qwythos_unavailable_hermes_reverse_tools() {
        let executor = green_executor();
        let rncat_reason =
            executor.malformed_bash_command_reason(r"rncat -h ./files/main.jsbundle");
        let rbin2_reason = executor.malformed_bash_command_reason(r"rbin2 -Z Assets.car");
        let allowed_path = executor.malformed_bash_command_reason(
            r"strings ./files/chals/Payload/HermesChallenge.app/Frameworks/hermes.framework/hermes | head",
        );

        assert!(rncat_reason.is_some());
        assert!(rncat_reason.unwrap().contains("not installed"));
        assert!(rbin2_reason.is_some());
        assert!(allowed_path.is_none());
    }

    #[test]
    fn rejects_qwythos_malformed_binary_probe_commands() {
        let executor = green_executor();
        let xxd_reason = executor.malformed_bash_command_reason(r"xxd . -g 1 ./files/Info.plist");
        let base64_reason = executor.malformed_bash_command_reason(r"base64 -d .");
        let rabin2_reason = executor.malformed_bash_command_reason(r"rabin2 -z head-c 1000");
        let sed_reason = executor.malformed_bash_command_reason(r"sed i 'before'");

        assert!(xxd_reason.is_some());
        assert!(base64_reason.is_some());
        assert!(rabin2_reason.is_some());
        assert!(sed_reason.is_some());
    }

    #[test]
    fn normalizes_small_tool_timeout_as_seconds() {
        assert_eq!(normalize_tool_timeout_ms(120), 120_000);
        assert_eq!(normalize_tool_timeout_ms(30_000), 30_000);
    }

    #[test]
    fn rejects_bash_syntax_errors_before_execution() {
        let executor = green_executor();
        let reason = executor.malformed_bash_command_reason("if true; then echo yes");

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("Bash syntax check failed"));
    }

    #[test]
    fn rejects_qwythos_notes_inside_files() {
        let executor = green_executor();
        let reason =
            executor.malformed_bash_command_reason(r"echo finding > ./files/public/notes.md");

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("under ./files/"));
    }

    #[test]
    fn rejects_qwythos_unrelated_solver_paths() {
        let executor = green_executor();
        let reason = executor.malformed_bash_command_reason(
            r"find /usr/local/share/codenames-ctf-solver/2026 -type f",
        );

        assert!(reason.is_some());
        assert!(reason
            .unwrap()
            .contains("not part of the current challenge"));
    }

    #[test]
    fn rejects_qwythos_checksec_on_source() {
        let executor = green_executor();
        let reason = executor.malformed_bash_command_reason(r"checksec --file=./files/prob.c");

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("ELF"));
    }

    #[test]
    fn normalizes_qwythos_grep_search_bad_flag_braces() {
        let mut input = json!({
            "pattern": r"FLAG|flag|#\w+.+={[^}]+}$",
            "path": "./files"
        });
        let notes = CtfToolExecutor::normalize_grep_search_input(&mut input);
        let pattern = input.get("pattern").and_then(Value::as_str).unwrap();

        assert!(!notes.is_empty());
        assert!(Regex::new(pattern).is_ok());
        assert!(pattern.contains(r"\{"));
    }

    #[test]
    fn normalizes_qwythos_descending_regex_range() {
        let mut input = json!({
            "pattern": r#""STRING[0-9]+":\s*"[^"]{18,5}"|passcode|Passcode"#,
            "path": "./files"
        });
        let notes = CtfToolExecutor::normalize_grep_search_input(&mut input);
        let pattern = input.get("pattern").and_then(Value::as_str).unwrap();

        assert!(!notes.is_empty());
        assert!(Regex::new(pattern).is_ok());
        assert!(pattern.contains("{5,18}"));
    }

    #[test]
    fn regex_brace_escape_preserves_valid_quantifiers() {
        let escaped = escape_invalid_regex_braces(r"[A-F0-9]{32}|FLAG{");

        assert!(escaped.contains("{32}"));
        assert!(escaped.contains(r"FLAG\{"));
        assert!(Regex::new(&escaped).is_ok());
    }
}
