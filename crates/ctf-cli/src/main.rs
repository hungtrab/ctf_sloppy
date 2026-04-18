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
            // SIGTERM first, best-effort
            #[cfg(unix)]
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status();
        }
    }
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
    compact_session, ApiClient, ApiRequest, AssistantEvent, CompactionConfig, ConfigLoader,
    ContentBlock, ConversationMessage, ConversationRuntime, MessageRole, PermissionMode,
    PermissionPolicy, RuntimeError, Session, TokenUsage, ToolError, ToolExecutor,
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
    // Kill any background processes we spawned when the process exits
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
        _ => {}
    }

    let (challenge_dir, model, category_override, resume_path, api_mode, notify) = parse_args(&args)?;
    let mut challenge = Challenge::load(&challenge_dir);
    if let Some(cat) = category_override {
        challenge = challenge.with_category(cat);
    }

    // Ensure files/ and notes.md exist
    fs::create_dir_all(challenge.dir.join("files"))?;
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

fn print_help() {
    println!(
        "ctf-solver {VERSION} — autonomous CTF challenge solver

USAGE
  ctf --challenge <dir> [OPTIONS]
  ctf <dir>             # shorthand

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
    description.txt    Challenge description (optional)
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
        "/export".to_string(), "/help".to_string(), "/exit".to_string(),
    ];
    let mut editor = input::LineEditor::new(
        format!("\x1b[38;5;46m[{}]\x1b[0m > ", challenge.category.as_str()),
        completions,
    );

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
  /hint  /submit <flag>  /notes  /files  /reset  /help",
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
        let result = self.runtime.run_turn(input, None);

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
                }
                Ok(())
            }
            Err(error) => {
                if interrupted || error.to_string().contains("interrupted") {
                    spinner.finish("⏸ Paused", TerminalRenderer::new().color_theme(), &mut stdout)?;
                    println!("\n\x1b[33mAgent paused. Session saved. Continue with your next message.\x1b[0m\n");
                    let _ = self.persist();
                    Ok(())
                } else {
                    spinner.fail("❌ Failed", TerminalRenderer::new().color_theme(), &mut stdout)?;
                    Err(Box::new(error))
                }
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
                    Err(_) => println!("(no notes yet — {}", path.display()),
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
        //   2. OPENAI_BASE_URL env var → OpenAI mode
        //   3. fallback → Anthropic mode
        let effective_mode = mode_override.unwrap_or_else(|| {
            if std::env::var("OPENAI_BASE_URL").is_ok() {
                ApiMode::OpenAi
            } else {
                ApiMode::Anthropic
            }
        });

        let backend = match effective_mode {
            ApiMode::OpenAi => {
                let base_url = std::env::var("OPENAI_BASE_URL")
                    .unwrap_or_else(|_| "http://localhost:8000".to_string());
                let api_key = std::env::var("OPENAI_API_KEY")
                    .unwrap_or_else(|_| "dummy".to_string());
                let http = reqwest::Client::new();
                eprintln!("\x1b[2m[api] OpenAI-compatible mode → {base_url}\x1b[0m");
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
        let tool_defs: Vec<ToolDefinition> = mvp_tool_specs()
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

        let tools_json: Vec<Value> = mvp_tool_specs()
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
            // Retry on 502/503/504 up to 3 times with backoff
            let resp = {
                let mut last_err = None;
                let mut result = None;
                for attempt in 0..3u32 {
                    if attempt > 0 {
                        let wait = std::time::Duration::from_secs(2u64.pow(attempt));
                        eprintln!("\x1b[2m[api] retrying in {}s (attempt {}/3)...\x1b[0m", wait.as_secs(), attempt + 1);
                        tokio::time::sleep(wait).await;
                    }
                    match http.post(&endpoint).bearer_auth(&api_key).json(&body).send().await {
                        Err(e) => { last_err = Some(format!("openai request failed: {e}")); }
                        Ok(r) => {
                            let status = r.status();
                            if matches!(status.as_u16(), 502 | 503 | 504) && attempt < 2 {
                                let text = r.text().await.unwrap_or_default();
                                last_err = Some(format!("openai api returned {status}: {text}"));
                                continue;
                            }
                            result = Some(r);
                            break;
                        }
                    }
                }
                match result {
                    Some(r) => r,
                    None => return Err(RuntimeError::new(last_err.unwrap_or_default())),
                }
            };

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(RuntimeError::new(format!("openai api returned {status}: {text}")));
            }

            let renderer = TerminalRenderer::new();
            let mut markdown_state = MarkdownStreamState::default();
            let mut stdout = io::stdout();
            let mut events: Vec<AssistantEvent> = Vec::new();

            // Accumulate tool calls by index: index → (id, name, arguments)
            let mut pending_tools: std::collections::HashMap<usize, (String, String, String)> =
                std::collections::HashMap::new();

            let bytes = resp.bytes_stream();
            use futures_util::StreamExt;
            // reqwest bytes_stream is already a Stream<Item=Result<Bytes>>
            // We need to split on newlines manually
            let mut buf = String::new();

            tokio::pin!(bytes);
            while let Some(chunk) = bytes.next().await {
                let chunk = chunk.map_err(|e| RuntimeError::new(e.to_string()))?;
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

            // Emit stop if not yet emitted
            if !events.iter().any(|e| matches!(e, AssistantEvent::MessageStop)) {
                if events.iter().any(|e| {
                    matches!(e, AssistantEvent::TextDelta(t) if !t.is_empty())
                        || matches!(e, AssistantEvent::ToolUse { .. })
                }) {
                    events.push(AssistantEvent::MessageStop);
                }
            }

            Ok(events)
        })
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

        let result = execute_tool(tool_name, &effective_input);

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
            Err(error) => {
                let md = format!("\n\x1b[31m✘ {error}\x1b[0m\n");
                let _ = write!(stdout, "{md}");
                let _ = stdout.flush();
                Err(ToolError::new(error))
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
                            content: vec![ToolResultContentBlock::Text { text: output.clone() }],
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

/// Convert runtime messages to OpenAI chat format.
/// Key differences from Anthropic:
///   - Tool results → separate messages with role="tool"
///   - Tool calls   → "tool_calls" array in assistant message
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
