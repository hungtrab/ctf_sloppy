// auth.rs — Unified multi-provider credential storage for ctf-cli.
//
// auth.json format (one entry per provider):
// {
//   "openai":    {"type": "oauth",   "access_token": "...", "refresh_token": "...", "expires_at": 123, "scopes": [...]},
//   "anthropic": {"type": "api_key", "key": "sk-ant-..."}
// }
//
// settings.json format:
// {"default_provider": "openai", "default_model": "gpt-4o"}

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;

use runtime::{
    generate_pkce_pair, generate_state, parse_oauth_callback_query, OAuthAuthorizationRequest,
    OAuthConfig,
};

pub const OPENAI_OAUTH_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const OPENAI_OAUTH_CALLBACK_PORT: u16 = 1455;
const OPENAI_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const OPENAI_AUTHORIZE_URL: &str = "https://auth.openai.com/oauth/authorize";
// Minimal scopes — identical to what pi-coding-agent (feynman) requests.
// The chatgpt.com backend only needs openid+profile+email+offline_access.
const OPENAI_SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];

// ── Provider definitions ──────────────────────────────────────────────────────
// Provider registry consumed by the (not-yet-wired) interactive provider
// picker; kept here as the single source of truth for supported backends.

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    OAuth,
    ApiKey,
}

#[allow(dead_code)]
pub struct ProviderInfo {
    pub id: &'static str,
    pub label: &'static str,
    pub kind: AuthKind,
    pub env_var: Option<&'static str>,
}

/// All providers supported by ctf-cli.
#[allow(dead_code)]
pub const PROVIDERS: &[ProviderInfo] = &[
    ProviderInfo {
        id: "openai",
        label: "OpenAI / ChatGPT Plus (OAuth)",
        kind: AuthKind::OAuth,
        env_var: Some("OPENAI_API_KEY"),
    },
    ProviderInfo {
        id: "openai",
        label: "OpenAI Platform (API key)",
        kind: AuthKind::ApiKey,
        env_var: Some("OPENAI_API_KEY"),
    },
    ProviderInfo {
        id: "anthropic",
        label: "Anthropic (API key)",
        kind: AuthKind::ApiKey,
        env_var: Some("ANTHROPIC_API_KEY"),
    },
];

/// Available models per provider.
pub fn models_for_provider(provider: &str) -> &'static [&'static str] {
    match provider {
        "openai" => &[
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4.1",
            "gpt-4.1-mini",
            "gpt-5",
            "gpt-5-mini",
            "gpt-5.2",
            "gpt-5.4",
            "gpt-5.4-mini",
            "gpt-5.5",
            "gpt-5.5-pro",
            "o3",
            "o3-pro",
            "o4-mini",
            "codex-mini-latest",
        ],
        "anthropic" => &[
            "claude-opus-4-6",
            "claude-opus-4-5",
            "claude-sonnet-4-6",
            "claude-sonnet-4-5",
            "claude-haiku-4-5-20251001",
        ],
        _ => &[],
    }
}

// ── Credential ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Credential {
    #[serde(rename = "api_key")]
    ApiKey { key: String },
    #[serde(rename = "oauth")]
    OAuth {
        access_token: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        refresh_token: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        expires_at: Option<u64>,
        #[serde(default)]
        scopes: Vec<String>,
    },
}

impl Credential {
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::ApiKey { .. } => "API key",
            Self::OAuth { .. } => "OAuth",
        }
    }
}

// ── AuthStorage ───────────────────────────────────────────────────────────────

pub struct AuthStorage {
    data: HashMap<String, Credential>,
}

impl AuthStorage {
    /// Load auth.json, migrating old openai-credentials.json if needed.
    pub fn load() -> Self {
        let new_path = auth_path();
        if !new_path.exists() {
            let old_path = old_openai_credentials_path();
            if let Ok(raw) = fs::read_to_string(&old_path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                    let cred = Credential::OAuth {
                        access_token: v["access_token"].as_str().unwrap_or("").to_string(),
                        refresh_token: v["refresh_token"].as_str().map(String::from),
                        expires_at: v["expires_at"].as_u64(),
                        scopes: v["scopes"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|s| s.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    };
                    let mut storage = Self {
                        data: HashMap::new(),
                    };
                    storage.data.insert("openai".to_string(), cred);
                    let _ = storage.save();
                    return storage;
                }
            }
        }
        let data = fs::read_to_string(&new_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { data }
    }

    pub fn save(&self) -> io::Result<()> {
        let path = auth_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, json + "\n")
    }

    pub fn get(&self, provider: &str) -> Option<&Credential> {
        self.data.get(provider)
    }

    pub fn set(&mut self, provider: &str, cred: Credential) {
        self.data.insert(provider.to_string(), cred);
    }

    pub fn remove(&mut self, provider: &str) -> bool {
        self.data.remove(provider).is_some()
    }

    pub fn has(&self, provider: &str) -> bool {
        self.data.contains_key(provider)
    }

    pub fn configured_providers(&self) -> Vec<String> {
        let mut v: Vec<_> = self.data.keys().cloned().collect();
        v.sort();
        v
    }

    /// Returns the bearer token for a provider, refreshing OAuth if near-expiry.
    pub fn resolve_token(&mut self, provider: &str) -> Option<String> {
        let cred = self.data.get(provider)?.clone();
        match cred {
            Credential::ApiKey { key } => Some(key),
            Credential::OAuth {
                access_token,
                refresh_token,
                expires_at,
                scopes,
            } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()?
                    .as_secs();

                if expires_at.is_some_and(|exp| exp <= now + 300) {
                    if let Some(rt) = refresh_token.clone() {
                        let rt2 = rt.clone();
                        let scopes2 = scopes.clone();
                        let provider_owned = provider.to_string();
                        let rt_handle = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .ok()?;
                        let result = rt_handle.block_on(refresh_oauth_token(
                            &provider_owned,
                            OPENAI_TOKEN_URL,
                            &rt2,
                            now,
                            &scopes2,
                        ));
                        if let Some(new_cred) = result {
                            let token = match &new_cred {
                                Credential::OAuth { access_token, .. } => access_token.clone(),
                                Credential::ApiKey { key } => key.clone(),
                            };
                            self.data.insert(provider.to_string(), new_cred);
                            let _ = self.save();
                            return Some(token);
                        }
                        // Refresh failed — use cached if not hard-expired.
                        if expires_at.is_none_or(|exp| exp > now) {
                            return Some(access_token);
                        }
                        return None;
                    }
                }
                Some(access_token)
            }
        }
    }

    /// Apply stored API keys to env vars (skips if env var already set).
    /// Call this once at startup so the existing Anthropic/OpenAI backend
    /// detection picks up keys stored in auth.json.
    pub fn apply_env_vars(&self) {
        if let Some(Credential::ApiKey { key }) = self.data.get("anthropic") {
            if std::env::var("ANTHROPIC_API_KEY").is_err() {
                std::env::set_var("ANTHROPIC_API_KEY", key);
            }
        }
        if let Some(Credential::ApiKey { key }) = self.data.get("openai") {
            if std::env::var("OPENAI_API_KEY").is_err() {
                std::env::set_var("OPENAI_API_KEY", key);
            }
        }
    }
}

// ── Paths ─────────────────────────────────────────────────────────────────────

pub fn auth_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".config/ctf-solver/auth.json")
}

fn old_openai_credentials_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".config/ctf-solver/openai-credentials.json")
}

pub fn settings_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".config/ctf-solver/settings.json")
}

// ── Settings ──────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CtfSettings {
    pub default_provider: Option<String>,
    pub default_model: Option<String>,
}

impl CtfSettings {
    pub fn load() -> Self {
        fs::read_to_string(settings_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> io::Result<()> {
        let path = settings_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, json + "\n")
    }

    pub fn model_spec(&self) -> Option<String> {
        match (&self.default_provider, &self.default_model) {
            (Some(p), Some(m)) => Some(format!("{p}/{m}")),
            _ => None,
        }
    }
}

// ── OAuth refresh ─────────────────────────────────────────────────────────────

/// Refresh an OAuth access token and return the new Credential.
pub async fn refresh_oauth_token(
    provider: &str,
    token_url: &str,
    refresh_token: &str,
    now_secs: u64,
    scopes: &[String],
) -> Option<Credential> {
    let http = reqwest::Client::new();
    let resp = http
        .post(token_url)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", OPENAI_OAUTH_CLIENT_ID),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        eprintln!(
            "\x1b[31m[auth] {} token refresh returned {}\x1b[0m",
            provider,
            resp.status()
        );
        return None;
    }
    let json: serde_json::Value = resp.json().await.ok()?;
    let access_token = json["access_token"].as_str()?.to_string();
    let new_refresh = json["refresh_token"]
        .as_str()
        .map(String::from)
        .or_else(|| Some(refresh_token.to_string()));
    let expires_at = json["expires_in"].as_u64().map(|s| now_secs + s);
    eprintln!("\x1b[2m[auth] {provider} token refreshed.\x1b[0m");
    Some(Credential::OAuth {
        access_token,
        refresh_token: new_refresh,
        expires_at,
        scopes: scopes.to_vec(),
    })
}

// ── Login flows ───────────────────────────────────────────────────────────────

fn openai_oauth_config() -> OAuthConfig {
    OAuthConfig {
        client_id: OPENAI_OAUTH_CLIENT_ID.to_string(),
        authorize_url: OPENAI_AUTHORIZE_URL.to_string(),
        token_url: OPENAI_TOKEN_URL.to_string(),
        callback_port: Some(OPENAI_OAUTH_CALLBACK_PORT),
        manual_redirect_url: None,
        scopes: OPENAI_SCOPES
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
    }
}

/// Run the `OpenAI` PKCE OAuth login flow and persist the credential.
pub fn run_openai_oauth_login(storage: &mut AuthStorage) -> Result<(), Box<dyn std::error::Error>> {
    let config = openai_oauth_config();
    let redirect_uri = format!("http://localhost:{OPENAI_OAUTH_CALLBACK_PORT}/auth/callback");
    let pkce = generate_pkce_pair()?;
    let state = generate_state()?;

    let authorize_url =
        OAuthAuthorizationRequest::from_config(&config, redirect_uri.clone(), state.clone(), &pkce)
            .with_extra_param("id_token_add_organizations", "true")
            .with_extra_param("codex_cli_simplified_flow", "true")
            .build_url();

    println!("Starting OpenAI login...");
    println!("Listening on {redirect_uri}");

    if let Err(e) = open_browser_url(&authorize_url) {
        eprintln!("warning: could not open browser: {e}");
        println!("Open this URL manually:\n{authorize_url}");
    }

    let listener = TcpListener::bind(("127.0.0.1", OPENAI_OAUTH_CALLBACK_PORT))
        .map_err(|e| format!("could not bind port {OPENAI_OAUTH_CALLBACK_PORT}: {e}"))?;
    let (mut stream, _) = listener.accept()?;
    let mut buf = [0u8; 4096];
    let n = { stream.read(&mut buf)? };
    let request = String::from_utf8_lossy(&buf[..n]);
    let request_line = request.lines().next().ok_or("empty callback request")?;
    let target = request_line
        .split_whitespace()
        .nth(1)
        .ok_or("missing target")?;

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
        let desc = callback
            .error_description
            .unwrap_or_else(|| "auth failed".to_string());
        return Err(format!("{err}: {desc}").into());
    }
    let code = callback.code.ok_or("callback missing authorization code")?;
    let returned_state = callback.state.ok_or("callback missing state")?;
    if returned_state != state {
        return Err("OAuth state mismatch — possible CSRF attack".into());
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let cred = rt.block_on(async {
        let http = reqwest::Client::new();
        let resp = http
            .post(&config.token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", &redirect_uri),
                ("client_id", &config.client_id),
                ("code_verifier", &pkce.verifier),
            ])
            .send()
            .await
            .map_err(|e| format!("token exchange failed: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("token exchange failed {status}: {text}"));
        }
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("token parse failed: {e}"))?;
        let access_token = json["access_token"]
            .as_str()
            .ok_or("missing access_token")?
            .to_string();
        let refresh_token = json["refresh_token"].as_str().map(String::from);
        let scope = json["scope"].as_str().unwrap_or("").to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires_at = json["expires_in"].as_u64().map(|s| now + s);
        Ok::<Credential, String>(Credential::OAuth {
            access_token,
            refresh_token,
            expires_at,
            scopes: scope.split_whitespace().map(String::from).collect(),
        })
    })?;

    storage.set("openai", cred);
    storage.save()?;
    println!(
        "Login complete. Credentials saved to {}",
        auth_path().display()
    );
    println!("Run `ctf <challenge>` to start solving.");
    Ok(())
}

/// Save an Anthropic API key to auth storage.
pub fn save_api_key(storage: &mut AuthStorage, provider: &str, key: String) -> io::Result<()> {
    storage.set(provider, Credential::ApiKey { key });
    storage.save()
}

// ── Browser ───────────────────────────────────────────────────────────────────

pub fn open_browser_url(url: &str) -> io::Result<()> {
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
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no browser opener found",
    ))
}

// ── Interactive commands ──────────────────────────────────────────────────────

fn read_line() -> Option<String> {
    let mut s = String::new();
    match io::stdin().read_line(&mut s) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(s),
    }
}

/// `ctf login [provider]` — like feynman model login.
pub fn handle_login(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut storage = AuthStorage::load();

    // `ctf login openai` or `ctf login --oauth openai`
    let provider_arg = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str);
    let force_key = args.iter().any(|a| a == "--key" || a == "-k");
    let _force_oauth = args.iter().any(|a| a == "--oauth");

    match provider_arg {
        Some("openai") if !force_key => {
            return run_openai_oauth_login(&mut storage);
        }
        Some("openai") => {
            return do_api_key_setup(&mut storage, "openai");
        }
        Some("anthropic") => {
            return do_api_key_setup(&mut storage, "anthropic");
        }
        Some(p) => {
            return Err(format!("Unknown provider: {p}. Available: openai, anthropic").into());
        }
        None => {}
    }

    // No provider given — show menu like feynman.
    println!();
    println!("  \x1b[1mHow do you want to authenticate?\x1b[0m");
    println!();
    println!(
        "    \x1b[2m1)\x1b[0m  OAuth login  \x1b[2m(ChatGPT Plus — browser, no key needed)\x1b[0m"
    );
    println!("    \x1b[2m2)\x1b[0m  API key      \x1b[2m(OpenAI Platform, Anthropic, ...)\x1b[0m");
    println!("    \x1b[2m3)\x1b[0m  Cancel");
    println!();

    let choice: u8 = loop {
        print!("  Choice [1]: ");
        let _ = io::stdout().flush();
        let Some(line) = read_line() else {
            return Ok(());
        };
        match line.trim() {
            "" | "1" => break 1,
            "2" => break 2,
            "3" => return Ok(()),
            _ => println!("  Enter 1, 2, or 3"),
        }
    };
    println!();

    if choice == 1 {
        run_openai_oauth_login(&mut storage)
    } else {
        println!("  \x1b[1mChoose provider:\x1b[0m");
        println!();
        println!("    \x1b[2m1)\x1b[0m  OpenAI Platform  \x1b[2m(OPENAI_API_KEY)\x1b[0m");
        println!("    \x1b[2m2)\x1b[0m  Anthropic        \x1b[2m(ANTHROPIC_API_KEY)\x1b[0m");
        println!("    \x1b[2m3)\x1b[0m  Cancel");
        println!();
        let p: u8 = loop {
            print!("  Provider [1]: ");
            let _ = io::stdout().flush();
            let Some(line) = read_line() else {
                return Ok(());
            };
            match line.trim() {
                "" | "1" => break 1,
                "2" => break 2,
                "3" => return Ok(()),
                _ => println!("  Enter 1, 2, or 3"),
            }
        };
        println!();
        let provider = if p == 2 { "anthropic" } else { "openai" };
        do_api_key_setup(&mut storage, provider)
    }
}

fn do_api_key_setup(
    storage: &mut AuthStorage,
    provider: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let env_hint = match provider {
        "openai" => "OPENAI_API_KEY",
        "anthropic" => "ANTHROPIC_API_KEY",
        _ => "API_KEY",
    };
    println!("  \x1b[2mTip: set {env_hint} in your shell to avoid writing the key to disk.\x1b[0m");
    println!();
    print!("  Paste API key: ");
    let _ = io::stdout().flush();
    let Some(line) = read_line() else {
        return Ok(());
    };
    let key = line.trim().to_string();
    if key.is_empty() {
        println!("  \x1b[33m⚠  No key entered.\x1b[0m");
        return Ok(());
    }
    save_api_key(storage, provider, key)?;
    println!(
        "  \x1b[38;5;46m✓\x1b[0m  {} API key saved to {}",
        provider,
        auth_path().display()
    );
    println!(
        "  Run `ctf model set {provider}/... ` to set a default model, or run `ctf <challenge>`."
    );
    Ok(())
}

/// `ctf logout [provider]`
pub fn handle_logout(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut storage = AuthStorage::load();
    let configured = storage.configured_providers();

    if configured.is_empty() {
        println!("No credentials configured.");
        return Ok(());
    }

    let provider = args.first().map(String::as_str);

    if let Some(p) = provider {
        if storage.remove(p) {
            storage.save()?;
            println!("Logged out from {p}.");
        } else {
            println!("No credentials found for {p}.");
        }
        return Ok(());
    }

    if configured.len() == 1 {
        let p = configured[0].clone();
        storage.remove(&p);
        storage.save()?;
        println!("Logged out from {p}.");
        return Ok(());
    }

    println!();
    println!("  \x1b[1mLogout from:\x1b[0m");
    println!();
    for (i, p) in configured.iter().enumerate() {
        let kind = storage.get(p).map_or("", Credential::kind_label);
        println!("    \x1b[2m{}\x1b[0m) {p}  \x1b[2m({kind})\x1b[0m", i + 1);
    }
    println!("    \x1b[2m{}\x1b[0m) Cancel", configured.len() + 1);
    println!();
    loop {
        print!("  Choice: ");
        let _ = io::stdout().flush();
        let Some(line) = read_line() else {
            return Ok(());
        };
        if let Ok(n) = line.trim().parse::<usize>() {
            if n >= 1 && n <= configured.len() {
                let p = configured[n - 1].clone();
                storage.remove(&p);
                storage.save()?;
                println!("Logged out from {p}.");
                return Ok(());
            }
            if n == configured.len() + 1 {
                return Ok(());
            }
        }
        println!("  Invalid choice.");
    }
}

/// `ctf model` / `ctf model list` / `ctf model set <spec>`
pub fn handle_model_cmd(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let sub = args.first().map(String::as_str);
    match sub {
        None | Some("list") => {
            print_model_list();
            Ok(())
        }
        Some("set") => {
            let spec = args.get(1).ok_or("Usage: ctf model set <provider/model>")?;
            set_default_model(spec)
        }
        Some(s) => Err(format!(
            "Unknown model command: {s}. Try: ctf model list | ctf model set <spec>"
        )
        .into()),
    }
}

fn print_model_list() {
    let storage = AuthStorage::load();
    let settings = CtfSettings::load();
    let current = settings.model_spec();

    println!();
    println!("  \x1b[1mModel Providers\x1b[0m");
    println!();

    let all_providers = ["openai", "anthropic"];
    for provider in all_providers {
        let configured = storage.has(provider);
        let kind = storage.get(provider).map_or("-", Credential::kind_label);
        let status = if configured {
            format!("\x1b[38;5;46m✓\x1b[0m  \x1b[2m{kind}\x1b[0m")
        } else {
            "\x1b[2m✗  not configured\x1b[0m".to_string()
        };
        println!("  {provider:<12} {status}");
        if configured {
            let models = models_for_provider(provider);
            let model_str: Vec<&str> = models
                .iter()
                .copied()
                .filter(|m| current.as_deref() != Some(&format!("{provider}/{m}")))
                .take(6)
                .collect();
            let suffix = if models.len() > 6 {
                format!(" +{}", models.len() - 6)
            } else {
                String::new()
            };
            println!(
                "               \x1b[2m{}{suffix}\x1b[0m",
                model_str.join(", ")
            );
        }
        println!();
    }

    if let Some(ref spec) = current {
        println!("  \x1b[1mDefault\x1b[0m  {spec}  \x1b[2m(current)\x1b[0m");
    } else {
        println!("  \x1b[2mNo default model set. Run `ctf model set <provider/model>`.\x1b[0m");
    }
    println!();
    println!("  \x1b[2mRun `ctf login` to authenticate a provider.\x1b[0m");
    println!("  \x1b[2mRun `ctf model set openai/gpt-4o` to set default.\x1b[0m");
    println!();
}

fn set_default_model(spec: &str) -> Result<(), Box<dyn std::error::Error>> {
    let sep = if spec.contains('/') {
        '/'
    } else if spec.contains(':') {
        ':'
    } else {
        return Err(format!(
            "Invalid model spec '{spec}'. Use provider/model (e.g. openai/gpt-4o)."
        )
        .into());
    };
    let (provider, model) = spec.split_once(sep).unwrap();
    let provider = provider.trim();
    let model = model.trim();
    if provider.is_empty() || model.is_empty() {
        return Err(format!(
            "Invalid model spec '{spec}'. Use provider/model (e.g. openai/gpt-4o)."
        )
        .into());
    }

    let storage = AuthStorage::load();
    if !storage.has(provider) {
        eprintln!(
            "\x1b[33m⚠  Provider '{provider}' is not configured. Run `ctf login` first.\x1b[0m"
        );
    }

    let mut settings = CtfSettings::load();
    settings.default_provider = Some(provider.to_string());
    settings.default_model = Some(model.to_string());
    settings.save()?;
    println!("Default model set to {provider}/{model}");
    Ok(())
}
