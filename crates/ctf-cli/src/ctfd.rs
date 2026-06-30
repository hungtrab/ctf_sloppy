use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtfdMetadata {
    pub url: String,
    pub challenge_id: u64,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
}

struct CtfdClient {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl CtfdClient {
    fn from_env() -> Result<Self, Box<dyn Error>> {
        let base_url = env::var("CTFD_URL")
            .map_err(|_| "CTFD_URL is required, e.g. https://ctf.example.com")?;
        let token =
            env::var("CTFD_TOKEN").map_err(|_| "CTFD_TOKEN is required (CTFd access token)")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            http: reqwest::Client::new(),
        })
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}/api/v1/{}", self.base_url, path.trim_start_matches('/'))
    }

    fn file_url(&self, raw: &str) -> String {
        if raw.starts_with("http://") || raw.starts_with("https://") {
            raw.to_string()
        } else {
            format!("{}/{}", self.base_url, raw.trim_start_matches('/'))
        }
    }

    async fn get_json(&self, path: &str) -> Result<Value, Box<dyn Error>> {
        let response = self
            .http
            .get(self.api_url(path))
            .header("Authorization", format!("Token {}", self.token))
            .header("Accept", "application/json")
            .send()
            .await?;
        json_response(response).await
    }

    async fn post_json(&self, path: &str, body: Value) -> Result<Value, Box<dyn Error>> {
        let response = self
            .http
            .post(self.api_url(path))
            .header("Authorization", format!("Token {}", self.token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;
        json_response(response).await
    }

    async fn download(&self, raw_url: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let response = self
            .http
            .get(self.file_url(raw_url))
            .header("Authorization", format!("Token {}", self.token))
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(format!("download failed ({status}): {text}").into());
        }
        Ok(response.bytes().await?.to_vec())
    }
}

async fn json_response(response: reqwest::Response) -> Result<Value, Box<dyn Error>> {
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        return Err(format!("CTFd API returned {status}: {text}").into());
    }
    let value: Value = serde_json::from_str(&text)?;
    if value.get("success").and_then(Value::as_bool) == Some(false) {
        return Err(format!("CTFd API error: {text}").into());
    }
    Ok(value)
}

fn runtime() -> Result<tokio::runtime::Runtime, Box<dyn Error>> {
    Ok(tokio::runtime::Runtime::new()?)
}

pub fn handle_cli(args: &[String]) -> Result<(), Box<dyn Error>> {
    let Some(cmd) = args.first().map(String::as_str) else {
        print_help();
        return Ok(());
    };

    match cmd {
        "list" => runtime()?.block_on(list_challenges()),
        "info" => {
            let id = parse_id(args.get(1), "ctf ctfd info <id>")?;
            runtime()?.block_on(show_challenge(id))
        }
        "pull" => {
            let id = parse_id(args.get(1), "ctf ctfd pull <id> [dir]")?;
            let dir = args.get(2).map(PathBuf::from);
            runtime()?.block_on(pull_challenge(id, dir.as_deref()))
        }
        "submit" => {
            if args.len() < 3 {
                return Err("usage: ctf ctfd submit <id> <flag>".into());
            }
            let id = parse_id(args.get(1), "ctf ctfd submit <id> <flag>")?;
            let flag = args[2..].join(" ");
            runtime()?.block_on(submit_challenge(id, &flag))
        }
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown ctfd command: {other}").into()),
    }
}

pub fn handle_repl(challenge_dir: &Path, rest: &str) -> Result<(), Box<dyn Error>> {
    let parts: Vec<_> = rest.split_whitespace().collect();
    let Some(cmd) = parts.first().copied() else {
        print_help();
        return Ok(());
    };

    match cmd {
        "list" => runtime()?.block_on(list_challenges()),
        "info" => {
            let id = parse_id(parts.get(1).copied(), "/ctfd info <id>")?;
            runtime()?.block_on(show_challenge(id))
        }
        "pull" => {
            let id = parse_id(parts.get(1).copied(), "/ctfd pull <id> [dir]")?;
            let dir = parts.get(2).map(PathBuf::from);
            runtime()?.block_on(pull_challenge(id, dir.as_deref()))
        }
        "submit" => {
            if parts.len() < 2 {
                return Err("usage: /ctfd submit <flag>".into());
            }
            let flag = rest
                .split_once(char::is_whitespace)
                .map_or("", |(_, flag)| flag.trim());
            submit_flag_for_challenge(challenge_dir, flag)
        }
        "help" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown ctfd command: {other}").into()),
    }
}

pub fn submit_flag_for_challenge(challenge_dir: &Path, flag: &str) -> Result<(), Box<dyn Error>> {
    let metadata = load_metadata(challenge_dir)?;
    runtime()?.block_on(submit_challenge(metadata.challenge_id, flag))
}

pub fn has_metadata(challenge_dir: &Path) -> bool {
    challenge_dir.join(".ctfd.json").exists()
}

fn load_metadata(challenge_dir: &Path) -> Result<CtfdMetadata, Box<dyn Error>> {
    let path = challenge_dir.join(".ctfd.json");
    let raw =
        fs::read_to_string(&path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    Ok(serde_json::from_str(&raw)?)
}

async fn list_challenges() -> Result<(), Box<dyn Error>> {
    let client = CtfdClient::from_env()?;
    let value = client.get_json("challenges").await?;
    let challenges = value["data"].as_array().ok_or("missing challenges data")?;

    println!(
        "{:<6} {:<12} {:<8} {:<8} Name",
        "ID", "Category", "Value", "Solves"
    );
    for item in challenges {
        println!(
            "{:<6} {:<12} {:<8} {:<8} {}",
            item["id"].as_u64().unwrap_or_default(),
            item["category"].as_str().unwrap_or("-"),
            item["value"].as_i64().unwrap_or_default(),
            item["solves"].as_i64().unwrap_or_default(),
            item["name"].as_str().unwrap_or("<unnamed>"),
        );
    }
    Ok(())
}

async fn show_challenge(id: u64) -> Result<(), Box<dyn Error>> {
    let client = CtfdClient::from_env()?;
    let data = challenge_detail(&client, id).await?;
    println!("ID       : {id}");
    println!(
        "Name     : {}",
        data["name"].as_str().unwrap_or("<unnamed>")
    );
    println!("Category : {}", data["category"].as_str().unwrap_or("-"));
    println!("Value    : {}", data["value"].as_i64().unwrap_or_default());
    if let Some(connection) = data["connection_info"].as_str() {
        if !connection.trim().is_empty() {
            println!("Connect  : {connection}");
        }
    }
    if let Some(files) = data["files"].as_array() {
        println!("Files    : {}", files.len());
        for file in files.iter().filter_map(Value::as_str) {
            println!("  {file}");
        }
    }
    println!();
    println!("{}", data["description"].as_str().unwrap_or(""));
    Ok(())
}

async fn pull_challenge(id: u64, dir: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let client = CtfdClient::from_env()?;
    let data = challenge_detail(&client, id).await?;
    let name = data["name"].as_str().unwrap_or("challenge");
    let category = data["category"].as_str().unwrap_or("misc").to_string();
    let target = dir.map_or_else(
        || PathBuf::from(safe_path_component(name)),
        Path::to_path_buf,
    );

    fs::create_dir_all(target.join("files"))?;
    fs::create_dir_all(target.join("logs"))?;
    fs::create_dir_all(target.join("self"))?;
    fs::create_dir_all(target.join("tmp"))?;

    let mut description = String::new();
    description.push_str(data["description"].as_str().unwrap_or(""));
    if let Some(connection) = data["connection_info"].as_str() {
        if !connection.trim().is_empty() {
            description.push_str("\n\n## Connection\n");
            description.push_str(connection);
            description.push('\n');
        }
    }
    fs::write(target.join("desc.txt"), description)?;
    fs::write(
        target.join("category.txt"),
        category.to_ascii_lowercase() + "\n",
    )?;

    if let Ok(flag_format) = env::var("CTFD_FLAG_FORMAT") {
        if !flag_format.trim().is_empty() {
            fs::write(
                target.join("flag_format.txt"),
                flag_format.trim().to_string() + "\n",
            )?;
        }
    }

    let files = data["files"].as_array().cloned().unwrap_or_default();
    let mut downloaded = Vec::new();
    for (index, file) in files.iter().filter_map(Value::as_str).enumerate() {
        let bytes = client.download(file).await?;
        let filename = unique_filename(&target.join("files"), file, index);
        fs::write(target.join("files").join(&filename), bytes)?;
        downloaded.push(filename);
    }

    let metadata = CtfdMetadata {
        url: client.base_url,
        challenge_id: id,
        name: name.to_string(),
        category: Some(category),
        files: downloaded,
    };
    fs::write(
        target.join(".ctfd.json"),
        serde_json::to_string_pretty(&metadata)? + "\n",
    )?;

    println!("Pulled CTFd challenge {id} into {}", target.display());
    println!("Run: ctf {}", target.display());
    Ok(())
}

async fn submit_challenge(id: u64, flag: &str) -> Result<(), Box<dyn Error>> {
    let client = CtfdClient::from_env()?;
    let value = client
        .post_json(
            "challenges/attempt",
            json!({
                "challenge_id": id,
                "submission": flag,
            }),
        )
        .await?;
    let data = &value["data"];
    let status = data["status"].as_str().unwrap_or("unknown");
    let message = data["message"].as_str().unwrap_or("");
    println!("CTFd submit: {status}");
    if !message.is_empty() {
        println!("{message}");
    }
    Ok(())
}

async fn challenge_detail(client: &CtfdClient, id: u64) -> Result<Value, Box<dyn Error>> {
    let value = client.get_json(&format!("challenges/{id}")).await?;
    value
        .get("data")
        .cloned()
        .ok_or_else(|| "missing challenge data".into())
}

fn parse_id<T: AsRef<str>>(raw: Option<T>, usage: &str) -> Result<u64, Box<dyn Error>> {
    raw.ok_or_else(|| format!("usage: {usage}"))?
        .as_ref()
        .parse::<u64>()
        .map_err(|e| format!("invalid challenge id: {e}").into())
}

fn unique_filename(files_dir: &Path, raw_url: &str, index: usize) -> String {
    let mut name = raw_url
        .split('?')
        .next()
        .and_then(|path| path.rsplit('/').next())
        .filter(|s| !s.is_empty())
        .map_or_else(|| format!("file-{index}"), safe_path_component);
    if !files_dir.join(&name).exists() {
        return name;
    }
    let original = name.clone();
    let mut n = 1usize;
    while files_dir.join(&name).exists() {
        name = format!("{n}-{original}");
        n += 1;
    }
    name
}

fn safe_path_component(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(|c| c == '_' || c == '.');
    if trimmed.is_empty() {
        "challenge".to_string()
    } else {
        trimmed.to_string()
    }
}

fn print_help() {
    println!(
        "CTFd integration

Environment:
  CTFD_URL             Base URL, e.g. https://ctf.example.com
  CTFD_TOKEN           CTFd access token
  CTFD_FLAG_FORMAT     Optional local flag_format.txt value when pulling

Commands:
  ctf ctfd list
  ctf ctfd info <id>
  ctf ctfd pull <id> [dir]
  ctf ctfd submit <id> <flag>

REPL:
  /ctfd list
  /ctfd info <id>
  /ctfd pull <id> [dir]
  /ctfd submit <flag>     # uses .ctfd.json in current challenge dir"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_path_components() {
        assert_eq!(safe_path_component("../web chall!"), "web_chall");
        assert_eq!(safe_path_component(""), "challenge");
    }

    #[test]
    fn extracts_filename_from_ctfd_file_url() {
        let dir = PathBuf::from("/definitely/missing");
        assert_eq!(
            unique_filename(&dir, "/files/abc123/chall.py?token=x", 0),
            "chall.py"
        );
    }
}
