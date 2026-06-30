// CTF Vulnerability Knowledge Base — v2
// Storage: ~/.local/share/ctf/vuln_db.json
// Tracks vulnerabilities, OWASP mapping, recognition indicators, and solve status.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

// ─── Color palette (feynman theme) ────────────────────────────────────────────

const C_RESET: &str = "\x1b[0m";
const C_BOLD: &str = "\x1b[1m";
const C_DIM: &str = "\x1b[2m";
const C_TEAL: &str = "\x1b[38;2;127;187;179m";
const C_SAGE: &str = "\x1b[38;2;167;192;128m";
const C_ASH: &str = "\x1b[38;2;133;146;137m";
const C_INK: &str = "\x1b[38;2;211;198;170m";
const C_STONE: &str = "\x1b[38;2;157;169;160m";
const C_DARK_ASH: &str = "\x1b[38;2;92;106;114m";

// ─── Storage ──────────────────────────────────────────────────────────────────

fn db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".local/share/ctf/vuln_db.json")
}

pub fn load_db() -> Value {
    // Migrate v1 → v2 (new fields are optional, so old entries just lack them)
    fs::read_to_string(db_path())
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or_else(|| json!({"version": 2, "entries": []}))
}

fn save_db(db: &Value) -> std::io::Result<()> {
    let path = db_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, serde_json::to_string_pretty(db).unwrap_or_default())
}

fn term_width() -> usize {
    crossterm::terminal::size()
        .map(|(w, _)| w as usize)
        .unwrap_or(80)
}

// ─── OWASP / CWE mapping ──────────────────────────────────────────────────────
// Maps vulnerability keyword patterns → (OWASP Top 10 id, CWE id, display label)

pub struct OwaspEntry {
    pub owasp: &'static str, // e.g. "A03:2021"
    pub cwe: &'static str,   // e.g. "CWE-89"
    pub label: &'static str, // e.g. "Injection"
}

// Returns all OWASP entries that match any keyword in the vuln string (case-insensitive).
pub fn owasp_for_vuln(vuln: &str) -> Vec<&'static OwaspEntry> {
    static MAP: &[(&[&str], OwaspEntry)] = &[
        // ── Web ─────────────────────────────────────────────────────────────────
        (
            &["sql injection", "sqli", "sql", "union select", "blind sql"],
            OwaspEntry {
                owasp: "A03:2021",
                cwe: "CWE-89",
                label: "SQL Injection",
            },
        ),
        (
            &[
                "xss",
                "cross-site scripting",
                "stored xss",
                "reflected xss",
                "dom xss",
            ],
            OwaspEntry {
                owasp: "A03:2021",
                cwe: "CWE-79",
                label: "XSS",
            },
        ),
        (
            &[
                "command injection",
                "os injection",
                "rce",
                "remote code execution",
                "code injection",
            ],
            OwaspEntry {
                owasp: "A03:2021",
                cwe: "CWE-78",
                label: "Command Injection",
            },
        ),
        (
            &["template injection", "ssti", "server-side template"],
            OwaspEntry {
                owasp: "A03:2021",
                cwe: "CWE-94",
                label: "Template Injection",
            },
        ),
        (
            &["xxe", "xml external", "xml injection"],
            OwaspEntry {
                owasp: "A05:2021",
                cwe: "CWE-611",
                label: "XXE",
            },
        ),
        (
            &["ssrf", "server-side request forgery"],
            OwaspEntry {
                owasp: "A10:2021",
                cwe: "CWE-918",
                label: "SSRF",
            },
        ),
        (
            &[
                "idor",
                "insecure direct object",
                "broken access",
                "access control",
                "privilege escalation",
                "authorization bypass",
            ],
            OwaspEntry {
                owasp: "A01:2021",
                cwe: "CWE-284",
                label: "Broken Access Control",
            },
        ),
        (
            &[
                "path traversal",
                "directory traversal",
                "lfi",
                "local file inclusion",
                "rfi",
                "remote file inclusion",
            ],
            OwaspEntry {
                owasp: "A01:2021",
                cwe: "CWE-22",
                label: "Path Traversal / LFI",
            },
        ),
        (
            &["csrf", "cross-site request forgery"],
            OwaspEntry {
                owasp: "A01:2021",
                cwe: "CWE-352",
                label: "CSRF",
            },
        ),
        (
            &[
                "deserialization",
                "pickle",
                "java deserialization",
                "php unserialize",
                "object injection",
            ],
            OwaspEntry {
                owasp: "A08:2021",
                cwe: "CWE-502",
                label: "Insecure Deserialization",
            },
        ),
        (
            &[
                "jwt",
                "json web token",
                "algorithm confusion",
                "none algorithm",
                "jwt secret",
            ],
            OwaspEntry {
                owasp: "A02:2021",
                cwe: "CWE-347",
                label: "JWT / Auth Token Flaw",
            },
        ),
        (
            &["open redirect", "redirect"],
            OwaspEntry {
                owasp: "A01:2021",
                cwe: "CWE-601",
                label: "Open Redirect",
            },
        ),
        (
            &["race condition", "toctou", "time-of-check"],
            OwaspEntry {
                owasp: "A04:2021",
                cwe: "CWE-362",
                label: "Race Condition",
            },
        ),
        (
            &["business logic", "logic flaw", "workflow bypass"],
            OwaspEntry {
                owasp: "A04:2021",
                cwe: "CWE-840",
                label: "Business Logic Flaw",
            },
        ),
        (
            &[
                "mass assignment",
                "parameter pollution",
                "prototype pollution",
            ],
            OwaspEntry {
                owasp: "A04:2021",
                cwe: "CWE-915",
                label: "Mass Assignment",
            },
        ),
        (
            &["cors", "cross-origin"],
            OwaspEntry {
                owasp: "A05:2021",
                cwe: "CWE-942",
                label: "CORS Misconfiguration",
            },
        ),
        (
            &["graphql injection", "introspection", "graphql"],
            OwaspEntry {
                owasp: "A03:2021",
                cwe: "CWE-89",
                label: "GraphQL Injection",
            },
        ),
        (
            &["nosql", "mongodb injection", "nosql injection"],
            OwaspEntry {
                owasp: "A03:2021",
                cwe: "CWE-943",
                label: "NoSQL Injection",
            },
        ),
        (
            &["request smuggling", "http smuggling", "cl.te", "te.cl"],
            OwaspEntry {
                owasp: "A05:2021",
                cwe: "CWE-444",
                label: "HTTP Request Smuggling",
            },
        ),
        (
            &["cache poisoning", "web cache", "cache deception"],
            OwaspEntry {
                owasp: "A05:2021",
                cwe: "CWE-444",
                label: "Cache Poisoning",
            },
        ),
        // ── Pwn / Binary ────────────────────────────────────────────────────────
        (
            &[
                "buffer overflow",
                "stack overflow",
                "bof",
                "stack bof",
                "gets(",
                "strcpy",
                "scanf",
            ],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-121",
                label: "Stack Buffer Overflow",
            },
        ),
        (
            &["heap overflow", "heap bof", "heap corruption"],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-122",
                label: "Heap Buffer Overflow",
            },
        ),
        (
            &["use after free", "uaf", "heap uaf", "tcache", "fastbin"],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-416",
                label: "Use-After-Free",
            },
        ),
        (
            &["format string", "printf", "%n write", "fmt"],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-134",
                label: "Format String",
            },
        ),
        (
            &[
                "integer overflow",
                "integer underflow",
                "integer wrap",
                "signedness",
            ],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-190",
                label: "Integer Overflow",
            },
        ),
        (
            &[
                "rop",
                "return-oriented",
                "ret2libc",
                "ret2win",
                "gadget",
                "ropc",
            ],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-94",
                label: "ROP / Code Reuse",
            },
        ),
        (
            &["null pointer", "null deref", "null dereference"],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-476",
                label: "Null Pointer Dereference",
            },
        ),
        (
            &["double free", "dfb", "free twice"],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-415",
                label: "Double Free",
            },
        ),
        (
            &["off-by-one", "off by one", "obo"],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-193",
                label: "Off-By-One",
            },
        ),
        (
            &["type confusion", "type mismatch"],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-843",
                label: "Type Confusion",
            },
        ),
        (
            &["arbitrary write", "write-what-where", "www primitive"],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-123",
                label: "Write-What-Where",
            },
        ),
        (
            &["stack canary", "canary bypass", "stack cookie"],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-121",
                label: "Stack Canary Bypass",
            },
        ),
        (
            &[
                "aslr bypass",
                "pie bypass",
                "info leak",
                "libc leak",
                "address leak",
            ],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-200",
                label: "Address Leak / ASLR Bypass",
            },
        ),
        (
            &[
                "kernel exploit",
                "lpe",
                "local privilege",
                "kernel pwn",
                "kernel rop",
            ],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-269",
                label: "Kernel Privilege Escalation",
            },
        ),
        (
            &["sandbox escape", "seccomp bypass", "container escape"],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-284",
                label: "Sandbox Escape",
            },
        ),
        // ── Crypto ──────────────────────────────────────────────────────────────
        (
            &[
                "rsa",
                "small exponent",
                "broadcast attack",
                "wiener",
                "fermat",
                "common modulus",
                "rsa crt",
            ],
            OwaspEntry {
                owasp: "A02:2021",
                cwe: "CWE-326",
                label: "Weak RSA",
            },
        ),
        (
            &["aes ecb", "ecb mode", "electronic codebook"],
            OwaspEntry {
                owasp: "A02:2021",
                cwe: "CWE-327",
                label: "AES-ECB Mode",
            },
        ),
        (
            &["padding oracle", "lucky13", "bleichenbacher", "cbc padding"],
            OwaspEntry {
                owasp: "A02:2021",
                cwe: "CWE-209",
                label: "Padding Oracle",
            },
        ),
        (
            &["hash length extension", "length extension", "sha extension"],
            OwaspEntry {
                owasp: "A02:2021",
                cwe: "CWE-327",
                label: "Hash Length Extension",
            },
        ),
        (
            &[
                "xor reuse",
                "key reuse",
                "one-time pad",
                "otp reuse",
                "stream cipher reuse",
            ],
            OwaspEntry {
                owasp: "A02:2021",
                cwe: "CWE-330",
                label: "XOR / OTP Key Reuse",
            },
        ),
        (
            &[
                "weak prng",
                "predictable random",
                "seeded prng",
                "mt19937",
                "mersenne",
            ],
            OwaspEntry {
                owasp: "A02:2021",
                cwe: "CWE-338",
                label: "Weak PRNG",
            },
        ),
        (
            &[
                "ecdsa",
                "ecdsa nonce",
                "nonce reuse",
                "k reuse",
                "lattice attack",
            ],
            OwaspEntry {
                owasp: "A02:2021",
                cwe: "CWE-327",
                label: "ECDSA Nonce Reuse",
            },
        ),
        (
            &[
                "dh",
                "diffie-hellman",
                "pohlig-hellman",
                "small subgroup",
                "invalid curve",
            ],
            OwaspEntry {
                owasp: "A02:2021",
                cwe: "CWE-326",
                label: "DH Key Exchange Flaw",
            },
        ),
        (
            &[
                "cbc bit flip",
                "cbc bitflip",
                "iv manipulation",
                "iv control",
            ],
            OwaspEntry {
                owasp: "A02:2021",
                cwe: "CWE-327",
                label: "CBC Bit-Flipping",
            },
        ),
        (
            &[
                "side channel",
                "timing attack",
                "cache timing",
                "power analysis",
            ],
            OwaspEntry {
                owasp: "A02:2021",
                cwe: "CWE-208",
                label: "Side-Channel Attack",
            },
        ),
        // ── Rev / Misc ───────────────────────────────────────────────────────────
        (
            &["anti-debug", "ptrace", "isdebuggerpresent", "antidebug"],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-1209",
                label: "Anti-Debug",
            },
        ),
        (
            &[
                "obfuscation",
                "obfuscated",
                "packed",
                "upx",
                "vm protection",
                "virtualization",
            ],
            OwaspEntry {
                owasp: "",
                cwe: "CWE-656",
                label: "Code Obfuscation",
            },
        ),
        (
            &["steganography", "stego", "lsb", "hidden data"],
            OwaspEntry {
                owasp: "",
                cwe: "",
                label: "Steganography",
            },
        ),
        (
            &[
                "path injection",
                "environment variable",
                "ld_preload",
                "library hijack",
            ],
            OwaspEntry {
                owasp: "A08:2021",
                cwe: "CWE-427",
                label: "Library/Path Hijacking",
            },
        ),
        (
            &[
                "insecure file permission",
                "world-writable",
                "suid",
                "setuid",
                "suid binary",
            ],
            OwaspEntry {
                owasp: "A05:2021",
                cwe: "CWE-732",
                label: "Insecure File Permission",
            },
        ),
        (
            &["dependency confusion", "supply chain", "typosquatting"],
            OwaspEntry {
                owasp: "A06:2021",
                cwe: "CWE-829",
                label: "Dependency Confusion",
            },
        ),
    ];

    let lower = vuln.to_lowercase();
    MAP.iter()
        .filter(|(keywords, _)| keywords.iter().any(|k| lower.contains(k)))
        .map(|(_, entry)| entry)
        .collect()
}

/// Format OWASP+CWE tags as a compact string, e.g. "A03:2021 (CWE-89)"
#[allow(dead_code)]
pub fn format_owasp_tags(owasp_list: &[String]) -> String {
    if owasp_list.is_empty() {
        return String::new();
    }
    owasp_list.join("  ")
}

// ─── Entry ────────────────────────────────────────────────────────────────────

pub struct KbEntry {
    pub id: String,
    pub timestamp: u64,
    pub challenge: String,
    pub category: String,
    pub vulns: Vec<String>,
    pub description: String,
    pub snippets: Vec<(String, String)>,
    pub tags: Vec<String>,
    // v2 fields
    pub owasp: Vec<String>,      // e.g. ["A03:2021 Injection (CWE-89)"]
    pub indicators: Vec<String>, // recognition patterns/signatures
    pub solved: bool,            // was the flag actually found?
    pub flag: Option<String>,    // the actual flag (stored hashed or plain)
}

impl KbEntry {
    /// Auto-populate OWASP tags from the vuln list if not explicitly provided.
    pub fn auto_owasp(&mut self) {
        if !self.owasp.is_empty() {
            return;
        }
        let mut seen = std::collections::HashSet::new();
        for v in &self.vulns {
            for entry in owasp_for_vuln(v) {
                let tag = if entry.cwe.is_empty() {
                    entry.label.to_string()
                } else if entry.owasp.is_empty() {
                    format!("{} ({})", entry.label, entry.cwe)
                } else {
                    format!("{} {} ({})", entry.owasp, entry.label, entry.cwe)
                };
                if seen.insert(tag.clone()) {
                    self.owasp.push(tag);
                }
            }
        }
    }
}

/// Returns true if the KB already has a `solved: true` entry for this challenge.
pub fn is_solved(challenge: &str) -> bool {
    let db = load_db();
    db["entries"].as_array().is_some_and(|entries| {
        entries
            .iter()
            .any(|e| e["challenge"] == challenge && e["solved"].as_bool().unwrap_or(false))
    })
}

pub fn generate_id(challenge: &str, ts: u64) -> String {
    let slug = challenge
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>();
    format!("{slug}-{}", ts % 100_000)
}

pub fn add_entry(entry: KbEntry) -> Result<String, Box<dyn std::error::Error>> {
    let mut db = load_db();
    let entries = db["entries"].as_array_mut().ok_or("invalid db")?;
    let id = entry.id.clone();

    if let Some(existing) = entries
        .iter_mut()
        .find(|e| e["challenge"] == entry.challenge)
    {
        merge_vulns(existing, &entry.vulns);
        merge_tags(existing, &entry.tags);
        merge_snippets(existing, &entry.snippets);
        merge_string_list(existing, "owasp", &entry.owasp);
        merge_string_list(existing, "indicators", &entry.indicators);
        if !entry.description.is_empty() {
            existing["description"] = json!(entry.description);
        }
        existing["timestamp"] = json!(entry.timestamp);
        // Only overwrite solved/flag if the new entry has them
        if entry.solved {
            existing["solved"] = json!(true);
        }
        if let Some(ref flag) = entry.flag {
            existing["flag"] = json!(flag);
        }
        save_db(&db)?;
        return Ok(id);
    }

    let entry_json = json!({
        "id":          entry.id,
        "timestamp":   entry.timestamp,
        "challenge":   entry.challenge,
        "category":    entry.category,
        "vulns":       entry.vulns,
        "description": entry.description,
        "snippets":    entry.snippets.iter()
                           .map(|(l, c)| json!({"label": l, "code": c}))
                           .collect::<Vec<_>>(),
        "tags":        entry.tags,
        "owasp":       entry.owasp,
        "indicators":  entry.indicators,
        "solved":      entry.solved,
        "flag":        entry.flag,
    });
    entries.push(entry_json);
    save_db(&db)?;
    Ok(id)
}

fn merge_vulns(existing: &mut Value, new: &[String]) {
    let mut current: Vec<String> = existing["vulns"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    for v in new {
        if !current.contains(v) {
            current.push(v.clone());
        }
    }
    existing["vulns"] = json!(current);
}

fn merge_tags(existing: &mut Value, new: &[String]) {
    let mut current: Vec<String> = existing["tags"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    for t in new {
        if !current.contains(t) {
            current.push(t.clone());
        }
    }
    existing["tags"] = json!(current);
}

fn merge_string_list(existing: &mut Value, key: &str, new: &[String]) {
    if new.is_empty() {
        return;
    }
    let mut current: Vec<String> = existing[key]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    for item in new {
        if !current.contains(item) {
            current.push(item.clone());
        }
    }
    existing[key] = json!(current);
}

fn merge_snippets(existing: &mut Value, new: &[(String, String)]) {
    if new.is_empty() {
        return;
    }
    let mut snippets = existing["snippets"].as_array().cloned().unwrap_or_default();
    for (label, code) in new {
        if !snippets.iter().any(|s| s["label"] == *label) {
            snippets.push(json!({"label": label, "code": code}));
        }
    }
    existing["snippets"] = json!(snippets);
}

// ─── Cheatsheet for agent ─────────────────────────────────────────────────────

/// Returns a compact cheatsheet string for injection into the agent system prompt.
/// Lists the top vulnerabilities for this category with their recognition indicators.
pub fn cheatsheet_for_category(category: &str) -> Option<String> {
    let db = load_db();
    let entries = db["entries"].as_array()?;
    if entries.is_empty() {
        return None;
    }

    let cat_entries: Vec<&Value> = entries
        .iter()
        .filter(|e| {
            e["category"]
                .as_str()
                .unwrap_or("")
                .eq_ignore_ascii_case(category)
        })
        .collect();

    if cat_entries.is_empty() {
        return None;
    }

    // Aggregate: vuln → (count, owasp tags, indicators)
    let mut vuln_data: HashMap<String, (usize, Vec<String>, Vec<String>)> = HashMap::new();
    for e in &cat_entries {
        let vulns: Vec<String> = e["vulns"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        let owasp: Vec<String> = e["owasp"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        let indicators: Vec<String> = e["indicators"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();

        for v in &vulns {
            let entry = vuln_data
                .entry(v.clone())
                .or_insert((0, Vec::new(), Vec::new()));
            entry.0 += 1;
            for ow in &owasp {
                if !entry.1.contains(ow) {
                    entry.1.push(ow.clone());
                }
            }
            for ind in &indicators {
                if !entry.2.contains(ind) {
                    entry.2.push(ind.clone());
                }
            }
        }
    }

    if vuln_data.is_empty() {
        return None;
    }

    let mut sorted: Vec<(String, usize, Vec<String>, Vec<String>)> = vuln_data
        .into_iter()
        .map(|(k, (c, ow, ind))| (k, c, ow, ind))
        .collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    let solved_count = cat_entries
        .iter()
        .filter(|e| e["solved"].as_bool().unwrap_or(false))
        .count();

    let mut out = format!(
        "## KB Cheatsheet: {} ({} challenges, {} solved)\n\n",
        category.to_uppercase(),
        cat_entries.len(),
        solved_count
    );
    out.push_str("Common vulnerabilities (most frequent first):\n");

    for (vuln, count, owasp, indicators) in sorted.iter().take(10) {
        out.push_str(&format!("- **{vuln}** (×{count})"));
        if let Some(ow) = owasp.first() {
            out.push_str(&format!("  `{ow}`"));
        }
        out.push('\n');
        if !indicators.is_empty() {
            let ind_preview: Vec<&str> = indicators.iter().take(4).map(String::as_str).collect();
            out.push_str(&format!("  *Indicators:* {}\n", ind_preview.join(" · ")));
        }
    }
    out.push('\n');
    out.push_str("Use this to prioritize your recon — check for these patterns first.\n");

    Some(out)
}

/// Returns the full cheatsheet across all categories for /kb cheatsheet command.
pub fn full_cheatsheet() -> String {
    let db = load_db();
    let entries = match db["entries"].as_array() {
        Some(a) if !a.is_empty() => a.clone(),
        _ => {
            return format!(
            "{C_STONE}Knowledge base empty. Use /kb capture after solving a challenge.{C_RESET}\n"
        )
        }
    };

    let mut cats: HashMap<String, Vec<&Value>> = HashMap::new();
    for e in &entries {
        let cat = e["category"].as_str().unwrap_or("misc").to_string();
        cats.entry(cat).or_default().push(e);
    }

    let mut out = format!("{C_TEAL}{C_BOLD}◆ KB Cheatsheet — All Categories{C_RESET}\n\n");
    let mut sorted_cats: Vec<(String, Vec<&Value>)> = cats.into_iter().collect();
    sorted_cats.sort_by_key(|(_, v)| usize::MAX - v.len());

    for (cat, cat_entries) in &sorted_cats {
        let color = category_color(cat);
        out.push_str(&format!(
            "{color}{C_BOLD}▸ {} ({} challenges){C_RESET}\n",
            cat.to_uppercase(),
            cat_entries.len()
        ));

        let mut vuln_counts: HashMap<String, usize> = HashMap::new();
        for e in cat_entries {
            let empty = vec![];
            for v in e["vulns"].as_array().unwrap_or(&empty) {
                if let Some(name) = v.as_str() {
                    *vuln_counts.entry(name.to_string()).or_insert(0) += 1;
                }
            }
        }
        let mut top: Vec<(&String, &usize)> = vuln_counts.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1));
        for (vuln, count) in top.iter().take(5) {
            out.push_str(&format!(
                "  {C_DARK_ASH}×{count}{C_RESET}  {C_INK}{vuln}{C_RESET}\n"
            ));
        }
        out.push('\n');
    }
    out
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn category_color(cat: &str) -> &'static str {
    match cat {
        "pwn" => "\x1b[38;2;230;126;128m",       // ROSE - red
        "web" => "\x1b[38;2;127;187;179m",       // TEAL - cyan
        "rev" => "\x1b[38;2;157;169;160m",       // STONE - grey
        "forensics" => "\x1b[38;2;133;146;137m", // ASH
        "osint" => "\x1b[38;2;167;192;128m",     // SAGE - green
        "network" => "\x1b[38;2;92;106;114m",    // DARK_ASH
        _ => "\x1b[38;2;211;198;170m",           // INK
    }
}

fn bar_fill(count: usize, max: usize, width: usize) -> String {
    if max == 0 {
        return " ".repeat(width);
    }
    let filled = (count * width).min(max * width) / max;
    let empty = width - filled;
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

fn format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return "????-??-??".to_string();
    }
    let days = ts / 86400;
    let mut y = 1970u64;
    let mut d = days;
    loop {
        let yd = if is_leap(y) { 366 } else { 365 };
        if d < yd {
            break;
        }
        d -= yd;
        y += 1;
    }
    let month_days: [u64; 12] = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 1usize;
    for (i, &ml) in month_days.iter().enumerate() {
        if d < ml {
            m = i + 1;
            break;
        }
        d -= ml;
    }
    format!("{y}-{m:02}-{:02}", d + 1)
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

fn divider(w: usize) -> String {
    "─".repeat(w)
}

fn entries_sorted_by_time(entries: &[Value]) -> Vec<&Value> {
    let mut v: Vec<&Value> = entries.iter().collect();
    v.sort_by(|a, b| {
        b["timestamp"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["timestamp"].as_u64().unwrap_or(0))
    });
    v
}

// ─── Render: Overview ─────────────────────────────────────────────────────────

pub fn render_overview() -> String {
    let db = load_db();
    let entries = match db["entries"].as_array() {
        Some(a) if !a.is_empty() => a.clone(),
        _ => return format!(
            "{C_STONE}Knowledge base is empty.{C_RESET}\n\
             {C_DIM}Use {C_RESET}{C_TEAL}/kb capture{C_RESET}{C_DIM} after solving a challenge.\n\
             Or {C_RESET}{C_TEAL}/kb add <vuln> | <description>{C_RESET}{C_DIM} for a quick entry.{C_RESET}\n"
        ),
    };

    let width = term_width().min(88);
    let div = divider(width);
    let bar_w = 24usize;

    let solved_count = entries
        .iter()
        .filter(|e| e["solved"].as_bool().unwrap_or(false))
        .count();

    // Category counts
    let mut cat_counts: HashMap<String, usize> = HashMap::new();
    for e in &entries {
        *cat_counts
            .entry(e["category"].as_str().unwrap_or("misc").to_string())
            .or_insert(0) += 1;
    }
    let mut sorted_cats: Vec<(String, usize)> = cat_counts.into_iter().collect();
    sorted_cats.sort_by(|a, b| b.1.cmp(&a.1));
    let max_cat = sorted_cats.first().map_or(1, |(_, c)| *c);

    // Vuln frequency
    let mut vuln_cats: HashMap<String, Vec<String>> = HashMap::new();
    for e in &entries {
        let cat = e["category"].as_str().unwrap_or("misc").to_string();
        for v in e["vulns"].as_array().unwrap_or(&vec![]) {
            if let Some(name) = v.as_str() {
                vuln_cats
                    .entry(name.to_string())
                    .or_default()
                    .push(cat.clone());
            }
        }
    }
    let mut sorted_vulns: Vec<(String, Vec<String>)> = vuln_cats.into_iter().collect();
    sorted_vulns.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    let max_vuln = sorted_vulns.first().map_or(1, |(_, v)| v.len());

    // OWASP frequency
    let mut owasp_counts: HashMap<String, usize> = HashMap::new();
    for e in &entries {
        for v in e["owasp"].as_array().unwrap_or(&vec![]) {
            if let Some(s) = v.as_str() {
                *owasp_counts.entry(s.to_string()).or_insert(0) += 1;
            }
        }
    }

    let mut out = String::new();
    out += &format!("{C_TEAL}{C_BOLD}◆ CTF Knowledge Base{C_RESET}  {C_DIM}─  {} challenge{}  ·  {} solved{C_RESET}\n",
        entries.len(), if entries.len() == 1 { "" } else { "s" }, solved_count);
    out += &format!("{C_DARK_ASH}{div}{C_RESET}\n");

    // Category distribution
    out += &format!("\n{C_ASH}Category Distribution{C_RESET}\n");
    for (cat, count) in &sorted_cats {
        let color = category_color(cat);
        let b = bar_fill(*count, max_cat, bar_w);
        out += &format!("  {color}{cat:<10}{C_RESET} {C_STONE}{b}{C_RESET}  {count:2}  {C_DIM}({:.0}%){C_RESET}\n",
            *count as f64 / entries.len() as f64 * 100.0);
    }

    // Top vulnerabilities
    if !sorted_vulns.is_empty() {
        out += &format!("\n{C_ASH}Top Vulnerabilities{C_RESET}\n");
        for (vuln, cats) in sorted_vulns.iter().take(8) {
            let count = cats.len();
            let b = bar_fill(count, max_vuln, 14);
            let cats_preview: Vec<&str> = cats
                .iter()
                .take(3)
                .map(std::string::String::as_str)
                .collect();
            let cats_str = cats_preview.join(",");
            let cats_display = if cats.len() > 3 {
                format!("{cats_str}…")
            } else {
                cats_str
            };
            let vuln_trunc = if vuln.len() > 38 {
                &vuln[..38]
            } else {
                vuln.as_str()
            };
            out += &format!("  {C_STONE}{b}{C_RESET}  {count:2}×  {C_INK}{vuln_trunc:<40}{C_RESET}  {C_DIM}{cats_display}{C_RESET}\n");
        }
    }

    // OWASP breakdown
    if !owasp_counts.is_empty() {
        let mut sorted_owasp: Vec<(String, usize)> = owasp_counts.into_iter().collect();
        sorted_owasp.sort_by(|a, b| b.1.cmp(&a.1));
        out += &format!("\n{C_ASH}OWASP / CWE Mapping{C_RESET}\n");
        for (tag, count) in sorted_owasp.iter().take(8) {
            let tag_trunc = if tag.len() > 50 {
                &tag[..50]
            } else {
                tag.as_str()
            };
            out += &format!("  {C_TEAL}×{count:<2}{C_RESET}  {C_DIM}{tag_trunc}{C_RESET}\n");
        }
    }

    // Recent challenges
    out += &format!("\n{C_ASH}Recent Challenges{C_RESET}\n");
    let sorted = entries_sorted_by_time(&entries);
    for e in sorted.iter().take(6) {
        let date = format_timestamp(e["timestamp"].as_u64().unwrap_or(0));
        let cat = e["category"].as_str().unwrap_or("misc");
        let color = category_color(cat);
        let name = e["challenge"].as_str().unwrap_or("?");
        let first_vuln = e["vulns"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let solved = if e["solved"].as_bool().unwrap_or(false) {
            format!("{C_SAGE}✓{C_RESET}")
        } else {
            format!("{C_DARK_ASH}·{C_RESET}")
        };
        let name_trunc = if name.len() > 22 { &name[..22] } else { name };
        let vuln_trunc = if first_vuln.len() > 34 {
            &first_vuln[..34]
        } else {
            first_vuln
        };
        out += &format!("  {solved} {C_DIM}{date}{C_RESET}  {color}{cat:<10}{C_RESET}  {C_INK}{name_trunc:<24}{C_RESET}  {C_DIM}{vuln_trunc}{C_RESET}\n");
    }

    out += &format!("\n{C_DARK_ASH}{div}{C_RESET}\n");
    out += &format!("{C_DIM}/kb stats · /kb list [cat] · /kb search <term> · /kb show <challenge> · /kb cheatsheet · /kb capture{C_RESET}\n");
    out
}

// ─── Render: Stats ────────────────────────────────────────────────────────────

pub fn render_stats() -> String {
    let db = load_db();
    let entries = match db["entries"].as_array() {
        Some(a) if !a.is_empty() => a.clone(),
        _ => return format!("{C_STONE}Knowledge base is empty.{C_RESET}\n"),
    };

    let width = term_width().min(96);
    let div = divider(width);
    let bar_w = 32usize;

    let solved_count = entries
        .iter()
        .filter(|e| e["solved"].as_bool().unwrap_or(false))
        .count();

    let mut out = format!("{C_TEAL}{C_BOLD}◆ CTF Knowledge Base — Full Stats{C_RESET}  {C_DIM}({} challenges, {} solved){C_RESET}\n",
        entries.len(), solved_count);
    out += &format!("{C_DARK_ASH}{div}{C_RESET}\n\n");

    // Category distribution
    let mut cat_counts: HashMap<String, usize> = HashMap::new();
    for e in &entries {
        *cat_counts
            .entry(e["category"].as_str().unwrap_or("misc").to_string())
            .or_insert(0) += 1;
    }
    let mut sorted_cats: Vec<(String, usize)> = cat_counts.into_iter().collect();
    sorted_cats.sort_by(|a, b| b.1.cmp(&a.1));
    let max_cat = sorted_cats.first().map_or(1, |(_, c)| *c);

    out += &format!("{C_ASH}▸ Category Distribution{C_RESET}\n");
    for (cat, count) in &sorted_cats {
        let color = category_color(cat);
        let b = bar_fill(*count, max_cat, bar_w);
        out += &format!("  {color}{cat:<10}{C_RESET}  {C_STONE}{b}{C_RESET}  {count:3}  {C_DIM}({:.1}%){C_RESET}\n",
            *count as f64 / entries.len() as f64 * 100.0);
    }
    out += "\n";

    // Vulnerability frequency (top 15)
    let mut vuln_cats: HashMap<String, Vec<String>> = HashMap::new();
    for e in &entries {
        let cat = e["category"].as_str().unwrap_or("misc").to_string();
        for v in e["vulns"].as_array().unwrap_or(&vec![]) {
            if let Some(name) = v.as_str() {
                vuln_cats
                    .entry(name.to_string())
                    .or_default()
                    .push(cat.clone());
            }
        }
    }
    let mut sorted_vulns: Vec<(String, Vec<String>)> = vuln_cats.into_iter().collect();
    sorted_vulns.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    let max_vuln = sorted_vulns.first().map_or(1, |(_, v)| v.len());

    out += &format!("{C_ASH}▸ Vulnerability Frequency (top 15){C_RESET}\n");
    for (vuln, cats) in sorted_vulns.iter().take(15) {
        let count = cats.len();
        let b = bar_fill(count, max_vuln, bar_w);
        let vuln_trunc = if vuln.len() > 40 {
            &vuln[..40]
        } else {
            vuln.as_str()
        };
        out += &format!("  {C_INK}{vuln_trunc:<42}{C_RESET}  {C_STONE}{b}{C_RESET}  {count:3}×\n");
    }
    out += "\n";

    // OWASP distribution
    let mut owasp_counts: HashMap<String, usize> = HashMap::new();
    for e in &entries {
        for v in e["owasp"].as_array().unwrap_or(&vec![]) {
            if let Some(s) = v.as_str() {
                *owasp_counts.entry(s.to_string()).or_insert(0) += 1;
            }
        }
    }
    if !owasp_counts.is_empty() {
        let mut sorted_owasp: Vec<(String, usize)> = owasp_counts.into_iter().collect();
        sorted_owasp.sort_by(|a, b| b.1.cmp(&a.1));
        let max_ow = sorted_owasp.first().map_or(1, |(_, c)| *c);
        out += &format!("{C_ASH}▸ OWASP / CWE Distribution{C_RESET}\n");
        for (tag, count) in sorted_owasp.iter().take(12) {
            let b = bar_fill(*count, max_ow, 20);
            let tag_trunc = if tag.len() > 46 {
                &tag[..46]
            } else {
                tag.as_str()
            };
            out +=
                &format!("  {C_TEAL}{tag_trunc:<48}{C_RESET}  {C_STONE}{b}{C_RESET}  {count:3}×\n");
        }
        out += "\n";
    }

    // Tag cloud (top 40)
    let mut tag_counts: HashMap<String, usize> = HashMap::new();
    for e in &entries {
        for t in e["tags"].as_array().unwrap_or(&vec![]) {
            if let Some(tag) = t.as_str() {
                *tag_counts.entry(tag.to_string()).or_insert(0) += 1;
            }
        }
    }
    if !tag_counts.is_empty() {
        let mut sorted_tags: Vec<(String, usize)> = tag_counts.into_iter().collect();
        sorted_tags.sort_by(|a, b| b.1.cmp(&a.1));
        out += &format!("{C_ASH}▸ Tag Cloud{C_RESET}\n  ");
        let colors = [C_TEAL, C_SAGE, C_STONE, C_INK, C_ASH, C_DARK_ASH];
        let mut line_len = 0usize;
        for (col_idx, (tag, count)) in sorted_tags.iter().take(40).enumerate() {
            let display = if *count > 1 {
                format!("{tag}({count})")
            } else {
                tag.clone()
            };
            if line_len + display.len() + 2 > width - 2 {
                out += "\n  ";
                line_len = 0;
            }
            out += &format!("{}{display}{C_RESET}  ", colors[col_idx % colors.len()]);
            line_len += display.len() + 2;
        }
        out += "\n\n";
    }

    // Monthly timeline
    let mut month_counts: HashMap<String, usize> = HashMap::new();
    for e in &entries {
        let ts = e["timestamp"].as_u64().unwrap_or(0);
        let month = format_timestamp(ts).chars().take(7).collect::<String>();
        *month_counts.entry(month).or_insert(0) += 1;
    }
    if !month_counts.is_empty() {
        let mut sorted_months: Vec<(String, usize)> = month_counts.into_iter().collect();
        sorted_months.sort_by(|a, b| a.0.cmp(&b.0));
        let max_m = sorted_months.iter().map(|(_, c)| *c).max().unwrap_or(1);
        out += &format!("{C_ASH}▸ Timeline (by month){C_RESET}\n");
        for (month, count) in &sorted_months {
            let b = bar_fill(*count, max_m, 20);
            out += &format!("  {C_DIM}{month}{C_RESET}  {C_TEAL}{b}{C_RESET}  {count:2}\n");
        }
        out += "\n";
    }

    // Multi-vuln challenges (complexity indicator)
    let mut complex: Vec<(String, String, usize)> = entries
        .iter()
        .map(|e| {
            (
                e["challenge"].as_str().unwrap_or("?").to_string(),
                e["category"].as_str().unwrap_or("misc").to_string(),
                e["vulns"].as_array().map_or(0, std::vec::Vec::len),
            )
        })
        .filter(|(_, _, vc)| *vc > 1)
        .collect();
    complex.sort_by(|a, b| b.2.cmp(&a.2));
    if !complex.is_empty() {
        out += &format!(
            "{C_ASH}▸ Multi-Vuln Challenges{C_RESET}  {C_DIM}(chained exploits){C_RESET}\n"
        );
        for (name, cat, count) in complex.iter().take(10) {
            let color = category_color(cat);
            let n = if name.len() > 30 {
                &name[..30]
            } else {
                name.as_str()
            };
            out += &format!("  {color}{cat:<10}{C_RESET}  {C_INK}{n:<32}{C_RESET}  {C_DIM}{count} vulns{C_RESET}\n");
        }
        out += "\n";
    }

    out += &format!("{C_DARK_ASH}{div}{C_RESET}\n");
    out
}

// ─── Render: List ─────────────────────────────────────────────────────────────

pub fn render_list(filter: Option<&str>) -> String {
    let db = load_db();
    let entries = match db["entries"].as_array() {
        Some(a) if !a.is_empty() => a.clone(),
        _ => return format!("{C_STONE}Knowledge base is empty.{C_RESET}\n"),
    };

    let filtered: Vec<&Value> = entries
        .iter()
        .filter(|e| match filter {
            None => true,
            Some(f) => e["category"].as_str().unwrap_or("").eq_ignore_ascii_case(f),
        })
        .collect();

    if filtered.is_empty() {
        return format!(
            "{C_STONE}No entries for category '{}'.{C_RESET}\n",
            filter.unwrap_or("?")
        );
    }

    let width = term_width().min(96);
    let div = divider(width);
    let header = match filter {
        Some(f) => format!(
            "{C_TEAL}{C_BOLD}◆ KB — {f}{C_RESET}  {C_DIM}({} entries){C_RESET}\n",
            filtered.len()
        ),
        None => format!(
            "{C_TEAL}{C_BOLD}◆ KB — All{C_RESET}  {C_DIM}({} entries){C_RESET}\n",
            filtered.len()
        ),
    };

    let mut out = header;
    out += &format!("{C_DARK_ASH}{div}{C_RESET}\n");
    out += &format!(
        "  {C_ASH}{:<4}  {:<10}  {:<24}  {:<34}  {}{C_RESET}\n",
        "OK", "Category", "Challenge", "Vulnerability", "Date"
    );
    out += &format!("  {C_DARK_ASH}{}\n{C_RESET}", "─".repeat(width - 4));

    let mut sorted = filtered;
    sorted.sort_by(|a, b| {
        b["timestamp"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["timestamp"].as_u64().unwrap_or(0))
    });

    for e in &sorted {
        let cat = e["category"].as_str().unwrap_or("misc");
        let color = category_color(cat);
        let name = e["challenge"].as_str().unwrap_or("?");
        let first_vuln = e["vulns"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let date = format_timestamp(e["timestamp"].as_u64().unwrap_or(0));
        let vuln_count = e["vulns"].as_array().map_or(0, std::vec::Vec::len);
        let solved = if e["solved"].as_bool().unwrap_or(false) {
            format!("{C_SAGE}✓{C_RESET}   ")
        } else {
            format!("{C_DARK_ASH}·{C_RESET}   ")
        };

        let name_trunc = if name.len() > 24 { &name[..24] } else { name };
        let vuln_trunc = if first_vuln.len() > 32 {
            &first_vuln[..32]
        } else {
            first_vuln
        };
        let vuln_suffix = if vuln_count > 1 {
            format!("+{}", vuln_count - 1)
        } else {
            String::new()
        };

        out += &format!("  {solved}{color}{cat:<10}{C_RESET}  {C_INK}{name_trunc:<24}{C_RESET}  {C_DIM}{vuln_trunc:<34}{vuln_suffix}{C_RESET}  {C_DARK_ASH}{date}{C_RESET}\n");
    }

    out += &format!("{C_DARK_ASH}{div}{C_RESET}\n");
    out
}

// ─── Render: Search ───────────────────────────────────────────────────────────

pub fn render_search(term: &str) -> String {
    let db = load_db();
    let entries = match db["entries"].as_array() {
        Some(a) if !a.is_empty() => a.clone(),
        _ => return format!("{C_STONE}Knowledge base is empty.{C_RESET}\n"),
    };

    let lower = term.to_lowercase();
    let matches: Vec<&Value> = entries
        .iter()
        .filter(|e| {
            let challenge = e["challenge"].as_str().unwrap_or("").to_lowercase();
            let description = e["description"].as_str().unwrap_or("").to_lowercase();
            let vulns = e["vulns"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            let tags = e["tags"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            let indicators = e["indicators"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            let owasp = e["owasp"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            challenge.contains(&lower)
                || description.contains(&lower)
                || vulns.contains(&lower)
                || tags.contains(&lower)
                || indicators.contains(&lower)
                || owasp.contains(&lower)
        })
        .collect();

    if matches.is_empty() {
        return format!("{C_STONE}No results for '{term}'.{C_RESET}\n");
    }

    let width = term_width().min(88);
    let div = divider(width);
    let mut out = format!(
        "{C_TEAL}{C_BOLD}◆ Search: {term}{C_RESET}  {C_DIM}({} match{}){C_RESET}\n",
        matches.len(),
        if matches.len() == 1 { "" } else { "es" }
    );
    out += &format!("{C_DARK_ASH}{div}{C_RESET}\n\n");

    for e in &matches {
        let cat = e["category"].as_str().unwrap_or("misc");
        let color = category_color(cat);
        let name = e["challenge"].as_str().unwrap_or("?");
        let date = format_timestamp(e["timestamp"].as_u64().unwrap_or(0));
        let vulns: Vec<String> = e["vulns"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let owasp: Vec<String> = e["owasp"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let indicators: Vec<String> = e["indicators"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let desc = e["description"].as_str().unwrap_or("");
        let solved_mark = if e["solved"].as_bool().unwrap_or(false) {
            format!("{C_SAGE}✓{C_RESET} ")
        } else {
            String::new()
        };

        out += &format!("  {solved_mark}{color}[{cat}]{C_RESET}  {C_BOLD}{name}{C_RESET}  {C_DIM}({date}){C_RESET}\n");
        for v in &vulns {
            out += &format!("          {C_TEAL}•{C_RESET} {C_INK}{v}{C_RESET}\n");
        }
        if !owasp.is_empty() {
            let ow = owasp.iter().take(2).cloned().collect::<Vec<_>>().join("  ");
            out += &format!("          {C_DIM}{ow}{C_RESET}\n");
        }
        if !indicators.is_empty() {
            let ind = indicators
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(" · ");
            out += &format!("          {C_DARK_ASH}Indicators: {ind}{C_RESET}\n");
        }
        if !desc.is_empty() {
            let d = if desc.len() > 90 {
                format!("{}…", &desc[..90])
            } else {
                desc.to_string()
            };
            out += &format!("          {C_DIM}{d}{C_RESET}\n");
        }
        out += "\n";
    }
    out
}

// ─── Render: Show ─────────────────────────────────────────────────────────────

pub fn render_show(query: &str) -> String {
    let db = load_db();
    let entries = match db["entries"].as_array() {
        Some(a) => a.clone(),
        None => return format!("{C_STONE}Knowledge base is empty.{C_RESET}\n"),
    };

    let lower = query.to_lowercase();
    let e = match entries.iter().find(|e| {
        e["challenge"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains(&lower)
            || e["id"]
                .as_str()
                .unwrap_or("")
                .to_lowercase()
                .contains(&lower)
    }) {
        Some(e) => e.clone(),
        None => return format!("{C_STONE}No entry found matching '{query}'.{C_RESET}\n"),
    };

    let width = term_width().min(88);
    let div = divider(width);
    let cat = e["category"].as_str().unwrap_or("misc");
    let color = category_color(cat);
    let name = e["challenge"].as_str().unwrap_or("?");
    let date = format_timestamp(e["timestamp"].as_u64().unwrap_or(0));
    let desc = e["description"].as_str().unwrap_or("");
    let solved = e["solved"].as_bool().unwrap_or(false);

    let solved_mark = if solved {
        format!("{C_SAGE}✓ Solved{C_RESET}  ")
    } else {
        format!("{C_DARK_ASH}· Unsolved{C_RESET}  ")
    };

    let mut out = format!(
        "{C_BOLD}{name}{C_RESET}  {color}[{cat}]{C_RESET}  {C_DIM}{date}{C_RESET}  {solved_mark}\n"
    );
    out += &format!("{C_DARK_ASH}{div}{C_RESET}\n\n");

    // Vulnerabilities
    let vulns: Vec<String> = e["vulns"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if !vulns.is_empty() {
        out += &format!("{C_ASH}Vulnerabilities{C_RESET}\n");
        for v in &vulns {
            out += &format!("  {C_TEAL}•{C_RESET} {C_INK}{v}{C_RESET}\n");
        }
        out += "\n";
    }

    // OWASP / CWE
    let owasp: Vec<String> = e["owasp"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if !owasp.is_empty() {
        out += &format!("{C_ASH}OWASP / CWE{C_RESET}\n");
        for ow in &owasp {
            out += &format!("  {C_DARK_ASH}▸{C_RESET} {C_DIM}{ow}{C_RESET}\n");
        }
        out += "\n";
    }

    // Recognition indicators
    let indicators: Vec<String> = e["indicators"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if !indicators.is_empty() {
        out += &format!("{C_ASH}Recognition Indicators{C_RESET}\n");
        for ind in &indicators {
            out += &format!("  {C_STONE}→{C_RESET} {ind}\n");
        }
        out += "\n";
    }

    // Description
    if !desc.is_empty() {
        out += &format!("{C_ASH}Description{C_RESET}\n");
        for line in wrap_text(desc, width - 4) {
            out += &format!("  {C_DIM}{line}{C_RESET}\n");
        }
        out += "\n";
    }

    // Tags
    let tags: Vec<String> = e["tags"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if !tags.is_empty() {
        out += &format!(
            "{C_ASH}Tags{C_RESET}  {C_TEAL}{}{C_RESET}\n\n",
            tags.join("  ")
        );
    }

    // Code snippets
    let snippets = e["snippets"].as_array().cloned().unwrap_or_default();
    for snippet in &snippets {
        let label = snippet["label"].as_str().unwrap_or("snippet");
        let code = snippet["code"].as_str().unwrap_or("");
        out += &format!("{C_ASH}Snippet: {label}{C_RESET}\n");
        out += &format!(
            "{C_DARK_ASH}{}{C_RESET}\n",
            "─".repeat((label.len() + 9).min(width))
        );
        for line in code.lines().take(50) {
            out += &format!("  {C_DIM}{line}{C_RESET}\n");
        }
        if code.lines().count() > 50 {
            out += &format!("  {C_DARK_ASH}… (truncated){C_RESET}\n");
        }
        out += "\n";
    }

    out += &format!("{C_DARK_ASH}{div}{C_RESET}\n");
    out
}

// ─── Writeup/reference notes corpus ─────────────────────────────────────────────
// Agent-curated technique notes saved under <skills_dir>/writeups/<category>/*.md,
// indexed by <skills_dir>/writeups/_index.jsonl (one JSON object per line, schema
// `IndexEntry` below) and a Claude-skills fallback dir. The index — not the raw
// markdown — is what `kb_search` matches against, so the agent can recall prior
// research by technique/trigger-signal without re-crawling the web or bloating
// the prompt. `kb_read(id)` fetches the full markdown for a matched entry.

/// One row of `writeups/_index.jsonl`. `path` is relative to the directory the
/// index file lives in (e.g. `crypto/wu-00042.md`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IndexEntry {
    pub id: String,
    #[serde(default)]
    pub source: String,
    pub category: String,
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub techniques: Vec<String>,
    #[serde(default)]
    pub primitives: Vec<String>,
    #[serde(default)]
    pub difficulty: String,
    pub summary: String,
    #[serde(default)]
    pub trigger_signals: Vec<String>,
    pub path: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub year: u32,
    #[serde(default)]
    pub quality: f32,
}

fn writeups_dirs() -> Vec<PathBuf> {
    let local_base = if let Ok(dir) = std::env::var("CTF_SKILLS_DIR") {
        PathBuf::from(dir)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".local/share/ctf-skills")
    };

    let claude_base = if let Ok(dir) = std::env::var("CLAUDE_CONFIG_HOME") {
        PathBuf::from(dir).join("skills")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".claude/skills")
    };

    vec![local_base.join("writeups"), claude_base.join("writeups")]
}

/// Load all `_index.jsonl` entries from every writeups dir, paired with the
/// base dir they came from (needed to resolve `entry.path`). Malformed lines
/// are skipped.
fn load_index_entries() -> Vec<(PathBuf, IndexEntry)> {
    let mut out = Vec::new();
    for base in writeups_dirs() {
        let Ok(content) = fs::read_to_string(base.join("_index.jsonl")) else {
            continue;
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<IndexEntry>(line) {
                out.push((base.clone(), entry));
            }
        }
    }
    out
}

/// Term-frequency score for an index entry against lowercase query `terms`,
/// weighting fields by how strongly they signal relevance: trigger signals
/// (early recognition patterns in a challenge) score highest, then
/// tags/techniques, then title/summary/primitives.
fn score_index_entry(entry: &IndexEntry, terms: &[String]) -> f32 {
    let fields: [(f32, String); 6] = [
        (3.0, entry.trigger_signals.join(" ")),
        (2.0, entry.tags.join(" ")),
        (2.0, entry.techniques.join(" ")),
        (1.5, entry.title.clone()),
        (1.0, entry.summary.clone()),
        (1.0, entry.primitives.join(" ")),
    ];

    let mut score = 0.0;
    for (weight, field) in &fields {
        let lower = field.to_lowercase();
        for term in terms {
            if lower.contains(term.as_str()) {
                score += weight;
            }
        }
    }
    score
}

/// Search the solved-challenge KB and the writeups/reference index for `query`,
/// returning a compact plain-text summary for the agent (used by the `kb_search`
/// tool). `category` optionally restricts writeup-index matches; `top_k` caps
/// how many writeup-index results are returned.
#[must_use]
pub fn kb_search(query: &str, category: Option<&str>, top_k: usize) -> String {
    let lower_query = query.to_lowercase();
    let terms: Vec<String> = lower_query.split_whitespace().map(str::to_string).collect();
    let terms: Vec<String> = if terms.is_empty() {
        vec![lower_query.clone()]
    } else {
        terms
    };

    let mut out = String::new();

    let db = load_db();
    if let Some(entries) = db["entries"].as_array() {
        let matches: Vec<&Value> = entries
            .iter()
            .filter(|e| {
                let challenge = e["challenge"].as_str().unwrap_or("").to_lowercase();
                let description = e["description"].as_str().unwrap_or("").to_lowercase();
                let vulns = e["vulns"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_lowercase();
                let tags = e["tags"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_lowercase();
                let indicators = e["indicators"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_lowercase();
                challenge.contains(&lower_query)
                    || description.contains(&lower_query)
                    || vulns.contains(&lower_query)
                    || tags.contains(&lower_query)
                    || indicators.contains(&lower_query)
            })
            .take(5)
            .collect();

        if !matches.is_empty() {
            out += "## Solved challenges (local KB)\n\n";
            for e in &matches {
                let name = e["challenge"].as_str().unwrap_or("?");
                let cat = e["category"].as_str().unwrap_or("misc");
                let desc = e["description"].as_str().unwrap_or("");
                let vulns: Vec<&str> = e["vulns"]
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                out += &format!("- [{cat}] {name}: {}\n", vulns.join(", "));
                if !desc.is_empty() {
                    out += &format!("  {desc}\n");
                }
            }
            out += "\n";
        }
    }

    let mut scored: Vec<(f32, IndexEntry)> = load_index_entries()
        .into_iter()
        .map(|(_, e)| e)
        .filter(|e| category.is_none_or(|c| e.category.eq_ignore_ascii_case(c)))
        .map(|e| (score_index_entry(&e, &terms), e))
        .filter(|(score, _)| *score > 0.0)
        .collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(top_k.max(1));

    if !scored.is_empty() {
        out += "## Writeup / reference notes\n\n";
        for (score, e) in &scored {
            out += &format!(
                "- id={} [{}/{}] {} (score {score:.1})\n",
                e.id, e.source, e.category, e.title
            );
            out += &format!("  summary: {}\n", e.summary);
            if !e.trigger_signals.is_empty() {
                out += &format!("  triggers: {}\n", e.trigger_signals.join(", "));
            }
            out += &format!("  -> kb_read(\"{}\") for full content\n", e.id);
        }
        out += "\n";
    }

    let mut scored_learned: Vec<(f32, LearnedEntry)> = load_learned_entries()
        .into_iter()
        .filter(|e| category.is_none_or(|c| e.category.eq_ignore_ascii_case(c)))
        .map(|e| (score_learned_entry(&e, &terms), e))
        .filter(|(score, _)| *score > 0.0)
        .collect();
    scored_learned.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    scored_learned.truncate(top_k.max(1));

    if !scored_learned.is_empty() {
        out += "## Learned patterns (agent-recorded, lower confidence — verify)\n\n";
        for (score, e) in &scored_learned {
            out += &format!(
                "- id={} [{}] confidence={} (score {score:.1})\n",
                e.id, e.category, e.confidence
            );
            if !e.fingerprint.is_empty() {
                out += &format!("  fingerprint: {}\n", e.fingerprint.join(", "));
            }
            out += &format!("  worked: {}\n", e.what_worked);
            if !e.what_failed.is_empty() {
                out += &format!("  failed: {}\n", e.what_failed);
            }
        }
        out += "\n";
    }

    if out.is_empty() {
        format!(
            "No matches for '{query}' in the solved-challenge KB or writeups/reference index.\n\
             Tip: after researching a technique via WebSearch/WebFetch, save a markdown summary \
             to ~/.local/share/ctf-skills/writeups/<category>/<slug>.md and append an index entry \
             (id, source, category, title, tags, techniques, primitives, difficulty, summary, \
             trigger_signals, path, url, year, quality) to \
             ~/.local/share/ctf-skills/writeups/_index.jsonl so it can be found here next time."
        )
    } else {
        out
    }
}

/// Fetch the full markdown content for a writeup/reference index entry by `id`
/// (used by the `kb_read` tool, after `kb_search` surfaces a relevant id).
#[must_use]
pub fn kb_read(id: &str) -> String {
    for (base, entry) in load_index_entries() {
        if entry.id == id {
            let path = base.join(&entry.path);
            return match fs::read_to_string(&path) {
                Ok(content) => content,
                Err(err) => format!("Failed to read {}: {err}", path.display()),
            };
        }
    }
    format!("No index entry found with id '{id}'. Use kb_search to find valid ids.")
}

// ─── Learned tier ────────────────────────────────────────────────────────────
// Agent-accumulated patterns from past sessions, appended to
// <skills_dir>/learned/kb.jsonl via the `kb_add` tool. Lowest-confidence tier —
// written by the agent itself, possibly wrong — but cheap to record and records
// dead ends (`what_failed`) as well as what worked.

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LearnedEntry {
    pub id: String,
    pub category: String,
    #[serde(default)]
    pub fingerprint: Vec<String>,
    pub what_worked: String,
    #[serde(default)]
    pub what_failed: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub session_ref: String,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub timestamp: u64,
}

fn local_skills_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CTF_SKILLS_DIR") {
        PathBuf::from(dir)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".local/share/ctf-skills")
    }
}

fn learned_path() -> PathBuf {
    local_skills_dir().join("learned").join("kb.jsonl")
}

/// Load all `learned/kb.jsonl` entries. Malformed lines are skipped.
fn load_learned_entries() -> Vec<LearnedEntry> {
    let Ok(content) = fs::read_to_string(learned_path()) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            serde_json::from_str(line).ok()
        })
        .collect()
}

/// Term-frequency score for a learned entry, weighting `fingerprint` (the
/// recognition signals for when this pattern applies) highest, then `tags`,
/// then the free-text `what_worked`/`what_failed`.
fn score_learned_entry(entry: &LearnedEntry, terms: &[String]) -> f32 {
    let fields: [(f32, String); 4] = [
        (3.0, entry.fingerprint.join(" ")),
        (2.0, entry.tags.join(" ")),
        (1.0, entry.what_worked.clone()),
        (1.0, entry.what_failed.clone()),
    ];

    let mut score = 0.0;
    for (weight, field) in &fields {
        let lower = field.to_lowercase();
        for term in terms {
            if lower.contains(term.as_str()) {
                score += weight;
            }
        }
    }
    score
}

/// Append a new entry to `learned/kb.jsonl` (used by the `kb_add` tool, normally
/// called after a challenge is solved or a dead end is identified).
pub fn kb_add(
    category: &str,
    fingerprint: Vec<String>,
    what_worked: &str,
    what_failed: &str,
    tags: Vec<String>,
    session_ref: &str,
    confidence: &str,
) -> Result<String, String> {
    use std::io::Write;

    let path = learned_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let id = format!("lk-{timestamp}");

    let entry = LearnedEntry {
        id: id.clone(),
        category: category.to_string(),
        fingerprint,
        what_worked: what_worked.to_string(),
        what_failed: what_failed.to_string(),
        tags,
        session_ref: session_ref.to_string(),
        confidence: confidence.to_string(),
        timestamp,
    };

    let line = serde_json::to_string(&entry).map_err(|e| e.to_string())?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    writeln!(file, "{line}").map_err(|e| e.to_string())?;

    Ok(id)
}

// ─── Capture prompt ───────────────────────────────────────────────────────────

/// Returns the prompt to send to the agent for /kb capture.
pub fn capture_prompt(capture_path: &std::path::Path) -> String {
    format!(
        "Capture this challenge's vulnerability for the shared knowledge base.\n\
         Analyze the challenge files, notes.md, and our conversation to identify what weakness was exploited.\n\
         Then use bash to write a JSON object to {path}:\n\n\
         ```\n\
         cat > {path} << 'KB_EOF'\n\
         {{\n\
           \"vulns\": [\"specific technical name — e.g. 'RSA small exponent e=3 broadcast attack', 'stack BOF with ROP ret2libc', 'SQL injection UNION-based'\"],\n\
           \"owasp\": [\"OWASP category and CWE — e.g. 'A03:2021 Injection (CWE-89)', 'CWE-121 Stack BOF'\"],\n\
           \"indicators\": [\"patterns that would suggest this vuln early — e.g. 'small public exponent e=3', 'gets() or strcpy() without bounds', 'user input directly in SQL query', 'no CSRF token in form'\"],\n\
           \"description\": \"1-3 sentence technical summary: what the weakness was and the key exploit technique\",\n\
           \"solved\": true,\n\
           \"snippets\": [\n\
             {{\"label\": \"exploit.py\", \"code\": \"# decisive exploit code, max 30 lines\"}}\n\
           ],\n\
           \"tags\": [\"keyword1\", \"keyword2\", \"keyword3\"]\n\
         }}\n\
         KB_EOF\n\
         ```\n\n\
         Rules:\n\
         - vulns: use specific technical names (not just 'buffer overflow' — say 'stack buffer overflow via gets() with ROP chain ret2libc')\n\
         - owasp: map to OWASP Top 10 2021 (e.g. A03:2021) and/or CWE number. Use empty array [] if not applicable (forensics/osint).\n\
         - indicators: 3-6 early recognition signals someone would observe in the challenge (file analysis, network traffic, source code patterns, binary properties)\n\
         - description: ≤ 150 words, technically precise\n\
         - solved: true if flag was found, false if we're capturing partial progress\n\
         - snippets: max 2 entries, max 30 lines each — only the decisive exploit/solve code\n\
         - tags: 3-6 searchable keywords\n\
         Write the file now, then confirm the path.",
        path = capture_path.display()
    )
}

/// Returns the prompt to send to the agent right after a flag is found, so the
/// session's vulnerability gets recorded in the KB without a manual /kb capture.
pub fn auto_capture_prompt(capture_path: &std::path::Path, flag: &str) -> String {
    format!(
        "We just found the flag for this challenge: {flag}\n\n\
         Capture this challenge's vulnerability for the shared knowledge base.\n\
         Analyze the challenge files, notes.md, and our conversation to identify what weakness was exploited.\n\
         Then use bash to write a JSON object to {path}:\n\n\
         ```\n\
         cat > {path} << 'KB_EOF'\n\
         {{\n\
           \"vulns\": [\"specific technical name — e.g. 'RSA small exponent e=3 broadcast attack', 'stack BOF with ROP ret2libc', 'SQL injection UNION-based'\"],\n\
           \"owasp\": [\"OWASP category and CWE — e.g. 'A03:2021 Injection (CWE-89)', 'CWE-121 Stack BOF'\"],\n\
           \"indicators\": [\"patterns that would suggest this vuln early — e.g. 'small public exponent e=3', 'gets() or strcpy() without bounds', 'user input directly in SQL query', 'no CSRF token in form'\"],\n\
           \"description\": \"1-3 sentence technical summary: what the weakness was and the key exploit technique\",\n\
           \"solved\": true,\n\
           \"flag\": \"{flag}\",\n\
           \"snippets\": [\n\
             {{\"label\": \"exploit.py\", \"code\": \"# decisive exploit code, max 30 lines\"}}\n\
           ],\n\
           \"tags\": [\"keyword1\", \"keyword2\", \"keyword3\"]\n\
         }}\n\
         KB_EOF\n\
         ```\n\n\
         Rules:\n\
         - vulns: use specific technical names (not just 'buffer overflow' — say 'stack buffer overflow via gets() with ROP chain ret2libc')\n\
         - owasp: map to OWASP Top 10 2021 (e.g. A03:2021) and/or CWE number. Use empty array [] if not applicable (forensics/osint).\n\
         - indicators: 3-6 early recognition signals someone would observe in the challenge (file analysis, network traffic, source code patterns, binary properties)\n\
         - description: ≤ 150 words, technically precise\n\
         - snippets: max 2 entries, max 30 lines each — only the decisive exploit/solve code\n\
         - tags: 3-6 searchable keywords\n\
         Write the file now, then confirm the path. Do not do anything else.",
        path = capture_path.display()
    )
}

// ─── Utilities ────────────────────────────────────────────────────────────────

fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= max_width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current.clone());
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // CTF_SKILLS_DIR / CLAUDE_CONFIG_HOME are process-wide env vars read by
    // writeups_dirs(); serialize tests that touch them so they don't clobber
    // each other when run in parallel.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_writeups_index(jsonl: &str, body: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile_dir();
        let writeups = dir.join("writeups");
        fs::create_dir_all(writeups.join("crypto")).unwrap();
        fs::write(
            writeups.join("crypto").join("jwt-alg-none.md"),
            "# JWT alg:none bypass\n\nStrip the signature and set alg to none.\n",
        )
        .unwrap();
        fs::write(writeups.join("_index.jsonl"), jsonl).unwrap();

        let prev_skills = std::env::var("CTF_SKILLS_DIR").ok();
        let prev_claude = std::env::var("CLAUDE_CONFIG_HOME").ok();
        std::env::set_var("CTF_SKILLS_DIR", &dir);
        std::env::set_var("CLAUDE_CONFIG_HOME", dir.join("no-claude-skills"));

        body();

        match prev_skills {
            Some(v) => std::env::set_var("CTF_SKILLS_DIR", v),
            None => std::env::remove_var("CTF_SKILLS_DIR"),
        }
        match prev_claude {
            Some(v) => std::env::set_var("CLAUDE_CONFIG_HOME", v),
            None => std::env::remove_var("CLAUDE_CONFIG_HOME"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    fn tempfile_dir() -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "ctf-kb-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    const ENTRY: &str = r#"{"id":"wu-00001","source":"hacktricks","category":"web","title":"JWT alg:none bypass","tags":["jwt","auth-bypass"],"techniques":["alg none"],"primitives":["jwt"],"difficulty":"easy","summary":"Set JWT header alg to none and strip signature to forge claims.","trigger_signals":["JWT token","alg field in header","no signature verification"],"path":"crypto/jwt-alg-none.md","url":"https://example.com","year":2023,"quality":0.9}"#;

    #[test]
    fn score_index_entry_weights_trigger_signals_highest() {
        let entry: IndexEntry = serde_json::from_str(ENTRY).unwrap();
        let terms = vec!["jwt".to_string()];
        // "jwt" appears in tags, primitives, summary, and trigger_signals.
        let score = score_index_entry(&entry, &terms);
        assert!(score > 0.0);

        let no_match = score_index_entry(&entry, &["sqlmap".to_string()]);
        assert!(no_match.abs() < f32::EPSILON);
    }

    #[test]
    fn kb_search_finds_indexed_writeup_by_trigger_signal() {
        with_writeups_index(&format!("{ENTRY}\n"), || {
            let out = kb_search("alg field in header", None, 5);
            assert!(out.contains("wu-00001"), "expected hit, got: {out}");
            assert!(out.contains("JWT alg:none bypass"));
        });
    }

    #[test]
    fn kb_search_respects_category_filter() {
        with_writeups_index(&format!("{ENTRY}\n"), || {
            let out = kb_search("jwt", Some("pwn"), 5);
            assert!(
                !out.contains("wu-00001"),
                "category filter should exclude web entry: {out}"
            );
        });
    }

    #[test]
    fn kb_search_reports_no_match_with_tip() {
        with_writeups_index("", || {
            let out = kb_search("nonexistent-technique-xyz", None, 5);
            assert!(out.contains("No matches"));
            assert!(out.contains("_index.jsonl"));
        });
    }

    #[test]
    fn kb_read_returns_full_markdown_for_known_id() {
        with_writeups_index(&format!("{ENTRY}\n"), || {
            let out = kb_read("wu-00001");
            assert!(out.contains("Strip the signature"));
        });
    }

    #[test]
    fn kb_read_reports_unknown_id() {
        with_writeups_index(&format!("{ENTRY}\n"), || {
            let out = kb_read("wu-99999");
            assert!(out.contains("No index entry found"));
        });
    }

    #[test]
    fn kb_add_then_kb_search_surfaces_learned_pattern() {
        with_writeups_index("", || {
            let id = kb_add(
                "pwn",
                vec![
                    "64-bit".to_string(),
                    "no canary".to_string(),
                    "win() present".to_string(),
                ],
                "ret2win: overflow to saved RIP, jump to win(), offset 40",
                "tried ret2libc first, unnecessary since win() exists",
                vec!["ret2win".to_string(), "buffer-overflow".to_string()],
                "test-challenge",
                "high",
            )
            .expect("kb_add should succeed");
            assert!(id.starts_with("lk-"));

            let out = kb_search("win() present", Some("pwn"), 5);
            assert!(
                out.contains(&id),
                "expected learned entry in results: {out}"
            );
            assert!(out.contains("ret2win"));
            assert!(out.contains("ret2libc"));
        });
    }

    #[test]
    fn kb_add_respects_category_filter_on_search() {
        with_writeups_index("", || {
            let id = kb_add(
                "crypto",
                vec!["rsa".to_string()],
                "common modulus attack",
                "",
                vec!["rsa".to_string()],
                "test-challenge",
                "medium",
            )
            .expect("kb_add should succeed");

            let out = kb_search("rsa", Some("pwn"), 5);
            assert!(
                !out.contains(&id),
                "category filter should exclude crypto entry: {out}"
            );
        });
    }
}
