use regex::Regex;

pub struct FlagExtractor {
    patterns: Vec<Regex>,
}

impl FlagExtractor {
    pub fn new(flag_format_hint: &str) -> Self {
        let mut patterns = vec![
            // Generic broad pattern — matches most CTF flags
            Regex::new(r"[A-Za-z0-9_\-]+\{[^}]{1,200}\}").unwrap(),
            // Common prefixes
            Regex::new(r"(?i)FLAG\{[^}]+\}").unwrap(),
            Regex::new(r"(?i)CTF\{[^}]+\}").unwrap(),
            Regex::new(r"(?i)flag\{[^}]+\}").unwrap(),
        ];

        // Parse custom format hint like "picoCTF{...}" or "UCTF{...}"
        let prefix = flag_format_hint
            .trim_end_matches("{...}")
            .trim_end_matches('{');
        if !prefix.is_empty() && prefix != "FLAG" && prefix != "CTF" {
            let escaped = regex::escape(prefix);
            if let Ok(re) = Regex::new(&format!(r"(?i){}\{{[^}}]+\}}", escaped)) {
                patterns.push(re);
            }
        }

        Self { patterns }
    }

    /// Scan a string for flag patterns. Returns the first match found.
    pub fn scan(&self, text: &str) -> Option<String> {
        self.patterns
            .iter()
            .find_map(|re| re.find(text).map(|m| m.as_str().to_string()))
    }

    /// Scan multiple strings (tool outputs from a turn). Returns first flag found.
    pub fn scan_outputs(&self, outputs: &[String]) -> Option<String> {
        outputs.iter().find_map(|s| self.scan(s))
    }
}

/// Returns ANSI-colored flag banner for terminal display.
pub fn render_flag_found(flag: &str) -> String {
    let width = (flag.len() + 6).max(40);
    let border = "═".repeat(width);
    let padding = " ".repeat((width - flag.len() - 2) / 2);
    format!(
        "\n\x1b[38;5;226m╔{border}╗\n║{padding} {flag} {padding}║\n╚{border}╝\x1b[0m\n",
    )
}
