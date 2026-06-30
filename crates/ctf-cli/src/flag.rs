use regex::Regex;

pub struct FlagExtractor {
    declared_patterns: Vec<Regex>,
    patterns: Vec<Regex>,
}

impl FlagExtractor {
    pub fn new(flag_format_hint: &str) -> Self {
        let declared_patterns = format_patterns(flag_format_hint);
        let mut patterns = declared_patterns.clone();
        patterns.extend([
            // Generic broad pattern — matches most CTF flags
            Regex::new(r"[A-Za-z0-9_\-]+\{[^}]{1,200}\}").unwrap(),
            // Common prefixes
            Regex::new(r"(?i)FLAG\{[^}]+\}").unwrap(),
            Regex::new(r"(?i)CTF\{[^}]+\}").unwrap(),
            Regex::new(r"(?i)flag\{[^}]+\}").unwrap(),
        ]);

        Self {
            declared_patterns,
            patterns,
        }
    }

    /// Scan a string for flag patterns. Returns the first match found.
    pub fn scan(&self, text: &str) -> Option<String> {
        self.patterns.iter().find_map(|re| {
            re.find_iter(text)
                .map(|m| m.as_str().to_string())
                .find(|candidate| !is_placeholder(candidate))
        })
    }

    /// Look for an explicit "FLAG: <value>" declaration — the convention the
    /// system prompt asks the agent to use only after its VALIDATE phase
    /// confirms the flag via execution. This is a much stronger signal than
    /// `scan`, which can match decoy strings anywhere in raw tool output
    /// (e.g. `strings` dumps of a binary).
    pub fn scan_declared(&self, text: &str) -> Option<String> {
        for line in text.lines() {
            let lower = line.to_lowercase();
            let Some(pos) = lower.find("flag:") else {
                continue;
            };
            let rest = &line[pos + "flag:".len()..];

            if let Some(found) = scan_with_patterns(&self.declared_patterns, rest) {
                return Some(found);
            }
            if self.declared_patterns.is_empty() {
                return self.scan(rest);
            }
        }
        None
    }
}

fn format_patterns(flag_format_hint: &str) -> Vec<Regex> {
    let hint = flag_format_hint.trim();
    if hint.is_empty() {
        return Vec::new();
    }
    let normalized = hint.to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "flag{...}" | "ctf{...}" | "flag" | "ctf"
    ) {
        return Vec::new();
    }

    if let Some((prefix, suffix)) = hint.split_once("...") {
        let escaped_prefix = regex::escape(prefix);
        let escaped_suffix = regex::escape(suffix);
        let body = if suffix == "}" {
            r"[^}\r\n]{1,200}"
        } else {
            r"[^\r\n]{1,200}"
        };
        return Regex::new(&format!(r"(?i){escaped_prefix}{body}{escaped_suffix}"))
            .ok()
            .into_iter()
            .collect();
    }

    Regex::new(&format!(r"(?i){}", regex::escape(hint)))
        .ok()
        .into_iter()
        .collect()
}

fn scan_with_patterns(patterns: &[Regex], text: &str) -> Option<String> {
    patterns.iter().find_map(|re| {
        re.find_iter(text)
            .map(|m| m.as_str().to_string())
            .find(|candidate| !is_placeholder(candidate))
    })
}

/// True if `s` contains at least one alphanumeric character — used to reject
/// placeholders/empty declarations like "...", "N/A", "TBD".
fn looks_like_real(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_alphanumeric())
}

/// True if the `{...}` body of a candidate flag has no alphanumeric
/// characters — i.e. it's a placeholder like `BKSEC{...}` or `FLAG{flag_here}`
/// rather than a real flag.
fn is_placeholder(candidate: &str) -> bool {
    match candidate
        .split_once('{')
        .and_then(|(_, rest)| rest.strip_suffix('}'))
    {
        Some(inner) => !looks_like_real(inner),
        None => false,
    }
}

/// Returns ANSI-colored flag banner for terminal display.
pub fn render_flag_found(flag: &str) -> String {
    let width = (flag.len() + 6).max(40);
    let border = "═".repeat(width);
    let padding = " ".repeat((width - flag.len() - 2) / 2);
    format!("\n\x1b[38;5;226m╔{border}╗\n║{padding} {flag} {padding}║\n╚{border}╝\x1b[0m\n",)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_placeholder_flag() {
        let extractor = FlagExtractor::new("BKSEC{...}");
        let text = "Final flag format reminder: BKSEC{...}";
        assert_eq!(extractor.scan(text), None);
    }

    #[test]
    fn finds_real_flag() {
        let extractor = FlagExtractor::new("BKSEC{...}");
        let text = "Got it: BKSEC{r3al_fl4g_h3re}";
        assert_eq!(
            extractor.scan(text),
            Some("BKSEC{r3al_fl4g_h3re}".to_string())
        );
    }

    #[test]
    fn finds_real_flag_after_placeholder_mention() {
        let extractor = FlagExtractor::new("BKSEC{...}");
        let text = "format is BKSEC{...}, found flag: BKSEC{r3al_fl4g_h3re}";
        assert_eq!(
            extractor.scan(text),
            Some("BKSEC{r3al_fl4g_h3re}".to_string())
        );
    }

    #[test]
    fn scan_declared_finds_explicit_flag_line() {
        let extractor = FlagExtractor::new("BKSEC{...}");
        let text = "Verified via execution.\nFLAG: BKSEC{r3al_fl4g_h3re}\n";
        assert_eq!(
            extractor.scan_declared(text),
            Some("BKSEC{r3al_fl4g_h3re}".to_string())
        );
    }

    #[test]
    fn scan_declared_ignores_strings_dump_without_declaration() {
        let extractor = FlagExtractor::new("BKSEC{...}");
        // A `strings` dump may contain decoy flag-shaped strings, but with no
        // "FLAG:" declaration this must not be treated as found.
        let text = "BKSEC{decoy_string_in_binary}\nBKSEC{another_decoy}";
        assert_eq!(extractor.scan_declared(text), None);
    }

    #[test]
    fn scan_declared_rejects_failed_verification() {
        let extractor = FlagExtractor::new("BKSEC{...}");
        let text = "FLAG VERIFICATION FAILED — that string was a decoy.";
        assert_eq!(extractor.scan_declared(text), None);
    }

    #[test]
    fn scan_declared_rejects_non_format_blob() {
        let extractor = FlagExtractor::new("BKSEC{...}");
        let text = "FLAG: 0000000000000000000000000000000000000000";
        assert_eq!(extractor.scan_declared(text), None);
    }

    #[test]
    fn scan_declared_uses_configured_format_prefix() {
        let extractor = FlagExtractor::new("DUCTF{...}");
        let text = "FLAG: DUCTF{works_for_other_formats}";
        assert_eq!(
            extractor.scan_declared(text),
            Some("DUCTF{works_for_other_formats}".to_string())
        );
    }

    #[test]
    fn scan_declared_rejects_wrong_prefix_when_format_is_configured() {
        let extractor = FlagExtractor::new("DUCTF{...}");
        let text = "FLAG: BKSEC{wrong_competition_prefix}";
        assert_eq!(extractor.scan_declared(text), None);
    }

    #[test]
    fn default_flag_format_allows_generic_ctf_flags() {
        let extractor = FlagExtractor::new("FLAG{...}");
        let text = "FLAG: BKSEC{accepted_when_no_custom_format_is_set}";
        assert_eq!(
            extractor.scan_declared(text),
            Some("BKSEC{accepted_when_no_custom_format_is_set}".to_string())
        );
    }
}
