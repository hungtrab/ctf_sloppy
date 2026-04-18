use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Pwn,
    Web,
    Crypto,
    Rev,
    Forensics,
    Misc,
    Osint,
    Network,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pwn => "pwn",
            Self::Web => "web",
            Self::Crypto => "crypto",
            Self::Rev => "rev",
            Self::Forensics => "forensics",
            Self::Misc => "misc",
            Self::Osint => "osint",
            Self::Network => "network",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().trim() {
            "pwn" | "binary" | "exploit" | "exploitation" => Some(Self::Pwn),
            "web" | "webapp" | "web-exploitation" => Some(Self::Web),
            "crypto" | "cryptography" | "cryptanalysis" => Some(Self::Crypto),
            "rev" | "reverse" | "reversing" | "re" => Some(Self::Rev),
            "forensics" | "forensic" | "for" => Some(Self::Forensics),
            "misc" | "miscellaneous" | "other" => Some(Self::Misc),
            "osint" => Some(Self::Osint),
            "network" | "net" | "networking" | "pcap" => Some(Self::Network),
            _ => None,
        }
    }

    /// Emoji indicator shown in banner
    pub fn emoji(self) -> &'static str {
        match self {
            Self::Pwn => "💥",
            Self::Web => "🌐",
            Self::Crypto => "🔐",
            Self::Rev => "🔍",
            Self::Forensics => "🔬",
            Self::Misc => "🎲",
            Self::Osint => "👁",
            Self::Network => "📡",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Challenge {
    pub name: String,
    pub dir: PathBuf,
    pub category: Category,
    pub flag_format: String,
    pub description: String,
}

impl Challenge {
    /// Load from a challenge directory.
    /// Expected layout:
    ///   <dir>/
    ///     files/          ← challenge binaries/sources/pcaps
    ///     description.txt ← challenge text (optional)
    ///     category.txt    ← single word category (optional)
    ///     flag_format.txt ← e.g. "picoCTF{...}" (optional)
    pub fn load(dir: &Path) -> Self {
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "challenge".to_string());

        let description = fs::read_to_string(dir.join("description.txt"))
            .unwrap_or_default()
            .trim()
            .to_string();

        let flag_format = fs::read_to_string(dir.join("flag_format.txt"))
            .unwrap_or_else(|_| "FLAG{...}".to_string())
            .trim()
            .to_string();

        let category = Self::detect_category(dir, &description);

        Challenge { name, dir: dir.to_path_buf(), category, flag_format, description }
    }

    pub fn with_category(mut self, category: Category) -> Self {
        self.category = category;
        self
    }

    fn detect_category(dir: &Path, description: &str) -> Category {
        // 1. Explicit category.txt
        if let Ok(cat) = fs::read_to_string(dir.join("category.txt")) {
            if let Some(c) = Category::from_str(cat.trim()) {
                return c;
            }
        }

        // 2. File-based heuristics
        let files_dir = dir.join("files");
        let extensions = collect_extensions(&files_dir);
        let has_elf = has_elf_binary(&files_dir);

        if extensions.iter().any(|e| matches!(e.as_str(), "pcap" | "pcapng" | "cap")) {
            return Category::Network;
        }
        if extensions.iter().any(|e| matches!(e.as_str(), "apk" | "jar" | "class" | "dex")) {
            return Category::Rev;
        }
        if has_elf && !description.to_lowercase().contains("disassem") {
            // ELF + no explicit rev keywords → likely pwn
        }

        // 3. Description keywords
        let desc = description.to_lowercase();
        if desc.contains("overflow") || desc.contains("heap") || desc.contains("rop")
            || desc.contains("shellcode") || desc.contains("stack smash")
        {
            return Category::Pwn;
        }
        if desc.contains("sql injection") || desc.contains("xss") || desc.contains("lfi")
            || desc.contains("ssrf") || desc.contains("csrf") || desc.contains("http")
            || desc.contains("cookie") || desc.contains("web server")
        {
            return Category::Web;
        }
        if desc.contains("rsa") || desc.contains("aes") || desc.contains("cipher")
            || desc.contains("encrypt") || desc.contains("decrypt") || desc.contains("hash")
            || desc.contains("modular") || desc.contains("prime")
        {
            return Category::Crypto;
        }
        if desc.contains("reverse") || desc.contains("disassem") || desc.contains("decompil") {
            return Category::Rev;
        }
        if desc.contains("steganograph") || desc.contains("forensic") || desc.contains("memory dump")
            || desc.contains("volatility") || desc.contains("wireshark")
        {
            return Category::Forensics;
        }
        if desc.contains("osint") || desc.contains("open source intelligence") {
            return Category::Osint;
        }

        // 4. ELF fallback
        if has_elf {
            return Category::Pwn;
        }

        Category::Misc
    }
}

fn collect_extensions(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            e.path()
                .extension()
                .map(|ext| ext.to_string_lossy().to_lowercase())
        })
        .collect()
}

fn has_elf_binary(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            if let Ok(mut file) = fs::File::open(&path) {
                use std::io::Read;
                let mut magic = [0u8; 4];
                if file.read_exact(&mut magic).is_ok() && &magic == b"\x7fELF" {
                    return true;
                }
            }
        }
    }
    false
}
