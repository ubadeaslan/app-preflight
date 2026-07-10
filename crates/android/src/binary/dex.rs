//! Lightweight signals pulled from `classes*.dex` without a full DEX parser.
//!
//! DEX files store class descriptors (e.g. `Ldalvik/system/DexClassLoader;`) and
//! string constants literally in their string pool, so a byte scan reliably
//! detects the *presence* of specific classes and hard-coded secrets — enough
//! for high-signal, low-false-positive checks. Full method-graph analysis is a
//! future addition.

#[derive(Debug, Clone, Default)]
pub struct DexFacts {
    /// The app references `DexClassLoader` (dynamic code loading).
    pub dynamic_code_loading: bool,
    /// Kinds of hard-coded secret detected (e.g. "Google API key").
    pub secret_kinds: Vec<String>,
}

const DEX_CLASS_LOADER: &[u8] = b"Ldalvik/system/DexClassLoader;";

/// Scan one DEX blob, accumulating into `facts`.
pub fn scan(bytes: &[u8], facts: &mut DexFacts) {
    if !facts.dynamic_code_loading && contains(bytes, DEX_CLASS_LOADER) {
        facts.dynamic_code_loading = true;
    }
    detect_secrets(bytes, facts);
}

fn detect_secrets(bytes: &[u8], facts: &mut DexFacts) {
    let mut add = |kind: &str| {
        if !facts.secret_kinds.iter().any(|k| k == kind) {
            facts.secret_kinds.push(kind.to_string());
        }
    };

    // Google API key: "AIza" + 35 chars of [A-Za-z0-9_-].
    if find_token(bytes, b"AIza", 35, is_google_key_char) {
        add("Google API key");
    }
    // AWS access key id: "AKIA" + 16 chars of [A-Z0-9].
    if find_token(bytes, b"AKIA", 16, |c| {
        c.is_ascii_uppercase() || c.is_ascii_digit()
    }) {
        add("AWS access key");
    }
    // A PEM private key block.
    if contains(bytes, b"PRIVATE KEY-----") {
        add("PEM private key");
    }
}

fn is_google_key_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

/// True if `prefix` occurs followed by exactly `len` bytes all satisfying `pred`.
fn find_token(haystack: &[u8], prefix: &[u8], len: usize, pred: impl Fn(u8) -> bool) -> bool {
    if haystack.len() < prefix.len() + len {
        return false;
    }
    haystack
        .windows(prefix.len())
        .enumerate()
        .filter(|(_, w)| *w == prefix)
        .any(|(i, _)| {
            let start = i + prefix.len();
            let end = start + len;
            end <= haystack.len() && haystack[start..end].iter().all(|&b| pred(b))
        })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
