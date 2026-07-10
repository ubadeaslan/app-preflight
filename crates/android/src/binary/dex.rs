//! Signals pulled from `classes*.dex`.
//!
//! We parse the DEX string pool and type-id table directly (little-endian, per
//! the DEX format) so detection works on *actual referenced types and string
//! constants* rather than incidental byte sequences. If the header doesn't parse
//! we fall back to a raw byte scan so a weird/packed DEX still yields something.

#[derive(Debug, Clone, Default)]
pub struct DexFacts {
    /// The app references `DexClassLoader` (dynamic code loading).
    pub dynamic_code_loading: bool,
    /// Kinds of hard-coded secret detected (e.g. "Google API key").
    pub secret_kinds: Vec<String>,
    /// Restricted / non-SDK (hidden) API classes referenced.
    pub restricted_apis: Vec<String>,
}

/// Descriptors that load executable code at runtime (dynamic code loading).
const DYNAMIC_LOADERS: &[&str] = &[
    "Ldalvik/system/DexClassLoader;",
    "Ldalvik/system/InMemoryDexClassLoader;",
];

/// Non-SDK / hidden API classes apps commonly reach via reflection. An exact
/// match or the `Lcom/android/internal/` prefix is flagged.
const RESTRICTED_TYPES: &[&str] = &[
    "Landroid/os/SystemProperties;",
    "Ldalvik/system/VMRuntime;",
    "Landroid/app/ActivityThread;",
    "Landroid/os/ServiceManager;",
    "Landroid/app/ActivityManagerNative;",
];
const RESTRICTED_PREFIX: &str = "Lcom/android/internal/";

/// Parse `bytes` and accumulate findings into `facts`.
pub fn scan(bytes: &[u8], facts: &mut DexFacts) {
    match parse(bytes) {
        Some(dex) => {
            scan_parsed(&dex, facts);
            // A valid header with an empty/unreadable type table would miss all
            // class-descriptor signals — supplement with a raw class scan.
            if dex.types.is_empty() {
                scan_raw_classes(bytes, facts);
            }
        }
        None => {
            scan_raw_classes(bytes, facts);
            detect_secret(&String::from_utf8_lossy(bytes), facts);
        }
    }
}

struct DexContents {
    strings: Vec<String>,
    types: Vec<String>,
}

fn scan_parsed(dex: &DexContents, facts: &mut DexFacts) {
    if dex
        .types
        .iter()
        .any(|t| DYNAMIC_LOADERS.contains(&t.as_str()))
    {
        facts.dynamic_code_loading = true;
    }
    for t in &dex.types {
        if is_restricted(t) && !facts.restricted_apis.contains(t) {
            facts.restricted_apis.push(t.clone());
        }
    }
    for s in &dex.strings {
        detect_secret(s, facts);
    }
}

fn is_restricted(t: &str) -> bool {
    RESTRICTED_TYPES.contains(&t) || t.starts_with(RESTRICTED_PREFIX)
}

/// Raw byte scan for class descriptors — the fallback path that covers packed /
/// header-corrupt DEX where the parsed type table is unavailable.
fn scan_raw_classes(bytes: &[u8], facts: &mut DexFacts) {
    if DYNAMIC_LOADERS
        .iter()
        .any(|d| memchr::memmem::find(bytes, d.as_bytes()).is_some())
    {
        facts.dynamic_code_loading = true;
    }
    for t in RESTRICTED_TYPES {
        if memchr::memmem::find(bytes, t.as_bytes()).is_some()
            && !facts.restricted_apis.iter().any(|r| r == t)
        {
            facts.restricted_apis.push((*t).to_string());
        }
    }
}

fn detect_secret(s: &str, facts: &mut DexFacts) {
    let mut add = |kind: &str| {
        if !facts.secret_kinds.iter().any(|k| k == kind) {
            facts.secret_kinds.push(kind.to_string());
        }
    };
    let b = s.as_bytes();
    if find_token(b, b"AIza", 35, |c| {
        c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
    }) {
        add("Google API key");
    }
    if find_token(b, b"AKIA", 16, |c| {
        c.is_ascii_uppercase() || c.is_ascii_digit()
    }) {
        add("AWS access key");
    }
    if s.contains("PRIVATE KEY-----") {
        add("PEM private key");
    }
}

// --- Minimal DEX parser -----------------------------------------------------

fn parse(bytes: &[u8]) -> Option<DexContents> {
    // Header is 0x70 bytes; must start with the DEX magic.
    if bytes.len() < 0x70 || &bytes[0..4] != b"dex\n" {
        return None;
    }
    let u32_at = |off: usize| -> Option<u32> {
        bytes
            .get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };

    // Sanity cap so a corrupt size field can't drive a huge loop/allocation.
    const MAX_ITEMS: usize = 4_000_000;
    let string_ids_size = (u32_at(0x38)? as usize).min(MAX_ITEMS);
    let string_ids_off = u32_at(0x3C)? as usize;
    let type_ids_size = (u32_at(0x40)? as usize).min(MAX_ITEMS);
    let type_ids_off = u32_at(0x44)? as usize;

    // String pool.
    let mut strings = Vec::with_capacity(string_ids_size.min(1 << 16));
    for i in 0..string_ids_size {
        let Some(data_off) = u32_at(string_ids_off + i * 4) else {
            break;
        };
        if let Some(s) = read_mutf8(bytes, data_off as usize) {
            strings.push(s);
        } else {
            strings.push(String::new());
        }
    }

    // Type descriptors index into the string pool.
    let mut types = Vec::with_capacity(type_ids_size.min(1 << 16));
    for i in 0..type_ids_size {
        let Some(idx) = u32_at(type_ids_off + i * 4) else {
            break;
        };
        if let Some(s) = strings.get(idx as usize) {
            types.push(s.clone());
        }
    }

    Some(DexContents { strings, types })
}

/// Read a `string_data_item`: a uleb128 length we skip, then null-terminated
/// MUTF-8 (read lossily as UTF-8, fine for ASCII descriptors/strings).
fn read_mutf8(bytes: &[u8], mut off: usize) -> Option<String> {
    if off >= bytes.len() {
        return None;
    }
    // Skip the uleb128 UTF-16 length prefix.
    while off < bytes.len() && bytes[off] & 0x80 != 0 {
        off += 1;
    }
    off += 1; // final uleb128 byte
    if off > bytes.len() {
        return None;
    }
    let start = off;
    let mut end = off;
    while end < bytes.len() && bytes[end] != 0 {
        end += 1;
    }
    Some(String::from_utf8_lossy(&bytes[start..end]).into_owned())
}

/// True if `prefix` occurs followed by exactly `len` bytes all satisfying `pred`.
fn find_token(haystack: &[u8], prefix: &[u8], len: usize, pred: impl Fn(u8) -> bool) -> bool {
    memchr::memmem::find_iter(haystack, prefix).any(|i| {
        let start = i + prefix.len();
        let end = start + len;
        end <= haystack.len() && haystack[start..end].iter().all(|&b| pred(b))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid DEX with a single string used as a single type
    /// descriptor (`descriptor` must be < 128 UTF-16 units for the 1-byte uleb).
    fn build_min_dex(descriptor: &str) -> Vec<u8> {
        let mut v = vec![0u8; 0x78];
        v[0..8].copy_from_slice(b"dex\n035\0");
        v[0x38..0x3C].copy_from_slice(&1u32.to_le_bytes()); // string_ids_size
        v[0x3C..0x40].copy_from_slice(&0x70u32.to_le_bytes()); // string_ids_off
        v[0x40..0x44].copy_from_slice(&1u32.to_le_bytes()); // type_ids_size
        v[0x44..0x48].copy_from_slice(&0x74u32.to_le_bytes()); // type_ids_off
        v[0x70..0x74].copy_from_slice(&0x78u32.to_le_bytes()); // string_ids[0] -> data
        v[0x74..0x78].copy_from_slice(&0u32.to_le_bytes()); // type_ids[0] -> string 0
        let bytes = descriptor.as_bytes();
        v.push(bytes.len() as u8); // uleb128 length (single byte)
        v.extend_from_slice(bytes);
        v.push(0); // null terminator
        v
    }

    #[test]
    fn parses_restricted_type_descriptor() {
        let dex = build_min_dex("Landroid/os/SystemProperties;");
        let mut facts = DexFacts::default();
        scan(&dex, &mut facts);
        assert!(facts
            .restricted_apis
            .iter()
            .any(|t| t == "Landroid/os/SystemProperties;"));
    }

    #[test]
    fn parses_dexclassloader_type() {
        let dex = build_min_dex("Ldalvik/system/DexClassLoader;");
        let mut facts = DexFacts::default();
        scan(&dex, &mut facts);
        assert!(facts.dynamic_code_loading);
    }

    #[test]
    fn raw_fallback_on_non_dex_bytes() {
        // No DEX magic -> raw byte scan still catches DexClassLoader and secrets.
        let mut facts = DexFacts::default();
        scan(
            b"junk Ldalvik/system/DexClassLoader; AIzaSyA1234567890abcdefghijklmnopqrstuvw",
            &mut facts,
        );
        assert!(facts.dynamic_code_loading);
        assert!(facts.secret_kinds.iter().any(|k| k == "Google API key"));
    }

    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    #[test]
    fn fuzz_parser_never_panics() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..4000 {
            let len = (xorshift(&mut state) % 8192) as usize;
            let mut buf: Vec<u8> = (0..len)
                .map(|_| (xorshift(&mut state) & 0xff) as u8)
                .collect();
            // Half the time, stamp the DEX magic so the header parser runs against
            // garbage sizes/offsets.
            if len >= 8 && xorshift(&mut state) & 1 == 0 {
                buf[0..8].copy_from_slice(b"dex\n035\0");
            }
            let mut facts = DexFacts::default();
            scan(&buf, &mut facts); // must not panic
        }
    }
}
