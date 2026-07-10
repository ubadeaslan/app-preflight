//! Decode a compiled (binary AXML) `AndroidManifest.xml` into plain
//! [`ManifestFacts`] the checks can reason about.
//!
//! The decode is best-effort: any failure yields `None` and the manifest-based
//! checks simply don't run. The check logic works off `ManifestFacts`, so it is
//! unit-testable without a real compiled manifest.

use axmldecoder::{Element, Node};

/// The subset of the merged manifest we check in a compiled APK.
#[derive(Debug, Clone, Default)]
pub struct ManifestFacts {
    pub debuggable: bool,
    pub target_sdk: Option<u32>,
    pub uses_cleartext_traffic: bool,
    pub permissions: Vec<String>,
}

/// Decode the binary `AndroidManifest.xml` bytes, or `None` if it can't be read.
pub fn decode(bytes: &[u8]) -> Option<ManifestFacts> {
    // The AXML decoder can panic on some malformed inputs; contain it so a bad
    // manifest in a user's APK never crashes preflight.
    let parsed =
        std::panic::catch_unwind(|| axmldecoder::parse(&mut std::io::Cursor::new(bytes)).ok())
            .ok()
            .flatten()?;
    let root = parsed.get_root().as_ref()?;
    let mut facts = ManifestFacts::default();
    walk(root, &mut facts);
    Some(facts)
}

fn walk(node: &Node, facts: &mut ManifestFacts) {
    let Node::Element(el) = node else {
        return;
    };
    match el.get_tag() {
        "application" => {
            if let Some(v) = attr(el, "debuggable") {
                facts.debuggable = v.eq_ignore_ascii_case("true");
            }
            if let Some(v) = attr(el, "usesCleartextTraffic") {
                facts.uses_cleartext_traffic = v.eq_ignore_ascii_case("true");
            }
        }
        "uses-sdk" => {
            if let Some(v) = attr(el, "targetSdkVersion") {
                facts.target_sdk = v.trim().parse().ok();
            }
        }
        "uses-permission" | "uses-permission-sdk-23" => {
            if let Some(name) = attr(el, "name") {
                facts.permissions.push(name);
            }
        }
        _ => {}
    }
    for child in el.get_children() {
        walk(child, facts);
    }
}

/// Look up an attribute by its local name, tolerating the `android:` prefix that
/// the decoder attaches from the namespace declaration.
fn attr(el: &Element, local: &str) -> Option<String> {
    let suffix = format!(":{local}");
    el.get_attributes()
        .iter()
        .find(|(k, _)| k.as_str() == local || k.ends_with(&suffix))
        .map(|(_, v)| v.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    #[test]
    fn fuzz_decode_never_panics() {
        // The panic guard in `decode` must contain any decoder panic; a bad
        // manifest yields None, never a crash.
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        for _ in 0..3000 {
            let len = (xorshift(&mut state) % 4096) as usize;
            let buf: Vec<u8> = (0..len)
                .map(|_| (xorshift(&mut state) & 0xff) as u8)
                .collect();
            let _ = decode(&buf);
        }
    }
}
