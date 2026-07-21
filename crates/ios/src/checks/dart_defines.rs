//! IOS-CONFIG-014 — Flutter `--dart-define` environment about to ship as dev.
//!
//! Flutter writes the last build's `--dart-define` values into
//! `ios/Flutter/Generated.xcconfig` as `DART_DEFINES=<base64>,<base64>,...`.
//! Archiving from that tree bakes those values into the store binary; a
//! default of `ENV=dev` means the App Store build talks to the dev backend
//! (Nokturn near-miss, 2026-07). The file is typically gitignored, so this
//! fires on the machine that is about to archive — exactly where it matters —
//! and stays silent in CI checkouts.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct DartDefinesEnvCheck;

const DART_DEFINES_META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-014",
    title: "Flutter dart-define environment is not production",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some("https://docs.flutter.dev/deployment/flavors"),
};

/// Keys that name the app environment in common Flutter setups.
const ENV_KEYS: &[&str] = &["ENV", "APP_ENV", "ENVIRONMENT"];
/// Values accepted as production.
const PROD_VALUES: &[&str] = &["prod", "production", "release"];

impl IosCheck for DartDefinesEnvCheck {
    fn meta(&self) -> CheckMeta {
        DART_DEFINES_META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let path = project.root.join("ios/Flutter/Generated.xcconfig");
        let Ok(contents) = std::fs::read_to_string(&path) else {
            return Vec::new(); // Not a Flutter iOS project, or file not generated.
        };
        let Some(raw) = contents
            .lines()
            .find_map(|l| l.trim().strip_prefix("DART_DEFINES="))
        else {
            return Vec::new();
        };
        for entry in raw.split(',') {
            let Some(decoded) = decode_base64(entry.trim()) else {
                continue;
            };
            let Some((key, value)) = decoded.split_once('=') else {
                continue;
            };
            if !ENV_KEYS.contains(&key.trim()) {
                continue;
            }
            let value = value.trim();
            if PROD_VALUES.contains(&value.to_ascii_lowercase().as_str()) {
                return Vec::new(); // Explicitly production — all good.
            }
            return vec![Finding::from_meta(
                &DART_DEFINES_META,
                format!(
                    "Generated.xcconfig carries {key}={value} from the last `flutter build`. \
                     Archiving from this tree ships a store binary pointing at the \
                     `{value}` environment."
                ),
            )
            .location(Location::file(path))
            .remediation(
                "Re-run the build with --dart-define ENV=prod (or your flavor equivalent) \
                 before archiving, and add a `kReleaseMode && ENV != prod` assert in main() \
                 as the last line of defense.",
            )];
        }
        Vec::new()
    }
}

/// Minimal base64 decoder (standard + URL-safe alphabet, padding optional).
/// Kept local to avoid a dependency for one field.
fn decode_base64(input: &str) -> Option<String> {
    let mut bits: u32 = 0;
    let mut bit_count = 0;
    let mut out = Vec::new();
    for c in input.bytes() {
        let value = match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => continue,
            _ => return None,
        };
        bits = (bits << 6) | value;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::decode_base64;

    #[test]
    fn decodes_standard_base64() {
        assert_eq!(decode_base64("RU5WPXByb2Q=").as_deref(), Some("ENV=prod"));
        assert_eq!(decode_base64("RU5WPWRldg==").as_deref(), Some("ENV=dev"));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(decode_base64("not base64!"), None);
    }
}
