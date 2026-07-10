//! IOS-PRIVACY-002 — Permission purpose strings (`NS*UsageDescription`).
//!
//! A permission key with an empty or placeholder purpose string is one of the
//! most common hard rejections (Guideline 5.1.1) — and an empty string will
//! also crash the app the moment the permission is requested.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct UsageDescriptionsCheck;

const META: CheckMeta = CheckMeta {
    id: "IOS-PRIVACY-002",
    title: "Weak or empty permission purpose string",
    platform: Platform::Ios,
    category: Category::Privacy,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("5.1.1"),
    docs_url: Some(
        "https://developer.apple.com/documentation/bundleresources/information_property_list/protected_resources",
    ),
};

/// Substrings that betray a placeholder left in by mistake.
/// Placeholder tokens, matched on word boundaries so `test` doesn't fire on
/// `latest`/`fastest`/`contest` and `tbd` doesn't fire inside real words.
const PLACEHOLDERS: &[&str] = &["todo", "tbd", "asdf", "lorem", "placeholder", "foobar"];

/// True if any placeholder token appears as a whole word in `text` (lowercased).
fn has_placeholder_word(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| PLACEHOLDERS.contains(&word))
}

impl IosCheck for UsageDescriptionsCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        let plist_path = project.info_plist_path.clone().unwrap_or_default();

        for (key, value) in project.info_entries() {
            if !key.ends_with("UsageDescription") {
                continue;
            }
            let text = value.as_string().unwrap_or("").trim();

            let problem = if text.is_empty() {
                Some((
                    Severity::Error,
                    format!("`{key}` has an empty purpose string. iOS will crash when the permission is requested, and App Review rejects empty descriptions."),
                ))
            } else if text.len() < 10 {
                Some((
                    Severity::Warning,
                    format!("`{key}` purpose string is very short (\"{text}\"). Reviewers expect a specific, user-facing reason."),
                ))
            } else if has_placeholder_word(text) {
                Some((
                    Severity::Warning,
                    format!("`{key}` purpose string looks like a placeholder (\"{text}\")."),
                ))
            } else {
                None
            };

            if let Some((severity, message)) = problem {
                findings.push(
                    Finding::from_meta(&META, message)
                        .severity(severity)
                        .location(Location::file(plist_path.clone()))
                        .remediation(format!(
                            "Set `{key}` to a clear sentence describing exactly why the app needs this access, e.g. what feature uses it."
                        )),
                );
            }
        }

        findings
    }
}
