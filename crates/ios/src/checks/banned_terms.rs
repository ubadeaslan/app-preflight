//! IOS-STORE-004 — project-specific banned terms in store metadata.
//!
//! Guideline 2.3.7 rejects irrelevant / off-category keywords, and localized
//! metadata drifts into them easily (Nokturn's Korean keywords grew 타로 —
//! tarot — in a dreams app). The dangerous words are app-specific, so the
//! list lives in `preflight.toml`:
//!
//! ```toml
//! banned_metadata_terms = ["tarot", "타로", "fal", "horoscope"]
//! ```
//!
//! An empty list keeps the check silent.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};
use std::path::PathBuf;

pub struct BannedTermsCheck;

const BANNED_TERMS_META: CheckMeta = CheckMeta {
    id: "IOS-STORE-004",
    title: "Banned term found in store metadata",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: Some("2.3.7"),
    docs_url: Some("https://developer.apple.com/app-store/review/guidelines/#accurate-metadata"),
};

/// Metadata files scanned per locale.
const SCANNED_FILES: &[&str] = &[
    "name.txt",
    "subtitle.txt",
    "keywords.txt",
    "promotional_text.txt",
    "description.txt",
];

impl IosCheck for BannedTermsCheck {
    fn meta(&self) -> CheckMeta {
        BANNED_TERMS_META
    }

    fn run(&self, project: &IosProject, config: &Config) -> Vec<Finding> {
        if config.banned_metadata_terms.is_empty() {
            return Vec::new();
        }
        let terms: Vec<String> = config
            .banned_metadata_terms
            .iter()
            .map(|t| t.trim().to_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        let mut findings = Vec::new();
        for dir in locale_dirs(project) {
            for file in SCANNED_FILES {
                let path = dir.join(file);
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let lower = text.to_lowercase();
                for term in &terms {
                    if !lower.contains(term.as_str()) {
                        continue;
                    }
                    findings.push(
                        Finding::from_meta(
                            &BANNED_TERMS_META,
                            format!(
                                "{} contains the banned term `{term}` \
                                 (banned_metadata_terms in preflight.toml).",
                                path.display(),
                            ),
                        )
                        .location(Location::file(path.clone()))
                        .remediation(
                            "Remove the term — off-category keywords invite a 2.3.7 \
                             rejection, and localized metadata drifts into them easily.",
                        ),
                    );
                }
            }
        }
        findings
    }
}

/// Locale dirs under `fastlane/metadata` or `ios/fastlane/metadata`.
fn locale_dirs(project: &IosProject) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for base in ["fastlane/metadata", "ios/fastlane/metadata"] {
        let base = project.root.join(base);
        let Ok(entries) = std::fs::read_dir(&base) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                dirs.push(entry.path());
            }
        }
    }
    dirs
}
