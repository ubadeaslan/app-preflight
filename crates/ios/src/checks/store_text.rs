//! Static checks over fastlane store-metadata text files
//! (`fastlane/metadata/<locale>/*.txt`), when the project keeps its App Store
//! listing in the repo. Unlike the App Store Connect layer these run offline,
//! before anything is pushed to Apple.
//!
//! IOS-STORE-001 — hard character limits per field. Latin-language first drafts
//! overflow the short fields constantly; deliver only fails after the upload.
//!
//! IOS-STORE-002 — subtitle that reads as a keyword list. Guideline 2.3.7
//! rejects keyword-stuffed subtitles; translated subtitles drift into
//! separator-joined term lists easily.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};
use std::path::PathBuf;

/// `(file name, character limit)` for each length-limited metadata field.
const FIELD_LIMITS: &[(&str, usize)] = &[
    ("name.txt", 30),
    ("subtitle.txt", 30),
    ("keywords.txt", 100),
    ("promotional_text.txt", 170),
];

/// Separators that indicate a subtitle is a joined keyword list rather than a
/// sentence (Latin comma, CJK enumeration comma, middle dot, slash, pipe).
const SUBTITLE_SEPARATORS: &[char] = &[',', '，', '、', '·', '/', '|', ';'];
const SUBTITLE_SEPARATOR_THRESHOLD: usize = 3;

/// Locale directories under either `fastlane/metadata` or
/// `ios/fastlane/metadata`, whichever exists.
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

pub struct StoreTextLimitsCheck;

const LIMITS_META: CheckMeta = CheckMeta {
    id: "IOS-STORE-001",
    title: "Store metadata text over its character limit",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some("https://developer.apple.com/help/app-store-connect/reference/app-information"),
};

impl IosCheck for StoreTextLimitsCheck {
    fn meta(&self) -> CheckMeta {
        LIMITS_META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        for dir in locale_dirs(project) {
            for (file, limit) in FIELD_LIMITS {
                let path = dir.join(file);
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let len = text.trim().chars().count();
                if len <= *limit {
                    continue;
                }
                findings.push(
                    Finding::from_meta(
                        &LIMITS_META,
                        format!(
                            "{} is {len} characters — the limit is {limit}. deliver only \
                             fails on this after the upload round-trip.",
                            path.display(),
                        ),
                    )
                    .location(Location::file(path))
                    .remediation(format!("Shorten the text to at most {limit} characters.")),
                );
            }
        }
        findings
    }
}

pub struct SubtitleKeywordListCheck;

const SUBTITLE_META: CheckMeta = CheckMeta {
    id: "IOS-STORE-002",
    title: "Subtitle reads as a keyword list",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Warning,
    confidence: Confidence::Medium,
    guideline: Some("2.3.7"),
    docs_url: Some("https://developer.apple.com/app-store/review/guidelines/#accurate-metadata"),
};

impl IosCheck for SubtitleKeywordListCheck {
    fn meta(&self) -> CheckMeta {
        SUBTITLE_META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        for dir in locale_dirs(project) {
            let path = dir.join("subtitle.txt");
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let separators = text
                .trim()
                .chars()
                .filter(|c| SUBTITLE_SEPARATORS.contains(c))
                .count();
            if separators < SUBTITLE_SEPARATOR_THRESHOLD {
                continue;
            }
            findings.push(
                Finding::from_meta(
                    &SUBTITLE_META,
                    format!(
                        "{} contains {separators} separator characters — it reads as a \
                         joined keyword list, which Guideline 2.3.7 rejects as keyword \
                         stuffing. Translated subtitles drift into this shape easily.",
                        path.display(),
                    ),
                )
                .location(Location::file(path))
                .remediation(
                    "Rewrite the subtitle as a short benefit phrase; put search terms in \
                     keywords.txt instead.",
                ),
            );
        }
        findings
    }
}
