//! IOS-STORE-003 — "supports N languages" claims that don't match reality.
//!
//! Store metadata loves round numbers; the app's ARB count moves on. Nokturn
//! shipped "15 dil" in 13 metadata files while the app had 16 — a Guideline
//! 2.3.1 accuracy risk in the boring direction, and underselling in the other.
//! The check compares every `<number> <language-word>` claim in fastlane
//! metadata text files against the project's `.arb` file count (Flutter l10n).
//! Projects without ARB files stay silent.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};
use std::path::PathBuf;
use walkdir::WalkDir;

pub struct LanguageClaimCheck;

const LANGUAGE_CLAIM_META: CheckMeta = CheckMeta {
    id: "IOS-STORE-003",
    title: "Language-count claim doesn't match ARB count",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Warning,
    confidence: Confidence::Medium,
    guideline: Some("2.3.1"),
    docs_url: Some("https://developer.apple.com/app-store/review/guidelines/#accurate-metadata"),
};

/// Words that follow a number in a "supports N languages" claim, lowercase.
/// Latin-script entries match as a word prefix ("languages", "dilde",
/// "sprachen", ...); CJK entries match directly after the digits.
const LANGUAGE_WORDS: &[&str] = &[
    "language",
    "dil",
    "sprache",
    "langue",
    "idioma",
    "lingua",
    "língua",
    "taal",
    "språk",
    "kieli",
    "язык",
    "لغة",
    "언어",
    "言語",
    "语言",
    "種語言",
    "种语言",
    "ngôn ngữ",
    "bahasa",
];

/// Metadata files worth scanning for claims.
const CLAIM_FILES: &[&str] = &[
    "description.txt",
    "subtitle.txt",
    "promotional_text.txt",
    "release_notes.txt",
    "keywords.txt",
];

impl IosCheck for LanguageClaimCheck {
    fn meta(&self) -> CheckMeta {
        LANGUAGE_CLAIM_META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let arb_count = count_arb_files(&project.root);
        if arb_count == 0 {
            return Vec::new(); // Not a Flutter-l10n project — nothing to compare.
        }
        let mut findings = Vec::new();
        for dir in locale_dirs(project) {
            for file in CLAIM_FILES {
                let path = dir.join(file);
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                for claim in find_language_claims(&text) {
                    if claim as usize == arb_count {
                        continue;
                    }
                    findings.push(
                        Finding::from_meta(
                            &LANGUAGE_CLAIM_META,
                            format!(
                                "{} claims {claim} languages, but the project's ARB files cover \
                                 {arb_count} distinct languages (regional variants collapsed). \
                                 Numeric claims must match reality (2.3.1) — and underselling \
                                 wastes a feature. If the number refers to something narrower \
                                 (e.g. a content library), say so explicitly.",
                                path.display(),
                            ),
                        )
                        .location(Location::file(path.clone()))
                        .remediation(format!(
                            "Update the claim to {arb_count} (or drop the number and say \
                             \"multiple languages\" so it never goes stale)."
                        )),
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

/// Count distinct LANGUAGES among `.arb` files under `lib/` (the Flutter l10n
/// convention). Regional variants (`app_es_419.arb`, `app_fr_CA.arb`) collapse
/// into their base language — a "supports N languages" claim counts languages,
/// not locales.
fn count_arb_files(root: &std::path::Path) -> usize {
    let lib = root.join("lib");
    if !lib.is_dir() {
        return 0;
    }
    let mut languages = std::collections::HashSet::new();
    for entry in WalkDir::new(lib).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let is_arb = path
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| x.eq_ignore_ascii_case("arb"));
        if !is_arb {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let locale = stem
            .strip_prefix("app_")
            .or_else(|| stem.strip_prefix("intl_"))
            .unwrap_or(stem);
        let language = locale.split('_').next().unwrap_or(locale).to_lowercase();
        if !language.is_empty() {
            languages.insert(language);
        }
    }
    languages.len()
}

/// Extract every `<number> <language-word>` claim from `text`.
pub(crate) fn find_language_claims(text: &str) -> Vec<u32> {
    let lower = text.to_lowercase();
    let chars: Vec<char> = lower.chars().collect();
    let mut claims = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // Parse the digit run.
        let start = i;
        while i < chars.len() && chars[i].is_ascii_digit() {
            i += 1;
        }
        let number: u32 = match chars[start..i].iter().collect::<String>().parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        // Skip spaces and a possible '+' ("15+ languages").
        let mut j = i;
        while j < chars.len() && (chars[j].is_whitespace() || chars[j] == '+') {
            j += 1;
        }
        let rest: String = chars[j..chars.len().min(j + 24)].iter().collect();
        if LANGUAGE_WORDS.iter().any(|w| rest.starts_with(w)) {
            claims.push(number);
        }
    }
    claims
}

#[cfg(test)]
mod tests {
    use super::find_language_claims;

    #[test]
    fn finds_claims_across_languages() {
        assert_eq!(find_language_claims("Available in 15 languages."), vec![15]);
        assert_eq!(find_language_claims("16 dilde rüya sözlüğü"), vec![16]);
        assert_eq!(find_language_claims("In 12 Sprachen verfügbar"), vec![12]);
        assert_eq!(find_language_claims("支持16种语言"), vec![16]);
        assert_eq!(find_language_claims("15+ languages supported"), vec![15]);
    }

    #[test]
    fn ignores_unrelated_numbers() {
        assert!(find_language_claims("300 dream symbols, 4.8 stars").is_empty());
        assert!(find_language_claims("version 2.0 with dark mode").is_empty());
    }
}
