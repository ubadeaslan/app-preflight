//! Flutter l10n (ARB) consistency — the zero-token mechanical gate of a
//! multi-language pipeline.
//!
//! When an app ships 30+ languages, translation runs in batched agent waves;
//! the cheap-but-critical validation (did every locale get every key? did the
//! placeholders survive?) must NOT cost tokens or reviewer attention. These
//! checks catch the two mechanical failure modes:
//!
//! - IOS-CONFIG-015 — a locale is missing keys from the template ARB. Flutter
//!   silently falls back to the template language for those strings, shipping
//!   a mixed-language screen.
//! - IOS-CONFIG-016 — a translation's `{placeholder}` set differs from the
//!   template's. The interpolation breaks at runtime (raw braces or missing
//!   values shown to the user).
//!
//! Template resolution: `l10n.yaml` (`arb-dir`, `template-arb-file`) when
//! present; otherwise `lib/l10n/app_en.arb`.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub struct ArbMissingKeysCheck;
pub struct ArbPlaceholderCheck;

const MISSING_KEYS_META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-015",
    title: "Flutter l10n: locale missing keys from the template ARB",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some(
        "https://docs.flutter.dev/ui/accessibility-and-internationalization/internationalization",
    ),
};

const PLACEHOLDER_META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-016",
    title: "Flutter l10n: placeholder mismatch in translation",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some(
        "https://docs.flutter.dev/ui/accessibility-and-internationalization/internationalization",
    ),
};

/// A parsed ARB: locale name + translatable `key -> value` pairs
/// (`@`-metadata and `@@`-directives skipped).
struct Arb {
    locale: String,
    path: PathBuf,
    entries: Vec<(String, String)>,
}

fn load_arbs(root: &Path) -> Option<(Arb, Vec<Arb>)> {
    let (arb_dir, template_file) = l10n_settings(root);
    let dir = root.join(&arb_dir);
    let entries = std::fs::read_dir(&dir).ok()?;
    let mut template: Option<Arb> = None;
    let mut others = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let is_arb = path
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| x.eq_ignore_ascii_case("arb"));
        if !is_arb {
            continue;
        }
        let Some(arb) = parse_arb(&path) else {
            continue;
        };
        let is_template = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == template_file);
        if is_template {
            template = Some(arb);
        } else {
            others.push(arb);
        }
    }
    let template = template?;
    (!others.is_empty()).then_some((template, others))
}

/// Read `arb-dir` and `template-arb-file` from `l10n.yaml` (line-based — the
/// file is flat key: value), with the Flutter defaults as fallback.
fn l10n_settings(root: &Path) -> (String, String) {
    let mut arb_dir = "lib/l10n".to_string();
    let mut template = "app_en.arb".to_string();
    if let Ok(text) = std::fs::read_to_string(root.join("l10n.yaml")) {
        for line in text.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("arb-dir:") {
                arb_dir = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("template-arb-file:") {
                template = v.trim().to_string();
            }
        }
    }
    (arb_dir, template)
}

fn parse_arb(path: &Path) -> Option<Arb> {
    let text = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    let map = json.as_object()?;
    let locale = map
        .get("@@locale")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| {
            path.file_stem().and_then(|s| s.to_str()).map(|s| {
                s.trim_start_matches("app_")
                    .trim_start_matches("intl_")
                    .to_string()
            })
        })?;
    let entries = map
        .iter()
        .filter(|(k, v)| !k.starts_with('@') && v.is_string())
        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
        .collect();
    Some(Arb {
        locale,
        path: path.to_path_buf(),
        entries,
    })
}

/// Placeholder names in an ICU message: `{name}` and `{name, plural, ...}`
/// both yield `name`.
///
/// ICU sub-messages are NOT scanned. In `{count, plural, two{بطاقتان} other{…}}`
/// the branch bodies are text, not arguments — and a single-word body in a
/// language without spaces (Arabic, CJK) is indistinguishable from a
/// placeholder unless the nested block is skipped whole. (Caught dogfooding
/// Snapaw's 34 locales, 2026-07-22.)
pub(crate) fn placeholders(message: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let chars: Vec<char> = message.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '{' {
            i += 1;
            continue;
        }
        let open = i;
        i += 1;
        let start = i;
        while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
            i += 1;
        }
        if i <= start || i >= chars.len() {
            continue;
        }
        match chars[i] {
            // Plain `{name}` — a simple placeholder.
            '}' => {
                out.insert(chars[start..i].iter().collect());
            }
            // `{name, plural|select, ...}` — record the argument, then jump past
            // the whole block so its branch bodies are never scanned.
            ',' => {
                out.insert(chars[start..i].iter().collect());
                i = skip_balanced(&chars, open);
            }
            _ => {}
        }
    }
    out
}

/// Index just past the `}` matching the `{` at `open`.
fn skip_balanced(chars: &[char], open: usize) -> usize {
    let mut depth = 0usize;
    let mut i = open;
    while i < chars.len() {
        match chars[i] {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    chars.len()
}

impl IosCheck for ArbMissingKeysCheck {
    fn meta(&self) -> CheckMeta {
        MISSING_KEYS_META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let Some((template, others)) = load_arbs(&project.root) else {
            return Vec::new();
        };
        let template_keys: BTreeSet<&str> =
            template.entries.iter().map(|(k, _)| k.as_str()).collect();
        let mut findings = Vec::new();
        for arb in &others {
            let keys: BTreeSet<&str> = arb.entries.iter().map(|(k, _)| k.as_str()).collect();
            let missing: Vec<&&str> = template_keys.difference(&keys).collect();
            if missing.is_empty() {
                continue;
            }
            let sample: Vec<String> = missing.iter().take(5).map(|k| k.to_string()).collect();
            findings.push(
                Finding::from_meta(
                    &MISSING_KEYS_META,
                    format!(
                        "Locale `{}` is missing {} key(s) present in the template (e.g. {}). \
                         Flutter silently falls back to the template language for these — a \
                         mixed-language screen ships.",
                        arb.locale,
                        missing.len(),
                        sample.join(", "),
                    ),
                )
                .location(Location::file(arb.path.clone()))
                .remediation(
                    "Run a delta translation wave for the missing keys (translate only the \
                     diff, not the whole file).",
                ),
            );
        }
        findings
    }
}

impl IosCheck for ArbPlaceholderCheck {
    fn meta(&self) -> CheckMeta {
        PLACEHOLDER_META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let Some((template, others)) = load_arbs(&project.root) else {
            return Vec::new();
        };
        let mut findings = Vec::new();
        for arb in &others {
            let mut broken: Vec<String> = Vec::new();
            for (key, value) in &arb.entries {
                let Some((_, template_value)) = template.entries.iter().find(|(k, _)| k == key)
                else {
                    continue; // Extra key — not this check's business.
                };
                let expected = placeholders(template_value);
                if expected.is_empty() {
                    continue;
                }
                let got = placeholders(value);
                if got != expected {
                    broken.push(format!(
                        "{key} (expected {{{}}}, found {{{}}})",
                        expected.iter().cloned().collect::<Vec<_>>().join(", "),
                        got.iter().cloned().collect::<Vec<_>>().join(", "),
                    ));
                }
            }
            if broken.is_empty() {
                continue;
            }
            let shown = broken
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ");
            findings.push(
                Finding::from_meta(
                    &PLACEHOLDER_META,
                    format!(
                        "Locale `{}` has {} translation(s) whose placeholders differ from the \
                         template: {}{}. Interpolation breaks at runtime for these strings.",
                        arb.locale,
                        broken.len(),
                        shown,
                        if broken.len() > 3 { "; ..." } else { "" },
                    ),
                )
                .location(Location::file(arb.path.clone()))
                .remediation(
                    "Keep placeholder names byte-identical to the template ({count} stays \
                     {count} in every language); re-translate only the broken keys.",
                ),
            );
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::placeholders;

    #[test]
    fn extracts_simple_and_icu_placeholders() {
        let set =
            placeholders("You have {count, plural, one{# dream} other{# dreams}} since {date}");
        assert!(set.contains("count"));
        assert!(set.contains("date"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn plain_text_has_no_placeholders() {
        assert!(placeholders("Just a sentence, nothing else.").is_empty());
    }

    #[test]
    fn mismatch_is_detectable_via_set_compare() {
        assert_ne!(placeholders("Hello {name}"), placeholders("Hello {nom}"));
    }

    /// Branch bodies of a plural are text, not arguments — languages without
    /// spaces produce single-word bodies that must not read as placeholders.
    #[test]
    fn icu_branch_bodies_are_not_placeholders() {
        let arabic =
            placeholders("{count, plural, zero{لا بطاقات} one{بطاقة} two{بطاقتان} other{# بطاقة}}");
        assert_eq!(arabic, placeholders("{count, plural, other{# cards}}"));
        assert!(arabic.contains("count"));
        assert_eq!(arabic.len(), 1);
    }

    /// A second argument after a plural block is still found.
    #[test]
    fn arguments_after_a_plural_block_are_found() {
        let set = placeholders("{count, plural, other{# cards}} on {date}");
        assert!(set.contains("count") && set.contains("date"));
        assert_eq!(set.len(), 2);
    }
}
