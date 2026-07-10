//! ANDROID-PRIVACY-002 — Special permissions that need a Play declaration.
//!
//! These aren't ordinary runtime permissions; each triggers a specific Google
//! Play policy declaration and extra review, and several are only allowed for
//! narrow app categories.

use crate::{android_attr, AndroidCheck, AndroidProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct SpecialPermissionsCheck;

const META: CheckMeta = CheckMeta {
    id: "ANDROID-PRIVACY-002",
    title: "Special permission requiring a Play declaration",
    platform: Platform::Android,
    category: Category::Privacy,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: Some("Play: Permissions declaration"),
    docs_url: Some("https://support.google.com/googleplay/android-developer/answer/12085295"),
};

/// (permission, why it needs special handling).
const SPECIAL: &[(&str, &str)] = &[
    (
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "All files access is only permitted for specific app types and needs a Play declaration.",
    ),
    (
        "android.permission.SYSTEM_ALERT_WINDOW",
        "Drawing over other apps is restricted and heavily scrutinized by Play.",
    ),
    (
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "Installing packages requires a Play declaration and justification.",
    ),
    (
        "android.permission.PACKAGE_USAGE_STATS",
        "Usage-access is a sensitive, special-access permission.",
    ),
    (
        "android.permission.QUERY_ALL_PACKAGES",
        "Broad package visibility requires a Play declaration for most app types.",
    ),
];

impl AndroidCheck for SpecialPermissionsCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &AndroidProject, _config: &Config) -> Vec<Finding> {
        let Some(doc) = project.manifest_doc() else {
            return Vec::new();
        };
        let loc = project.manifest_path.clone().map(Location::file);
        let mut findings = Vec::new();

        for node in doc
            .descendants()
            .filter(|n| n.has_tag_name("uses-permission"))
        {
            let Some(name) = android_attr(node, "name") else {
                continue;
            };
            let Some((_, note)) = SPECIAL.iter().find(|(p, _)| *p == name) else {
                continue;
            };
            let mut finding = Finding::from_meta(&META, format!("Declares `{name}`. {note}"));
            if let Some(l) = &loc {
                finding = finding.location(l.clone());
            }
            findings.push(finding);
        }

        findings
    }
}
