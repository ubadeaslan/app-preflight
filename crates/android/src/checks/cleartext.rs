//! ANDROID-CONFIG-003 — Cleartext (unencrypted HTTP) traffic enabled.

use crate::{android_attr, AndroidCheck, AndroidProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct CleartextTrafficCheck;

const META: CheckMeta = CheckMeta {
    id: "ANDROID-CONFIG-003",
    title: "Cleartext network traffic is permitted",
    platform: Platform::Android,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: Some("Play: User Data"),
    docs_url: Some(
        "https://developer.android.com/privacy-and-security/risks/cleartext-communications",
    ),
};

impl AndroidCheck for CleartextTrafficCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &AndroidProject, _config: &Config) -> Vec<Finding> {
        let Some(doc) = project.manifest_doc() else {
            return Vec::new();
        };
        let permits = doc
            .descendants()
            .find(|n| n.has_tag_name("application"))
            .and_then(|app| android_attr(app, "usesCleartextTraffic"))
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if !permits {
            return Vec::new();
        }

        let mut finding = Finding::from_meta(
            &META,
            "`android:usesCleartextTraffic=\"true\"` allows unencrypted HTTP. \
             This weakens user-data protection and draws Play policy attention.",
        )
        .remediation(
            "Remove the flag (cleartext is disabled by default on API 28+) or \
             restrict it to specific domains with a network-security-config.",
        );
        if let Some(path) = &project.manifest_path {
            finding = finding.location(Location::file(path.clone()));
        }
        vec![finding]
    }
}
