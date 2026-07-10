//! ANDROID-CONFIG-001 — `android:debuggable="true"` in the manifest.
//!
//! A debuggable release build is a hard Play rejection and a security risk.

use crate::{android_attr, AndroidCheck, AndroidProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct DebuggableCheck;

const META: CheckMeta = CheckMeta {
    id: "ANDROID-CONFIG-001",
    title: "Application is marked debuggable",
    platform: Platform::Android,
    category: Category::Configuration,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("Play: Device and Network Abuse"),
    docs_url: Some("https://developer.android.com/privacy-and-security/risks/android-debuggable"),
};

impl AndroidCheck for DebuggableCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &AndroidProject, _config: &Config) -> Vec<Finding> {
        let Some(doc) = project.manifest_doc() else {
            return Vec::new();
        };
        let debuggable = doc
            .descendants()
            .find(|n| n.has_tag_name("application"))
            .and_then(|app| android_attr(app, "debuggable"))
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if !debuggable {
            return Vec::new();
        }

        let mut finding = Finding::from_meta(
            &META,
            "`android:debuggable=\"true\"` is set on <application>. Google Play \
             rejects debuggable release builds.",
        )
        .remediation(
            "Remove android:debuggable from the manifest. Let the build type \
             control it — release builds are non-debuggable by default.",
        );
        if let Some(path) = &project.manifest_path {
            finding = finding.location(Location::file(path.clone()));
        }
        vec![finding]
    }
}
