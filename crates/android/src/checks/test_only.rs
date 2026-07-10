//! ANDROID-CONFIG-007 — `android:testOnly="true"` in the manifest.
//!
//! A test-only APK can't be installed from Google Play (only via `adb install
//! -t`), so shipping one blocks the release.

use crate::{android_attr, AndroidCheck, AndroidProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct TestOnlyCheck;

const META: CheckMeta = CheckMeta {
    id: "ANDROID-CONFIG-007",
    title: "Application is marked testOnly",
    platform: Platform::Android,
    category: Category::Configuration,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("Play: Upload requirements"),
    docs_url: Some(
        "https://developer.android.com/guide/topics/manifest/application-element#testOnly",
    ),
};

impl AndroidCheck for TestOnlyCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &AndroidProject, _config: &Config) -> Vec<Finding> {
        let Some(doc) = project.manifest_doc() else {
            return Vec::new();
        };
        let test_only = doc
            .descendants()
            .find(|n| n.has_tag_name("application"))
            .and_then(|app| android_attr(app, "testOnly"))
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !test_only {
            return Vec::new();
        }
        let mut finding = Finding::from_meta(
            &META,
            "`android:testOnly=\"true\"` is set. Google Play refuses to install test-only APKs.",
        )
        .remediation("Remove android:testOnly (or the setting/flag that injects it) for release.");
        if let Some(path) = &project.manifest_path {
            finding = finding.location(Location::file(path.clone()));
        }
        vec![finding]
    }
}
