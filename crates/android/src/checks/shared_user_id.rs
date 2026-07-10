//! ANDROID-CONFIG-009 — Deprecated `android:sharedUserId`.
//!
//! `sharedUserId` is deprecated (API 29+) and effectively permanent: once an app
//! ships with it you can't remove it without breaking updates for existing
//! installs, so new apps should never set it.

use crate::{android_attr, AndroidCheck, AndroidProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct SharedUserIdCheck;

const META: CheckMeta = CheckMeta {
    id: "ANDROID-CONFIG-009",
    title: "Deprecated android:sharedUserId",
    platform: Platform::Android,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some("https://developer.android.com/guide/topics/manifest/manifest-element#uid"),
};

impl AndroidCheck for SharedUserIdCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &AndroidProject, _config: &Config) -> Vec<Finding> {
        let Some(doc) = project.manifest_doc() else {
            return Vec::new();
        };
        let Some(manifest) = doc.descendants().find(|n| n.has_tag_name("manifest")) else {
            return Vec::new();
        };
        if android_attr(manifest, "sharedUserId").is_none() {
            return Vec::new();
        }
        let mut finding = Finding::from_meta(
            &META,
            "`android:sharedUserId` is set. It is deprecated and cannot be removed later without \
             breaking updates for existing installs.",
        )
        .remediation("Avoid sharedUserId; use explicit IPC/permissions to share data instead.");
        if let Some(path) = &project.manifest_path {
            finding = finding.location(Location::file(path.clone()));
        }
        vec![finding]
    }
}
