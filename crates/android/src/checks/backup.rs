//! ANDROID-PRIVACY-003 — Backup enabled without backup rules.
//!
//! With `android:allowBackup="true"` and no `fullBackupContent` /
//! `dataExtractionRules`, all app data (including potentially sensitive files)
//! is eligible for cloud/adb backup. Worth a Data-Safety-form reminder.

use crate::{android_attr, AndroidCheck, AndroidProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct BackupRulesCheck;

const META: CheckMeta = CheckMeta {
    id: "ANDROID-PRIVACY-003",
    title: "Backup enabled without backup rules",
    platform: Platform::Android,
    category: Category::Privacy,
    default_severity: Severity::Info,
    confidence: Confidence::Medium,
    guideline: Some("Play: Data safety"),
    docs_url: Some("https://developer.android.com/identity/data/autobackup"),
};

impl AndroidCheck for BackupRulesCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &AndroidProject, _config: &Config) -> Vec<Finding> {
        let Some(doc) = project.manifest_doc() else {
            return Vec::new();
        };
        let Some(app) = doc.descendants().find(|n| n.has_tag_name("application")) else {
            return Vec::new();
        };

        let allows_backup = android_attr(app, "allowBackup")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let has_rules = android_attr(app, "fullBackupContent").is_some()
            || android_attr(app, "dataExtractionRules").is_some();

        if !allows_backup || has_rules {
            return Vec::new();
        }
        let mut finding = Finding::from_meta(
            &META,
            "`android:allowBackup=\"true\"` with no fullBackupContent / dataExtractionRules — all \
             app data is eligible for backup.",
        )
        .remediation(
            "Add backup rules that exclude sensitive data, or set allowBackup=\"false\" if backup \
             isn't needed.",
        );
        if let Some(path) = &project.manifest_path {
            finding = finding.location(Location::file(path.clone()));
        }
        vec![finding]
    }
}
