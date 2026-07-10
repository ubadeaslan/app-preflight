//! ANDROID-CONFIG-008 — Exported `<provider>` without a permission.
//!
//! A ContentProvider with `android:exported="true"` and no permission is
//! reachable by any app on the device, a common data-leak finding.

use crate::{android_attr, AndroidCheck, AndroidProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct ExportedProviderCheck;

const META: CheckMeta = CheckMeta {
    id: "ANDROID-CONFIG-008",
    title: "Exported content provider without a permission",
    platform: Platform::Android,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::Medium,
    guideline: Some("Play: User Data"),
    docs_url: Some(
        "https://developer.android.com/privacy-and-security/risks/content-provider-exported",
    ),
};

impl AndroidCheck for ExportedProviderCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &AndroidProject, _config: &Config) -> Vec<Finding> {
        let Some(doc) = project.manifest_doc() else {
            return Vec::new();
        };
        let loc = project.manifest_path.clone().map(Location::file);
        let mut findings = Vec::new();

        for node in doc.descendants().filter(|n| n.has_tag_name("provider")) {
            let exported = android_attr(node, "exported")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !exported {
                continue;
            }
            let has_permission = android_attr(node, "permission").is_some()
                || android_attr(node, "readPermission").is_some()
                || android_attr(node, "writePermission").is_some();
            if has_permission {
                continue;
            }
            let name = android_attr(node, "name").unwrap_or("<unnamed>");
            let mut finding = Finding::from_meta(
                &META,
                format!(
                    "<provider> `{name}` is exported with no permission, so any app can access \
                     it."
                ),
            )
            .remediation(
                "Set android:exported=\"false\", or protect it with android:permission / \
                 read/writePermission.",
            );
            if let Some(l) = &loc {
                finding = finding.location(l.clone());
            }
            findings.push(finding);
        }
        findings
    }
}
