//! ANDROID-CONFIG-005 — Component with an intent-filter but no `android:exported`.
//!
//! On Android 12 (API 31) and above, any activity, service, or receiver that
//! declares an intent-filter must set `android:exported` explicitly. Omitting it
//! makes the app fail to install.

use crate::{android_attr, AndroidCheck, AndroidProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct ExportedComponentCheck;

const COMPONENT_TAGS: &[&str] = &["activity", "activity-alias", "service", "receiver"];

const META: CheckMeta = CheckMeta {
    id: "ANDROID-CONFIG-005",
    title: "Component with intent-filter missing android:exported",
    platform: Platform::Android,
    category: Category::Configuration,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("Android 12: explicit exported"),
    docs_url: Some("https://developer.android.com/about/versions/12/behavior-changes-12#exported"),
};

impl AndroidCheck for ExportedComponentCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &AndroidProject, _config: &Config) -> Vec<Finding> {
        let Some(doc) = project.manifest_doc() else {
            return Vec::new();
        };
        let loc = project.manifest_path.clone().map(Location::file);
        let mut findings = Vec::new();

        for node in doc.descendants() {
            if !COMPONENT_TAGS.contains(&node.tag_name().name()) {
                continue;
            }
            let has_intent_filter = node.children().any(|c| c.has_tag_name("intent-filter"));
            if !has_intent_filter || android_attr(node, "exported").is_some() {
                continue;
            }
            let name = android_attr(node, "name").unwrap_or("<unnamed>");
            let mut finding = Finding::from_meta(
                &META,
                format!(
                    "<{}> `{name}` has an intent-filter but no android:exported. This fails to \
                     install on Android 12+.",
                    node.tag_name().name()
                ),
            )
            .remediation(
                "Set android:exported=\"true\" (if it must be reachable by other apps) or \
                 \"false\" explicitly.",
            );
            if let Some(l) = &loc {
                finding = finding.location(l.clone());
            }
            findings.push(finding);
        }

        findings
    }
}
