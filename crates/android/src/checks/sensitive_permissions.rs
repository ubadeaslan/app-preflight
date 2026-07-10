//! ANDROID-PRIVACY-001 — Flag sensitive permissions for the Data Safety form.
//!
//! Declaring high-risk permissions (SMS/Call Log especially) triggers extra
//! Play policy scrutiny and a mandatory Data Safety declaration. This surfaces
//! them so nothing is forgotten before submission.

use crate::{android_attr, AndroidCheck, AndroidProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct SensitivePermissionsCheck;

const META: CheckMeta = CheckMeta {
    id: "ANDROID-PRIVACY-001",
    title: "Sensitive permission requires Play policy declaration",
    platform: Platform::Android,
    category: Category::Privacy,
    default_severity: Severity::Warning,
    confidence: Confidence::Medium,
    guideline: Some("Play: Permissions and APIs that Access Sensitive Info"),
    docs_url: Some("https://support.google.com/googleplay/android-developer/answer/9888170"),
};

use crate::permissions::{RESTRICTED, SENSITIVE};

impl AndroidCheck for SensitivePermissionsCheck {
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
            let (severity, note) = if RESTRICTED.contains(&name) {
                (
                    Severity::Error,
                    "This is a restricted permission — Play only allows it for a narrow set of app types and requires a Permissions Declaration; most apps are rejected.",
                )
            } else if SENSITIVE.contains(&name) {
                (
                    Severity::Info,
                    "Make sure this is disclosed in your Play Data Safety form and justified in the listing.",
                )
            } else {
                continue;
            };

            let mut finding =
                Finding::from_meta(&META, format!("Declares `{name}`. {note}")).severity(severity);
            if let Some(l) = &loc {
                finding = finding.location(l.clone());
            }
            findings.push(finding);
        }

        findings
    }
}
