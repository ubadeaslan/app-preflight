//! IOS-PRIVACY-001 — Privacy manifest (`PrivacyInfo.xcprivacy`) presence.

use crate::{IosCheck, IosProject};
use preflight_core::{Category, CheckMeta, Confidence, Config, Finding, Platform, Severity};

pub struct PrivacyManifestCheck;

const META: CheckMeta = CheckMeta {
    id: "IOS-PRIVACY-001",
    title: "Missing privacy manifest (PrivacyInfo.xcprivacy)",
    platform: Platform::Ios,
    category: Category::Privacy,
    default_severity: Severity::Warning,
    confidence: Confidence::Medium,
    guideline: Some("5.1.1"),
    docs_url: Some(
        "https://developer.apple.com/documentation/bundleresources/privacy_manifest_files",
    ),
};

impl IosCheck for PrivacyManifestCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        if !project.privacy_manifests.is_empty() {
            return Vec::new();
        }
        vec![Finding::from_meta(
            &META,
            "No PrivacyInfo.xcprivacy found. Apple requires a privacy manifest \
             for apps that use required-reason APIs (e.g. UserDefaults, file \
             timestamps) or that bundle common third-party SDKs.",
        )
        .remediation(
            "Add a PrivacyInfo.xcprivacy to the app target declaring collected \
             data types and required-reason API usage. In Xcode: File > New > \
             File > App Privacy.",
        )]
    }
}
