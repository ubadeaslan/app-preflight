//! IOS-CONFIG-001 — Export-compliance encryption declaration.
//!
//! Without `ITSAppUsesNonExemptEncryption` in Info.plist, App Store Connect
//! asks the export-compliance question on *every* build submission, stalling
//! releases. Declaring it up front removes that friction.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct EncryptionDeclarationCheck;

const KEY: &str = "ITSAppUsesNonExemptEncryption";

const META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-001",
    title: "Missing export-compliance encryption declaration",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: Some("Export Compliance"),
    docs_url: Some(
        "https://developer.apple.com/documentation/security/complying_with_encryption_export_regulations",
    ),
};

impl IosCheck for EncryptionDeclarationCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        if project.info_plist.is_none() || project.has_info_key(KEY) {
            return Vec::new();
        }
        let plist_path = project.info_plist_path.clone().unwrap_or_default();
        vec![Finding::from_meta(
            &META,
            format!(
                "`{KEY}` is not set. App Store Connect will prompt for export \
                 compliance on every submission until you declare it."
            ),
        )
        .location(Location::file(plist_path))
        .remediation(
            "Add `ITSAppUsesNonExemptEncryption` to Info.plist. Set it to \
             `false` if you only use exempt encryption (HTTPS/TLS), or `true` \
             plus the relevant compliance keys otherwise.",
        )]
    }
}
