//! IOS-CONFIG-002 — Required version keys and placeholder bundle identifier.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct VersioningCheck;

const META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-002",
    title: "Version keys / bundle identifier issues",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some(
        "https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundleshortversionstring",
    ),
};

/// Fragments that indicate an unedited template bundle identifier. `$(` is
/// skipped because build-setting placeholders like `$(PRODUCT_BUNDLE_IDENTIFIER)`
/// are legitimate in Info.plist.
const PLACEHOLDER_BUNDLE_FRAGMENTS: &[&str] = &[
    "com.example",
    "com.yourcompany",
    "com.mycompany",
    "example.com",
];

impl IosCheck for VersioningCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        if project.info_plist.is_none() {
            return Vec::new();
        }
        let plist_path = project.info_plist_path.clone().unwrap_or_default();
        let loc = || Location::file(plist_path.clone());
        let mut findings = Vec::new();

        let short_version = project.info_string("CFBundleShortVersionString");
        if short_version.map(str::trim).unwrap_or("").is_empty()
            && !is_build_variable(short_version)
        {
            findings.push(
                Finding::from_meta(
                    &META,
                    "`CFBundleShortVersionString` (marketing version) is missing or empty. \
                     App Store Connect requires a version string.",
                )
                .severity(Severity::Error)
                .location(loc())
                .remediation("Set CFBundleShortVersionString, e.g. `1.0.0`."),
            );
        }

        if let Some(bundle_id) = project.info_string("CFBundleIdentifier") {
            let lower = bundle_id.to_ascii_lowercase();
            if PLACEHOLDER_BUNDLE_FRAGMENTS
                .iter()
                .any(|frag| lower.contains(frag))
            {
                findings.push(
                    Finding::from_meta(
                        &META,
                        format!(
                            "Bundle identifier looks like an unedited template (\"{bundle_id}\")."
                        ),
                    )
                    .severity(Severity::Warning)
                    .location(loc())
                    .remediation(
                        "Set CFBundleIdentifier to your real reverse-DNS identifier before submission.",
                    ),
                );
            }
        }

        findings
    }
}

/// True when the value is an Xcode build-setting reference like `$(MARKETING_VERSION)`.
fn is_build_variable(value: Option<&str>) -> bool {
    value.map(|v| v.contains("$(")).unwrap_or(false)
}
