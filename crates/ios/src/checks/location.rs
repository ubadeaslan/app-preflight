//! Location-authorization checks.
//!
//! - IOS-PRIVACY-004: background location requested without an "Always" purpose string.
//! - IOS-CONFIG-004: the legacy `NSLocationAlwaysUsageDescription` without the
//!   combined key iOS 11+ requires.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

const ALWAYS_COMBINED: &str = "NSLocationAlwaysAndWhenInUseUsageDescription";
const ALWAYS_LEGACY: &str = "NSLocationAlwaysUsageDescription";

fn has_location_background_mode(project: &IosProject) -> bool {
    project
        .info_plist
        .as_ref()
        .and_then(|d| d.get("UIBackgroundModes"))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().any(|v| v.as_string() == Some("location")))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------

/// IOS-PRIVACY-004 — Background location without an "Always" purpose string.
pub struct BackgroundLocationCheck;

const BACKGROUND_META: CheckMeta = CheckMeta {
    id: "IOS-PRIVACY-004",
    title: "Background location without an Always usage description",
    platform: Platform::Ios,
    category: Category::Privacy,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("5.1.1"),
    docs_url: Some(
        "https://developer.apple.com/documentation/corelocation/requesting_authorization_to_use_location_services",
    ),
};

impl IosCheck for BackgroundLocationCheck {
    fn meta(&self) -> CheckMeta {
        BACKGROUND_META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        if !has_location_background_mode(project) {
            return Vec::new();
        }
        if project.has_info_key(ALWAYS_COMBINED) || project.has_info_key(ALWAYS_LEGACY) {
            return Vec::new();
        }
        let mut finding = Finding::from_meta(
            &BACKGROUND_META,
            "`UIBackgroundModes` includes `location` but no Always location usage description \
             is set. Background location needs NSLocationAlwaysAndWhenInUseUsageDescription.",
        )
        .remediation(
            "Add NSLocationAlwaysAndWhenInUseUsageDescription explaining the background use, or \
             remove the `location` background mode if it isn't needed.",
        );
        if let Some(path) = &project.info_plist_path {
            finding = finding.location(Location::file(path.clone()));
        }
        vec![finding]
    }
}

// ---------------------------------------------------------------------------

/// IOS-CONFIG-004 — Legacy Always location key without the combined key.
pub struct DeprecatedLocationKeyCheck;

const LEGACY_KEY_META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-004",
    title: "Legacy location key without the combined authorization key",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: Some("5.1.1"),
    docs_url: Some(
        "https://developer.apple.com/documentation/bundleresources/information_property_list/nslocationalwaysandwheninuseusagedescription",
    ),
};

impl IosCheck for DeprecatedLocationKeyCheck {
    fn meta(&self) -> CheckMeta {
        LEGACY_KEY_META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        if !project.has_info_key(ALWAYS_LEGACY) || project.has_info_key(ALWAYS_COMBINED) {
            return Vec::new();
        }
        let mut finding = Finding::from_meta(
            &LEGACY_KEY_META,
            "`NSLocationAlwaysUsageDescription` is set without \
             `NSLocationAlwaysAndWhenInUseUsageDescription`. Since iOS 11 the combined key is \
             required for Always authorization.",
        )
        .remediation("Add NSLocationAlwaysAndWhenInUseUsageDescription alongside the legacy key.");
        if let Some(path) = &project.info_plist_path {
            finding = finding.location(Location::file(path.clone()));
        }
        vec![finding]
    }
}
