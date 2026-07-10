//! IOS-CONFIG-009 — Legacy calendar key without the iOS 17 full-access key.
//!
//! iOS 17 split calendar access: `NSCalendarsUsageDescription` no longer grants
//! write/full access. Apps that need it must add
//! `NSCalendarsFullAccessUsageDescription`, or calendar access silently fails on
//! iOS 17+.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct CalendarFullAccessCheck;

const LEGACY: &str = "NSCalendarsUsageDescription";
const FULL_ACCESS: &str = "NSCalendarsFullAccessUsageDescription";
const WRITE_ONLY: &str = "NSCalendarsWriteOnlyAccessUsageDescription";

const META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-009",
    title: "Legacy calendar key without the iOS 17 full-access key",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some(
        "https://developer.apple.com/documentation/bundleresources/information_property_list/nscalendarsfullaccessusagedescription",
    ),
};

impl IosCheck for CalendarFullAccessCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        // Only relevant if the app declares the legacy key and neither iOS 17 key.
        if !project.has_info_key(LEGACY)
            || project.has_info_key(FULL_ACCESS)
            || project.has_info_key(WRITE_ONLY)
        {
            return Vec::new();
        }
        let mut finding = Finding::from_meta(
            &META,
            "`NSCalendarsUsageDescription` is set without \
             `NSCalendarsFullAccessUsageDescription`. On iOS 17+ the legacy key no longer grants \
             full calendar access.",
        )
        .remediation(
            "Add NSCalendarsFullAccessUsageDescription (and/or \
             NSCalendarsWriteOnlyAccessUsageDescription) for iOS 17+.",
        );
        if let Some(path) = &project.info_plist_path {
            finding = finding.location(Location::file(path.clone()));
        }
        vec![finding]
    }
}
