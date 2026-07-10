//! IOS-CONFIG-008 — `LSApplicationQueriesSchemes` over the 50-entry limit.
//!
//! iOS only honors the first 50 declared query schemes; beyond that,
//! `canOpenURL:` silently returns false, so integrations quietly break.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct QuerySchemesLimitCheck;

const LIMIT: usize = 50;

const META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-008",
    title: "LSApplicationQueriesSchemes exceeds the 50-entry limit",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some(
        "https://developer.apple.com/documentation/bundleresources/information_property_list/lsapplicationqueriesschemes",
    ),
};

impl IosCheck for QuerySchemesLimitCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let count = project
            .info_plist
            .as_ref()
            .and_then(|d| d.get("LSApplicationQueriesSchemes"))
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);

        if count <= LIMIT {
            return Vec::new();
        }
        let mut finding = Finding::from_meta(
            &META,
            format!(
                "`LSApplicationQueriesSchemes` declares {count} schemes; iOS only honors the \
                 first {LIMIT}, so `canOpenURL:` silently fails for the rest."
            ),
        )
        .remediation("Trim the list to the schemes you actually query (max 50).");
        if let Some(path) = &project.info_plist_path {
            finding = finding.location(Location::file(path.clone()));
        }
        vec![finding]
    }
}
