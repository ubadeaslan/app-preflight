//! IOS-CONFIG-003 — App Transport Security disabled in the source Info.plist.
//!
//! The compiled-binary layer catches this too (IOS-BIN-006), but flagging it at
//! the source level means you see it in a pull request instead of only after a
//! build.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct AtsArbitraryLoadsCheck;

const META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-003",
    title: "App Transport Security disabled (NSAllowsArbitraryLoads)",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: Some("2.5.1"),
    docs_url: Some(
        "https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity",
    ),
};

impl IosCheck for AtsArbitraryLoadsCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let allows_arbitrary = project
            .info_plist
            .as_ref()
            .and_then(|d| d.get("NSAppTransportSecurity"))
            .and_then(|v| v.as_dictionary())
            .and_then(|ats| ats.get("NSAllowsArbitraryLoads"))
            .and_then(|v| v.as_boolean())
            .unwrap_or(false);

        if !allows_arbitrary {
            return Vec::new();
        }

        let mut finding = Finding::from_meta(
            &META,
            "`NSAppTransportSecurity.NSAllowsArbitraryLoads` is true, disabling App Transport \
             Security globally. Apple requires justification and may reject blanket exceptions.",
        )
        .remediation(
            "Remove the global exception and scope any needed HTTP exceptions to specific \
             domains under NSExceptionDomains.",
        );
        if let Some(path) = &project.info_plist_path {
            finding = finding.location(Location::file(path.clone()));
        }
        vec![finding]
    }
}
