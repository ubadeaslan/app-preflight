//! IOS-CONFIG-013 — landscape declared but rarely tested.
//!
//! Flutter's template (and many starter projects) declare all orientations in
//! `UISupportedInterfaceOrientations`. App Review rotates the phone; a layout
//! that was never run in landscape shows clipped or overflowing UI and collects
//! a 2.1/4.0 rejection. If landscape was never tested, the honest declaration
//! is portrait-only. A landscape-ONLY app is a deliberate choice and stays
//! silent.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct OrientationLockCheck;

const ORIENTATION_META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-013",
    title: "Landscape orientations declared (reviewer will rotate)",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Info,
    confidence: Confidence::Medium,
    guideline: None,
    docs_url: Some(
        "https://developer.apple.com/documentation/bundleresources/information-property-list/uisupportedinterfaceorientations",
    ),
};

const ORIENTATION_KEYS: &[&str] = &[
    "UISupportedInterfaceOrientations",
    "UISupportedInterfaceOrientations~ipad",
];

impl IosCheck for OrientationLockCheck {
    fn meta(&self) -> CheckMeta {
        ORIENTATION_META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let Some(plist) = project.info_plist.as_ref() else {
            return Vec::new();
        };
        let mut has_portrait = false;
        let mut has_landscape = false;
        for key in ORIENTATION_KEYS {
            let Some(values) = plist.get(key).and_then(|v| v.as_array()) else {
                continue;
            };
            for value in values {
                let Some(s) = value.as_string() else { continue };
                if s.contains("Portrait") {
                    has_portrait = true;
                }
                if s.contains("Landscape") {
                    has_landscape = true;
                }
            }
        }
        // Landscape-only is deliberate; portrait+landscape is the untested trap.
        if !(has_portrait && has_landscape) {
            return Vec::new();
        }
        let mut finding = Finding::from_meta(
            &ORIENTATION_META,
            "Both portrait and landscape orientations are declared (the Flutter/Xcode template \
             default). App Review rotates the device — if the app was never tested in landscape, \
             a broken rotated layout is a rejection waiting to happen.",
        )
        .remediation(
            "Either test every screen in landscape, or restrict \
             UISupportedInterfaceOrientations to portrait until landscape is a real, tested \
             feature.",
        );
        if let Some(path) = &project.info_plist_path {
            finding = finding.location(Location::file(path.clone()));
        }
        vec![finding]
    }
}
