//! ANDROID-CONFIG-004 — Foreground service without a `foregroundServiceType`.
//!
//! From Android 14 (targetSdk 34) every foreground service must declare a
//! `android:foregroundServiceType`. Shipping one without it crashes at runtime
//! and blocks the Play upload flow.

use crate::{android_attr, AndroidCheck, AndroidProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct ForegroundServiceTypeCheck;

const FGS_PERMISSION: &str = "android.permission.FOREGROUND_SERVICE";

const META: CheckMeta = CheckMeta {
    id: "ANDROID-CONFIG-004",
    title: "Foreground service without a foregroundServiceType",
    platform: Platform::Android,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::Medium,
    guideline: Some("Android 14: Foreground service types"),
    docs_url: Some("https://developer.android.com/about/versions/14/changes/fgs-types-required"),
};

impl AndroidCheck for ForegroundServiceTypeCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &AndroidProject, _config: &Config) -> Vec<Finding> {
        let Some(doc) = project.manifest_doc() else {
            return Vec::new();
        };

        let declares_fgs = doc
            .descendants()
            .filter(|n| n.has_tag_name("uses-permission"))
            .any(|n| android_attr(n, "name") == Some(FGS_PERMISSION));
        if !declares_fgs {
            return Vec::new();
        }

        let missing_type = doc.descendants().any(|n| {
            n.has_tag_name("service") && android_attr(n, "foregroundServiceType").is_none()
        });
        if !missing_type {
            return Vec::new();
        }

        let mut finding = Finding::from_meta(
            &META,
            "The app declares FOREGROUND_SERVICE but a <service> has no \
             android:foregroundServiceType. Android 14 (targetSdk 34+) requires a type on every \
             foreground service.",
        )
        .remediation(
            "Add android:foregroundServiceType to each foreground service and the matching \
             FOREGROUND_SERVICE_* permission.",
        );
        if let Some(path) = &project.manifest_path {
            finding = finding.location(Location::file(path.clone()));
        }
        vec![finding]
    }
}
