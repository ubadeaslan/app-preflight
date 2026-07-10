//! ANDROID-CONFIG-002 — `targetSdk` must meet Play's current minimum.
//!
//! Google Play requires new apps and updates to target a recent API level
//! (roughly "latest stable minus one"). Ship below it and the release is blocked
//! at upload time.

use crate::{AndroidCheck, AndroidProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct TargetSdkCheck;

/// Play's minimum target API for new uploads. Bump this as Google raises it
/// (API 35 / Android 15 since 2025-08-31; raise to 36 after the 2026 deadline).
const MIN_TARGET_SDK: u32 = 35;

const META: CheckMeta = CheckMeta {
    id: "ANDROID-CONFIG-002",
    title: "targetSdk below Google Play minimum",
    platform: Platform::Android,
    category: Category::Configuration,
    default_severity: Severity::Error,
    confidence: Confidence::Medium,
    guideline: Some("Play: Target API level"),
    docs_url: Some("https://developer.android.com/google/play/requirements/target-sdk"),
};

impl AndroidCheck for TargetSdkCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &AndroidProject, _config: &Config) -> Vec<Finding> {
        let Some(target) = parse_target_sdk(&project.gradle_text) else {
            // Can't determine it statically (e.g. from a version catalog); stay quiet.
            return Vec::new();
        };

        if target >= MIN_TARGET_SDK {
            return Vec::new();
        }

        let mut finding = Finding::from_meta(
            &META,
            format!(
                "targetSdk is {target}, below Google Play's current minimum of \
                 {MIN_TARGET_SDK}. Play will reject the upload."
            ),
        )
        .remediation(format!(
            "Raise targetSdk to at least {MIN_TARGET_SDK} and test against the \
             behavior changes for that API level."
        ));
        // Point at a gradle file if we have one recorded.
        if let Some(path) = gradle_path(project) {
            finding = finding.location(Location::file(path));
        }
        vec![finding]
    }
}

/// Extract `targetSdk` / `targetSdkVersion` from Gradle text (Groovy or KTS).
fn parse_target_sdk(gradle: &str) -> Option<u32> {
    for line in gradle.lines() {
        let line = line.trim();
        if !line.contains("targetSdk") {
            continue;
        }
        // Grab the first integer after the keyword.
        if let Some(idx) = line.find("targetSdk") {
            let rest = &line[idx..];
            let digits: String = rest
                .chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(v) = digits.parse::<u32>() {
                return Some(v);
            }
        }
    }
    None
}

fn gradle_path(project: &AndroidProject) -> Option<std::path::PathBuf> {
    // Best-effort: the app module gradle is commonly at app/build.gradle(.kts).
    for candidate in [
        "app/build.gradle.kts",
        "app/build.gradle",
        "build.gradle.kts",
        "build.gradle",
    ] {
        let p = project.root.join(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    None
}
