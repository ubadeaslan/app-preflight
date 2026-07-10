//! Entitlements checks.
//!
//! - IOS-CONFIG-005: `aps-environment = development` shipped (push won't work in
//!   production).
//! - IOS-CONFIG-006: `get-task-allow = true` (a debuggable entitlement Apple
//!   rejects on App Store builds).

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

fn location(project: &IosProject) -> Option<Location> {
    project.entitlements_path.clone().map(Location::file)
}

// ---------------------------------------------------------------------------

/// IOS-CONFIG-005 — Push notifications in the development environment.
pub struct ApsEnvironmentCheck;

const APS_META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-005",
    title: "aps-environment set to development",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some(
        "https://developer.apple.com/documentation/bundleresources/entitlements/aps-environment",
    ),
};

impl IosCheck for ApsEnvironmentCheck {
    fn meta(&self) -> CheckMeta {
        APS_META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let is_dev = project
            .entitlement("aps-environment")
            .and_then(|v| v.as_string())
            .map(|s| s.eq_ignore_ascii_case("development"))
            .unwrap_or(false);
        if !is_dev {
            return Vec::new();
        }
        let mut finding = Finding::from_meta(
            &APS_META,
            "`aps-environment` is set to `development`. A build shipped with the development \
             push environment can't receive production push notifications.",
        )
        .remediation("Use `production` for release builds (Xcode manages this per configuration).");
        if let Some(l) = location(project) {
            finding = finding.location(l);
        }
        vec![finding]
    }
}

// ---------------------------------------------------------------------------

/// IOS-CONFIG-006 — Debuggable entitlement (`get-task-allow = true`).
pub struct GetTaskAllowCheck;

const GET_TASK_ALLOW_META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-006",
    title: "get-task-allow enabled (debuggable entitlement)",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("2.5.1"),
    docs_url: Some(
        "https://developer.apple.com/documentation/bundleresources/entitlements/get-task-allow",
    ),
};

impl IosCheck for GetTaskAllowCheck {
    fn meta(&self) -> CheckMeta {
        GET_TASK_ALLOW_META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let allowed = project
            .entitlement("get-task-allow")
            .and_then(|v| v.as_boolean())
            .unwrap_or(false);
        if !allowed {
            return Vec::new();
        }
        let mut finding = Finding::from_meta(
            &GET_TASK_ALLOW_META,
            "`get-task-allow` is true, which marks the app as debuggable. App Store builds must \
             ship with this disabled.",
        )
        .remediation(
            "Ensure the release entitlements set get-task-allow to false (the App Store \
             distribution profile does this automatically).",
        );
        if let Some(l) = location(project) {
            finding = finding.location(l);
        }
        vec![finding]
    }
}
