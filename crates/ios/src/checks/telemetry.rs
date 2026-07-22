//! IOS-CONFIG-017 — Firebase app shipping without crash reporting.
//!
//! An app with a backend but no crash reporter flies blind: the first
//! release-only failure has to be diagnosed over a USB cable instead of from a
//! dashboard (Snapaw, 2026-07-22). Crashlytics is one dependency and a few
//! lines of bootstrap, so its absence in a project that already uses Firebase
//! is nearly always an oversight rather than a decision.
//!
//! Scope is deliberately narrow — it fires only when `firebase_core` is
//! already a dependency, so non-Firebase projects stay silent.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct CrashReportingCheck;

const CRASH_REPORTING_META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-017",
    title: "Firebase project without crash reporting",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Info,
    confidence: Confidence::Medium,
    guideline: None,
    docs_url: Some("https://firebase.google.com/docs/crashlytics/get-started?platform=flutter"),
};

/// Crash reporters that satisfy the check (Crashlytics or a known alternative).
const CRASH_REPORTERS: &[&str] = &[
    "firebase_crashlytics",
    "sentry_flutter",
    "bugsnag_flutter",
    "appcenter",
];

impl IosCheck for CrashReportingCheck {
    fn meta(&self) -> CheckMeta {
        CRASH_REPORTING_META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let path = project.root.join("pubspec.yaml");
        let Ok(pubspec) = std::fs::read_to_string(&path) else {
            return Vec::new(); // Not a Flutter project.
        };
        if !pubspec.contains("firebase_core") {
            return Vec::new(); // No backend wiring — out of scope.
        }
        if CRASH_REPORTERS.iter().any(|dep| pubspec.contains(dep)) {
            return Vec::new();
        }
        vec![Finding::from_meta(
            &CRASH_REPORTING_META,
            "The project depends on firebase_core but declares no crash reporter \
             (firebase_crashlytics or an equivalent). Release-only failures then have to be \
             diagnosed over a cable instead of from a dashboard.",
        )
        .location(Location::file(path))
        .remediation(
            "Add firebase_crashlytics, route FlutterError.onError and \
             PlatformDispatcher.instance.onError to it, and verify a test crash actually \
             appears in the console — an installed-but-unverified reporter is the same as \
             none.",
        )]
    }
}
