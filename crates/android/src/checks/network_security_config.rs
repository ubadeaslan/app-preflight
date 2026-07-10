//! ANDROID-CONFIG-006 — Cleartext traffic permitted via a network security config.
//!
//! `usesCleartextTraffic` isn't the only way to allow HTTP: a
//! `network-security-config` referenced from the manifest can re-enable it with
//! `cleartextTrafficPermitted="true"` in its base- or domain-config.

use crate::{AndroidCheck, AndroidProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct NetworkSecurityConfigCheck;

const META: CheckMeta = CheckMeta {
    id: "ANDROID-CONFIG-006",
    title: "Network security config permits cleartext traffic",
    platform: Platform::Android,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: Some("Play: User Data"),
    docs_url: Some("https://developer.android.com/privacy-and-security/security-config"),
};

impl AndroidCheck for NetworkSecurityConfigCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &AndroidProject, _config: &Config) -> Vec<Finding> {
        let Some(nsc) = project.network_security_config() else {
            return Vec::new();
        };
        let Ok(doc) = roxmltree::Document::parse(nsc) else {
            return Vec::new();
        };

        let permits = doc.descendants().any(|n| {
            (n.has_tag_name("base-config") || n.has_tag_name("domain-config"))
                && n.attribute("cleartextTrafficPermitted")
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
        });
        if !permits {
            return Vec::new();
        }

        let mut finding = Finding::from_meta(
            &META,
            "The referenced network security config sets \
             `cleartextTrafficPermitted=\"true\"`, allowing unencrypted HTTP.",
        )
        .remediation(
            "Set cleartextTrafficPermitted=\"false\" (or scope any needed exception to specific \
             domains).",
        );
        if let Some(path) = &project.manifest_path {
            finding = finding.location(Location::file(path.clone()));
        }
        vec![finding]
    }
}
