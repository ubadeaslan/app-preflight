//! IOS-CONFIG-007 — Insecure per-domain App Transport Security exceptions.
//!
//! Even without a global `NSAllowsArbitraryLoads`, per-domain entries under
//! `NSExceptionDomains` can quietly weaken ATS: allowing insecure HTTP loads or
//! a minimum TLS version below 1.2. Apple scrutinizes these.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct AtsExceptionDomainsCheck;

const META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-007",
    title: "Insecure App Transport Security exception domain",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: Some("2.5.1"),
    docs_url: Some(
        "https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity/nsexceptiondomains",
    ),
};

/// TLS versions below 1.2 that are considered weak.
const WEAK_TLS: &[&str] = &["TLSv1.0", "TLSv1.1"];

impl IosCheck for AtsExceptionDomainsCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let Some(domains) = project
            .info_plist
            .as_ref()
            .and_then(|d| d.get("NSAppTransportSecurity"))
            .and_then(|v| v.as_dictionary())
            .and_then(|ats| ats.get("NSExceptionDomains"))
            .and_then(|v| v.as_dictionary())
        else {
            return Vec::new();
        };

        let loc = project.info_plist_path.clone().map(Location::file);
        let mut findings = Vec::new();

        for (domain, value) in domains {
            let Some(entry) = value.as_dictionary() else {
                continue;
            };
            let allows_http = entry
                .get("NSExceptionAllowsInsecureHTTPLoads")
                .and_then(|v| v.as_boolean())
                .unwrap_or(false);
            let weak_tls = entry
                .get("NSExceptionMinimumTLSVersion")
                .and_then(|v| v.as_string())
                .map(|v| WEAK_TLS.contains(&v))
                .unwrap_or(false);

            if !allows_http && !weak_tls {
                continue;
            }
            let reason = if allows_http {
                "allows insecure HTTP loads"
            } else {
                "sets a minimum TLS version below 1.2"
            };
            let mut finding = Finding::from_meta(
                &META,
                format!("ATS exception for `{domain}` {reason}."),
            )
            .remediation(
                "Remove the exception or use HTTPS with TLS 1.2+; Apple expects a justification \
                 for ATS exceptions.",
            );
            if let Some(l) = &loc {
                finding = finding.location(l.clone());
            }
            findings.push(finding);
        }

        findings
    }
}
