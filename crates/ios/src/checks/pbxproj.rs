//! Checks over the raw `project.pbxproj` text.
//!
//! IOS-CONFIG-011 — inconsistent `IPHONEOS_DEPLOYMENT_TARGET` values. The value
//! lives in several build configurations (project-level Debug/Release/Profile
//! plus target-level); editing one and missing the others ships a stale minimum
//! that modern SDKs (e.g. Firebase, which requires iOS 15) refuse to build
//! against — or worse, builds against the lowest one.
//!
//! IOS-CONFIG-012 — `CODE_SIGN_IDENTITY` pinned to "iPhone Developer". Project
//! templates carry this pin; during an App Store archive it forces the
//! development identity and the archive fails with misleading errors
//! ("no devices", "requires a development team") instead of pointing at the pin.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct DeploymentTargetConsistencyCheck;

const DEPLOYMENT_TARGET_META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-011",
    title: "Inconsistent IPHONEOS_DEPLOYMENT_TARGET values",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: None,
    docs_url: None,
};

impl IosCheck for DeploymentTargetConsistencyCheck {
    fn meta(&self) -> CheckMeta {
        DEPLOYMENT_TARGET_META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let Some(text) = &project.pbxproj else {
            return Vec::new();
        };
        let mut values: Vec<String> = Vec::new();
        for line in text.lines() {
            let Some(value) = setting_value(line, "IPHONEOS_DEPLOYMENT_TARGET") else {
                continue;
            };
            if !values.iter().any(|v| v == value) {
                values.push(value.to_string());
            }
        }
        if values.len() <= 1 {
            return Vec::new();
        }
        let path = project.pbxproj_path.clone().unwrap_or_default();
        vec![Finding::from_meta(
            &DEPLOYMENT_TARGET_META,
            format!(
                "project.pbxproj sets IPHONEOS_DEPLOYMENT_TARGET to {} in different build \
                 configurations. A stale low value can make the build target an OS the \
                 linked SDKs no longer support.",
                values.join(" and "),
            ),
        )
        .location(Location::file(path))
        .remediation(
            "Set the same deployment target in every build configuration (project- and \
             target-level Debug/Release/Profile), matching the minimum your SDKs require.",
        )]
    }
}

pub struct CodeSignIdentityPinCheck;

const SIGN_IDENTITY_META: CheckMeta = CheckMeta {
    id: "IOS-CONFIG-012",
    title: "CODE_SIGN_IDENTITY pinned to \"iPhone Developer\"",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: None,
    docs_url: None,
};

impl IosCheck for CodeSignIdentityPinCheck {
    fn meta(&self) -> CheckMeta {
        SIGN_IDENTITY_META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let Some(text) = &project.pbxproj else {
            return Vec::new();
        };
        let pinned = text.lines().any(|line| {
            setting_value(line, "CODE_SIGN_IDENTITY")
                .map(|v| v.contains("iPhone Developer"))
                .unwrap_or(false)
        });
        if !pinned {
            return Vec::new();
        }
        let path = project.pbxproj_path.clone().unwrap_or_default();
        vec![Finding::from_meta(
            &SIGN_IDENTITY_META,
            "project.pbxproj pins CODE_SIGN_IDENTITY to \"iPhone Developer\". An App Store \
             archive then fails with misleading errors (\"no devices registered\", \
             development-profile complaints) because the pin forces the development \
             identity over the distribution one.",
        )
        .location(Location::file(path))
        .remediation(
            "Remove the CODE_SIGN_IDENTITY pin (including the [sdk=iphoneos*] variant) and \
             let the signing style / export options choose the identity.",
        )]
    }
}

/// If `line` assigns build setting `key` (optionally quoted and with a
/// `[sdk=...]` qualifier), return the trimmed value without the trailing `;`
/// or surrounding quotes.
fn setting_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let trimmed = line.trim_start().trim_start_matches('"');
    let mut rest = trimmed.strip_prefix(key)?;
    // Reject longer identifiers that merely start with `key`.
    if !matches!(rest.chars().next(), Some(' ' | '\t' | '[' | '"' | '=')) {
        return None;
    }
    // Skip a `[sdk=...]` qualifier so its `=` is not mistaken for the assignment.
    if let Some(after) = rest.strip_prefix('[') {
        rest = after.split_once(']')?.1;
    }
    let rest = rest.trim_start_matches('"').trim_start();
    let rest = rest.strip_prefix('=')?;
    Some(rest.trim().trim_end_matches(';').trim().trim_matches('"'))
}

#[cfg(test)]
mod tests {
    use super::setting_value;

    #[test]
    fn parses_plain_and_qualified_settings() {
        assert_eq!(
            setting_value("\t\tIPHONEOS_DEPLOYMENT_TARGET = 13.0;", "IPHONEOS_DEPLOYMENT_TARGET"),
            Some("13.0")
        );
        assert_eq!(
            setting_value(
                "\t\t\"CODE_SIGN_IDENTITY[sdk=iphoneos*]\" = \"iPhone Developer\";",
                "CODE_SIGN_IDENTITY"
            ),
            Some("iPhone Developer")
        );
        assert_eq!(setting_value("SWIFT_VERSION = 5.0;", "IPHONEOS_DEPLOYMENT_TARGET"), None);
    }
}
