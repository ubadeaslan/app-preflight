//! Android analysis for app-preflight.
//!
//! Mirrors the iOS crate: [`analyze`] loads an [`AndroidProject`] and runs every
//! [`AndroidCheck`] in [`checks::registry`].

pub mod binary;
pub mod checks;
pub mod metadata;
mod permissions;
mod project;

pub use preflight_core::MetadataScan;
pub use project::{android_attr, AndroidProject, ANDROID_NS};

use preflight_core::{CheckMeta, Config, Finding};
use std::path::Path;

/// A single Android check, run against a parsed [`AndroidProject`].
pub trait AndroidCheck: Sync {
    fn meta(&self) -> CheckMeta;
    fn run(&self, project: &AndroidProject, config: &Config) -> Vec<Finding>;
}

/// Analyze the Android project rooted at `root`, or `None` if there isn't one.
pub fn analyze(root: &Path, config: &Config) -> Option<Vec<Finding>> {
    let project = AndroidProject::load(root)?;
    let mut findings = Vec::new();
    for check in checks::registry() {
        if config.is_disabled(check.meta().id) {
            continue;
        }
        findings.extend(check.run(&project, config));
    }
    Some(findings)
}

/// Metadata for every registered Android check (source-scan + Play metadata) —
/// used by `preflight rules`.
pub fn all_check_meta() -> Vec<CheckMeta> {
    let mut metas: Vec<CheckMeta> = checks::registry().iter().map(|c| c.meta()).collect();
    metas.extend(metadata::all_check_meta());
    metas.extend(binary::all_check_meta());
    metas
}

/// Analyze a compiled `.apk` file.
pub fn analyze_binary(path: &Path) -> Result<Vec<Finding>, binary::BinaryError> {
    binary::analyze(path)
}

/// Analyze an `.aab` (Android App Bundle) file.
pub fn analyze_bundle(path: &Path) -> Result<Vec<Finding>, binary::BinaryError> {
    binary::analyze_bundle(path)
}

/// Run the Google Play metadata scan, if it is configured.
///
/// The package name comes from `GPLAY_PACKAGE_NAME` when set, otherwise from the
/// project's Gradle `applicationId` or the manifest `package` attribute.
pub fn analyze_metadata(root: &Path, _config: &Config) -> MetadataScan {
    let Some(sa) = metadata::ServiceAccount::from_env() else {
        return MetadataScan::Skipped;
    };
    let package = sa
        .package_name
        .clone()
        .or_else(|| detect_package_name(root));
    let Some(package) = package else {
        return MetadataScan::NoTarget;
    };
    match metadata::analyze(&sa, &package) {
        Ok(findings) => MetadataScan::Done(findings),
        Err(e) => MetadataScan::Failed(e.to_string()),
    }
}

/// The application id from Gradle (`applicationId = "..."`), falling back to the
/// manifest `package` attribute.
fn detect_package_name(root: &Path) -> Option<String> {
    let project = AndroidProject::load(root)?;
    if let Some(id) = gradle_application_id(&project.gradle_text) {
        return Some(id);
    }
    let doc = project.manifest_doc()?;
    doc.root_element()
        .attribute("package")
        .map(str::to_string)
        .filter(|p| !p.is_empty())
}

/// Extract `applicationId "com.x"` / `applicationId = "com.x"` from Gradle text.
fn gradle_application_id(gradle: &str) -> Option<String> {
    for line in gradle.lines() {
        let line = line.trim();
        if !line.starts_with("applicationId") {
            continue;
        }
        // Exclude `applicationIdSuffix` — the next char after the keyword must not
        // be an identifier char.
        let after = &line["applicationId".len()..];
        if after.chars().next().is_some_and(|c| c.is_alphanumeric()) {
            continue;
        }
        if let Some(start) = line.find(['"', '\'']) {
            let rest = &line[start + 1..];
            if let Some(end) = rest.find(['"', '\'']) {
                let id = &rest[..end];
                if !id.is_empty() {
                    return Some(id.to_string());
                }
            }
        }
    }
    None
}
