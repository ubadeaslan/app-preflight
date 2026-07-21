//! iOS analysis for app-preflight.
//!
//! Entry point is [`analyze`]. Each check implements [`IosCheck`] and is
//! registered in [`checks::registry`]. Adding a new App Store rejection check
//! means writing one file under `src/checks/` and adding it to the registry —
//! nothing else.

pub mod binary;
pub mod checks;
pub mod metadata;
mod project;

pub use project::IosProject;

use preflight_core::{CheckMeta, Config, Finding};
use std::path::Path;

/// A single iOS check. Runs against a fully-parsed [`IosProject`].
pub trait IosCheck: Sync {
    fn meta(&self) -> CheckMeta;
    fn run(&self, project: &IosProject, config: &Config) -> Vec<Finding>;
}

/// Analyze the iOS project rooted at `root`.
///
/// Returns `None` when `root` does not contain an iOS project, so the caller can
/// distinguish "clean" from "nothing to check".
pub fn analyze(root: &Path, config: &Config) -> Option<Vec<Finding>> {
    let project = IosProject::load(root)?;
    let mut findings = Vec::new();
    for check in checks::registry() {
        if config.is_disabled(check.meta().id) {
            continue;
        }
        findings.extend(check.run(&project, config));
    }
    Some(findings)
}

/// Metadata for every registered iOS check (source-scan + App Store Connect
/// metadata) — used by `preflight rules`.
pub fn all_check_meta() -> Vec<CheckMeta> {
    let mut metas: Vec<CheckMeta> = checks::registry().iter().map(|c| c.meta()).collect();
    metas.extend(metadata::all_check_meta());
    metas.extend(binary::all_check_meta());
    metas
}

/// Analyze a compiled `.ipa` file.
pub fn analyze_binary(path: &Path) -> Result<Vec<Finding>, binary::BinaryError> {
    binary::analyze(path)
}

pub use preflight_core::MetadataScan;

/// Run the App Store Connect metadata scan, if it is configured.
///
/// The bundle id comes from `ASC_BUNDLE_ID` when set, otherwise from the
/// project's `Info.plist` (skipped when that value is a build-setting variable).
pub fn analyze_metadata(root: &Path, _config: &Config) -> MetadataScan {
    let Some(creds) = metadata::AscCredentials::from_env() else {
        return MetadataScan::Skipped;
    };
    let bundle_id = creds.bundle_id.clone().or_else(|| detect_bundle_id(root));
    let Some(bundle_id) = bundle_id else {
        return MetadataScan::NoTarget;
    };
    match metadata::analyze(&creds, &bundle_id, detect_build_number(root)) {
        Ok(findings) => MetadataScan::Done(findings),
        Err(e) => MetadataScan::Failed(e.to_string()),
    }
}

/// The project's `CFBundleVersion` when it is a concrete plain number —
/// build-setting variables (`$(FLUTTER_BUILD_NUMBER)`) and dotted values
/// return `None`, which keeps the burned-build-number check silent.
fn detect_build_number(root: &Path) -> Option<u64> {
    let project = IosProject::load(root)?;
    project
        .info_string("CFBundleVersion")?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Outcome of `preflight submit-sim` at the CLI boundary.
pub enum SubmitSimScan {
    /// ASC credentials are not configured.
    Skipped,
    /// Credentials are set but no concrete bundle id was found.
    NoTarget,
    Done(metadata::SubmitSimReport),
    Failed(String),
}

/// Run the review-submission simulation (see [`metadata::submit_sim`]).
///
/// Unlike [`analyze_metadata`] this WRITES to App Store Connect (a draft
/// submission that is rolled back), so it only ever runs from its own explicit
/// CLI command.
pub fn submit_simulation(root: &Path, _config: &Config) -> SubmitSimScan {
    let Some(creds) = metadata::AscCredentials::from_env() else {
        return SubmitSimScan::Skipped;
    };
    let bundle_id = creds.bundle_id.clone().or_else(|| detect_bundle_id(root));
    let Some(bundle_id) = bundle_id else {
        return SubmitSimScan::NoTarget;
    };
    match metadata::submit_sim::run(&creds, &bundle_id) {
        Ok(report) => SubmitSimScan::Done(report),
        Err(e) => SubmitSimScan::Failed(e.to_string()),
    }
}

/// The concrete bundle identifier from the project, or `None` if it is missing
/// or expressed as an Xcode build variable like `$(PRODUCT_BUNDLE_IDENTIFIER)`.
fn detect_bundle_id(root: &Path) -> Option<String> {
    let project = IosProject::load(root)?;
    let bundle_id = project.info_string("CFBundleIdentifier")?;
    if bundle_id.contains("$(") {
        None
    } else {
        Some(bundle_id.to_string())
    }
}
