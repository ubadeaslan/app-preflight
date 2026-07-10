//! iOS analysis for app-preflight.
//!
//! Entry point is [`analyze`]. Each check implements [`IosCheck`] and is
//! registered in [`checks::registry`]. Adding a new App Store rejection check
//! means writing one file under `src/checks/` and adding it to the registry —
//! nothing else.

pub mod checks;
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

/// Metadata for every registered iOS check — used by `preflight rules`.
pub fn all_check_meta() -> Vec<CheckMeta> {
    checks::registry().iter().map(|c| c.meta()).collect()
}
