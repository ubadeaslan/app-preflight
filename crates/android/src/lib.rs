//! Android analysis for app-preflight.
//!
//! Mirrors the iOS crate: [`analyze`] loads an [`AndroidProject`] and runs every
//! [`AndroidCheck`] in [`checks::registry`].

pub mod checks;
mod project;

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

/// Metadata for every registered Android check — used by `preflight rules`.
pub fn all_check_meta() -> Vec<CheckMeta> {
    checks::registry().iter().map(|c| c.meta()).collect()
}
