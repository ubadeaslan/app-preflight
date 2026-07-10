//! Compiled `.ipa` inspection.
//!
//! An IPA is a ZIP containing `Payload/<App>.app/` with a Mach-O executable and
//! resources. This layer extracts a [`BinarySnapshot`] (linked private
//! frameworks, UIWebView usage, embedded debug endpoints, privacy-manifest
//! presence) and runs [`checks`] against it. As elsewhere, extraction and rules
//! are separated so the checks are unit-testable on a hand-built snapshot.

pub mod checks;
mod extract;

use preflight_core::{CheckMeta, Finding};
use std::path::Path;

/// A normalized, check-ready view of a compiled iOS app.
#[derive(Debug, Clone, Default)]
pub struct BinarySnapshot {
    pub app_name: String,
    /// A `PrivacyInfo.xcprivacy` was found inside the app bundle.
    pub has_privacy_manifest: bool,
    /// The Mach-O references the deprecated `UIWebView` class.
    pub uses_uiwebview: bool,
    /// Private frameworks the binary links against (Guideline 2.5.1).
    pub private_frameworks: Vec<String>,
    /// Debug / local network endpoints found embedded in the binary.
    pub debug_endpoints: Vec<String>,
}

/// Analyze an `.ipa` at `path`.
pub fn analyze(path: &Path) -> Result<Vec<Finding>, BinaryError> {
    let snapshot = extract::extract(path)?;
    Ok(run_checks(&snapshot))
}

/// Run every binary check against an already-extracted snapshot.
pub fn run_checks(snapshot: &BinarySnapshot) -> Vec<Finding> {
    checks::registry()
        .iter()
        .flat_map(|c| c.run(snapshot))
        .collect()
}

pub fn all_check_meta() -> Vec<CheckMeta> {
    checks::all_meta()
}

#[derive(Debug)]
pub enum BinaryError {
    Io(std::io::Error),
    Zip(String),
    /// The archive did not contain a `Payload/*.app/` bundle.
    NotAnIpa,
}

impl std::fmt::Display for BinaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryError::Io(e) => write!(f, "reading .ipa: {e}"),
            BinaryError::Zip(e) => write!(f, "reading .ipa archive: {e}"),
            BinaryError::NotAnIpa => {
                write!(f, "no Payload/*.app bundle found — is this a valid .ipa?")
            }
        }
    }
}

impl std::error::Error for BinaryError {}
