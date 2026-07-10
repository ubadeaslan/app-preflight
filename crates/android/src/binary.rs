//! Compiled `.apk` inspection.
//!
//! An APK is a ZIP. The high-value, decode-free signal is the set of native ABIs
//! under `lib/<abi>/` — Google Play blocks uploads that ship 32-bit native code
//! without a 64-bit counterpart. We read the ABI set and check it; DEX/AXML
//! decoding is left to a future iteration.

use preflight_core::{Category, CheckMeta, Confidence, Finding, Platform, Severity};
use std::collections::BTreeSet;
use std::path::Path;
use zip::ZipArchive;

/// The native ABIs present in an APK, from `lib/<abi>/`.
#[derive(Debug, Clone, Default)]
pub struct AbiSnapshot {
    pub abis: BTreeSet<String>,
}

impl AbiSnapshot {
    fn has_32bit(&self) -> bool {
        self.abis.iter().any(|a| a == "armeabi-v7a" || a == "x86")
    }
    fn has_64bit(&self) -> bool {
        self.abis.iter().any(|a| a == "arm64-v8a" || a == "x86_64")
    }
}

/// Analyze an `.apk` at `path`.
pub fn analyze(path: &Path) -> Result<Vec<Finding>, BinaryError> {
    let snapshot = extract(path)?;
    Ok(run_checks(&snapshot))
}

pub fn run_checks(snapshot: &AbiSnapshot) -> Vec<Finding> {
    let mut findings = Vec::new();
    // ANDROID-BIN-001 — 64-bit requirement.
    if snapshot.has_32bit() && !snapshot.has_64bit() {
        findings.push(
            Finding::from_meta(
                &SIXTYFOUR_BIT_META,
                format!(
                    "The APK ships 32-bit native libraries ({}) but no 64-bit ABI. \
                     Google Play requires a 64-bit version.",
                    snapshot.abis.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
            )
            .remediation(
                "Build and include arm64-v8a (and x86_64 if you ship x86) native libraries.",
            ),
        );
    }
    findings
}

pub fn all_check_meta() -> Vec<CheckMeta> {
    vec![SIXTYFOUR_BIT_META]
}

const SIXTYFOUR_BIT_META: CheckMeta = CheckMeta {
    id: "ANDROID-BIN-001",
    title: "Missing 64-bit native libraries",
    platform: Platform::Android,
    category: Category::Binary,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("Play: 64-bit requirement"),
    docs_url: Some("https://developer.android.com/google/play/requirements/64-bit"),
};

fn extract(path: &Path) -> Result<AbiSnapshot, BinaryError> {
    let file = std::fs::File::open(path).map_err(BinaryError::Io)?;
    let archive = ZipArchive::new(file).map_err(|e| BinaryError::Zip(e.to_string()))?;

    let mut abis = BTreeSet::new();
    for name in archive.file_names() {
        // Entries look like `lib/arm64-v8a/libfoo.so`.
        if let Some(rest) = name.strip_prefix("lib/") {
            if let Some((abi, _)) = rest.split_once('/') {
                if !abi.is_empty() {
                    abis.insert(abi.to_string());
                }
            }
        }
    }
    Ok(AbiSnapshot { abis })
}

#[derive(Debug)]
pub enum BinaryError {
    Io(std::io::Error),
    Zip(String),
}

impl std::fmt::Display for BinaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryError::Io(e) => write!(f, "reading .apk: {e}"),
            BinaryError::Zip(e) => write!(f, "reading .apk archive: {e}"),
        }
    }
}

impl std::error::Error for BinaryError {}
