//! Compiled `.apk` inspection.
//!
//! An APK is a ZIP. We read two things without a full DEX parser:
//! - the native ABIs under `lib/<abi>/` (Google Play's 64-bit requirement), and
//! - the compiled `AndroidManifest.xml`, decoded from binary AXML into
//!   [`manifest::ManifestFacts`] (the merged, ground-truth manifest).
//!
//! Extraction is separated from checks so the check logic is unit-testable on a
//! hand-built [`BinarySnapshot`].

mod manifest;

pub use manifest::ManifestFacts;

use preflight_core::{Category, CheckMeta, Confidence, Finding, Platform, Severity};
use std::collections::BTreeSet;
use std::path::Path;
use zip::ZipArchive;

/// Play's minimum target API for new uploads (kept in sync with the source check).
const MIN_TARGET_SDK: u32 = 34;

/// A check-ready view of a compiled APK.
#[derive(Debug, Clone, Default)]
pub struct BinarySnapshot {
    /// Native ABIs present under `lib/<abi>/`.
    pub abis: BTreeSet<String>,
    /// Facts decoded from the compiled `AndroidManifest.xml`, if decodable.
    pub manifest: Option<ManifestFacts>,
}

impl BinarySnapshot {
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

pub fn run_checks(snapshot: &BinarySnapshot) -> Vec<Finding> {
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

    if let Some(m) = &snapshot.manifest {
        // ANDROID-BIN-002 — debuggable in the shipped (merged) manifest.
        if m.debuggable {
            findings.push(
                Finding::from_meta(
                    &DEBUGGABLE_META,
                    "The compiled manifest is marked android:debuggable=\"true\". A shipped \
                     debuggable build is a hard Play rejection and a security risk.",
                )
                .remediation("Ensure the release build type does not set debuggable."),
            );
        }
        // ANDROID-BIN-003 — targetSdk below Play's minimum, read from the binary.
        if let Some(target) = m.target_sdk {
            if target < MIN_TARGET_SDK {
                findings.push(
                    Finding::from_meta(
                        &TARGET_SDK_META,
                        format!(
                            "The compiled manifest targets API {target}, below Google Play's \
                             minimum of {MIN_TARGET_SDK}."
                        ),
                    )
                    .remediation(format!("Raise targetSdk to at least {MIN_TARGET_SDK}.")),
                );
            }
        }
        // ANDROID-BIN-004 — cleartext traffic permitted in the shipped manifest.
        if m.uses_cleartext_traffic {
            findings.push(
                Finding::from_meta(
                    &CLEARTEXT_META,
                    "The compiled manifest permits cleartext (HTTP) traffic \
                     (usesCleartextTraffic=\"true\").",
                )
                .remediation(
                    "Disable cleartext traffic or restrict it with a network-security-config.",
                ),
            );
        }
    }

    findings
}

pub fn all_check_meta() -> Vec<CheckMeta> {
    vec![
        SIXTYFOUR_BIT_META,
        DEBUGGABLE_META,
        TARGET_SDK_META,
        CLEARTEXT_META,
    ]
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

const DEBUGGABLE_META: CheckMeta = CheckMeta {
    id: "ANDROID-BIN-002",
    title: "Compiled manifest is debuggable",
    platform: Platform::Android,
    category: Category::Binary,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("Play: Device and Network Abuse"),
    docs_url: Some("https://developer.android.com/privacy-and-security/risks/android-debuggable"),
};

const TARGET_SDK_META: CheckMeta = CheckMeta {
    id: "ANDROID-BIN-003",
    title: "Compiled targetSdk below Google Play minimum",
    platform: Platform::Android,
    category: Category::Binary,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("Play: Target API level"),
    docs_url: Some("https://developer.android.com/google/play/requirements/target-sdk"),
};

const CLEARTEXT_META: CheckMeta = CheckMeta {
    id: "ANDROID-BIN-004",
    title: "Compiled manifest permits cleartext traffic",
    platform: Platform::Android,
    category: Category::Binary,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: Some("Play: User Data"),
    docs_url: Some(
        "https://developer.android.com/privacy-and-security/risks/cleartext-communications",
    ),
};

fn extract(path: &Path) -> Result<BinarySnapshot, BinaryError> {
    let file = std::fs::File::open(path).map_err(BinaryError::Io)?;
    let mut archive = ZipArchive::new(file).map_err(|e| BinaryError::Zip(e.to_string()))?;

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

    // Decode the compiled manifest, best-effort.
    let manifest = read_entry(&mut archive, "AndroidManifest.xml")
        .ok()
        .and_then(|bytes| manifest::decode(&bytes));

    Ok(BinarySnapshot { abis, manifest })
}

fn read_entry(archive: &mut ZipArchive<std::fs::File>, name: &str) -> Result<Vec<u8>, BinaryError> {
    use std::io::Read;
    let mut entry = archive
        .by_name(name)
        .map_err(|e| BinaryError::Zip(e.to_string()))?;
    let mut buf = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut buf).map_err(BinaryError::Io)?;
    Ok(buf)
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
