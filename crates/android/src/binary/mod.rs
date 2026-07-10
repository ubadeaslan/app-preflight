//! Compiled `.apk` inspection.
//!
//! An APK is a ZIP. We read three things:
//! - the native ABIs under `lib/<abi>/` (Google Play's 64-bit requirement),
//! - the compiled `AndroidManifest.xml`, decoded from binary AXML into
//!   [`manifest::ManifestFacts`] (the merged, ground-truth manifest), and
//! - signals from `classes*.dex` ([`dex::DexFacts`]), parsed from the DEX string
//!   pool and type-id table.
//!
//! Extraction is separated from checks so the check logic is unit-testable on a
//! hand-built [`BinarySnapshot`].

mod dex;
mod manifest;

pub use dex::DexFacts;
pub use manifest::ManifestFacts;

use preflight_core::{Category, CheckMeta, Confidence, Finding, Platform, Severity};
use std::collections::BTreeSet;
use std::path::Path;
use zip::ZipArchive;

/// Play's minimum target API for new uploads (kept in sync with the source check).
/// API 35 (Android 15) has been the floor since 2025-08-31; bump to 36 after the
/// 2026 deadline.
const MIN_TARGET_SDK: u32 = 35;

/// A check-ready view of a compiled APK.
#[derive(Debug, Clone, Default)]
pub struct BinarySnapshot {
    /// Native ABIs present under `lib/<abi>/`.
    pub abis: BTreeSet<String>,
    /// Facts decoded from the compiled `AndroidManifest.xml`, if decodable.
    pub manifest: Option<ManifestFacts>,
    /// Byte-level signals from the app's `classes*.dex`.
    pub dex: DexFacts,
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
        // ANDROID-BIN-005 — testOnly in the shipped manifest.
        if m.test_only {
            findings.push(
                Finding::from_meta(
                    &TEST_ONLY_META,
                    "The compiled manifest sets android:testOnly=\"true\". Google Play refuses to \
                     install test-only APKs.",
                )
                .remediation("Remove android:testOnly for the release build."),
            );
        }
    }

    // ANDROID-DEX-001 — dynamic code loading.
    if snapshot.dex.dynamic_code_loading {
        findings.push(
            Finding::from_meta(
                &DYNAMIC_CODE_META,
                "The DEX references `DexClassLoader`, i.e. loading executable code at runtime. \
                 Google Play restricts downloading and executing code that isn't in the APK.",
            )
            .remediation(
                "Avoid loading external dex/code. If it's from a dependency, confirm it doesn't \
                 fetch executable code at runtime.",
            ),
        );
    }

    // ANDROID-DEX-002 — hard-coded secrets.
    if !snapshot.dex.secret_kinds.is_empty() {
        findings.push(
            Finding::from_meta(
                &SECRETS_META,
                format!(
                    "The DEX appears to contain hard-coded secret(s): {}. Embedded keys can be \
                     extracted from a shipped APK.",
                    snapshot.dex.secret_kinds.join(", ")
                ),
            )
            .remediation(
                "Move secrets out of the app (server-side), rotate any exposed keys, and restrict \
                 API keys by app signature/package.",
            ),
        );
    }

    // ANDROID-DEX-003 — restricted / non-SDK (hidden) API references.
    if !snapshot.dex.restricted_apis.is_empty() {
        let mut shown = snapshot.dex.restricted_apis.clone();
        shown.sort();
        shown.truncate(5);
        findings.push(
            Finding::from_meta(
                &RESTRICTED_API_META,
                format!(
                    "The DEX references restricted / non-SDK (hidden) API class(es): {}. Google \
                     restricts non-SDK interfaces; they can break across Android versions and \
                     draw policy attention.",
                    shown.join(", ")
                ),
            )
            .remediation("Replace hidden-API usage with public SDK APIs (or an official Jetpack)."),
        );
    }

    findings
}

pub fn all_check_meta() -> Vec<CheckMeta> {
    vec![
        SIXTYFOUR_BIT_META,
        DEBUGGABLE_META,
        TARGET_SDK_META,
        CLEARTEXT_META,
        DYNAMIC_CODE_META,
        SECRETS_META,
        RESTRICTED_API_META,
        TEST_ONLY_META,
    ]
}

const TEST_ONLY_META: CheckMeta = CheckMeta {
    id: "ANDROID-BIN-005",
    title: "Compiled manifest is marked testOnly",
    platform: Platform::Android,
    category: Category::Binary,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("Play: Upload requirements"),
    docs_url: Some(
        "https://developer.android.com/guide/topics/manifest/application-element#testOnly",
    ),
};

const DYNAMIC_CODE_META: CheckMeta = CheckMeta {
    id: "ANDROID-DEX-001",
    title: "Dynamic code loading (DexClassLoader)",
    platform: Platform::Android,
    category: Category::Binary,
    default_severity: Severity::Warning,
    confidence: Confidence::Medium,
    guideline: Some("Play: Device and Network Abuse"),
    docs_url: Some("https://support.google.com/googleplay/android-developer/answer/9888379"),
};

const SECRETS_META: CheckMeta = CheckMeta {
    id: "ANDROID-DEX-002",
    title: "Hard-coded secret in the compiled code",
    platform: Platform::Android,
    category: Category::Binary,
    default_severity: Severity::Warning,
    confidence: Confidence::Medium,
    guideline: None,
    docs_url: Some("https://developer.android.com/privacy-and-security/security-tips"),
};

const RESTRICTED_API_META: CheckMeta = CheckMeta {
    id: "ANDROID-DEX-003",
    title: "Restricted / non-SDK (hidden) API reference",
    platform: Platform::Android,
    category: Category::Binary,
    default_severity: Severity::Warning,
    confidence: Confidence::Low,
    guideline: Some("Play: non-SDK interface restrictions"),
    docs_url: Some(
        "https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces",
    ),
};

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
    let mut dex_names = Vec::new();
    for name in archive.file_names() {
        // Entries look like `lib/arm64-v8a/libfoo.so`.
        if let Some(rest) = name.strip_prefix("lib/") {
            if let Some((abi, _)) = rest.split_once('/') {
                if !abi.is_empty() {
                    abis.insert(abi.to_string());
                }
            }
        } else if is_dex_name(name) {
            dex_names.push(name.to_string());
        }
    }

    // Decode the compiled manifest, best-effort.
    let manifest = read_entry(&mut archive, "AndroidManifest.xml")
        .ok()
        .and_then(|bytes| manifest::decode(&bytes));

    // Byte-scan every classes*.dex.
    let mut dex_facts = DexFacts::default();
    for name in &dex_names {
        if let Ok(bytes) = read_entry(&mut archive, name) {
            dex::scan(&bytes, &mut dex_facts);
        }
    }

    Ok(BinarySnapshot {
        abis,
        manifest,
        dex: dex_facts,
    })
}

/// `classes.dex`, `classes2.dex`, … at the archive root.
fn is_dex_name(name: &str) -> bool {
    name.starts_with("classes") && name.ends_with(".dex") && !name.contains('/')
}

/// Cap on bytes read from one archive entry, to bound memory against a corrupt
/// or malicious APK (e.g. a zip bomb reporting a huge uncompressed size).
const MAX_ENTRY_BYTES: u64 = 512 * 1024 * 1024;

fn read_entry(archive: &mut ZipArchive<std::fs::File>, name: &str) -> Result<Vec<u8>, BinaryError> {
    use std::io::Read;
    let entry = archive
        .by_name(name)
        .map_err(|e| BinaryError::Zip(e.to_string()))?;
    let cap = entry.size().min(MAX_ENTRY_BYTES);
    let mut buf = Vec::with_capacity(cap as usize);
    entry
        .take(MAX_ENTRY_BYTES)
        .read_to_end(&mut buf)
        .map_err(BinaryError::Io)?;
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
