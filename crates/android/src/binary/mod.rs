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
mod elf;
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
    /// 64-bit native libraries whose LOAD segments aren't 16 KB-aligned.
    pub unaligned_native_libs: Vec<String>,
}

/// ABIs that satisfy Google Play's 64-bit requirement.
const KNOWN_64BIT: &[&str] = &["arm64-v8a", "x86_64", "riscv64"];

impl BinarySnapshot {
    /// True when the APK ships native libraries but none for a 64-bit ABI. Any
    /// ABI not in [`KNOWN_64BIT`] (armeabi, armeabi-v7a, x86, mips, …) counts as
    /// 32-bit, so an armeabi-only APK is correctly flagged.
    fn missing_64bit(&self) -> bool {
        !self.abis.is_empty() && !self.abis.iter().any(|a| KNOWN_64BIT.contains(&a.as_str()))
    }
}

/// Analyze an `.apk` at `path`.
pub fn analyze(path: &Path) -> Result<Vec<Finding>, BinaryError> {
    let snapshot = extract(path)?;
    Ok(run_checks(&snapshot))
}

/// Analyze an `.aab` (Android App Bundle) at `path`.
///
/// A bundle is a ZIP with a `base/` (and feature-module) layout and a *protobuf*
/// manifest (not binary AXML). We cover the parts that are robust without a
/// protobuf schema: native ABIs, 16 KB alignment, DEX signals, and permissions
/// (their names are literal strings in the manifest). Manifest booleans/ints
/// (debuggable/targetSdk/cleartext/testOnly) are release-moot or better checked
/// from source, so they're left unset for bundles.
pub fn analyze_bundle(path: &Path) -> Result<Vec<Finding>, BinaryError> {
    let snapshot = extract_bundle(path)?;
    Ok(run_checks(&snapshot))
}

pub fn run_checks(snapshot: &BinarySnapshot) -> Vec<Finding> {
    let mut findings = Vec::new();

    // ANDROID-BIN-001 — 64-bit requirement.
    if snapshot.missing_64bit() {
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
        // ANDROID-BIN-007 — sensitive/restricted/special permissions in the
        // merged manifest (mirrors the source-scan permission checks so an
        // APK-only scan surfaces them too).
        for perm in &m.permissions {
            let name = perm.as_str();
            let (severity, note) = if crate::permissions::RESTRICTED.contains(&name) {
                (
                    Severity::Error,
                    "restricted permission — Play requires a Permissions Declaration and rejects most apps.".to_string(),
                )
            } else if let Some((_, n)) =
                crate::permissions::SPECIAL.iter().find(|(p, _)| *p == name)
            {
                (Severity::Warning, (*n).to_string())
            } else if crate::permissions::SENSITIVE.contains(&name) {
                (
                    Severity::Info,
                    "disclose in your Play Data Safety form and justify in the listing."
                        .to_string(),
                )
            } else {
                continue;
            };
            findings.push(
                Finding::from_meta(&PERMISSIONS_META, format!("Declares `{name}`. {note}"))
                    .severity(severity),
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

    // ANDROID-BIN-006 — 16 KB page-size alignment (required for API 35+ uploads
    // since 2025-11-01). Only gate when the target is unknown or >= 35.
    let target = snapshot.manifest.as_ref().and_then(|m| m.target_sdk);
    if !snapshot.unaligned_native_libs.is_empty() && target.map(|t| t >= 35).unwrap_or(true) {
        let mut shown = snapshot.unaligned_native_libs.clone();
        shown.sort();
        shown.truncate(5);
        findings.push(
            Finding::from_meta(
                &SIXTEEN_KB_META,
                format!(
                    "Native librar(ies) are not 16 KB-aligned: {}. Since 2025-11-01 Google Play \
                     blocks uploads targeting API 35+ that don't support 16 KB page sizes.",
                    shown.join(", ")
                ),
            )
            .remediation(
                "Rebuild the native code with a 16 KB max-page-size linker flag (NDK r27+ / AGP \
                 8.5.1+) so LOAD segments align to 16384.",
            ),
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
        SIXTEEN_KB_META,
        PERMISSIONS_META,
    ]
}

const PERMISSIONS_META: CheckMeta = CheckMeta {
    id: "ANDROID-BIN-007",
    title: "Sensitive / restricted permission in the compiled manifest",
    platform: Platform::Android,
    category: Category::Privacy,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: Some("Play: Permissions declaration"),
    docs_url: Some("https://support.google.com/googleplay/android-developer/answer/9888170"),
};

const SIXTEEN_KB_META: CheckMeta = CheckMeta {
    id: "ANDROID-BIN-006",
    title: "Native libraries not 16 KB page-size aligned",
    platform: Platform::Android,
    category: Category::Binary,
    default_severity: Severity::Error,
    confidence: Confidence::Medium,
    guideline: Some("Play: 16 KB page size"),
    docs_url: Some("https://developer.android.com/guide/practices/page-sizes"),
};

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
    let mut native_libs_64 = Vec::new();
    for name in archive.file_names() {
        // Entries look like `lib/arm64-v8a/libfoo.so`.
        if let Some(rest) = name.strip_prefix("lib/") {
            if let Some((abi, _)) = rest.split_once('/') {
                if !abi.is_empty() {
                    abis.insert(abi.to_string());
                    if KNOWN_64BIT.contains(&abi) && name.ends_with(".so") {
                        native_libs_64.push(name.to_string());
                    }
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

    // Check 16 KB page-size alignment of each 64-bit native lib. Only the ELF
    // header + program headers are needed, so read a small prefix.
    let mut unaligned_native_libs = Vec::new();
    for name in &native_libs_64 {
        if let Ok(bytes) = read_entry_prefix(&mut archive, name, 256 * 1024) {
            if elf::is_16k_aligned(&bytes) == Some(false) {
                unaligned_native_libs.push(name.clone());
            }
        }
    }

    Ok(BinarySnapshot {
        abis,
        manifest,
        dex: dex_facts,
        unaligned_native_libs,
    })
}

/// Read at most `limit` bytes of an entry — enough for an ELF header + program
/// headers without pulling a whole multi-MB `.so` into memory.
fn read_entry_prefix(
    archive: &mut ZipArchive<std::fs::File>,
    name: &str,
    limit: u64,
) -> Result<Vec<u8>, BinaryError> {
    use std::io::Read;
    let entry = archive
        .by_name(name)
        .map_err(|e| BinaryError::Zip(e.to_string()))?;
    let cap = entry.size().min(limit);
    let mut buf = Vec::with_capacity(cap as usize);
    entry
        .take(limit)
        .read_to_end(&mut buf)
        .map_err(BinaryError::Io)?;
    Ok(buf)
}

/// `classes.dex`, `classes2.dex`, … at the archive root.
fn is_dex_name(name: &str) -> bool {
    name.starts_with("classes") && name.ends_with(".dex") && !name.contains('/')
}

/// Extract a [`BinarySnapshot`] from an `.aab` bundle. Native libs live at
/// `<module>/lib/<abi>/`, dex at `<module>/dex/`, and the manifest at
/// `<module>/manifest/AndroidManifest.xml` (protobuf).
fn extract_bundle(path: &Path) -> Result<BinarySnapshot, BinaryError> {
    let file = std::fs::File::open(path).map_err(BinaryError::Io)?;
    let mut archive = ZipArchive::new(file).map_err(|e| BinaryError::Zip(e.to_string()))?;

    let mut abis = BTreeSet::new();
    let mut dex_names = Vec::new();
    let mut native_libs_64 = Vec::new();
    let mut manifest_names = Vec::new();
    for name in archive.file_names() {
        if let Some(rest) = name.split_once("/lib/").map(|(_, r)| r) {
            if let Some((abi, _)) = rest.split_once('/') {
                if !abi.is_empty() {
                    abis.insert(abi.to_string());
                    if KNOWN_64BIT.contains(&abi) && name.ends_with(".so") {
                        native_libs_64.push(name.to_string());
                    }
                }
            }
        } else if name.contains("/dex/") && name.ends_with(".dex") {
            dex_names.push(name.to_string());
        } else if name.ends_with("/manifest/AndroidManifest.xml") {
            manifest_names.push(name.to_string());
        }
    }

    // Permissions from the protobuf manifest(s): permission names are stored as
    // literal UTF-8 strings, so a targeted scan is reliable without a schema.
    let mut permissions: Vec<String> = Vec::new();
    for name in &manifest_names {
        if let Ok(bytes) = read_entry(&mut archive, name) {
            for p in known_permissions() {
                if memchr::memmem::find(&bytes, p.as_bytes()).is_some() && !permissions.contains(&p)
                {
                    permissions.push(p);
                }
            }
        }
    }
    let manifest = Some(ManifestFacts {
        permissions,
        ..Default::default()
    });

    let mut dex_facts = DexFacts::default();
    for name in &dex_names {
        if let Ok(bytes) = read_entry(&mut archive, name) {
            dex::scan(&bytes, &mut dex_facts);
        }
    }

    let mut unaligned_native_libs = Vec::new();
    for name in &native_libs_64 {
        if let Ok(bytes) = read_entry_prefix(&mut archive, name, 256 * 1024) {
            if elf::is_16k_aligned(&bytes) == Some(false) {
                unaligned_native_libs.push(name.clone());
            }
        }
    }

    Ok(BinarySnapshot {
        abis,
        manifest,
        dex: dex_facts,
        unaligned_native_libs,
    })
}

/// All permission names we classify (restricted + special + sensitive).
fn known_permissions() -> Vec<String> {
    crate::permissions::RESTRICTED
        .iter()
        .copied()
        .chain(crate::permissions::SPECIAL.iter().map(|(p, _)| *p))
        .chain(crate::permissions::SENSITIVE.iter().copied())
        .map(str::to_string)
        .collect()
}

/// Cap on bytes read from one archive entry, to bound memory against a corrupt
/// or malicious APK (e.g. a zip bomb reporting a huge uncompressed size).
const MAX_ENTRY_BYTES: u64 = 512 * 1024 * 1024;

fn read_entry(archive: &mut ZipArchive<std::fs::File>, name: &str) -> Result<Vec<u8>, BinaryError> {
    use std::io::Read;
    let entry = archive
        .by_name(name)
        .map_err(|e| BinaryError::Zip(e.to_string()))?;
    // Pre-allocate only a modest amount; the header size is attacker-controlled,
    // so don't trust it for the initial capacity. `.take` still bounds the read.
    let cap = entry.size().min(1 << 20);
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
