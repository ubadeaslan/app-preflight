//! Pull a [`BinarySnapshot`] out of an `.ipa` archive.
//!
//! The string-based signals (UIWebView, debug endpoints, private-framework
//! paths) are found by scanning the raw executable bytes, so they work even when
//! the Mach-O can't be fully parsed. `goblin` is used opportunistically to list
//! the exact linked dylibs of a thin binary.

use super::{BinaryError, BinarySnapshot};
use goblin::mach::Mach;
use std::io::{Cursor, Read};
use std::path::Path;
use zip::ZipArchive;

/// Substrings that indicate a debug/staging endpoint left in a release build.
const DEBUG_NEEDLES: &[&str] = &[
    "http://localhost",
    "http://127.0.0.1",
    "://192.168.",
    "://10.0.",
    ".ngrok.io",
    "://staging.",
];

const PRIVATE_FRAMEWORKS_PATH: &str = "/System/Library/PrivateFrameworks/";

pub fn extract(path: &Path) -> Result<BinarySnapshot, BinaryError> {
    let file = std::fs::File::open(path).map_err(BinaryError::Io)?;
    let mut archive = ZipArchive::new(file).map_err(|e| BinaryError::Zip(e.to_string()))?;

    let names: Vec<String> = archive.file_names().map(str::to_string).collect();
    let app_dir = names
        .iter()
        .find_map(|n| app_dir_of(n))
        .ok_or(BinaryError::NotAnIpa)?;

    let has_privacy_manifest = names
        .iter()
        .any(|n| n.starts_with(&app_dir) && n.ends_with(".xcprivacy"));

    let mut snap = BinarySnapshot {
        app_name: app_base_name(&app_dir),
        has_privacy_manifest,
        ..Default::default()
    };

    // The executable name comes from Info.plist's CFBundleExecutable, falling
    // back to the app bundle's base name.
    let exec_name = read_entry(&mut archive, &format!("{app_dir}Info.plist"))
        .ok()
        .and_then(|bytes| plist::Value::from_reader(Cursor::new(bytes)).ok())
        .and_then(|v| v.into_dictionary())
        .and_then(|d| d.get("CFBundleExecutable")?.as_string().map(str::to_string))
        .unwrap_or_else(|| snap.app_name.clone());

    if let Ok(bytes) = read_entry(&mut archive, &format!("{app_dir}{exec_name}")) {
        scan_executable(&bytes, &mut snap);
    }

    Ok(snap)
}

fn scan_executable(bytes: &[u8], snap: &mut BinarySnapshot) {
    snap.uses_uiwebview = contains(bytes, b"UIWebView");

    // Exact linked private frameworks, when the Mach-O parses as a thin binary.
    if let Ok(Mach::Binary(macho)) = Mach::parse(bytes) {
        for lib in &macho.libs {
            if lib.contains("/PrivateFrameworks/") {
                snap.private_frameworks.push((*lib).to_string());
            }
        }
    }
    // Fallback signal that also covers fat/unparseable binaries.
    if snap.private_frameworks.is_empty() && contains(bytes, PRIVATE_FRAMEWORKS_PATH.as_bytes()) {
        snap.private_frameworks
            .push("(private framework reference in binary)".to_string());
    }

    for needle in DEBUG_NEEDLES {
        if contains(bytes, needle.as_bytes()) {
            snap.debug_endpoints.push((*needle).to_string());
        }
    }
}

/// If `name` is inside an app bundle, return the bundle directory prefix ending
/// in `.app/`, e.g. `Payload/Demo.app/Demo` → `Payload/Demo.app/`.
fn app_dir_of(name: &str) -> Option<String> {
    let marker = ".app/";
    let idx = name.find(marker)?;
    Some(name[..idx + marker.len()].to_string())
}

/// `Payload/Demo.app/` → `Demo`.
fn app_base_name(app_dir: &str) -> String {
    app_dir
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(app_dir)
        .trim_end_matches(".app")
        .to_string()
}

fn read_entry(archive: &mut ZipArchive<std::fs::File>, name: &str) -> Result<Vec<u8>, BinaryError> {
    let mut entry = archive
        .by_name(name)
        .map_err(|e| BinaryError::Zip(e.to_string()))?;
    let mut buf = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut buf).map_err(BinaryError::Io)?;
    Ok(buf)
}

/// True if `haystack` contains the byte sequence `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
