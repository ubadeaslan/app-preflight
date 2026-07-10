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

    // The app target's own privacy manifest lives at the bundle root. A
    // framework-bundled `.xcprivacy` (SDKs ship their own) must NOT satisfy this
    // — that would mask a missing app-level manifest.
    let app_privacy = format!("{app_dir}PrivacyInfo.xcprivacy");
    let has_privacy_manifest = names.contains(&app_privacy);

    let mut snap = BinarySnapshot {
        app_name: app_base_name(&app_dir),
        has_privacy_manifest,
        ..Default::default()
    };

    // Read the bundle Info.plist once for the executable name and privacy keys.
    let info = read_entry(&mut archive, &format!("{app_dir}Info.plist"))
        .ok()
        .and_then(|bytes| plist::Value::from_reader(Cursor::new(bytes)).ok())
        .and_then(|v| v.into_dictionary());

    if let Some(dict) = &info {
        snap.has_tracking_usage_description = dict
            .get("NSUserTrackingUsageDescription")
            .and_then(|v| v.as_string())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        snap.ats_allows_arbitrary_loads = dict
            .get("NSAppTransportSecurity")
            .and_then(|v| v.as_dictionary())
            .and_then(|ats| ats.get("NSAllowsArbitraryLoads"))
            .and_then(|v| v.as_boolean())
            .unwrap_or(false);
    }

    let exec_name = info
        .as_ref()
        .and_then(|d| d.get("CFBundleExecutable")?.as_string().map(str::to_string))
        .unwrap_or_else(|| snap.app_name.clone());

    if let Ok(bytes) = read_entry(&mut archive, &format!("{app_dir}{exec_name}")) {
        scan_executable(&bytes, &mut snap);
    }

    // Inspect the embedded provisioning profile, if present.
    if let Ok(bytes) = read_entry(&mut archive, &format!("{app_dir}embedded.mobileprovision")) {
        parse_provisioning(&bytes, &mut snap);
    }

    Ok(snap)
}

/// A `.mobileprovision` is a CMS-signed blob wrapping an XML plist. Slice out the
/// plist by its `<?xml ... </plist>` markers and read the fields we care about.
fn parse_provisioning(bytes: &[u8], snap: &mut BinarySnapshot) {
    let Some(start) = memchr::memmem::find(bytes, b"<?xml") else {
        return;
    };
    // Search for the closing tag only after the opening one, so a stray
    // `</plist>` earlier in the CMS wrapper can't produce a reversed range.
    let Some(rel_end) = memchr::memmem::find(&bytes[start..], b"</plist>") else {
        return;
    };
    let end = start + rel_end + b"</plist>".len();
    let xml = &bytes[start..end.min(bytes.len())];
    let Some(dict) = plist::Value::from_reader(Cursor::new(xml))
        .ok()
        .and_then(|v| v.into_dictionary())
    else {
        return;
    };
    snap.provisioning_has_devices = dict
        .get("ProvisionedDevices")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    snap.provisioning_get_task_allow = dict
        .get("Entitlements")
        .and_then(|v| v.as_dictionary())
        .and_then(|e| e.get("get-task-allow"))
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);
}

fn scan_executable(bytes: &[u8], snap: &mut BinarySnapshot) {
    snap.uses_uiwebview = contains(bytes, b"UIWebView");
    snap.uses_idfa =
        contains(bytes, b"advertisingIdentifier") || contains(bytes, b"ASIdentifierManager");

    // Exact linked private frameworks, when the Mach-O parses as a thin binary.
    let mut parsed_thin = false;
    if let Ok(Mach::Binary(macho)) = Mach::parse(bytes) {
        parsed_thin = true;
        for lib in &macho.libs {
            if lib.contains("/PrivateFrameworks/") {
                snap.private_frameworks.push((*lib).to_string());
            }
        }
    }
    // String fallback for fat/unparseable binaries only. When goblin parsed the
    // thin binary and enumerated its libs, trust that — the literal path may just
    // be a logging/diagnostic constant, not actual linkage.
    if !parsed_thin && contains(bytes, PRIVATE_FRAMEWORKS_PATH.as_bytes()) {
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

/// Cap on how many bytes we read from a single archive entry, so a malicious or
/// corrupt IPA (e.g. a zip bomb reporting a huge size) can't exhaust memory.
const MAX_ENTRY_BYTES: u64 = 512 * 1024 * 1024;

fn read_entry(archive: &mut ZipArchive<std::fs::File>, name: &str) -> Result<Vec<u8>, BinaryError> {
    let entry = archive
        .by_name(name)
        .map_err(|e| BinaryError::Zip(e.to_string()))?;
    // Pre-allocate only a modest amount; the header size is attacker-controlled.
    // `.take` still bounds the actual read.
    let cap = entry.size().min(1 << 20);
    let mut buf = Vec::with_capacity(cap as usize);
    entry
        .take(MAX_ENTRY_BYTES)
        .read_to_end(&mut buf)
        .map_err(BinaryError::Io)?;
    Ok(buf)
}

/// True if `haystack` contains the byte sequence `needle` (fast, via memchr).
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    memchr::memmem::find(haystack, needle).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// Mach-O / fat magics, so `goblin` runs its parser against garbage.
    const MAGICS: &[[u8; 4]] = &[
        [0xCF, 0xFA, 0xED, 0xFE], // MH_MAGIC_64 (little-endian)
        [0xFE, 0xED, 0xFA, 0xCF],
        [0xCA, 0xFE, 0xBA, 0xBE], // FAT_MAGIC
    ];

    #[test]
    fn fuzz_scan_executable_never_panics() {
        let mut state = 0xDEAD_BEEF_CAFE_F00Du64;
        for _ in 0..3000 {
            let len = (xorshift(&mut state) % 8192) as usize;
            let mut buf: Vec<u8> = (0..len)
                .map(|_| (xorshift(&mut state) & 0xff) as u8)
                .collect();
            if len >= 4 {
                let magic = MAGICS[(xorshift(&mut state) as usize) % MAGICS.len()];
                buf[0..4].copy_from_slice(&magic);
            }
            let mut snap = BinarySnapshot::default();
            scan_executable(&buf, &mut snap); // must not panic
        }
    }
}
