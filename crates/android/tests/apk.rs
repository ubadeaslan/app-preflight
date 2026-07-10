//! Tests for the `.apk` binary layer using crafted fake archives.

use preflight_android::binary::{run_checks, BinarySnapshot, ManifestFacts};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use zip::write::SimpleFileOptions;

fn write_apk(tag: &str, entries: &[&str]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("preflight_{tag}_{}.apk", std::process::id()));
    let file = std::fs::File::create(&path).unwrap();
    let mut zw = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default();
    for name in entries {
        zw.start_file(*name, opts).unwrap();
        zw.write_all(b"\x7fELF fake").unwrap();
    }
    zw.finish().unwrap();
    path
}

#[test]
fn flags_missing_64bit_when_only_32bit_present() {
    let path = write_apk("only32", &["lib/armeabi-v7a/libnative.so", "classes.dex"]);
    let findings = preflight_android::analyze_binary(&path).expect("analyzes");
    let _ = std::fs::remove_file(&path);
    let ids: Vec<&str> = findings.iter().map(|f| f.check_id.as_str()).collect();
    assert!(ids.contains(&"ANDROID-BIN-001"));
}

#[test]
fn no_finding_when_64bit_present() {
    let path = write_apk(
        "with64",
        &["lib/armeabi-v7a/libnative.so", "lib/arm64-v8a/libnative.so"],
    );
    let findings = preflight_android::analyze_binary(&path).expect("analyzes");
    let _ = std::fs::remove_file(&path);
    assert!(findings.is_empty());
}

#[test]
fn no_native_libs_is_fine() {
    // Pure-Java/Kotlin apps have no lib/ entries and are unaffected.
    let path = write_apk("nolibs", &["classes.dex", "AndroidManifest.xml"]);
    let findings = preflight_android::analyze_binary(&path).expect("analyzes");
    let _ = std::fs::remove_file(&path);
    assert!(findings.is_empty());
}

#[test]
fn snapshot_check_detects_32bit_only() {
    let snap = BinarySnapshot {
        abis: BTreeSet::from(["armeabi-v7a".to_string(), "x86".to_string()]),
        manifest: None,
    };
    assert_eq!(run_checks(&snap).len(), 1);
}

#[test]
fn manifest_facts_drive_binary_checks() {
    let snap = BinarySnapshot {
        abis: BTreeSet::new(),
        manifest: Some(ManifestFacts {
            debuggable: true,             // ANDROID-BIN-002
            target_sdk: Some(30),         // ANDROID-BIN-003 (< 34)
            uses_cleartext_traffic: true, // ANDROID-BIN-004
            permissions: vec![],
        }),
    };
    let ids: Vec<String> = run_checks(&snap).into_iter().map(|f| f.check_id).collect();
    assert!(ids.contains(&"ANDROID-BIN-002".to_string()));
    assert!(ids.contains(&"ANDROID-BIN-003".to_string()));
    assert!(ids.contains(&"ANDROID-BIN-004".to_string()));
}
