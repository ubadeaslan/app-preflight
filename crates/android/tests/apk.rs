//! Tests for the `.apk` binary layer using crafted fake archives.

use preflight_android::binary::{run_checks, BinarySnapshot, DexFacts, ManifestFacts};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use zip::write::SimpleFileOptions;

fn write_apk(tag: &str, entries: &[&str]) -> PathBuf {
    write_apk_with(
        tag,
        &entries
            .iter()
            .map(|n| (*n, "\x7fELF fake"))
            .collect::<Vec<_>>(),
    )
}

/// Write an APK with explicit per-entry contents.
fn write_apk_with(tag: &str, entries: &[(&str, &str)]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("preflight_{tag}_{}.apk", std::process::id()));
    let file = std::fs::File::create(&path).unwrap();
    let mut zw = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default();
    for (name, body) in entries {
        zw.start_file(*name, opts).unwrap();
        zw.write_all(body.as_bytes()).unwrap();
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
fn garbage_manifest_and_dex_do_not_panic() {
    // Non-AXML manifest and random DEX bytes must decode to nothing, not panic.
    let path = write_apk_with(
        "garbage",
        &[
            ("AndroidManifest.xml", "not binary axml"),
            ("classes.dex", "random bytes not a real dex"),
        ],
    );
    let findings = preflight_android::analyze_binary(&path).expect("no panic");
    let _ = std::fs::remove_file(&path);
    assert!(findings.is_empty());
}

#[test]
fn corrupt_archive_errors_without_panicking() {
    let path = std::env::temp_dir().join(format!("preflight_corrupt_{}.apk", std::process::id()));
    std::fs::write(&path, b"not a zip").unwrap();
    let result = preflight_android::analyze_binary(&path);
    let _ = std::fs::remove_file(&path);
    assert!(result.is_err());
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
fn dex_scan_flags_dynamic_code_loading_and_secrets() {
    let dex = "prefix Ldalvik/system/DexClassLoader; middle \
               AIzaSyA1234567890abcdefghijklmnopqrstuvw end";
    let path = write_apk_with(
        "dex",
        &[("classes.dex", dex), ("AndroidManifest.xml", "junk")],
    );
    let findings = preflight_android::analyze_binary(&path).expect("analyzes");
    let _ = std::fs::remove_file(&path);
    let ids: Vec<&str> = findings.iter().map(|f| f.check_id.as_str()).collect();
    assert!(ids.contains(&"ANDROID-DEX-001"), "dynamic code loading");
    assert!(ids.contains(&"ANDROID-DEX-002"), "hard-coded secret");
}

#[test]
fn dex_facts_drive_checks() {
    let snap = BinarySnapshot {
        abis: BTreeSet::new(),
        manifest: None,
        dex: DexFacts {
            dynamic_code_loading: true,
            secret_kinds: vec!["Google API key".into()],
        },
    };
    let ids: Vec<String> = run_checks(&snap).into_iter().map(|f| f.check_id).collect();
    assert!(ids.contains(&"ANDROID-DEX-001".to_string()));
    assert!(ids.contains(&"ANDROID-DEX-002".to_string()));
}

#[test]
fn snapshot_check_detects_32bit_only() {
    let snap = BinarySnapshot {
        abis: BTreeSet::from(["armeabi-v7a".to_string(), "x86".to_string()]),
        manifest: None,
        dex: DexFacts::default(),
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
        dex: DexFacts::default(),
    };
    let ids: Vec<String> = run_checks(&snap).into_iter().map(|f| f.check_id).collect();
    assert!(ids.contains(&"ANDROID-BIN-002".to_string()));
    assert!(ids.contains(&"ANDROID-BIN-003".to_string()));
    assert!(ids.contains(&"ANDROID-BIN-004".to_string()));
}
