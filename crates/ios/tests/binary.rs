//! End-to-end tests for the `.ipa` binary layer using crafted fake archives,
//! plus snapshot-level check tests.

use preflight_ios::binary::{run_checks, BinarySnapshot};
use std::io::Write;
use std::path::PathBuf;
use zip::write::SimpleFileOptions;

fn info_plist(exec: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>{exec}</string>
</dict></plist>"#
    )
}

/// Write a fake .ipa to a temp path with the given (name, bytes) entries.
fn write_ipa(tag: &str, entries: &[(&str, &[u8])]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("preflight_{tag}_{}.ipa", std::process::id()));
    let file = std::fs::File::create(&path).unwrap();
    let mut zw = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default();
    for (name, bytes) in entries {
        zw.start_file(*name, opts).unwrap();
        zw.write_all(bytes).unwrap();
    }
    zw.finish().unwrap();
    path
}

#[test]
fn flags_uiwebview_private_framework_endpoints_and_missing_manifest() {
    let exec = b"padding UIWebView more /System/Library/PrivateFrameworks/Foo.framework/Foo \
                 and http://localhost:8080 trailing";
    let path = write_ipa(
        "broken",
        &[
            ("Payload/Demo.app/Info.plist", info_plist("Demo").as_bytes()),
            ("Payload/Demo.app/Demo", exec),
        ],
    );

    let findings = preflight_ios::analyze_binary(&path).expect("analyzes");
    let ids: Vec<&str> = findings.iter().map(|f| f.check_id.as_str()).collect();
    let _ = std::fs::remove_file(&path);

    assert!(ids.contains(&"IOS-BIN-001"), "UIWebView not flagged");
    assert!(
        ids.contains(&"IOS-BIN-002"),
        "private framework not flagged"
    );
    assert!(ids.contains(&"IOS-BIN-003"), "debug endpoint not flagged");
    assert!(
        ids.contains(&"IOS-BIN-004"),
        "missing privacy manifest not flagged"
    );
}

#[test]
fn clean_ipa_with_privacy_manifest_produces_no_findings() {
    let exec = b"a perfectly ordinary binary with WKWebView and https://api.example.com";
    let path = write_ipa(
        "clean",
        &[
            ("Payload/Demo.app/Info.plist", info_plist("Demo").as_bytes()),
            ("Payload/Demo.app/Demo", exec),
            ("Payload/Demo.app/PrivacyInfo.xcprivacy", b"<plist/>"),
        ],
    );

    let findings = preflight_ios::analyze_binary(&path).expect("analyzes");
    let _ = std::fs::remove_file(&path);
    assert!(findings.is_empty(), "unexpected findings: {findings:?}");
}

#[test]
fn non_ipa_archive_errors() {
    let path = write_ipa("notipa", &[("random.txt", b"hello")]);
    let result = preflight_ios::analyze_binary(&path);
    let _ = std::fs::remove_file(&path);
    assert!(result.is_err());
}

#[test]
fn checks_run_on_a_snapshot() {
    let snap = BinarySnapshot {
        app_name: "Demo".into(),
        has_privacy_manifest: false,
        uses_uiwebview: true,
        private_frameworks: vec!["/System/Library/PrivateFrameworks/X.framework/X".into()],
        debug_endpoints: vec!["http://localhost".into()],
    };
    let ids: Vec<String> = run_checks(&snap).into_iter().map(|f| f.check_id).collect();
    assert_eq!(ids.len(), 4);
}
