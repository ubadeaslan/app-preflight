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

/// Info.plist that also disables App Transport Security globally.
fn info_plist_ats_disabled(exec: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>{exec}</string>
<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>
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
                 and http://localhost:8080 and advertisingIdentifier trailing";
    // A .mobileprovision is CMS-signed, but our extractor slices the embedded
    // XML plist; a plain XML plist with those markers is enough for the test.
    let profile = br#"garbage-cms-header <?xml version="1.0"?>
<plist version="1.0"><dict>
<key>Entitlements</key><dict><key>get-task-allow</key><true/></dict>
</dict></plist> garbage-cms-trailer"#;
    let path = write_ipa(
        "broken",
        &[
            (
                "Payload/Demo.app/Info.plist",
                info_plist_ats_disabled("Demo").as_bytes(),
            ),
            ("Payload/Demo.app/Demo", exec),
            ("Payload/Demo.app/embedded.mobileprovision", profile),
        ],
    );

    let findings = preflight_ios::analyze_binary(&path).expect("analyzes");
    let ids: Vec<&str> = findings.iter().map(|f| f.check_id.as_str()).collect();
    let _ = std::fs::remove_file(&path);

    for expected in [
        "IOS-BIN-001", // UIWebView
        "IOS-BIN-002", // private framework
        "IOS-BIN-003", // debug endpoint
        "IOS-BIN-004", // missing privacy manifest
        "IOS-BIN-005", // IDFA without ATT
        "IOS-BIN-006", // ATS disabled
        "IOS-BIN-007", // development provisioning profile (get-task-allow)
    ] {
        assert!(ids.contains(&expected), "{expected} not flagged");
    }
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
fn garbage_info_plist_does_not_panic() {
    // A bundle whose Info.plist isn't a plist at all must not panic; extraction
    // falls back to the app base name for the executable.
    let path = write_ipa(
        "garbageplist",
        &[
            ("Payload/Demo.app/Info.plist", b"this is not a plist"),
            ("Payload/Demo.app/Demo", b"UIWebView"),
        ],
    );
    let findings = preflight_ios::analyze_binary(&path).expect("no panic");
    let _ = std::fs::remove_file(&path);
    let ids: Vec<&str> = findings.iter().map(|f| f.check_id.as_str()).collect();
    assert!(ids.contains(&"IOS-BIN-001")); // still finds UIWebView in the exec
}

#[test]
fn corrupt_archive_errors_without_panicking() {
    let path = std::env::temp_dir().join(format!("preflight_corrupt_{}.ipa", std::process::id()));
    std::fs::write(&path, b"definitely not a zip file").unwrap();
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
        uses_idfa: true,
        has_tracking_usage_description: false,
        ats_allows_arbitrary_loads: true,
        provisioning_get_task_allow: true,
        provisioning_has_devices: false,
    };
    // All seven iOS binary checks should fire.
    let ids: Vec<String> = run_checks(&snap).into_iter().map(|f| f.check_id).collect();
    assert_eq!(ids.len(), 7);
}

#[test]
fn idfa_with_tracking_description_is_not_flagged() {
    let snap = BinarySnapshot {
        app_name: "Demo".into(),
        has_privacy_manifest: true,
        uses_idfa: true,
        has_tracking_usage_description: true,
        ..Default::default()
    };
    let ids: Vec<String> = run_checks(&snap).into_iter().map(|f| f.check_id).collect();
    assert!(!ids.contains(&"IOS-BIN-005".to_string()));
}
