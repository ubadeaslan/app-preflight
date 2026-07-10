use preflight_core::Config;
use std::path::PathBuf;

fn sample() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/ios-sample")
}

fn ids(findings: &[preflight_core::Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.check_id.as_str()).collect()
}

#[test]
fn detects_known_issues_in_sample() {
    let config = Config::default();
    let findings = preflight_ios::analyze(&sample(), &config).expect("ios project detected");
    let ids = ids(&findings);

    // Empty camera purpose string + short location string.
    assert!(ids.contains(&"IOS-PRIVACY-002"));
    // No PrivacyInfo.xcprivacy.
    assert!(ids.contains(&"IOS-PRIVACY-001"));
    // No ITSAppUsesNonExemptEncryption.
    assert!(ids.contains(&"IOS-CONFIG-001"));
    // Placeholder bundle id / missing version.
    assert!(ids.contains(&"IOS-CONFIG-002"));
    // Sign-up without deletion path.
    assert!(ids.contains(&"IOS-LEGAL-001"));
    // App Transport Security disabled in Info.plist.
    assert!(ids.contains(&"IOS-CONFIG-003"));
    // Social login without Sign in with Apple.
    assert!(ids.contains(&"IOS-LEGAL-002"));
    // Legacy Always location key without the combined key.
    assert!(ids.contains(&"IOS-CONFIG-004"));
    // Entitlements: development push env + debuggable get-task-allow.
    assert!(ids.contains(&"IOS-CONFIG-005"));
    assert!(ids.contains(&"IOS-CONFIG-006"));
    // Insecure ATS exception domain.
    assert!(ids.contains(&"IOS-CONFIG-007"));
}

#[test]
fn background_location_without_any_always_key_is_flagged() {
    // A project that requests background location but sets no location usage
    // key at all triggers IOS-PRIVACY-004 (and not the legacy-key IOS-CONFIG-004).
    let dir = std::env::temp_dir().join(format!("preflight_bgloc_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join("Info.plist"),
        r#"<?xml version="1.0"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.acme.app</string>
<key>UIBackgroundModes</key><array><string>location</string></array>
</dict></plist>"#,
    )
    .unwrap();

    let findings = preflight_ios::analyze(&dir, &Config::default()).expect("ios project");
    let ids = ids(&findings);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(ids.contains(&"IOS-PRIVACY-004"));
    assert!(!ids.contains(&"IOS-CONFIG-004"));
}

#[test]
fn malformed_info_plist_does_not_panic() {
    let dir = std::env::temp_dir().join(format!("preflight_badplist_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(dir.join("Info.plist"), b"<<< not a plist >>>").unwrap();
    // It's still detected as an iOS project (Info.plist present); checks that read
    // the plist must simply find nothing rather than panic.
    let result = preflight_ios::analyze(&dir, &Config::default());
    let _ = std::fs::remove_dir_all(&dir);
    assert!(result.is_some());
}

#[test]
fn returns_none_for_non_ios_dir() {
    // The Android sample has Gradle files but no iOS markers.
    let android = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/android-sample");
    assert!(preflight_ios::analyze(&android, &Config::default()).is_none());
}

#[test]
fn empty_purpose_string_is_error() {
    let config = Config::default();
    let findings = preflight_ios::analyze(&sample(), &config).unwrap();
    let camera = findings
        .iter()
        .find(|f| f.message.contains("NSCameraUsageDescription"))
        .expect("camera finding present");
    assert_eq!(camera.severity, preflight_core::Severity::Error);
}
