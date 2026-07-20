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
    // Legacy calendar key without the iOS 17 full-access key.
    assert!(ids.contains(&"IOS-CONFIG-009"));
    // iCloud container in the Development environment.
    assert!(ids.contains(&"IOS-CONFIG-010"));
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
fn too_many_query_schemes_is_flagged() {
    let dir = std::env::temp_dir().join(format!("preflight_schemes_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let schemes: String = (0..51).map(|i| format!("<string>s{i}</string>")).collect();
    std::fs::write(
        dir.join("Info.plist"),
        format!(
            r#"<?xml version="1.0"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.acme.app</string>
<key>LSApplicationQueriesSchemes</key><array>{schemes}</array>
</dict></plist>"#
        ),
    )
    .unwrap();

    let findings = preflight_ios::analyze(&dir, &Config::default()).expect("ios project");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(ids(&findings).contains(&"IOS-CONFIG-008"));
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

#[test]
fn pbxproj_inconsistent_target_and_identity_pin_are_flagged() {
    let dir = std::env::temp_dir().join(format!("preflight_pbx_{}", std::process::id()));
    let proj = dir.join("Runner.xcodeproj");
    let _ = std::fs::create_dir_all(&proj);
    std::fs::write(
        dir.join("Info.plist"),
        r#"<?xml version="1.0"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.acme.app</string>
<key>CFBundleShortVersionString</key><string>1.0.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>ITSAppUsesNonExemptEncryption</key><false/>
</dict></plist>"#,
    )
    .unwrap();
    std::fs::write(
        proj.join("project.pbxproj"),
        r#"// !$*UTF8*$!
		IPHONEOS_DEPLOYMENT_TARGET = 13.0;
		"CODE_SIGN_IDENTITY[sdk=iphoneos*]" = "iPhone Developer";
		IPHONEOS_DEPLOYMENT_TARGET = 15.0;
		IPHONEOS_DEPLOYMENT_TARGET = 15.0;
"#,
    )
    .unwrap();

    let findings = preflight_ios::analyze(&dir, &Config::default()).expect("ios project");
    let ids = ids(&findings);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(ids.contains(&"IOS-CONFIG-011"), "ids: {ids:?}");
    assert!(ids.contains(&"IOS-CONFIG-012"), "ids: {ids:?}");
}

#[test]
fn consistent_pbxproj_produces_no_pbxproj_findings() {
    let dir = std::env::temp_dir().join(format!("preflight_pbxok_{}", std::process::id()));
    let proj = dir.join("Runner.xcodeproj");
    let _ = std::fs::create_dir_all(&proj);
    std::fs::write(
        dir.join("Info.plist"),
        r#"<?xml version="1.0"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.acme.app</string>
</dict></plist>"#,
    )
    .unwrap();
    std::fs::write(
        proj.join("project.pbxproj"),
        "\t\tIPHONEOS_DEPLOYMENT_TARGET = 15.0;\n\t\tIPHONEOS_DEPLOYMENT_TARGET = 15.0;\n",
    )
    .unwrap();

    let findings = preflight_ios::analyze(&dir, &Config::default()).expect("ios project");
    let ids = ids(&findings);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(!ids.contains(&"IOS-CONFIG-011"));
    assert!(!ids.contains(&"IOS-CONFIG-012"));
}

#[test]
fn fastlane_metadata_limits_and_keyword_subtitle_are_flagged() {
    let dir = std::env::temp_dir().join(format!("preflight_store_{}", std::process::id()));
    let ko = dir.join("ios/fastlane/metadata/ko");
    let en = dir.join("ios/fastlane/metadata/en-US");
    let _ = std::fs::create_dir_all(&ko);
    let _ = std::fs::create_dir_all(&en);
    std::fs::write(
        dir.join("Info.plist"),
        r#"<?xml version="1.0"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.acme.app</string>
</dict></plist>"#,
    )
    .unwrap();
    // ko: keyword-list subtitle (the Nokturn case) — also over 30 chars.
    std::fs::write(ko.join("subtitle.txt"), "dream, diary, sleep, ai art, comics, symbols").unwrap();
    // en-US: fine subtitle, oversized promotional text.
    std::fs::write(en.join("subtitle.txt"), "Your dreams, beautifully kept").unwrap();
    std::fs::write(en.join("promotional_text.txt"), "x".repeat(171)).unwrap();

    let findings = preflight_ios::analyze(&dir, &Config::default()).expect("ios project");
    let _ = std::fs::remove_dir_all(&dir);

    let store1: Vec<_> = findings
        .iter()
        .filter(|f| f.check_id == "IOS-STORE-001")
        .collect();
    let store2: Vec<_> = findings
        .iter()
        .filter(|f| f.check_id == "IOS-STORE-002")
        .collect();
    // ko subtitle over limit + en promotional over limit.
    assert_eq!(store1.len(), 2, "{store1:?}");
    // Only the ko subtitle is a keyword list.
    assert_eq!(store2.len(), 1, "{store2:?}");
    assert!(store2[0].message.contains("ko"));
}
