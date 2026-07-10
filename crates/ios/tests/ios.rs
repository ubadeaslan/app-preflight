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
