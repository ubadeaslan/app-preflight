use preflight_core::{Config, Severity};
use std::path::PathBuf;

fn sample() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/android-sample")
}

#[test]
fn detects_known_issues_in_sample() {
    let findings = preflight_android::analyze(&sample(), &Config::default())
        .expect("android project detected");
    let ids: Vec<&str> = findings.iter().map(|f| f.check_id.as_str()).collect();

    assert!(ids.contains(&"ANDROID-CONFIG-001")); // debuggable
    assert!(ids.contains(&"ANDROID-CONFIG-002")); // targetSdk 30 < 34
    assert!(ids.contains(&"ANDROID-CONFIG-003")); // cleartext
    assert!(ids.contains(&"ANDROID-PRIVACY-001")); // READ_SMS + fine location
}

#[test]
fn debuggable_is_error() {
    let findings = preflight_android::analyze(&sample(), &Config::default()).unwrap();
    let debuggable = findings
        .iter()
        .find(|f| f.check_id == "ANDROID-CONFIG-001")
        .expect("debuggable finding");
    assert_eq!(debuggable.severity, Severity::Error);
}

#[test]
fn read_sms_is_flagged_above_info() {
    let findings = preflight_android::analyze(&sample(), &Config::default()).unwrap();
    let sms = findings
        .iter()
        .find(|f| f.message.contains("READ_SMS"))
        .expect("READ_SMS finding");
    assert!(sms.severity >= Severity::Warning);
}
