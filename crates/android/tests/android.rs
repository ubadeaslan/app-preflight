use preflight_core::{Config, Severity};
use std::path::PathBuf;

fn sample() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/android-sample")
}

#[test]
fn malformed_manifest_does_not_panic() {
    let dir = std::env::temp_dir().join(format!("preflight_badmanifest_{}", std::process::id()));
    let main = dir.join("app/src/main");
    let _ = std::fs::create_dir_all(&main);
    std::fs::write(dir.join("build.gradle"), b"android {}").unwrap();
    std::fs::write(main.join("AndroidManifest.xml"), b"<<< not xml >>>").unwrap();
    let result = preflight_android::analyze(&dir, &Config::default());
    let _ = std::fs::remove_dir_all(&dir);
    // Detected as an Android project (has build.gradle); manifest-based checks
    // simply produce nothing rather than panic.
    assert!(result.is_some());
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
    assert!(ids.contains(&"ANDROID-CONFIG-004")); // FGS without foregroundServiceType
    assert!(ids.contains(&"ANDROID-CONFIG-005")); // activity intent-filter w/o exported
    assert!(ids.contains(&"ANDROID-PRIVACY-002")); // MANAGE_EXTERNAL_STORAGE
    assert!(ids.contains(&"ANDROID-CONFIG-006")); // NSC cleartextTrafficPermitted
    assert!(ids.contains(&"ANDROID-CONFIG-007")); // testOnly
    assert!(ids.contains(&"ANDROID-CONFIG-008")); // exported provider w/o permission
    assert!(ids.contains(&"ANDROID-PRIVACY-003")); // allowBackup without rules
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
