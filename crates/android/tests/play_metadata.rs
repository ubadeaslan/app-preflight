//! Play metadata tests that need no live account: the RS256 assertion is
//! verified against a throwaway key, and checks run on hand-built snapshots.

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use preflight_android::metadata::auth::{build_assertion, ServiceAccount};
use preflight_android::metadata::{run_checks, PlayListing, PlayListingSnapshot};
use serde::Deserialize;

const TEST_PRIVATE_KEY: &str = include_str!("fixtures/test_rsa_private.pem");
const TEST_PUBLIC_KEY: &str = include_str!("fixtures/test_rsa_public.pem");

#[derive(Deserialize)]
struct Assertion {
    iss: String,
    scope: String,
    exp: u64,
    iat: u64,
}

fn service_account() -> ServiceAccount {
    ServiceAccount {
        client_email: "bot@example.iam.gserviceaccount.com".into(),
        private_key: TEST_PRIVATE_KEY.into(),
        token_uri: "https://oauth2.googleapis.com/token".into(),
        package_name: None,
    }
}

#[test]
fn builds_an_rs256_assertion_verifiable_with_the_public_key() {
    let sa = service_account();
    let assertion = build_assertion(&sa, 1_700_000_000).expect("assertion signs");

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["https://oauth2.googleapis.com/token"]);
    validation.set_issuer(&["bot@example.iam.gserviceaccount.com"]);
    // The fixed `now` above puts exp in the past; we're testing the signature,
    // not expiry.
    validation.validate_exp = false;
    let data = decode::<Assertion>(
        &assertion,
        &DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY.as_bytes()).unwrap(),
        &validation,
    )
    .expect("signature verifies");

    assert_eq!(
        data.claims.scope,
        "https://www.googleapis.com/auth/androidpublisher"
    );
    assert_eq!(data.claims.iss, "bot@example.iam.gserviceaccount.com");
    assert_eq!(data.claims.exp - data.claims.iat, 3600);
}

#[test]
fn service_account_parses_from_json() {
    let json = r#"{
        "client_email": "bot@example.iam.gserviceaccount.com",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
        "token_uri": "https://oauth2.googleapis.com/token"
    }"#;
    let sa: ServiceAccount = serde_json::from_str(json).expect("parses");
    assert_eq!(sa.client_email, "bot@example.iam.gserviceaccount.com");
    assert_eq!(sa.token_uri, "https://oauth2.googleapis.com/token");
}

fn listing(title: &str, full: &str, screenshots: usize, feature: bool, icon: bool) -> PlayListing {
    PlayListing {
        language: "en-US".into(),
        title: Some(title.into()),
        short_description: Some("A short description".into()),
        full_description: Some(full.into()),
        phone_screenshot_count: screenshots,
        has_feature_graphic: feature,
        has_icon: icon,
    }
}

#[test]
fn flags_all_play_metadata_issues_in_a_broken_snapshot() {
    let snap = PlayListingSnapshot {
        package_name: "com.example.myapp".into(),
        default_language: Some("en-US".into()),
        contact_email: None, // ANDROID-META-006
        contact_website: None,
        contact_phone: None,
        listings: vec![listing(
            "",    // empty title       -> ANDROID-META-002
            "",    // empty description -> ANDROID-META-001
            1,     // < 2 screenshots   -> ANDROID-META-003
            false, // no feature graphic -> ANDROID-META-004
            false, // no icon            -> ANDROID-META-005
        )],
    };

    let ids: Vec<String> = run_checks(&snap).into_iter().map(|f| f.check_id).collect();
    for expected in [
        "ANDROID-META-001",
        "ANDROID-META-002",
        "ANDROID-META-003",
        "ANDROID-META-004",
        "ANDROID-META-005",
        "ANDROID-META-006",
    ] {
        assert!(ids.contains(&expected.to_string()), "missing {expected}");
    }
}

#[test]
fn clean_snapshot_produces_no_findings() {
    let snap = PlayListingSnapshot {
        package_name: "com.example.myapp".into(),
        default_language: Some("en-US".into()),
        contact_email: Some("support@example.com".into()),
        contact_website: None,
        contact_phone: None,
        listings: vec![listing(
            "MyApp",
            "A genuinely useful description of the app that clears the length bar.",
            3,
            true,
            true,
        )],
    };

    assert!(run_checks(&snap).is_empty());
}
