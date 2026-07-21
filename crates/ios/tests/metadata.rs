//! Tests for the App Store Connect metadata layer that need no live account:
//! the JWT is verified cryptographically against a throwaway P-256 key, and the
//! checks run against hand-built snapshots.

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use preflight_ios::metadata::auth::{make_token, AscCredentials};
use preflight_ios::metadata::{
    run_checks, FailedBuildUpload, Localization, MetadataSnapshot, ReviewDetail, SubscriptionInfo,
};
use serde::Deserialize;

const TEST_PRIVATE_KEY: &str = include_str!("fixtures/test_ec_private.pem");
const TEST_PUBLIC_KEY: &str = include_str!("fixtures/test_ec_public.pem");

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    exp: u64,
    iat: u64,
}

#[test]
fn signs_an_es256_token_verifiable_with_the_public_key() {
    let creds = AscCredentials {
        issuer_id: "issuer-123".into(),
        key_id: "KEY123".into(),
        private_key_pem: TEST_PRIVATE_KEY.into(),
        bundle_id: None,
    };

    let token = make_token(&creds).expect("token signs");

    // Header carries ES256 + the key id Apple uses to pick the verifying key.
    let header = decode_header(&token).expect("decodable header");
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(header.kid.as_deref(), Some("KEY123"));

    // Signature verifies against the matching public key, and claims are correct.
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["appstoreconnect-v1"]);
    validation.set_issuer(&["issuer-123"]);
    let data = decode::<Claims>(
        &token,
        &DecodingKey::from_ec_pem(TEST_PUBLIC_KEY.as_bytes()).unwrap(),
        &validation,
    )
    .expect("signature verifies");

    assert_eq!(data.claims.aud, "appstoreconnect-v1");
    assert_eq!(data.claims.iss, "issuer-123");
    assert_eq!(data.claims.exp - data.claims.iat, 15 * 60);
}

#[test]
fn tampered_token_fails_verification() {
    let creds = AscCredentials {
        issuer_id: "issuer-123".into(),
        key_id: "KEY123".into(),
        private_key_pem: TEST_PRIVATE_KEY.into(),
        bundle_id: None,
    };
    let token = make_token(&creds).unwrap();

    // Flip the final signature character; verification with the real key must fail.
    let mut chars: Vec<char> = token.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();

    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["appstoreconnect-v1"]);
    validation.set_issuer(&["issuer-123"]);
    let result = decode::<Claims>(
        &tampered,
        &DecodingKey::from_ec_pem(TEST_PUBLIC_KEY.as_bytes()).unwrap(),
        &validation,
    );
    assert!(result.is_err());
}

fn locale(support: Option<&str>, desc: &str, keywords: &str) -> Localization {
    Localization {
        locale: "en-US".into(),
        description: Some(desc.into()),
        keywords: Some(keywords.into()),
        support_url: support.map(str::to_string),
        marketing_url: None,
        whats_new: None,
    }
}

#[test]
fn flags_all_metadata_issues_in_a_broken_snapshot() {
    let snap = MetadataSnapshot {
        bundle_id: "com.example.myapp".into(),
        app_name: Some("MyApp".into()),
        privacy_policy_url: None, // IOS-META-001
        version_string: Some("1.0".into()),
        app_store_state: Some("PREPARE_FOR_SUBMISSION".into()),
        localizations: vec![locale(None, "short", &"a".repeat(120))], // 002, 004, 006
        screenshot_display_types: vec![],                             // IOS-META-005
        review_detail: Some(ReviewDetail {
            demo_account_required: true,
            demo_account_name: None, // IOS-META-003
            demo_account_password: None,
            ..Default::default()
        }),
        availability_configured: Some(false), // IOS-META-007
        manual_prices_present: Some(false),   // IOS-META-008
        review_detail_present: Some(true),    // present, contacts blank → IOS-META-009
        project_build_number: Some(4),
        max_uploaded_build_number: Some(7), // 4 <= 7 → IOS-META-011
        failed_build_upload: Some(FailedBuildUpload {
            version: Some("7".into()),
            messages: vec!["ITMS-90683: missing purpose string".into()],
        }), // IOS-META-010
        subscriptions: vec![
            SubscriptionInfo {
                name: "Premium Monthly".into(),
                state: Some("MISSING_METADATA".into()), // IOS-META-012
                price_count: Some(1),                   // IOS-META-013
                intro_offer_count: None,
            },
            SubscriptionInfo {
                name: "Premium Yearly".into(),
                state: Some("READY_TO_SUBMIT".into()),
                price_count: Some(175),
                intro_offer_count: Some(3), // 3 < 175 → IOS-META-014
            },
        ],
        age_rating_completed: Some(false), // IOS-META-015
        name_collisions: vec!["MyApp — Someone Else (com.other.myapp)".into()], // IOS-META-016
    };

    let ids: Vec<String> = run_checks(&snap).into_iter().map(|f| f.check_id).collect();
    for expected in [
        "IOS-META-001",
        "IOS-META-002",
        "IOS-META-003",
        "IOS-META-004",
        "IOS-META-005",
        "IOS-META-006",
        "IOS-META-007",
        "IOS-META-008",
        "IOS-META-009",
        "IOS-META-010",
        "IOS-META-011",
        "IOS-META-012",
        "IOS-META-013",
        "IOS-META-014",
        "IOS-META-015",
        "IOS-META-016",
    ] {
        assert!(ids.contains(&expected.to_string()), "missing {expected}");
    }
}

#[test]
fn clean_snapshot_produces_no_findings() {
    let snap = MetadataSnapshot {
        bundle_id: "com.example.myapp".into(),
        app_name: Some("MyApp".into()),
        privacy_policy_url: Some("https://example.com/privacy".into()),
        version_string: Some("1.0".into()),
        app_store_state: Some("READY_FOR_SALE".into()),
        localizations: vec![locale(
            Some("https://example.com/support"),
            "A genuinely descriptive app description that clears the length bar.",
            "productivity, notes",
        )],
        screenshot_display_types: vec!["APP_IPHONE_67".into()],
        review_detail: Some(ReviewDetail {
            demo_account_required: false,
            contact_first_name: Some("Ada".into()),
            contact_last_name: Some("Lovelace".into()),
            contact_email: Some("ada@example.com".into()),
            contact_phone: Some("+1 555 0100".into()),
            ..Default::default()
        }),
        availability_configured: Some(true),
        manual_prices_present: Some(true),
        review_detail_present: Some(true),
        project_build_number: Some(8),
        max_uploaded_build_number: Some(7), // 8 > 7 — next number is free
        failed_build_upload: None,
        subscriptions: vec![SubscriptionInfo {
            name: "Premium".into(),
            state: Some("READY_TO_SUBMIT".into()),
            price_count: Some(175),
            intro_offer_count: Some(175),
        }],
        age_rating_completed: Some(true),
        name_collisions: vec![],
    };

    assert!(run_checks(&snap).is_empty());
}

/// `review_detail_present == Some(false)` (definitively no review detail
/// resource) must fire IOS-META-009 even though `review_detail` is None.
#[test]
fn absent_review_detail_fires_contact_check() {
    let snap = MetadataSnapshot {
        bundle_id: "com.example.myapp".into(),
        review_detail_present: Some(false),
        ..Default::default()
    };
    let ids: Vec<String> = run_checks(&snap).into_iter().map(|f| f.check_id).collect();
    assert!(ids.contains(&"IOS-META-009".to_string()));
}

/// A subscription with no intro offers at all is fine (no trial is a valid
/// product decision) — IOS-META-014 only fires on PARTIAL coverage.
#[test]
fn zero_intro_offers_is_not_flagged() {
    let snap = MetadataSnapshot {
        bundle_id: "com.example.myapp".into(),
        subscriptions: vec![SubscriptionInfo {
            name: "Premium".into(),
            state: Some("READY_TO_SUBMIT".into()),
            price_count: Some(175),
            intro_offer_count: Some(0),
        }],
        ..Default::default()
    };
    let ids: Vec<String> = run_checks(&snap).into_iter().map(|f| f.check_id).collect();
    assert!(!ids.contains(&"IOS-META-014".to_string()));
}

/// `None` means "could not determine" for availability/pricing — the submit
/// blocker checks must stay silent rather than guess.
#[test]
fn undetermined_availability_and_pricing_produce_no_findings() {
    let snap = MetadataSnapshot {
        bundle_id: "com.example.myapp".into(),
        availability_configured: None,
        manual_prices_present: None,
        ..Default::default()
    };
    let ids: Vec<String> = run_checks(&snap).into_iter().map(|f| f.check_id).collect();
    assert!(!ids.contains(&"IOS-META-007".to_string()));
    assert!(!ids.contains(&"IOS-META-008".to_string()));
}
