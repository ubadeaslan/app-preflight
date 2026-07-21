//! App Store Connect metadata checks.
//!
//! Each check runs against a [`MetadataSnapshot`] — the already-fetched view of
//! the app's store listing — so it never touches the network and is unit-testable
//! with a hand-built snapshot. Adding a metadata check means adding a struct here
//! and registering it in [`registry`].

use super::model::MetadataSnapshot;
use preflight_core::{Category, CheckMeta, Confidence, Finding, Platform, Severity};

pub trait MetadataCheck: Sync {
    fn meta(&self) -> CheckMeta;
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding>;
}

pub fn registry() -> Vec<Box<dyn MetadataCheck>> {
    vec![
        Box::new(PrivacyPolicyUrl),
        Box::new(SupportUrl),
        Box::new(DemoAccount),
        Box::new(DescriptionQuality),
        Box::new(IphoneScreenshots),
        Box::new(KeywordsLength),
        Box::new(AvailabilityConfigured),
        Box::new(ManualPricesPresent),
        Box::new(ReviewContactInfo),
        Box::new(BuildUploadFailed),
        Box::new(BuildNumberBurned),
        Box::new(SubscriptionMetadataComplete),
        Box::new(SubscriptionPriceCoverage),
        Box::new(IntroOfferCoverage),
        Box::new(AgeRatingCompleted),
    ]
}

pub fn all_meta() -> Vec<CheckMeta> {
    registry().iter().map(|c| c.meta()).collect()
}

const PLACEHOLDERS: &[&str] = &[
    "lorem ipsum",
    "todo",
    "tbd",
    "placeholder",
    "test test",
    "asdf",
];

// ---------------------------------------------------------------------------

/// IOS-META-001 — A privacy policy URL is required for every app.
struct PrivacyPolicyUrl;

const PRIVACY_POLICY_META: CheckMeta = CheckMeta {
    id: "IOS-META-001",
    title: "Missing privacy policy URL",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("5.1.1"),
    docs_url: Some("https://developer.apple.com/app-store/review/guidelines/#privacy"),
};

impl MetadataCheck for PrivacyPolicyUrl {
    fn meta(&self) -> CheckMeta {
        PRIVACY_POLICY_META
    }
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding> {
        if is_blank(&snap.privacy_policy_url) {
            vec![Finding::from_meta(
                &PRIVACY_POLICY_META,
                "No privacy policy URL is set on the App Store listing. Apple requires one for all apps.",
            )
            .remediation("Add a reachable privacy policy URL in App Store Connect > App Information.")]
        } else {
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------

/// IOS-META-002 — A support URL is required.
struct SupportUrl;

const SUPPORT_URL_META: CheckMeta = CheckMeta {
    id: "IOS-META-002",
    title: "Missing support URL",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("1.5"),
    docs_url: Some("https://developer.apple.com/app-store/review/guidelines/#safety"),
};

impl MetadataCheck for SupportUrl {
    fn meta(&self) -> CheckMeta {
        SUPPORT_URL_META
    }
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding> {
        // Required per localization; flag any locale that is missing it.
        let mut findings = Vec::new();
        for loc in &snap.localizations {
            if is_blank(&loc.support_url) {
                findings.push(
                    Finding::from_meta(
                        &SUPPORT_URL_META,
                        format!("No support URL set for locale `{}`.", loc.locale),
                    )
                    .remediation("Add a support URL for each localization in App Store Connect."),
                );
            }
        }
        findings
    }
}

// ---------------------------------------------------------------------------

/// IOS-META-003 — If the app needs a login to review, a working demo account
/// must be provided. Missing credentials is one of the most common 2.1
/// rejections.
struct DemoAccount;

const DEMO_ACCOUNT_META: CheckMeta = CheckMeta {
    id: "IOS-META-003",
    title: "Demo account required but not provided",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("2.1"),
    docs_url: Some("https://developer.apple.com/app-store/review/guidelines/#app-completeness"),
};

impl MetadataCheck for DemoAccount {
    fn meta(&self) -> CheckMeta {
        DEMO_ACCOUNT_META
    }
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding> {
        let Some(review) = &snap.review_detail else {
            return Vec::new();
        };
        if review.demo_account_required
            && (is_blank(&review.demo_account_name) || is_blank(&review.demo_account_password))
        {
            vec![Finding::from_meta(
                &DEMO_ACCOUNT_META,
                "The review details mark a demo account as required, but the account name or password is empty. App Review will be unable to sign in and reject under Guideline 2.1.",
            )
            .remediation(
                "Fill in a working demo account (username + password) in App Store Connect > App Review Information.",
            )]
        } else {
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------

/// IOS-META-004 — Description present, meaningful, and not placeholder text.
struct DescriptionQuality;

const DESCRIPTION_META: CheckMeta = CheckMeta {
    id: "IOS-META-004",
    title: "Weak or missing app description",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Warning,
    confidence: Confidence::Medium,
    guideline: Some("2.3"),
    docs_url: Some("https://developer.apple.com/app-store/review/guidelines/#accurate-metadata"),
};

impl MetadataCheck for DescriptionQuality {
    fn meta(&self) -> CheckMeta {
        DESCRIPTION_META
    }
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding> {
        let mut findings = Vec::new();
        for loc in &snap.localizations {
            let desc = loc.description.as_deref().unwrap_or("").trim();
            let lower = desc.to_ascii_lowercase();
            if desc.is_empty() {
                findings.push(
                    Finding::from_meta(
                        &DESCRIPTION_META,
                        format!("Description is empty for locale `{}`.", loc.locale),
                    )
                    .severity(Severity::Error),
                );
            } else if desc.chars().count() < 30 || PLACEHOLDERS.iter().any(|p| lower.contains(p)) {
                findings.push(Finding::from_meta(
                    &DESCRIPTION_META,
                    format!(
                        "Description for locale `{}` looks too short or like placeholder text.",
                        loc.locale
                    ),
                ));
            }
        }
        findings
    }
}

// ---------------------------------------------------------------------------

/// IOS-META-005 — At least one iPhone screenshot set is required to submit.
struct IphoneScreenshots;

const SCREENSHOTS_META: CheckMeta = CheckMeta {
    id: "IOS-META-005",
    title: "No iPhone screenshots uploaded",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("2.3.3"),
    docs_url: Some(
        "https://developer.apple.com/help/app-store-connect/reference/screenshot-specifications/",
    ),
};

impl MetadataCheck for IphoneScreenshots {
    fn meta(&self) -> CheckMeta {
        SCREENSHOTS_META
    }
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding> {
        // No screenshots of any kind is a hard blocker. Screenshots present but
        // none for iPhone is only a problem if the app supports iPhone — which we
        // can't tell from this snapshot — so flag it as a softer warning (an
        // iPad-only app legitimately ships only iPad screenshots).
        if snap.screenshot_display_types.is_empty() {
            return vec![Finding::from_meta(
                &SCREENSHOTS_META,
                "No screenshots were found on the current App Store version. At least one \
                 screenshot for a supported device size is required to submit.",
            )
            .remediation(
                "Upload screenshots for your supported device sizes in App Store Connect.",
            )];
        }
        let has_iphone = snap
            .screenshot_display_types
            .iter()
            .any(|t| t.to_ascii_uppercase().contains("IPHONE"));
        if has_iphone {
            return Vec::new();
        }
        vec![Finding::from_meta(
            &SCREENSHOTS_META,
            "No iPhone screenshots were found (only non-iPhone sizes). If the app supports \
             iPhone, at least one iPhone display size is required.",
        )
        .severity(Severity::Warning)
        .remediation(
            "Upload iPhone screenshots (e.g. 6.7\") if the app supports iPhone; ignore this if it \
             is iPad-only.",
        )]
    }
}

// ---------------------------------------------------------------------------

/// IOS-META-006 — Keyword field has a 100-character limit; overflow is dropped
/// or rejected.
struct KeywordsLength;

const KEYWORDS_META: CheckMeta = CheckMeta {
    id: "IOS-META-006",
    title: "Keyword list exceeds 100 characters",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some("https://developer.apple.com/app-store/product-page/"),
};

const KEYWORDS_LIMIT: usize = 100;

impl MetadataCheck for KeywordsLength {
    fn meta(&self) -> CheckMeta {
        KEYWORDS_META
    }
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding> {
        let mut findings = Vec::new();
        for loc in &snap.localizations {
            if let Some(keywords) = &loc.keywords {
                let len = keywords.chars().count();
                if len > KEYWORDS_LIMIT {
                    findings.push(Finding::from_meta(
                        &KEYWORDS_META,
                        format!(
                            "Keywords for locale `{}` are {len} characters (limit {KEYWORDS_LIMIT}).",
                            loc.locale
                        ),
                    ));
                }
            }
        }
        findings
    }
}

// ---------------------------------------------------------------------------

/// IOS-META-007 — App availability (sale territories) never configured. An app
/// created through the ASC UI can reach submission with `appAvailabilityV2`
/// unset; the review submission then 409s. Subscription availability is a
/// separate resource and does NOT cover this.
struct AvailabilityConfigured;

const AVAILABILITY_META: CheckMeta = CheckMeta {
    id: "IOS-META-007",
    title: "App availability (territories) not configured",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some("https://developer.apple.com/documentation/appstoreconnectapi/app-availability"),
};

impl MetadataCheck for AvailabilityConfigured {
    fn meta(&self) -> CheckMeta {
        AVAILABILITY_META
    }
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding> {
        // Only fire on a definitive "never set" — `None` means undetermined.
        if snap.availability_configured == Some(false) {
            vec![Finding::from_meta(
                &AVAILABILITY_META,
                "App availability (sale territories) has never been configured for this app. \
                 Submitting for review will fail with a 409. Note this is separate from \
                 subscription availability — configuring one does not configure the other.",
            )
            .remediation(
                "Set the sale territories in App Store Connect > Pricing and Availability, or \
                 POST /v2/appAvailabilities with your territory list.",
            )]
        } else {
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------

/// IOS-META-008 — Price schedule has no manual prices. `GET .../appPriceSchedule`
/// answering 200 proves nothing (it can be an empty shell); only `manualPrices`
/// rows do. Submitting without them fails with `APP_PRICING_REQUIRED`.
struct ManualPricesPresent;

const MANUAL_PRICES_META: CheckMeta = CheckMeta {
    id: "IOS-META-008",
    title: "App price schedule is empty",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some(
        "https://developer.apple.com/documentation/appstoreconnectapi/app-price-schedules",
    ),
};

impl MetadataCheck for ManualPricesPresent {
    fn meta(&self) -> CheckMeta {
        MANUAL_PRICES_META
    }
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding> {
        if snap.manual_prices_present == Some(false) {
            vec![Finding::from_meta(
                &MANUAL_PRICES_META,
                "The app's price schedule contains no manual prices, so submitting for review \
                 will fail with APP_PRICING_REQUIRED. A 200 from the appPriceSchedule endpoint \
                 alone does not mean pricing is set.",
            )
            .remediation(
                "Set a price (0.00 for a free app is fine) in App Store Connect > Pricing and \
                 Availability, or POST /v1/appPriceSchedules with a base territory price point.",
            )]
        } else {
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------

/// IOS-META-009 — `appStoreReviewDetail` with contact name, phone and email is
/// required; its absence is a hidden submit blocker.
struct ReviewContactInfo;

const REVIEW_CONTACT_META: CheckMeta = CheckMeta {
    id: "IOS-META-009",
    title: "App Review contact information missing",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some(
        "https://developer.apple.com/help/app-store-connect/manage-submissions-to-app-review/",
    ),
};

impl MetadataCheck for ReviewContactInfo {
    fn meta(&self) -> CheckMeta {
        REVIEW_CONTACT_META
    }
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding> {
        if snap.review_detail_present == Some(false) {
            return vec![Finding::from_meta(
                &REVIEW_CONTACT_META,
                "No App Review information exists for this version at all (contact name, phone \
                 and email are required to submit).",
            )
            .remediation(
                "Fill in App Store Connect > App Review Information, or POST \
                 /v1/appStoreReviewDetails via the API.",
            )];
        }
        let Some(review) = &snap.review_detail else {
            return Vec::new(); // Undetermined — stay silent.
        };
        let mut missing = Vec::new();
        if is_blank(&review.contact_first_name) || is_blank(&review.contact_last_name) {
            missing.push("contact name");
        }
        if is_blank(&review.contact_phone) {
            missing.push("contact phone");
        }
        if is_blank(&review.contact_email) {
            missing.push("contact email");
        }
        if missing.is_empty() {
            Vec::new()
        } else {
            vec![Finding::from_meta(
                &REVIEW_CONTACT_META,
                format!(
                    "App Review information is missing: {}. Submission requires all of them.",
                    missing.join(", ")
                ),
            )
            .remediation("Complete App Store Connect > App Review Information.")]
        }
    }
}

// ---------------------------------------------------------------------------

/// IOS-META-010 — The latest build upload failed processing. `/v1/builds`
/// never lists such a build (it just "disappears") and the rejection email
/// arrives hours later; only `buildUploads.state.errors[]` has the reason.
struct BuildUploadFailed;

const BUILD_UPLOAD_META: CheckMeta = CheckMeta {
    id: "IOS-META-010",
    title: "Latest build upload failed processing",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some("https://developer.apple.com/documentation/appstoreconnectapi"),
};

impl MetadataCheck for BuildUploadFailed {
    fn meta(&self) -> CheckMeta {
        BUILD_UPLOAD_META
    }
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding> {
        let Some(failed) = &snap.failed_build_upload else {
            return Vec::new();
        };
        let version = failed.version.as_deref().unwrap_or("unknown");
        let reasons = if failed.messages.is_empty() {
            "no reason given".to_string()
        } else {
            failed.messages.join("; ")
        };
        vec![Finding::from_meta(
            &BUILD_UPLOAD_META,
            format!(
                "The most recent build upload (build {version}) was rejected during processing: \
                 {reasons}. It will never appear in the builds list."
            ),
        )
        .remediation(
            "Fix the listed issue (often a missing Info.plist purpose string, e.g. ITMS-90683) \
             and upload again with a NEW build number — the failed one is burned.",
        )]
    }
}

// ---------------------------------------------------------------------------

/// IOS-META-011 — The project's build number was already uploaded once
/// (including uploads rejected during processing) and cannot be reused.
struct BuildNumberBurned;

const BUILD_NUMBER_META: CheckMeta = CheckMeta {
    id: "IOS-META-011",
    title: "Build number already uploaded (burned)",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some("https://developer.apple.com/documentation/appstoreconnectapi"),
};

impl MetadataCheck for BuildNumberBurned {
    fn meta(&self) -> CheckMeta {
        BUILD_NUMBER_META
    }
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding> {
        let (Some(project), Some(max_uploaded)) =
            (snap.project_build_number, snap.max_uploaded_build_number)
        else {
            return Vec::new();
        };
        if project > max_uploaded {
            return Vec::new();
        }
        vec![Finding::from_meta(
            &BUILD_NUMBER_META,
            format!(
                "The project's CFBundleVersion is {project}, but build {max_uploaded} was \
                 already uploaded — numbers are burned even when processing rejected them."
            ),
        )
        .remediation(format!(
            "Bump the build number to at least {}.",
            max_uploaded + 1
        ))]
    }
}

// ---------------------------------------------------------------------------

/// IOS-META-012 — ASC's own subscription readiness verdict. A subscription in
/// `MISSING_METADATA` (localizations, review screenshot or prices incomplete)
/// blocks the first submission that carries it.
struct SubscriptionMetadataComplete;

const SUB_METADATA_META: CheckMeta = CheckMeta {
    id: "IOS-META-012",
    title: "Subscription metadata incomplete (MISSING_METADATA)",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("2.1"),
    docs_url: Some(
        "https://developer.apple.com/documentation/appstoreconnectapi/app-store/subscriptions",
    ),
};

impl MetadataCheck for SubscriptionMetadataComplete {
    fn meta(&self) -> CheckMeta {
        SUB_METADATA_META
    }
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding> {
        snap.subscriptions
            .iter()
            .filter(|s| s.state.as_deref() == Some("MISSING_METADATA"))
            .map(|s| {
                Finding::from_meta(
                    &SUB_METADATA_META,
                    format!(
                        "Subscription `{}` is in MISSING_METADATA — App Store Connect considers \
                         its localizations, review screenshot or prices incomplete.",
                        s.name
                    ),
                )
                .remediation(
                    "Complete every locale's display name + description (45 chars), upload the \
                     review screenshot, and make sure prices cover all sale territories; the \
                     state flips to READY_TO_SUBMIT by itself when everything is in place.",
                )
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------

/// IOS-META-013 — Subscription priced only in the base territory. Writing
/// `subscriptionPrices` covers ONE country; the other ~174 need equalization
/// POSTs, and availability must be set before prices (409 otherwise).
struct SubscriptionPriceCoverage;

const SUB_PRICE_META: CheckMeta = CheckMeta {
    id: "IOS-META-013",
    title: "Subscription priced in only one territory",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some(
        "https://developer.apple.com/documentation/appstoreconnectapi/app-store/subscriptions",
    ),
};

impl MetadataCheck for SubscriptionPriceCoverage {
    fn meta(&self) -> CheckMeta {
        SUB_PRICE_META
    }
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding> {
        snap.subscriptions
            .iter()
            .filter(|s| s.price_count == Some(1))
            .map(|s| {
                Finding::from_meta(
                    &SUB_PRICE_META,
                    format!(
                        "Subscription `{}` has a price in only one territory — the base-country \
                         price does not propagate to the other sale territories by itself.",
                        s.name
                    ),
                )
                .remediation(
                    "Fetch subscriptionPricePoints/{id}/equalizations and POST a price per \
                     territory (set availability BEFORE prices, or the POSTs 409).",
                )
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------

/// IOS-META-014 — Introductory offers are per-territory. Offers covering fewer
/// territories than the prices mean some countries see no trial.
struct IntroOfferCoverage;

const INTRO_OFFER_META: CheckMeta = CheckMeta {
    id: "IOS-META-014",
    title: "Introductory offer does not cover all priced territories",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Warning,
    confidence: Confidence::Medium,
    guideline: None,
    docs_url: Some(
        "https://developer.apple.com/documentation/appstoreconnectapi/app-store/subscriptions",
    ),
};

impl MetadataCheck for IntroOfferCoverage {
    fn meta(&self) -> CheckMeta {
        INTRO_OFFER_META
    }
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding> {
        snap.subscriptions
            .iter()
            .filter(|s| {
                matches!(
                    (s.intro_offer_count, s.price_count),
                    (Some(offers), Some(prices)) if offers > 0 && offers < prices
                )
            })
            .map(|s| {
                let offers = s.intro_offer_count.unwrap_or(0);
                let prices = s.price_count.unwrap_or(0);
                Finding::from_meta(
                    &INTRO_OFFER_META,
                    format!(
                        "Subscription `{}` has introductory offers in {offers} territories but \
                         prices in {prices} — offers are per-territory and do not propagate.",
                        s.name
                    ),
                )
                .remediation(
                    "POST the introductory offer for each remaining territory (the API answers \
                     409 \"must provide territory\" when the territory is omitted).",
                )
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------

/// IOS-META-015 — The age rating declaration (under `appInfos`, not the
/// version) has never been filled in; submission requires it.
struct AgeRatingCompleted;

const AGE_RATING_META: CheckMeta = CheckMeta {
    id: "IOS-META-015",
    title: "Age rating declaration not completed",
    platform: Platform::Ios,
    category: Category::Metadata,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some(
        "https://developer.apple.com/documentation/appstoreconnectapi/managing-age-rating-declarations",
    ),
};

impl MetadataCheck for AgeRatingCompleted {
    fn meta(&self) -> CheckMeta {
        AGE_RATING_META
    }
    fn run(&self, snap: &MetadataSnapshot) -> Vec<Finding> {
        if snap.age_rating_completed == Some(false) {
            vec![Finding::from_meta(
                &AGE_RATING_META,
                "The age rating declaration has never been filled in (all fields are null). It \
                 lives under appInfos — not the version — and submission requires it.",
            )
            .remediation(
                "Complete the age rating questionnaire in App Store Connect > App Information, \
                 or PATCH /v1/ageRatingDeclarations/{id}. Note some fields are booleans \
                 (healthOrWellnessTopics, ageAssurance) while most are NONE/INFREQUENT_OR_MILD \
                 enums; new required fields surface as 409s.",
            )]
        } else {
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------

fn is_blank(value: &Option<String>) -> bool {
    value.as_deref().map(str::trim).unwrap_or("").is_empty()
}
