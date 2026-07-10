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
    guideline: Some("2.3.7"),
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
            } else if desc.len() < 30 || PLACEHOLDERS.iter().any(|p| lower.contains(p)) {
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
        let has_iphone = snap
            .screenshot_display_types
            .iter()
            .any(|t| t.to_ascii_uppercase().contains("IPHONE"));
        if has_iphone {
            return Vec::new();
        }
        vec![Finding::from_meta(
            &SCREENSHOTS_META,
            "No iPhone screenshots were found on the current App Store version. \
             At least one iPhone display size is required to submit.",
        )
        .remediation(
            "Upload screenshots for a current iPhone display size (e.g. 6.7\") in App Store Connect.",
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

fn is_blank(value: &Option<String>) -> bool {
    value.as_deref().map(str::trim).unwrap_or("").is_empty()
}
