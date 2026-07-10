//! Google Play store-listing checks.
//!
//! Each runs against a [`PlayListingSnapshot`] — the already-fetched listing —
//! so it never touches the network and is unit-testable with a hand-built
//! snapshot. Add a check by adding a struct here and registering it.

use super::model::PlayListingSnapshot;
use preflight_core::{Category, CheckMeta, Confidence, Finding, Platform, Severity};

pub trait MetadataCheck: Sync {
    fn meta(&self) -> CheckMeta;
    fn run(&self, snap: &PlayListingSnapshot) -> Vec<Finding>;
}

pub fn registry() -> Vec<Box<dyn MetadataCheck>> {
    vec![
        Box::new(FullDescription),
        Box::new(TitleAndShortDescription),
        Box::new(PhoneScreenshots),
        Box::new(FeatureGraphic),
        Box::new(AppIcon),
        Box::new(ContactDetails),
    ]
}

pub fn all_meta() -> Vec<CheckMeta> {
    registry().iter().map(|c| c.meta()).collect()
}

// Google Play field limits.
const TITLE_LIMIT: usize = 30;
const SHORT_DESC_LIMIT: usize = 80;
const FULL_DESC_MIN: usize = 30;
const FULL_DESC_MAX: usize = 4000;
/// Play requires at least this many phone screenshots to publish.
const MIN_PHONE_SCREENSHOTS: usize = 2;

fn char_len(s: &str) -> usize {
    s.chars().count()
}

// ---------------------------------------------------------------------------

/// ANDROID-META-001 — Full description present and not trivially short.
struct FullDescription;

const FULL_DESCRIPTION_META: CheckMeta = CheckMeta {
    id: "ANDROID-META-001",
    title: "Missing or too-short full description",
    platform: Platform::Android,
    category: Category::Metadata,
    default_severity: Severity::Warning,
    confidence: Confidence::Medium,
    guideline: Some("Play: Store listing"),
    docs_url: Some("https://support.google.com/googleplay/android-developer/answer/9866151"),
};

impl MetadataCheck for FullDescription {
    fn meta(&self) -> CheckMeta {
        FULL_DESCRIPTION_META
    }
    fn run(&self, snap: &PlayListingSnapshot) -> Vec<Finding> {
        let mut findings = Vec::new();
        for l in &snap.listings {
            let desc = l.full_description.as_deref().unwrap_or("").trim();
            if desc.is_empty() {
                findings.push(
                    Finding::from_meta(
                        &FULL_DESCRIPTION_META,
                        format!("Full description is empty for language `{}`.", l.language),
                    )
                    .severity(Severity::Error),
                );
            } else if char_len(desc) < FULL_DESC_MIN {
                findings.push(Finding::from_meta(
                    &FULL_DESCRIPTION_META,
                    format!(
                        "Full description for `{}` is very short ({} chars).",
                        l.language,
                        char_len(desc)
                    ),
                ));
            } else if char_len(desc) > FULL_DESC_MAX {
                findings.push(Finding::from_meta(
                    &FULL_DESCRIPTION_META,
                    format!(
                        "Full description for `{}` is {} chars (Play limit {FULL_DESC_MAX}).",
                        l.language,
                        char_len(desc)
                    ),
                ));
            }
        }
        findings
    }
}

// ---------------------------------------------------------------------------

/// ANDROID-META-002 — Title (≤30) and short description (≤80) present and within limits.
struct TitleAndShortDescription;

const TITLE_META: CheckMeta = CheckMeta {
    id: "ANDROID-META-002",
    title: "Title or short description missing / over limit",
    platform: Platform::Android,
    category: Category::Metadata,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: Some("Play: Store listing"),
    docs_url: Some("https://support.google.com/googleplay/android-developer/answer/9866151"),
};

impl MetadataCheck for TitleAndShortDescription {
    fn meta(&self) -> CheckMeta {
        TITLE_META
    }
    fn run(&self, snap: &PlayListingSnapshot) -> Vec<Finding> {
        let mut findings = Vec::new();
        for l in &snap.listings {
            let title = l.title.as_deref().unwrap_or("").trim();
            if title.is_empty() {
                findings.push(
                    Finding::from_meta(
                        &TITLE_META,
                        format!("Title is empty for language `{}`.", l.language),
                    )
                    .severity(Severity::Error),
                );
            } else if char_len(title) > TITLE_LIMIT {
                findings.push(Finding::from_meta(
                    &TITLE_META,
                    format!(
                        "Title for `{}` is {} chars (limit {TITLE_LIMIT}).",
                        l.language,
                        char_len(title)
                    ),
                ));
            }

            if let Some(short) = &l.short_description {
                if char_len(short.trim()) > SHORT_DESC_LIMIT {
                    findings.push(Finding::from_meta(
                        &TITLE_META,
                        format!(
                            "Short description for `{}` is {} chars (limit {SHORT_DESC_LIMIT}).",
                            l.language,
                            char_len(short.trim())
                        ),
                    ));
                }
            }
        }
        findings
    }
}

// ---------------------------------------------------------------------------

/// ANDROID-META-003 — At least two phone screenshots are required to publish.
struct PhoneScreenshots;

const SCREENSHOTS_META: CheckMeta = CheckMeta {
    id: "ANDROID-META-003",
    title: "Fewer than two phone screenshots",
    platform: Platform::Android,
    category: Category::Metadata,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("Play: Store listing"),
    docs_url: Some("https://support.google.com/googleplay/android-developer/answer/9866151"),
};

impl MetadataCheck for PhoneScreenshots {
    fn meta(&self) -> CheckMeta {
        SCREENSHOTS_META
    }
    fn run(&self, snap: &PlayListingSnapshot) -> Vec<Finding> {
        let mut findings = Vec::new();
        for l in &snap.listings {
            if l.phone_screenshot_count < MIN_PHONE_SCREENSHOTS {
                findings.push(
                    Finding::from_meta(
                        &SCREENSHOTS_META,
                        format!(
                            "Language `{}` has {} phone screenshot(s); Play requires at least {MIN_PHONE_SCREENSHOTS}.",
                            l.language, l.phone_screenshot_count
                        ),
                    )
                    .remediation("Upload at least two phone screenshots per active language."),
                );
            }
        }
        findings
    }
}

// ---------------------------------------------------------------------------

/// ANDROID-META-004 — A feature graphic is required to publish.
struct FeatureGraphic;

const FEATURE_GRAPHIC_META: CheckMeta = CheckMeta {
    id: "ANDROID-META-004",
    title: "Missing feature graphic",
    platform: Platform::Android,
    category: Category::Metadata,
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("Play: Store listing"),
    docs_url: Some("https://support.google.com/googleplay/android-developer/answer/9866151"),
};

impl MetadataCheck for FeatureGraphic {
    fn meta(&self) -> CheckMeta {
        FEATURE_GRAPHIC_META
    }
    fn run(&self, snap: &PlayListingSnapshot) -> Vec<Finding> {
        snap.listings
            .iter()
            .filter(|l| !l.has_feature_graphic)
            .map(|l| {
                Finding::from_meta(
                    &FEATURE_GRAPHIC_META,
                    format!("No feature graphic uploaded for language `{}`.", l.language),
                )
                .remediation("Upload a 1024x500 feature graphic; it is required to publish.")
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------

/// ANDROID-META-005 — A high-res app icon is expected on the listing.
struct AppIcon;

const ICON_META: CheckMeta = CheckMeta {
    id: "ANDROID-META-005",
    title: "Missing high-res app icon on listing",
    platform: Platform::Android,
    category: Category::Metadata,
    // A 512x512 hi-res icon is a mandatory publish asset, like the feature
    // graphic (ANDROID-META-004) and screenshots (ANDROID-META-003).
    default_severity: Severity::Error,
    confidence: Confidence::High,
    guideline: Some("Play: Store listing"),
    docs_url: Some("https://support.google.com/googleplay/android-developer/answer/9866151"),
};

impl MetadataCheck for AppIcon {
    fn meta(&self) -> CheckMeta {
        ICON_META
    }
    fn run(&self, snap: &PlayListingSnapshot) -> Vec<Finding> {
        snap.listings
            .iter()
            .filter(|l| !l.has_icon)
            .map(|l| {
                Finding::from_meta(
                    &ICON_META,
                    format!(
                        "No high-res icon set on the listing for language `{}`.",
                        l.language
                    ),
                )
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------

/// ANDROID-META-006 — Some contact channel must be provided.
struct ContactDetails;

const CONTACT_META: CheckMeta = CheckMeta {
    id: "ANDROID-META-006",
    title: "No contact details on the store listing",
    platform: Platform::Android,
    category: Category::Metadata,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: Some("Play: Store listing"),
    docs_url: Some("https://support.google.com/googleplay/android-developer/answer/9859455"),
};

impl MetadataCheck for ContactDetails {
    fn meta(&self) -> CheckMeta {
        CONTACT_META
    }
    fn run(&self, snap: &PlayListingSnapshot) -> Vec<Finding> {
        let has_contact = snap.contact_email.is_some()
            || snap.contact_website.is_some()
            || snap.contact_phone.is_some();
        if has_contact {
            return Vec::new();
        }
        vec![Finding::from_meta(
            &CONTACT_META,
            "No contact email, website, or phone is set on the store listing.",
        )
        .remediation("Add at least a contact email in Play Console > Store listing.")]
    }
}
