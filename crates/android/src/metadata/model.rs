//! The [`PlayListingSnapshot`] — a normalized, network-free view of a Play
//! store listing — and the code that assembles one via the Android Publisher
//! "edits" API. Checks only ever see the snapshot.

use super::client::PlayClient;
use super::MetadataError;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct PlayListingSnapshot {
    pub package_name: String,
    pub default_language: Option<String>,
    pub contact_email: Option<String>,
    pub contact_website: Option<String>,
    pub contact_phone: Option<String>,
    pub listings: Vec<PlayListing>,
}

#[derive(Debug, Clone, Default)]
pub struct PlayListing {
    pub language: String,
    pub title: Option<String>,
    pub short_description: Option<String>,
    pub full_description: Option<String>,
    pub phone_screenshot_count: usize,
    pub has_feature_graphic: bool,
    pub has_icon: bool,
}

/// Open a read-only edit, read the listing, then abandon the edit.
///
/// We never commit, so this makes no changes to the app. The edit is deleted at
/// the end (and best-effort on error paths) so nothing is left dangling.
pub fn fetch(
    client: &PlayClient,
    package_name: &str,
) -> Result<PlayListingSnapshot, MetadataError> {
    let edit = client.post_empty(&format!(
        "/androidpublisher/v3/applications/{package_name}/edits"
    ))?;
    let edit_id = edit["id"]
        .as_str()
        .ok_or_else(|| MetadataError::Unexpected("edit had no id".into()))?
        .to_string();

    let result = fetch_with_edit(client, package_name, &edit_id);

    // Always try to clean up the edit, regardless of how the read went.
    let _ = client.delete(&format!(
        "/androidpublisher/v3/applications/{package_name}/edits/{edit_id}"
    ));

    result
}

fn fetch_with_edit(
    client: &PlayClient,
    package_name: &str,
    edit_id: &str,
) -> Result<PlayListingSnapshot, MetadataError> {
    let base = format!("/androidpublisher/v3/applications/{package_name}/edits/{edit_id}");

    let mut snap = PlayListingSnapshot {
        package_name: package_name.to_string(),
        ..Default::default()
    };

    // Contact details / default language.
    if let Ok(details) = client.get(&format!("{base}/details")) {
        snap.default_language = str_field(&details, "defaultLanguage");
        snap.contact_email = str_field(&details, "contactEmail");
        snap.contact_website = str_field(&details, "contactWebsite");
        snap.contact_phone = str_field(&details, "contactPhone");
    }

    // Per-language listings.
    let listings = client.get(&format!("{base}/listings"))?;
    if let Some(items) = listings["listings"].as_array() {
        for item in items {
            let language = str_field(item, "language").unwrap_or_default();
            let (phones, feature, icon) = fetch_image_presence(client, &base, &language);
            snap.listings.push(PlayListing {
                title: str_field(item, "title"),
                short_description: str_field(item, "shortDescription"),
                full_description: str_field(item, "fullDescription"),
                phone_screenshot_count: phones,
                has_feature_graphic: feature,
                has_icon: icon,
                language,
            });
        }
    }

    Ok(snap)
}

/// Count phone screenshots and detect feature graphic / icon for a language.
fn fetch_image_presence(client: &PlayClient, base: &str, language: &str) -> (usize, bool, bool) {
    let count = |image_type: &str| -> usize {
        client
            .get(&format!("{base}/listings/{language}/{image_type}"))
            .ok()
            .and_then(|v| v["images"].as_array().map(|a| a.len()))
            .unwrap_or(0)
    };
    (
        count("phoneScreenshots"),
        count("featureGraphic") > 0,
        count("icon") > 0,
    )
}

/// Read a top-level string field, treating empty strings as absent.
fn str_field(node: &Value, key: &str) -> Option<String> {
    node[key]
        .as_str()
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}
