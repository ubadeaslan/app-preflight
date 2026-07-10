//! The [`MetadataSnapshot`] — a normalized, network-free view of an app's App
//! Store listing — and the code that assembles one from the App Store Connect
//! API. Checks only ever see the snapshot, never the raw API.

use super::client::AscClient;
use super::MetadataError;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct MetadataSnapshot {
    pub bundle_id: String,
    pub app_name: Option<String>,
    pub privacy_policy_url: Option<String>,
    pub version_string: Option<String>,
    pub app_store_state: Option<String>,
    pub localizations: Vec<Localization>,
    /// Screenshot display types present on the current version, e.g.
    /// `APP_IPHONE_67`, `APP_IPAD_PRO_129`.
    pub screenshot_display_types: Vec<String>,
    pub review_detail: Option<ReviewDetail>,
}

#[derive(Debug, Clone, Default)]
pub struct Localization {
    pub locale: String,
    pub description: Option<String>,
    pub keywords: Option<String>,
    pub support_url: Option<String>,
    pub marketing_url: Option<String>,
    pub whats_new: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ReviewDetail {
    pub demo_account_required: bool,
    pub demo_account_name: Option<String>,
    pub demo_account_password: Option<String>,
    pub contact_email: Option<String>,
    pub contact_phone: Option<String>,
}

/// Fetch and assemble a snapshot for `bundle_id`.
///
/// The app and its current version are required; optional pieces (privacy
/// policy, screenshots, review detail) are best-effort — a failure fetching one
/// leaves that part of the snapshot empty rather than failing the whole scan.
pub fn fetch(client: &AscClient, bundle_id: &str) -> Result<MetadataSnapshot, MetadataError> {
    let apps = client.get(&format!("/v1/apps?filter[bundleId]={bundle_id}&limit=1"))?;
    let app = apps["data"]
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| MetadataError::AppNotFound(bundle_id.to_string()))?;
    let app_id = app["id"]
        .as_str()
        .ok_or_else(|| MetadataError::Unexpected("app has no id".into()))?;

    let mut snap = MetadataSnapshot {
        bundle_id: bundle_id.to_string(),
        app_name: str_attr(app, "name"),
        ..Default::default()
    };

    // Propagate fetch errors rather than swallowing them — a failed fetch must
    // not be reported as "missing" by the checks (that would be a false Error).
    snap.privacy_policy_url = fetch_privacy_policy(client, app_id)?;

    // Current (most recent) iOS App Store version.
    let versions = client.get(&format!(
        "/v1/apps/{app_id}/appStoreVersions?filter[platform]=IOS&limit=1"
    ))?;
    let Some(version) = versions["data"].as_array().and_then(|a| a.first()) else {
        return Ok(snap); // App exists but has no version yet.
    };
    let version_id = version["id"].as_str().unwrap_or_default().to_string();
    snap.version_string = str_attr(version, "versionString");
    snap.app_store_state = str_attr(version, "appStoreState");

    let (localizations, localization_ids) = fetch_localizations(client, &version_id)?;
    snap.localizations = localizations;

    snap.screenshot_display_types = fetch_screenshot_types(client, &localization_ids)?;
    snap.review_detail = fetch_review_detail(client, &version_id).unwrap_or(None);

    Ok(snap)
}

fn fetch_privacy_policy(client: &AscClient, app_id: &str) -> Result<Option<String>, MetadataError> {
    let infos = client.get(&format!("/v1/apps/{app_id}/appInfos?limit=1"))?;
    let Some(info) = infos["data"].as_array().and_then(|a| a.first()) else {
        return Ok(None);
    };
    let info_id = info["id"].as_str().unwrap_or_default();
    let locs = client.get(&format!("/v1/appInfos/{info_id}/appInfoLocalizations"))?;
    let url = locs["data"]
        .as_array()
        .into_iter()
        .flatten()
        .find_map(|l| str_attr(l, "privacyPolicyUrl"));
    Ok(url)
}

fn fetch_localizations(
    client: &AscClient,
    version_id: &str,
) -> Result<(Vec<Localization>, Vec<String>), MetadataError> {
    let resp = client.get(&format!(
        "/v1/appStoreVersions/{version_id}/appStoreVersionLocalizations?limit=50"
    ))?;
    let mut localizations = Vec::new();
    let mut ids = Vec::new();
    if let Some(items) = resp["data"].as_array() {
        for item in items {
            if let Some(id) = item["id"].as_str() {
                ids.push(id.to_string());
            }
            localizations.push(Localization {
                locale: str_attr(item, "locale").unwrap_or_default(),
                description: str_attr(item, "description"),
                keywords: str_attr(item, "keywords"),
                support_url: str_attr(item, "supportUrl"),
                marketing_url: str_attr(item, "marketingUrl"),
                whats_new: str_attr(item, "whatsNew"),
            });
        }
    }
    Ok((localizations, ids))
}

fn fetch_screenshot_types(
    client: &AscClient,
    localization_ids: &[String],
) -> Result<Vec<String>, MetadataError> {
    let mut types = Vec::new();
    for id in localization_ids {
        // Propagate errors: a failed fetch must not look like "no screenshots".
        let resp = client.get(&format!(
            "/v1/appStoreVersionLocalizations/{id}/appScreenshotSets"
        ))?;
        if let Some(items) = resp["data"].as_array() {
            for item in items {
                if let Some(t) = str_attr(item, "screenshotDisplayType") {
                    if !types.contains(&t) {
                        types.push(t);
                    }
                }
            }
        }
    }
    Ok(types)
}

fn fetch_review_detail(
    client: &AscClient,
    version_id: &str,
) -> Result<Option<ReviewDetail>, MetadataError> {
    let resp = client.get(&format!(
        "/v1/appStoreVersions/{version_id}/appStoreReviewDetail"
    ))?;
    let data = &resp["data"];
    if data.is_null() {
        return Ok(None);
    }
    Ok(Some(ReviewDetail {
        demo_account_required: bool_attr(data, "demoAccountRequired").unwrap_or(false),
        demo_account_name: str_attr(data, "demoAccountName"),
        demo_account_password: str_attr(data, "demoAccountPassword"),
        contact_email: str_attr(data, "contactEmail"),
        contact_phone: str_attr(data, "contactPhone"),
    }))
}

/// Read a string `attributes.<key>`, treating empty strings as absent.
fn str_attr(node: &Value, key: &str) -> Option<String> {
    node["attributes"][key]
        .as_str()
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

fn bool_attr(node: &Value, key: &str) -> Option<bool> {
    node["attributes"][key].as_bool()
}
