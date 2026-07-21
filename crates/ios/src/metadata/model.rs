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
    /// Whether app availability (sale territories, `appAvailabilityV2`) has ever
    /// been configured. `Some(false)` means the API definitively says "never set"
    /// (a first submission blocker); `None` means we couldn't determine it.
    pub availability_configured: Option<bool>,
    /// Whether the app's price schedule actually contains manual prices. A bare
    /// `GET .../appPriceSchedule` returning 200 can be an empty shell — only
    /// `manualPrices` rows prove pricing is set. Same `Some(false)`/`None`
    /// semantics as [`Self::availability_configured`].
    pub manual_prices_present: Option<bool>,
    /// Whether an `appStoreReviewDetail` resource exists at all. `Some(false)`
    /// (definitively absent) is a hidden submit blocker — contact name, phone
    /// and email are required. `None` = undetermined.
    pub review_detail_present: Option<bool>,
    /// The project's `CFBundleVersion` when it is a concrete number (supplied
    /// by the caller from the local project; `None` for build-setting
    /// variables like `$(FLUTTER_BUILD_NUMBER)`).
    pub project_build_number: Option<u64>,
    /// Highest build number ever uploaded (from `builds` + `buildUploads`,
    /// so numbers burned by processing rejections count too).
    pub max_uploaded_build_number: Option<u64>,
    /// Set when the LATEST build upload failed processing — `/v1/builds` never
    /// shows such a build; only `buildUploads` carries the rejection reason.
    pub failed_build_upload: Option<FailedBuildUpload>,
    /// One entry per in-app subscription across all subscription groups.
    pub subscriptions: Vec<SubscriptionInfo>,
    /// Whether the age rating declaration (under `appInfos`, not the version)
    /// has been filled in. `Some(false)` = all fields still null.
    pub age_rating_completed: Option<bool>,
    /// Other store apps whose name matches this app's name exactly
    /// (`"Name — Seller (bundle.id)"`), from the public iTunes Search API.
    /// Same-name apps in the same space are impersonation-flag material
    /// (TipsterHub was REMOVED over name + visuals matching a company).
    pub name_collisions: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct FailedBuildUpload {
    /// Build number of the failed upload, when the API exposes it.
    pub version: Option<String>,
    /// Error messages from `state.errors[]`.
    pub messages: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SubscriptionInfo {
    pub name: String,
    /// ASC's own readiness verdict, e.g. `MISSING_METADATA`, `READY_TO_SUBMIT`,
    /// `APPROVED`. ASC computes this from localizations + screenshot + prices,
    /// so it is the single most reliable "subscription metadata complete" signal.
    pub state: Option<String>,
    /// Number of territory price rows. 1 = only the base territory — the other
    /// ~174 need equalization POSTs before the sub leaves MISSING_METADATA.
    pub price_count: Option<usize>,
    /// Number of introductory-offer rows (they are per-territory too).
    pub intro_offer_count: Option<usize>,
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
    pub contact_first_name: Option<String>,
    pub contact_last_name: Option<String>,
    pub contact_email: Option<String>,
    pub contact_phone: Option<String>,
}

/// Fetch and assemble a snapshot for `bundle_id`.
///
/// `project_build_number` is the local project's concrete `CFBundleVersion`,
/// when known — used for the burned-build-number comparison.
///
/// Listing pieces propagate fetch errors (a failed fetch must not read as
/// "missing"); the advisory pieces (builds, subscriptions, age rating) are
/// best-effort and collapse to "undetermined" — their checks then stay silent.
pub fn fetch(
    client: &AscClient,
    bundle_id: &str,
    project_build_number: Option<u64>,
) -> Result<MetadataSnapshot, MetadataError> {
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
        project_build_number,
        ..Default::default()
    };

    // Propagate fetch errors rather than swallowing them — a failed fetch must
    // not be reported as "missing" by the checks (that would be a false Error).
    snap.privacy_policy_url = fetch_privacy_policy(client, app_id)?;
    snap.availability_configured = fetch_availability_configured(client, app_id)?;
    snap.manual_prices_present = fetch_manual_prices_present(client, app_id)?;

    // Advisory layers: best-effort. A failure leaves the field undetermined
    // (None / empty), which the corresponding checks treat as "stay silent".
    if let Ok((max_build, failed)) = fetch_build_uploads(client, app_id) {
        snap.max_uploaded_build_number = max_build;
        snap.failed_build_upload = failed;
    }
    snap.subscriptions = fetch_subscriptions(client, app_id).unwrap_or_default();
    snap.age_rating_completed = fetch_age_rating_completed(client, app_id).unwrap_or(None);
    if let Some(name) = snap.app_name.clone() {
        snap.name_collisions = fetch_name_collisions(bundle_id, &name);
    }

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
    let (present, detail) = fetch_review_detail(client, &version_id)?;
    snap.review_detail_present = Some(present);
    snap.review_detail = detail;

    Ok(snap)
}

/// `appAvailabilityV2` 404s (or comes back empty) when territories were never
/// configured — apps created through the ASC UI can reach submission with this
/// unset, and the submit then fails with a 409.
fn fetch_availability_configured(
    client: &AscClient,
    app_id: &str,
) -> Result<Option<bool>, MetadataError> {
    let resp = client.get_optional(&format!("/v1/apps/{app_id}/appAvailabilityV2"))?;
    Ok(Some(match resp {
        None => false,
        Some(v) => !v["data"].is_null(),
    }))
}

/// Only `manualPrices` rows prove the price schedule is real; the schedule
/// resource itself can exist as an empty shell (`APP_PRICING_REQUIRED` on
/// submit).
fn fetch_manual_prices_present(
    client: &AscClient,
    app_id: &str,
) -> Result<Option<bool>, MetadataError> {
    let resp = client.get_optional(&format!(
        "/v1/appPriceSchedules/{app_id}/manualPrices?limit=1"
    ))?;
    Ok(Some(match resp {
        None => false,
        Some(v) => v["data"].as_array().is_some_and(|a| !a.is_empty()),
    }))
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

/// Returns `(present, detail)`. A 404 or null data is a definitive "no review
/// detail resource" — a hidden submit blocker — while real errors propagate so
/// they are never mistaken for absence.
fn fetch_review_detail(
    client: &AscClient,
    version_id: &str,
) -> Result<(bool, Option<ReviewDetail>), MetadataError> {
    let Some(resp) = client.get_optional(&format!(
        "/v1/appStoreVersions/{version_id}/appStoreReviewDetail"
    ))?
    else {
        return Ok((false, None));
    };
    let data = &resp["data"];
    if data.is_null() {
        return Ok((false, None));
    }
    Ok((
        true,
        Some(ReviewDetail {
            demo_account_required: bool_attr(data, "demoAccountRequired").unwrap_or(false),
            demo_account_name: str_attr(data, "demoAccountName"),
            demo_account_password: str_attr(data, "demoAccountPassword"),
            contact_first_name: str_attr(data, "contactFirstName"),
            contact_last_name: str_attr(data, "contactLastName"),
            contact_email: str_attr(data, "contactEmail"),
            contact_phone: str_attr(data, "contactPhone"),
        }),
    ))
}

/// Scan `buildUploads` (which still lists processing-rejected builds that
/// `/v1/builds` hides) plus `/v1/builds?filter[app]` (the relationship path
/// 400s with sort — Nokturn lesson B27) for two facts: the highest build
/// number ever uploaded, and whether the LATEST upload failed processing.
#[allow(clippy::type_complexity)]
fn fetch_build_uploads(
    client: &AscClient,
    app_id: &str,
) -> Result<(Option<u64>, Option<FailedBuildUpload>), MetadataError> {
    let mut max_number: Option<u64> = None;
    let mut bump = |candidate: Option<u64>| {
        if let Some(n) = candidate {
            max_number = Some(max_number.map_or(n, |m| m.max(n)));
        }
    };

    // Latest-by-date failed upload tracking.
    let mut latest_date = String::new();
    let mut latest_failed: Option<FailedBuildUpload> = None;

    if let Some(uploads) = client.get_optional(&format!("/v1/apps/{app_id}/buildUploads"))? {
        for item in uploads["data"].as_array().into_iter().flatten() {
            let attrs = &item["attributes"];
            bump(parse_build_number(
                attrs["cfBundleVersion"]
                    .as_str()
                    .or_else(|| attrs["version"].as_str()),
            ));
            let date = attrs["uploadedDate"]
                .as_str()
                .or_else(|| attrs["createdDate"].as_str())
                .unwrap_or("");
            // ISO-8601 timestamps order correctly as strings.
            if date < latest_date.as_str() {
                continue;
            }
            let messages = collect_state_errors(attrs);
            latest_date = date.to_string();
            latest_failed = if messages.is_empty() {
                None
            } else {
                Some(FailedBuildUpload {
                    version: attrs["cfBundleVersion"]
                        .as_str()
                        .or_else(|| attrs["version"].as_str())
                        .map(str::to_string),
                    messages,
                })
            };
        }
    }

    if let Some(builds) =
        client.get_optional(&format!("/v1/builds?filter[app]={app_id}&limit=50"))?
    {
        for item in builds["data"].as_array().into_iter().flatten() {
            bump(parse_build_number(item["attributes"]["version"].as_str()));
        }
    }

    Ok((max_number, latest_failed))
}

/// Pull error messages out of a buildUpload's `state.errors[]`.
fn collect_state_errors(attrs: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for err in attrs["state"]["errors"].as_array().into_iter().flatten() {
        let msg = err["message"]
            .as_str()
            .or_else(|| err["description"].as_str())
            .or_else(|| err["detail"].as_str())
            .or_else(|| err.as_str());
        if let Some(m) = msg {
            out.push(m.to_string());
        } else if let Some(code) = err["code"].as_str() {
            out.push(code.to_string());
        }
    }
    out
}

/// A build number compares only when it is a plain integer (Flutter's
/// `1.0.0+N` style lands here as `N`); dotted values are skipped.
fn parse_build_number(value: Option<&str>) -> Option<u64> {
    value.and_then(|v| v.trim().parse::<u64>().ok())
}

/// Walk subscription groups → subscriptions, recording ASC's own readiness
/// state plus per-territory price/intro-offer coverage.
fn fetch_subscriptions(
    client: &AscClient,
    app_id: &str,
) -> Result<Vec<SubscriptionInfo>, MetadataError> {
    let mut subs = Vec::new();
    let Some(groups) =
        client.get_optional(&format!("/v1/apps/{app_id}/subscriptionGroups?limit=50"))?
    else {
        return Ok(subs);
    };
    for group in groups["data"].as_array().into_iter().flatten() {
        let Some(group_id) = group["id"].as_str() else {
            continue;
        };
        let Some(list) = client.get_optional(&format!(
            "/v1/subscriptionGroups/{group_id}/subscriptions?limit=50"
        ))?
        else {
            continue;
        };
        for sub in list["data"].as_array().into_iter().flatten() {
            let Some(sub_id) = sub["id"].as_str() else {
                continue;
            };
            let price_count = client
                .get_optional(&format!("/v1/subscriptions/{sub_id}/prices?limit=200"))
                .ok()
                .flatten()
                .and_then(|v| v["data"].as_array().map(Vec::len));
            let intro_offer_count = client
                .get_optional(&format!(
                    "/v1/subscriptions/{sub_id}/introductoryOffers?limit=200"
                ))
                .ok()
                .flatten()
                .and_then(|v| v["data"].as_array().map(Vec::len));
            subs.push(SubscriptionInfo {
                name: str_attr(sub, "name").unwrap_or_else(|| sub_id.to_string()),
                state: str_attr(sub, "state"),
                price_count,
                intro_offer_count,
            });
        }
    }
    Ok(subs)
}

/// The age rating declaration lives under `appInfos` (not the version). An
/// untouched declaration has every attribute null.
fn fetch_age_rating_completed(
    client: &AscClient,
    app_id: &str,
) -> Result<Option<bool>, MetadataError> {
    let Some(infos) = client.get_optional(&format!("/v1/apps/{app_id}/appInfos?limit=1"))? else {
        return Ok(None);
    };
    let Some(info_id) = infos["data"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|i| i["id"].as_str())
    else {
        return Ok(None);
    };
    let Some(decl) =
        client.get_optional(&format!("/v1/appInfos/{info_id}/ageRatingDeclaration"))?
    else {
        return Ok(Some(false));
    };
    let attrs = &decl["data"]["attributes"];
    let Some(map) = attrs.as_object() else {
        return Ok(Some(false));
    };
    Ok(Some(map.values().any(|v| !v.is_null())))
}

/// Ask the public iTunes Search API (no auth) whether another app already
/// carries exactly this name. Best-effort: any failure returns an empty list.
fn fetch_name_collisions(bundle_id: &str, app_name: &str) -> Vec<String> {
    let url = format!(
        "https://itunes.apple.com/search?term={}&entity=software&limit=25",
        percent_encode(app_name)
    );
    let Ok(resp) = ureq::get(&url).call() else {
        return Vec::new();
    };
    let Ok(json) = resp.into_json::<Value>() else {
        return Vec::new();
    };
    let target = app_name.trim().to_lowercase();
    let mut out = Vec::new();
    for result in json["results"].as_array().into_iter().flatten() {
        let name = result["trackName"].as_str().unwrap_or("");
        let bid = result["bundleId"].as_str().unwrap_or("");
        if bid.eq_ignore_ascii_case(bundle_id) {
            continue; // Our own listing.
        }
        if name.trim().to_lowercase() == target {
            let seller = result["sellerName"]
                .as_str()
                .or_else(|| result["artistName"].as_str())
                .unwrap_or("?");
            out.push(format!("{name} — {seller} ({bid})"));
        }
    }
    out
}

/// Minimal percent-encoding for a query value.
fn percent_encode(input: &str) -> String {
    let mut out = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
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
