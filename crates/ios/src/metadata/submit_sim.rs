//! Submit simulation — using Apple's own submission validator for free.
//!
//! The App Store Connect submit flow is `POST /v1/reviewSubmissions` →
//! `POST /v1/reviewSubmissionItems` → `PATCH submitted:true`. When the item
//! POST is rejected, the 409 body's `meta.associatedErrors` lists *every*
//! missing prerequisite at once (availability, pricing, age rating, ...) —
//! far better than discovering them one submit at a time.
//!
//! This module performs only the first two steps, harvests the errors, and
//! rolls everything back (deletes the item if one was created, cancels the
//! draft submission). It MUTATES App Store Connect state, which is why it runs
//! as an explicit `preflight submit-sim` command and never as part of
//! `preflight check`.
//!
//! Safety rule: if any unfinished review submission already exists for the
//! app, the simulation refuses to run — it must never risk touching a real
//! submission that is waiting for or under review.

use super::client::{AscClient, PostFailure};
use super::{AscCredentials, MetadataError};
use serde_json::{json, Value};

/// What the simulation concluded. `cleanup_warning` is set when rollback of
/// the draft submission failed — harmless (an unsubmitted draft), but the user
/// should delete it in the ASC UI.
pub struct SubmitSimReport {
    pub outcome: SubmitSimOutcome,
    pub cleanup_warning: Option<String>,
}

pub enum SubmitSimOutcome {
    /// An unfinished review submission already exists; nothing was touched.
    InProgress { state: String },
    /// The app has no App Store version to attach yet.
    NoVersion,
    /// The item POST was accepted — nothing blocks a real submission.
    Clean,
    /// Apple rejected the item; these are the collected blockers.
    Blocked { errors: Vec<String> },
}

/// Review submission states that mean "finished, safe to ignore".
const FINISHED_STATES: &[&str] = &["COMPLETE", "CANCELED"];

pub fn run(creds: &AscCredentials, bundle_id: &str) -> Result<SubmitSimReport, MetadataError> {
    let client = AscClient::new(creds)?;

    // App id lookup (same shape as the metadata snapshot fetch).
    let apps = client.get(&format!("/v1/apps?filter[bundleId]={bundle_id}&limit=1"))?;
    let app_id = apps["data"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|app| app["id"].as_str())
        .ok_or_else(|| MetadataError::AppNotFound(bundle_id.to_string()))?
        .to_string();

    // SAFETY GUARD: refuse to run while any unfinished submission exists.
    let submissions = client.get(&format!(
        "/v1/apps/{app_id}/reviewSubmissions?filter[platform]=IOS&limit=25"
    ))?;
    if let Some(items) = submissions["data"].as_array() {
        for sub in items {
            let state = sub["attributes"]["state"].as_str().unwrap_or("");
            if !state.is_empty() && !FINISHED_STATES.contains(&state) {
                return Ok(SubmitSimReport {
                    outcome: SubmitSimOutcome::InProgress {
                        state: state.to_string(),
                    },
                    cleanup_warning: None,
                });
            }
        }
    }

    // Latest App Store version — the thing a real submit would attach.
    let versions = client.get(&format!(
        "/v1/apps/{app_id}/appStoreVersions?filter[platform]=IOS&limit=1"
    ))?;
    let Some(version_id) = versions["data"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v["id"].as_str())
        .map(str::to_string)
    else {
        return Ok(SubmitSimReport {
            outcome: SubmitSimOutcome::NoVersion,
            cleanup_warning: None,
        });
    };

    // Step 1: draft review submission.
    let submission = client
        .post(
            "/v1/reviewSubmissions",
            json!({
                "data": {
                    "type": "reviewSubmissions",
                    "attributes": { "platform": "IOS" },
                    "relationships": {
                        "app": { "data": { "type": "apps", "id": app_id } }
                    }
                }
            }),
        )
        .map_err(post_failure_to_error)?;
    let Some(submission_id) = submission["data"]["id"].as_str().map(str::to_string) else {
        return Err(MetadataError::Unexpected(
            "reviewSubmissions POST returned no id".into(),
        ));
    };

    // Step 2: try to attach the version. This is where ASC validates the whole
    // app and answers with meta.associatedErrors when something is missing.
    let item_result = client.post(
        "/v1/reviewSubmissionItems",
        json!({
            "data": {
                "type": "reviewSubmissionItems",
                "relationships": {
                    "reviewSubmission": {
                        "data": { "type": "reviewSubmissions", "id": submission_id }
                    },
                    "appStoreVersion": {
                        "data": { "type": "appStoreVersions", "id": version_id }
                    }
                }
            }
        }),
    );

    let (outcome, item_id) = match item_result {
        Ok(item) => (
            SubmitSimOutcome::Clean,
            item["data"]["id"].as_str().map(str::to_string),
        ),
        Err(PostFailure::Status { body, .. }) => (
            SubmitSimOutcome::Blocked {
                errors: collect_blockers(&body),
            },
            None,
        ),
        Err(PostFailure::Other(msg)) => {
            // Transport-level failure: still try to roll back the draft.
            let cleanup_warning = rollback(&client, None, &submission_id).err();
            return Ok(SubmitSimReport {
                outcome: SubmitSimOutcome::Blocked {
                    errors: vec![format!("request failed before ASC answered: {msg}")],
                },
                cleanup_warning,
            });
        }
    };

    let cleanup_warning = rollback(&client, item_id.as_deref(), &submission_id).err();
    Ok(SubmitSimReport {
        outcome,
        cleanup_warning,
    })
}

/// Delete the item (if one was created) and cancel the draft submission we
/// made. Returns a human-readable warning on failure instead of an error —
/// a leaked draft is annoying, not dangerous, and must not mask the outcome.
fn rollback(client: &AscClient, item_id: Option<&str>, submission_id: &str) -> Result<(), String> {
    let mut problems = Vec::new();
    if let Some(id) = item_id {
        if let Err(e) = client.delete(&format!("/v1/reviewSubmissionItems/{id}")) {
            problems.push(format!("could not delete simulation item {id}: {e}"));
        }
    }
    if let Err(e) = client.patch(
        &format!("/v1/reviewSubmissions/{submission_id}"),
        json!({
            "data": {
                "type": "reviewSubmissions",
                "id": submission_id,
                "attributes": { "canceled": true }
            }
        }),
    ) {
        problems.push(format!(
            "could not cancel draft submission {submission_id}: {e}. It is unsubmitted and \
             harmless, but delete it in App Store Connect to keep things tidy."
        ));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

/// Flatten the useful content of an ASC error body: every entry under each
/// error's `meta.associatedErrors` (keyed by the offending resource URL), and
/// the error's own detail/title as fallback.
pub fn collect_blockers(body: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(errors) = body["errors"].as_array() else {
        return out;
    };
    for err in errors {
        let mut had_associated = false;
        if let Some(assoc) = err["meta"]["associatedErrors"].as_object() {
            for (source, list) in assoc {
                for item in list.as_array().into_iter().flatten() {
                    had_associated = true;
                    let code = item["code"].as_str().unwrap_or("");
                    let detail = item["detail"]
                        .as_str()
                        .or_else(|| item["title"].as_str())
                        .unwrap_or("");
                    let line = format!("{source} → {code} {detail}");
                    out.push(line.trim().trim_end_matches('→').trim().to_string());
                }
            }
        }
        if !had_associated {
            if let Some(msg) = err["detail"].as_str().or_else(|| err["title"].as_str()) {
                out.push(msg.to_string());
            }
        }
    }
    out
}

fn post_failure_to_error(f: PostFailure) -> MetadataError {
    match f {
        PostFailure::Status { status, body } => {
            let detail = collect_blockers(&body).join("; ");
            MetadataError::Api {
                status,
                detail: if detail.is_empty() {
                    "no detail".into()
                } else {
                    detail
                },
            }
        }
        PostFailure::Other(msg) => MetadataError::Transport(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_associated_errors_by_source() {
        let body = json!({
            "errors": [{
                "status": "409",
                "code": "STATE_ERROR.ENTITY_STATE_INVALID",
                "detail": "Review submission item cannot be added.",
                "meta": {
                    "associatedErrors": {
                        "/v2/appPrices/": [
                            { "code": "APP_PRICING_REQUIRED", "detail": "You must set a price." }
                        ],
                        "/v2/appAvailabilities/": [
                            { "code": "AVAILABILITY_REQUIRED", "detail": "Set availability." }
                        ]
                    }
                }
            }]
        });
        let blockers = collect_blockers(&body);
        assert_eq!(blockers.len(), 2);
        assert!(blockers
            .iter()
            .any(|b| b.contains("APP_PRICING_REQUIRED") && b.contains("/v2/appPrices/")));
        assert!(blockers
            .iter()
            .any(|b| b.contains("AVAILABILITY_REQUIRED")));
    }

    #[test]
    fn falls_back_to_detail_when_no_associated_errors() {
        let body = json!({
            "errors": [{ "detail": "Something else went wrong." }]
        });
        assert_eq!(collect_blockers(&body), vec!["Something else went wrong."]);
    }

    #[test]
    fn empty_body_yields_no_blockers() {
        assert!(collect_blockers(&Value::Null).is_empty());
    }
}
