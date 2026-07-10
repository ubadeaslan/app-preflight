//! A thin, blocking Google Play (Android Publisher) API client.
//!
//! On construction it performs the OAuth2 JWT-bearer exchange to obtain an
//! access token, then offers `get`/`post`/`delete` against the Publisher API.

use super::auth::{build_assertion, ServiceAccount};
use super::MetadataError;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

const API_BASE: &str = "https://androidpublisher.googleapis.com";
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

pub struct PlayClient {
    access_token: String,
}

impl PlayClient {
    /// Exchange the service account's signed assertion for an access token.
    pub fn new(sa: &ServiceAccount) -> Result<Self, MetadataError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MetadataError::Unexpected("system clock before Unix epoch".into()))?
            .as_secs();
        let assertion = build_assertion(sa, now)?;

        let response = ureq::post(&sa.token_uri)
            .send_form(&[("grant_type", GRANT_TYPE), ("assertion", &assertion)])
            .map_err(map_ureq_error)?;
        let body: Value = response
            .into_json()
            .map_err(|e| MetadataError::Unexpected(format!("invalid token response: {e}")))?;
        let access_token = body["access_token"]
            .as_str()
            .ok_or_else(|| MetadataError::Unexpected("token response had no access_token".into()))?
            .to_string();

        Ok(PlayClient { access_token })
    }

    pub fn get(&self, path: &str) -> Result<Value, MetadataError> {
        self.request("GET", path, None)
    }

    /// POST with an empty JSON body (used to create edits).
    pub fn post_empty(&self, path: &str) -> Result<Value, MetadataError> {
        self.request("POST", path, Some(Value::Object(Default::default())))
    }

    /// DELETE, ignoring the (empty) response body. Used to abandon edits.
    pub fn delete(&self, path: &str) -> Result<(), MetadataError> {
        let url = format!("{API_BASE}{path}");
        ureq::request("DELETE", &url)
            .set("Authorization", &self.bearer())
            .call()
            .map_err(map_ureq_error)?;
        Ok(())
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, MetadataError> {
        let url = format!("{API_BASE}{path}");
        let req = ureq::request(method, &url).set("Authorization", &self.bearer());
        let response = match body {
            Some(json) => req.send_json(json),
            None => req.call(),
        }
        .map_err(map_ureq_error)?;
        response
            .into_json::<Value>()
            .map_err(|e| MetadataError::Unexpected(format!("invalid JSON from {path}: {e}")))
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", self.access_token)
    }
}

fn map_ureq_error(err: ureq::Error) -> MetadataError {
    match err {
        ureq::Error::Status(code, response) => {
            // Publisher errors use `error.message`; the OAuth token endpoint uses
            // `error_description` / a string `error`. Try each.
            let detail = response
                .into_json::<Value>()
                .ok()
                .and_then(|v| {
                    v["error"]["message"]
                        .as_str()
                        .or_else(|| v["error_description"].as_str())
                        .or_else(|| v["error"].as_str())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| "no detail".to_string());
            MetadataError::Api {
                status: code,
                detail,
            }
        }
        ureq::Error::Transport(t) => MetadataError::Transport(t.to_string()),
    }
}
