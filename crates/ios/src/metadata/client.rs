//! A thin, blocking App Store Connect API client built on `ureq`.
//!
//! Blocking on purpose: preflight is a short-lived CLI, so avoiding an async
//! runtime keeps the binary small and the code simple.

use super::auth::{self, AscCredentials};
use super::MetadataError;
use serde_json::Value;

const BASE_URL: &str = "https://api.appstoreconnect.apple.com";

pub struct AscClient {
    token: String,
}

impl AscClient {
    /// Build a client, signing a bearer token from the credentials.
    pub fn new(creds: &AscCredentials) -> Result<Self, MetadataError> {
        let token = auth::make_token(creds)?;
        Ok(AscClient { token })
    }

    /// GET an API path (starting with `/v1/...`) and parse the JSON body.
    pub fn get(&self, path: &str) -> Result<Value, MetadataError> {
        let url = format!("{BASE_URL}{path}");
        let response = ureq::get(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .call()
            .map_err(map_ureq_error)?;
        response
            .into_json::<Value>()
            .map_err(|e| MetadataError::Unexpected(format!("invalid JSON from {path}: {e}")))
    }
}

fn map_ureq_error(err: ureq::Error) -> MetadataError {
    match err {
        ureq::Error::Status(code, response) => {
            // ASC returns a JSON error body with a `detail` message.
            let detail = response
                .into_json::<Value>()
                .ok()
                .and_then(|v| {
                    v["errors"]
                        .as_array()
                        .and_then(|a| a.first())
                        .and_then(|e| e["detail"].as_str().map(str::to_string))
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
