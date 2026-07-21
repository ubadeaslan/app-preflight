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

    /// GET where a 404 is a meaningful "this resource was never created" answer
    /// (e.g. `appAvailabilityV2` before territories are ever configured), not a
    /// failure: 404 maps to `Ok(None)`, other errors propagate.
    pub fn get_optional(&self, path: &str) -> Result<Option<Value>, MetadataError> {
        match self.get(path) {
            Ok(v) => Ok(Some(v)),
            Err(MetadataError::Api { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// POST a JSON:API body. On a non-2xx response the *full* error body is
    /// returned, because ASC packs the useful part (`meta.associatedErrors`)
    /// inside it — a flattened detail string would lose exactly what the
    /// submit simulation exists to read.
    pub fn post(&self, path: &str, body: Value) -> Result<Value, PostFailure> {
        let url = format!("{BASE_URL}{path}");
        let result = ureq::post(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .send_json(body);
        match result {
            Ok(response) => response
                .into_json::<Value>()
                .map_err(|e| PostFailure::Other(format!("invalid JSON from {path}: {e}"))),
            Err(ureq::Error::Status(status, response)) => {
                let body = response.into_json::<Value>().unwrap_or(Value::Null);
                Err(PostFailure::Status { status, body })
            }
            Err(ureq::Error::Transport(t)) => Err(PostFailure::Other(t.to_string())),
        }
    }

    /// PATCH a JSON:API body; non-2xx maps to `MetadataError`.
    pub fn patch(&self, path: &str, body: Value) -> Result<(), MetadataError> {
        let url = format!("{BASE_URL}{path}");
        ureq::request("PATCH", &url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .send_json(body)
            .map_err(map_ureq_error)?;
        Ok(())
    }

    /// DELETE a resource; non-2xx maps to `MetadataError`.
    pub fn delete(&self, path: &str) -> Result<(), MetadataError> {
        let url = format!("{BASE_URL}{path}");
        ureq::delete(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .call()
            .map_err(map_ureq_error)?;
        Ok(())
    }
}

/// A failed POST, keeping the whole ASC error body when there is one.
pub enum PostFailure {
    Status { status: u16, body: Value },
    Other(String),
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
