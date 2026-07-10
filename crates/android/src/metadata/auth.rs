//! Google Play service-account authentication.
//!
//! Unlike App Store Connect (where the signed JWT *is* the bearer token), Google
//! uses a two-step OAuth2 flow: sign an RS256 assertion with the service
//! account's private key, exchange it at the token endpoint for a short-lived
//! access token, then call the Android Publisher API with that token.
//!
//! Credentials come from the environment so no secret lives in the repo:
//! - `GOOGLE_APPLICATION_CREDENTIALS` — path to the service account JSON, **or**
//! - `GPLAY_SERVICE_ACCOUNT_JSON`     — the JSON contents inline
//! - `GPLAY_PACKAGE_NAME`             — optional; overrides the detected package name

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

const SCOPE: &str = "https://www.googleapis.com/auth/androidpublisher";
const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
/// Assertion lifetime. Google allows up to one hour.
const ASSERTION_TTL_SECS: u64 = 3600;

/// The parts of a Google service-account JSON we need.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceAccount {
    pub client_email: String,
    pub private_key: String,
    #[serde(default = "default_token_uri")]
    pub token_uri: String,
    /// Not part of the JSON; filled from `GPLAY_PACKAGE_NAME` if set.
    #[serde(skip)]
    pub package_name: Option<String>,
}

fn default_token_uri() -> String {
    DEFAULT_TOKEN_URI.to_string()
}

impl ServiceAccount {
    /// Load a service account from the environment, or `None` if not configured.
    pub fn from_env() -> Option<Self> {
        let json = load_json()?;
        let mut sa: ServiceAccount = serde_json::from_str(&json).ok()?;
        sa.package_name = non_empty_env("GPLAY_PACKAGE_NAME");
        Some(sa)
    }
}

#[derive(Serialize)]
struct Assertion {
    iss: String,
    scope: String,
    aud: String,
    iat: u64,
    exp: u64,
}

/// Build the signed RS256 assertion JWT. Split out with an injectable `now` so
/// it can be verified in tests without a live token exchange.
pub fn build_assertion(sa: &ServiceAccount, now: u64) -> Result<String, AuthError> {
    let claims = Assertion {
        iss: sa.client_email.clone(),
        scope: SCOPE.to_string(),
        aud: sa.token_uri.clone(),
        iat: now,
        exp: now + ASSERTION_TTL_SECS,
    };
    let header = Header::new(Algorithm::RS256);
    let key = EncodingKey::from_rsa_pem(sa.private_key.as_bytes())
        .map_err(|e| AuthError::Key(e.to_string()))?;
    encode(&header, &claims, &key).map_err(|e| AuthError::Sign(e.to_string()))
}

fn load_json() -> Option<String> {
    if let Some(inline) = non_empty_env("GPLAY_SERVICE_ACCOUNT_JSON") {
        return Some(inline);
    }
    let path = non_empty_env("GOOGLE_APPLICATION_CREDENTIALS")?;
    std::fs::read_to_string(path)
        .ok()
        .filter(|s| !s.trim().is_empty())
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[derive(Debug)]
pub enum AuthError {
    Key(String),
    Sign(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Key(e) => write!(f, "invalid service-account private key: {e}"),
            AuthError::Sign(e) => write!(f, "failed to sign Google assertion: {e}"),
        }
    }
}

impl std::error::Error for AuthError {}
