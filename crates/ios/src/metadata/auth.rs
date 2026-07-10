//! App Store Connect credentials and ES256 JWT generation.
//!
//! ASC authenticates every request with a short-lived JWT signed by your API
//! key's `.p8` (an EC P-256 private key). Credentials are read from the
//! environment so secrets never live in a config file or the repo:
//!
//! - `ASC_ISSUER_ID`   — the issuer id from App Store Connect > Users and Access > Keys
//! - `ASC_KEY_ID`      — the key id
//! - `ASC_PRIVATE_KEY` — the `.p8` contents inline, **or**
//! - `ASC_PRIVATE_KEY_PATH` — a path to the `.p8` file
//! - `ASC_BUNDLE_ID`   — optional; overrides the bundle id detected from the project

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Audience required by the App Store Connect API.
const AUDIENCE: &str = "appstoreconnect-v1";
/// Token lifetime. ASC rejects tokens valid for more than 20 minutes.
const TOKEN_TTL_SECS: u64 = 15 * 60;

#[derive(Debug, Clone)]
pub struct AscCredentials {
    pub issuer_id: String,
    pub key_id: String,
    pub private_key_pem: String,
    pub bundle_id: Option<String>,
}

impl AscCredentials {
    /// Resolve credentials from the environment. Returns `None` when the core
    /// three (issuer id, key id, private key) are not all present, which the
    /// CLI treats as "metadata scanning not configured — skip it".
    pub fn from_env() -> Option<Self> {
        let issuer_id = non_empty_env("ASC_ISSUER_ID")?;
        let key_id = non_empty_env("ASC_KEY_ID")?;
        let private_key_pem = load_private_key()?;
        Some(AscCredentials {
            issuer_id,
            key_id,
            private_key_pem,
            bundle_id: non_empty_env("ASC_BUNDLE_ID"),
        })
    }
}

#[derive(Serialize)]
struct Claims {
    iss: String,
    iat: u64,
    exp: u64,
    aud: String,
}

/// Sign an App Store Connect bearer token from these credentials.
pub fn make_token(creds: &AscCredentials) -> Result<String, AuthError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::Clock)?
        .as_secs();
    make_token_at(creds, now)
}

/// Testable core of [`make_token`] with an injectable "now".
pub(crate) fn make_token_at(creds: &AscCredentials, now: u64) -> Result<String, AuthError> {
    let claims = Claims {
        iss: creds.issuer_id.clone(),
        iat: now,
        exp: now + TOKEN_TTL_SECS,
        aud: AUDIENCE.to_string(),
    };
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(creds.key_id.clone());
    let key = EncodingKey::from_ec_pem(creds.private_key_pem.as_bytes())
        .map_err(|e| AuthError::Key(e.to_string()))?;
    encode(&header, &claims, &key).map_err(|e| AuthError::Sign(e.to_string()))
}

fn load_private_key() -> Option<String> {
    if let Some(inline) = non_empty_env("ASC_PRIVATE_KEY") {
        return Some(inline);
    }
    let path = non_empty_env("ASC_PRIVATE_KEY_PATH")?;
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
    Clock,
    Key(String),
    Sign(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Clock => write!(f, "system clock is before the Unix epoch"),
            AuthError::Key(e) => write!(f, "invalid App Store Connect private key: {e}"),
            AuthError::Sign(e) => write!(f, "failed to sign App Store Connect token: {e}"),
        }
    }
}

impl std::error::Error for AuthError {}
