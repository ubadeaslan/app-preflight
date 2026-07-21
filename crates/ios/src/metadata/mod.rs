//! App Store Connect metadata scanning.
//!
//! This layer talks to the App Store Connect API to check the *store listing*
//! (privacy policy, support URL, demo account, screenshots, description) rather
//! than the project on disk. It only runs when credentials are configured; see
//! [`auth::AscCredentials::from_env`].
//!
//! Pipeline: [`AscCredentials`] → [`client::AscClient`] (signs a JWT) →
//! [`model::fetch`] (builds a [`MetadataSnapshot`]) → [`checks`] (produce
//! findings). Only the last step is network-free, and it is where all the rules
//! live, so the whole rule set is unit-testable without a live account.

pub mod auth;
pub mod checks;
mod client;
mod model;
pub mod submit_sim;

pub use auth::AscCredentials;
pub use model::{Localization, MetadataSnapshot, ReviewDetail};
pub use submit_sim::{SubmitSimOutcome, SubmitSimReport};

use preflight_core::{CheckMeta, Finding};

/// Run the metadata checks for `bundle_id` using `creds`.
pub fn analyze(creds: &AscCredentials, bundle_id: &str) -> Result<Vec<Finding>, MetadataError> {
    let client = client::AscClient::new(creds)?;
    let snapshot = model::fetch(&client, bundle_id)?;
    Ok(run_checks(&snapshot))
}

/// Run every metadata check against an already-fetched snapshot.
pub fn run_checks(snapshot: &MetadataSnapshot) -> Vec<Finding> {
    checks::registry()
        .iter()
        .flat_map(|c| c.run(snapshot))
        .collect()
}

/// Metadata for every metadata check — folded into `preflight rules`.
pub fn all_check_meta() -> Vec<CheckMeta> {
    checks::all_meta()
}

#[derive(Debug)]
pub enum MetadataError {
    Auth(auth::AuthError),
    /// The API responded with a non-2xx status.
    Api {
        status: u16,
        detail: String,
    },
    /// Network-level failure (DNS, TLS, timeout).
    Transport(String),
    /// No app matched the bundle id under this account.
    AppNotFound(String),
    /// The API returned something we couldn't make sense of.
    Unexpected(String),
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetadataError::Auth(e) => write!(f, "{e}"),
            MetadataError::Api { status, detail } => {
                write!(f, "App Store Connect API error {status}: {detail}")
            }
            MetadataError::Transport(e) => {
                write!(f, "network error contacting App Store Connect: {e}")
            }
            MetadataError::AppNotFound(bundle) => {
                write!(
                    f,
                    "no app with bundle id `{bundle}` found under this API key"
                )
            }
            MetadataError::Unexpected(e) => write!(f, "unexpected App Store Connect response: {e}"),
        }
    }
}

impl std::error::Error for MetadataError {}

impl From<auth::AuthError> for MetadataError {
    fn from(e: auth::AuthError) -> Self {
        MetadataError::Auth(e)
    }
}
