//! Google Play store-listing metadata scanning via the Android Publisher API.
//!
//! Runs only when a service account is configured; see
//! [`auth::ServiceAccount::from_env`]. Pipeline: [`ServiceAccount`] →
//! [`client::PlayClient`] (OAuth2 token exchange) → [`model::fetch`] (opens a
//! read-only edit, builds a [`PlayListingSnapshot`], abandons the edit) →
//! [`checks`]. Only the last step is network-free, so all rules are unit-testable.

pub mod auth;
pub mod checks;
mod client;
mod model;

pub use auth::ServiceAccount;
pub use model::{PlayListing, PlayListingSnapshot};

use preflight_core::{CheckMeta, Finding};

/// Run the Play metadata checks for `package_name` using `sa`.
pub fn analyze(sa: &ServiceAccount, package_name: &str) -> Result<Vec<Finding>, MetadataError> {
    let client = client::PlayClient::new(sa)?;
    let snapshot = model::fetch(&client, package_name)?;
    Ok(run_checks(&snapshot))
}

/// Run every Play metadata check against an already-fetched snapshot.
pub fn run_checks(snapshot: &PlayListingSnapshot) -> Vec<Finding> {
    checks::registry()
        .iter()
        .flat_map(|c| c.run(snapshot))
        .collect()
}

/// Metadata for every Play metadata check — folded into `preflight rules`.
pub fn all_check_meta() -> Vec<CheckMeta> {
    checks::all_meta()
}

#[derive(Debug)]
pub enum MetadataError {
    Auth(auth::AuthError),
    Api { status: u16, detail: String },
    Transport(String),
    Unexpected(String),
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetadataError::Auth(e) => write!(f, "{e}"),
            MetadataError::Api { status, detail } => {
                write!(f, "Google Play API error {status}: {detail}")
            }
            MetadataError::Transport(e) => write!(f, "network error contacting Google Play: {e}"),
            MetadataError::Unexpected(e) => write!(f, "unexpected Google Play response: {e}"),
        }
    }
}

impl std::error::Error for MetadataError {}

impl From<auth::AuthError> for MetadataError {
    fn from(e: auth::AuthError) -> Self {
        MetadataError::Auth(e)
    }
}
