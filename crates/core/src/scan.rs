//! Outcome of an optional, credential-gated remote scan (App Store Connect,
//! Google Play). Shared by the platform crates so the CLI handles them
//! uniformly.

use crate::finding::Finding;

pub enum MetadataScan {
    /// No credentials configured; the scan was skipped.
    Skipped,
    /// Credentials are present but no concrete target (bundle id / package name)
    /// could be determined.
    NoTarget,
    /// Credentials present but the fetch failed (network, auth, no such app).
    Failed(String),
    /// Completed; carries the findings.
    Done(Vec<Finding>),
}
