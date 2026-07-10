//! Core types shared across all app-preflight crates.
//!
//! The model is intentionally small so that adding a new check means adding a
//! single self-contained unit: some [`CheckMeta`] describing it, and a function
//! that returns [`Finding`]s. Platform crates (`preflight-ios`,
//! `preflight-android`) build on top of these types.

pub mod check;
pub mod config;
pub mod finding;
pub mod report;
pub mod scan;

pub use check::{CheckMeta, Confidence};
pub use config::Config;
pub use finding::{Category, Finding, Location, Platform, Severity};
pub use report::Report;
pub use scan::MetadataScan;
