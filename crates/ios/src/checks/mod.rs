//! The registry of iOS checks. Add a new module here and push it into
//! [`registry`] to enable it.

use crate::IosCheck;

mod account_deletion;
mod ats;
mod encryption;
mod location;
mod privacy_manifest;
mod sign_in_with_apple;
mod usage_descriptions;
mod versioning;

/// All iOS checks, in no particular order (the report sorts findings).
pub fn registry() -> Vec<Box<dyn IosCheck>> {
    vec![
        Box::new(privacy_manifest::PrivacyManifestCheck),
        Box::new(usage_descriptions::UsageDescriptionsCheck),
        Box::new(encryption::EncryptionDeclarationCheck),
        Box::new(versioning::VersioningCheck),
        Box::new(account_deletion::AccountDeletionCheck),
        Box::new(ats::AtsArbitraryLoadsCheck),
        Box::new(sign_in_with_apple::SignInWithAppleCheck),
        Box::new(location::BackgroundLocationCheck),
        Box::new(location::DeprecatedLocationKeyCheck),
    ]
}
