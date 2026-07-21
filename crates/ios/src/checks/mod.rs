//! The registry of iOS checks. Add a new module here and push it into
//! [`registry`] to enable it.

use crate::IosCheck;

mod account_deletion;
mod ats;
mod ats_exceptions;
mod banned_terms;
mod dart_defines;
mod encryption;
mod entitlements;
mod ios17_permissions;
mod l10n_arb;
mod language_claims;
mod location;
mod orientation;
mod password_reset;
mod pbxproj;
mod privacy_manifest;
mod sign_in_with_apple;
mod store_text;
mod url_schemes;
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
        Box::new(entitlements::ApsEnvironmentCheck),
        Box::new(entitlements::GetTaskAllowCheck),
        Box::new(entitlements::IcloudEnvironmentCheck),
        Box::new(ats_exceptions::AtsExceptionDomainsCheck),
        Box::new(url_schemes::QuerySchemesLimitCheck),
        Box::new(ios17_permissions::CalendarFullAccessCheck),
        Box::new(pbxproj::DeploymentTargetConsistencyCheck),
        Box::new(pbxproj::CodeSignIdentityPinCheck),
        Box::new(store_text::StoreTextLimitsCheck),
        Box::new(store_text::SubtitleKeywordListCheck),
        Box::new(orientation::OrientationLockCheck),
        Box::new(dart_defines::DartDefinesEnvCheck),
        Box::new(language_claims::LanguageClaimCheck),
        Box::new(banned_terms::BannedTermsCheck),
        Box::new(password_reset::PasswordResetCheck),
        Box::new(l10n_arb::ArbMissingKeysCheck),
        Box::new(l10n_arb::ArbPlaceholderCheck),
    ]
}
