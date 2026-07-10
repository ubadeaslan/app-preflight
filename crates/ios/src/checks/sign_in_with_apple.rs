//! IOS-LEGAL-002 — Sign in with Apple requirement (heuristic).
//!
//! Guideline 4.8: apps that offer third-party or social login as their *only*
//! or a primary sign-in option must also offer Sign in with Apple. We can't
//! prove intent statically, but if the project integrates a social login SDK and
//! shows no sign of Sign in with Apple, that's worth a low-confidence reminder.

use crate::{IosCheck, IosProject};
use preflight_core::{Category, CheckMeta, Confidence, Config, Finding, Platform, Severity};

pub struct SignInWithAppleCheck;

const META: CheckMeta = CheckMeta {
    id: "IOS-LEGAL-002",
    title: "Third-party login without Sign in with Apple",
    platform: Platform::Ios,
    category: Category::Legal,
    default_severity: Severity::Info,
    confidence: Confidence::Low,
    guideline: Some("4.8"),
    docs_url: Some("https://developer.apple.com/app-store/review/guidelines/#sign-in-with-apple"),
};

/// Signals a third-party / social login SDK is in use.
const SOCIAL_LOGIN_SIGNALS: &[&str] = &[
    "GIDSignIn",
    "GoogleSignIn",
    "FBSDKLoginKit",
    "FBSDKLoginManager",
    "FacebookLogin",
    "LineSDKLogin",
    "VKSdk",
    "TwitterKit",
];

/// Signals Sign in with Apple is already offered.
const APPLE_LOGIN_SIGNALS: &[&str] = &[
    "ASAuthorizationAppleIDProvider",
    "ASAuthorizationController",
    "ASAuthorizationAppleIDButton",
    "SignInWithAppleButton",
];

impl IosCheck for SignInWithAppleCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let mut has_social = false;
        let mut has_apple = false;

        for path in project.source_files.iter().take(2000) {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            if !has_social && SOCIAL_LOGIN_SIGNALS.iter().any(|s| text.contains(s)) {
                has_social = true;
            }
            if !has_apple && APPLE_LOGIN_SIGNALS.iter().any(|s| text.contains(s)) {
                has_apple = true;
            }
            if has_social && has_apple {
                break;
            }
        }

        if has_social && !has_apple {
            return vec![Finding::from_meta(
                &META,
                "The project integrates a third-party/social login SDK but shows no sign of \
                 Sign in with Apple. Guideline 4.8 requires it alongside other social logins.",
            )
            .remediation(
                "Add Sign in with Apple (AuthenticationServices) as a login option, or confirm \
                 4.8 doesn't apply to your login setup.",
            )];
        }
        Vec::new()
    }
}
