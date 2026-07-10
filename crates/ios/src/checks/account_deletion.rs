//! IOS-LEGAL-001 — Account-deletion reminder (heuristic).
//!
//! Guideline 5.1.1(v): apps that let users create an account must let them
//! delete it from within the app. We can't prove this statically, but if the
//! project clearly has account creation and no sign of a deletion path, that's
//! worth a low-confidence reminder.

use crate::{IosCheck, IosProject};
use preflight_core::{Category, CheckMeta, Confidence, Config, Finding, Platform, Severity};

pub struct AccountDeletionCheck;

const META: CheckMeta = CheckMeta {
    id: "IOS-LEGAL-001",
    title: "Account creation without visible deletion path",
    platform: Platform::Ios,
    category: Category::Legal,
    default_severity: Severity::Info,
    confidence: Confidence::Low,
    guideline: Some("5.1.1(v)"),
    docs_url: Some("https://developer.apple.com/support/offering-account-deletion-in-your-app/"),
};

/// Signals the app creates accounts. Kept specific to auth APIs — a bare
/// `register(` matched ubiquitous UIKit calls like `tableView.register(...)`.
const SIGNUP_SIGNALS: &[&str] = &[
    "createUser",
    "signUp",
    "createAccount",
    "registerUser",
    "SignInWithApple",
    "ASAuthorizationController",
];

/// Signals a deletion path already exists.
const DELETION_SIGNALS: &[&str] = &[
    "deleteAccount",
    "deleteUser",
    "delete account",
    "closeAccount",
    "revoketoken",
    "revokeToken",
];

impl IosCheck for AccountDeletionCheck {
    fn meta(&self) -> CheckMeta {
        META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let mut has_signup = false;
        let mut has_deletion = false;

        // Scan a bounded number of source files to keep this cheap.
        for path in project.source_files.iter().take(2000) {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            if !has_signup && SIGNUP_SIGNALS.iter().any(|s| text.contains(s)) {
                has_signup = true;
            }
            if !has_deletion {
                let lower = text.to_ascii_lowercase();
                has_deletion = DELETION_SIGNALS
                    .iter()
                    .any(|s| lower.contains(&s.to_ascii_lowercase()));
            }
            if has_signup && has_deletion {
                break;
            }
        }

        if has_signup && !has_deletion {
            return vec![Finding::from_meta(
                &META,
                "The project appears to support account creation but no in-app \
                 account-deletion path was detected. Apple requires one under \
                 Guideline 5.1.1(v).",
            )
            .remediation(
                "Provide a clearly visible way to initiate account deletion from \
                 within the app (not only a support email).",
            )];
        }
        Vec::new()
    }
}
