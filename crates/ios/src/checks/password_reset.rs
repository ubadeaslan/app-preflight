//! IOS-LEGAL-003 — email sign-in without a password reset path.
//!
//! An email/password login with no "forgot password" flow is a dead end: the
//! user who forgets a password can neither sign in nor recover, which reads as
//! an incomplete app in review and produces one-star "locked out" reviews in
//! production. Heuristic (FirebaseAuth, the factory default): Dart code calls
//! `signInWithEmailAndPassword` / `createUserWithEmailAndPassword` but never
//! `sendPasswordResetEmail`.

use crate::{IosCheck, IosProject};
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};
use std::path::PathBuf;
use walkdir::WalkDir;

pub struct PasswordResetCheck;

const PASSWORD_RESET_META: CheckMeta = CheckMeta {
    id: "IOS-LEGAL-003",
    title: "Email sign-in without a password reset path",
    platform: Platform::Ios,
    category: Category::Legal,
    default_severity: Severity::Warning,
    confidence: Confidence::Medium,
    guideline: Some("2.1"),
    docs_url: Some(
        "https://firebase.google.com/docs/auth/flutter/manage-users#send_a_password_reset_email",
    ),
};

const EMAIL_SIGN_IN_MARKERS: &[&str] = &[
    "signInWithEmailAndPassword",
    "createUserWithEmailAndPassword",
];
const RESET_MARKER: &str = "sendPasswordResetEmail";

impl IosCheck for PasswordResetCheck {
    fn meta(&self) -> CheckMeta {
        PASSWORD_RESET_META
    }

    fn run(&self, project: &IosProject, _config: &Config) -> Vec<Finding> {
        let mut sign_in_file: Option<PathBuf> = None;
        let mut has_reset = false;
        for path in dart_files(&project.root) {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if sign_in_file.is_none() && EMAIL_SIGN_IN_MARKERS.iter().any(|m| text.contains(m)) {
                sign_in_file = Some(path.clone());
            }
            if text.contains(RESET_MARKER) {
                has_reset = true;
                break; // A reset path exists — nothing to flag.
            }
        }
        let (Some(path), false) = (sign_in_file, has_reset) else {
            return Vec::new();
        };
        vec![Finding::from_meta(
            &PASSWORD_RESET_META,
            "The app signs users in with email/password but no call to \
             sendPasswordResetEmail was found — a user who forgets the password has \
             no way back in (dead-end flow; review and one-star-review risk).",
        )
        .location(Location::file(path))
        .remediation(
            "Add a \"forgot password?\" flow that calls \
             FirebaseAuth.sendPasswordResetEmail (or your auth provider's \
             equivalent) from the sign-in screen.",
        )]
    }
}

/// Dart sources under `lib/` (skipping generated l10n output is not needed —
/// markers are auth calls that only live in handwritten code).
fn dart_files(root: &std::path::Path) -> Vec<PathBuf> {
    let lib = root.join("lib");
    if !lib.is_dir() {
        return Vec::new();
    }
    WalkDir::new(lib)
        .into_iter()
        .flatten()
        .filter(|e| {
            e.file_type().is_file()
                && e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| x.eq_ignore_ascii_case("dart"))
        })
        .map(|e| e.into_path())
        .collect()
}
