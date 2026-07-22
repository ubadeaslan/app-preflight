//! ANDROID-CONFIG-010 — release shrinking without R8 keep rules.
//!
//! Flutter's release build runs R8. Room generates `*_Impl` classes whose
//! no-arg constructors are only ever called reflectively, so R8 removes them —
//! and the app dies at process start, before Flutter boots:
//!
//! ```text
//! RuntimeException: Unable to get provider androidx.startup.InitializationProvider
//! Caused by: NoSuchMethodException: androidx.work.impl.WorkDatabase_Impl.<init> []
//! ```
//!
//! WorkManager arrives transitively with common Firebase artifacts (ML model
//! downloader, analytics), and `androidx.startup` initializes it before
//! `main()`, so there is no Dart error screen and no Crashlytics report — just
//! "app keeps stopping". Debug builds don't shrink, so it never reproduces in
//! development. (Snapaw, 2026-07-22 — first real-device launch.)
//!
//! The check fires when the project pulls in a reflection-heavy dependency but
//! the release build type has no `proguardFiles` line: cheap, high-signal, and
//! it only takes one line of Gradle to fix.

use crate::checks::AndroidCheck;
use crate::AndroidProject;
use preflight_core::{
    Category, CheckMeta, Confidence, Config, Finding, Location, Platform, Severity,
};

pub struct R8KeepRulesCheck;

const R8_KEEP_META: CheckMeta = CheckMeta {
    id: "ANDROID-CONFIG-010",
    title: "Release build shrinks without R8 keep rules (startup crash risk)",
    platform: Platform::Android,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::Medium,
    guideline: None,
    docs_url: Some("https://developer.android.com/build/shrink-code#keep-code"),
};

/// Dependencies whose classes are instantiated reflectively and therefore need
/// keep rules (Room-backed or reflection-driven at startup).
const REFLECTIVE_DEPS: &[&str] = &[
    "androidx.work",
    "androidx.room",
    "firebase_ml_model_downloader",
    "firebase-ml-modeldownloader",
    "firebase_analytics",
    "firebase-analytics",
    "google_mlkit",
    "com.google.mlkit",
];

impl AndroidCheck for R8KeepRulesCheck {
    fn meta(&self) -> CheckMeta {
        R8_KEEP_META
    }

    fn run(&self, project: &AndroidProject, _config: &Config) -> Vec<Finding> {
        // All module Gradle scripts, already concatenated by the loader — the
        // app module lives at a different depth per project layout (Flutter
        // keeps it under `android/app/`).
        let text = project.gradle_text.as_str();

        // Only meaningful when a release build type exists.
        if !text.contains("release") {
            return Vec::new();
        }
        // Explicitly disabled shrinking is a deliberate (and safe) choice.
        let shrinking_off =
            text.contains("minifyEnabled false") || text.contains("isMinifyEnabled = false");
        if shrinking_off || text.contains("proguardFiles") {
            return Vec::new();
        }

        let hit = REFLECTIVE_DEPS
            .iter()
            .find(|dep| project_uses(project, dep))
            .copied();
        let Some(dep) = hit else {
            return Vec::new();
        };

        vec![Finding::from_meta(
            &R8_KEEP_META,
            format!(
                "The release build type declares no `proguardFiles`, but the project uses \
                 `{dep}`, whose classes are constructed reflectively. R8 strips the generated \
                 Room `*_Impl` constructors and the app crashes at process start \
                 (NoSuchMethodException via androidx.startup) — with no Dart error screen and \
                 no Crashlytics report. Debug builds do not shrink, so this only shows up on a \
                 real release install."
            ),
        )
        .location(Location::file(
            app_gradle_path(project).unwrap_or_else(|| project.root.clone()),
        ))
        .remediation(
            "Add an app/proguard-rules.pro with `-keep class * extends androidx.room.RoomDatabase \
             { <init>(); }` (plus androidx.work / Firebase / ML Kit keeps) and wire it via \
             `proguardFiles(getDefaultProguardFile(\"proguard-android-optimize.txt\"), \
             \"proguard-rules.pro\")` — then smoke-test the release build on a real device.",
        )]
    }
}

/// The app module's Gradle build file, for the finding's location. Covers both
/// a plain Android layout and Flutter's `android/app/` nesting.
fn app_gradle_path(project: &AndroidProject) -> Option<std::path::PathBuf> {
    for name in [
        "app/build.gradle.kts",
        "app/build.gradle",
        "android/app/build.gradle.kts",
        "android/app/build.gradle",
    ] {
        let path = project.root.join(name);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

/// Whether `needle` appears in the project's dependency declarations —
/// `pubspec.yaml` for Flutter plugins, Gradle scripts for direct Android deps.
fn project_uses(project: &AndroidProject, needle: &str) -> bool {
    if project.gradle_text.contains(needle) {
        return true;
    }
    for name in ["pubspec.yaml", "../pubspec.yaml"] {
        if std::fs::read_to_string(project.root.join(name))
            .map(|t| t.contains(needle))
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}
