//! The [`Finding`] — a single issue surfaced by a check — and its supporting
//! enums.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// How serious an issue is. Also drives the process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational. Will not fail a build.
    Info,
    /// Likely to cause friction or a soft rejection; worth fixing.
    Warning,
    /// Very likely to cause an App Store / Play rejection or a broken build.
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The target platform a finding relates to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Ios,
    Android,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Ios => "ios",
            Platform::Android => "android",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Broad grouping used for reporting and filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// Privacy manifests, tracking, permission purpose strings.
    Privacy,
    /// Legal / policy requirements (account deletion, licenses).
    Legal,
    /// Store listing: screenshots, descriptions, support URLs.
    Metadata,
    /// App completeness, crashes, placeholder content.
    Functionality,
    /// In-app purchase / payment rules.
    Payments,
    /// Issues found by inspecting a compiled IPA/APK.
    Binary,
    /// Project/build configuration (versions, signing, encryption flags).
    Configuration,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Privacy => "privacy",
            Category::Legal => "legal",
            Category::Metadata => "metadata",
            Category::Functionality => "functionality",
            Category::Payments => "payments",
            Category::Binary => "binary",
            Category::Configuration => "configuration",
        }
    }
}

/// Where in the project a finding was located.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

impl Location {
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            file: path.into(),
            line: None,
        }
    }

    pub fn at(path: impl Into<PathBuf>, line: u32) -> Self {
        Self {
            file: path.into(),
            line: Some(line),
        }
    }
}

/// A single issue surfaced by a check.
///
/// Checks build these with [`Finding::from_meta`] so that identity fields
/// (`check_id`, `title`, `category`, `guideline`, `docs_url`) stay in sync with
/// the check's [`crate::CheckMeta`] and only the situational fields
/// (`severity`, `message`, `location`, `remediation`) are supplied per finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub check_id: String,
    pub title: String,
    pub severity: Severity,
    pub category: Category,
    pub platform: Platform,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Reference to an Apple guideline number or Play policy, e.g. "5.1.1(v)".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guideline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs_url: Option<String>,
}

impl Finding {
    /// Start a finding from its check's metadata. The default severity comes
    /// from the meta and can be overridden with [`Finding::severity`].
    pub fn from_meta(meta: &crate::CheckMeta, message: impl Into<String>) -> Self {
        Finding {
            check_id: meta.id.to_string(),
            title: meta.title.to_string(),
            severity: meta.default_severity,
            category: meta.category,
            platform: meta.platform,
            message: message.into(),
            location: None,
            remediation: None,
            guideline: meta.guideline.map(str::to_string),
            docs_url: meta.docs_url.map(str::to_string),
        }
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn location(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }

    pub fn remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }
}
