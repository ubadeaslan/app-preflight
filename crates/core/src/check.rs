//! Metadata describing a check. The runnable part of a check lives in the
//! platform crates, but every check exposes one of these so the CLI can list,
//! document and filter checks uniformly.

use crate::finding::{Category, Platform, Severity};

/// How sure a check is that its finding is a real problem.
///
/// Static analysis of a project can only go so far — some rejection reasons
/// (e.g. "app requires login but ships no demo account") can only be *hinted*
/// at. Confidence lets the CLI separate hard failures from heuristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Deterministic — the file is missing, the key is empty, etc.
    High,
    /// A strong signal, but there are legitimate exceptions.
    Medium,
    /// A reminder / heuristic that a human should confirm.
    Low,
}

use serde::{Deserialize, Serialize};

/// Static description of a check. Kept `'static` so the registry is cheap and
/// checks read like declarations.
#[derive(Debug, Clone, Copy)]
pub struct CheckMeta {
    /// Stable, greppable identifier, e.g. "IOS-PRIVACY-001".
    pub id: &'static str,
    /// One-line human title.
    pub title: &'static str,
    pub platform: Platform,
    pub category: Category,
    pub default_severity: Severity,
    pub confidence: Confidence,
    /// Apple guideline number or Play policy reference, if any.
    pub guideline: Option<&'static str>,
    /// Link to the relevant documentation.
    pub docs_url: Option<&'static str>,
}
