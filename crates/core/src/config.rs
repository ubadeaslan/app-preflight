//! `preflight.toml` — optional per-project configuration.
//!
//! Everything works with zero config; this only exists to silence checks that
//! don't apply to a given project or to raise the strictness bar.

use crate::finding::Severity;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Check ids to skip entirely, e.g. ["IOS-CONFIG-002"].
    pub disabled_checks: Vec<String>,
    /// Findings below this severity are hidden from the report.
    pub min_severity: Option<Severity>,
    /// Severity at or above which the process exits non-zero. Defaults to
    /// `error` when unset.
    pub fail_on: Option<Severity>,
}

impl Config {
    /// Load `preflight.toml` from `dir` if present, otherwise return defaults.
    pub fn load_from_dir(dir: &Path) -> Result<Self, ConfigError> {
        let path = dir.join("preflight.toml");
        if !path.exists() {
            return Ok(Config::default());
        }
        let text = std::fs::read_to_string(&path).map_err(ConfigError::Io)?;
        toml::from_str(&text).map_err(ConfigError::Parse)
    }

    pub fn is_disabled(&self, check_id: &str) -> bool {
        self.disabled_checks.iter().any(|c| c == check_id)
    }

    /// Severity threshold that should fail the run. Defaults to `Error`.
    pub fn fail_threshold(&self) -> Severity {
        self.fail_on.unwrap_or(Severity::Error)
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "reading preflight.toml: {e}"),
            ConfigError::Parse(e) => write!(f, "parsing preflight.toml: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}
