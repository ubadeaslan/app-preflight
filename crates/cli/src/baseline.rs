//! A baseline suppresses findings that already exist, so a scan only fails on
//! *new* issues. Handy for adopting preflight on a project that isn't clean yet.

use preflight_core::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// Default baseline file name when `--baseline` has no explicit path.
pub const DEFAULT_PATH: &str = ".preflight-baseline.json";

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Entry {
    pub check_id: String,
    #[serde(default)]
    pub file: String,
    pub message: String,
}

fn entry_of(finding: &Finding, root: &Path) -> Entry {
    let file = finding
        .location
        .as_ref()
        .map(|l| {
            l.file
                .strip_prefix(root)
                .unwrap_or(&l.file)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .unwrap_or_default();
    Entry {
        check_id: finding.check_id.clone(),
        file,
        message: finding.message.clone(),
    }
}

/// Write the current findings to `path` as a baseline. Returns the count.
pub fn write(path: &Path, findings: &[Finding], root: &Path) -> std::io::Result<usize> {
    let entries: Vec<Entry> = findings.iter().map(|f| entry_of(f, root)).collect();
    let json = serde_json::to_string_pretty(&entries)?;
    std::fs::write(path, json)?;
    Ok(entries.len())
}

/// Drop findings already present in the baseline file. Returns how many were
/// suppressed.
pub fn suppress(path: &Path, findings: &mut Vec<Finding>, root: &Path) -> std::io::Result<usize> {
    let text = std::fs::read_to_string(path)?;
    let entries: Vec<Entry> = serde_json::from_str(&text).unwrap_or_default();
    let known: HashSet<Entry> = entries.into_iter().collect();
    let before = findings.len();
    findings.retain(|f| !known.contains(&entry_of(f, root)));
    Ok(before - findings.len())
}
