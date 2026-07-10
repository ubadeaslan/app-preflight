//! Aggregation of findings into a [`Report`] plus the summary counts and
//! exit-code logic the CLI needs.

use crate::config::Config;
use crate::finding::{Finding, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub summary: Summary,
    /// All findings after `disabled_checks` + severity overrides but BEFORE the
    /// `min_severity` display filter — so the pass/fail gate is independent of
    /// what's shown. Not serialized.
    #[serde(skip)]
    gate_findings: Vec<Finding>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Summary {
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
}

impl Report {
    /// Build a report from raw findings, applying config filters
    /// (`disabled_checks`, `min_severity`). Findings are sorted most-severe
    /// first, then by check id for stable output.
    pub fn build(mut findings: Vec<Finding>, config: &Config) -> Self {
        findings.retain(|f| !config.is_disabled(&f.check_id));
        // Apply per-check severity overrides before filtering/sorting.
        for f in &mut findings {
            f.severity = config.severity_for(&f.check_id, f.severity);
        }

        // `min_severity` hides low findings from the report, but the pass/fail
        // gate must still consider them — keep a pre-filter copy for `should_fail`.
        let gate_findings = findings.clone();
        if let Some(min) = config.min_severity {
            findings.retain(|f| f.severity >= min);
        }
        // Fully deterministic order: severity desc, then id, then location, then
        // message. Stability matters for baselines and SARIF/JSON diffs.
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.check_id.cmp(&b.check_id))
                .then_with(|| location_key(a).cmp(&location_key(b)))
                .then_with(|| a.message.cmp(&b.message))
        });

        let mut summary = Summary::default();
        for f in &findings {
            match f.severity {
                Severity::Error => summary.errors += 1,
                Severity::Warning => summary.warnings += 1,
                Severity::Info => summary.infos += 1,
            }
        }

        Report {
            findings,
            summary,
            gate_findings,
        }
    }

    /// True when any finding meets or exceeds the configured fail threshold.
    /// Evaluated against the pre-`min_severity` set so hiding low findings never
    /// changes the exit code.
    pub fn should_fail(&self, config: &Config) -> bool {
        let threshold = config.fail_threshold();
        self.gate_findings.iter().any(|f| f.severity >= threshold)
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

/// A sortable key for a finding's location (file then line), for stable ordering.
fn location_key(f: &Finding) -> (String, u32) {
    match &f.location {
        Some(loc) => (
            loc.file.to_string_lossy().into_owned(),
            loc.line.unwrap_or(0),
        ),
        None => (String::new(), 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Category, Finding, Platform};

    fn finding(id: &str, sev: Severity) -> Finding {
        Finding {
            check_id: id.into(),
            title: "t".into(),
            severity: sev,
            category: Category::Configuration,
            platform: Platform::Ios,
            message: "m".into(),
            location: None,
            remediation: None,
            guideline: None,
            docs_url: None,
        }
    }

    #[test]
    fn sorts_most_severe_first_then_by_id() {
        let report = Report::build(
            vec![
                finding("B", Severity::Warning),
                finding("A", Severity::Error),
                finding("C", Severity::Warning),
            ],
            &Config::default(),
        );
        let order: Vec<&str> = report
            .findings
            .iter()
            .map(|f| f.check_id.as_str())
            .collect();
        assert_eq!(order, ["A", "B", "C"]);
        assert_eq!(report.summary.errors, 1);
        assert_eq!(report.summary.warnings, 2);
    }

    #[test]
    fn respects_disabled_checks_and_min_severity() {
        let config = Config {
            disabled_checks: vec!["A".into()],
            min_severity: Some(Severity::Warning),
            fail_on: None,
            ..Default::default()
        };
        let report = Report::build(
            vec![
                finding("A", Severity::Error),
                finding("B", Severity::Info),
                finding("C", Severity::Warning),
            ],
            &config,
        );
        let order: Vec<&str> = report
            .findings
            .iter()
            .map(|f| f.check_id.as_str())
            .collect();
        assert_eq!(order, ["C"]); // A disabled, B below min severity
    }

    #[test]
    fn severity_override_applies() {
        let mut severity = std::collections::HashMap::new();
        severity.insert("A".to_string(), Severity::Info);
        let config = Config {
            severity,
            ..Default::default()
        };
        let report = Report::build(vec![finding("A", Severity::Error)], &config);
        assert_eq!(report.findings[0].severity, Severity::Info);
        assert_eq!(report.summary.errors, 0);
        assert_eq!(report.summary.infos, 1);
    }

    #[test]
    fn min_severity_does_not_change_the_fail_gate() {
        // Hide warnings from display, but still fail on them.
        let config = Config {
            min_severity: Some(Severity::Error),
            fail_on: Some(Severity::Warning),
            ..Default::default()
        };
        let report = Report::build(vec![finding("A", Severity::Warning)], &config);
        assert!(report.findings.is_empty()); // hidden from display
        assert!(report.should_fail(&config)); // but still fails the build
    }

    #[test]
    fn should_fail_uses_threshold() {
        let warn_only = vec![finding("A", Severity::Warning)];
        let report = Report::build(warn_only, &Config::default());
        assert!(!report.should_fail(&Config::default())); // default threshold is error

        let strict = Config {
            fail_on: Some(Severity::Warning),
            ..Config::default()
        };
        assert!(report.should_fail(&strict));
    }
}
