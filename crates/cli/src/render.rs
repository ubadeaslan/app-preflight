//! Terminal rendering for reports and the rule catalog.

use preflight_core::{CheckMeta, Finding, Report, Severity};
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;

/// SARIF severity levels: info maps to "note".
fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

/// A path relative to the scan root, with `/` separators (SARIF URIs).
fn relative_uri(file: &Path, root: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Render the report as SARIF 2.1.0 for GitHub code scanning and other tools.
pub fn sarif(report: &Report, root: &Path) -> String {
    let mut metas: Vec<CheckMeta> = preflight_ios::all_check_meta();
    metas.extend(preflight_android::all_check_meta());

    let mut index_of: HashMap<&str, usize> = HashMap::new();
    let rules: Vec<_> = metas
        .iter()
        .enumerate()
        .map(|(i, m)| {
            index_of.insert(m.id, i);
            let mut rule = json!({
                "id": m.id,
                "name": m.title,
                "shortDescription": { "text": m.title },
                "defaultConfiguration": { "level": sarif_level(m.default_severity) },
                "properties": { "category": m.category.as_str(), "platform": m.platform.as_str() },
            });
            if let Some(u) = m.docs_url {
                rule["helpUri"] = json!(u);
            }
            rule
        })
        .collect();

    let results: Vec<_> = report
        .findings
        .iter()
        .map(|f| {
            let mut result = json!({
                "ruleId": f.check_id,
                "level": sarif_level(f.severity),
                "message": { "text": f.message },
            });
            if let Some(idx) = index_of.get(f.check_id.as_str()) {
                result["ruleIndex"] = json!(idx);
            }
            if let Some(loc) = &f.location {
                let mut physical = json!({
                    "artifactLocation": { "uri": relative_uri(&loc.file, root) }
                });
                if let Some(line) = loc.line {
                    physical["region"] = json!({ "startLine": line });
                }
                result["locations"] = json!([{ "physicalLocation": physical }]);
            }
            result
        })
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "app-preflight",
                "informationUri": "https://github.com/ubadeaslan/app-preflight",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules,
            }},
            "results": results,
        }],
    });

    serde_json::to_string_pretty(&doc).expect("serialize sarif")
}

// Minimal ANSI styling. Modern Windows terminals (Windows 10+) support these.
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const GREEN: &str = "\x1b[32m";

fn sev_color(sev: Severity) -> &'static str {
    match sev {
        Severity::Error => RED,
        Severity::Warning => YELLOW,
        Severity::Info => BLUE,
    }
}

fn sev_label(sev: Severity) -> &'static str {
    match sev {
        Severity::Error => "error",
        Severity::Warning => "warn ",
        Severity::Info => "info ",
    }
}

pub fn print_pretty(report: &Report, root: &Path) {
    println!(
        "\n{BOLD}app-preflight{RESET} {DIM}— {}{RESET}\n",
        root.display()
    );

    if report.is_empty() {
        println!("{GREEN}✓ No issues found. Cleared for submission.{RESET}\n");
        return;
    }

    for f in &report.findings {
        print_finding(f);
    }

    let s = &report.summary;
    println!(
        "{BOLD}Summary:{RESET} {RED}{} error(s){RESET}, {YELLOW}{} warning(s){RESET}, {BLUE}{} info{RESET}\n",
        s.errors, s.warnings, s.infos
    );
}

fn print_finding(f: &Finding) {
    let color = sev_color(f.severity);
    println!(
        "{color}{BOLD}{}{RESET} {DIM}[{}]{RESET} {}",
        sev_label(f.severity),
        f.check_id,
        f.title
    );
    println!("      {}", f.message);
    if let Some(loc) = &f.location {
        let line = loc.line.map(|l| format!(":{l}")).unwrap_or_default();
        println!("      {DIM}at {}{}{RESET}", loc.file.display(), line);
    }
    if let Some(rem) = &f.remediation {
        println!("      {GREEN}fix:{RESET} {rem}");
    }
    if let Some(g) = &f.guideline {
        let docs = f
            .docs_url
            .as_deref()
            .map(|u| format!(" — {u}"))
            .unwrap_or_default();
        println!("      {DIM}guideline {g}{docs}{RESET}");
    } else if let Some(u) = &f.docs_url {
        println!("      {DIM}{u}{RESET}");
    }
    println!();
}

pub fn print_rules(json: bool) {
    let mut metas: Vec<CheckMeta> = preflight_ios::all_check_meta();
    metas.extend(preflight_android::all_check_meta());
    metas.sort_by(|a, b| a.id.cmp(b.id));

    if json {
        let arr: Vec<_> = metas
            .iter()
            .map(|m| {
                serde_json::json!({
                    "id": m.id,
                    "title": m.title,
                    "platform": m.platform.as_str(),
                    "category": m.category.as_str(),
                    "default_severity": m.default_severity.as_str(),
                    "guideline": m.guideline,
                    "docs_url": m.docs_url,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&arr).expect("serialize rules")
        );
        return;
    }

    println!("\n{BOLD}Registered checks ({}){RESET}\n", metas.len());
    for m in &metas {
        let color = sev_color(m.default_severity);
        println!(
            "  {color}{}{RESET} {DIM}({}/{}){RESET}  {}",
            m.id,
            m.platform.as_str(),
            m.category.as_str(),
            m.title
        );
    }
    println!();
}
