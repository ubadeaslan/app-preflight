//! Terminal rendering for reports and the rule catalog.

use preflight_core::{CheckMeta, Finding, Report, Severity};
use std::path::Path;

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
