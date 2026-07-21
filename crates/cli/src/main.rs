//! `preflight` — pre-submission checker for mobile apps.

mod baseline;
mod init;
mod render;

use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use preflight_core::{Config, Report};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "preflight",
    version,
    about = "Check an iOS/Android project for App Store & Play rejection reasons before you ship."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a project directory and report issues.
    Check(CheckArgs),
    /// List every check preflight knows about.
    Rules(RulesArgs),
    /// Explain a single check by id, e.g. `preflight explain IOS-CONFIG-007`.
    Explain(ExplainArgs),
    /// Scaffold a preflight.toml and a CI workflow.
    Init,
    /// Dry-run an App Store review submission and report every blocker Apple
    /// lists (availability, pricing, age rating, ...). Creates a draft
    /// submission on App Store Connect and rolls it back; refuses to run if a
    /// real submission is already in progress. Needs ASC_* credentials.
    SubmitSim(SubmitSimArgs),
}

#[derive(Args)]
struct SubmitSimArgs {
    /// Project directory (used to detect the bundle id when ASC_BUNDLE_ID is
    /// not set).
    #[arg(default_value = ".")]
    path: PathBuf,
}

#[derive(Args)]
struct ExplainArgs {
    /// The check id (case-insensitive), e.g. `ANDROID-CONFIG-006`.
    id: String,
}

#[derive(Args)]
struct CheckArgs {
    /// Project directory, or a compiled .ipa / .apk / .aab file (defaults to
    /// the current directory).
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Pretty)]
    format: Format,

    /// Exit non-zero at this severity or above (overrides preflight.toml).
    #[arg(long, value_enum)]
    fail_on: Option<Level>,

    /// Skip the App Store Connect metadata scan even if credentials are set.
    #[arg(long)]
    skip_metadata: bool,

    /// Suppress findings already recorded in this baseline file (so only new
    /// issues are reported). Defaults to `.preflight-baseline.json` when the
    /// flag is given without a path.
    #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = baseline::DEFAULT_PATH)]
    baseline: Option<PathBuf>,

    /// Write the current findings to the baseline file and exit 0.
    #[arg(long)]
    write_baseline: bool,
}

#[derive(Args)]
struct RulesArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Pretty)]
    format: Format,
}

#[derive(Copy, Clone, ValueEnum)]
enum Format {
    Pretty,
    Json,
    /// SARIF 2.1.0 for GitHub code scanning and other tools.
    Sarif,
    /// Markdown, e.g. for a GitHub job summary or PR comment.
    Markdown,
}

#[derive(Copy, Clone, ValueEnum)]
enum Level {
    Info,
    Warning,
    Error,
}

impl From<Level> for preflight_core::Severity {
    fn from(l: Level) -> Self {
        match l {
            Level::Info => preflight_core::Severity::Info,
            Level::Warning => preflight_core::Severity::Warning,
            Level::Error => preflight_core::Severity::Error,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Check(args) => run_check(args),
        Command::Rules(args) => {
            match args.format {
                Format::Markdown => print!("{}", render::rules_markdown()),
                Format::Json => render::print_rules(true),
                _ => render::print_rules(false),
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Explain(args) => match render::explain(&args.id) {
            Some(text) => {
                print!("{text}");
                Ok(ExitCode::SUCCESS)
            }
            None => {
                eprintln!(
                    "Unknown check id `{}`. Run `preflight rules` to list them.",
                    args.id
                );
                Ok(ExitCode::from(2))
            }
        },
        Command::Init => init::run(),
        Command::SubmitSim(args) => run_submit_sim(args),
    };

    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

/// Run the optional remote metadata scans (App Store Connect + Google Play) and
/// fold their findings into `raw`. Failures are surfaced as warnings on stderr
/// rather than aborting — a flaky network shouldn't block source-scan results.
fn run_metadata_scan(
    root: &std::path::Path,
    config: &Config,
    ios_present: bool,
    android_present: bool,
    raw: &mut Vec<preflight_core::Finding>,
) {
    handle_scan(
        preflight_ios::analyze_metadata(root, config),
        ios_present,
        "App Store Connect",
        "no concrete bundle id was found — set ASC_BUNDLE_ID",
        "set ASC_ISSUER_ID, ASC_KEY_ID and ASC_PRIVATE_KEY(_PATH) to also check your App Store \
         listing (privacy policy, demo account, screenshots)",
        raw,
    );
    handle_scan(
        preflight_android::analyze_metadata(root, config),
        android_present,
        "Google Play",
        "no package name was found — set GPLAY_PACKAGE_NAME",
        "set GOOGLE_APPLICATION_CREDENTIALS (service account JSON) to also check your Play \
         listing (description, screenshots, feature graphic)",
        raw,
    );
}

/// Fold one platform's [`MetadataScan`] outcome into `raw`, emitting the right
/// warning or hint on stderr.
fn handle_scan(
    scan: preflight_core::MetadataScan,
    present: bool,
    label: &str,
    no_target_hint: &str,
    skipped_hint: &str,
    raw: &mut Vec<preflight_core::Finding>,
) {
    use preflight_core::MetadataScan;
    match scan {
        MetadataScan::Done(findings) => raw.extend(findings),
        MetadataScan::Failed(msg) => eprintln!("warning: {label} metadata scan failed: {msg}"),
        MetadataScan::NoTarget => {
            eprintln!("warning: {label} credentials are set but {no_target_hint}.");
        }
        MetadataScan::Skipped => {
            if present {
                eprintln!("hint: {skipped_hint}.");
            }
        }
    }
}

/// Analyze a single compiled artifact (`.ipa` or `.apk`) instead of a project
/// directory.
fn run_binary_check(path: &std::path::Path, args: &CheckArgs) -> Result<ExitCode> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let findings = match ext.as_str() {
        "ipa" => preflight_ios::analyze_binary(path)?,
        "apk" => preflight_android::analyze_binary(path)?,
        "aab" => preflight_android::analyze_bundle(path)?,
        _ => {
            eprintln!(
                "Unsupported file '{}'. Pass a project directory, or an .ipa / .apk / .aab file.",
                path.display()
            );
            return Ok(ExitCode::from(2));
        }
    };

    let parent = path.parent().unwrap_or(path);
    let mut config = Config::load_from_dir(parent).map_err(anyhow::Error::msg)?;
    if let Some(level) = args.fail_on {
        config.fail_on = Some(level.into());
    }

    // Honor the baseline flags for artifact scans too (findings have no file
    // locations, so entries are keyed by check id + message).
    let mut findings = findings;
    if args.write_baseline {
        let report = Report::build(findings, &config);
        let bpath = args
            .baseline
            .clone()
            .unwrap_or_else(|| PathBuf::from(baseline::DEFAULT_PATH));
        let n = baseline::write(&bpath, &report.findings, parent)?;
        eprintln!("Wrote {n} finding(s) to baseline {}", bpath.display());
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(bpath) = &args.baseline {
        if bpath.exists() {
            baseline::suppress(bpath, &mut findings, parent)?;
        }
    }

    let report = Report::build(findings, &config);
    let fail = report.should_fail(&config);
    match args.format {
        Format::Pretty => render::print_pretty(&report, path),
        Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        Format::Sarif => println!("{}", render::sarif(&report, path)),
        Format::Markdown => println!("{}", render::markdown(&report, path)),
    }
    Ok(if fail {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// Warn (on stderr) when `preflight.toml` references a check id that doesn't
/// exist — usually a typo that would otherwise be silently ignored.
fn warn_unknown_config_ids(config: &Config) {
    let mut known = std::collections::HashSet::new();
    for m in preflight_ios::all_check_meta() {
        known.insert(m.id);
    }
    for m in preflight_android::all_check_meta() {
        known.insert(m.id);
    }
    let referenced = config
        .disabled_checks
        .iter()
        .chain(config.severity.keys())
        .map(String::as_str);
    for id in referenced {
        if !known.contains(id) {
            eprintln!("warning: preflight.toml references unknown check id `{id}`");
        }
    }
}

/// On Windows, `canonicalize` returns a `\\?\C:\...` verbatim path that looks
/// noisy in reports. Strip the prefix for display and downstream walking, while
/// keeping UNC paths (`\\?\UNC\server\share` → `\\server\share`) valid.
fn strip_verbatim(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path
    }
}

/// `preflight submit-sim` — dry-run an App Store review submission. Talks to
/// (and briefly writes to) App Store Connect, so it is its own command and
/// never part of `preflight check`.
fn run_submit_sim(args: SubmitSimArgs) -> Result<ExitCode> {
    use preflight_ios::metadata::SubmitSimOutcome;
    use preflight_ios::SubmitSimScan;

    let root = strip_verbatim(
        args.path
            .canonicalize()
            .with_context(|| format!("cannot access path {}", args.path.display()))?,
    );
    let config = Config::load_from_dir(&root).map_err(anyhow::Error::msg)?;

    eprintln!("Simulating an App Store review submission (the draft is rolled back)...");
    match preflight_ios::submit_simulation(&root, &config) {
        SubmitSimScan::Skipped => {
            eprintln!(
                "error: App Store Connect credentials are not set — set ASC_ISSUER_ID, \
                 ASC_KEY_ID and ASC_PRIVATE_KEY(_PATH)."
            );
            Ok(ExitCode::from(2))
        }
        SubmitSimScan::NoTarget => {
            eprintln!("error: no concrete bundle id was found — set ASC_BUNDLE_ID.");
            Ok(ExitCode::from(2))
        }
        SubmitSimScan::Failed(msg) => {
            eprintln!("error: submit simulation failed: {msg}");
            Ok(ExitCode::from(2))
        }
        SubmitSimScan::Done(report) => {
            if let Some(warning) = &report.cleanup_warning {
                eprintln!("warning: {warning}");
            }
            match report.outcome {
                SubmitSimOutcome::InProgress { state } => {
                    println!(
                        "A review submission already exists (state: {state}). Simulation \
                         skipped — it never touches a live submission."
                    );
                    Ok(ExitCode::SUCCESS)
                }
                SubmitSimOutcome::NoVersion => {
                    eprintln!(
                        "error: the app has no App Store version yet — create one in App \
                         Store Connect first."
                    );
                    Ok(ExitCode::from(2))
                }
                SubmitSimOutcome::Clean => {
                    println!(
                        "Clean: Apple accepted the draft submission item — nothing blocks a \
                         real submission. (Draft rolled back.)"
                    );
                    Ok(ExitCode::SUCCESS)
                }
                SubmitSimOutcome::Blocked { errors } => {
                    println!("Apple lists {} submission blocker(s):", errors.len());
                    for e in &errors {
                        println!("  - {e}");
                    }
                    Ok(ExitCode::FAILURE)
                }
            }
        }
    }
}

fn run_check(args: CheckArgs) -> Result<ExitCode> {
    let root = strip_verbatim(
        args.path
            .canonicalize()
            .with_context(|| format!("cannot access path {}", args.path.display()))?,
    );

    // A file input is a compiled artifact (.ipa/.apk); a directory is a project.
    if root.is_file() {
        return run_binary_check(&root, &args);
    }

    let mut config = Config::load_from_dir(&root).map_err(anyhow::Error::msg)?;
    if let Some(level) = args.fail_on {
        config.fail_on = Some(level.into());
    }
    warn_unknown_config_ids(&config);

    let mut raw = Vec::new();
    let mut ios_present = false;
    let mut android_present = false;

    if let Some(findings) = preflight_ios::analyze(&root, &config) {
        ios_present = true;
        raw.extend(findings);
    }
    if let Some(findings) = preflight_android::analyze(&root, &config) {
        android_present = true;
        raw.extend(findings);
    }

    if !ios_present && !android_present {
        eprintln!(
            "No iOS or Android project found under {}.\n\
             Point preflight at the folder containing your Xcode project or Gradle build.",
            root.display()
        );
        return Ok(ExitCode::from(2));
    }

    if !args.skip_metadata {
        run_metadata_scan(&root, &config, ios_present, android_present, &mut raw);
    }

    // Baseline: record current findings and exit, or suppress known ones.
    if args.write_baseline {
        let report = Report::build(raw, &config);
        let path = args
            .baseline
            .clone()
            .unwrap_or_else(|| PathBuf::from(baseline::DEFAULT_PATH));
        let n = baseline::write(&path, &report.findings, &root)?;
        eprintln!("Wrote {n} finding(s) to baseline {}", path.display());
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(bpath) = &args.baseline {
        if bpath.exists() {
            let suppressed = baseline::suppress(bpath, &mut raw, &root)?;
            if suppressed > 0 {
                eprintln!(
                    "Suppressed {suppressed} finding(s) via baseline {}",
                    bpath.display()
                );
            }
        }
    }

    let report = Report::build(raw, &config);
    let fail = report.should_fail(&config);

    match args.format {
        Format::Pretty => render::print_pretty(&report, &root),
        Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        Format::Sarif => println!("{}", render::sarif(&report, &root)),
        Format::Markdown => println!("{}", render::markdown(&report, &root)),
    }

    Ok(if fail {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}
