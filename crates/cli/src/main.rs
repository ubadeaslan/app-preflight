//! `preflight` — pre-submission checker for mobile apps.

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
}

#[derive(Args)]
struct CheckArgs {
    /// Project directory, or a compiled .ipa / .apk file (defaults to the
    /// current directory).
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
            render::print_rules(matches!(args.format, Format::Json));
            Ok(ExitCode::SUCCESS)
        }
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
        _ => {
            eprintln!(
                "Unsupported file '{}'. Pass a project directory, or an .ipa / .apk file.",
                path.display()
            );
            return Ok(ExitCode::from(2));
        }
    };

    let mut config =
        Config::load_from_dir(path.parent().unwrap_or(path)).map_err(anyhow::Error::msg)?;
    if let Some(level) = args.fail_on {
        config.fail_on = Some(level.into());
    }

    let report = Report::build(findings, &config);
    let fail = report.should_fail(&config);
    match args.format {
        Format::Pretty => render::print_pretty(&report, path),
        Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }
    Ok(if fail {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// On Windows, `canonicalize` returns a `\\?\C:\...` verbatim path that looks
/// noisy in reports. Strip the prefix for display and downstream walking.
fn strip_verbatim(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path
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

    let report = Report::build(raw, &config);
    let fail = report.should_fail(&config);

    match args.format {
        Format::Pretty => render::print_pretty(&report, &root),
        Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }

    Ok(if fail {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}
