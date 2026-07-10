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
    /// Path to the project root (defaults to the current directory).
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Pretty)]
    format: Format,

    /// Exit non-zero at this severity or above (overrides preflight.toml).
    #[arg(long, value_enum)]
    fail_on: Option<Level>,
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

    let mut config = Config::load_from_dir(&root).map_err(anyhow::Error::msg)?;
    if let Some(level) = args.fail_on {
        config.fail_on = Some(level.into());
    }

    let mut raw = Vec::new();
    let mut scanned_any = false;

    if let Some(findings) = preflight_ios::analyze(&root, &config) {
        scanned_any = true;
        raw.extend(findings);
    }
    if let Some(findings) = preflight_android::analyze(&root, &config) {
        scanned_any = true;
        raw.extend(findings);
    }

    if !scanned_any {
        eprintln!(
            "No iOS or Android project found under {}.\n\
             Point preflight at the folder containing your Xcode project or Gradle build.",
            root.display()
        );
        return Ok(ExitCode::from(2));
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
