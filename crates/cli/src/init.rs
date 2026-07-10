//! `preflight init` — scaffold a `preflight.toml` and a CI workflow.

use anyhow::Result;
use std::path::Path;
use std::process::ExitCode;

const CONFIG_TEMPLATE: &str = r#"# preflight configuration. All fields are optional.

# Check ids to skip entirely. Run `preflight rules` to see all ids.
disabled_checks = []

# Hide findings below this severity: "info" | "warning" | "error".
# min_severity = "info"

# Exit non-zero at this severity or above. Defaults to "error".
# fail_on = "warning"

# Override the severity of specific checks.
# [severity]
# IOS-CONFIG-001 = "warning"
"#;

const WORKFLOW_TEMPLATE: &str = r#"name: preflight
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install --git https://github.com/ubadeaslan/app-preflight preflight-cli
      - run: preflight check . --format sarif > preflight.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: preflight.sarif
"#;

pub fn run() -> Result<ExitCode> {
    write_if_absent(Path::new("preflight.toml"), CONFIG_TEMPLATE)?;
    let workflow = Path::new(".github/workflows/preflight.yml");
    if let Some(parent) = workflow.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_if_absent(workflow, WORKFLOW_TEMPLATE)?;

    println!("\nDone. Next: run `preflight check .` to scan this project.");
    Ok(ExitCode::SUCCESS)
}

fn write_if_absent(path: &Path, contents: &str) -> Result<()> {
    if path.exists() {
        println!("  skip   {} (already exists)", path.display());
    } else {
        std::fs::write(path, contents)?;
        println!("  create {}", path.display());
    }
    Ok(())
}
