# app-preflight

**Catch App Store & Google Play rejections *before* you submit.**

`preflight` is a fast, zero-config CLI that statically scans an iOS or Android
project and flags the things that most often trigger an Apple "red" (Metadata
Rejected / Guideline violation) or a Play upload block — empty permission purpose
strings, missing privacy manifests, debuggable release builds, out-of-date
target SDKs, placeholder bundle identifiers, and more.

It's built to live in your terminal and your CI, so a rejection reason shows up
in a pull request instead of three days into App Review.

```
$ preflight check ./MyApp

error [IOS-PRIVACY-002] Weak or empty permission purpose string
      `NSCameraUsageDescription` has an empty purpose string. iOS will crash
      when the permission is requested, and App Review rejects empty descriptions.
      at MyApp/Info.plist
      fix: Set NSCameraUsageDescription to a clear sentence describing exactly
           why the app needs this access.
      guideline 5.1.1

Summary: 4 error(s), 6 warning(s), 2 info
```

> **Status:** early, open source, and actively growing. The check catalog is the
> point — see [Contributing](#contributing) to add one in a single file.

---

## Why

Apple's review process can cost days per rejection round-trip, and most
rejections are for boring, mechanical, *detectable* reasons. `preflight` encodes
those reasons as checks so you never lose a review cycle to an empty
`NSPhotoLibraryUsageDescription` again.

## Install

Requires a [Rust toolchain](https://rustup.rs) (1.80+) for now; prebuilt
binaries are on the roadmap.

```sh
git clone https://github.com/ubadeaslan/app-preflight
cd app-preflight
cargo build --release
# binary at ./target/release/preflight
```

## Usage

```sh
preflight check [PATH]          # scan a project (defaults to current dir)
preflight check . --format json # machine-readable output for CI/tools
preflight check . --fail-on warning
preflight rules                 # list every check preflight knows about
```

`preflight` auto-detects whether the folder is an iOS project (`.xcodeproj`,
`Info.plist`, `Podfile`, `Package.swift`), an Android project (`build.gradle`,
`AndroidManifest.xml`), or both, and runs the relevant checks.

**Exit codes:** `0` clean · `1` findings at/above the fail threshold (default:
`error`) · `2` usage / no project found.

## What it checks today

| ID | Platform | What it catches |
|----|----------|-----------------|
| `IOS-PRIVACY-001` | iOS | Missing `PrivacyInfo.xcprivacy` privacy manifest |
| `IOS-PRIVACY-002` | iOS | Empty / placeholder / too-short permission purpose strings |
| `IOS-CONFIG-001`  | iOS | Missing `ITSAppUsesNonExemptEncryption` (export-compliance prompt every build) |
| `IOS-CONFIG-002`  | iOS | Missing version string / placeholder bundle identifier |
| `IOS-LEGAL-001`   | iOS | Account creation with no in-app deletion path (Guideline 5.1.1(v)) |
| `ANDROID-CONFIG-001` | Android | `android:debuggable="true"` in the manifest |
| `ANDROID-CONFIG-002` | Android | `targetSdk` below Google Play's current minimum |
| `ANDROID-CONFIG-003` | Android | Cleartext (HTTP) traffic permitted |
| `ANDROID-PRIVACY-001`| Android | Sensitive / restricted permissions needing a Play declaration |

Run `preflight rules` for the live list. The roadmap adds **store-metadata**
checks (via the App Store Connect / Play Developer APIs) and **compiled-binary**
checks (private-API usage and embedded strings inside an `.ipa` / `.apk`).

## Configuration

Everything works with zero config. To tune, drop a `preflight.toml` at the
project root:

```toml
# Skip checks that don't apply to your app.
disabled_checks = ["IOS-CONFIG-001"]

# Hide findings below this severity: info | warning | error
min_severity = "info"

# Fail the process at this severity or above (default: error).
fail_on = "warning"
```

## CI / GitHub Actions

Fail a pull request when a new rejection risk is introduced:

```yaml
# .github/workflows/preflight.yml
name: preflight
on: [pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install --git https://github.com/ubadeaslan/app-preflight preflight-cli
      - run: preflight check . --fail-on warning
```

## Architecture

A small Cargo workspace:

```
crates/
  core/      Finding, Severity, Category, Report, Config — the shared vocabulary
  ios/       IosProject loader + one file per iOS check
  android/   AndroidProject loader + one file per Android check
  cli/       the `preflight` binary (argument parsing + rendering)
```

A **check** is deliberately tiny: a `CheckMeta` constant (id, title, guideline,
docs link, default severity) plus a `run()` that returns `Finding`s. Platform
crates load the project once and hand each check a parsed model, so a check never
touches the filesystem or parses XML/plist itself.

## Contributing

New checks are the most valuable contribution, and they're meant to be a
15-minute job:

1. Copy an existing file in `crates/ios/src/checks/` or
   `crates/android/src/checks/`.
2. Give it a new `CheckMeta` (id, guideline reference, docs URL).
3. Implement `run()` against the `IosProject` / `AndroidProject` model.
4. Register it in the crate's `checks/mod.rs`.
5. Add a fixture under `examples/` and a test.

Please cite the specific Apple guideline number or Play policy in the check's
`guideline`/`docs_url` so findings are actionable and defensible.

## License

Dual-licensed under either [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
