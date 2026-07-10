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

### Prebuilt binaries

Download the archive for your platform from the
[latest release](https://github.com/ubadeaslan/app-preflight/releases/latest)
(Linux x86_64, macOS arm64/x86_64, Windows x86_64), extract it, and put
`preflight` on your `PATH`. Each archive ships with a `.sha256` you can verify.

### From source

Requires a [Rust toolchain](https://rustup.rs) (1.80+):

```sh
git clone https://github.com/ubadeaslan/app-preflight
cd app-preflight
cargo build --release
# binary at ./target/release/preflight

# or install straight from git:
cargo install --git https://github.com/ubadeaslan/app-preflight preflight-cli
```

## Usage

```sh
preflight init                    # scaffold preflight.toml + a CI workflow
preflight check [PATH]            # scan a project (defaults to current dir)
preflight check . --format json   # machine-readable output for CI/tools
preflight check . --format sarif  # SARIF for GitHub code scanning
preflight check . --fail-on warning
preflight rules                   # list every check preflight knows about

# Baseline: adopt on a project that isn't clean yet — fail only on NEW issues.
preflight check . --write-baseline                       # record current findings
preflight check . --baseline .preflight-baseline.json    # suppress those, fail on new
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
| `IOS-CONFIG-003`  | iOS | App Transport Security disabled in `Info.plist` (2.5.1) |
| `IOS-CONFIG-004`  | iOS | Legacy `NSLocationAlwaysUsageDescription` without the combined key |
| `IOS-PRIVACY-004` | iOS | Background location without an Always usage description |
| `IOS-LEGAL-001`   | iOS | Account creation with no in-app deletion path (Guideline 5.1.1(v)) |
| `IOS-LEGAL-002`   | iOS | Third-party/social login without Sign in with Apple (4.8) |
| `IOS-META-001`    | iOS | Missing privacy policy URL on the store listing (5.1.1) |
| `IOS-META-002`    | iOS | Missing support URL (1.5) |
| `IOS-META-003`    | iOS | Demo account required but no credentials provided (2.1) |
| `IOS-META-004`    | iOS | Empty / placeholder app description (2.3.7) |
| `IOS-META-005`    | iOS | No iPhone screenshots uploaded (2.3.3) |
| `IOS-META-006`    | iOS | Keyword list over the 100-character limit |
| `IOS-BIN-001`     | iOS | Compiled binary references the banned `UIWebView` |
| `IOS-BIN-002`     | iOS | Binary links a private framework (2.5.1) |
| `IOS-BIN-003`     | iOS | Debug / local endpoints embedded in the binary |
| `IOS-BIN-004`     | iOS | No `PrivacyInfo.xcprivacy` inside the built `.app` |
| `IOS-BIN-005`     | iOS | IDFA used without an App Tracking Transparency string (5.1.2) |
| `IOS-BIN-006`     | iOS | App Transport Security disabled (`NSAllowsArbitraryLoads`) |
| `ANDROID-CONFIG-001` | Android | `android:debuggable="true"` in the manifest |
| `ANDROID-CONFIG-002` | Android | `targetSdk` below Google Play's current minimum |
| `ANDROID-CONFIG-003` | Android | Cleartext (HTTP) traffic permitted |
| `ANDROID-CONFIG-004` | Android | Foreground service without a `foregroundServiceType` (Android 14) |
| `ANDROID-CONFIG-005` | Android | Component with intent-filter missing `android:exported` (Android 12) |
| `ANDROID-PRIVACY-002`| Android | Special permission needing a Play declaration (e.g. All files access) |
| `ANDROID-PRIVACY-001`| Android | Sensitive / restricted permissions needing a Play declaration |
| `ANDROID-META-001`   | Android | Missing / too-short full description |
| `ANDROID-META-002`   | Android | Title (>30) or short description (>80) missing or over limit |
| `ANDROID-META-003`   | Android | Fewer than two phone screenshots |
| `ANDROID-META-004`   | Android | Missing feature graphic |
| `ANDROID-META-005`   | Android | Missing high-res app icon on the listing |
| `ANDROID-META-006`   | Android | No contact details on the store listing |
| `ANDROID-BIN-001`    | Android | APK ships 32-bit native libs but no 64-bit ABI |
| `ANDROID-BIN-002`    | Android | Compiled (merged) manifest is `debuggable` |
| `ANDROID-BIN-003`    | Android | Compiled manifest `targetSdk` below Play minimum |
| `ANDROID-BIN-004`    | Android | Compiled manifest permits cleartext traffic |
| `ANDROID-DEX-001`    | Android | Dynamic code loading (`DexClassLoader`) in `classes*.dex` |
| `ANDROID-DEX-002`    | Android | Hard-coded secret (API key / AWS key / PEM) in the DEX |

The `IOS-META-*` and `ANDROID-META-*` checks talk to the App Store Connect /
Google Play APIs and only run when credentials are configured (see below);
everything else is offline. Run `preflight rules` for the live list.

## Scanning a compiled `.ipa` / `.apk`

Point `check` at a built artifact instead of a directory to inspect the compiled
binary — things you can only see post-build:

```sh
preflight check ./build/MyApp.ipa
preflight check ./app/release/app-release.apk
```

For iOS this unzips the IPA and inspects the Mach-O for `UIWebView` usage,
private-framework linkage, embedded debug endpoints, and a bundled privacy
manifest. For Android it checks the APK's native ABIs for the Google Play 64-bit
requirement, decodes the compiled (binary AXML) `AndroidManifest.xml` to verify
the *merged, shipped* manifest isn't debuggable, meets the target-SDK minimum,
and doesn't permit cleartext traffic, and byte-scans `classes*.dex` for dynamic
code loading and hard-coded secrets. (Full DEX method-graph analysis is a future
addition.)

## App Store Connect metadata scanning

`preflight` can also check your live store listing — privacy policy, support
URL, demo account, screenshots, description — by calling the App Store Connect
API. It authenticates with an API key you create under **App Store Connect >
Users and Access > Integrations > App Store Connect API**, signing a short-lived
ES256 JWT on each request. Credentials come from the environment so no secret
touches the repo:

```sh
export ASC_ISSUER_ID="your-issuer-id"
export ASC_KEY_ID="your-key-id"
export ASC_PRIVATE_KEY_PATH="/path/to/AuthKey_XXXX.p8"   # or ASC_PRIVATE_KEY with the contents inline
# Optional: override the bundle id (otherwise read from Info.plist)
export ASC_BUNDLE_ID="com.yourcompany.app"

preflight check .
```

If these aren't set, metadata checks are silently skipped — the rest of the scan
still runs. Use `--skip-metadata` to force-skip them even when configured (e.g.
in an offline CI job).

## Google Play metadata scanning

Likewise for Google Play, `preflight` can check your store listing —
description, title/short-description limits, screenshots, feature graphic, icon,
contact details — through the Android Publisher API. It authenticates with a
**service account** (Google Cloud) that has been granted access in the Play
Console, doing the OAuth2 JWT-bearer exchange for you. It opens a *read-only*
edit and abandons it, so it never changes your app.

```sh
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
# or inline: export GPLAY_SERVICE_ACCOUNT_JSON="$(cat service-account.json)"
# Optional: override the package name (otherwise read from applicationId / manifest)
export GPLAY_PACKAGE_NAME="com.yourcompany.app"

preflight check .
```

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

# Override the severity of specific checks.
[severity]
IOS-CONFIG-001 = "warning"
ANDROID-DEX-002 = "error"
```

`preflight init` writes a starter `preflight.toml` and a
`.github/workflows/preflight.yml` for you.

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

### Inline findings via code scanning

Emit SARIF and upload it so findings appear inline on the PR and in the
repository's **Security > Code scanning** tab:

```yaml
name: preflight
on: [pull_request]
permissions:
  contents: read
  security-events: write   # required to upload SARIF
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
