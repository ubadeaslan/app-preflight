# Checks

app-preflight ships 54 checks. Regenerate this file with `preflight rules --format markdown > CHECKS.md`.

## iOS (28)

| ID | Severity | Category | Guideline | Check |
|----|----------|----------|-----------|-------|
| `IOS-BIN-001` | error | binary | Apple: UIWebView removal | Binary references the deprecated UIWebView |
| `IOS-BIN-002` | error | binary | 2.5.1 | Binary links a private framework |
| `IOS-BIN-003` | warning | binary |  | Debug or local network endpoints embedded in the binary |
| `IOS-BIN-004` | warning | privacy | 5.1.1 | No privacy manifest in the app bundle |
| `IOS-BIN-005` | error | privacy | 5.1.2 | IDFA used without an App Tracking Transparency string |
| `IOS-BIN-006` | warning | configuration | 2.5.1 | App Transport Security disabled (NSAllowsArbitraryLoads) |
| `IOS-BIN-007` | warning | binary |  | Development / ad-hoc provisioning profile |
| `IOS-CONFIG-001` | warning | configuration | Export Compliance | Missing export-compliance encryption declaration |
| `IOS-CONFIG-002` | warning | configuration |  | Version keys / bundle identifier issues |
| `IOS-CONFIG-003` | warning | configuration | 2.5.1 | App Transport Security disabled (NSAllowsArbitraryLoads) |
| `IOS-CONFIG-004` | warning | configuration | 5.1.1 | Legacy location key without the combined authorization key |
| `IOS-CONFIG-005` | warning | configuration |  | aps-environment set to development |
| `IOS-CONFIG-006` | error | configuration | 2.5.1 | get-task-allow enabled (debuggable entitlement) |
| `IOS-CONFIG-007` | warning | configuration | 2.5.1 | Insecure App Transport Security exception domain |
| `IOS-CONFIG-008` | warning | configuration |  | LSApplicationQueriesSchemes exceeds the 50-entry limit |
| `IOS-CONFIG-009` | warning | configuration |  | Legacy calendar key without the iOS 17 full-access key |
| `IOS-CONFIG-010` | warning | configuration |  | iCloud container set to the Development environment |
| `IOS-LEGAL-001` | info | legal | 5.1.1(v) | Account creation without visible deletion path |
| `IOS-LEGAL-002` | info | legal | 4.8 | Third-party login without Sign in with Apple |
| `IOS-META-001` | error | metadata | 5.1.1 | Missing privacy policy URL |
| `IOS-META-002` | error | metadata | 1.5 | Missing support URL |
| `IOS-META-003` | error | metadata | 2.1 | Demo account required but not provided |
| `IOS-META-004` | warning | metadata | 2.3.7 | Weak or missing app description |
| `IOS-META-005` | error | metadata | 2.3.3 | No iPhone screenshots uploaded |
| `IOS-META-006` | warning | metadata |  | Keyword list exceeds 100 characters |
| `IOS-PRIVACY-001` | warning | privacy | 5.1.1 | Missing privacy manifest (PrivacyInfo.xcprivacy) |
| `IOS-PRIVACY-002` | error | privacy | 5.1.1 | Weak or empty permission purpose string |
| `IOS-PRIVACY-004` | error | privacy | 5.1.1 | Background location without an Always usage description |

## Android (26)

| ID | Severity | Category | Guideline | Check |
|----|----------|----------|-----------|-------|
| `ANDROID-BIN-001` | error | binary | Play: 64-bit requirement | Missing 64-bit native libraries |
| `ANDROID-BIN-002` | error | binary | Play: Device and Network Abuse | Compiled manifest is debuggable |
| `ANDROID-BIN-003` | error | binary | Play: Target API level | Compiled targetSdk below Google Play minimum |
| `ANDROID-BIN-004` | warning | binary | Play: User Data | Compiled manifest permits cleartext traffic |
| `ANDROID-BIN-005` | error | binary | Play: Upload requirements | Compiled manifest is marked testOnly |
| `ANDROID-CONFIG-001` | error | configuration | Play: Device and Network Abuse | Application is marked debuggable |
| `ANDROID-CONFIG-002` | error | configuration | Play: Target API level | targetSdk below Google Play minimum |
| `ANDROID-CONFIG-003` | warning | configuration | Play: User Data | Cleartext network traffic is permitted |
| `ANDROID-CONFIG-004` | warning | configuration | Android 14: Foreground service types | Foreground service without a foregroundServiceType |
| `ANDROID-CONFIG-005` | error | configuration | Android 12: explicit exported | Component with intent-filter missing android:exported |
| `ANDROID-CONFIG-006` | warning | configuration | Play: User Data | Network security config permits cleartext traffic |
| `ANDROID-CONFIG-007` | error | configuration | Play: Upload requirements | Application is marked testOnly |
| `ANDROID-CONFIG-008` | warning | configuration | Play: User Data | Exported content provider without a permission |
| `ANDROID-CONFIG-009` | warning | configuration |  | Deprecated android:sharedUserId |
| `ANDROID-DEX-001` | warning | binary | Play: Device and Network Abuse | Dynamic code loading (DexClassLoader) |
| `ANDROID-DEX-002` | warning | binary |  | Hard-coded secret in the compiled code |
| `ANDROID-DEX-003` | warning | binary | Play: non-SDK interface restrictions | Restricted / non-SDK (hidden) API reference |
| `ANDROID-META-001` | warning | metadata | Play: Store listing | Missing or too-short full description |
| `ANDROID-META-002` | warning | metadata | Play: Store listing | Title or short description missing / over limit |
| `ANDROID-META-003` | error | metadata | Play: Store listing | Fewer than two phone screenshots |
| `ANDROID-META-004` | error | metadata | Play: Store listing | Missing feature graphic |
| `ANDROID-META-005` | error | metadata | Play: Store listing | Missing high-res app icon on listing |
| `ANDROID-META-006` | warning | metadata | Play: Store listing | No contact details on the store listing |
| `ANDROID-PRIVACY-001` | warning | privacy | Play: Permissions and APIs that Access Sensitive Info | Sensitive permission requires Play policy declaration |
| `ANDROID-PRIVACY-002` | warning | privacy | Play: Permissions declaration | Special permission requiring a Play declaration |
| `ANDROID-PRIVACY-003` | info | privacy | Play: Data safety | Backup enabled without backup rules |
