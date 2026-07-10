//! Permission classifications shared by the source-scan checks and the compiled
//! APK check, so an `.apk`-only scan surfaces the same permission findings as a
//! source scan.

/// Highly restricted permissions (SMS / Call-Log): Play only allows them for a
/// narrow set of app types and requires a Permissions Declaration.
pub(crate) const RESTRICTED: &[&str] = &[
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
];

/// Special-access permissions that each need a specific Play declaration.
pub(crate) const SPECIAL: &[(&str, &str)] = &[
    (
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "All files access is only permitted for specific app types and needs a Play declaration.",
    ),
    (
        "android.permission.SYSTEM_ALERT_WINDOW",
        "Drawing over other apps is restricted and heavily scrutinized by Play.",
    ),
    (
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "Installing packages requires a Play declaration and justification.",
    ),
    (
        "android.permission.PACKAGE_USAGE_STATS",
        "Usage-access is a sensitive, special-access permission.",
    ),
    (
        "android.permission.QUERY_ALL_PACKAGES",
        "Broad package visibility requires a Play declaration for most app types.",
    ),
];

/// Sensitive but commonly legitimate — flagged for the Data Safety form.
pub(crate) const SENSITIVE: &[&str] = &[
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS",
];
