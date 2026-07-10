//! Checks over a compiled iOS [`BinarySnapshot`].

use super::BinarySnapshot;
use preflight_core::{Category, CheckMeta, Confidence, Finding, Platform, Severity};

pub trait BinaryCheck: Sync {
    fn meta(&self) -> CheckMeta;
    fn run(&self, snap: &BinarySnapshot) -> Vec<Finding>;
}

pub fn registry() -> Vec<Box<dyn BinaryCheck>> {
    vec![
        Box::new(UiWebView),
        Box::new(PrivateFramework),
        Box::new(DebugEndpoints),
        Box::new(EmbeddedPrivacyManifest),
        Box::new(IdfaWithoutTracking),
        Box::new(AtsArbitraryLoads),
        Box::new(ProvisioningProfile),
    ]
}

pub fn all_meta() -> Vec<CheckMeta> {
    registry().iter().map(|c| c.meta()).collect()
}

// ---------------------------------------------------------------------------

/// IOS-BIN-001 — `UIWebView` is banned; apps referencing it are rejected.
struct UiWebView;

const UIWEBVIEW_META: CheckMeta = CheckMeta {
    id: "IOS-BIN-001",
    title: "Binary references the deprecated UIWebView",
    platform: Platform::Ios,
    category: Category::Binary,
    default_severity: Severity::Error,
    confidence: Confidence::Medium,
    guideline: Some("Apple: UIWebView removal"),
    docs_url: Some("https://developer.apple.com/news/?id=12232019b"),
};

impl BinaryCheck for UiWebView {
    fn meta(&self) -> CheckMeta {
        UIWEBVIEW_META
    }
    fn run(&self, snap: &BinarySnapshot) -> Vec<Finding> {
        if !snap.uses_uiwebview {
            return Vec::new();
        }
        vec![Finding::from_meta(
            &UIWEBVIEW_META,
            "The app binary references `UIWebView`, which Apple no longer accepts. \
             This often comes from an outdated third-party SDK.",
        )
        .remediation("Replace UIWebView with WKWebView and update any SDK that still bundles it.")]
    }
}

// ---------------------------------------------------------------------------

/// IOS-BIN-002 — Linking a private framework is a hard 2.5.1 rejection.
struct PrivateFramework;

const PRIVATE_FRAMEWORK_META: CheckMeta = CheckMeta {
    id: "IOS-BIN-002",
    title: "Binary links a private framework",
    platform: Platform::Ios,
    category: Category::Binary,
    default_severity: Severity::Error,
    confidence: Confidence::Medium,
    guideline: Some("2.5.1"),
    docs_url: Some(
        "https://developer.apple.com/app-store/review/guidelines/#software-requirements",
    ),
};

impl BinaryCheck for PrivateFramework {
    fn meta(&self) -> CheckMeta {
        PRIVATE_FRAMEWORK_META
    }
    fn run(&self, snap: &BinarySnapshot) -> Vec<Finding> {
        if snap.private_frameworks.is_empty() {
            return Vec::new();
        }
        vec![Finding::from_meta(
            &PRIVATE_FRAMEWORK_META,
            format!(
                "The binary references private framework(s): {}. Apple rejects use of \
                 non-public APIs under Guideline 2.5.1.",
                snap.private_frameworks.join(", ")
            ),
        )
        .remediation("Remove the dependency on the private framework or the SDK that links it.")]
    }
}

// ---------------------------------------------------------------------------

/// IOS-BIN-003 — Debug / local endpoints shipped in a release binary.
struct DebugEndpoints;

const DEBUG_ENDPOINTS_META: CheckMeta = CheckMeta {
    id: "IOS-BIN-003",
    title: "Debug or local network endpoints embedded in the binary",
    platform: Platform::Ios,
    category: Category::Binary,
    default_severity: Severity::Warning,
    confidence: Confidence::Low,
    guideline: None,
    docs_url: None,
};

impl BinaryCheck for DebugEndpoints {
    fn meta(&self) -> CheckMeta {
        DEBUG_ENDPOINTS_META
    }
    fn run(&self, snap: &BinarySnapshot) -> Vec<Finding> {
        if snap.debug_endpoints.is_empty() {
            return Vec::new();
        }
        vec![Finding::from_meta(
            &DEBUG_ENDPOINTS_META,
            format!(
                "The binary contains what look like debug/staging endpoints: {}. \
                 Make sure the release build points at production.",
                snap.debug_endpoints.join(", ")
            ),
        )]
    }
}

// ---------------------------------------------------------------------------

/// IOS-BIN-004 — The shipped bundle should contain a privacy manifest.
struct EmbeddedPrivacyManifest;

const EMBEDDED_PRIVACY_META: CheckMeta = CheckMeta {
    id: "IOS-BIN-004",
    title: "No privacy manifest in the app bundle",
    platform: Platform::Ios,
    category: Category::Privacy,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: Some("5.1.1"),
    docs_url: Some(
        "https://developer.apple.com/documentation/bundleresources/privacy_manifest_files",
    ),
};

impl BinaryCheck for EmbeddedPrivacyManifest {
    fn meta(&self) -> CheckMeta {
        EMBEDDED_PRIVACY_META
    }
    fn run(&self, snap: &BinarySnapshot) -> Vec<Finding> {
        if snap.has_privacy_manifest {
            return Vec::new();
        }
        vec![Finding::from_meta(
            &EMBEDDED_PRIVACY_META,
            "No PrivacyInfo.xcprivacy is bundled inside the compiled app. Apps using \
             required-reason APIs or common SDKs need one.",
        )
        .remediation("Add a privacy manifest to the app target and rebuild.")]
    }
}

// ---------------------------------------------------------------------------

/// IOS-BIN-005 — IDFA access without an App Tracking Transparency prompt.
struct IdfaWithoutTracking;

const IDFA_META: CheckMeta = CheckMeta {
    id: "IOS-BIN-005",
    title: "IDFA used without an App Tracking Transparency string",
    platform: Platform::Ios,
    category: Category::Privacy,
    default_severity: Severity::Error,
    confidence: Confidence::Medium,
    guideline: Some("5.1.2"),
    docs_url: Some("https://developer.apple.com/documentation/apptrackingtransparency"),
};

impl BinaryCheck for IdfaWithoutTracking {
    fn meta(&self) -> CheckMeta {
        IDFA_META
    }
    fn run(&self, snap: &BinarySnapshot) -> Vec<Finding> {
        if !snap.uses_idfa || snap.has_tracking_usage_description {
            return Vec::new();
        }
        vec![Finding::from_meta(
            &IDFA_META,
            "The binary references the advertising identifier (IDFA) but the bundle has no \
             `NSUserTrackingUsageDescription`. Apps that access the IDFA must request \
             permission via App Tracking Transparency.",
        )
        .remediation(
            "Add NSUserTrackingUsageDescription and call \
             ATTrackingManager.requestTrackingAuthorization before accessing the IDFA — or \
             remove the SDK that reads it.",
        )]
    }
}

// ---------------------------------------------------------------------------

/// IOS-BIN-006 — App Transport Security fully disabled.
struct AtsArbitraryLoads;

const ATS_META: CheckMeta = CheckMeta {
    id: "IOS-BIN-006",
    title: "App Transport Security disabled (NSAllowsArbitraryLoads)",
    platform: Platform::Ios,
    category: Category::Configuration,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: Some("2.5.1"),
    docs_url: Some(
        "https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity",
    ),
};

impl BinaryCheck for AtsArbitraryLoads {
    fn meta(&self) -> CheckMeta {
        ATS_META
    }
    fn run(&self, snap: &BinarySnapshot) -> Vec<Finding> {
        if !snap.ats_allows_arbitrary_loads {
            return Vec::new();
        }
        vec![Finding::from_meta(
            &ATS_META,
            "The bundle sets `NSAllowsArbitraryLoads = true`, disabling App Transport \
             Security globally. Apple requires justification for this and may reject it.",
        )
        .remediation(
            "Remove the global exception and scope any needed HTTP exceptions to specific \
             domains under NSExceptionDomains.",
        )]
    }
}

// ---------------------------------------------------------------------------

/// IOS-BIN-007 — Development / ad-hoc provisioning profile, not distribution.
struct ProvisioningProfile;

const PROVISIONING_META: CheckMeta = CheckMeta {
    id: "IOS-BIN-007",
    title: "Development / ad-hoc provisioning profile",
    platform: Platform::Ios,
    category: Category::Binary,
    default_severity: Severity::Warning,
    confidence: Confidence::High,
    guideline: None,
    docs_url: Some(
        "https://developer.apple.com/help/account/manage-profiles/create-a-distribution-profile",
    ),
};

impl BinaryCheck for ProvisioningProfile {
    fn meta(&self) -> CheckMeta {
        PROVISIONING_META
    }
    fn run(&self, snap: &BinarySnapshot) -> Vec<Finding> {
        // `get-task-allow` means a debuggable (dev) build — a hard problem for
        // the App Store; ProvisionedDevices means development/ad-hoc.
        if snap.provisioning_get_task_allow {
            return vec![Finding::from_meta(
                &PROVISIONING_META,
                "The embedded provisioning profile grants `get-task-allow` — this is a debuggable \
                 development build, not an App Store distribution build.",
            )
            .severity(Severity::Error)
            .remediation("Re-sign with an App Store distribution profile before submitting.")];
        }
        if snap.provisioning_has_devices {
            return vec![Finding::from_meta(
                &PROVISIONING_META,
                "The embedded provisioning profile lists specific devices, so this is a \
                 development or ad-hoc build rather than an App Store distribution build.",
            )
            .remediation("Re-sign with an App Store distribution profile before submitting.")];
        }
        Vec::new()
    }
}
