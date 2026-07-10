//! The registry of Android checks.

use crate::AndroidCheck;

mod cleartext;
mod debuggable;
mod foreground_service;
mod sensitive_permissions;
mod target_sdk;

pub fn registry() -> Vec<Box<dyn AndroidCheck>> {
    vec![
        Box::new(debuggable::DebuggableCheck),
        Box::new(target_sdk::TargetSdkCheck),
        Box::new(sensitive_permissions::SensitivePermissionsCheck),
        Box::new(cleartext::CleartextTrafficCheck),
        Box::new(foreground_service::ForegroundServiceTypeCheck),
    ]
}
