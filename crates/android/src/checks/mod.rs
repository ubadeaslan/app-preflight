//! The registry of Android checks.

use crate::AndroidCheck;

mod backup;
mod cleartext;
mod debuggable;
mod exported;
mod exported_provider;
mod foreground_service;
mod network_security_config;
mod sensitive_permissions;
mod shared_user_id;
mod special_permissions;
mod target_sdk;
mod test_only;

pub fn registry() -> Vec<Box<dyn AndroidCheck>> {
    vec![
        Box::new(debuggable::DebuggableCheck),
        Box::new(target_sdk::TargetSdkCheck),
        Box::new(sensitive_permissions::SensitivePermissionsCheck),
        Box::new(cleartext::CleartextTrafficCheck),
        Box::new(foreground_service::ForegroundServiceTypeCheck),
        Box::new(exported::ExportedComponentCheck),
        Box::new(special_permissions::SpecialPermissionsCheck),
        Box::new(network_security_config::NetworkSecurityConfigCheck),
        Box::new(test_only::TestOnlyCheck),
        Box::new(exported_provider::ExportedProviderCheck),
        Box::new(backup::BackupRulesCheck),
        Box::new(shared_user_id::SharedUserIdCheck),
    ]
}
