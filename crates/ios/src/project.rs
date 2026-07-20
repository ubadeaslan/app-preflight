//! Locating and parsing an iOS project on disk.

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Directories that never contain first-party source worth scanning.
const PRUNED_DIRS: &[&str] = &[
    ".git",
    "Pods",
    "Carthage",
    "DerivedData",
    "build",
    ".build",
    "node_modules",
    ".swiftpm",
];

/// A parsed iOS project. `load` returns `None` when `root` does not look like an
/// iOS project at all, so the CLI can report "no iOS project found" cleanly.
pub struct IosProject {
    pub root: PathBuf,
    /// The primary `Info.plist` (app target, not tests/pods), if one was found.
    pub info_plist_path: Option<PathBuf>,
    pub info_plist: Option<plist::Dictionary>,
    /// All `*.xcprivacy` privacy manifests discovered.
    pub privacy_manifests: Vec<PathBuf>,
    /// All `*.entitlements` files discovered.
    pub entitlement_files: Vec<PathBuf>,
    /// The primary `*.entitlements` file (app target), if one was found.
    pub entitlements_path: Option<PathBuf>,
    /// The parsed primary entitlements plist.
    pub entitlements: Option<plist::Dictionary>,
    /// First-party source files (`.swift`, `.m`, `.mm`) for content heuristics.
    pub source_files: Vec<PathBuf>,
    /// The primary `project.pbxproj` (app project, not pods), if one was found.
    pub pbxproj_path: Option<PathBuf>,
    /// Raw text of the primary `project.pbxproj`.
    pub pbxproj: Option<String>,
}

impl IosProject {
    pub fn load(root: &Path) -> Option<Self> {
        let mut has_project_marker = false;
        let mut info_plists: Vec<PathBuf> = Vec::new();
        let mut privacy_manifests = Vec::new();
        let mut entitlement_files: Vec<PathBuf> = Vec::new();
        let mut source_files = Vec::new();
        let mut pbxprojs: Vec<PathBuf> = Vec::new();

        for entry in WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| !is_pruned(e.path()))
            .flatten()
        {
            let path = entry.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };

            if entry.file_type().is_dir() {
                if name.ends_with(".xcodeproj") || name.ends_with(".xcworkspace") {
                    has_project_marker = true;
                }
                continue;
            }

            if name == "Info.plist" {
                info_plists.push(path.to_path_buf());
            } else if name == "project.pbxproj" {
                pbxprojs.push(path.to_path_buf());
            } else if name == "Podfile" || name == "Package.swift" {
                has_project_marker = true;
            } else if name.ends_with(".xcprivacy") {
                privacy_manifests.push(path.to_path_buf());
            } else if name.ends_with(".entitlements") {
                entitlement_files.push(path.to_path_buf());
            } else if name.ends_with(".swift") || name.ends_with(".m") || name.ends_with(".mm") {
                source_files.push(path.to_path_buf());
            }
        }

        if !has_project_marker && info_plists.is_empty() {
            return None;
        }

        let info_plist_path = pick_primary(&info_plists);
        let info_plist = info_plist_path
            .as_deref()
            .and_then(|p| plist::Value::from_file(p).ok())
            .and_then(|v| v.into_dictionary());

        let entitlements_path = pick_primary(&entitlement_files);
        let entitlements = entitlements_path
            .as_deref()
            .and_then(|p| plist::Value::from_file(p).ok())
            .and_then(|v| v.into_dictionary());

        let pbxproj_path = pick_primary(&pbxprojs);
        let pbxproj = pbxproj_path
            .as_deref()
            .and_then(|p| std::fs::read_to_string(p).ok());

        Some(IosProject {
            root: root.to_path_buf(),
            info_plist_path,
            info_plist,
            privacy_manifests,
            entitlement_files,
            entitlements_path,
            entitlements,
            source_files,
            pbxproj_path,
            pbxproj,
        })
    }

    /// Read a top-level value from the primary entitlements plist.
    pub fn entitlement(&self, key: &str) -> Option<&plist::Value> {
        self.entitlements.as_ref()?.get(key)
    }

    /// Read a top-level string value from the primary `Info.plist`.
    pub fn info_string(&self, key: &str) -> Option<&str> {
        self.info_plist.as_ref()?.get(key)?.as_string()
    }

    /// Whether the primary `Info.plist` declares `key` at the top level.
    pub fn has_info_key(&self, key: &str) -> bool {
        self.info_plist
            .as_ref()
            .map(|d| d.contains_key(key))
            .unwrap_or(false)
    }

    /// Iterate top-level `(key, value)` pairs of the primary `Info.plist`.
    pub fn info_entries(&self) -> impl Iterator<Item = (&String, &plist::Value)> {
        self.info_plist.iter().flat_map(|d| d.iter())
    }
}

fn is_pruned(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| PRUNED_DIRS.contains(&n))
        .unwrap_or(false)
}

/// Prefer a file that belongs to the app target: not under a test directory,
/// shallowest in the tree.
fn pick_primary(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .filter(|p| !path_looks_like_tests(p))
        .min_by_key(|p| p.components().count())
        .or_else(|| candidates.first())
        .cloned()
}

fn path_looks_like_tests(path: &Path) -> bool {
    path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .map(|s| {
                let s = s.to_ascii_lowercase();
                s.contains("test") || s.contains("uitests")
            })
            .unwrap_or(false)
    })
}
