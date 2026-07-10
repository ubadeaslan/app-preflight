//! Locating and reading an Android project on disk.

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const PRUNED_DIRS: &[&str] = &[".git", "build", ".gradle", "node_modules", ".idea"];

/// The Android namespace URI; attributes like `android:name` resolve here.
pub const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

/// A parsed Android project. `load` returns `None` when `root` is not an Android
/// project.
pub struct AndroidProject {
    pub root: PathBuf,
    /// Primary `AndroidManifest.xml` (main source set), if found.
    pub manifest_path: Option<PathBuf>,
    pub manifest_xml: Option<String>,
    /// Concatenated text of module-level Gradle build scripts.
    pub gradle_text: String,
}

impl AndroidProject {
    pub fn load(root: &Path) -> Option<Self> {
        let mut manifests: Vec<PathBuf> = Vec::new();
        let mut gradle_files: Vec<PathBuf> = Vec::new();
        let mut has_marker = false;

        for entry in WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| !is_pruned(e.path()))
            .flatten()
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };
            match name {
                "AndroidManifest.xml" => manifests.push(path.to_path_buf()),
                "build.gradle" | "build.gradle.kts" => {
                    has_marker = true;
                    gradle_files.push(path.to_path_buf());
                }
                "settings.gradle" | "settings.gradle.kts" => has_marker = true,
                _ => {}
            }
        }

        if !has_marker && manifests.is_empty() {
            return None;
        }

        let manifest_path = pick_primary_manifest(&manifests);
        let manifest_xml = manifest_path
            .as_deref()
            .and_then(|p| std::fs::read_to_string(p).ok());

        let mut gradle_text = String::new();
        for path in &gradle_files {
            if let Ok(text) = std::fs::read_to_string(path) {
                gradle_text.push_str(&text);
                gradle_text.push('\n');
            }
        }

        Some(AndroidProject {
            root: root.to_path_buf(),
            manifest_path,
            manifest_xml,
            gradle_text,
        })
    }

    /// Parse the manifest, returning the document for checks that need it.
    pub fn manifest_doc(&self) -> Option<roxmltree::Document<'_>> {
        let xml = self.manifest_xml.as_deref()?;
        roxmltree::Document::parse(xml).ok()
    }
}

/// Read the value of an `android:`-namespaced attribute by local name.
pub fn android_attr<'a>(node: roxmltree::Node<'a, 'a>, local: &str) -> Option<&'a str> {
    node.attribute((ANDROID_NS, local))
        // Fall back to a prefixed match in case the namespace isn't declared.
        .or_else(|| {
            node.attributes()
                .find(|a| a.name() == local)
                .map(|a| a.value())
        })
}

fn is_pruned(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| PRUNED_DIRS.contains(&n))
        .unwrap_or(false)
}

/// Prefer the manifest under a `main` source set, shallowest otherwise.
fn pick_primary_manifest(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .find(|p| {
            p.components().any(|c| c.as_os_str() == "main")
                && !p.components().any(|c| {
                    let s = c.as_os_str().to_string_lossy().to_ascii_lowercase();
                    s.contains("test")
                })
        })
        .or_else(|| candidates.iter().min_by_key(|p| p.components().count()))
        .cloned()
}
