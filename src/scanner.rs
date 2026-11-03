//! Recursive traversal that honors `.gitignore` and skips build directories.

use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use rayon::prelude::*;

/// Controls ignore rules inherited from outside the scan root.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Honor `.gitignore` files above the directory being scanned.
    pub respect_parent_ignores: bool,
    /// Honor the global gitignore and `.git/info/exclude`.
    pub respect_global_gitignore: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            respect_parent_ignores: true,
            respect_global_gitignore: true,
        }
    }
}

#[derive(Debug)]
pub enum ScanError {
    Walk(ignore::Error),
    NotADirectory(PathBuf),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Walk(err) => write!(f, "scanning files: {err}"),
            Self::NotADirectory(path) => write!(f, "not a directory: {}", path.display()),
        }
    }
}

impl std::error::Error for ScanError {}

const MAX_FILE_BYTES: u64 = 1024 * 1024;

const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "pdf", "zip", "gz", "tar", "bz2", "xz", "7z",
    "wasm", "so", "dll", "dylib", "class", "exe", "bin", "woff", "woff2", "ttf", "eot", "mp3",
    "mp4", "mov", "avi",
];

const LOCKFILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Gemfile.lock",
    "composer.lock",
];

/// Walk `root`, skipping gitignored paths, `.git`, `target/`, and `node_modules/`.
pub fn scan(root: &Path) -> Result<Vec<PathBuf>, ScanError> {
    scan_with(root, &ScanOptions::default())
}

pub fn scan_with(root: &Path, options: &ScanOptions) -> Result<Vec<PathBuf>, ScanError> {
    if !root.is_dir() {
        return Err(ScanError::NotADirectory(root.to_path_buf()));
    }

    let walker = WalkBuilder::new(root)
        .standard_filters(true)
        .hidden(false)
        .parents(options.respect_parent_ignores)
        .git_global(options.respect_global_gitignore)
        .git_exclude(options.respect_global_gitignore)
        .max_filesize(Some(MAX_FILE_BYTES))
        .filter_entry(|entry| !is_skipped_directory(entry))
        .build();

    let mut paths = Vec::new();
    for entry in walker {
        let entry = entry.map_err(ScanError::Walk)?;
        if entry.file_type().is_some_and(|kind| kind.is_file()) {
            paths.push(entry.into_path());
        }
    }

    let mut files: Vec<PathBuf> = paths
        .into_par_iter()
        .filter(|path| !is_skipped_file(path))
        .collect();
    files.sort();
    files.dedup();
    Ok(files)
}

fn is_skipped_directory(entry: &ignore::DirEntry) -> bool {
    if entry.depth() == 0 {
        return false;
    }
    if !entry.file_type().is_some_and(|kind| kind.is_dir()) {
        return false;
    }
    matches!(
        entry.file_name().to_str(),
        Some("target" | "node_modules" | ".git")
    )
}

fn is_skipped_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    if name == ".env" || name.starts_with(".env.") || LOCKFILES.contains(&name) {
        return true;
    }
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| BINARY_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}
