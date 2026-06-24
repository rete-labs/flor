// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Source file discovery for rete config repositories.

use std::path::{Path, PathBuf};

use glob::glob;

use super::loader::LoadError;
use super::model::Source;
use error_stack::{Report, ResultExt};

/// Options controlling where config files are loaded from.
pub struct LoadOpts {
    /// Repository root; `rete.yaml` must exist here.
    pub repo: PathBuf,
    /// When non-empty, overrides discovery entirely.
    /// At least one selected file must contain the `rete` block.
    pub files: Vec<String>,
}

/// Discover all YAML source files to load.
///
/// Returns an ordered list of paths. `rete.yaml` is always first.
pub fn discover_files(
    opts: &LoadOpts,
    source: Option<&Source>,
) -> Result<Vec<PathBuf>, Report<LoadError>> {
    if !opts.files.is_empty() {
        return expand_overrides(&opts.files);
    }
    discover_from_repo(&opts.repo, source)
}

fn discover_from_repo(
    repo: &Path,
    source: Option<&Source>,
) -> Result<Vec<PathBuf>, Report<LoadError>> {
    // rete.yaml is handled separately by the loader (already parsed in Phase 1);
    // exclude it from discovery so it isn't parsed a second time.
    let anchor = repo.join("rete.yaml");
    let mut paths = Vec::new();

    let include_globs: Vec<String> = source
        .and_then(|s| s.include.clone())
        .unwrap_or_else(|| vec!["**/*.yaml".into(), "**/*.yml".into()]);

    let exclude_globs: Vec<String> = source.and_then(|s| s.exclude.clone()).unwrap_or_default();

    for pattern in &include_globs {
        let full_pattern = repo.join(pattern);
        let full_pattern_str = full_pattern.to_string_lossy();
        for entry in glob(&full_pattern_str)
            .change_context_lazy(|| LoadError::Discovery(pattern.clone()))?
            .flatten()
        {
            if should_skip(&entry, repo) {
                continue;
            }
            if is_excluded(&entry, repo, &exclude_globs) {
                continue;
            }
            if entry == anchor {
                continue;
            }
            if !paths.contains(&entry) {
                paths.push(entry);
            }
        }
    }

    Ok(paths)
}

fn expand_overrides(patterns: &[String]) -> Result<Vec<PathBuf>, Report<LoadError>> {
    let mut paths = Vec::new();
    for pattern in patterns {
        let mut matched = false;
        for entry in glob(pattern)
            .change_context_lazy(|| LoadError::Discovery(pattern.clone()))?
            .flatten()
        {
            if !paths.contains(&entry) {
                paths.push(entry);
            }
            matched = true;
        }
        if !matched {
            // Treat as a literal path (file may not exist yet; loader will report that)
            let p = PathBuf::from(pattern);
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    Ok(paths)
}

fn should_skip(path: &Path, repo: &Path) -> bool {
    let Ok(rel) = path.strip_prefix(repo) else {
        return false;
    };

    for component in rel.components() {
        let name = component.as_os_str().to_string_lossy();
        // Skip dotfiles and dotdirs
        if name.starts_with('.') {
            return true;
        }
        // Skip certs/ directories
        if name == "certs" {
            return true;
        }
    }
    false
}

fn is_excluded(path: &Path, repo: &Path, exclude_globs: &[String]) -> bool {
    for pattern in exclude_globs {
        let full_pattern = repo.join(pattern);
        let full_pattern_str = full_pattern.to_string_lossy();
        if let Ok(g) = glob::Pattern::new(&full_pattern_str)
            && g.matches_path(path)
        {
            return true;
        }
    }
    false
}
