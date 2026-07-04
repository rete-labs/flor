// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! File discovery for rete config repositories.

use std::path::{Path, PathBuf};

use glob::glob;

use error_stack::{Report, ResultExt};

use super::super::model::Source;
use super::{LoadError, LoadOpts};

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
    // rete.yaml is handled separately by the loader;
    // exclude it from discovery so it isn't parsed a second time.
    let root_config = repo.join("rete.yaml");
    let mut paths = Vec::new();

    let include_globs: Vec<String> = source
        .and_then(|s| s.include.clone())
        .unwrap_or_else(|| vec!["**/*.yaml".into(), "**/*.yml".into()]);

    let exclude_globs: Vec<String> = source.and_then(|s| s.exclude.clone()).unwrap_or_default();

    // Escape the repo path so any glob metacharacters it happens to contain
    // (e.g. `[`, `]`, `*` in a directory name) are treated literally; only
    // `pattern` itself should be interpreted as a glob.
    let escaped_repo = escaped_repo_path(repo)?;

    for pattern in &include_globs {
        let full_pattern = escaped_repo.join(pattern);
        let full_pattern_str = path_to_str(&full_pattern)?;
        for entry in glob(full_pattern_str)
            .change_context_lazy(|| LoadError::Discovery(pattern.clone()))?
            .flatten()
        {
            if should_skip(&entry, repo)? {
                continue;
            }
            if is_excluded(&entry, &escaped_repo, &exclude_globs)? {
                continue;
            }
            if entry == root_config {
                continue;
            }
            if !paths.contains(&entry) {
                paths.push(entry);
            }
        }
    }

    Ok(paths)
}

/// Escape a repo path for safe embedding in a glob pattern, so characters
/// meaningful to `repo` (a real filesystem path) aren't reinterpreted as
/// glob wildcards.
fn escaped_repo_path(repo: &Path) -> Result<PathBuf, Report<LoadError>> {
    let repo_str = path_to_str(repo)?;
    Ok(PathBuf::from(glob::Pattern::escape(repo_str)))
}

fn path_to_str(path: &Path) -> Result<&str, Report<LoadError>> {
    path.to_str()
        .ok_or_else(|| Report::new(LoadError::InvalidPath(path.to_path_buf())))
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

fn should_skip(path: &Path, repo: &Path) -> Result<bool, Report<LoadError>> {
    let Ok(rel) = path.strip_prefix(repo) else {
        return Ok(false);
    };

    for component in rel.components() {
        let name = path_to_str(component.as_ref())?;
        // Skip dotfiles and dotdirs
        if name.starts_with('.') {
            return Ok(true);
        }
        // Skip certs/ directories
        if name == "certs" {
            return Ok(true);
        }
    }
    Ok(false)
}

fn is_excluded(
    path: &Path,
    escaped_repo: &Path,
    exclude_globs: &[String],
) -> Result<bool, Report<LoadError>> {
    for pattern in exclude_globs {
        let full_pattern = escaped_repo.join(pattern);
        let full_pattern_str = path_to_str(&full_pattern)?;
        if let Ok(g) = glob::Pattern::new(full_pattern_str)
            && g.matches_path(path)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
