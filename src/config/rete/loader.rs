// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! YAML parsing and the top-level `load` entry point.

use std::path::{Path, PathBuf};

use error_stack::{Report, ResultExt};

use super::model::{ConfigFragment, RepoModel};
use discover::discover_files;
use merge::merge;

mod discover;
mod merge;

/// Options controlling where config files are loaded from.
pub struct LoadOpts {
    /// Repository root; `rete.yaml` must exist here.
    pub repo: PathBuf,
    /// When non-empty, overrides discovery entirely.
    /// At least one selected file must contain the `rete` block.
    pub files: Vec<String>,
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("'rete.yaml' not found at repo root '{}'", .0.display())]
    MissingRootConfig(PathBuf),

    #[error("Failed to read '{}'", .0.display())]
    Io(PathBuf),

    #[error("Failed to parse '{}'", .0.display())]
    Parse(PathBuf),

    #[error("Invalid glob pattern '{0}'")]
    Discovery(String),

    #[error("Invalid path: '{}'", .0.display())]
    InvalidPath(PathBuf),

    #[error("{0}")]
    Merge(String),
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Load and merge all rete config files according to `opts`.
///
/// Fails if `rete.yaml` is missing, files can't be read, YAML is malformed,
/// or the merged source violates structural invariants (rete singleton,
/// duplicate names). Validation rule checks are left to `validate()`. Every
/// independent failure is collected and returned together, rather than
/// stopping at the first one.
pub fn load(opts: &LoadOpts) -> Result<RepoModel, Vec<Report<LoadError>>> {
    // Phase 1: read rete.yaml early (in discovery mode) to get the source block
    // for discovery; in -f override mode this step is skipped.
    // The parsed fragment is saved so Phase 3 can inject it directly, avoiding
    // a second parse of the root config file.
    //
    // A parse failure here doesn't abort immediately: it's recorded and
    // discovery falls back to the default include globs (the custom `source`
    // block, if any, lives inside the very fragment that failed to parse), so
    // Phase 3 still surfaces every other broken file in the same report
    // instead of forcing a fix-and-rerun cycle one file at a time.
    let mut failures: Vec<Report<LoadError>> = Vec::new();
    let (source_block, root_config_fragment) = if opts.files.is_empty() {
        let root_config = opts.repo.join("rete.yaml");
        if !root_config.exists() {
            return Err(vec![Report::new(LoadError::MissingRootConfig(
                opts.repo.clone(),
            ))]);
        }
        let raw = read_bytes(&root_config).map_err(|e| vec![e])?;
        match parse_bytes(&raw, &root_config) {
            Ok(fragment) => {
                let source = fragment.source.clone();
                (source, Some((root_config, fragment)))
            }
            Err(e) => {
                failures.push(e);
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    // Phase 2: discover the full file list
    let paths = discover_files(opts, source_block.as_ref()).map_err(|e| vec![e])?;

    // Phase 3: parse all files, collecting every failure before bailing.
    // The root config is injected from Phase 1; paths contains only the remaining files.
    let mut parsed: Vec<(PathBuf, ConfigFragment)> = Vec::with_capacity(paths.len() + 1);

    if let Some((root_config_path, fragment)) = root_config_fragment {
        parsed.push((root_config_path, fragment));
    }

    for path in &paths {
        match read_bytes(path) {
            Err(e) => failures.push(e),
            Ok(raw) => match parse_bytes(&raw, path) {
                Ok(file) => parsed.push((path.clone(), file)),
                Err(e) => failures.push(e),
            },
        }
    }

    if !failures.is_empty() {
        return Err(failures);
    }

    // Phase 4: merge into a unified RepoModel
    let discovery_mode = opts.files.is_empty();
    merge(parsed, discovery_mode)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_bytes(path: &Path) -> Result<String, Report<LoadError>> {
    std::fs::read_to_string(path).change_context_lazy(|| LoadError::Io(path.to_path_buf()))
}

fn parse_bytes(raw: &str, path: &Path) -> Result<ConfigFragment, Report<LoadError>> {
    serde_yaml_ng::from_str::<ConfigFragment>(raw)
        .change_context_lazy(|| LoadError::Parse(path.to_path_buf()))
}
