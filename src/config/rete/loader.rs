// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! YAML parsing and the top-level `load` entry point.

use std::fmt;
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

/// One file that failed to parse.
#[derive(Debug)]
pub struct FileParseError {
    pub path: PathBuf,
    pub message: String,
}

impl fmt::Display for FileParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.message)
    }
}

/// All files that failed to parse in a single discovery pass.
/// Embedded inside `LoadError::ParseFailures` so the full list is visible
/// in the terminal without needing `attach_printable` (removed in error-stack 0.7).
#[derive(Debug)]
pub struct ParseFailures(pub Vec<FileParseError>);

impl fmt::Display for ParseFailures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} file(s) failed to parse", self.0.len())?;
        for e in &self.0 {
            write!(f, "\n  {}", e)?;
        }
        Ok(())
    }
}

impl std::error::Error for ParseFailures {}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("'rete.yaml' not found at repo root '{}'", .0.display())]
    MissingRootConfig(PathBuf),

    #[error("Failed to read '{}'", .0.display())]
    Io(PathBuf),

    #[error("{0}")]
    ParseFailures(ParseFailures),

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
/// duplicate names). Validation rule checks are left to `validate()`.
pub fn load(opts: &LoadOpts) -> Result<RepoModel, Report<LoadError>> {
    // Phase 1: read rete.yaml early (in discovery mode) to get the source block
    // for discovery; in -f override mode this step is skipped.
    // The parsed fragment is saved so Phase 3 can inject it directly, avoiding
    // a second parse of the root config file.
    let (source_block, root_config_fragment) = if opts.files.is_empty() {
        let root_config = opts.repo.join("rete.yaml");
        if !root_config.exists() {
            return Err(Report::new(LoadError::MissingRootConfig(opts.repo.clone())));
        }
        let raw = read_bytes(&root_config)?;
        let fragment = parse_bytes(&raw, &root_config)
            .map_err(|e| Report::new(LoadError::ParseFailures(ParseFailures(vec![e]))))?;
        let source = fragment.source.clone();
        (source, Some((root_config, fragment)))
    } else {
        (None, None)
    };

    // Phase 2: discover the full file list
    let paths = discover_files(opts, source_block.as_ref())?;

    // Phase 3: parse all files, collecting every failure before bailing.
    // The root config is injected from Phase 1; paths contains only the remaining files.
    let mut parsed: Vec<(PathBuf, ConfigFragment)> = Vec::with_capacity(paths.len() + 1);
    let mut parse_errors: Vec<FileParseError> = Vec::new();

    if let Some((root_config_path, fragment)) = root_config_fragment {
        parsed.push((root_config_path, fragment));
    }

    for path in &paths {
        match read_bytes(path) {
            Err(e) => {
                // Surface I/O failures as parse errors so we collect all failures
                // before returning.
                parse_errors.push(FileParseError {
                    path: path.clone(),
                    message: format!("{e}"),
                });
            }
            Ok(raw) => match parse_bytes(&raw, path) {
                Ok(file) => parsed.push((path.clone(), file)),
                Err(e) => parse_errors.push(e),
            },
        }
    }

    if !parse_errors.is_empty() {
        return Err(Report::new(LoadError::ParseFailures(ParseFailures(
            parse_errors,
        ))));
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

fn parse_bytes(raw: &str, path: &Path) -> Result<ConfigFragment, FileParseError> {
    serde_yaml_ng::from_str::<ConfigFragment>(raw).map_err(|e| FileParseError {
        path: path.to_path_buf(),
        message: e.to_string(),
    })
}
