// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Locating the flor home directory and the rete roots beneath it.
//!
//! flor home is `$FLOR_HOME` if set, else `$HOME/.flor`; each enrolled rete
//! lives at `<flor-home>/retes/<scope>/`. [`rete_root`] resolves a scope (or
//! auto-detects the sole enrolled rete) to that directory. The `$FLOR_HOME`
//! override exists mainly to relocate the tree for development and CI, keeping
//! tests and the e2e harness off the real `$HOME/.flor`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use error_stack::{Report, ResultExt, bail};

/// A failure locating the flor home directory or a rete root.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

impl Error {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Resolve the rete root `<flor-home>/retes/<scope>/`, auto-detecting the scope
/// when exactly one rete is enrolled. flor home is `$FLOR_HOME` if set, else
/// `$HOME/.flor`.
pub fn rete_root(scope: Option<&str>) -> Result<PathBuf, Report<Error>> {
    rete_root_under(&flor_home()?, scope)
}

/// The flor home directory, resolved from the process environment.
fn flor_home() -> Result<PathBuf, Report<Error>> {
    flor_home_from(std::env::var_os("FLOR_HOME"), std::env::var_os("HOME"))
}

/// Pure resolution of flor home from the two env values, so the branching is
/// testable without mutating the (process-global) environment.
fn flor_home_from(
    flor_home: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, Report<Error>> {
    if let Some(dir) = flor_home {
        return Ok(PathBuf::from(dir));
    }
    let home = home.ok_or_else(|| {
        Report::new(Error::new(
            "Neither FLOR_HOME nor HOME is set; cannot locate the rete root",
        ))
    })?;
    Ok(PathBuf::from(home).join(".flor"))
}

/// Resolve a scope under a given flor home, so the layout logic is testable
/// against a tempdir without touching the environment.
fn rete_root_under(home: &Path, scope: Option<&str>) -> Result<PathBuf, Report<Error>> {
    let retes = home.join("retes");
    let scope = match scope {
        Some(s) => s.to_string(),
        None => sole_rete(&retes)?,
    };
    let root = retes.join(&scope);
    if !root.is_dir() {
        bail!(Error::new(format!(
            "Rete scope '{scope}' not found at {}",
            root.display()
        )));
    }
    Ok(root)
}

/// The single enrolled rete scope under `retes/`; errors (asking for `--rete`)
/// when there are zero or several.
fn sole_rete(retes: &Path) -> Result<String, Report<Error>> {
    let entries = std::fs::read_dir(retes).change_context_lazy(|| {
        Error::new(format!("Failed to read retes dir {}", retes.display()))
    })?;
    let mut scopes = Vec::new();
    for entry in entries {
        let entry = entry.change_context_lazy(|| Error::new("Failed to read a retes entry"))?;
        if entry.path().is_dir()
            && let Some(name) = entry.file_name().to_str()
        {
            scopes.push(name.to_string());
        }
    }
    match scopes.as_slice() {
        [one] => Ok(one.clone()),
        [] => bail!(Error::new(format!(
            "No retes enrolled under {}",
            retes.display()
        ))),
        _ => bail!(Error::new(format!(
            "Multiple retes enrolled ({}); pass --rete to select one",
            scopes.join(", ")
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn flor_home_prefers_flor_home_var() {
        let home = flor_home_from(Some("/custom/flor".into()), Some("/home/u".into())).unwrap();
        assert_eq!(home, PathBuf::from("/custom/flor"));
    }

    #[test]
    fn flor_home_falls_back_to_home_dotflor() {
        let home = flor_home_from(None, Some("/home/u".into())).unwrap();
        assert_eq!(home, PathBuf::from("/home/u/.flor"));
    }

    #[test]
    fn flor_home_errors_when_neither_set() {
        let err = flor_home_from(None, None).unwrap_err();
        assert!(format!("{err:?}").contains("FLOR_HOME"), "{err:?}");
    }

    #[test]
    fn sole_rete_auto_detects_single() {
        let dir = tempdir().unwrap();
        std::fs::create_dir(dir.path().join("alpha")).unwrap();
        assert_eq!(sole_rete(dir.path()).unwrap(), "alpha");
    }

    #[test]
    fn sole_rete_ignores_plain_files() {
        let dir = tempdir().unwrap();
        std::fs::create_dir(dir.path().join("alpha")).unwrap();
        std::fs::write(dir.path().join("note.txt"), b"x").unwrap();
        assert_eq!(sole_rete(dir.path()).unwrap(), "alpha");
    }

    #[test]
    fn sole_rete_errors_when_retes_dir_missing() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let err = sole_rete(&missing).unwrap_err();
        assert!(
            format!("{err:?}").contains("Failed to read retes dir"),
            "{err:?}"
        );
    }

    #[test]
    fn sole_rete_errors_when_none_enrolled() {
        let dir = tempdir().unwrap();
        let err = sole_rete(dir.path()).unwrap_err();
        assert!(format!("{err:?}").contains("No retes"), "{err:?}");
    }

    #[test]
    fn sole_rete_errors_when_several_enrolled() {
        let dir = tempdir().unwrap();
        std::fs::create_dir(dir.path().join("alpha")).unwrap();
        std::fs::create_dir(dir.path().join("beta")).unwrap();
        let err = sole_rete(dir.path()).unwrap_err();
        assert!(format!("{err:?}").contains("Multiple retes"), "{err:?}");
    }

    #[test]
    fn rete_root_under_resolves_explicit_scope() {
        let dir = tempdir().unwrap();
        let scope = dir.path().join("retes").join("alpha");
        std::fs::create_dir_all(&scope).unwrap();
        assert_eq!(rete_root_under(dir.path(), Some("alpha")).unwrap(), scope);
    }

    #[test]
    fn rete_root_under_errors_on_missing_scope() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("retes")).unwrap();
        let err = rete_root_under(dir.path(), Some("ghost")).unwrap_err();
        assert!(format!("{err:?}").contains("not found"), "{err:?}");
    }

    #[test]
    fn rete_root_under_auto_detects_sole_scope() {
        let dir = tempdir().unwrap();
        let scope = dir.path().join("retes").join("only");
        std::fs::create_dir_all(&scope).unwrap();
        assert_eq!(rete_root_under(dir.path(), None).unwrap(), scope);
    }
}
