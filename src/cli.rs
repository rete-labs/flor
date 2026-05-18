// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Shared CLI helpers used by both `flor` and `florctl` binaries.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use error_stack::{Report, ResultExt};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

/// Write a file holding private key material.
///
/// On Unix the file is created with mode `0600` (owner read/write only). On
/// other platforms the OS default applies and the caller should rely on
/// directory-level protections.
pub fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), Report<Error>> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .change_context_lazy(|| Error(format!("Failed to open {} for writing", path.display())))?;
    f.write_all(bytes)
        .change_context_lazy(|| Error(format!("Failed to write {}", path.display())))?;
    Ok(())
}
