// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Shared CLI helpers used by both `flor` and `florctl` binaries.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{IsTerminal, Write};
use std::path::Path;

use error_stack::{FrameKind, Report, ResultExt};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

/// Print an error report to stderr with a bold-red `error:` prefix, in the
/// style of `cargo` / `rustc`.
///
/// - `verbose = false`: compact anyhow-style chain — each context's
///   message joined by `": "`. Hides frame locations and internal lib detail.
/// - `verbose = true`: full error-stack tree via `Debug`. Use when the
///   compact chain doesn't point at the cause.
pub fn print_error<E>(report: &Report<E>, verbose: bool) {
    let prefix = error_prefix();
    if verbose {
        eprintln!("{prefix} {report:?}");
    } else {
        eprintln!("{prefix} {}", CompactChain(report));
    }
}

fn error_prefix() -> &'static str {
    // ANSI bold red. Suppressed when stderr isn't a TTY or NO_COLOR is set
    // (https://no-color.org/).
    let use_color = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    if use_color {
        "\x1b[1;31merror:\x1b[0m"
    } else {
        "error:"
    }
}

struct CompactChain<'a, E>(&'a Report<E>);

impl<E> fmt::Display for CompactChain<'_, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for frame in self.0.frames() {
            if let FrameKind::Context(ctx) = frame.kind() {
                if !first {
                    f.write_str(": ")?;
                }
                write!(f, "{ctx}")?;
                first = false;
            }
        }
        Ok(())
    }
}

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
