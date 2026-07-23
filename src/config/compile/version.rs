// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! The rete-wide compile counter, read back off the compiled tree.
//!
//! The `version` an artifact carries is a monotonic per-compilation number:
//! agents reject anything older than what they already hold, so it must never go
//! backwards. Every compile rewrites the whole tree at one number, so the tree
//! itself records it — [`next_version`] reads the artifacts already there and
//! returns one past the highest.
//!
//! Reading the whole set rather than the first artifact found costs one small
//! parse per node and is honest about a half-written tree: whatever the highest
//! number on disk is, the next compile clears it.

use std::path::Path;

use error_stack::{Report, ResultExt};
use serde::Deserialize;

use super::Error;

/// Just the envelope field this module needs; the rest of the artifact is
/// irrelevant to picking a number, and parsing it would couple the counter to
/// the payload schema.
#[derive(Debug, Deserialize)]
struct ArtifactVersion {
    version: u64,
}

/// The next rete-wide compilation number: one past the highest carried by any
/// artifact under `out` (1 when the tree holds none).
///
/// An artifact that exists but cannot be read is an error, not a reason to
/// quietly restart from 1 — that would hand every agent in the rete a version it
/// refuses.
pub fn next_version(out: &Path) -> Result<u64, Report<Error>> {
    let mut highest = 0;
    for path in artifact_paths(out)? {
        let json = std::fs::read(&path)
            .change_context_lazy(|| Error::new(format!("Failed to read {}", path.display())))?;
        let artifact: ArtifactVersion = serde_json::from_slice(&json)
            .change_context_lazy(|| Error::new(format!("Failed to parse {}", path.display())))?;
        highest = highest.max(artifact.version);
    }
    Ok(highest + 1)
}

/// Every artifact in the compiled tree: the flat `<out>/<node>/mgmt/*.json`.
///
/// An absent tree is the first compile, not a failure; anything else that fails
/// to list is real, since a tree we cannot walk is one we cannot trust the
/// counter from.
fn artifact_paths(out: &Path) -> Result<Vec<std::path::PathBuf>, Report<Error>> {
    let nodes = match std::fs::read_dir(out) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(Report::new(e))
                .change_context_lazy(|| Error::new(format!("Failed to list {}", out.display())));
        }
    };

    let mut paths = Vec::new();
    for node in nodes {
        let node =
            node.change_context_lazy(|| Error::new(format!("Failed to list {}", out.display())))?;
        let mgmt = node.path().join("mgmt");
        let entries = match std::fs::read_dir(&mgmt) {
            Ok(entries) => entries,
            // Not every directory under the tree root is a node's: skip what
            // does not have the shape one has.
            Err(_) => continue,
        };
        for entry in entries {
            let entry = entry
                .change_context_lazy(|| Error::new(format!("Failed to list {}", mgmt.display())))?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                paths.push(path);
            }
        }
    }
    Ok(paths)
}
