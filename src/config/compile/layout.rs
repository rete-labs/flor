// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! The compiled tree's on-disk layout — the one place that knows it.
//!
//! [`NodeVertexArtifact::path`](super::NodeVertexArtifact::path) names where a single
//! artifact belongs; this module owns the one operation *over* the whole tree:
//! replacing it with a freshly compiled set. Keeping it here means the CLI never
//! spells the layout out a second time. Reading the rete-wide version counter
//! back off that tree is a separate concern, owned by [`super::version`].

use std::path::{Path, PathBuf};

use error_stack::{Report, ResultExt};

use super::{Error, NodeVertexArtifact};

/// Replace the compiled tree under `out` with `artifacts`, returning what was
/// written.
///
/// The stale tree is cleared first, so a node dropped from the source stops
/// being shipped. Every compile rewrites the whole tree, so what is left behind
/// is exactly what the source still names, all at one version.
pub fn write(out: &Path, artifacts: &[NodeVertexArtifact]) -> Result<Vec<PathBuf>, Report<Error>> {
    if out.exists() {
        std::fs::remove_dir_all(out)
            .change_context_lazy(|| Error::new(format!("Failed to clear {}", out.display())))?;
    }

    let mut written = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let path = out.join(artifact.path());
        let dir = path
            .parent()
            .ok_or_else(|| Error::new(format!("Invalid artifact path {}", path.display())))?;
        std::fs::create_dir_all(dir)
            .change_context_lazy(|| Error::new(format!("Failed to create {}", dir.display())))?;

        let json = artifact.to_json().change_context_lazy(|| {
            Error::new(format!("Failed to serialize {}", path.display()))
        })?;
        std::fs::write(&path, &json)
            .change_context_lazy(|| Error::new(format!("Failed to write {}", path.display())))?;

        written.push(path);
    }
    Ok(written)
}
