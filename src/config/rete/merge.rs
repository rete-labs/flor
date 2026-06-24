// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Multi-file merge into a unified `RepoModel`.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::{Path, PathBuf};

use error_stack::Report;

use super::loader::LoadError;
use super::model::{ConfigFragment, Group, Node, Rete, Role, Service, User};

/// The merged whole-view of a rete config repository.
///
/// All collections are unioned from every source file; the `rete` block is
/// the single canonical rete metadata entry.
#[derive(Debug)]
pub struct RepoModel {
    pub rete: Rete,
    pub nodes: HashMap<String, Node>,
    pub services: HashMap<String, Service>,
    /// Values are `Option<Group>` to preserve null-body reserved groups.
    pub groups: HashMap<String, Option<Group>>,
    pub roles: HashMap<String, Role>,
    pub users: HashMap<String, User>,
}

fn merge_entries<V>(
    target: &mut HashMap<String, V>,
    source: impl IntoIterator<Item = (String, V)>,
    kind: &str,
    path: &Path,
    errors: &mut Vec<String>,
) {
    for (name, def) in source {
        match target.entry(name) {
            Entry::Occupied(e) => errors.push(format!(
                "Duplicate {kind} '{}' in '{}'",
                e.key(),
                path.display()
            )),
            Entry::Vacant(e) => {
                e.insert(def);
            }
        }
    }
}

/// Merge parsed config files into one `RepoModel`.
///
/// `override_mode = true` when the `-f` flag was used; in that mode the
/// `rete` block is still required in at least one selected file.
pub fn merge(
    files: Vec<(PathBuf, ConfigFragment)>,
    discovery_mode: bool,
) -> Result<RepoModel, Report<LoadError>> {
    let mut rete_block: Option<(PathBuf, Rete)> = None;
    let mut nodes: HashMap<String, Node> = HashMap::new();
    let mut services: HashMap<String, Service> = HashMap::new();
    let mut groups: HashMap<String, Option<Group>> = HashMap::new();
    let mut roles: HashMap<String, Role> = HashMap::new();
    let mut users: HashMap<String, User> = HashMap::new();
    let mut merge_errors: Vec<String> = Vec::new();

    for (path, fragment) in files {
        // --- rete singleton ---
        if let Some(rete) = fragment.rete {
            if let Some((ref existing_path, _)) = rete_block {
                merge_errors.push(format!(
                    "Duplicate `rete` block: found in both '{}' and '{}'",
                    existing_path.display(),
                    path.display(),
                ));
            } else {
                rete_block = Some((path.clone(), rete));
            }
        }

        if let Some(src) = fragment.nodes {
            merge_entries(&mut nodes, src, "node", &path, &mut merge_errors);
        }

        if let Some(src) = fragment.services {
            merge_entries(&mut services, src, "service", &path, &mut merge_errors);
        }

        if let Some(src) = fragment.groups {
            merge_entries(&mut groups, src, "group", &path, &mut merge_errors);
        }

        if let Some(src) = fragment.roles {
            merge_entries(&mut roles, src, "role", &path, &mut merge_errors);
        }

        if let Some(src) = fragment.users {
            merge_entries(&mut users, src, "user", &path, &mut merge_errors);
        }
    }

    let Some((_, rete)) = rete_block else {
        let msg = if discovery_mode {
            "No `rete` block found; rete.yaml must contain a `rete:` entry".into()
        } else {
            "No `rete` block found in the specified files; at least one must contain a `rete:` entry".into()
        };
        merge_errors.push(msg);
        return Err(Report::new(LoadError::Merge(merge_errors.join("; "))));
    };

    if !merge_errors.is_empty() {
        return Err(Report::new(LoadError::Merge(merge_errors.join("; "))));
    }

    Ok(RepoModel {
        rete,
        nodes,
        services,
        groups,
        roles,
        users,
    })
}
