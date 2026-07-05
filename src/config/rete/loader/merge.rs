// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Multi-file merge into a unified `RepoModel`.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::{Path, PathBuf};

use error_stack::Report;

use super::super::model::{ConfigFragment, Group, Node, RepoModel, Rete, Role, Service, User};
use super::LoadError;

fn merge_entries<V>(
    target: &mut HashMap<String, V>,
    source: impl IntoIterator<Item = (String, V)>,
    kind: &str,
    path: &Path,
    errors: &mut Vec<Report<LoadError>>,
) {
    for (name, def) in source {
        match target.entry(name) {
            Entry::Occupied(e) => errors.push(Report::new(LoadError::Merge(format!(
                "Duplicate {kind} '{}' in '{}'",
                e.key(),
                path.display()
            )))),
            Entry::Vacant(e) => {
                e.insert(def);
            }
        }
    }
}

/// Merge parsed config files into one `RepoModel`.
///
/// `discovery_mode = false` when the `-f` flag was used; in that mode the
/// `rete` block is still required in at least one selected file.
pub fn merge(
    files: Vec<(PathBuf, ConfigFragment)>,
    discovery_mode: bool,
) -> Result<RepoModel, Vec<Report<LoadError>>> {
    let mut rete_block: Option<(PathBuf, Rete)> = None;
    let mut nodes: HashMap<String, Node> = HashMap::new();
    let mut services: HashMap<String, Service> = HashMap::new();
    let mut groups: HashMap<String, Option<Group>> = HashMap::new();
    let mut roles: HashMap<String, Role> = HashMap::new();
    let mut users: HashMap<String, User> = HashMap::new();
    let mut merge_errors: Vec<Report<LoadError>> = Vec::new();

    for (path, fragment) in files {
        // --- rete singleton ---
        if let Some(rete) = fragment.rete {
            if let Some((ref existing_path, _)) = rete_block {
                merge_errors.push(Report::new(LoadError::Merge(format!(
                    "Duplicate `rete` block: found in both '{}' and '{}'",
                    existing_path.display(),
                    path.display(),
                ))));
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
        merge_errors.push(Report::new(LoadError::Merge(msg)));
        return Err(merge_errors);
    };

    if !merge_errors.is_empty() {
        return Err(merge_errors);
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::super::super::model::ConfigFragment;
    use super::merge;

    fn fragment(yaml: &str) -> (PathBuf, ConfigFragment) {
        let f = serde_yaml_ng::from_str::<ConfigFragment>(yaml).expect("test YAML must be valid");
        (PathBuf::from("test.yaml"), f)
    }

    fn named(name: &str, yaml: &str) -> (PathBuf, ConfigFragment) {
        let f = serde_yaml_ng::from_str::<ConfigFragment>(yaml).expect("test YAML must be valid");
        (PathBuf::from(name), f)
    }

    const RETE_BLOCK: &str = "\
rete:
  name: test-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []
";

    const NODE_A: &str = "\
nodes:
  node-a:
    vertices:
      - name: quic0
        kind: link
        type: quic
        address: \"1.2.3.4:4433\"
";

    const NODE_B: &str = "\
nodes:
  node-b:
    vertices:
      - name: quic0
        kind: link
        type: quic
        address: \"5.6.7.8:4433\"
";

    const SVC_A: &str = "\
services:
  svc-a:
    at: node-a
    addr: \"127.0.0.1:8080\"
";

    const SVC_B: &str = "\
services:
  svc-b:
    at: node-b
    addr: \"127.0.0.1:9090\"
";

    // -----------------------------------------------------------------------
    // Success cases
    // -----------------------------------------------------------------------

    #[test]
    fn single_file_with_rete_block_succeeds() {
        let model = merge(vec![fragment(RETE_BLOCK)], true).unwrap();
        assert_eq!(model.rete.name, "test-rete");
    }

    #[test]
    fn multiple_files_merge_nodes_and_services() {
        let files = vec![
            fragment(RETE_BLOCK),
            named("nodes.yaml", NODE_A),
            named("nodes2.yaml", NODE_B),
            named("svcs.yaml", SVC_A),
            named("svcs2.yaml", SVC_B),
        ];
        let model = merge(files, true).unwrap();
        assert!(model.nodes.contains_key("node-a"));
        assert!(model.nodes.contains_key("node-b"));
        assert!(model.services.contains_key("svc-a"));
        assert!(model.services.contains_key("svc-b"));
    }

    // -----------------------------------------------------------------------
    // Duplicate rete block
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_rete_block_returns_error() {
        let files = vec![
            named("rete.yaml", RETE_BLOCK),
            named("other.yaml", RETE_BLOCK),
        ];
        let errs = merge(files, true).unwrap_err();
        assert_eq!(errs.len(), 1);
        let msg = errs[0].current_context().to_string();
        assert!(msg.contains("Duplicate `rete`"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // Missing rete block
    // -----------------------------------------------------------------------

    #[test]
    fn missing_rete_block_discovery_mode_returns_error() {
        let errs = merge(vec![fragment(NODE_A)], true).unwrap_err();
        assert_eq!(errs.len(), 1);
        let msg = errs[0].current_context().to_string();
        assert!(msg.contains("rete.yaml"), "got: {msg}");
    }

    #[test]
    fn missing_rete_block_override_mode_returns_error() {
        let errs = merge(vec![fragment(NODE_A)], false).unwrap_err();
        assert_eq!(errs.len(), 1);
        let msg = errs[0].current_context().to_string();
        assert!(msg.contains("specified files"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // Duplicate entry names across files
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_node_name_across_files_returns_error() {
        let files = vec![
            named("file1.yaml", &format!("{RETE_BLOCK}{NODE_A}")),
            named("file2.yaml", NODE_A),
        ];
        let errs = merge(files, true).unwrap_err();
        assert_eq!(errs.len(), 1);
        let msg = errs[0].current_context().to_string();
        assert!(msg.contains("Duplicate node 'node-a'"), "got: {msg}");
    }

    #[test]
    fn duplicate_service_name_across_files_returns_error() {
        let files = vec![
            named("file1.yaml", &format!("{RETE_BLOCK}{SVC_A}")),
            named("file2.yaml", SVC_A),
        ];
        let errs = merge(files, true).unwrap_err();
        assert_eq!(errs.len(), 1);
        let msg = errs[0].current_context().to_string();
        assert!(msg.contains("Duplicate service 'svc-a'"), "got: {msg}");
    }

    #[test]
    fn duplicate_role_name_across_files_returns_error() {
        let role_yaml = "roles:\n  admin:\n    allow: []\n";
        let files = vec![
            named("file1.yaml", &format!("{RETE_BLOCK}{role_yaml}")),
            named("file2.yaml", role_yaml),
        ];
        let errs = merge(files, true).unwrap_err();
        assert_eq!(errs.len(), 1);
        let msg = errs[0].current_context().to_string();
        assert!(msg.contains("Duplicate role 'admin'"), "got: {msg}");
    }

    #[test]
    fn duplicate_user_name_across_files_returns_error() {
        let user_yaml = "users:\n  alice:\n    roles: []\n";
        let files = vec![
            named("file1.yaml", &format!("{RETE_BLOCK}{user_yaml}")),
            named("file2.yaml", user_yaml),
        ];
        let errs = merge(files, true).unwrap_err();
        assert_eq!(errs.len(), 1);
        let msg = errs[0].current_context().to_string();
        assert!(msg.contains("Duplicate user 'alice'"), "got: {msg}");
    }

    #[test]
    fn duplicate_group_name_across_files_returns_error() {
        let group_yaml = "groups:\n  my-group:\n";
        let files = vec![
            named("file1.yaml", &format!("{RETE_BLOCK}{group_yaml}")),
            named("file2.yaml", group_yaml),
        ];
        let errs = merge(files, true).unwrap_err();
        assert_eq!(errs.len(), 1);
        let msg = errs[0].current_context().to_string();
        assert!(msg.contains("Duplicate group 'my-group'"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // All errors are collected before returning
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_merge_errors_all_collected() {
        // Two files each redefine node-a AND svc-a → expect both errors in one report.
        let combined = format!("{NODE_A}{SVC_A}");
        let files = vec![
            named("file1.yaml", &format!("{RETE_BLOCK}{combined}")),
            named("file2.yaml", &combined),
        ];
        let errs = merge(files, true).unwrap_err();
        assert_eq!(errs.len(), 2);
        let combined = errs
            .iter()
            .map(|e| e.current_context().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(combined.contains("node-a"), "got: {combined}");
        assert!(combined.contains("svc-a"), "got: {combined}");
    }
}
