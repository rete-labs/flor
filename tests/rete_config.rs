// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Integration tests for the rete config load + validate pipeline.
//!
//! These tests exercise the full path: YAML files on disk → `load()` → `validate()`.
//! They complement the unit tests in `src/config/rete/validate.rs`, which build
//! `RepoModel` directly. Here we catch bugs that unit tests cannot:
//!   - serde field names and enum aliases (`kind: link`, `type: quic`)
//!   - `deny_unknown_fields` rejecting typos in YAML
//!   - null-body group deserialization (`config-read:` with no value)
//!   - glob-based file discovery, include/exclude patterns, skip rules
//!   - duplicate key detection across files at merge time

use std::path::PathBuf;

use flor::config::rete::{LoadError, LoadOpts, Rule, load, validate};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write(dir: &TempDir, rel: &str, content: &str) {
    let path = dir.path().join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn discovery(dir: &TempDir) -> LoadOpts {
    LoadOpts {
        repo: dir.path().to_owned(),
        files: vec![],
    }
}

fn file_override(paths: &[PathBuf]) -> LoadOpts {
    LoadOpts {
        repo: PathBuf::from("."),
        files: paths
            .iter()
            .map(|p| p.to_str().expect("test paths are valid UTF-8").to_owned())
            .collect(),
    }
}

fn count_violations(violations: &[flor::config::rete::Violation], rule: Rule) -> usize {
    violations.iter().filter(|v| v.rule == rule).count()
}

// ---------------------------------------------------------------------------
// Shared YAML fixture
// ---------------------------------------------------------------------------

/// Minimal valid rete config that passes all validation rules.
const MINIMAL: &str = r#"
rete:
  name: test-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []

nodes:
  mgmt:
    vertices:
      - name: quic0
        kind: link
        type: quic
        address: "1.2.3.4:4433"

services:
  config-server:
    at: mgmt
    addr: "127.0.0.1:9000"
    groups: [config-read]
  config-publisher:
    at: mgmt
    addr: "127.0.0.1:9001"
    groups: [config-write]

groups:
  config-read:
  config-write:

roles:
  node:
    allow: [config-read]
  operator:
    allow: [config-write]

users:
  alice:
    roles: [operator]
"#;

// ---------------------------------------------------------------------------
// L1-L7: Loader-level errors
// ---------------------------------------------------------------------------

#[test]
fn missing_rete_yaml_returns_missing_root_config_error() {
    let dir = TempDir::new().unwrap();
    let errs = load(&discovery(&dir)).unwrap_err();
    assert_eq!(errs.len(), 1);
    assert!(
        matches!(errs[0].current_context(), LoadError::MissingRootConfig(_)),
        "expected MissingRootConfig, got: {errs:?}"
    );
}

#[test]
fn malformed_yaml_returns_parse_failures() {
    let dir = TempDir::new().unwrap();
    write(&dir, "rete.yaml", "{ bad yaml: [unclosed");
    let errs = load(&discovery(&dir)).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e.current_context(), LoadError::Parse(_))),
        "expected Parse error, got: {errs:?}"
    );
}

#[test]
fn invalid_socket_address_returns_parse_failures() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "rete.yaml",
        r#"
services:
  broken-svc:
    at: mgmt
    addr: "not-an-address"
"#,
    );
    let errs = load(&discovery(&dir)).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e.current_context(), LoadError::Parse(_))),
        "expected Parse error, got: {errs:?}"
    );
}

#[test]
fn unknown_top_level_key_rejected_by_deny_unknown_fields() {
    let dir = TempDir::new().unwrap();
    // "servies" is a typo of "services"; deny_unknown_fields should reject it
    write(
        &dir,
        "rete.yaml",
        r#"
rete:
  name: test-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []
servies:
  my-svc:
    at: mgmt
    addr: "127.0.0.1:8080"
"#,
    );
    let errs = load(&discovery(&dir)).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e.current_context(), LoadError::Parse(_))),
        "expected Parse error for unknown field 'servies', got: {errs:?}"
    );
}

#[test]
fn duplicate_node_across_two_files_returns_merge_error() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "rete.yaml",
        r#"
source:
  include: ["*.yaml"]
rete:
  name: test-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []
nodes:
  mgmt:
    vertices:
      - name: quic0
        kind: link
        type: quic
        address: "1.2.3.4:4433"
"#,
    );
    write(
        &dir,
        "extra.yaml",
        r#"
nodes:
  mgmt:
    vertices:
      - name: quic0
        kind: link
        type: quic
        address: "5.6.7.8:4433"
"#,
    );
    let errs = load(&discovery(&dir)).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e.current_context(), LoadError::Merge(_))),
        "expected Merge error for duplicate node, got: {errs:?}"
    );
    assert!(
        errs.iter()
            .any(|e| e.to_string().contains("mgmt") || format!("{e:?}").contains("mgmt")),
        "error should name the duplicate key"
    );
}

#[test]
fn duplicate_rete_block_across_files_returns_merge_error() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "rete.yaml",
        r#"
source:
  include: ["*.yaml"]
rete:
  name: test-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []
"#,
    );
    write(
        &dir,
        "second.yaml",
        r#"
rete:
  name: second-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []
"#,
    );
    let errs = load(&discovery(&dir)).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e.current_context(), LoadError::Merge(_))),
        "expected Merge error for duplicate rete block, got: {errs:?}"
    );
}

#[test]
fn file_override_mode_does_not_require_rete_yaml_at_repo_root() {
    let dir = TempDir::new().unwrap();
    // Write the config somewhere other than rete.yaml
    let cfg = dir.path().join("my-config.yaml");
    std::fs::write(&cfg, MINIMAL).unwrap();

    // Discovery mode would fail (no rete.yaml), but file override mode should succeed
    let opts = file_override(&[cfg]);
    let model = load(&opts).expect("file override should succeed without rete.yaml at root");
    let violations = validate(&model);
    assert!(violations.is_empty());
}

#[test]
fn file_override_mode_fails_when_no_rete_block_present() {
    let dir = TempDir::new().unwrap();
    let cfg = dir.path().join("nodes-only.yaml");
    std::fs::write(
        &cfg,
        r#"
nodes:
  mgmt:
    vertices:
      - name: quic0
        kind: link
        type: quic
        address: "1.2.3.4:4433"
"#,
    )
    .unwrap();

    let errs = load(&file_override(&[cfg])).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e.current_context(), LoadError::Merge(_))),
        "expected Merge error when rete block is absent, got: {errs:?}"
    );
}

// ---------------------------------------------------------------------------
// L8-L11: Discovery rules
// ---------------------------------------------------------------------------

#[test]
fn certs_dir_is_excluded_from_discovery() {
    let dir = TempDir::new().unwrap();
    write(&dir, "rete.yaml", MINIMAL);
    // A duplicate node placed in certs/ must be silently skipped
    write(
        &dir,
        "certs/extra.yaml",
        r#"
nodes:
  mgmt:
    vertices:
      - name: quic1
        kind: link
        type: quic
        address: "9.9.9.9:4433"
"#,
    );
    let model = load(&discovery(&dir)).expect("certs/ dir should be skipped");
    let violations = validate(&model);
    assert!(violations.is_empty());
}

#[test]
fn dotdir_is_excluded_from_discovery() {
    let dir = TempDir::new().unwrap();
    write(&dir, "rete.yaml", MINIMAL);
    // A conflicting file in a dotdir must be silently skipped
    write(
        &dir,
        ".private/extra.yaml",
        r#"
nodes:
  mgmt:
    vertices:
      - name: quic1
        kind: link
        type: quic
        address: "9.9.9.9:4433"
"#,
    );
    let model = load(&discovery(&dir)).expect(".dotdir should be skipped");
    let violations = validate(&model);
    assert!(violations.is_empty());
}

#[test]
fn repo_path_with_glob_metacharacters_is_discovered_literally() {
    // A repo checked out under a directory name containing glob-special
    // characters (`[`, `]`) must not have those characters reinterpreted
    // as wildcards when building the discovery pattern. Prove the extra
    // file was actually found (not silently skipped) via the duplicate-node
    // merge error it triggers, mirroring `duplicate_node_name_across_files_returns_error`.
    let base = TempDir::new().unwrap();
    let repo = base.path().join("rete-configs [staging]");
    std::fs::create_dir_all(repo.join("nodes")).unwrap();
    std::fs::write(repo.join("rete.yaml"), MINIMAL).unwrap();
    std::fs::write(
        repo.join("nodes/extra.yaml"),
        r#"
nodes:
  mgmt:
    vertices:
      - name: quic1
        kind: link
        type: quic
        address: "9.9.9.9:4433"
"#,
    )
    .unwrap();
    let opts = LoadOpts {
        repo: repo.clone(),
        files: vec![],
    };
    let errs = load(&opts).expect_err(
        "nodes/extra.yaml redeclares node 'mgmt'; if discovery silently found no files \
         (e.g. due to unescaped glob metacharacters in the repo path) this would load fine instead",
    );
    assert!(
        errs.iter()
            .any(|e| matches!(e.current_context(), LoadError::Merge(_))),
        "expected Merge error from duplicate node 'mgmt', got: {errs:?}"
    );
}

#[test]
fn source_exclude_glob_suppresses_matching_files() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "rete.yaml",
        r#"
source:
  include: ["**/*.yaml"]
  exclude: ["infra/*.yaml"]
rete:
  name: test-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []
nodes:
  mgmt:
    vertices:
      - name: quic0
        kind: link
        type: quic
        address: "1.2.3.4:4433"
services:
  config-server:
    at: mgmt
    addr: "127.0.0.1:9000"
    groups: [config-read]
  config-publisher:
    at: mgmt
    addr: "127.0.0.1:9001"
    groups: [config-write]
groups:
  config-read:
  config-write:
roles:
  node:
    allow: [config-read]
  operator:
    allow: [config-write]
users:
  alice:
    roles: [operator]
"#,
    );
    // A conflicting node in infra/ must be excluded
    write(
        &dir,
        "infra/topology.yaml",
        r#"
nodes:
  mgmt:
    vertices:
      - name: quic1
        kind: link
        type: quic
        address: "9.9.9.9:4433"
"#,
    );
    let model = load(&discovery(&dir)).expect("infra/ should be excluded by glob");
    let violations = validate(&model);
    assert!(violations.is_empty());
}

#[test]
fn source_include_glob_limits_discovery_to_matching_files() {
    let dir = TempDir::new().unwrap();
    // rete.yaml declares only nodes/*.yaml; users/ is out of scope
    write(
        &dir,
        "rete.yaml",
        r#"
source:
  include: ["nodes/*.yaml"]
rete:
  name: test-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []
services:
  config-server:
    at: mgmt
    addr: "127.0.0.1:9000"
    groups: [config-read]
  config-publisher:
    at: mgmt
    addr: "127.0.0.1:9001"
    groups: [config-write]
groups:
  config-read:
  config-write:
roles:
  node:
    allow: [config-read]
  operator:
    allow: [config-write]
users:
  alice:
    roles: [operator]
"#,
    );
    write(
        &dir,
        "nodes/topology.yaml",
        r#"
nodes:
  mgmt:
    vertices:
      - name: quic0
        kind: link
        type: quic
        address: "1.2.3.4:4433"
"#,
    );
    // This would cause a conflict if picked up; the include glob should prevent that
    write(
        &dir,
        "users/extra-users.yaml",
        r#"
users:
  alice:
    roles: [operator]
"#,
    );
    let model = load(&discovery(&dir)).expect("users/ should not be discovered");
    let violations = validate(&model);
    assert!(violations.is_empty());
}

// ---------------------------------------------------------------------------
// V1-V9: Load + validate end-to-end
// ---------------------------------------------------------------------------

#[test]
fn valid_minimal_config_end_to_end() {
    let dir = TempDir::new().unwrap();
    write(&dir, "rete.yaml", MINIMAL);
    let model = load(&discovery(&dir)).expect("minimal config should load");
    let violations = validate(&model);
    assert!(
        violations.is_empty(),
        "expected no violations, got: {:?}",
        violations.iter().map(|v| &v.message).collect::<Vec<_>>()
    );
}

#[test]
fn missing_config_server_service_triggers_management_node_integrity() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "rete.yaml",
        r#"
rete:
  name: test-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []
nodes:
  mgmt:
    vertices:
      - name: quic0
        kind: link
        type: quic
        address: "1.2.3.4:4433"
services:
  config-publisher:
    at: mgmt
    addr: "127.0.0.1:9001"
    groups: [config-write]
groups:
  config-read:
  config-write:
roles:
  node:
    allow: [config-read]
  operator:
    allow: [config-write]
users:
  alice:
    roles: [operator]
"#,
    );
    let model = load(&discovery(&dir)).unwrap();
    let violations = validate(&model);
    assert!(
        count_violations(&violations, Rule::ManagementNodeIntegrity) >= 1,
        "expected ManagementNodeIntegrity violation"
    );
    assert!(
        violations
            .iter()
            .any(|v| v.rule == Rule::ManagementNodeIntegrity && v.message.contains("config-server")),
        "violation message should name 'config-server'"
    );
}

#[test]
fn no_operator_user_triggers_operator_presence() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "rete.yaml",
        r#"
rete:
  name: test-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []
nodes:
  mgmt:
    vertices:
      - name: quic0
        kind: link
        type: quic
        address: "1.2.3.4:4433"
services:
  config-server:
    at: mgmt
    addr: "127.0.0.1:9000"
    groups: [config-read]
  config-publisher:
    at: mgmt
    addr: "127.0.0.1:9001"
    groups: [config-write]
groups:
  config-read:
  config-write:
roles:
  node:
    allow: [config-read]
  operator:
    allow: [config-write]
users:
  alice:
    roles: []
"#,
    );
    let model = load(&discovery(&dir)).unwrap();
    let violations = validate(&model);
    assert_eq!(
        count_violations(&violations, Rule::OperatorPresence),
        1,
        "expected exactly one OperatorPresence violation"
    );
}

#[test]
fn service_at_undefined_node_triggers_service_placement() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "rete.yaml",
        r#"
rete:
  name: test-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []
nodes:
  mgmt:
    vertices:
      - name: quic0
        kind: link
        type: quic
        address: "1.2.3.4:4433"
services:
  config-server:
    at: mgmt
    addr: "127.0.0.1:9000"
    groups: [config-read]
  config-publisher:
    at: mgmt
    addr: "127.0.0.1:9001"
    groups: [config-write]
  my-app:
    at: ghost-node
    addr: "127.0.0.1:8080"
groups:
  config-read:
  config-write:
roles:
  node:
    allow: [config-read]
  operator:
    allow: [config-write]
users:
  alice:
    roles: [operator]
"#,
    );
    let model = load(&discovery(&dir)).unwrap();
    let violations = validate(&model);
    assert_eq!(
        count_violations(&violations, Rule::ServicePlacement),
        1,
        "expected ServicePlacement violation for 'ghost-node'"
    );
    assert!(
        violations
            .iter()
            .any(|v| v.rule == Rule::ServicePlacement && v.message.contains("ghost-node")),
        "violation message should name the undefined node"
    );
}

#[test]
fn socks5_proxy_without_roles_triggers_principal_role_coherence() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "rete.yaml",
        r#"
rete:
  name: test-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []
nodes:
  mgmt:
    vertices:
      - name: quic0
        kind: link
        type: quic
        address: "1.2.3.4:4433"
services:
  config-server:
    at: mgmt
    addr: "127.0.0.1:9000"
    groups: [config-read]
  config-publisher:
    at: mgmt
    addr: "127.0.0.1:9001"
    groups: [config-write]
  client-app:
    at: mgmt
    addr: "127.0.0.1:8080"
    socks5_proxy: "127.0.0.1:1080"
groups:
  config-read:
  config-write:
roles:
  node:
    allow: [config-read]
  operator:
    allow: [config-write]
users:
  alice:
    roles: [operator]
"#,
    );
    let model = load(&discovery(&dir)).unwrap();
    let violations = validate(&model);
    assert_eq!(
        count_violations(&violations, Rule::PrincipalRoleCoherence),
        1
    );
    assert!(
        violations
            .iter()
            .any(|v| v.rule == Rule::PrincipalRoleCoherence && v.message.contains("client-app")),
        "violation message should name the offending service"
    );
}

#[test]
fn mgmt_node_without_public_address_triggers_management_node_integrity() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "rete.yaml",
        r#"
rete:
  name: test-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []
nodes:
  mgmt:
    vertices:
      - name: quic0
        kind: link
        type: quic
groups:
  config-read:
  config-write:
services:
  config-server:
    at: mgmt
    addr: "127.0.0.1:9000"
    groups: [config-read]
  config-publisher:
    at: mgmt
    addr: "127.0.0.1:9001"
    groups: [config-write]
roles:
  node:
    allow: [config-read]
  operator:
    allow: [config-write]
users:
  alice:
    roles: [operator]
"#,
    );
    let model = load(&discovery(&dir)).unwrap();
    let violations = validate(&model);
    assert!(
        count_violations(&violations, Rule::ManagementNodeIntegrity) >= 1,
        "expected ManagementNodeIntegrity when mgmt node has no public address"
    );
    assert!(
        violations
            .iter()
            .any(|v| v.rule == Rule::ManagementNodeIntegrity && v.message.contains("address")),
        "violation message should mention 'address'"
    );
}

#[test]
fn via_binding_resolves_correctly_on_multi_vertex_node() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "rete.yaml",
        r#"
rete:
  name: test-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []
nodes:
  mgmt:
    vertices:
      - name: quic0
        kind: link
        type: quic
        address: "1.2.3.4:4433"
      - name: mesh0
        kind: mesh
        type: udp
services:
  config-server:
    at: mgmt
    via: quic0
    addr: "127.0.0.1:9000"
    groups: [config-read]
  config-publisher:
    at: mgmt
    via: quic0
    addr: "127.0.0.1:9001"
    groups: [config-write]
groups:
  config-read:
  config-write:
roles:
  node:
    allow: [config-read]
  operator:
    allow: [config-write]
users:
  alice:
    roles: [operator]
    nodes:
      - at: mgmt
        via: quic0
"#,
    );
    let model = load(&discovery(&dir)).unwrap();
    let violations = validate(&model);
    assert_eq!(
        count_violations(&violations, Rule::WorkloadVertexBinding),
        0,
        "explicit via: quic0 should resolve without violation"
    );
    assert!(
        violations.is_empty(),
        "expected no violations, got: {:?}",
        violations.iter().map(|v| &v.message).collect::<Vec<_>>()
    );
}

#[test]
fn multi_file_split_config_loads_and_validates_clean() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "rete.yaml",
        r#"
source:
  include: ["**/*.yaml"]
rete:
  name: test-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []
nodes:
  mgmt:
    vertices:
      - name: quic0
        kind: link
        type: quic
        address: "1.2.3.4:4433"
services:
  config-server:
    at: mgmt
    addr: "127.0.0.1:9000"
    groups: [config-read]
  config-publisher:
    at: mgmt
    addr: "127.0.0.1:9001"
    groups: [config-write]
"#,
    );
    write(
        &dir,
        "access/roles.yaml",
        r#"
groups:
  config-read:
  config-write:
roles:
  node:
    allow: [config-read]
  operator:
    allow: [config-write]
"#,
    );
    write(
        &dir,
        "access/users.yaml",
        r#"
users:
  alice:
    roles: [operator]
  bob:
    roles: [node]
    nodes:
      - at: mgmt
"#,
    );
    let model = load(&discovery(&dir)).expect("multi-file config should load");
    assert_eq!(model.users.len(), 2);
    let violations = validate(&model);
    assert!(
        violations.is_empty(),
        "expected no violations, got: {:?}",
        violations.iter().map(|v| &v.message).collect::<Vec<_>>()
    );
}

#[test]
fn cross_file_cross_reference_error_is_reported() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "rete.yaml",
        r#"
source:
  include: ["**/*.yaml"]
rete:
  name: test-rete
  ca:
    cert: ca.pem
  signers:
    mgmt:
      keys: []
nodes:
  mgmt:
    vertices:
      - name: quic0
        kind: link
        type: quic
        address: "1.2.3.4:4433"
services:
  config-server:
    at: mgmt
    addr: "127.0.0.1:9000"
    groups: [config-read]
  config-publisher:
    at: mgmt
    addr: "127.0.0.1:9001"
    groups: [config-write]
groups:
  config-read:
  config-write:
roles:
  node:
    allow: [config-read]
  operator:
    allow: [config-write]
  fancy:
    allow: [ghost-group]
users:
  alice:
    roles: [operator]
"#,
    );
    // ghost-group is referenced by 'fancy' role but never defined anywhere
    let model = load(&discovery(&dir))
        .expect("load should succeed; reference errors are caught by validate");
    let violations = validate(&model);
    assert_eq!(
        count_violations(&violations, Rule::CrossReferences),
        1,
        "expected one CrossReferences violation for ghost-group"
    );
    assert!(
        violations
            .iter()
            .any(|v| v.rule == Rule::CrossReferences && v.message.contains("ghost-group")),
        "violation message should name 'ghost-group'"
    );
}
