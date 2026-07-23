// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! `retectl compile` integration test.
//!
//! Drives the command as an operator does — a repo with `rete.yaml`, no flags —
//! and checks the tree it writes is one `flor vertex run` would accept: the
//! documented paths, and artifacts that parse and validate as the real
//! `Envelope<VertexMgmtPayload>`.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use flor::config::artifact::{Envelope, VertexMgmtPayload};

const RETE: &str = r#"
rete:
  name: demo.flor
  ca:
    cert: certs/ca.crt
  signers:
    mgmt:
      keys:
        - { name: primary, cert: certs/management-planes/primary.crt }

nodes:
  mgmt01:
    vertices:
      - { name: public, kind: link, type: quic, address: "9.10.11.12:4433" }
  alpha:
    vertices:
      - { name: public, kind: link, type: quic, address: "1.2.3.4:4433" }
  alice-laptop:
    vertices:
      - { name: flor, kind: link, type: quic }

services:
  coordinator:
    at: mgmt01
    addr: "127.0.0.1:9000"
    groups: [coordinator-sync]
  coordinator-publisher:
    at: mgmt01
    addr: "127.0.0.1:9001"
    groups: [coordinator-publish]
  api:
    at: alpha
    addr: "127.0.0.1:8000"
    groups: [api]

groups:
  coordinator-sync:
  coordinator-publish:
  api:

roles:
  node: { allow: [coordinator-sync] }
  operator: { allow: [coordinator-publish] }
  developer: { allow: [api] }

users:
  alice:
    roles: [operator, developer]
    nodes:
      - { at: alice-laptop, socks5_proxy: "127.0.0.1:1080" }
"#;

fn retectl() -> Command {
    Command::cargo_bin("retectl").unwrap()
}

fn repo(config: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rete.yaml"), config).unwrap();
    dir
}

fn compiled(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join(".flor").join("compiled")
}

/// Parse an artifact the way `flor` does, and run the artifact schema's own
/// semantic rules over it.
fn load_artifact(path: &Path, expected_name: &str) -> Envelope<VertexMgmtPayload> {
    let json = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let env: Envelope<VertexMgmtPayload> =
        serde_json::from_slice(&json).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    env.validate(expected_name)
        .unwrap_or_else(|e| panic!("validate {}: {e:?}", path.display()));
    env
}

#[test]
fn compiles_every_node_into_the_documented_tree() {
    let dir = repo(RETE);
    retectl()
        .args(["compile", "--repo"])
        .arg(dir.path())
        .assert()
        .success();

    let out = compiled(&dir);
    let alpha = load_artifact(&out.join("alpha/mgmt/public.json"), "public");
    assert_eq!(alpha.node, "alpha");
    assert_eq!(alpha.version, 1);

    // The artifact holds only what this node needs: its own workloads, and the
    // ACL rows for the target it hosts. No synthesized node-agent principal.
    let ids: Vec<String> = alpha
        .payload
        .workloads
        .iter()
        .map(|w| w.spiffe_id.to_string())
        .collect();
    assert_eq!(ids, ["spiffe://demo.flor/service/api"]);
    assert_eq!(alpha.payload.ingress.len(), 1);
    assert_eq!(
        alpha.payload.ingress[0].target.to_string(),
        "spiffe://demo.flor/service/api"
    );
    assert_eq!(
        alpha.payload.ingress[0]
            .allow
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>(),
        ["spiffe://demo.flor/user/alice"]
    );

    // The user device is named for its own vertex, not a fixed filename.
    let alice = load_artifact(&out.join("alice-laptop/mgmt/flor.json"), "flor");
    assert_eq!(alice.node, "alice-laptop");

    load_artifact(&out.join("mgmt01/mgmt/public.json"), "public");
}

#[test]
fn version_advances_on_every_compile() {
    let dir = repo(RETE);
    let out = compiled(&dir);
    let path = out.join("alpha/mgmt/public.json");

    for expected in 1..=3 {
        retectl()
            .args(["compile", "--repo"])
            .arg(dir.path())
            .assert()
            .success();
        assert_eq!(load_artifact(&path, "public").version, expected);
    }
}

#[test]
fn every_node_advances_to_the_same_version() {
    // The tree is the counter: every compile rewrites every node, so no artifact
    // is ever left behind at an older number.
    let dir = repo(RETE);
    let out = compiled(&dir);

    for expected in 1..=2 {
        retectl()
            .args(["compile", "--repo"])
            .arg(dir.path())
            .assert()
            .success();

        for (node, vertex) in [
            ("alpha", "public"),
            ("mgmt01", "public"),
            ("alice-laptop", "flor"),
        ] {
            let path = out.join(node).join("mgmt").join(format!("{vertex}.json"));
            assert_eq!(load_artifact(&path, vertex).version, expected, "{node}");
        }
    }
}

#[test]
fn a_node_dropped_from_the_source_stops_being_shipped() {
    let dir = repo(RETE);
    let out = compiled(&dir);

    retectl()
        .args(["compile", "--repo"])
        .arg(dir.path())
        .assert()
        .success();
    assert!(out.join("mgmt01").exists());

    // Move the mgmt services onto alpha and drop the mgmt01 node entirely.
    let trimmed = RETE
        .replace("  mgmt01:\n    vertices:\n      - { name: public, kind: link, type: quic, address: \"9.10.11.12:4433\" }\n", "")
        .replace("at: mgmt01", "at: alpha");
    std::fs::write(dir.path().join("rete.yaml"), trimmed).unwrap();

    retectl()
        .args(["compile", "--repo"])
        .arg(dir.path())
        .assert()
        .success();

    assert!(!out.join("mgmt01").exists(), "stale node must be cleared");
    assert_eq!(
        load_artifact(&out.join("alpha/mgmt/public.json"), "public").version,
        2
    );
}

#[test]
fn out_override_writes_elsewhere() {
    let dir = repo(RETE);
    let out = tempfile::tempdir().unwrap();

    retectl()
        .args(["compile", "--repo"])
        .arg(dir.path())
        .arg("--out")
        .arg(out.path())
        .assert()
        .success();

    load_artifact(&out.path().join("alpha/mgmt/public.json"), "public");
    assert!(!compiled(&dir).exists());
}

#[test]
fn file_override_bypasses_discovery() {
    let dir = repo(RETE);
    // A stray YAML the default glob would pick up; `-f` must ignore it.
    std::fs::write(
        dir.path().join("junk.yaml"),
        "services:\n  ghost:\n    bogus: 1\n",
    )
    .unwrap();

    retectl()
        .args(["compile", "--repo"])
        .arg(dir.path())
        .arg("-f")
        .arg(dir.path().join("rete.yaml"))
        .assert()
        .success();

    load_artifact(&compiled(&dir).join("alpha/mgmt/public.json"), "public");
}

#[test]
fn refuses_to_compile_an_invalid_rete() {
    // Drop the operator: nobody could publish, so the validator rejects it and
    // compile writes nothing.
    let dir = repo(&RETE.replace("roles: [operator, developer]", "roles: [developer]"));

    let output = retectl()
        .args(["compile", "--repo"])
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success(), "expected non-zero exit");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("operator presence"),
        "expected violation in stderr, got: {stderr}"
    );
    assert!(!compiled(&dir).exists(), "no artifacts on a failed compile");
}
