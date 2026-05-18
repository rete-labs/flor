// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Cross-binary mint-flow integration test.
//!
//! Exercises the plumbing surface end-to-end:
//!   1. `florctl ca init` produces ca.crt + ca.key.
//!   2. `flor id keygen` produces alice.key + alice.csr.
//!   3. `florctl ca sign` consumes the CSR and emits alice.crt.
//!   4. The crate verifies alice.crt was issued by the CA and carries the
//!      expected SPIFFE ID.

use std::path::PathBuf;

use assert_cmd::Command;
use flor::core::identity::{Ca, SpiffeId};

fn flor() -> Command {
    Command::cargo_bin("flor").unwrap()
}

fn florctl() -> Command {
    Command::cargo_bin("florctl").unwrap()
}

fn p(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

#[test]
fn end_to_end_mint_flow_user_principal() {
    let dir = tempfile::tempdir().unwrap();
    let ca_cert = p(&dir, "ca.crt");
    let ca_key = p(&dir, "ca.key");
    let alice_key = p(&dir, "alice.key");
    let alice_csr = p(&dir, "alice.csr");
    let alice_cert = p(&dir, "alice.crt");

    florctl()
        .args(["ca", "init", "--trust-domain", "demo.flor", "--out-cert"])
        .arg(&ca_cert)
        .arg("--out-key")
        .arg(&ca_key)
        .assert()
        .success();

    flor()
        .args([
            "id",
            "keygen",
            "--kind",
            "user",
            "--name",
            "alice",
            "--trust-domain",
            "demo.flor",
            "--out-key",
        ])
        .arg(&alice_key)
        .arg("--out-csr")
        .arg(&alice_csr)
        .assert()
        .success();

    florctl()
        .args(["ca", "sign", "--kind", "user", "--name", "alice", "--csr"])
        .arg(&alice_csr)
        .arg("--ca-cert")
        .arg(&ca_cert)
        .arg("--ca-key")
        .arg(&ca_key)
        .arg("--out")
        .arg(&alice_cert)
        .assert()
        .success();

    // Verify the cert was issued by our CA and carries the expected SPIFFE ID.
    let ca = Ca::from_pem(
        &std::fs::read(&ca_cert).unwrap(),
        &std::fs::read(&ca_key).unwrap(),
    )
    .unwrap();
    let leaf_pem = std::fs::read(&alice_cert).unwrap();
    let recovered = ca.verify(&leaf_pem).unwrap();
    assert_eq!(
        recovered,
        SpiffeId::new("spiffe://demo.flor/user/alice").unwrap()
    );
}

#[test]
fn end_to_end_mint_flow_node_scoped_service() {
    let dir = tempfile::tempdir().unwrap();
    let ca_cert = p(&dir, "ca.crt");
    let ca_key = p(&dir, "ca.key");
    let key = p(&dir, "db.key");
    let csr = p(&dir, "db.csr");
    let cert = p(&dir, "db.crt");

    florctl()
        .args(["ca", "init", "--trust-domain", "demo.flor", "--out-cert"])
        .arg(&ca_cert)
        .arg("--out-key")
        .arg(&ca_key)
        .assert()
        .success();

    flor()
        .args([
            "id",
            "keygen",
            "--kind",
            "service",
            "--name",
            "db",
            "--trust-domain",
            "demo.flor",
            "--scope",
            "alpha",
            "--out-key",
        ])
        .arg(&key)
        .arg("--out-csr")
        .arg(&csr)
        .assert()
        .success();

    florctl()
        .args([
            "ca", "sign", "--kind", "service", "--name", "db", "--scope", "alpha", "--csr",
        ])
        .arg(&csr)
        .arg("--ca-cert")
        .arg(&ca_cert)
        .arg("--ca-key")
        .arg(&ca_key)
        .arg("--out")
        .arg(&cert)
        .assert()
        .success();

    let ca = Ca::from_pem(
        &std::fs::read(&ca_cert).unwrap(),
        &std::fs::read(&ca_key).unwrap(),
    )
    .unwrap();
    let leaf_pem = std::fs::read(&cert).unwrap();
    let recovered = ca.verify(&leaf_pem).unwrap();
    assert_eq!(
        recovered,
        SpiffeId::new("spiffe://demo.flor/service/alpha/db").unwrap()
    );
}

#[test]
fn ca_init_writes_key_with_mode_0600() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ca_cert = p(&dir, "ca.crt");
        let ca_key = p(&dir, "ca.key");

        florctl()
            .args(["ca", "init", "--trust-domain", "demo.flor", "--out-cert"])
            .arg(&ca_cert)
            .arg("--out-key")
            .arg(&ca_key)
            .assert()
            .success();

        let mode = std::fs::metadata(&ca_key).unwrap().permissions().mode();
        // Compare the low 9 bits (rwx for owner/group/other).
        assert_eq!(mode & 0o777, 0o600, "got mode {:o}", mode & 0o777);
    }
}

#[test]
fn ca_sign_rejects_kind_mismatch() {
    // CSR was minted as `user/alice`, but operator authorises `node/alpha`.
    let dir = tempfile::tempdir().unwrap();
    let ca_cert = p(&dir, "ca.crt");
    let ca_key = p(&dir, "ca.key");
    let key = p(&dir, "alice.key");
    let csr = p(&dir, "alice.csr");
    let cert = p(&dir, "out.crt");

    florctl()
        .args(["ca", "init", "--trust-domain", "demo.flor", "--out-cert"])
        .arg(&ca_cert)
        .arg("--out-key")
        .arg(&ca_key)
        .assert()
        .success();

    flor()
        .args([
            "id",
            "keygen",
            "--kind",
            "user",
            "--name",
            "alice",
            "--trust-domain",
            "demo.flor",
            "--out-key",
        ])
        .arg(&key)
        .arg("--out-csr")
        .arg(&csr)
        .assert()
        .success();

    florctl()
        .args(["ca", "sign", "--kind", "node", "--name", "alpha", "--csr"])
        .arg(&csr)
        .arg("--ca-cert")
        .arg(&ca_cert)
        .arg("--ca-key")
        .arg(&ca_key)
        .arg("--out")
        .arg(&cert)
        .assert()
        .failure();
}

#[test]
fn id_keygen_rejects_scope_for_user_kind() {
    // `--scope` only makes sense for service / vertex.
    let dir = tempfile::tempdir().unwrap();
    let key = p(&dir, "alice.key");
    let csr = p(&dir, "alice.csr");

    flor()
        .args([
            "id",
            "keygen",
            "--kind",
            "user",
            "--name",
            "alice",
            "--trust-domain",
            "demo.flor",
            "--scope",
            "alpha",
            "--out-key",
        ])
        .arg(&key)
        .arg("--out-csr")
        .arg(&csr)
        .assert()
        .failure();
}
