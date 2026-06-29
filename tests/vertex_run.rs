// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.
//
// End-to-end test of the link-vertex runtime, hermetic in-process: build two
// rete roots (an initiator and a server vertex) from compiled artifacts, run
// each `flor` vertex, and drive a SOCKS5 connection through the initiator that
// relays over real QUIC mTLS to the server's tcp-echo upstream. Mirrors
// scripts/e2e-relay.sh, but with minted material in tempdirs.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::thread;
use std::time::Duration;

use flor::core::identity::{Ca, Kind, SpiffeId, TrustDomain, keygen_csr};
use flor::vertex::{self, ConfigBundle};

use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TRUST_DOMAIN: &str = "demo.flor";
// Uncommon ports, distinct from the e2e-relay.sh topology so they do not interfere.
// Alpha is initiator-only node, so it uses ephemeral QUIC address.
const ALPHA_SOCKS5: &str = "127.0.0.1:19080";
const BETA_QUIC: &str = "127.0.0.1:19440";
const ECHO_UPSTREAM: &str = "127.0.0.1:19450";
const TARGET_HOST: &str = "tcp-echo.beta.demo.flor.rete";

fn day() -> Duration {
    Duration::from_secs(3600)
}

/// Mint an SVID for `uri`/`kind` from `ca` and write `<file>.crt`/`.key` flat
/// into the rete root `root`.
fn write_svid(ca: &Ca, root: &Path, uri: &str, kind: Kind, file: &str) {
    let id = SpiffeId::new(uri).unwrap();
    let (key, csr) = keygen_csr(&id).unwrap();
    let leaf = ca.sign_csr(csr.as_bytes(), &id, kind, day()).unwrap();
    std::fs::write(root.join(format!("{file}.crt")), leaf).unwrap();
    std::fs::write(root.join(format!("{file}.key")), key.serialize_pem()).unwrap();
}

/// Write a mgmt vertex artifact wrapping `payload` to `mgmt/vertices/flor.json`
/// under the rete root, as the agent/compiler would place it.
fn write_artifact(root: &Path, node: &str, payload: Value) {
    let env = json!({
        "schema_version": "1.0",
        "plane": "mgmt",
        "kind": "vertex",
        "version": 1,
        "node": node,
        "name": "flor",
        "generated_at": "2026-01-01T00:00:00Z",
        "payload": payload,
        "signature": { "alg": "none", "key_id": "spiffe://demo.flor/management-plane/dev", "value": "x" }
    });
    let dir = root.join("mgmt/vertices");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("flor.json"), serde_json::to_vec(&env).unwrap()).unwrap();
}

/// A TCP echo upstream (what the server vertex's tcp-echo service forwards to).
async fn echo_server(addr: SocketAddr) {
    let listener = TcpListener::bind(addr).await.expect("bind echo upstream");
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }
}

/// One SOCKS5 CONNECT to `host` through `socks5`, echoing `payload` and
/// returning the bytes read back. Returns an error if any step fails (so the
/// caller can retry while the vertices come up).
async fn try_relay(socks5: SocketAddr, host: &str, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(socks5).await?;
    s.write_all(&[0x05, 0x01, 0x00]).await?; // greeting: no-auth
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(io::Error::other("SOCKS5 no-auth not accepted"));
    }
    // CONNECT, ATYP=domain, port 1 (the connector ignores the port).
    let host = host.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&[0x00, 0x01]);
    s.write_all(&req).await?;
    let mut reply = [0u8; 10]; // VER REP RSV ATYP(v4) + BND.ADDR(4) + BND.PORT(2)
    s.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS5 CONNECT failed: {}",
            reply[1]
        )));
    }
    s.write_all(payload).await?;
    let mut got = vec![0u8; payload.len()];
    s.read_exact(&mut got).await?;
    Ok(got)
}

/// Run a vertex on its own OS thread + runtime (`vertex::run` is driven like the
/// binary's `block_on`, sidestepping `Send` bounds on the actor handles).
fn spawn_vertex(config: ConfigBundle) {
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("vertex runtime");
        let _ = rt.block_on(vertex::run(config));
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn link_vertex_relays_socks5_to_tcp_echo() {
    let td = TrustDomain::new(TRUST_DOMAIN).unwrap();
    let ca = Ca::init(&td, day()).unwrap();

    // Initiator rete root (alice, a SOCKS5 caller).
    let alpha_dir = TempDir::new().unwrap();
    let alpha_root = alpha_dir.path();
    std::fs::write(alpha_root.join("ca.crt"), ca.cert_pem()).unwrap();
    write_svid(
        &ca,
        alpha_root,
        "spiffe://demo.flor/user/alice",
        Kind::User,
        "alice",
    );

    // Server rete root (tcp-echo, relaying to the echo upstream).
    let beta_dir = TempDir::new().unwrap();
    let beta_root = beta_dir.path();
    std::fs::write(beta_root.join("ca.crt"), ca.cert_pem()).unwrap();
    write_svid(
        &ca,
        beta_root,
        "spiffe://demo.flor/service/beta/tcp-echo",
        Kind::Service,
        "tcp-echo",
    );

    write_artifact(
        alpha_root,
        "alpha",
        json!({
            "kind": "link",
            "ca_cert_path": "ca.crt",
            "transport_endpoint": { "type": "quic" },
            "connection_manager": { "adapters": [ { "name": "wire", "type": "udp" } ] },
            "workloads": [
                { "spiffe_id": "spiffe://demo.flor/user/alice",
                  "identity": { "cert_path": "alice.crt", "priv_path": "alice.key" },
                  "io": [ { "kind": "socks5", "listen": ALPHA_SOCKS5 } ] }
            ],
            "links": [ { "type": "enum", "members": [
                { "name": "tcp-echo", "peer": "spiffe://demo.flor/service/beta/tcp-echo", "via": { "type": "udp", "adapter": "wire", "addr": BETA_QUIC } }
            ] } ],
            "egress": [ { "target": "spiffe://demo.flor/service/beta/tcp-echo", "allow": ["spiffe://demo.flor/user/alice"] } ]
        }),
    );
    write_artifact(
        beta_root,
        "beta",
        json!({
            "kind": "link",
            "ca_cert_path": "ca.crt",
            "transport_endpoint": { "type": "quic" },
            "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": BETA_QUIC } ] },
            "workloads": [
                { "spiffe_id": "spiffe://demo.flor/service/beta/tcp-echo",
                  "identity": { "cert_path": "tcp-echo.crt", "priv_path": "tcp-echo.key" },
                  "io": [ { "kind": "tcp", "upstream": ECHO_UPSTREAM } ] }
            ],
            "ingress": [ { "target": "spiffe://demo.flor/service/beta/tcp-echo", "allow": ["spiffe://demo.flor/user/alice"] } ]
        }),
    );

    let alpha_config = ConfigBundle::load(alpha_root, "flor").unwrap();
    let beta_config = ConfigBundle::load(beta_root, "flor").unwrap();

    tokio::spawn(echo_server(ECHO_UPSTREAM.parse().unwrap()));
    spawn_vertex(beta_config);
    spawn_vertex(alpha_config);

    let socks5: SocketAddr = ALPHA_SOCKS5.parse().unwrap();
    let nonce = b"flor-vertex-run-e2e-nonce".to_vec();

    // Retry while the vertices bind and beta's QUIC endpoint comes up; the
    // overall timeout fails the test if the relay never completes.
    let relayed = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(Ok(got)) = tokio::time::timeout(
                Duration::from_secs(2),
                try_relay(socks5, TARGET_HOST, &nonce),
            )
            .await
                && got == nonce
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    })
    .await;

    assert!(
        relayed.is_ok(),
        "SOCKS5 → mTLS → tcp-echo relay did not round-trip in time"
    );
}
