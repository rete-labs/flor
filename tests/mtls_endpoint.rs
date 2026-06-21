// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! End-to-end mTLS over two real `QuicEndpoint`s sharing a rete CA.
//!
//! Drives the public transport API (`TransportBundle` → `QuicConnector` /
//! `QuicPublisher` / `QuicAcceptor`) over loopback UDP, completing real QUIC
//! mTLS handshakes. Covers the happy path (both peers' identities surface) and
//! the two rejection paths the verifiers gate: an untrusted caller and a target
//! the server never published.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use flor::core::identity::{
    Ca, Dialable, Kind, SpiffeId, TrustDomain, X509Bundle, X509Svid, build_id_in_rete, keygen_csr,
    load_bundle_from_pem, load_svid_from_pem,
};
use flor::core::transport::endpoint::connection::{Accept, Open};
use flor::core::transport::{AddrMap, EndpointAddr, TransportBundle, TrustBundle};

const TRUST_DOMAIN: &str = "demo.flor";

fn day() -> Duration {
    Duration::from_secs(3600)
}

fn td() -> TrustDomain {
    TrustDomain::new(TRUST_DOMAIN).unwrap()
}

fn service_id(name: &str) -> SpiffeId {
    build_id_in_rete(&td(), Kind::Service, name).unwrap()
}

fn user_id(name: &str) -> SpiffeId {
    build_id_in_rete(&td(), Kind::User, name).unwrap()
}

/// Mint an SVID for `id`/`kind`, signed by `ca`.
fn mint(ca: &Ca, id: &SpiffeId, kind: Kind) -> X509Svid {
    let (key, csr) = keygen_csr(id).unwrap();
    let leaf = ca.sign_csr(csr.as_bytes(), id, kind, day()).unwrap();
    load_svid_from_pem(leaf.as_bytes(), key.serialize_pem().as_bytes()).unwrap()
}

fn bundle_of(ca: &Ca) -> Arc<X509Bundle> {
    Arc::new(load_bundle_from_pem(&td(), ca.cert_pem().as_bytes()).unwrap())
}

/// Minimal carrier of [`TransportDeps`] inputs: `#[fundle::deps]` generates a
/// `From<T: AsRef<EndpointAddr> + AsRef<AddrMap> + AsRef<TrustBundle>>`.
struct Deps {
    endpoint_addr: EndpointAddr,
    addr_map: AddrMap,
    trust_bundle: TrustBundle,
}

impl AsRef<EndpointAddr> for Deps {
    fn as_ref(&self) -> &EndpointAddr {
        &self.endpoint_addr
    }
}
impl AsRef<AddrMap> for Deps {
    fn as_ref(&self) -> &AddrMap {
        &self.addr_map
    }
}
impl AsRef<TrustBundle> for Deps {
    fn as_ref(&self) -> &TrustBundle {
        &self.trust_bundle
    }
}

/// Build a transport bundle bound to `listen`, dialing targets per `addr_map`,
/// validating peers against `trust_bundle`.
fn node(
    listen: SocketAddr,
    addr_map: HashMap<SpiffeId, SocketAddr>,
    trust_bundle: Arc<X509Bundle>,
) -> TransportBundle {
    TransportBundle::try_new(Deps {
        endpoint_addr: EndpointAddr(listen),
        addr_map: AddrMap(addr_map),
        trust_bundle: TrustBundle(trust_bundle),
    })
    .expect("transport bundle should build")
}

async fn connect_within(
    connector: &flor::core::transport::QuicConnector,
    caller: &X509Svid,
    target: &Dialable,
) -> Result<flor::core::transport::endpoint::connection::QuicConnection, String> {
    tokio::time::timeout(Duration::from_secs(5), connector.connect(caller, target))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| format!("{e:?}"))
}

#[tokio::test]
async fn mtls_round_trip_exposes_peer_identities() {
    let ca = Ca::init(&td(), day()).unwrap();
    let trust = bundle_of(&ca);

    let echo_id = service_id("echo");
    let alice_id = user_id("alice");
    let echo_svid = mint(&ca, &echo_id, Kind::Service);
    let alice_svid = mint(&ca, &alice_id, Kind::User);

    let server_addr: SocketAddr = "127.0.0.1:34110".parse().unwrap();
    let client_addr: SocketAddr = "127.0.0.1:34111".parse().unwrap();

    let server = node(server_addr, HashMap::new(), trust.clone());
    let client = node(
        client_addr,
        HashMap::from([(echo_id.clone(), server_addr)]),
        trust.clone(),
    );

    let mut acceptor = server
        .endpoint_publisher
        .publish(vec![echo_svid])
        .await
        .expect("publish");

    let target = Dialable::new(echo_id.clone()).unwrap();

    let connect = async {
        connect_within(&client.endpoint_connector, &alice_svid, &target)
            .await
            .expect("connect should succeed")
    };
    let accept = async {
        tokio::time::timeout(Duration::from_secs(5), acceptor.accept())
            .await
            .expect("accept timed out")
            .expect("a connection should be accepted")
    };
    let (client_conn, (target_id, server_conn)) = tokio::join!(connect, accept);

    // The acceptor is tagged with which published service was dialed; each side
    // sees the other's verified identity.
    assert_eq!(target_id, echo_id, "dispatched target identity");
    assert_eq!(server_conn.peer_id(), &alice_id, "server sees the caller");
    assert_eq!(client_conn.peer_id(), &echo_id, "client sees the server");

    // A stream round-trip confirms the authenticated channel actually carries data.
    let (mut c_send, mut c_recv) = client_conn.open_bi().await.unwrap();
    c_send.write_all(b"hello mtls").await.unwrap();
    let _ = c_send.finish();

    let (mut s_send, mut s_recv) = server_conn.accept_bi().await.unwrap();
    let mut got = vec![0u8; 10];
    s_recv.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hello mtls");
    s_send.write_all(&got).await.unwrap();
    let _ = s_send.finish();

    let mut echoed = vec![0u8; 10];
    c_recv.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"hello mtls");
}

#[tokio::test]
async fn caller_from_untrusted_ca_is_rejected() {
    let ca = Ca::init(&td(), day()).unwrap();
    let rogue = Ca::init(&td(), day()).unwrap();
    let trust = bundle_of(&ca);

    let echo_id = service_id("echo");
    let echo_svid = mint(&ca, &echo_id, Kind::Service);
    // A caller with the right SPIFFE ID but signed by a CA the rete doesn't trust.
    let rogue_alice = mint(&rogue, &user_id("alice"), Kind::User);

    let server_addr: SocketAddr = "127.0.0.1:34120".parse().unwrap();
    let client_addr: SocketAddr = "127.0.0.1:34121".parse().unwrap();

    let server = node(server_addr, HashMap::new(), trust.clone());
    let client = node(
        client_addr,
        HashMap::from([(echo_id.clone(), server_addr)]),
        trust.clone(),
    );
    let mut acceptor = server
        .endpoint_publisher
        .publish(vec![echo_svid])
        .await
        .expect("publish");

    // The client may briefly establish 1-RTT before the server's client-cert
    // rejection alert arrives (QUIC mTLS), so `connect` is not a reliable signal.
    // The authoritative one is that the *server* never accepts the connection —
    // its `SpiffeClientCertVerifier` rejected the untrusted chain.
    let target = Dialable::new(echo_id).unwrap();
    let _ = connect_within(&client.endpoint_connector, &rogue_alice, &target).await;

    let accepted = tokio::time::timeout(Duration::from_secs(2), acceptor.accept()).await;
    assert!(
        accepted.is_err(),
        "server must not accept a caller signed by an untrusted CA"
    );
}

#[tokio::test]
async fn dialing_unpublished_target_is_rejected() {
    let ca = Ca::init(&td(), day()).unwrap();
    let trust = bundle_of(&ca);

    let echo_id = service_id("echo");
    let alice_svid = mint(&ca, &user_id("alice"), Kind::User);

    let server_addr: SocketAddr = "127.0.0.1:34130".parse().unwrap();
    let client_addr: SocketAddr = "127.0.0.1:34131".parse().unwrap();

    // Server is up but publishes nothing — it has no cert to present for `echo`.
    let _server = node(server_addr, HashMap::new(), trust.clone());
    let client = node(
        client_addr,
        HashMap::from([(echo_id.clone(), server_addr)]),
        trust.clone(),
    );

    let target = Dialable::new(echo_id).unwrap();
    let result = connect_within(&client.endpoint_connector, &alice_svid, &target).await;
    assert!(
        result.is_err(),
        "dialing a service the server never published must fail"
    );
}
