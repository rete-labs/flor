// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::sync::Arc;

use error_stack::{Report, ResultExt, bail};
use mockall_double::double;
use quinn::{
    ClientConfig, ServerConfig, VarInt,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    sign::CertifiedKey,
    version::TLS13,
};

use super::{Error, resolver::Resolver};

mod mocks;
#[double]
use mocks::Endpoint;

pub mod actor;
pub use actor::{QuicAcceptor, QuicConnector, QuicHandle, QuicPublisher};

pub mod connection;
use connection::{HandshakeInfo, QuicConnection};

mod registry;

mod verifier;
use verifier::{
    ServerCertRegistry, SpiffeClientCertVerifier, SpiffeResolvesServerCert,
    SpiffeServerCertVerifier,
};

use crate::core::identity::{Dialable, X509Bundle, X509Svid};

/// QUIC-based Florete Endpoint.
#[derive(Clone)]
struct QuicEndpoint {
    endpoint: Endpoint,
    resolver: Arc<dyn Resolver>,
    /// Published-cert registry: which SVID to present for an SNI, and where to
    /// route the accepted connection. Shared with the actor that mutates it.
    registry: Arc<registry::PublishedServices>,
    /// Rete trust anchors both mTLS verifiers validate peers against.
    trust_bundle: Arc<X509Bundle>,
}

// Close was caused by the endpoint, either normally or by internal error
const ENDPOINT_CLOSE_CODE: u32 = 0;
// Flor protocol string for ALPN
const FLOR_ALPN: &str = "flor/1";

/// The result of one successful [`QuicEndpoint::accept`] step (`Err` is a fault).
enum AcceptOutcome {
    /// A connection was authenticated and dispatched; keep accepting.
    Dispatched,
    /// The endpoint has shut down; stop the accept loop.
    Closed,
}

/// Why a [`QuicEndpoint::connect`] attempt did not yield a connection.
///
/// A routine dial failure is the caller's to handle, whereas a fault means
/// the endpoint itself is broken and must be shut down.
enum ConnectError {
    /// A routine, per-call failure — unresolvable target, unreachable peer, or a
    /// handshake the verifiers rejected. Reported to the dialing caller; the
    /// endpoint should be kept up.
    External(Report<Error>),
    /// An internal inconsistency: the endpoint's invariant is broken, so it must
    /// be shut down.
    Internal(Report<Error>),
}

/// The SNI routing label for a dial target: the transport's SNI-derivation seam.
/// Today the rendered `.rete` name; the receiver resolves it by registry lookup,
/// never by parsing an identity out of it (ADR-0007). Used by both the dialing
/// side (`connect`) and the publishing side (the registry key).
fn sni_for(target: &Dialable) -> String {
    target.render()
}

/// rustls conversions for a SPIFFE [`X509Svid`] (extension trait).
///
/// Lives in the transport layer rather than `identity` so the identity module
/// stays free of rustls types (`CertifiedKey`, signing keys).
trait SvidTls {
    /// The SVID's certificate chain (leaf first) and PKCS#8 private key, as the
    /// DER types rustls configs consume. No PEM round-trip — `X509Svid` holds DER.
    fn cert_chain_and_key(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

    /// The SVID as a rustls [`CertifiedKey`] — the certificate an endpoint
    /// presents for this identity.
    fn certified_key(&self) -> Result<Arc<CertifiedKey>, Report<Error>>;
}

impl SvidTls for X509Svid {
    fn cert_chain_and_key(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let chain = self
            .cert_chain()
            .iter()
            .map(|c| CertificateDer::from(c.as_bytes().to_vec()))
            .collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            self.private_key().as_bytes().to_vec(),
        ));
        (chain, key)
    }

    fn certified_key(&self) -> Result<Arc<CertifiedKey>, Report<Error>> {
        let (chain, key) = self.cert_chain_and_key();
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).change_context(
            Error("SVID private key is not a supported signing key".into()),
        )?;
        Ok(Arc::new(CertifiedKey::new(chain, signing_key)))
    }
}

impl QuicEndpoint {
    /// Create new QUIC endpoint, uses provided resolver for outgoing connections and works over
    /// UDP socket. Published services are managed dynamically through the shared
    /// `registry`, injected at actor spawn time.
    fn new(
        resolver: Arc<dyn Resolver>,
        socket: std::net::UdpSocket,
        registry: Arc<registry::PublishedServices>,
        trust_bundle: Arc<X509Bundle>,
    ) -> Result<Self, Report<Error>> {
        let runtime = quinn::default_runtime()
            .ok_or_else(|| Error("Failed to get default async runtime".into()))?;
        let async_socket = runtime
            .wrap_udp_socket(socket)
            .change_context(Error("Failed to wrap UDP socket".into()))?;
        Self::new_with_abstract_socket(resolver, runtime, async_socket, registry, trust_bundle)
    }

    /// Create new QUIC endpoint that works over quinn's abstract socket and runtime.
    /// This constructor allows using custom UDP-like sockets.
    pub fn new_with_abstract_socket(
        resolver: Arc<dyn Resolver>,
        runtime: Arc<dyn quinn::Runtime>,
        socket: Arc<dyn quinn::AsyncUdpSocket>,
        registry: Arc<registry::PublishedServices>,
        trust_bundle: Arc<X509Bundle>,
    ) -> Result<Self, Report<Error>> {
        // mTLS server: require + validate client certs against the rete bundle,
        // and present the SVID the SNI routes to (by registry lookup, not parse).
        let client_verifier = SpiffeClientCertVerifier::new(&trust_bundle)?;
        let cert_resolver =
            SpiffeResolvesServerCert::new(registry.clone() as Arc<dyn ServerCertRegistry>);
        let mut server_crypto = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_client_cert_verifier(Arc::new(client_verifier))
            .with_cert_resolver(Arc::new(cert_resolver));
        server_crypto.alpn_protocols = vec![FLOR_ALPN.as_bytes().to_vec()];
        let server_config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto)
                .change_context(Error("Failed to create server config".into()))?,
        ));

        // No default client config: `connect` builds a per-call mTLS `ClientConfig`
        // (caller SVID + per-target verifier) and dials via `connect_with`.
        let endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )
        .change_context(Error("Failed to create QUIC endpoint".into()))?;

        Ok(Self {
            endpoint,
            resolver,
            registry,
            trust_bundle,
        })
    }

    /// Dial `target` as `caller`, establishing an mTLS QUIC connection.
    ///
    /// Builds a per-call [`ClientConfig`]: the caller SVID is presented as the
    /// client cert, and a [`SpiffeServerCertVerifier`] gates the server on
    /// `target`'s identity (SAN), not on SNI. SNI carries only the routing label
    /// from [`sni_for`]. The returned connection's peer identity is read from the
    /// server's verified leaf cert — which the verifier already proved equals
    /// `target` — so it is never re-asserted from the caller's `target`.
    ///
    /// The error is classified: a routine dial failure is [`ConnectError::Failed`]
    /// (the caller's to handle), while an unreadable peer identity on a completed
    /// handshake is a [`ConnectError::Fault`] that should stop the endpoint.
    async fn connect(
        &self,
        caller: &X509Svid,
        target: &Dialable,
    ) -> Result<QuicConnection, ConnectError> {
        let conn = self
            .dial(caller, target)
            .await
            .map_err(ConnectError::External)?;
        // The verifier already proved the server's SAN equals `target`, so its
        // cert must yield a SPIFFE id; failing to read one is an endpoint fault.
        // `established` hands the connection back; dropping it here closes it.
        QuicConnection::established(conn).map_err(|(_, e)| {
            ConnectError::Internal(e.change_context(Error(format!(
                "Outbound handshake to {} completed but its certificate has no SPIFFE identity",
                target.id()
            ))))
        })
    }

    /// Run the outbound mTLS handshake, returning the raw connection. Every error
    /// here is a routine, per-call dial failure; identity extraction is the
    /// caller's ([`connect`](Self::connect)) job, as only that step can fault.
    async fn dial(
        &self,
        caller: &X509Svid,
        target: &Dialable,
    ) -> Result<quinn::Connection, Report<Error>> {
        let dest_addr = self.resolver.resolve(target.id()).await?;
        let sni = sni_for(target);
        let client_config = self.client_config(caller, target)?;
        let conn_error = || Error(format!("Failed to connect to {}", target.id()));
        self.endpoint
            .connect_with(client_config, dest_addr, &sni)
            .change_context_lazy(conn_error)?
            .await
            .change_context_lazy(conn_error)
    }

    /// Build the per-call client mTLS config for dialing `target` as `caller`.
    fn client_config(
        &self,
        caller: &X509Svid,
        target: &Dialable,
    ) -> Result<ClientConfig, Report<Error>> {
        let verifier = Arc::new(SpiffeServerCertVerifier::new(
            &self.trust_bundle,
            target.id().clone(),
        )?);
        let (chain, key) = caller.cert_chain_and_key();
        let mut crypto = rustls::ClientConfig::builder_with_protocol_versions(&[&TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(chain, key)
            .change_context(Error("Failed to configure client crypto".into()))?;
        crypto.alpn_protocols = vec![FLOR_ALPN.as_bytes().to_vec()];
        Ok(ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto)
                .change_context(Error("Failed to create client config".into()))?,
        )))
    }

    /// Accept one incoming connection and dispatch it to the subscriber that
    /// published the dialed service.
    ///
    /// Returns [`AcceptOutcome::Dispatched`] after handling a connection (keep
    /// calling), or [`AcceptOutcome::Closed`] once the endpoint has shut down.
    /// `Err` is an endpoint **fault** — CID exhaustion, or an internal
    /// inconsistency (non-rustls handshake data, a completed handshake carrying no
    /// SNI, or an unresolvable peer SPIFFE identity) — which means valid
    /// connections may be getting dropped; the caller stops the loop and can
    /// surface it (e.g. telemetry). The offending connection is closed here first.
    ///
    /// A handshake failure, or a service unpublished since its cert was resolved
    /// (a benign race), is logged and skipped internally. The mTLS handshake is
    /// the security gate: the client verifier validated the peer chain + SAN, the
    /// cert resolver presented our SVID.
    async fn accept(&self) -> Result<AcceptOutcome, Report<Error>> {
        loop {
            // Wait for an incoming connection attempt
            let conn_fut = match self.endpoint.accept().await {
                None => return Ok(AcceptOutcome::Closed),
                Some(fut) => fut,
            };

            // Attempt to complete the handshake (mTLS: peer chain + SAN validated)
            let conn = match conn_fut.await {
                Ok(conn) => conn,
                Err(quinn::ConnectionError::CidsExhausted) => {
                    // Connection ID space exhausted: a terminal fault indicating a
                    // configuration issue with the CID generator.
                    bail!(Error("Endpoint exhausted connection IDs".into()));
                }
                Err(e) => {
                    // Transient connection errors: log and continue accepting
                    // TODO(#13): use metrics/counters and rate-limited warnings for invalid clients
                    log::debug!("Incoming connection handshake failed: {e:?}");
                    continue;
                }
            };

            // Wrap the handshake-complete connection, deriving the peer identity
            // from its own cert SAN. A failure here is an internal inconsistency —
            // the handshake guaranteed a SPIFFE peer — so we close the connection
            // (the constructor handed it back) and surface the fault.
            let conn = match QuicConnection::established(conn) {
                Ok(conn) => conn,
                Err((conn, e)) => {
                    conn.close(VarInt::from_u32(ENDPOINT_CLOSE_CODE), b"internal-error");
                    return Err(e.change_context(Error(
                        "Failed to resolve peer identity for an accepted connection".into(),
                    )));
                }
            };

            // Routing label (SNI) selects which published service was dialed. The
            // cert resolver required it to complete the handshake, so an error
            // here is an internal fault.
            let sni = match conn.sni() {
                Ok(sni) => sni,
                Err(e) => {
                    conn.close(ENDPOINT_CLOSE_CODE, b"internal-error");
                    return Err(e);
                }
            };

            // Resolve the SNI to (target identity, dispatch channel). The service's
            // cert was published when the handshake resolved it, so a miss now means
            // it was unpublished in the gap since — a benign race; drop and continue.
            let Some((target, dispatch)) = self.registry.route(&sni) else {
                log::debug!("Dropping connection for '{sni}': service unpublished since handshake");
                conn.close(ENDPOINT_CLOSE_CODE, b"service-unavailable");
                continue;
            };

            log::debug!(
                "Accepted connection for '{target}' from peer '{}'",
                conn.peer_id()
            );
            if dispatch.send((target, conn)).await.is_err() {
                // Subscriber dropped its acceptor; the stale entry is reaped on
                // the next publish.
                log::debug!("Subscriber for '{sni}' dropped; connection discarded");
            }
            return Ok(AcceptOutcome::Dispatched);
        }
    }

    /// Close the endpoint, making it to close open connections and to stop accepting new ones.
    fn close(&self) {
        self.endpoint
            .close(VarInt::from_u32(ENDPOINT_CLOSE_CODE), b"endpoint-closed");
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core::identity::{
        Ca, Kind, SpiffeId, TrustDomain, keygen_csr, load_bundle_from_pem, load_svid_from_pem,
    };
    use crate::core::transport::resolver::MockResolver;
    use mocks::{MockAsyncUdpSocket, MockEndpoint, MockIncoming, MockRuntime};
    use std::time::Duration;

    // We need to serialize tests because of global mocks for static functions in mockall
    use serial_test::serial;

    /// A trust bundle from a throwaway CA. It must carry a real authority (the
    /// client-cert verifier rejects an empty root store), but the accept-path
    /// tests never complete a handshake, so its identity is otherwise irrelevant.
    fn make_test_trust_bundle() -> Arc<X509Bundle> {
        let td = TrustDomain::new("demo.flor").unwrap();
        let ca = Ca::init(&td, std::time::Duration::from_secs(3600)).unwrap();
        Arc::new(load_bundle_from_pem(&td, ca.cert_pem().as_bytes()).unwrap())
    }

    /// Core setup: creates mock context, socket, runtime, and attempts construction.
    fn setup_endpoint_creation(
        mut mock_setup: impl FnMut() -> std::io::Result<MockEndpoint> + Send + 'static,
    ) -> Result<QuicEndpoint, Report<Error>> {
        let ctx = MockEndpoint::new_with_abstract_socket_context();
        ctx.expect().returning(move |_, _, _, _| mock_setup());

        let sock = Arc::new(MockAsyncUdpSocket::new());
        let runtime = Arc::new(MockRuntime::new());
        QuicEndpoint::new_with_abstract_socket(
            Arc::new(MockResolver::new()),
            runtime,
            sock,
            registry::PublishedServices::new(),
            make_test_trust_bundle(),
        )
    }

    /// Convenience wrapper for tests that need a successfully created endpoint
    /// with custom `accept()` behavior. The registry starts empty — the accept
    /// loop tests exercise only the pre-handshake error paths.
    fn setup_endpoint_for_accept(
        mut configure_accept: impl FnMut(&mut MockEndpoint) + Send + 'static,
    ) -> QuicEndpoint {
        setup_endpoint_creation(move || {
            let mut mock = MockEndpoint::new();
            configure_accept(&mut mock);
            Ok(mock)
        })
        .expect("Test setup failed: could not create QuicEndpoint")
    }

    /// Build an endpoint with a caller-supplied resolver and `MockEndpoint`
    /// configuration — for `connect` tests, where the resolver and `connect_with`
    /// behaviour drive the outcome.
    fn setup_endpoint_with_resolver(
        resolver: MockResolver,
        mut configure: impl FnMut(&mut MockEndpoint) + Send + 'static,
    ) -> QuicEndpoint {
        let ctx = MockEndpoint::new_with_abstract_socket_context();
        ctx.expect().returning(move |_, _, _, _| {
            let mut mock = MockEndpoint::new();
            configure(&mut mock);
            Ok(mock)
        });
        QuicEndpoint::new_with_abstract_socket(
            Arc::new(resolver),
            Arc::new(MockRuntime::new()),
            Arc::new(MockAsyncUdpSocket::new()),
            registry::PublishedServices::new(),
            make_test_trust_bundle(),
        )
        .expect("Test setup failed: could not create QuicEndpoint")
    }

    /// A real caller SVID `spiffe://demo.flor/user/alice` from a throwaway CA —
    /// enough for `connect` to build a client config; the CA need not match the
    /// endpoint's bundle since these tests never complete a handshake.
    fn caller_svid() -> X509Svid {
        let td = TrustDomain::new("demo.flor").unwrap();
        let ca = Ca::init(&td, Duration::from_secs(3600)).unwrap();
        let id = SpiffeId::new("spiffe://demo.flor/user/alice").unwrap();
        let (key, csr) = keygen_csr(&id).unwrap();
        let leaf = ca
            .sign_csr(csr.as_bytes(), &id, Kind::User, Duration::from_secs(3600))
            .unwrap();
        load_svid_from_pem(leaf.as_bytes(), key.serialize_pem().as_bytes()).unwrap()
    }

    /// A dialable, rete-scoped service target `spiffe://demo.flor/service/<name>`.
    fn service_target(name: &str) -> Dialable {
        Dialable::new(SpiffeId::new(format!("spiffe://demo.flor/service/{name}")).unwrap()).unwrap()
    }

    #[tokio::test]
    #[serial]
    async fn test_connect_classifies_resolver_failure_as_failed() {
        // A target that doesn't resolve is a routine, per-call failure — it must
        // classify as `Failed` (caller's problem), never `Fault` (endpoint down).
        let mut resolver = MockResolver::new();
        resolver
            .expect_resolve()
            .returning(|_| Err(Report::new(Error("no route".into()))));
        // `connect_with` is never reached when resolution fails.
        let endpoint = setup_endpoint_with_resolver(resolver, |_mock| {});

        let result = endpoint
            .connect(&caller_svid(), &service_target("api"))
            .await;
        assert!(
            matches!(result, Err(ConnectError::External(_))),
            "an unresolvable target is a routine dial failure, not an endpoint fault"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_connect_classifies_dial_failure_as_failed() {
        // Target resolves, the client config builds, but the QUIC dial itself
        // fails — still a routine `Failed`, not a `Fault`.
        let mut resolver = MockResolver::new();
        resolver
            .expect_resolve()
            .returning(|_| Ok("127.0.0.1:9".parse().unwrap()));
        let endpoint = setup_endpoint_with_resolver(resolver, |mock| {
            mock.expect_connect_with()
                .returning(|_, _, _| Err(quinn::ConnectError::EndpointStopping));
        });

        let result = endpoint
            .connect(&caller_svid(), &service_target("api"))
            .await;
        assert!(
            matches!(result, Err(ConnectError::External(_))),
            "a failed QUIC dial is a routine failure, not an endpoint fault"
        );
    }

    /// Helper to create a MockIncoming that resolves to a specific ConnectionError.
    fn mock_incoming_error(err: quinn::ConnectionError) -> MockIncoming {
        let mut incoming = MockIncoming::new();
        incoming
            .expect_poll()
            .returning(move |_cx| std::task::Poll::Ready(Err(err.clone())));
        incoming
    }

    #[test]
    #[serial]
    fn test_failure_to_create_quinn_endpoint() {
        let res = setup_endpoint_creation(|| {
            Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "Mock IO error",
            ))
        });

        unsafe {
            // unsafe unwrap, because QuicEndpoint doesn't implement Debug
            let err = res.unwrap_err_unchecked();
            assert!(err.to_string().contains("Failed to create QUIC endpoint"));
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_accept_endpoint_closed() {
        let endpoint = setup_endpoint_for_accept(|mock| {
            // accept() returns future that resolves to None (endpoint closed)
            mock.expect_accept()
                .times(1)
                .returning(|| Box::pin(async { None }));
        });
        assert!(
            matches!(endpoint.accept().await, Ok(AcceptOutcome::Closed)),
            "a closed endpoint reports Closed, not a fault"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_accept_cids_exhausted() {
        let endpoint = setup_endpoint_for_accept(|mock| {
            // accept() returns Some(incoming), where incoming resolves to CidsExhausted
            mock.expect_accept().times(1).returning(|| {
                Box::pin(async { Some(mock_incoming_error(quinn::ConnectionError::CidsExhausted)) })
            });
        });
        // CID exhaustion is a terminal fault, surfaced as an error.
        assert!(endpoint.accept().await.is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_accept_transient_error_continues() {
        let endpoint = setup_endpoint_for_accept(|mock| {
            // First: transient error (should be logged and ignored, loop continues)
            mock.expect_accept().times(1).returning(|| {
                Box::pin(async { Some(mock_incoming_error(quinn::ConnectionError::TimedOut)) })
            });
            // Second: endpoint closed (loop exits)
            mock.expect_accept()
                .times(1)
                .returning(|| Box::pin(async { None }));
        });
        assert!(
            matches!(endpoint.accept().await, Ok(AcceptOutcome::Closed)),
            "a transient handshake error is skipped; the later close ends the loop"
        );
    }

    // The accept success path (SNI → registry route, peer-SAN extraction,
    // authenticate, dispatch) needs a completed mTLS handshake, which a mock
    // `quinn::Connection` can't produce; it's covered by the integration test.
}
