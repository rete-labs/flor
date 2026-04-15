// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::sync::Arc;

use error_stack::{Report, ResultExt};
use mockall_double::double;
use quinn::{
    ClientConfig, ServerConfig, VarInt,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    version::TLS13,
};

use super::{Error, insecure_server_verifier::InsecureServerVerifier, resolver::Resolver};

mod mocks;
#[double]
use mocks::Endpoint;

pub mod actor;
pub use actor::{QuicAcceptor, QuicConnector};

pub mod connection;
use connection::{Close, Inspect, QuicConnection};

/// QUIC-based Florete Endpoint.
#[derive(Clone)]
pub(crate) struct QuicEndpoint {
    endpoint: Endpoint,
    resolver: Arc<dyn Resolver>,
    served: Arc<Vec<String>>, // For SNI validation on accept
}

// Close was caused by the endpoint, either normally or by internal error
const ENDPOINT_CLOSE_CODE: u32 = 0;
// Client behaviour was incorrect, causing the connection to close
const CLIENT_ERROR_CODE: u32 = 1;
// Flor protocol string for ALPN
const FLOR_ALPN: &str = "flor/1";

impl QuicEndpoint {
    /// Create new QUIC endpoint that serves specified services, uses provided resolver for outgoing
    /// connections and works over UDP socket.
    pub fn new(
        served: Vec<String>,
        resolver: Arc<dyn Resolver>,
        socket: std::net::UdpSocket,
    ) -> Result<Self, Report<Error>> {
        let runtime = quinn::default_runtime()
            .ok_or_else(|| Error("Failed to get default async runtime".into()))?;
        let async_socket = runtime
            .wrap_udp_socket(socket)
            .change_context(Error("Failed to wrap UDP socket".into()))?;
        Self::new_with_abstract_socket(served, resolver, runtime, async_socket)
    }

    /// Create new QUIC endpoint that works over quinn's abstract socket and runtime.
    /// This constructor allows using custom UDP-like sockets.
    pub fn new_with_abstract_socket(
        served: Vec<String>,
        resolver: Arc<dyn Resolver>,
        runtime: Arc<dyn quinn::Runtime>,
        socket: Arc<dyn quinn::AsyncUdpSocket>,
    ) -> Result<Self, Report<Error>> {
        // Current impl: single self-signed cert + SNI routing in `accept`.
        // TODO(#5): replace with SNI routing in certificate provider, when integrating Identity
        let cert = rcgen::generate_simple_self_signed(vec!["example.rete".into()])
            .change_context(Error("Failed to generate self-signed cert".into()))?;
        let cert_der = CertificateDer::from(cert.cert);
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            cert.signing_key.serialize_der(),
        ));

        // TODO(#5): enable client auth (mTLS) when implementing Identities
        let mut server_crypto = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .change_context(Error("Failed to configure server crypto".into()))?;
        server_crypto.alpn_protocols = vec![FLOR_ALPN.as_bytes().to_vec()];
        let server_config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto)
                .change_context(Error("Failed to create server config".into()))?,
        ));

        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(InsecureServerVerifier::new())
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![FLOR_ALPN.as_bytes().to_vec()];
        let client_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_crypto)
                .change_context(Error("Failed to create client config".into()))?,
        ));

        let mut endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )
        .change_context(Error("Failed to create QUIC endpoint".into()))?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            resolver,
            served: Arc::new(served),
        })
    }

    /// Connect to the specified service.
    pub async fn connect(&self, connect_to: &str) -> Result<QuicConnection, Report<Error>> {
        let dest_addr = self.resolver.resolve(connect_to).await?;
        let conn_error = || Error(format!("Failed to connect to {connect_to}"));
        self.endpoint
            .connect(dest_addr, connect_to)
            .change_context_lazy(conn_error)?
            .await
            .change_context_lazy(conn_error)
            .map(QuicConnection::new)
    }

    /// Accept an incoming connection, returning `Some((service_name, conn))` on success,
    /// or `None` when the endpoint is closed or encounters a terminal error.
    ///
    /// Transient errors (e.g., handshake failures, unknown SNI, etc) are logged at `debug` level
    /// and ignored: the endpoint continues accepting.
    /// Only unrecoverable errors cause `None` return.
    pub async fn accept(&self) -> Option<(String, QuicConnection)> {
        loop {
            // Wait for an incoming connection attempt
            let conn_fut = match self.endpoint.accept().await {
                None => {
                    log::debug!("Endpoint closed, stopping accept loop");
                    return None;
                }
                Some(fut) => fut,
            };

            // Attempt to complete the handshake
            let conn = match conn_fut.await {
                Ok(conn) => conn,
                Err(quinn::ConnectionError::CidsExhausted) => {
                    // Connection ID space exhausted: endpoint cannot accept more connections.
                    // This is a terminal condition indicating a configuration issue with
                    // the CID generator.
                    log::error!("Endpoint exhausted Connection IDs, stopping accept loop");
                    return None;
                }
                Err(e) => {
                    // Transient connection errors: log and continue accepting
                    // TODO(#13): use metrics/counters and rate-limited warnings for invalid clients
                    log::debug!("Incoming connection handshake failed: {e:?}");
                    continue;
                }
            };

            let conn = QuicConnection::new(conn);

            match self.validate_connection(&conn) {
                Ok(service_name) => {
                    log::debug!("Accepted connection for service '{service_name}'");
                    return Some((service_name, conn));
                }
                Err(ValidationError::Reject { reason }) => {
                    conn.close(CLIENT_ERROR_CODE, reason);
                    continue;
                }
                Err(ValidationError::Internal(e)) => {
                    log::error!("Internal error: {e}, stopping accept loop");
                    conn.close(ENDPOINT_CLOSE_CODE, b"internal-error");
                    return None;
                }
            }
        }
    }

    /// Convert this endpoint into an actor, spawning its task and returning the two handles.
    ///
    /// [`QuicConnector`] is cloneable and intended for inbound components.
    /// [`QuicAcceptor`] is exclusive and intended for the outbound supervisor.
    pub fn into_actor(self) -> (QuicConnector, QuicAcceptor) {
        actor::QuicEndpointActor::spawn(self)
    }

    /// Close the endpoint, making it to close open connections and to stop accepting new ones.
    pub fn close(&self) {
        self.endpoint
            .close(VarInt::from_u32(ENDPOINT_CLOSE_CODE), b"endpoint-closed");
    }

    fn validate_connection<C: Inspect>(&self, conn: &C) -> Result<String, ValidationError> {
        // Extract SNI from handshake data
        let service_name = conn
            .handshake_data()
            .map_err(ValidationError::Internal)?
            .server_name
            .ok_or_else(|| {
                log::debug!("Connection missing SNI, rejecting");
                ValidationError::Reject {
                    reason: b"missing-sni",
                }
            })?;

        // Validate that the requested service is one we serve
        if !self.served.contains(&service_name) {
            log::debug!(
                "Connection to unknown service '{service_name}', rejecting; served: {:?}",
                self.served
            );
            return Err(ValidationError::Reject {
                reason: b"unknown-service",
            });
        }
        Ok(service_name)
    }
}

#[derive(Debug)]
enum ValidationError {
    Reject { reason: &'static [u8] },
    Internal(Report<Error>),
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transport::resolver::MockResolver;
    use mocks::{MockAsyncUdpSocket, MockEndpoint, MockIncoming, MockInspectConn, MockRuntime};

    // We need to serialize tests because of global mocks for static functions in mockall
    use serial_test::serial;

    /// Core setup: creates mock context, socket, runtime, and attempts construction.
    fn setup_endpoint_creation(
        mut mock_setup: impl FnMut() -> std::io::Result<MockEndpoint> + Send + 'static,
    ) -> Result<QuicEndpoint, Report<Error>> {
        let ctx = MockEndpoint::new_with_abstract_socket_context();
        ctx.expect().returning(move |_, _, _, _| mock_setup());

        let sock = Arc::new(MockAsyncUdpSocket::new());
        let runtime = Arc::new(MockRuntime::new());
        QuicEndpoint::new_with_abstract_socket(
            vec!["test_service".into()],
            Arc::new(MockResolver::new()),
            runtime,
            sock,
        )
    }

    /// Convenience wrapper for tests that need a successfully created endpoint
    /// with custom `accept()` behavior.
    fn setup_endpoint_for_accept(
        mut configure_accept: impl FnMut(&mut MockEndpoint) + Send + 'static,
    ) -> QuicEndpoint {
        setup_endpoint_creation(move || {
            let mut mock = MockEndpoint::new();
            mock.expect_set_default_client_config()
                .times(1)
                .return_const(());
            configure_accept(&mut mock);
            Ok(mock)
        })
        .expect("Test setup failed: could not create QuicEndpoint")
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
        assert!(endpoint.accept().await.is_none());
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
        // Should return None when CidsExhausted (terminal error) occurs
        assert!(endpoint.accept().await.is_none());
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
        assert!(endpoint.accept().await.is_none());
    }

    #[test]
    #[serial]
    fn test_validate_connection_success() {
        let endpoint = setup_endpoint_for_accept(|_| {}); // served = vec!["test_service"]
        let mut mock_conn = MockInspectConn::new();
        mock_conn.expect_handshake_data().returning(|| {
            Ok(quinn::crypto::rustls::HandshakeData {
                server_name: Some("test_service".into()),
                protocol: None,
            })
        });

        let service_name = endpoint
            .validate_connection(&mock_conn)
            .expect("Expected successful validation");
        assert_eq!(service_name, "test_service");
    }

    #[test]
    #[serial]
    fn test_validate_connection_missing_sni() {
        let endpoint = setup_endpoint_for_accept(|_| {});
        let mut mock_conn = MockInspectConn::new();
        mock_conn.expect_handshake_data().returning(|| {
            Ok(quinn::crypto::rustls::HandshakeData {
                server_name: None,
                protocol: None,
            })
        });

        match endpoint.validate_connection(&mock_conn) {
            Err(ValidationError::Reject { reason }) => assert_eq!(reason, b"missing-sni"),
            other => panic!("Expected Reject, got {other:?}"),
        }
    }

    #[test]
    #[serial]
    fn test_validate_connection_unknown_service() {
        let endpoint = setup_endpoint_for_accept(|_| {});
        let mut mock_conn = MockInspectConn::new();
        mock_conn.expect_handshake_data().returning(|| {
            Ok(quinn::crypto::rustls::HandshakeData {
                server_name: Some("unknown_svc".into()),
                protocol: None,
            })
        });

        match endpoint.validate_connection(&mock_conn) {
            Err(ValidationError::Reject { reason }) => assert_eq!(reason, b"unknown-service"),
            other => panic!("Expected Reject, got {other:?}"),
        }
    }

    #[test]
    #[serial]
    fn test_validate_connection_no_handshake_data() {
        let endpoint = setup_endpoint_for_accept(|_| {});
        let mut mock_conn = MockInspectConn::new();
        mock_conn
            .expect_handshake_data()
            .returning(|| Err(Report::new(Error("Mock internal error".into()))));

        match endpoint.validate_connection(&mock_conn) {
            Err(ValidationError::Internal(_)) => {} // Expected path
            other => panic!("Expected Internal, got {other:?}"),
        }
    }
}
