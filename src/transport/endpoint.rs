// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::sync::Arc;

use error_stack::{Report, ResultExt};
use quinn::{
    ClientConfig, ServerConfig, VarInt,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    version::TLS13,
};

use super::{Error, insecure_server_verifier::InsecureServerVerifier, resolver::Resolver};

/// QUIC-based Florete Endpoint.
#[derive(Clone)]
pub struct QuicEndpoint {
    endpoint: quinn::Endpoint,
    resolver: Arc<dyn Resolver>,
    served: Vec<String>, // For SNI validation on accept
}

// Close was caused by the endpoint, either normally or by internal error
const ENDPOINT_CLOSE_CODE: VarInt = VarInt::from_u32(0);
// Client behaviour was incorrect, causing the connection to close
const CLIENT_ERROR_CODE: VarInt = VarInt::from_u32(1);
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

        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
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
            served,
        })
    }

    /// Connect to the specified service.
    pub async fn connect(&self, connect_to: &str) -> Result<quinn::Connection, Report<Error>> {
        let dest_addr = self.resolver.resolve(connect_to).await?;
        let conn_error = || Error(format!("Failed to connect to {connect_to}"));
        self.endpoint
            .connect(dest_addr, connect_to)
            .change_context_lazy(conn_error)?
            .await
            .change_context_lazy(conn_error)
    }

    /// Accept an incoming connection, returning `Some((service_name, conn))` on success,
    /// or `None` when the endpoint is closed or encounters a terminal error.
    ///
    /// Transient errors (e.g., handshake failures, unknown SNI, etc) are logged at `debug` level
    /// and ignored: the endpoint continues accepting.
    /// Only unrecoverable errors cause `None` return.
    pub async fn accept(&self) -> Option<(String, quinn::Connection)> {
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
                    log::warn!("Endpoint exhausted Connection IDs, stopping accept loop");
                    return None;
                }
                Err(e) => {
                    // Transient connection errors: log and continue accepting
                    // TODO(#13): use metrics/counters and rate-limited warnings for invalid clients
                    log::debug!("Incoming connection handshake failed: {e:?}");
                    continue;
                }
            };

            // Extract and validate SNI from handshake data
            let service_name = match conn.handshake_data() {
                Some(data) => match data.downcast::<quinn::crypto::rustls::HandshakeData>() {
                    Ok(hs) => match hs.server_name {
                        Some(name) => name,
                        None => {
                            log::debug!("Connection missing SNI, rejecting");
                            conn.close(CLIENT_ERROR_CODE, b"missing-sni");
                            continue;
                        }
                    },
                    Err(e) => {
                        // Internal error: normally we must be able to downcast
                        log::error!("Failed to downcast handshake data: {e:?}");
                        conn.close(ENDPOINT_CLOSE_CODE, b"internal-error");
                        return None;
                    }
                },
                None => {
                    log::debug!("No handshake data available, rejecting");
                    conn.close(CLIENT_ERROR_CODE, b"no-handshake");
                    continue;
                }
            };

            // Validate that the requested service is one we serve
            if !self.served.contains(&service_name) {
                log::debug!(
                    "Rejected connection to unknown service '{service_name}'; served: {:?}",
                    self.served
                );
                conn.close(CLIENT_ERROR_CODE, b"unknown-service");
                continue;
            }

            // Success: return the validated connection
            log::debug!("Accepted connection for service '{service_name}'");
            return Some((service_name, conn));
        }
    }

    /// Close the endpoint, making it to close open connections and to stop accepting new ones.
    pub fn close(&self) {
        self.endpoint.close(ENDPOINT_CLOSE_CODE, b"endpoint-closed");
    }
}
