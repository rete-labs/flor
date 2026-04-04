use std::sync::Arc;

use error_stack::{Report, ResultExt};
use quinn::{
    AsyncUdpSocket, ClientConfig, Connection, Endpoint, EndpointConfig, Runtime, ServerConfig,
    VarInt,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    version::TLS13,
};

use super::{Error, insecure_server_verifier::InsecureServerVerifier, resolver::Resolver};

/// QUIC-based Florete Endpoint
#[derive(Clone)]
pub struct QuicEndpoint {
    endpoint: Endpoint,
    resolver: Arc<dyn Resolver>,
    served: Vec<String>, // For SNI validation on accept
}

const CLOSE_OK_CODE: VarInt = VarInt::from_u32(0);
const CLOSE_ERROR_CODE: VarInt = VarInt::from_u32(1);

impl QuicEndpoint {
    pub fn new(
        served: Vec<String>,
        resolver: Arc<dyn Resolver>,
        socket: std::net::UdpSocket,
    ) -> Result<Self, Report<Error>> {
        let runtime = quinn::default_runtime()
            .ok_or_else(|| Error::from("Failed to get default async runtime"))?;
        let async_socket = runtime
            .wrap_udp_socket(socket)
            .change_context(Error::from("Failed to wrap UDP socket"))?;
        Self::new_with_abstract_socket(served, resolver, runtime, async_socket)
    }

    pub fn new_with_abstract_socket(
        served: Vec<String>,
        resolver: Arc<dyn Resolver>,
        runtime: Arc<dyn Runtime>,
        socket: Arc<dyn AsyncUdpSocket>,
    ) -> Result<Self, Report<Error>> {
        // Current impl: single self-signed cert + SNI routing in `accept`.
        // TODO(#5): replace with SNI routing in certificate provider, when integrating Identity
        let cert = rcgen::generate_simple_self_signed(vec!["example.rete".into()])
            .change_context("Failed to generate self-signed cert".into())?;
        let cert_der = CertificateDer::from(cert.cert);
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            cert.signing_key.serialize_der(),
        ));

        // TODO(#5): enable client auth (mTLS) when implementing Identities
        let mut server_crypto = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .change_context("Failed to configure server crypto".into())?;
        server_crypto.alpn_protocols = vec![b"flor/1".to_vec()]; // FIXME: do we need this here?
        let server_config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto)
                .change_context("Failed to create server config".into())?,
        ));

        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(InsecureServerVerifier::new())
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"flor/1".to_vec()];
        let client_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_crypto)
                .change_context("Failed to create client config".into())?,
        ));

        let mut endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )
        .change_context("Failed to create QUIC endpoint".into())?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            resolver,
            served,
        })
    }

    /// Connect to the specified service.
    pub async fn connect(&self, connect_to: &str) -> Result<Connection, Report<Error>> {
        let dest_addr = self.resolver.resolve(connect_to).await?;
        self.endpoint
            .connect(dest_addr, connect_to)
            .change_context(format!("Failed to connect to {connect_to}").into())?
            .await
            .change_context(format!("Failed to connect to {connect_to}").into())
    }

    /// Accept an incoming connection, returning `Some((service_name, conn))` on success,
    /// or `None` when the endpoint is closed or encounters a terminal error.
    ///
    /// Transient errors (e.g., handshake failures, unknown SNI, etc) are logged at `debug` level
    /// and ignored: the endpoint continues accepting.
    /// Only unrecoverable errors cause `None` return.
    ///
    /// This design keeps the API simple. Detailed error observability can be added later
    /// via metrics, callbacks, or a separate error channel if needed.
    pub async fn accept(&self) -> Option<(String, Connection)> {
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
                Err(e) => {
                    // Transient connection errors: log and continue accepting
                    // FIXME: handle ConnectionError::CidsExhausted?
                    log::debug!("Incoming connection handshake failed: {:?}", e);
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
                            conn.close(CLOSE_ERROR_CODE, b"missing-sni");
                            continue;
                        }
                    },
                    Err(_) => {
                        log::debug!("Failed to downcast handshake data, rejecting");
                        conn.close(CLOSE_ERROR_CODE, b"handshake-error");
                        continue;
                    }
                },
                None => {
                    log::debug!("No handshake data available, rejecting");
                    conn.close(CLOSE_ERROR_CODE, b"no-handshake");
                    continue;
                }
            };

            // Validate that the requested service is one we serve
            if !self.served.contains(&service_name) {
                log::debug!(
                    "Rejected connection to unknown service '{}'; served: {:?}",
                    service_name,
                    self.served
                );
                conn.close(CLOSE_ERROR_CODE, b"unknown-service");
                continue;
            }

            // Success: return the validated connection
            log::debug!("Accepted connection for service '{}'", service_name);
            return Some((service_name, conn));
        }
    }

    /// Close the endpoint, making it to close open connections and to stop accepting new ones.
    pub fn close(&self) {
        self.endpoint.close(CLOSE_OK_CODE, b"endpoint-closed");
    }
}
