// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use async_trait::async_trait;
use error_stack::{Report, ResultExt, bail};
use quinn::{ConnectionError, RecvStream, SendStream, VarInt, crypto::rustls::HandshakeData};
use rustls::pki_types::CertificateDer;

use crate::core::identity::SpiffeId;
use crate::core::transport::Error;

/// Trait to accept incoming streams.
#[async_trait]
pub trait Accept {
    async fn accept_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError>;
}

/// Trait to open outgoing streams.
#[async_trait]
pub trait Open {
    async fn open_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError>;
}

/// A just-accepted, **handshake-complete** inbound QUIC connection whose peer
/// SPIFFE identity has not been attached yet. Internal to the endpoint's accept
/// path.
///
/// The peer is already cryptographically authenticated — rustls validated its
/// certificate chain against the rete bundle and required a SPIFFE SAN during the
/// handshake (see `SpiffeClientCertVerifier`). This type is only the staging form
/// between "quinn handed us a `Connection`" and the app-facing [`QuicConnection`]:
/// the accept path reads the routing SNI, resolves the peer identity, and trades
/// it in via [`into_connection`](Self::into_connection).
pub(super) struct AcceptedConnection {
    conn: quinn::Connection,
}

impl AcceptedConnection {
    pub(super) fn new(conn: quinn::Connection) -> Self {
        Self { conn }
    }

    /// The SNI routing label the client offered.
    ///
    /// Every `Err` is an internal inconsistency, not a client problem: the cert
    /// resolver (`SpiffeResolvesServerCert`) already aborts the handshake when no
    /// SNI is present, so a completed handshake always carries one — its absence
    /// (or non-rustls handshake data) means a bug.
    pub(super) fn sni(&self) -> Result<String, Report<Error>> {
        let Some(data) = self.conn.handshake_data() else {
            bail!(Error(
                "Established connection is missing handshake data".into()
            ));
        };
        let data = data.downcast::<HandshakeData>().map_err(|_| {
            Report::new(Error(
                "Handshake data was not the expected rustls type".into(),
            ))
        })?;
        data.server_name.ok_or_else(|| {
            Report::new(Error(
                "Established connection carries no SNI (the cert resolver requires one)".into(),
            ))
        })
    }

    /// The peer's verified SPIFFE identity, read from its leaf certificate SAN.
    ///
    /// Every `Err` here is an **internal inconsistency**, not an untrusted peer:
    /// the connection completed the mTLS handshake and `SpiffeClientCertVerifier`
    /// already required the leaf to carry a SPIFFE SAN, so a missing peer
    /// identity, chain, or SAN at this point means a bug — untrusted peers are
    /// rejected during the handshake, never reaching here.
    pub(super) fn peer_id(&self) -> Result<SpiffeId, Report<Error>> {
        let peer = self.conn.peer_identity().ok_or_else(|| {
            Report::new(Error(
                "Authenticated connection exposes no peer identity".into(),
            ))
        })?;
        let certs = peer
            .downcast::<Vec<CertificateDer<'static>>>()
            .map_err(|_| {
                Report::new(Error(
                    "Peer identity was not the expected certificate chain".into(),
                ))
            })?;
        let leaf = certs
            .first()
            .ok_or_else(|| Report::new(Error("Peer certificate chain is empty".into())))?;
        spiffe::cert::spiffe_id_from_der(leaf.as_ref())
            .change_context(Error("Peer leaf certificate has no SPIFFE SAN".into()))
    }

    /// Reject this connection, delivering `error_code` / `reason` to the peer.
    pub(super) fn close(&self, error_code: u32, reason: &[u8]) {
        self.conn.close(VarInt::from_u32(error_code), reason);
    }

    /// Attach the resolved `peer_id`, yielding the app-facing [`QuicConnection`].
    pub(super) fn into_connection(self, peer_id: SpiffeId) -> QuicConnection {
        QuicConnection::new(self.conn, peer_id)
    }
}

/// An established QUIC connection with its peer's authenticated SPIFFE identity
/// attached. Use the stream traits ([`Open`] / [`Accept`]) for I/O.
///
/// Constructed only within the endpoint module: [`QuicConnection::new`] on the
/// outbound side (where the peer is the dialed, SAN-verified target) and
/// [`AcceptedConnection::into_connection`] on the inbound side.
pub struct QuicConnection {
    conn: quinn::Connection,
    peer_id: SpiffeId,
}

impl QuicConnection {
    /// Wrap an established connection whose peer identity is already known —
    /// outbound, where the server-cert verifier proved the peer's SAN equals the
    /// dialed target.
    pub(super) fn new(conn: quinn::Connection, peer_id: SpiffeId) -> Self {
        Self { conn, peer_id }
    }

    /// The peer's authenticated SPIFFE identity, taken from its leaf cert SAN.
    ///
    /// Infallible: a `QuicConnection` cannot exist without it.
    pub fn peer_id(&self) -> &SpiffeId {
        &self.peer_id
    }
}

#[async_trait]
impl Accept for QuicConnection {
    async fn accept_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        self.conn.accept_bi().await
    }
}

#[async_trait]
impl Open for QuicConnection {
    async fn open_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        self.conn.open_bi().await
    }
}
