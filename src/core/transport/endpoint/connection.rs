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

/// An established, **handshake-complete** QUIC connection with its peer's
/// authenticated SPIFFE identity attached. Use the stream traits ([`Open`] /
/// [`Accept`]) for I/O.
///
/// Constructed only within the endpoint module via [`QuicConnection::established`]
/// — outbound from `connect`, inbound from the accept loop. There is no other
/// constructor and no way to supply the identity, so a `QuicConnection`'s
/// `peer_id` is, by construction, exactly the peer the mTLS handshake
/// authenticated; it cannot disagree with the certificate.
pub struct QuicConnection {
    conn: quinn::Connection,
    peer_id: SpiffeId,
}

impl QuicConnection {
    /// Wrap a handshake-complete connection, reading the peer's SPIFFE identity
    /// from its own verified leaf certificate ([`peer_id_from_conn`]). The
    /// **only** constructor, used by both the inbound and outbound paths.
    ///
    /// An `Err` means the SAN was unreadable, which a completed mTLS handshake
    /// should make impossible — an internal inconsistency, not an untrusted peer.
    /// The connection is handed back unchanged inside the `Err` so the caller can
    /// close it as its context dictates.
    pub(super) fn established(
        conn: quinn::Connection,
    ) -> Result<Self, (quinn::Connection, Report<Error>)> {
        match peer_id_from_conn(&conn) {
            Ok(peer_id) => Ok(Self { conn, peer_id }),
            Err(e) => Err((conn, e)),
        }
    }

    /// The peer's authenticated SPIFFE identity, taken from its leaf cert SAN.
    ///
    /// Infallible: a `QuicConnection` cannot exist without it.
    pub fn peer_id(&self) -> &SpiffeId {
        &self.peer_id
    }

    /// Close the connection, delivering `error_code` / `reason` to the peer.
    pub(super) fn close(&self, error_code: u32, reason: &[u8]) {
        self.conn.close(VarInt::from_u32(error_code), reason);
    }
}

/// The peer's verified SPIFFE identity, read from `conn`'s leaf certificate SAN.
///
/// Every `Err` is an **internal inconsistency**, not an untrusted peer: a
/// completed mTLS handshake has already validated the chain and required a
/// SPIFFE SAN (inbound via `SpiffeClientCertVerifier`, outbound via
/// `SpiffeServerCertVerifier`), so a missing peer identity, chain, or SAN here
/// means a bug — untrusted peers are rejected during the handshake, never
/// reaching this point.
fn peer_id_from_conn(conn: &quinn::Connection) -> Result<SpiffeId, Report<Error>> {
    let peer = conn.peer_identity().ok_or_else(|| {
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

/// Handshake-derived routing facts, readable only within the endpoint module.
///
/// Kept off `QuicConnection`'s app-facing surface via a `pub(super)` trait: the
/// SNI is a server-side routing concern the accept loop consumes to dispatch,
/// not something a connection's consumer should see.
pub(super) trait HandshakeInfo {
    /// The SNI routing label the client offered.
    ///
    /// Every `Err` is an internal inconsistency, not a client problem: the cert
    /// resolver (`SpiffeResolvesServerCert`) already aborts the handshake when no
    /// SNI is present, so a completed handshake always carries one — its absence
    /// (or non-rustls handshake data) means a bug.
    fn sni(&self) -> Result<String, Report<Error>>;
}

impl HandshakeInfo for QuicConnection {
    fn sni(&self) -> Result<String, Report<Error>> {
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
