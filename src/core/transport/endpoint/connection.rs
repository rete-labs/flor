// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use async_trait::async_trait;
use error_stack::{Report, bail};
use quinn::{ConnectionError, RecvStream, SendStream, VarInt, crypto::rustls::HandshakeData};

use crate::core::transport::Error;

/// Trait to inspect connections.
pub trait Inspect {
    /// Get information about parameters negotiated during handshake.
    /// Error is returned only on internal library error.
    fn handshake_data(&self) -> Result<HandshakeData, Report<Error>>;
}

/// Trait to close connections.
pub trait Close {
    /// Closes connection with specified error code and reason string to be delivered to
    /// the other end of it.
    fn close(&self, error_code: u32, reason: &[u8]);
}

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

/// Established QUIC connection. Use traits to access only needed functionality.
pub struct QuicConnection {
    conn: quinn::Connection,
}

impl QuicConnection {
    pub(super) fn new(conn: quinn::Connection) -> Self {
        Self { conn }
    }
}

impl Inspect for QuicConnection {
    fn handshake_data(&self) -> Result<HandshakeData, Report<Error>> {
        match self.conn.handshake_data() {
            Some(data) => data.downcast::<HandshakeData>().map(|b| *b).map_err(|e| {
                Report::new(Error(format!("Failed to downcast handshake data: {e:?}")))
            }),
            None => {
                bail!(Error(
                    "No handshake data available for established connection".into()
                ))
            }
        }
    }
}

impl Close for QuicConnection {
    fn close(&self, error_code: u32, reason: &[u8]) {
        self.conn.close(VarInt::from_u32(error_code), reason);
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
