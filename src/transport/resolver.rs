// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::net::SocketAddr;

use async_trait::async_trait;
use error_stack::Report;

use super::Error;

/// Resolver of service name into destination socket address.
/// It is needed for UDP-based transports like QUIC.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolve service name into destination socket address (IP and port).
    async fn resolve(&self, name: &str) -> Result<SocketAddr, Report<Error>>;
}
