use std::net::SocketAddr;

use async_trait::async_trait;
use error_stack::Report;

use super::Error;

/// Resolver of service names into destination socket addresses.
/// It is needed for UDP-based transports like QUIC.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolve service name into destination socket address (IP and port).
    async fn resolve(&self, name: &str) -> Result<SocketAddr, Report<Error>>;
}
