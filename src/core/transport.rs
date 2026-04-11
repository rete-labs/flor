// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::sync::Arc;

use error_stack::Report;

pub mod endpoint;
pub mod resolver;
pub mod udp_resolver;

mod insecure_server_verifier;

pub use endpoint::{QuicAcceptor, QuicConnector};
pub use udp_resolver::UdpResolver;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

/// Create a QUIC endpoint, spawn its actor task, and return the two handles.
///
/// [`QuicConnector`] is cloneable and intended for inbound components.
/// [`QuicAcceptor`] is exclusive and intended for the outbound supervisor.
///
/// Drop the [`QuicAcceptor`] to close and drop the endpoint.
///
/// This is a temporary construction path until the fundle `TransportModule` is in place.
pub fn create_endpoint(
    served: Vec<String>,
    resolver: Arc<dyn resolver::Resolver>,
    socket: std::net::UdpSocket,
) -> Result<(QuicConnector, QuicAcceptor), Report<Error>> {
    endpoint::QuicEndpoint::new(served, resolver, socket).map(|ep| ep.into_actor())
}
