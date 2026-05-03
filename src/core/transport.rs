// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::sync::Arc;

use error_stack::ResultExt;

pub mod endpoint;
pub mod resolver;
pub mod udp_resolver;

mod insecure_server_verifier;

pub use endpoint::{QuicAcceptor, QuicConnector, QuicHandle, QuicPublisher};
pub use udp_resolver::UdpResolver;

use crate::{AddrMap, EndpointAddr, utils::report::ErrorReport};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

/// Dependencies required to construct a [`TransportBundle`].
///
/// This groups the transport-layer configuration values consumed by
/// [`TransportBundle::try_new`].
#[fundle::deps]
pub struct TransportDeps {
    /// Local UDP socket address to bind for ingress and egress transport.
    endpoint_addr: EndpointAddr,
    /// Mapping of logical node names to reachable endpoint addresses.
    addr_map: AddrMap,
}

/// Fundle DI container for the transport layer.
///
/// Construct via [`TransportBundle::try_new`].
#[fundle::bundle]
pub struct TransportBundle {
    pub endpoint_connector: QuicConnector,
    pub endpoint_publisher: QuicPublisher,
    pub endpoint_handle: QuicHandle,
}

impl TransportBundle {
    /// Build the bundle from the given dependencies.
    pub fn try_new(deps: impl Into<TransportDeps>) -> Result<Self, ErrorReport<Error>> {
        let deps = deps.into();
        let resolver = Arc::new(UdpResolver::new(deps.addr_map.0));
        let socket = std::net::UdpSocket::bind(deps.endpoint_addr.0).change_context(Error(
            format!("Failed to bind UDP socket to {}", deps.endpoint_addr.0),
        ))?;
        let (connector, publisher, handle) =
            endpoint::actor::QuicEndpointActor::spawn_new(resolver.clone(), socket)?;

        Ok(Self {
            endpoint_connector: connector,
            endpoint_publisher: publisher,
            endpoint_handle: handle,
        })
    }
}
