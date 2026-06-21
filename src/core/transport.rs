// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use error_stack::ResultExt;

pub mod endpoint;
pub mod resolver;
pub mod udp_resolver;

pub use endpoint::{QuicAcceptor, QuicConnector, QuicHandle, QuicPublisher};
pub use udp_resolver::UdpResolver;

use crate::core::identity::{SpiffeId, X509Bundle};
use crate::utils::report::ErrorReport;

#[derive(Debug, Clone)]
pub struct EndpointAddr(pub SocketAddr);

#[derive(Debug, Clone)]
pub struct AddrMap(pub HashMap<SpiffeId, SocketAddr>);

/// The rete trust bundle (CA authorities) the transport validates peers against.
#[derive(Clone)]
pub struct TrustBundle(pub Arc<X509Bundle>);

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
    /// Mapping of target identities to their reachable endpoint addresses.
    addr_map: AddrMap,
    /// Rete trust bundle used by the mTLS verifiers.
    trust_bundle: TrustBundle,
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
        let (connector, publisher, handle) = endpoint::actor::QuicEndpointActor::spawn_new(
            resolver.clone(),
            socket,
            deps.trust_bundle.0,
        )?;

        Ok(Self {
            endpoint_connector: connector,
            endpoint_publisher: publisher,
            endpoint_handle: handle,
        })
    }
}
