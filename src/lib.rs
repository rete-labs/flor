// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::{collections::HashMap, net::SocketAddr};

pub mod cli;
pub mod core;
pub mod logging;
pub mod northbound;
pub mod utils;

#[derive(Debug, Clone)]
pub struct EndpointAddr(pub SocketAddr);

#[derive(Debug, Clone)]
pub struct AddrMap(pub HashMap<String, SocketAddr>);

#[derive(Debug, Clone)]
pub struct Socks5Targets(pub HashMap<String, SocketAddr>);

#[derive(Debug, Clone)]
pub struct TcpDirectTargets(pub HashMap<String, SocketAddr>);

/// Fundle DI container for the entire application configuration.
#[fundle::bundle]
pub struct AppConfigBundle {
    /// The UDP address to bind the QUIC endpoint to.
    pub endpoint_addr: EndpointAddr,

    /// A mapping of service names to their remote UDP addresses.
    pub addr_map: AddrMap,

    /// A mapping of client service names to local SOCKS5 inbound addresses.
    pub socks5_targets: Socks5Targets,

    /// A mapping of client service names to local TCP direct target addresses.
    pub tcp_direct_targets: TcpDirectTargets,
}
