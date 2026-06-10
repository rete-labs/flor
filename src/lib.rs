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
pub struct Socks5Addr(pub SocketAddr);

#[derive(Debug, Clone)]
pub struct TcpDirectTargets(pub HashMap<String, SocketAddr>);

/// Fundle DI container for the entire application configuration.
#[fundle::bundle]
pub struct AppConfigBundle {
    /// The UDP address to bind the QUIC endpoint to.
    pub endpoint_addr: EndpointAddr,

    /// A mapping of service names to their remote UDP addresses.
    pub addr_map: AddrMap,

    /// If present, the local address to bind the SOCKS5 inbound listener to.
    pub socks5_addr: Option<Socks5Addr>,

    /// A mapping of service names to their remote TCP addresses for TCP direct outbound.
    pub tcp_direct_targets: TcpDirectTargets,
}
