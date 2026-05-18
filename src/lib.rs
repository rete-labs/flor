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

/// Fundle DI container for the entire application configuration.
///
/// - `endpoint_addr`: UDP address to bind the QUIC endpoint to.
/// - `addr_map`: maps service names to their remote UDP addresses.
/// - `socks5_addr`: if present, the local address to bind the SOCKS5 listener to.
#[fundle::bundle]
pub struct AppConfigBundle {
    pub endpoint_addr: EndpointAddr,
    pub addr_map: AddrMap,
    pub socks5_addr: Option<Socks5Addr>,
}
