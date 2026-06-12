// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

pub mod cli;
pub mod core;
pub mod logging;
pub mod northbound;
pub mod utils;

use core::transport::{AddrMap, EndpointAddr};
use northbound::{inbound::Socks5Bindings, outbound::TcpDirectBindings};

/// Fundle DI container for the entire application configuration.
#[fundle::bundle]
pub struct AppConfigBundle {
    /// The UDP address to bind the QUIC endpoint to.
    pub endpoint_addr: EndpointAddr,

    /// A mapping of service names to their remote UDP addresses.
    pub addr_map: AddrMap,

    /// A mapping of client service names to local SOCKS5 inbound addresses.
    pub socks5_bindings: Socks5Bindings,

    /// A mapping of client service names to local TCP direct addresses.
    pub tcp_direct_bindings: TcpDirectBindings,
}
