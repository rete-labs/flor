// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

pub mod endpoint;
pub mod resolver;
pub mod udp_resolver;

mod insecure_server_verifier;

pub use endpoint::QuicEndpoint;
pub use udp_resolver::UdpResolver;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);
