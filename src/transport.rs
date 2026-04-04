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

// FIXME: introduce derive macro to get this code!
impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error(s.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error(s)
    }
}
