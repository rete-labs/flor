// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::net::SocketAddr;

use async_trait::async_trait;
use error_stack::Report;

#[cfg(test)]
use mockall::{self, automock};

use super::Error;
use crate::core::identity::SpiffeId;

/// Resolver of a target identity into a destination socket address.
/// It is needed for UDP-based transports like QUIC.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolve a target [`SpiffeId`] into a destination socket address (IP and port).
    async fn resolve(&self, target: &SpiffeId) -> Result<SocketAddr, Report<Error>>;
}
