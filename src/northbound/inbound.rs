// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use error_stack::ResultExt;

use crate::{
    Socks5Addr,
    core::transport::QuicConnector,
    northbound::inbound::socks5::{Socks5Handle, Socks5Inbound},
    utils::report::ErrorReport,
};

pub mod socks5;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

/// Dependencies required to construct an [`InboundBundle`].
///
/// This groups inbound listener inputs consumed by [`InboundBundle::try_new`].
#[fundle::deps]
pub struct InboundDeps {
    /// Optional local address for exposing a SOCKS5 listener.
    ///
    /// When `None`, SOCKS5 inbound is disabled.
    socks5_addr: Option<Socks5Addr>,
    /// QUIC connector used by inbound handlers to establish upstream sessions.
    quic_connector: QuicConnector,
}

/// Fundle DI container for northbound inbound components.
///
/// `socks5_handle` is `None` for nodes that do not expose a SOCKS5 listener.
///
/// Construct via [`InboundBundle::try_new`].
#[fundle::bundle]
pub struct InboundBundle {
    pub socks5_handle: Option<Socks5Handle>,
}

impl InboundBundle {
    /// Build the bundle from the given dependencies.
    ///
    /// [`Socks5Inbound`] is only created if a `socks5_addr` is provided in the config.
    /// It's immediately spawned within the bundle to ensure it lives for the duration of the app.
    pub async fn try_new(deps: impl Into<InboundDeps>) -> Result<Self, ErrorReport<Error>> {
        let deps = deps.into();

        let socks5_handle = init_socks5(&deps).await?;
        Ok(InboundBundle { socks5_handle })
    }
}

async fn init_socks5(deps: &InboundDeps) -> Result<Option<Socks5Handle>, ErrorReport<Error>> {
    let socks5 = if let Some(addr) = deps.socks5_addr.clone() {
        let socks5 = Socks5Inbound::new(addr.0, deps.quic_connector.clone())
            .await
            .change_context(Error("Failed to create SOCKS5 inbound".into()))?
            .spawn();
        log::info!("SOCKS5 server listening on {}", addr.0);
        Some(socks5)
    } else {
        None
    };
    Ok(socks5)
}
