// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::{collections::HashMap, net::SocketAddr};

use error_stack::ResultExt;

use crate::{
    core::transport::QuicConnector,
    northbound::inbound::socks5::{Socks5Handle, Socks5Inbound},
    utils::report::ErrorReport,
};

pub mod socks5;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

#[derive(Debug, Clone)]
pub struct Socks5Bindings(pub HashMap<String, SocketAddr>);

/// Dependencies required to construct an [`InboundBundle`].
///
/// This groups inbound listener inputs consumed by [`InboundBundle::try_new`].
#[fundle::deps]
pub struct InboundDeps {
    /// Local SOCKS5 listener addresses keyed by client service name.
    ///
    /// When empty, SOCKS5 inbound is disabled.
    socks5_bindings: Socks5Bindings,
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
    /// [`Socks5Inbound`] is only created if `socks5_bindings` is not empty.
    /// It's immediately spawned within the bundle to ensure it lives for the duration of the app.
    pub async fn try_new(deps: impl Into<InboundDeps>) -> Result<Self, ErrorReport<Error>> {
        let deps = deps.into();

        let socks5_handle = init_socks5(&deps).await?;
        Ok(InboundBundle { socks5_handle })
    }
}

async fn init_socks5(deps: &InboundDeps) -> Result<Option<Socks5Handle>, ErrorReport<Error>> {
    let socks5 = if deps.socks5_bindings.0.is_empty() {
        None
    } else {
        let socks5 =
            Socks5Inbound::new(deps.socks5_bindings.0.clone(), deps.quic_connector.clone())
                .await
                .change_context(Error("Failed to create SOCKS5 inbound".into()))?
                .spawn();
        for (service_name, addr) in &deps.socks5_bindings.0 {
            log::info!("SOCKS5 service '{service_name}' listening on {addr}");
        }
        Some(socks5)
    };
    Ok(socks5)
}
