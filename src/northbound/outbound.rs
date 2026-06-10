// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use async_trait::async_trait;
use error_stack::{Report, ResultExt};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    TcpDirectTargets,
    core::transport::{
        QuicPublisher,
        endpoint::connection::{Accept, QuicConnection},
    },
    northbound::outbound::tcp::{TcpDirectHandle, TcpDirectOutbound},
    utils::report::ErrorReport,
};

pub mod tcp;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

trait QuicStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> QuicStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

#[async_trait]
trait QuicInboundConnection: Send + Sync {
    async fn accept_stream(&self) -> Result<Box<dyn QuicStream>, Report<Error>>;
}

#[async_trait]
impl QuicInboundConnection for QuicConnection {
    async fn accept_stream(&self) -> Result<Box<dyn QuicStream>, Report<Error>> {
        let (send, recv) = self
            .accept_bi()
            .await
            .change_context(Error("QUIC stream accept failed".into()))?;
        Ok(Box::new(tokio::io::join(recv, send)))
    }
}

/// Dependencies required to construct an [`OutboundBundle`].
#[fundle::deps]
pub struct OutboundDeps {
    /// Service names served by this node and their TCP targets.
    tcp_direct_targets: TcpDirectTargets,
    /// QUIC publisher used by outbound handlers to subscribe to incoming sessions.
    quic_publisher: QuicPublisher,
}

/// Fundle DI container for northbound outbound components.
#[fundle::bundle]
pub struct OutboundBundle {
    pub tcp_direct_handle: Option<TcpDirectHandle>,
}

impl OutboundBundle {
    /// Build the bundle from the given dependencies.
    pub async fn try_new(deps: impl Into<OutboundDeps>) -> Result<Self, ErrorReport<Error>> {
        let deps = deps.into();

        let tcp_direct_handle = init_tcp_direct(deps).await?;
        Ok(OutboundBundle { tcp_direct_handle })
    }
}

async fn init_tcp_direct(
    deps: OutboundDeps,
) -> Result<Option<TcpDirectHandle>, ErrorReport<Error>> {
    if deps.tcp_direct_targets.0.is_empty() {
        return Ok(None);
    }

    let tcp_direct = TcpDirectOutbound::new(deps.tcp_direct_targets.0.clone(), deps.quic_publisher)
        .await
        .change_context(Error("Failed to create TCP direct outbound".into()))?
        .spawn();

    for (service_name, addr) in &deps.tcp_direct_targets.0 {
        log::info!("TCP direct outbound serving '{service_name}' on '{addr}'");
    }
    Ok(Some(tcp_direct))
}
