// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use async_trait::async_trait;
use tokio::sync::mpsc;

/// Trait for tokio actor components driven by an mpsc message channel.
///
/// Implement [`handle`] for actors with a single message source — the default
/// [`run`] loop takes care of the rest.
///
/// Override [`run`] when the actor needs additional concurrent concerns alongside
/// message processing, such as a background accept loop or a `watch` channel.
#[async_trait]
pub(crate) trait Actor: Sized + Send + 'static {
    type Message: Send + 'static;

    /// Handle a single incoming message.
    async fn handle(&mut self, msg: Self::Message);

    /// Drive the actor until the sender half of `rx` is dropped.
    ///
    /// The default processes messages sequentially via [`handle`]. Override
    /// this to multiplex additional futures concurrently with message receipt.
    async fn run(mut self, mut rx: mpsc::Receiver<Self::Message>) {
        while let Some(msg) = rx.recv().await {
            self.handle(msg).await;
        }
    }
}
