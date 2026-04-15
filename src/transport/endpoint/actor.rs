// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use async_trait::async_trait;
use error_stack::{Report, ResultExt};
use tokio::sync::{mpsc, oneshot};

use crate::actor::Actor;
use crate::transport::Error;

use super::{QuicEndpoint, connection::QuicConnection};

const CHANNEL_CAPACITY: usize = 32;

pub(crate) struct ConnectMsg {
    service: String,
    reply: oneshot::Sender<Result<QuicConnection, Report<Error>>>,
}

/// Clonable handle for opening outgoing QUIC connections.
///
/// Obtained from [`QuicEndpoint::into_actor`].
#[derive(Clone)]
pub struct QuicConnector(mpsc::Sender<ConnectMsg>);

impl QuicConnector {
    /// Open a connection to the named service.
    ///
    /// Fails if the actor has shut down or if the underlying QUIC connect fails.
    pub async fn connect(&self, service: &str) -> Result<QuicConnection, Report<Error>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.0
            .send(ConnectMsg {
                service: service.to_string(),
                reply: reply_tx,
            })
            .await
            .change_context(Error("QuicEndpoint actor shut down".into()))?;
        reply_rx
            .await
            .change_context(Error("QuicEndpoint actor dropped reply channel".into()))?
    }
}

/// Exclusive handle for receiving accepted incoming QUIC connections.
///
/// Obtained from [`QuicEndpoint::into_actor`].
pub struct QuicAcceptor(mpsc::Receiver<(String, QuicConnection)>);

impl QuicAcceptor {
    /// Wait for the next accepted connection.
    ///
    /// Returns `None` when the actor has shut down.
    pub async fn accept(&mut self) -> Option<(String, QuicConnection)> {
        self.0.recv().await
    }
}

pub(crate) struct QuicEndpointActor {
    endpoint: QuicEndpoint,
    accept_tx: mpsc::Sender<(String, QuicConnection)>,
}

impl QuicEndpointActor {
    pub(crate) fn spawn(endpoint: QuicEndpoint) -> (QuicConnector, QuicAcceptor) {
        let (connect_tx, connect_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (accept_tx, accept_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let actor = Self {
            endpoint,
            accept_tx,
        };
        tokio::spawn(actor.run(connect_rx));
        (QuicConnector(connect_tx), QuicAcceptor(accept_rx))
    }
}

#[async_trait]
impl Actor for QuicEndpointActor {
    type Message = ConnectMsg;

    async fn handle(&mut self, msg: ConnectMsg) {
        let result = self.endpoint.connect(&msg.service).await;
        let _ = msg.reply.send(result);
    }

    async fn run(mut self, mut rx: mpsc::Receiver<ConnectMsg>) {
        loop {
            tokio::select! {
                Some(msg) = rx.recv() => {
                    self.handle(msg).await
                },
                accepted = self.endpoint.accept() => match accepted {
                    Some(conn) => {
                        if self.accept_tx.send(conn).await.is_err() {
                            // Acceptor is dropped, nothing to dispatch to.
                            // Signal quinn to stop accepting so this future unblocks.
                            log::debug!("QuicEndpointActor: acceptor dropped, closing endpoint");
                            self.endpoint.close();
                        }
                    },
                    None => {
                        log::debug!("QuicEndpointActor: endpoint is closed, shutting down");
                        break;
                    }
                },
            }
        }
    }
}
