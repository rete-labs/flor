// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use error_stack::{Report, ResultExt};
use tokio::{
    net::TcpStream,
    task::{JoinHandle, JoinSet},
};

use crate::{
    core::transport::{QuicAcceptor, QuicPublisher},
    impl_lifecycle_handle,
    northbound::outbound::{QuicInboundConnection, QuicStream},
    utils::lifecycle::LifecycleHandle,
};

const LOG_TARGET: &str = "tcp_direct_outbound";

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

/// Lifecycle handle for a running [`TcpDirectOutbound`].
///
/// Dropping this handle aborts the accept loop and all tracked in-flight
/// connection tasks.
pub struct TcpDirectHandle(LifecycleHandle);

impl_lifecycle_handle!(TcpDirectHandle);

/// TCP direct outbound component.
///
/// Subscribes to incoming QUIC connections for the configured service names and
/// forwards every accepted bidirectional stream to the matching TCP address.
pub struct TcpDirectOutbound {
    acceptor: QuicAcceptor,
    targets: Arc<HashMap<String, SocketAddr>>,
}

impl TcpDirectOutbound {
    /// Publish the configured service names and return a component ready to start.
    pub async fn new(
        targets: HashMap<String, SocketAddr>,
        publisher: QuicPublisher,
    ) -> Result<Self, Report<Error>> {
        let served = targets.keys().cloned().collect::<Vec<_>>();
        let acceptor = publisher
            .publish(served)
            .await
            .change_context(Error("Failed to publish TCP direct services".into()))?;

        Ok(Self {
            acceptor,
            targets: Arc::new(targets),
        })
    }

    /// Start the accept loop, returning a [`TcpDirectHandle`] that controls its lifetime.
    pub fn spawn(self) -> TcpDirectHandle {
        TcpDirectHandle::new(tokio::spawn(self.run()))
    }

    async fn run(mut self) {
        let mut tasks = JoinSet::new();

        loop {
            tokio::select! {
                accepted = self.acceptor.accept() => match accepted {
                    Some((service_name, conn)) => {
                        let targets = self.targets.clone();
                        tasks.spawn(async move {
                            handle_connection(service_name, conn, targets).await;
                        });
                    }
                    None => {
                        log::debug!(target: LOG_TARGET, "QUIC acceptor closed");
                        break;
                    }
                },

                Some(result) = tasks.join_next() => {
                    if let Err(e) = result {
                        log::warn!(target: LOG_TARGET, "Connection task failed: {e:?}");
                    }
                }
            }
        }
        // Dropping JoinSet here aborts all in-flight connection tasks.
    }
}

async fn handle_connection(
    service_name: String,
    conn: impl QuicInboundConnection + 'static,
    targets: Arc<HashMap<String, SocketAddr>>,
) {
    let Some(target_addr) = targets.get(&service_name).copied() else {
        log::debug!(target: LOG_TARGET, "No TCP target configured for '{service_name}'");
        return;
    };

    let mut streams = JoinSet::new();

    loop {
        tokio::select! {
            stream = conn.accept_stream() => match stream {
                Ok(stream) => {
                    streams.spawn(relay_stream(service_name.clone(), target_addr, stream));
                }
                Err(e) => {
                    log::debug!(
                        target: LOG_TARGET,
                        "QUIC connection closed for '{service_name}': {e:?}"
                    );
                    break;
                }
            },

            Some(result) = streams.join_next() => {
                if let Err(e) = result {
                    log::debug!(target: LOG_TARGET,
                        "Stream task failed for '{service_name}': {e:?}");
                }
            }
        }
    }
    // Dropping JoinSet here aborts any streams still running on this connection.
}

async fn relay_stream(
    service_name: String,
    target_addr: SocketAddr,
    mut quic_stream: Box<dyn QuicStream>,
) {
    let mut tcp_stream = match TcpStream::connect(target_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            log::debug!(
                target: LOG_TARGET,
                "Failed to connect TCP target {target_addr} for '{service_name}': {e:?}"
            );
            return;
        }
    };

    match tokio::io::copy_bidirectional(&mut quic_stream, &mut tcp_stream).await {
        Ok((quic_to_tcp, tcp_to_quic)) => {
            log::trace!(
                target: LOG_TARGET,
                "Relayed '{service_name}' via {target_addr}: {quic_to_tcp} bytes QUIC->TCP, {tcp_to_quic} bytes TCP->QUIC"
            );
        }
        Err(e) => {
            log::debug!(
                target: LOG_TARGET,
                "Relay error for '{service_name}' via {target_addr}: {e:?}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, time::Duration};

    use async_trait::async_trait;
    use error_stack::Report;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::{Mutex, oneshot};

    use super::*;

    async fn bound_listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    struct MockQuicConnection {
        streams: Mutex<VecDeque<tokio::io::DuplexStream>>,
    }

    impl MockQuicConnection {
        fn new(streams: Vec<tokio::io::DuplexStream>) -> Self {
            Self {
                streams: Mutex::new(streams.into()),
            }
        }
    }

    struct DropSignal(Option<oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }

    async fn pending_handle_task() -> (TcpDirectHandle, oneshot::Receiver<()>) {
        let (started_tx, started_rx) = oneshot::channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let join = tokio::spawn(async move {
            let _guard = DropSignal(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.expect("task should start");
        (TcpDirectHandle::new(join), dropped_rx)
    }

    #[async_trait]
    impl QuicInboundConnection for MockQuicConnection {
        async fn accept_stream(
            &self,
        ) -> Result<Box<dyn QuicStream>, Report<crate::northbound::outbound::Error>> {
            let stream = self.streams.lock().await.pop_front();
            match stream {
                Some(stream) => Ok(Box::new(stream)),
                None => std::future::pending().await,
            }
        }
    }

    #[tokio::test]
    async fn test_stream_is_relayed_to_configured_tcp_target() {
        let (listener, target_addr) = bound_listener().await;
        let tcp_server = tokio::spawn(async move {
            let (mut stream, _peer) = listener.accept().await.unwrap();

            let mut buf = [0u8; 15];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello from quic");

            stream.write_all(b"hello from tcp").await.unwrap();
        });

        let (mut quic_peer, quic_component) = tokio::io::duplex(65536);
        let conn = MockQuicConnection::new(vec![quic_component]);
        let targets = Arc::new(HashMap::from([("service".to_string(), target_addr)]));
        let handle = tokio::spawn(handle_connection("service".to_string(), conn, targets));

        quic_peer.write_all(b"hello from quic").await.unwrap();

        let mut buf = [0u8; 14];
        tokio::time::timeout(Duration::from_secs(2), quic_peer.read_exact(&mut buf))
            .await
            .expect("timeout waiting for relayed TCP response")
            .unwrap();
        assert_eq!(&buf, b"hello from tcp");

        tcp_server.await.unwrap();
        handle.abort();
    }

    #[tokio::test]
    async fn test_missing_service_target_does_not_connect_tcp() {
        let (listener, target_addr) = bound_listener().await;
        let tcp_server = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(100), listener.accept()).await
        });

        let (_quic_peer, quic_component) = tokio::io::duplex(65536);
        let conn = MockQuicConnection::new(vec![quic_component]);
        let targets = Arc::new(HashMap::from([("other-service".to_string(), target_addr)]));

        tokio::time::timeout(
            Duration::from_secs(1),
            handle_connection("service".to_string(), conn, targets),
        )
        .await
        .expect("handler should return when service is not configured");

        assert!(tcp_server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_tcp_connect_failure_is_contained_to_stream() {
        let (listener, target_addr) = bound_listener().await;
        drop(listener);

        let (mut quic_peer, quic_component) = tokio::io::duplex(65536);
        let conn = MockQuicConnection::new(vec![quic_component]);
        let targets = Arc::new(HashMap::from([("service".to_string(), target_addr)]));
        let handle = tokio::spawn(handle_connection("service".to_string(), conn, targets));

        quic_peer.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 1];
        let result =
            tokio::time::timeout(Duration::from_millis(100), quic_peer.read(&mut buf)).await;
        assert!(
            result.is_err() || result.unwrap().unwrap() == 0,
            "failed TCP connect should not produce response data"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn test_handle_drop_aborts_task() {
        let (handle, dropped_rx) = pending_handle_task().await;

        drop(handle);

        tokio::time::timeout(Duration::from_secs(1), dropped_rx)
            .await
            .expect("handle drop should abort the task")
            .expect("task should drop its guard");
    }

    #[tokio::test]
    async fn test_handle_shutdown_aborts_and_waits_for_task() {
        let (handle, dropped_rx) = pending_handle_task().await;

        let result = handle.shutdown().await;

        assert!(
            result.is_err(),
            "shutdown currently reports the aborted JoinError"
        );
        dropped_rx
            .await
            .expect("shutdown should wait until the task drops its guard");
    }
}
