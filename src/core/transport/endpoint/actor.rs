// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::collections::HashMap;

use async_trait::async_trait;
use error_stack::{IntoReport, Report, ResultExt};
use tokio::{
    sync::{RwLock, mpsc, oneshot},
    task::JoinHandle,
};

use crate::{
    core::transport::{Error, resolver::Resolver},
    impl_lifecycle_handle,
    utils::lifecycle::LifecycleHandle,
};

use super::{QuicEndpoint, ServiceValidator, connection::QuicConnection};

/// Shared registry mapping service names to their subscriber channels.
///
/// Written by the actor on publish/cleanup; read by [`QuicEndpoint`] on every accepted
/// connection to decide whether the requested SNI service is served.
struct SharedServiceRegistry(RwLock<HashMap<String, mpsc::Sender<(String, QuicConnection)>>>);

impl SharedServiceRegistry {
    fn new() -> Arc<Self> {
        Arc::new(Self(RwLock::new(HashMap::new())))
    }
}

#[async_trait]
impl ServiceValidator for SharedServiceRegistry {
    async fn is_served(&self, service: &str) -> bool {
        self.0.read().await.contains_key(service)
    }
}

use std::sync::Arc;

const CHANNEL_CAPACITY: usize = 32;

type PublishResult = Result<mpsc::Receiver<(String, QuicConnection)>, Report<Error>>;

pub(crate) struct ConnectMsg {
    service: String,
    reply: oneshot::Sender<Result<QuicConnection, Report<Error>>>,
}

pub(crate) struct PublishMsg {
    served: Vec<String>,
    reply: oneshot::Sender<PublishResult>,
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

/// Clonable handle for subscribing to incoming QUIC connections.
///
/// Obtained from [`QuicEndpoint::into_actor`]. Call [`publish`](Self::publish) to register
/// a set of service names and receive a [`QuicAcceptor`] delivering connections for those services.
#[derive(Clone)]
pub struct QuicPublisher(mpsc::Sender<PublishMsg>);

impl QuicPublisher {
    /// Subscribe to incoming connections for the given service names.
    ///
    /// Returns a [`QuicAcceptor`] that will receive every incoming connection whose SNI matches
    /// one of the requested `served` names.
    ///
    /// # Errors
    ///
    /// Returns an error if any service in `served` is already claimed by another subscriber,
    /// or if the underlying actor has shut down.
    pub async fn publish(&self, served: Vec<String>) -> Result<QuicAcceptor, Report<Error>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.0
            .send(PublishMsg {
                served,
                reply: reply_tx,
            })
            .await
            .change_context(Error("QuicEndpoint actor shut down".into()))?;
        let rx = reply_rx
            .await
            .change_context(Error("QuicEndpoint actor dropped reply channel".into()))??;
        Ok(QuicAcceptor(rx))
    }
}

/// Handle for receiving incoming QUIC connections for subscribed services.
///
/// Obtained from [`QuicPublisher::publish`].
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
    registry: Arc<SharedServiceRegistry>,
}

impl Drop for QuicEndpointActor {
    fn drop(&mut self) {
        self.endpoint.close();
    }
}

impl QuicEndpointActor {
    pub(crate) fn spawn_new(
        resolver: Arc<dyn Resolver>,
        socket: std::net::UdpSocket,
    ) -> Result<(QuicConnector, QuicPublisher, QuicHandle), Report<Error>> {
        let registry = SharedServiceRegistry::new();
        let endpoint = QuicEndpoint::new(
            resolver,
            socket,
            registry.clone() as Arc<dyn ServiceValidator>,
        )?;
        Ok(Self::spawn(endpoint, registry))
    }

    fn spawn(
        endpoint: QuicEndpoint,
        registry: Arc<SharedServiceRegistry>,
    ) -> (QuicConnector, QuicPublisher, QuicHandle) {
        let (connect_tx, connect_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (publish_tx, publish_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let actor = Self { endpoint, registry };
        let join = tokio::spawn(actor.run(connect_rx, publish_rx));
        (
            QuicConnector(connect_tx),
            QuicPublisher(publish_tx),
            QuicHandle::new(join),
        )
    }

    async fn handle_connect(&self, msg: ConnectMsg) {
        let result = self.endpoint.connect(&msg.service).await;
        let _ = msg.reply.send(result);
    }

    async fn cleanup_stale(&self) {
        self.registry
            .0
            .write()
            .await
            .retain(|_, tx| !tx.is_closed());
    }

    async fn handle_publish(&self, msg: PublishMsg) {
        self.cleanup_stale().await;

        let mut locked_map = self.registry.0.write().await;

        let conflicting: Vec<String> = msg
            .served
            .iter()
            .filter(|s| locked_map.contains_key(s.as_str()))
            .cloned()
            .collect();

        if !conflicting.is_empty() {
            let _ = msg.reply.send(Err(Error(format!(
                "Failed to publish. Services already handled by another subscriber: {}",
                conflicting.join(", ")
            ))
            .into_report()));
            return;
        }

        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        for service in &msg.served {
            locked_map.insert(service.clone(), tx.clone());
        }
        let _ = msg.reply.send(Ok(rx));
    }

    async fn dispatch_connection(&self, service_name: String, conn: QuicConnection) {
        let tx = self.registry.0.read().await.get(&service_name).cloned();
        match tx {
            Some(tx) => {
                if tx.send((service_name.clone(), conn)).await.is_err() {
                    log::debug!(
                        "QuicEndpointActor: subscriber for '{service_name}' dropped, cleaning up"
                    );
                    self.cleanup_stale().await;
                }
            }
            None => {
                log::warn!(
                    "QuicEndpointActor: no subscriber for '{service_name}', dropping connection"
                );
            }
        }
    }

    async fn run(
        self,
        mut connect_rx: mpsc::Receiver<ConnectMsg>,
        mut publish_rx: mpsc::Receiver<PublishMsg>,
    ) {
        loop {
            tokio::select! {
                Some(msg) = connect_rx.recv() => {
                    self.handle_connect(msg).await;
                },
                Some(msg) = publish_rx.recv() => {
                    self.handle_publish(msg).await;
                },
                accepted = self.endpoint.accept() => match accepted {
                    Some((service_name, conn)) => {
                        self.dispatch_connection(service_name, conn).await;
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

/// Lifecycle handle for a running QUIC actor loop.
pub struct QuicHandle(LifecycleHandle);

impl_lifecycle_handle!(QuicHandle);

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use serial_test::serial;
    use tokio::sync::oneshot;

    use crate::core::transport::{endpoint::QuicEndpoint, resolver::MockResolver};

    use super::super::mocks::{MockAsyncUdpSocket, MockEndpoint, MockRuntime};
    use super::*;

    // Creates a QuicEndpoint whose inner MockEndpoint allows close() but never accepts connections.
    // Suitable for direct actor struct tests that only exercise handle_publish.
    fn setup_endpoint_for_publish_tests(registry: Arc<SharedServiceRegistry>) -> QuicEndpoint {
        let ctx = MockEndpoint::new_with_abstract_socket_context();
        ctx.expect().returning(|_, _, _, _| {
            let mut mock = MockEndpoint::new();
            mock.expect_set_default_client_config().return_const(());
            mock.expect_close().return_const(());
            Ok(mock)
        });
        QuicEndpoint::new_with_abstract_socket(
            Arc::new(MockResolver::new()),
            Arc::new(MockRuntime::new()),
            Arc::new(MockAsyncUdpSocket::new()),
            registry as Arc<dyn ServiceValidator>,
        )
        .expect("test endpoint setup failed")
    }

    fn make_actor() -> QuicEndpointActor {
        let registry = SharedServiceRegistry::new();
        QuicEndpointActor {
            endpoint: setup_endpoint_for_publish_tests(registry.clone()),
            registry,
        }
    }

    async fn do_publish(actor: &QuicEndpointActor, services: Vec<&str>) -> PublishResult {
        let (tx, rx) = oneshot::channel();
        actor
            .handle_publish(PublishMsg {
                served: services.into_iter().map(str::to_string).collect(),
                reply: tx,
            })
            .await;
        rx.await.expect("handle_publish must send a reply")
    }

    // --- handle_publish tests ---

    #[tokio::test]
    #[serial]
    async fn test_publish_registers_new_services() {
        let actor = make_actor();

        let result = do_publish(&actor, vec!["svc1", "svc2"]).await;

        assert!(result.is_ok());
        let map = actor.registry.0.read().await;
        assert!(map.contains_key("svc1"));
        assert!(map.contains_key("svc2"));
    }

    #[tokio::test]
    #[serial]
    async fn test_publish_single_service_shares_channel_across_names() {
        let actor = make_actor();
        let result = do_publish(&actor, vec!["svc1", "svc2"]).await;

        let rx = result.expect("publish failed");
        // Both service names map to senders on the same channel.
        // Verify by checking that both senders are alive and reference the same logical channel.
        {
            let map = actor.registry.0.read().await;
            assert!(!map.get("svc1").unwrap().is_closed());
            assert!(!map.get("svc2").unwrap().is_closed());
        }
        drop(rx);
        {
            let map = actor.registry.0.read().await;
            assert!(map.get("svc1").unwrap().is_closed());
            assert!(map.get("svc2").unwrap().is_closed());
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_publish_conflict_returns_error_naming_service() {
        let actor = make_actor();

        let _sub = do_publish(&actor, vec!["svc1"])
            .await
            .expect("first publish failed");

        let err = do_publish(&actor, vec!["svc1"]).await.unwrap_err();
        assert!(
            err.to_string().contains("svc1"),
            "error must name the conflicting service; got: {err}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_publish_partial_conflict_is_atomic() {
        let actor = make_actor();

        let _sub = do_publish(&actor, vec!["svc1"])
            .await
            .expect("setup failed");

        // svc1 conflicts, svc2 is new — the whole publish must be rejected.
        let result = do_publish(&actor, vec!["svc1", "svc2"]).await;
        assert!(result.is_err(), "publish with a conflict must fail");
        assert!(
            !actor.registry.0.read().await.contains_key("svc2"),
            "svc2 must not be partially registered when svc1 conflicts"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_publish_allows_reregister_after_subscriber_drops() {
        let actor = make_actor();

        let sub = do_publish(&actor, vec!["svc1"])
            .await
            .expect("first publish failed");
        drop(sub); // simulate subscriber dropping its QuicAcceptor

        let result = do_publish(&actor, vec!["svc1"]).await;
        assert!(
            result.is_ok(),
            "should succeed after stale subscriber is cleaned up"
        );
    }

    // --- Drop behaviour ---

    #[tokio::test]
    #[serial]
    async fn test_drop_calls_endpoint_close() {
        let ctx = MockEndpoint::new_with_abstract_socket_context();
        ctx.expect().returning(|_, _, _, _| {
            let mut mock = MockEndpoint::new();
            mock.expect_set_default_client_config().return_const(());
            // accept() returns None immediately → run loop exits naturally.
            mock.expect_accept().returning(|| Box::pin(async { None }));
            // close() must be called exactly once by Drop for QuicEndpointActor.
            mock.expect_close().times(1).return_const(());
            Ok(mock)
        });

        let registry = SharedServiceRegistry::new();
        let endpoint = QuicEndpoint::new_with_abstract_socket(
            Arc::new(MockResolver::new()),
            Arc::new(MockRuntime::new()),
            Arc::new(MockAsyncUdpSocket::new()),
            registry.clone() as Arc<dyn ServiceValidator>,
        )
        .unwrap();

        let (_, _, handle) = QuicEndpointActor::spawn(endpoint, registry);
        // Wait for the run task to finish naturally.
        // If MockEndpoint's expectation for close() is not met, the task panics and wait() returns Err.
        handle
            .wait()
            .await
            .expect("actor task panicked — close() expectation was not satisfied");
    }
}
