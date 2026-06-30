// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::sync::Arc;

use error_stack::{IntoReport, Report, ResultExt};
use tokio::{
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
};

use crate::{
    core::{
        identity::{Dialable, SpiffeId, X509Bundle, X509Svid},
        transport::{Error, resolver::Resolver},
    },
    impl_lifecycle_handle,
    utils::lifecycle::LifecycleHandle,
};

use super::{
    AcceptOutcome, ConnectError, QuicEndpoint, SvidTls,
    connection::QuicConnection,
    registry::{Publication, PublishedServices},
    sni_for,
};

const CHANNEL_CAPACITY: usize = 32;

type PublishResult = Result<mpsc::Receiver<(SpiffeId, QuicConnection)>, Report<Error>>;

pub(crate) struct ConnectMsg {
    caller: X509Svid,
    target: Dialable,
    reply: oneshot::Sender<Result<QuicConnection, Report<Error>>>,
}

pub(crate) struct PublishMsg {
    svids: Vec<X509Svid>,
    reply: oneshot::Sender<PublishResult>,
}

/// Clonable handle for opening outgoing QUIC connections.
///
/// Obtained from [`QuicEndpoint::into_actor`].
#[derive(Clone)]
pub struct QuicConnector(mpsc::Sender<ConnectMsg>);

impl QuicConnector {
    /// Open a connection to `target`, authenticating as `caller`.
    ///
    /// Fails if the actor has shut down or if the underlying QUIC connect fails.
    pub async fn connect(
        &self,
        caller: &X509Svid,
        target: &Dialable,
    ) -> Result<QuicConnection, Report<Error>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.0
            .send(ConnectMsg {
                caller: caller.clone(),
                target: target.clone(),
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
    /// Publish a set of service SVIDs and subscribe to their incoming connections.
    ///
    /// Returns a [`QuicAcceptor`] that receives every accepted connection dialed at
    /// any of the published identities, each tagged with the target [`SpiffeId`].
    ///
    /// # Errors
    ///
    /// Returns an error if any SVID is not dialable, if its routing label is
    /// already claimed by another subscriber, or if the actor has shut down.
    pub async fn publish(&self, svids: Vec<X509Svid>) -> Result<QuicAcceptor, Report<Error>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.0
            .send(PublishMsg {
                svids,
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

/// Handle for receiving incoming QUIC connections for published services.
///
/// Obtained from [`QuicPublisher::publish`].
pub struct QuicAcceptor(mpsc::Receiver<(SpiffeId, QuicConnection)>);

impl QuicAcceptor {
    /// Wait for the next accepted connection, tagged with the **target** identity
    /// it was dialed against (which of the published services). The authenticated
    /// **peer** identity is available on the connection via `peer_id()`.
    ///
    /// Returns `None` when the actor has shut down.
    pub async fn accept(&mut self) -> Option<(SpiffeId, QuicConnection)> {
        self.0.recv().await
    }
}

pub(crate) struct QuicEndpointActor {
    endpoint: QuicEndpoint,
    registry: Arc<PublishedServices>,
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
        trust_bundle: Arc<X509Bundle>,
    ) -> Result<(QuicConnector, QuicPublisher, QuicHandle), Report<Error>> {
        let registry = PublishedServices::new();
        let endpoint = QuicEndpoint::new(resolver, socket, registry.clone(), trust_bundle)?;
        Ok(Self::spawn(endpoint, registry))
    }

    fn spawn(
        endpoint: QuicEndpoint,
        registry: Arc<PublishedServices>,
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

    /// Spawn the dial for `msg`. The task replies to the caller and yields a fault
    /// (`Some`) only when the endpoint is broken, so the run loop — draining the
    /// `JoinSet` — can shut down, mirroring an accept-loop fault.
    fn handle_connect(&self, msg: ConnectMsg, connect_tasks: &mut JoinSet<Option<Report<Error>>>) {
        let endpoint = self.endpoint.clone();
        connect_tasks.spawn(async move {
            match endpoint.connect(&msg.caller, &msg.target).await {
                Ok(conn) => {
                    let _ = msg.reply.send(Ok(conn));
                    None
                }
                Err(ConnectError::External(e)) => {
                    let _ = msg.reply.send(Err(e));
                    None
                }
                Err(ConnectError::Internal(e)) => {
                    // The endpoint's outbound TLS machinery is inconsistent. Tell
                    // the caller their dial was aborted (distinct from a routine
                    // failure), then surface the fault to the run loop for shutdown.
                    let _ = msg.reply.send(Err(Report::new(Error(
                        "Connection aborted by an internal QuicEndpoint fault".into(),
                    ))));
                    Some(e)
                }
            }
        });
    }

    fn handle_publish(&mut self, msg: PublishMsg) {
        // Build a `Publication` per SVID up front — derive its routing label
        // (dialable-only) and its cert — so we bail before touching the registry
        // on any bad input.
        let mut publications = Vec::with_capacity(msg.svids.len());
        for svid in &msg.svids {
            let spiffe_id = svid.spiffe_id().clone();
            let dialable = match Dialable::new(spiffe_id.clone()) {
                Ok(dialable) => dialable,
                Err(e) => {
                    let _ = msg.reply.send(Err(e.change_context(Error(format!(
                        "Cannot publish {spiffe_id}: not a dialable identity"
                    )))));
                    return;
                }
            };
            let certified_key = match svid.certified_key() {
                Ok(key) => key,
                Err(e) => {
                    let _ = msg.reply.send(Err(e));
                    return;
                }
            };
            publications.push(Publication {
                sni: sni_for(&dialable),
                spiffe_id,
                certified_key,
            });
        }

        let (dispatch, acceptor_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let reply = match self.registry.publish(publications, dispatch) {
            Ok(()) => Ok(acceptor_rx),
            Err(conflicts) => {
                let names = conflicts
                    .iter()
                    .map(SpiffeId::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                Err(Error(format!(
                    "Failed to publish. Services already handled by another subscriber: {names}"
                ))
                .into_report())
            }
        };
        let _ = msg.reply.send(reply);
    }

    async fn run(
        mut self,
        mut connect_rx: mpsc::Receiver<ConnectMsg>,
        mut publish_rx: mpsc::Receiver<PublishMsg>,
    ) {
        let mut connect_tasks: JoinSet<Option<Report<Error>>> = JoinSet::new();

        loop {
            tokio::select! {
                Some(msg) = connect_rx.recv() => {
                    self.handle_connect(msg, &mut connect_tasks);
                },
                Some(msg) = publish_rx.recv() => {
                    self.handle_publish(msg);
                },
                // The endpoint resolves each accepted connection's identity and
                // dispatches it to its subscriber internally (it holds the registry).
                outcome = self.endpoint.accept() => match outcome {
                    Ok(AcceptOutcome::Dispatched) => {}
                    Ok(AcceptOutcome::Closed) => {
                        log::debug!("QuicEndpointActor: endpoint closed, shutting down");
                        break;
                    }
                    Err(e) => {
                        // The endpoint faulted (CID exhaustion / internal inconsistency).
                        // TODO(#13): surface this to telemetry rather than only logging.
                        log::error!("QuicEndpointActor: accept loop faulted, shutting down: {e:?}");
                        break;
                    }
                },
                Some(joined) = connect_tasks.join_next() => match joined {
                    // A connect task reported the endpoint is broken — same class of
                    // fault as the accept loop's `Err`, so shut down likewise.
                    Ok(Some(e)) => {
                        // TODO(#13): surface this to telemetry rather than only logging.
                        log::error!("QuicEndpointActor: connect faulted, shutting down: {e:?}");
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        log::debug!("QuicEndpointActor: connect task panicked: {e:?}");
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

    use std::time::Duration;

    use serial_test::serial;
    use tokio::sync::oneshot;

    use crate::core::identity::{
        Ca, Kind, TrustDomain, keygen_csr, load_bundle_from_pem, load_svid_from_pem,
    };
    use crate::core::transport::{endpoint::QuicEndpoint, resolver::MockResolver};

    use super::super::mocks::{MockAsyncUdpSocket, MockEndpoint, MockRuntime};
    use super::*;

    /// A trust bundle from a throwaway CA — the publish/drop tests never dial, so
    /// its contents don't matter; the endpoint just needs one to construct.
    fn make_test_trust_bundle() -> Arc<X509Bundle> {
        let td = TrustDomain::new("demo.flor").unwrap();
        let ca = Ca::init(&td, Duration::from_secs(3600)).unwrap();
        Arc::new(load_bundle_from_pem(&td, ca.cert_pem().as_bytes()).unwrap())
    }

    /// Mint an SVID for `uri`/`kind` from a throwaway CA.
    fn mint(uri: &str, kind: Kind) -> X509Svid {
        let td = TrustDomain::new("demo.flor").unwrap();
        let ca = Ca::init(&td, Duration::from_secs(3600)).unwrap();
        let id = SpiffeId::new(uri).unwrap();
        let (key, csr) = keygen_csr(&id).unwrap();
        let leaf = ca
            .sign_csr(csr.as_bytes(), &id, kind, Duration::from_secs(3600))
            .unwrap();
        load_svid_from_pem(leaf.as_bytes(), key.serialize_pem().as_bytes()).unwrap()
    }

    /// A dialable, rete-scoped service SVID `spiffe://demo.flor/service/<name>`.
    fn svc_svid(name: &str) -> X509Svid {
        mint(&format!("spiffe://demo.flor/service/{name}"), Kind::Service)
    }

    // Creates a QuicEndpoint whose inner MockEndpoint allows close() but never accepts connections.
    // Suitable for direct actor struct tests that only exercise handle_publish.
    fn setup_endpoint_for_publish_tests(registry: Arc<PublishedServices>) -> QuicEndpoint {
        let ctx = MockEndpoint::new_with_abstract_socket_context();
        ctx.expect().returning(|_, _, _, _| {
            let mut mock = MockEndpoint::new();
            mock.expect_close().return_const(());
            Ok(mock)
        });
        QuicEndpoint::new_with_abstract_socket(
            Arc::new(MockResolver::new()),
            Arc::new(MockRuntime::new()),
            Arc::new(MockAsyncUdpSocket::new()),
            registry,
            make_test_trust_bundle(),
        )
        .expect("test endpoint setup failed")
    }

    fn make_actor() -> QuicEndpointActor {
        let registry = PublishedServices::new();
        QuicEndpointActor {
            endpoint: setup_endpoint_for_publish_tests(registry.clone()),
            registry,
        }
    }

    /// An endpoint whose resolver always fails, so `connect` returns a routine
    /// `ConnectError::Failed`. `close()` is allowed for the actor's `Drop`.
    fn setup_endpoint_with_failing_resolver(registry: Arc<PublishedServices>) -> QuicEndpoint {
        let mut resolver = MockResolver::new();
        resolver
            .expect_resolve()
            .returning(|_| Err(Report::new(Error("no route".into()))));
        let ctx = MockEndpoint::new_with_abstract_socket_context();
        ctx.expect().returning(|_, _, _, _| {
            let mut mock = MockEndpoint::new();
            mock.expect_close().return_const(());
            // `handle_connect` clones the endpoint into the spawned task; the
            // clone never reaches `connect_with` (resolution fails first).
            mock.expect_clone().returning(|| {
                let mut clone = MockEndpoint::new();
                clone.expect_close().return_const(());
                clone
            });
            Ok(mock)
        });
        QuicEndpoint::new_with_abstract_socket(
            Arc::new(resolver),
            Arc::new(MockRuntime::new()),
            Arc::new(MockAsyncUdpSocket::new()),
            registry,
            make_test_trust_bundle(),
        )
        .expect("test endpoint setup failed")
    }

    fn publish(actor: &mut QuicEndpointActor, svids: Vec<X509Svid>) -> PublishResult {
        let (tx, mut rx) = oneshot::channel();
        actor.handle_publish(PublishMsg { svids, reply: tx });
        rx.try_recv()
            .expect("handle_publish must send a reply synchronously")
    }

    // --- handle_publish tests ---

    #[test]
    #[serial]
    fn test_publish_returns_an_acceptor() {
        let mut actor = make_actor();
        assert!(publish(&mut actor, vec![svc_svid("api")]).is_ok());
    }

    #[test]
    #[serial]
    fn test_publish_conflict_returns_error_naming_service() {
        let mut actor = make_actor();

        // Hold the first acceptor so its registration stays live (not reaped).
        let _sub = publish(&mut actor, vec![svc_svid("svc1")]).expect("first publish failed");

        let err = publish(&mut actor, vec![svc_svid("svc1")]).unwrap_err();
        assert!(
            err.to_string().contains("svc1"),
            "error must name the conflicting service; got: {err}"
        );
    }

    #[test]
    #[serial]
    fn test_publish_rejects_non_dialable_svid() {
        let mut actor = make_actor();

        // A user SVID is authenticated but not a dial target (ADR-0007).
        let err = publish(
            &mut actor,
            vec![mint("spiffe://demo.flor/user/alice", Kind::User)],
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not a dialable identity"),
            "got: {err}"
        );
    }

    // --- handle_connect: routine failure vs fault ---

    #[tokio::test]
    #[serial]
    async fn test_handle_connect_routine_failure_replies_error_without_faulting() {
        let registry = PublishedServices::new();
        let actor = QuicEndpointActor {
            endpoint: setup_endpoint_with_failing_resolver(registry.clone()),
            registry,
        };

        let mut connect_tasks: JoinSet<Option<Report<Error>>> = JoinSet::new();
        let (reply_tx, reply_rx) = oneshot::channel();
        let caller = mint("spiffe://demo.flor/user/alice", Kind::User);
        let target =
            Dialable::new(SpiffeId::new("spiffe://demo.flor/service/api").unwrap()).unwrap();
        actor.handle_connect(
            ConnectMsg {
                caller,
                target,
                reply: reply_tx,
            },
            &mut connect_tasks,
        );

        // The task yields `None`: a routine dial failure is not a fault, so the run
        // loop would keep the endpoint running.
        let yielded = connect_tasks
            .join_next()
            .await
            .expect("the connect task was spawned")
            .expect("the connect task did not panic");
        assert!(
            yielded.is_none(),
            "a routine dial failure must not signal a fault"
        );

        // The dialing caller receives the routine error.
        let reply = reply_rx
            .await
            .expect("handle_connect replied to the caller");
        assert!(reply.is_err(), "caller must receive the routine failure");
    }

    // The `ConnectError::Fault` arm (reply "aborted" + yield `Some` → run-loop
    // shutdown) needs a completed-but-SAN-less handshake, which a mock
    // `quinn::Connection` can't produce; it's covered end-to-end by the
    // integration test rather than here.

    // --- Drop behaviour ---

    #[tokio::test]
    #[serial]
    async fn test_drop_calls_endpoint_close() {
        let ctx = MockEndpoint::new_with_abstract_socket_context();
        ctx.expect().returning(|_, _, _, _| {
            let mut mock = MockEndpoint::new();
            // accept() returns None immediately → run loop exits naturally.
            mock.expect_accept().returning(|| Box::pin(async { None }));
            // close() must be called exactly once by Drop for QuicEndpointActor.
            mock.expect_close().times(1).return_const(());
            Ok(mock)
        });

        let registry = PublishedServices::new();
        let endpoint = QuicEndpoint::new_with_abstract_socket(
            Arc::new(MockResolver::new()),
            Arc::new(MockRuntime::new()),
            Arc::new(MockAsyncUdpSocket::new()),
            registry.clone(),
            make_test_trust_bundle(),
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
