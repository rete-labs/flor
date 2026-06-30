// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use async_trait::async_trait;
use error_stack::{FutureExt, IntoReport, Report, ResultExt, bail};
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

use crate::core::identity::{Dialable, X509Svid};
use crate::core::transport::QuicConnector;
use crate::impl_lifecycle_handle;
use crate::utils::lifecycle::LifecycleHandle;

const LOG_TARGET: &str = "socks5_inbound";

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

/// Abstraction over the QUIC backend used by [`handle_socks5`].
///
/// The production implementation wraps [`QuicConnector`].
/// Tests substitute a lightweight in-process mock.
#[async_trait]
trait QuicBackend: Send + Sync {
    /// Open a bidirectional stream to `target`, authenticating as `caller`.
    async fn open_stream(
        &self,
        caller: &X509Svid,
        target: &Dialable,
    ) -> Result<
        (
            Box<dyn AsyncWrite + Unpin + Send>,
            Box<dyn AsyncRead + Unpin + Send>,
        ),
        Report<BackendError>,
    >;
}

#[derive(Debug, thiserror::Error)]
enum BackendError {
    #[error("Connect failed")]
    ConnectFailed,
    #[error("Stream open failed")]
    OpenStreamFailed,
}

#[async_trait]
impl QuicBackend for QuicConnector {
    async fn open_stream(
        &self,
        caller: &X509Svid,
        target: &Dialable,
    ) -> Result<
        (
            Box<dyn AsyncWrite + Unpin + Send>,
            Box<dyn AsyncRead + Unpin + Send>,
        ),
        Report<BackendError>,
    > {
        use crate::core::transport::endpoint::connection::Open;

        let conn = self
            .connect(caller, target)
            .await
            .change_context(BackendError::ConnectFailed)?;

        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| e.into_report())
            .change_context(BackendError::OpenStreamFailed)?;

        Ok((Box::new(send), Box::new(recv)))
    }
}

/// Lifecycle handle for a running [`Socks5Inbound`].
///
/// Dropping this handle aborts the accept loops and all in-flight connections.
/// Call [`shutdown`](Self::shutdown) to also await full termination of the accept
/// loop tasks.
pub struct Socks5Handle(LifecycleHandle);

impl_lifecycle_handle!(Socks5Handle);

/// SOCKS5 inbound component.
///
/// Accepts TCP connections on per-principal listeners, performs the SOCKS5
/// handshake, then forwards each `TCP_CONNECT` request to the given
/// [`QuicConnector`], authenticating as the listener's caller SVID. The domain
/// name from the SOCKS5 target address is resolved to a [`Dialable`] identity
/// against the caller's trust domain.
///
/// # Lifecycle
///
/// Call [`spawn`](Self::spawn) to start and obtain a [`Socks5Handle`].
/// Dropping the handle stops all accept loops.
pub struct Socks5Inbound {
    /// One listener per principal, each paired with the caller SVID it serves.
    listeners: Vec<(Arc<X509Svid>, TcpListener)>,
    backend: Arc<dyn QuicBackend>,
}

impl Socks5Inbound {
    /// Bind one listener per `(caller SVID, listen address)` and return a
    /// component ready to be started via [`spawn`](Self::spawn).
    pub async fn new(
        bindings: Vec<(X509Svid, SocketAddr)>,
        connector: QuicConnector,
    ) -> Result<Self, Report<Error>> {
        let listeners = bind_listeners(bindings).await?;
        Ok(Self {
            listeners,
            backend: Arc::new(connector),
        })
    }

    /// Start the accept loop, returning a [`Socks5Handle`] that controls its lifetime.
    pub fn spawn(self) -> Socks5Handle {
        Socks5Handle::new(tokio::spawn(self.run()))
    }

    async fn run(self) {
        let mut tasks = JoinSet::new();
        for (caller, listener) in self.listeners {
            let backend = self.backend.clone();
            tasks.spawn(run_listener(caller, listener, backend));
        }

        // Any listener stopping terminates the whole inbound. Dropping the set
        // aborts the remaining listeners and their in-flight connections.
        let _ = tasks.join_next().await;
    }
}

async fn bind_listeners(
    bindings: Vec<(X509Svid, SocketAddr)>,
) -> Result<Vec<(Arc<X509Svid>, TcpListener)>, Report<Error>> {
    let mut listeners = Vec::with_capacity(bindings.len());
    for (caller, listen_addr) in bindings {
        let listener = TcpListener::bind(listen_addr)
            .await
            .change_context_lazy(|| {
                Error(format!(
                    "Failed to bind SOCKS5 listener for '{}' to {listen_addr}",
                    caller.spiffe_id()
                ))
            })?;
        listeners.push((Arc::new(caller), listener));
    }
    Ok(listeners)
}

async fn run_listener(caller: Arc<X509Svid>, listener: TcpListener, backend: Arc<dyn QuicBackend>) {
    let principal = caller.spiffe_id().clone();
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            result = listener.accept() => match result {
                Ok((stream, peer_addr)) => {
                    log::debug!(target: LOG_TARGET,
                        "Accepted connection from {peer_addr} for principal '{principal}'");
                    let backend = backend.clone();
                    let caller = caller.clone();
                    let principal = principal.clone();
                    tasks.spawn(async move {
                        if let Err(e) = handle_socks5(stream, backend, caller).await {
                            log::warn!(target: LOG_TARGET,
                                "Connection from {peer_addr} via SOCKS5 for principal \
                                 '{principal}' error: {e:?}");
                        }
                    });
                }
                Err(e) => {
                    log::error!(target: LOG_TARGET,
                        "SOCKS5 listener for '{principal}' accept error: {e:?}");
                    break;
                }
            },

            // Reap finished tasks to keep the set bounded.
            Some(_) = tasks.join_next() => {}
        }
    }
    // Dropping JoinSet here aborts all in-flight connection tasks.
}

/// Handles a single SOCKS5 connection: performs the handshake, opens connection to the target,
/// then relays traffic between the client and the target until either side closes.
async fn handle_socks5(
    stream: TcpStream,
    backend: Arc<dyn QuicBackend>,
    caller: Arc<X509Svid>,
) -> Result<(), Report<Error>> {
    // Step 1: SOCKS5 handshake.
    let proto = Socks5ServerProtocol::accept_no_auth(stream)
        .change_context(Error("SOCKS5 handshake failed".into()))
        .await?;
    let (proto, cmd, target_addr) = proto
        .read_command()
        .change_context(Error("SOCKS5 command read failed".into()))
        .await?;

    // Step 2: Reject unsupported commands.
    if cmd != Socks5Command::TCPConnect {
        log::debug!(target: LOG_TARGET, "Unsupported command {cmd:?}, rejecting");
        proto
            .reply_error(&ReplyError::CommandNotSupported)
            .change_context(Error("Failed to reply to unsupported command".into()))
            .await?;
        return Ok(());
    }

    // Step 3: Take the `.rete` hostname; IP targets are not addressable by identity.
    let host = match &target_addr {
        TargetAddr::Domain(host, _port) => host.clone(),
        TargetAddr::Ip(addr) => {
            log::debug!(target: LOG_TARGET, "Received IP target {addr}, which is not supported by the connector");
            proto
                .reply_error(&ReplyError::AddressTypeNotSupported)
                .change_context(Error("Failed to reply to unsupported address type".into()))
                .await?;
            return Ok(());
        }
    };

    // Step 4: Resolve the hostname to a dial target against the caller's trust
    // domain (inbound builds services only; see ADR-0007).
    let target = match Dialable::resolve(&host, caller.spiffe_id().trust_domain()) {
        Ok(target) => target,
        Err(e) => {
            log::debug!(target: LOG_TARGET, "Cannot resolve target '{host}': {e:?}");
            proto
                .reply_error(&ReplyError::HostUnreachable)
                .change_context(Error("Failed to reply to unresolvable target".into()))
                .await?;
            return Ok(());
        }
    };

    // Step 5: Open QUIC connection and bidirectional stream to the target.
    let (mut quic_send, mut quic_recv) = match backend.open_stream(&caller, &target).await {
        Ok(streams) => streams,
        Err(e) => {
            let reply = match e.current_context() {
                BackendError::ConnectFailed => ReplyError::HostUnreachable,
                BackendError::OpenStreamFailed => ReplyError::GeneralFailure,
            };
            let _ = proto.reply_error(&reply).await;
            bail!(e.change_context(Error(format!("Backend failure for '{host}'"))))
        }
    };

    // Step 5: Reply SOCKS5 success and start relaying traffic.
    // Use a standard address placeholder since we don't have a real local bind address for this
    // connection and it's not actually used by almost all SOCKS5 clients.
    let bind_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
    let client_stream = proto
        .reply_success(bind_addr)
        .change_context(Error("Failed to send SOCKS5 success reply".into()))
        .await?;
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);

    log::debug!(target: LOG_TARGET, "Relaying traffic for '{host}'");

    let client_to_quic = async {
        let _ = tokio::io::copy(&mut client_read, &mut quic_send).await?;
        quic_send.shutdown().await
    };
    let quic_to_client = async {
        let _ = tokio::io::copy(&mut quic_recv, &mut client_write).await?;
        client_write.shutdown().await
    };
    let (client_to_quic, quic_to_client) = tokio::join!(client_to_quic, quic_to_client);
    if let Err(e) = client_to_quic {
        log::debug!(target: LOG_TARGET, "Client->QUIC relay error for '{host}': {e:?}");
    }
    if let Err(e) = quic_to_client {
        log::debug!(target: LOG_TARGET, "QUIC->Client relay error for '{host}': {e:?}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::Mutex;

    // --- Test helpers ---

    async fn bound_listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    /// Mint a caller SVID `spiffe://demo.flor/user/<name>` from a throwaway CA.
    /// The backend is mocked, so the cert isn't validated — only its trust domain
    /// (`demo.flor`) matters, as it's the context for resolving `.rete` targets.
    fn caller_svid(name: &str) -> X509Svid {
        use crate::core::identity::{
            Ca, Kind, SpiffeId, TrustDomain, keygen_csr, load_svid_from_pem,
        };
        let td = TrustDomain::new("demo.flor").unwrap();
        let ca = Ca::init(&td, Duration::from_secs(3600)).unwrap();
        let id = SpiffeId::new(format!("spiffe://demo.flor/user/{name}")).unwrap();
        let (key, csr) = keygen_csr(&id).unwrap();
        let leaf = ca
            .sign_csr(csr.as_bytes(), &id, Kind::User, Duration::from_secs(3600))
            .unwrap();
        load_svid_from_pem(leaf.as_bytes(), key.serialize_pem().as_bytes()).unwrap()
    }

    fn inbound(listener: TcpListener, backend: impl QuicBackend + 'static) -> Socks5Inbound {
        inbound_with_listeners(vec![(caller_svid("alice"), listener)], backend)
    }

    fn inbound_with_listeners(
        bindings: Vec<(X509Svid, TcpListener)>,
        backend: impl QuicBackend + 'static,
    ) -> Socks5Inbound {
        Socks5Inbound {
            listeners: bindings
                .into_iter()
                .map(|(svid, listener)| (Arc::new(svid), listener))
                .collect(),
            backend: Arc::new(backend),
        }
    }

    /// Perform the SOCKS5 greeting + TCP_CONNECT handshake up to (but not including)
    /// the server's connect reply.
    async fn socks5_connect(stream: &mut TcpStream, target: &str, port: u16) {
        // Client greeting: version=5, nmethods=1, method=0 (no-auth)
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [0x05, 0x00], "server must accept no-auth");

        // CONNECT request: version=5, cmd=CONNECT(1), rsv=0, atyp=DOMAINNAME(3)
        let host = target.as_bytes();
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host);
        req.push((port >> 8) as u8);
        req.push((port & 0xff) as u8);
        stream.write_all(&req).await.unwrap();
    }

    /// Helper to send a non-connect SOCKS5 command (BIND = 0x02).
    async fn socks5_bind(stream: &mut TcpStream) {
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await.unwrap();

        // BIND request
        stream
            .write_all(&[0x05, 0x02, 0x00, 0x03, 0x09])
            .await
            .unwrap();
        stream.write_all(b"localhost\x00\x50").await.unwrap();
    }

    /// Backend that always fails at the connect step.
    struct MockFailingQuicBackend;

    #[async_trait]
    impl QuicBackend for MockFailingQuicBackend {
        async fn open_stream(
            &self,
            _caller: &X509Svid,
            _target: &Dialable,
        ) -> Result<
            (
                Box<dyn AsyncWrite + Unpin + Send>,
                Box<dyn AsyncRead + Unpin + Send>,
            ),
            Report<BackendError>,
        > {
            Err(Report::new(BackendError::ConnectFailed))
        }
    }

    /// Backend that must never be reached — used to prove the target was rejected
    /// before any dial was attempted.
    struct MockUnreachableQuicBackend;

    #[async_trait]
    impl QuicBackend for MockUnreachableQuicBackend {
        async fn open_stream(
            &self,
            _caller: &X509Svid,
            _target: &Dialable,
        ) -> Result<
            (
                Box<dyn AsyncWrite + Unpin + Send>,
                Box<dyn AsyncRead + Unpin + Send>,
            ),
            Report<BackendError>,
        > {
            panic!("backend must not be dialed for an unresolvable target");
        }
    }

    /// Backend that returns one side of a `tokio::io::duplex` pair.
    ///
    /// The test holds the other side and uses it to simulate a QUIC peer:
    /// writes appear as `quic_recv` data (client reads them), and
    /// data the client sends arrives as reads on the test side.
    struct MockConnectedQuicBackend {
        stream: Mutex<Option<tokio::io::DuplexStream>>,
    }

    impl MockConnectedQuicBackend {
        fn new_pair() -> (Self, tokio::io::DuplexStream) {
            let (server_side, test_side) = tokio::io::duplex(65536);
            (
                Self {
                    stream: Mutex::new(Some(server_side)),
                },
                test_side,
            )
        }
    }

    #[async_trait]
    impl QuicBackend for MockConnectedQuicBackend {
        async fn open_stream(
            &self,
            _caller: &X509Svid,
            _target: &Dialable,
        ) -> Result<
            (
                Box<dyn AsyncWrite + Unpin + Send>,
                Box<dyn AsyncRead + Unpin + Send>,
            ),
            Report<BackendError>,
        > {
            let stream = self
                .stream
                .lock()
                .await
                .take()
                .expect("stream already consumed");
            let (read_half, write_half) = tokio::io::split(stream);
            Ok((Box::new(write_half), Box::new(read_half)))
        }
    }

    // --- Tests ---

    #[tokio::test]
    async fn test_actor_accepts_on_all_listeners() {
        let (alice_listener, alice_addr) = bound_listener().await;
        let (bob_listener, bob_addr) = bound_listener().await;
        let _handle = inbound_with_listeners(
            vec![
                (caller_svid("alice"), alice_listener),
                (caller_svid("bob"), bob_listener),
            ],
            MockFailingQuicBackend,
        )
        .spawn();

        TcpStream::connect(alice_addr).await.unwrap();
        TcpStream::connect(bob_addr).await.unwrap();
    }

    #[tokio::test]
    async fn test_bind_failure_releases_previously_bound_listeners() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let result = bind_listeners(vec![
            (caller_svid("alice"), addr),
            (caller_svid("bob"), addr),
        ])
        .await;
        assert!(result.is_err(), "duplicate listen address must fail");

        TcpListener::bind(addr)
            .await
            .expect("listener bound before the error must be released");
    }

    #[tokio::test]
    async fn test_unsupported_command_gets_reply() {
        let (listener, addr) = bound_listener().await;
        let _handle = inbound(listener, MockFailingQuicBackend).spawn();

        let mut client = TcpStream::connect(addr).await.unwrap();
        socks5_bind(&mut client).await;

        let mut reply = [0u8; 10];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut reply))
            .await
            .expect("timeout")
            .expect("read error");
        assert!(n > 0);
        assert_eq!(reply[0], 0x05, "SOCKS5 version byte");
        assert_eq!(reply[1], 0x07, "CommandNotSupported");
    }

    #[tokio::test]
    async fn test_ip_target_gets_addr_type_not_supported() {
        let (listener, addr) = bound_listener().await;
        let _handle = inbound(listener, MockFailingQuicBackend).spawn();

        let mut client = TcpStream::connect(addr).await.unwrap();

        // Greeting
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).await.unwrap();

        // CONNECT with IPv4 target (atyp=0x01): 127.0.0.1:80
        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
            .await
            .unwrap();

        let mut reply = [0u8; 10];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut reply))
            .await
            .expect("timeout")
            .expect("read error");
        assert!(n > 0);
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x08, "AddressTypeNotSupported");
    }

    #[tokio::test]
    async fn test_backend_failure_gets_host_unreachable() {
        let (listener, addr) = bound_listener().await;
        let _handle = inbound(listener, MockFailingQuicBackend).spawn();

        let mut client = TcpStream::connect(addr).await.unwrap();
        socks5_connect(&mut client, "api.demo.flor.rete", 80).await;

        let mut reply = [0u8; 10];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut reply))
            .await
            .expect("timeout")
            .expect("read error");
        assert!(n > 0);
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x04, "HostUnreachable");
    }

    #[tokio::test]
    async fn test_foreign_trust_domain_target_gets_host_unreachable() {
        // The caller is in `demo.flor`; a target in another rete can't be resolved
        // against the caller's trust domain, so the dial is rejected *before* the
        // backend is reached (the backend panics if called).
        let (listener, addr) = bound_listener().await;
        let _handle = inbound(listener, MockUnreachableQuicBackend).spawn();

        let mut client = TcpStream::connect(addr).await.unwrap();
        socks5_connect(&mut client, "api.other-rete.rete", 80).await;

        let mut reply = [0u8; 10];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut reply))
            .await
            .expect("timeout")
            .expect("read error");
        assert!(n > 0);
        assert_eq!(reply[0], 0x05);
        assert_eq!(
            reply[1], 0x04,
            "HostUnreachable for a target in a foreign trust domain"
        );
    }

    #[tokio::test]
    async fn test_shutdown_stops_all_listeners() {
        let (alice_listener, alice_addr) = bound_listener().await;
        let (bob_listener, bob_addr) = bound_listener().await;
        let handle = inbound_with_listeners(
            vec![
                (caller_svid("alice"), alice_listener),
                (caller_svid("bob"), bob_listener),
            ],
            MockFailingQuicBackend,
        )
        .spawn();

        // Actor is running: connections to both listeners should succeed.
        TcpStream::connect(alice_addr).await.unwrap();
        TcpStream::connect(bob_addr).await.unwrap();

        // Shutting down the handle stops both listeners.
        let _ = handle.shutdown().await;

        for addr in [alice_addr, bob_addr] {
            let result =
                tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(addr)).await;
            assert!(
                result.is_err() || result.unwrap().is_err(),
                "connections to {addr} should fail after shutdown"
            );
        }
    }

    #[tokio::test]
    async fn test_happy_path_relay() {
        let (backend, mut backend_stream) = MockConnectedQuicBackend::new_pair();
        let (listener, addr) = bound_listener().await;
        let _handle = inbound(listener, backend).spawn();

        // Connect as SOCKS5 client and complete the handshake
        let mut client = TcpStream::connect(addr).await.unwrap();
        socks5_connect(&mut client, "api.demo.flor.rete", 80).await;

        // Read SOCKS5 success reply (10 bytes: ver, rep, rsv, atyp, 4-byte addr, 2-byte port)
        let mut reply = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply))
            .await
            .expect("timeout waiting for SOCKS5 reply")
            .expect("read error");
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x00, "expected success");

        // Backend → client direction
        backend_stream
            .write_all(b"hello from backend")
            .await
            .unwrap();
        let mut buf = vec![0u8; 18];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut buf))
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(&buf, b"hello from backend");

        // Client → backend direction
        client.write_all(b"hello from client").await.unwrap();
        let mut buf = vec![0u8; 17];
        tokio::time::timeout(Duration::from_secs(2), backend_stream.read_exact(&mut buf))
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(&buf, b"hello from client");

        // A client such as `printf ... | nc` closes its write half immediately after sending.
        // The reverse relay must remain alive long enough to deliver the backend response.
        client.shutdown().await.unwrap();
        backend_stream.write_all(b"reply after eof").await.unwrap();
        let mut buf = vec![0u8; 15];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut buf))
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(&buf, b"reply after eof");
    }
}
