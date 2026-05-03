// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use async_trait::async_trait;
use error_stack::{FutureExt, IntoReport, Report, ResultExt, bail};
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

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
    async fn open_stream(
        &self,
        target: &str,
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
    #[error("connect failed")]
    ConnectFailed,
    #[error("stream open failed")]
    OpenStreamFailed,
}

#[async_trait]
impl QuicBackend for QuicConnector {
    async fn open_stream(
        &self,
        target: &str,
    ) -> Result<
        (
            Box<dyn AsyncWrite + Unpin + Send>,
            Box<dyn AsyncRead + Unpin + Send>,
        ),
        Report<BackendError>,
    > {
        use crate::core::transport::endpoint::connection::Open;

        let conn = self
            .connect(target)
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
/// Dropping this handle aborts the accept loop and all in-flight connections.
/// Call [`shutdown`](Self::shutdown) to also await full termination of the accept
/// loop task.
pub struct Socks5Handle(LifecycleHandle);

impl_lifecycle_handle!(Socks5Handle);

/// SOCKS5 inbound component.
///
/// Accepts TCP connections, performs the SOCKS5 handshake, then forwards each
/// `TCP_CONNECT` request to the given [`QuicConnector`]. The domain name from
/// the SOCKS5 target address is used directly as the QUIC service name.
///
/// # Lifecycle
///
/// Call [`spawn`](Self::spawn) to start and obtain a [`Socks5Handle`].
/// Dropping the handle stops the accept loop.
pub struct Socks5Inbound {
    listener: TcpListener,
    backend: Arc<dyn QuicBackend>,
}

impl Socks5Inbound {
    /// Bind to `listen_addr` and return a component ready to be started via [`spawn`](Self::spawn).
    pub async fn new(
        listen_addr: SocketAddr,
        connector: QuicConnector,
    ) -> Result<Self, Report<Error>> {
        let listener = TcpListener::bind(listen_addr)
            .await
            .change_context_lazy(|| {
                Error(format!("Failed to bind SOCKS5 server to {listen_addr}"))
            })?;
        Ok(Self {
            listener,
            backend: Arc::new(connector),
        })
    }

    /// Start the accept loop, returning a [`Socks5Handle`] that controls its lifetime.
    pub fn spawn(self) -> Socks5Handle {
        Socks5Handle::new(tokio::spawn(self.run()))
    }

    async fn run(self) {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                result = self.listener.accept() => match result {
                    Ok((stream, peer_addr)) => {
                        log::debug!(target: LOG_TARGET, "Accepted connection from {peer_addr}");
                        let backend = self.backend.clone();
                        tasks.spawn(async move {
                            if let Err(e) = handle_socks5(stream, backend).await {
                                log::warn!(target: LOG_TARGET,
                                    "Connection from {peer_addr} error: {e:?}");
                            }
                        });
                    }
                    Err(e) => {
                        log::error!(target: LOG_TARGET, "Accept error: {e:?}");
                        break;
                    }
                },

                // Reap finished tasks to keep the set bounded.
                Some(_) = tasks.join_next() => {}
            }
        }
        // Dropping JoinSet here aborts all in-flight connection tasks.
    }
}

/// Handles a single SOCKS5 connection: performs the handshake, opens connection to the target,
/// then relays traffic between the client and the target until either side closes.
async fn handle_socks5(
    stream: TcpStream,
    backend: Arc<dyn QuicBackend>,
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

    // Step 3: Build the target address string passed to the connector.
    let target = match &target_addr {
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

    // Step 4: Open QUIC connection and bidirectional stream to the target.
    let (mut quic_send, mut quic_recv) = match backend.open_stream(&target).await {
        Ok(streams) => streams,
        Err(e) => {
            let reply = match e.current_context() {
                BackendError::ConnectFailed => ReplyError::HostUnreachable,
                BackendError::OpenStreamFailed => ReplyError::GeneralFailure,
            };
            let _ = proto.reply_error(&reply).await;
            bail!(e.change_context(Error(format!("Backend failure for '{target}'"))))
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

    log::debug!(target: LOG_TARGET, "Relaying traffic for '{target}'");

    tokio::select! {
        res = tokio::io::copy(&mut client_read, &mut quic_send) => {
            if let Err(e) = res {
                log::debug!(target: LOG_TARGET, "Client->QUIC relay error for '{target}': {e:?}");
            }
        }
        res = tokio::io::copy(&mut quic_recv, &mut client_write) => {
            if let Err(e) = res {
                log::debug!(target: LOG_TARGET, "QUIC->Client relay error for '{target}': {e:?}");
            }
        }
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

    fn inbound(listener: TcpListener, backend: impl QuicBackend + 'static) -> Socks5Inbound {
        Socks5Inbound {
            listener,
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
            _target: &str,
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
            _target: &str,
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
    async fn test_actor_binds_and_accepts() {
        let (listener, addr) = bound_listener().await;
        let _handle = inbound(listener, MockFailingQuicBackend).spawn();

        TcpStream::connect(addr).await.unwrap();
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
        socks5_connect(&mut client, "some-service", 80).await;

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
    async fn test_handle_dropped_stops_actor() {
        let (listener, addr) = bound_listener().await;
        let handle = inbound(listener, MockFailingQuicBackend).spawn();

        // Actor is running — connection should succeed
        TcpStream::connect(addr).await.unwrap();

        // Drop handle — actor shuts down
        let _ = handle.shutdown().await;

        // New connections should be refused now
        let result = tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(addr)).await;
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "connections should fail after shutdown"
        );
    }

    #[tokio::test]
    async fn test_happy_path_relay() {
        let (backend, mut backend_stream) = MockConnectedQuicBackend::new_pair();
        let (listener, addr) = bound_listener().await;
        let _handle = inbound(listener, backend).spawn();

        // Connect as SOCKS5 client and complete the handshake
        let mut client = TcpStream::connect(addr).await.unwrap();
        socks5_connect(&mut client, "some-service", 80).await;

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
    }
}
