// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

// Provide real quinn::Endpoint for production build
#[cfg(not(test))]
pub use quinn::Endpoint;

#[cfg(test)]
use quinn::{AsyncUdpSocket, ClientConfig, EndpointConfig, Runtime, ServerConfig, VarInt};

#[cfg(test)]
use mockall::mock;

#[cfg(test)]
use std::{
    fmt::Debug,
    io::{self},
    net::{SocketAddr, UdpSocket},
    pin::Pin,
    sync::Arc,
    task::Context,
    time::Instant,
};

#[cfg(test)]
use super::connection::Inspect;

#[cfg(test)]
mock! {
    pub Endpoint {
        pub fn new_with_abstract_socket(
            config: EndpointConfig,
            server_config: Option<ServerConfig>,
            socket: Arc<dyn AsyncUdpSocket>,
            runtime: Arc<dyn Runtime>,
        ) -> io::Result<Self>;

        pub fn set_default_client_config(&mut self, config: ClientConfig);

        // Simplified: we return Option<MockIncoming> directly; caller awaits the inner future
        pub fn accept(&self) -> Pin<Box<dyn Future<Output = Option<MockIncoming>> + Send>>;

        // We do not test `connect` now as it is trivial
        pub fn connect(
            &self,
            addr: SocketAddr,
            server_name: &str
        ) -> Result<quinn::Connecting, quinn::ConnectError>;

        pub fn close(&self, error_code: VarInt, reason: &[u8]);
    }

    impl Clone for Endpoint {
        fn clone(&self) -> Self;
    }
}

#[cfg(test)]
mock! {
    pub Incoming {}
    impl Future for Incoming {
        type Output = Result<quinn::Connection, quinn::ConnectionError>;

        fn poll<'a>(
            self: Pin<&mut Self>,
            cx: &mut Context<'a>
        ) -> std::task::Poll<Result<quinn::Connection, quinn::ConnectionError>>;
    }
}

#[cfg(test)]
mock! {
    pub AsyncUdpSocket {}

    impl AsyncUdpSocket for AsyncUdpSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>>;

        // In order to mock functions with anonymous lifetimes we specify them explictily
        fn try_send<'a>(&self, transmit: &quinn::udp::Transmit<'a>) -> io::Result<()>;

        // Here are two such lifetimes
        fn poll_recv<'a, 'b>(
            &self,
            cx: &mut Context<'a>,
            bufs: &mut [io::IoSliceMut<'b>],
            meta: &mut [quinn::udp::RecvMeta],
        ) -> std::task::Poll<io::Result<usize>>;

        fn local_addr(&self) -> io::Result<SocketAddr>;
    }

    impl Debug for AsyncUdpSocket {
        fn fmt<'a>(&self, fmt: &mut std::fmt::Formatter<'a>) -> Result<(), std::fmt::Error>;
    }
}

#[cfg(test)]
mock! {
    pub Runtime {}

    impl Runtime for Runtime {
        fn new_timer(&self, _i: Instant) -> Pin<Box<dyn quinn::AsyncTimer>>;
        fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>);
        fn wrap_udp_socket(&self, t: UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>>;
    }

    impl Debug for Runtime {
        fn fmt<'a>(&self, fmt: &mut std::fmt::Formatter<'a>) -> Result<(), std::fmt::Error>;
    }
}

#[cfg(test)]
mock! {
    pub InspectConn {}

    impl Inspect for InspectConn {
        fn handshake_data(
            &self,
        ) -> Result<
            quinn::crypto::rustls::HandshakeData,
            error_stack::Report<crate::core::transport::Error>,
        >;
    }
}
