// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! `flor vertex` runtime: the vertex's runtime configuration ([`ConfigBundle`]),
//! loading it from a compiled vertex artifact ([`ConfigBundle::load`]), and the
//! [`run`] loop that serves it.
//!
//! This is the flor-vertex consumer of [`config::artifact`](crate::config::artifact):
//! the artifact module stays binary-agnostic; the flor-specific runtime types
//! live here. A future `crate::agent` mirrors this for the agent.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use error_stack::{Report, ResultExt, bail};

use crate::config::artifact::model::vertex::{
    Adapter, IoChannel, LinkRule, VertexMgmtPayload, Via,
};
use crate::config::artifact::{Envelope, VertexKind, version};
use crate::core::identity::Store;
use crate::core::transport::{
    AddrMap, EndpointAddr, QuicConnector, QuicPublisher, TransportBundle, TrustBundle,
};
use crate::northbound::inbound::{Error as InboundError, InboundBundle, Socks5Bindings};
use crate::northbound::outbound::{Error as OutboundError, OutboundBundle, TcpDirectBindings};
use crate::utils::report::ErrorReport;

/// A vertex-runtime failure: loading/validating the artifact, loading identity
/// material, or assembling the runtime.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

impl Error {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Fundle DI container for the vertex runtime's configuration inputs.
#[fundle::bundle]
#[derive(Clone)]
pub struct ConfigBundle {
    /// The UDP address to bind the QUIC endpoint to.
    pub endpoint_addr: EndpointAddr,

    /// A mapping of target identities to their remote UDP addresses.
    pub addr_map: AddrMap,

    /// The rete trust bundle the transport validates peers against.
    pub trust_bundle: TrustBundle,

    /// SOCKS5 caller SVIDs and their local listen addresses.
    pub socks5_bindings: Socks5Bindings,

    /// TCP-direct service SVIDs and their local upstream addresses.
    pub tcp_direct_bindings: TcpDirectBindings,
}

impl ConfigBundle {
    /// Load and build the runtime config for the vertex named `name` under the
    /// scope root `root`: read `mgmt/<name>.json`, validate it, and (for a link
    /// vertex) build the bundle, resolving identity through the scope's store.
    /// A mesh vertex errors (its runtime is not implemented yet).
    ///
    /// The mgmt set is flat — one `<name>.json` per workload — which is where
    /// `retectl compile` puts it (see
    /// [`NodeVertexArtifact::path`](crate::config::compile::NodeVertexArtifact::path)).
    ///
    /// Self-contained: it owns the read → validate → build sequence, so callers
    /// cannot skip validation or feed it the wrong kind.
    pub fn load(root: &Path, name: &str) -> Result<ConfigBundle, Report<Error>> {
        let path = root.join("mgmt").join(format!("{name}.json"));
        let bytes = std::fs::read(&path).change_context_lazy(|| {
            Error::new(format!("Failed to read vertex config {}", path.display()))
        })?;
        // Strict typed parse on the happy path — one JSON pass. Only when it
        // fails do we diagnose *why*: `precheck_schema_version` distinguishes
        // version skew (a newer, unsupported schema whose added field/variant our
        // strict types reject → an actionable upgrade error) from an artifact
        // that is genuinely malformed for a supported version (preserve the parse
        // error — it signals a mis-stamped or corrupt artifact, not skew). It
        // probes both ladders, since either the envelope's or the vertex payload
        // family's minor can be what our types choked on.
        let env: Envelope<VertexMgmtPayload> = match serde_json::from_slice(&bytes) {
            Ok(env) => env,
            Err(parse_err) => {
                version::precheck_schema_version::<VertexMgmtPayload>(&bytes).change_context_lazy(
                    || {
                        Error::new(format!(
                            "Vertex artifact {} has an unsupported schema",
                            path.display()
                        ))
                    },
                )?;
                return Err(Report::new(parse_err)
                    .change_context(Error::new(format!("Failed to parse {}", path.display()))));
            }
        };
        env.validate(name).change_context_lazy(|| {
            Error::new(format!(
                "Vertex artifact {} failed validation",
                path.display()
            ))
        })?;
        match env.payload.kind {
            VertexKind::Link => build_link_bundle(&env.payload, root),
            VertexKind::Mesh => bail!(Error::new("Mesh vertex runtime not yet implemented")),
        }
    }
}

/// Build the runtime bundle for a validated **link** payload, resolving every
/// identity through the store at `root`. Assumes the payload is validated
/// (single trust domain, dialable peers, …) — the only entry point is
/// [`ConfigBundle::load`].
fn build_link_bundle(
    payload: &VertexMgmtPayload,
    root: &Path,
) -> Result<ConfigBundle, Report<Error>> {
    // Local UDP bind address. This also gates the connection manager to the one
    // shape flor can serve today (a single udp adapter); reject upfront, before
    // any file IO, so unsupported topologies fail fast and cheaply.
    let endpoint_addr = resolve_endpoint_addr(&payload.connection_manager.adapters)?;

    // The artifact names principals; the store is what materializes them — and
    // what says which rete this scope belongs to. The trust domain is never
    // sampled off the config's own SPIFFE IDs: those are what gets *checked*
    // against the anchor, so they cannot also be its source.
    let store = Store::open(root).change_context_lazy(|| {
        Error::new(format!(
            "Failed to open the identity store at {}",
            root.display()
        ))
    })?;
    let trust_bundle = store
        .trust_bundle()
        .change_context_lazy(|| Error::new("Failed to load the rete trust bundle"))?;

    // Dial table: each udp link member's peer -> its wire address.
    let mut addr_map = HashMap::new();
    for LinkRule::List { members } in &payload.links {
        for member in members {
            if let Via::Udp { addr, .. } = &member.via {
                addr_map.insert(member.peer.clone(), *addr);
            }
        }
    }

    // Per-workload io channels -> inbound (socks5) / outbound (tcp) bindings.
    let mut socks5 = Vec::new();
    let mut tcp = Vec::new();
    for workload in &payload.workloads {
        let svid = store.svid(&workload.spiffe_id).change_context_lazy(|| {
            Error::new(format!(
                "Failed to resolve the identity of workload {}",
                workload.spiffe_id
            ))
        })?;
        for io in &workload.io {
            match io {
                IoChannel::Socks5 { listen } => socks5.push((svid.clone(), *listen)),
                IoChannel::Tcp { upstream } => tcp.push((svid.clone(), *upstream)),
                // FlorIO is the recursive bidirectional channel: no C0 runtime
                // wires it into the inbound/outbound path. Warn rather than skip
                // silently so a mis-provisioned workload is visible until the C1
                // FlorIO runtime lands.
                IoChannel::Florio { socket } => log::warn!(
                    "Workload {} declares a FlorIO io channel ({}); FlorIO is not \
                     implemented in C0 and this channel is ignored",
                    workload.spiffe_id,
                    socket.display()
                ),
            }
        }
    }

    Ok(ConfigBundle {
        endpoint_addr: EndpointAddr(endpoint_addr),
        addr_map: AddrMap(addr_map),
        trust_bundle: TrustBundle(Arc::new(trust_bundle)),
        socks5_bindings: Socks5Bindings(socks5),
        tcp_direct_bindings: TcpDirectBindings(tcp),
    })
}

/// The local UDP address to bind the vertex's QUIC endpoint to, derived from
/// the connection manager's single `udp` adapter: its `listen`, if present, is
/// the bind address; otherwise an ephemeral one (an initiator-only node still
/// needs a local UDP socket).
///
/// A link vertex is one QUIC endpoint over one udp socket — by design, not a
/// runtime limitation: socket aggregation is a mesh-layer concern (parallel
/// link-vertices), and FlorIO is mesh-flor reaching down to link-flor. The
/// single-udp-adapter shape is enforced in [`validate_vertex_link`]; this match
/// is the defensive restatement of that invariant for [`build_link_bundle`],
/// the only caller (reached only after validation).
///
/// [`validate_vertex_link`]: crate::config::artifact::validate
fn resolve_endpoint_addr(adapters: &[Adapter]) -> Result<SocketAddr, Report<Error>> {
    match adapters {
        [Adapter::Udp { listen, .. }] => {
            Ok(listen.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))))
        }
        _ => bail!(Error::new(
            "Link vertex must have exactly one udp connection-manager adapter"
        )),
    }
}

/// The assembled vertex runtime: the config plus the transport and northbound
/// actors built from it.
#[fundle::bundle]
struct Bundle {
    #[forward(EndpointAddr, AddrMap, TrustBundle, Socks5Bindings, TcpDirectBindings)]
    pub config: ConfigBundle,
    #[forward(QuicConnector, QuicPublisher)]
    pub transport: TransportBundle,
    pub inbound: InboundBundle,
    pub outbound: OutboundBundle,
}

/// Run a vertex: assemble the transport + northbound actors from `config` and
/// serve until one of them exits.
pub async fn run(config: ConfigBundle) -> Result<(), Report<Error>> {
    let bundle_err = || Error::new("Failed to build the vertex runtime bundle");
    let app: Bundle = Bundle::builder()
        .config(|_| config.clone())
        .transport_try(|b| TransportBundle::try_new(b))
        .change_context_lazy(bundle_err)?
        .inbound_try_async(init_inbound)
        .await
        .change_context_lazy(bundle_err)?
        .outbound_try_async(init_outbound)
        .await
        .change_context_lazy(bundle_err)?
        .build();

    let endpoint_handle = app.transport.endpoint_handle;
    let socks5_handle = app.inbound.socks5_handle;
    let tcp_direct_handle = app.outbound.tcp_direct_handle;

    tokio::select! {
        result = endpoint_handle.wait() => {
            if let Err(e) = result {
                log::error!("Endpoint actor task failed: {e:?}");
            }
        }
        result = async {
            match socks5_handle {
                Some(h) => h.wait().await,
                None => std::future::pending().await,
            }
        } => {
            if let Err(e) = result {
                log::error!("Socks5 task failed: {e:?}");
            }
        }
        result = async {
            match tcp_direct_handle {
                Some(h) => h.wait().await,
                None => std::future::pending().await,
            }
        } => {
            if let Err(e) = result {
                log::error!("TCP direct outbound task failed: {e:?}");
            }
        }
    }

    Ok(())
}

// Workaround to avoid a rust-analyzer issue with async closures.
async fn init_inbound(
    b: &BundleBuilder<fundle::Read, fundle::Set, fundle::Set, fundle::NotSet, fundle::NotSet>,
) -> Result<InboundBundle, ErrorReport<InboundError>> {
    InboundBundle::try_new(b).await
}

// Workaround to avoid a rust-analyzer issue with async closures.
async fn init_outbound(
    b: &BundleBuilder<fundle::Read, fundle::Set, fundle::Set, fundle::Set, fundle::NotSet>,
) -> Result<OutboundBundle, ErrorReport<OutboundError>> {
    OutboundBundle::try_new(b).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use tempfile::tempdir;

    use crate::core::identity::{Ca, Kind, SpiffeId, TrustDomain, keygen_csr};

    fn td() -> TrustDomain {
        TrustDomain::new("demo.flor").unwrap()
    }

    fn day() -> std::time::Duration {
        std::time::Duration::from_secs(3600)
    }

    /// Lay down the store's trust anchor at `root`: the CA cert and the
    /// trust-domain record enrollment ships beside it.
    fn write_store(ca: &Ca, root: &Path) {
        std::fs::write(root.join("ca.crt"), ca.cert_pem()).unwrap();
        std::fs::write(
            root.join("rete.json"),
            json!({ "trust_domain": td().to_string() }).to_string(),
        )
        .unwrap();
    }

    /// Mint an SVID for `uri`/`kind` from `ca` and file it in the store under
    /// `certs/<file>.crt`/`.key` — where the consumer resolves it by leaf.
    fn write_svid(ca: &Ca, root: &Path, uri: &str, kind: Kind, file: &str) {
        let id = SpiffeId::new(uri).unwrap();
        let (key, csr) = keygen_csr(&id).unwrap();
        let leaf = ca.sign_csr(csr.as_bytes(), &id, kind, day()).unwrap();
        let certs = root.join("certs");
        std::fs::create_dir_all(&certs).unwrap();
        std::fs::write(certs.join(format!("{file}.crt")), leaf).unwrap();
        std::fs::write(certs.join(format!("{file}.key")), key.serialize_pem()).unwrap();
    }

    /// A minimal valid link payload: one udp adapter + one tcp-service workload.
    fn one_workload_link() -> Value {
        json!({
            "schema_version": "1.0",
            "kind": "link",
            "transport_endpoint": { "type": "quic" },
            "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "127.0.0.1:4433" } ] },
            "workloads": [
                { "spiffe_id": "spiffe://demo.flor/service/alpha/api",
                  "io": [ { "kind": "tcp", "upstream": "127.0.0.1:8000" } ] }
            ]
        })
    }

    /// Write a full envelope `Value` to `mgmt/flor.json`, letting a test set
    /// `schema_version` and inject unknown claims the wrapping helper can't.
    fn write_envelope(root: &Path, env: Value) {
        let dir = root.join("mgmt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("flor.json"), serde_json::to_vec(&env).unwrap()).unwrap();
    }

    /// A well-formed 1.0 mgmt vertex envelope wrapping `payload`.
    fn envelope_1_0(payload: Value) -> Value {
        json!({
            "schema_version": "1.0",
            "plane": "mgmt",
            "version": 1,
            "node": "alpha",
            "name": "flor",
            "generated_at": "2026-01-01T00:00:00Z",
            "payload": payload,
            "signature": { "alg": "none", "key_id": "spiffe://demo.flor/management-plane/dev", "value": "x" }
        })
    }

    /// Write a mgmt vertex artifact wrapping `payload` to `mgmt/flor.json`.
    fn write_artifact(root: &Path, payload: Value) {
        write_envelope(root, envelope_1_0(payload));
    }

    #[test]
    fn loads_bundle_from_link_artifact() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let ca = Ca::init(&td(), day()).unwrap();
        write_store(&ca, root);
        write_svid(
            &ca,
            root,
            "spiffe://demo.flor/service/alpha/api",
            Kind::Service,
            "api",
        );
        write_artifact(
            root,
            json!({
                "schema_version": "1.0",
                "kind": "link",
                "transport_endpoint": { "type": "quic" },
                "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "127.0.0.1:4433" } ] },
                "workloads": [
                    { "spiffe_id": "spiffe://demo.flor/service/alpha/api",
                      "io": [
                          { "kind": "tcp", "upstream": "127.0.0.1:8000" },
                          { "kind": "socks5", "listen": "127.0.0.1:18000" }
                      ] }
                ],
                "links": [ { "type": "list", "members": [
                    { "name": "mongodb", "peer": "spiffe://demo.flor/service/mongodb", "via": { "type": "udp", "adapter": "wire", "addr": "5.6.7.8:4433" } }
                ] } ],
                "egress": [ { "target": "spiffe://demo.flor/service/mongodb", "allow": ["spiffe://demo.flor/service/alpha/api"] } ]
            }),
        );

        let bundle = ConfigBundle::load(root, "flor").unwrap();

        assert_eq!(bundle.endpoint_addr.0.to_string(), "127.0.0.1:4433");
        let mongodb = SpiffeId::new("spiffe://demo.flor/service/mongodb").unwrap();
        assert_eq!(
            bundle.addr_map.0.get(&mongodb).map(|a| a.to_string()),
            Some("5.6.7.8:4433".to_string())
        );
        assert_eq!(bundle.socks5_bindings.0.len(), 1);
        assert_eq!(bundle.socks5_bindings.0[0].1.to_string(), "127.0.0.1:18000");
        assert_eq!(bundle.tcp_direct_bindings.0.len(), 1);
        assert_eq!(
            bundle.tcp_direct_bindings.0[0].1.to_string(),
            "127.0.0.1:8000"
        );
        assert_eq!(bundle.trust_bundle.0.trust_domain(), &td());
    }

    #[test]
    fn defaults_to_ephemeral_endpoint_without_listen() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let ca = Ca::init(&td(), day()).unwrap();
        write_store(&ca, root);
        write_svid(
            &ca,
            root,
            "spiffe://demo.flor/user/alice",
            Kind::User,
            "alice",
        );
        write_artifact(
            root,
            json!({
                "schema_version": "1.0",
                "kind": "link",
                "transport_endpoint": { "type": "quic" },
                "connection_manager": { "adapters": [ { "name": "wire", "type": "udp" } ] },
                "workloads": [
                    { "spiffe_id": "spiffe://demo.flor/user/alice",
                      "io": [ { "kind": "socks5", "listen": "127.0.0.1:1080" } ] }
                ],
                "links": [ { "type": "list", "members": [
                    { "name": "api", "peer": "spiffe://demo.flor/service/api", "via": { "type": "udp", "adapter": "wire", "addr": "1.2.3.4:4433" } }
                ] } ]
            }),
        );

        let bundle = ConfigBundle::load(root, "flor").unwrap();
        assert_eq!(bundle.endpoint_addr.0.to_string(), "0.0.0.0:0");
        assert_eq!(bundle.socks5_bindings.0.len(), 1);
        assert!(bundle.tcp_direct_bindings.0.is_empty());
    }

    #[test]
    fn mesh_artifact_is_not_yet_runnable() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let ca = Ca::init(&td(), day()).unwrap();
        write_store(&ca, root);
        write_artifact(
            root,
            json!({
                "schema_version": "1.0",
                "kind": "mesh",
                "transport_endpoint": { "type": "quic" },
                "connection_manager": { "adapters": [] },
                "workloads": []
            }),
        );

        // `ConfigBundle` isn't `Debug`, so destructure rather than `unwrap_err`.
        let Err(err) = ConfigBundle::load(root, "flor") else {
            panic!("expected a mesh-not-implemented error");
        };
        assert!(
            format!("{err:?}").contains("Mesh vertex runtime"),
            "{err:?}"
        );
    }

    #[test]
    fn errors_on_missing_identity_file() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let ca = Ca::init(&td(), day()).unwrap();
        write_store(&ca, root);
        // api.crt/.key intentionally not written.
        write_artifact(
            root,
            json!({
                "schema_version": "1.0",
                "kind": "link",
                "transport_endpoint": { "type": "quic" },
                "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "127.0.0.1:4433" } ] },
                "workloads": [
                    { "spiffe_id": "spiffe://demo.flor/service/alpha/api",
                      "io": [ { "kind": "tcp", "upstream": "127.0.0.1:8000" } ] }
                ]
            }),
        );

        let Err(err) = ConfigBundle::load(root, "flor") else {
            panic!("expected a missing-file error");
        };
        assert!(format!("{err:?}").contains("cert"), "{err:?}");
    }

    #[test]
    fn errors_when_cert_does_not_match_declared_id() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let ca = Ca::init(&td(), day()).unwrap();
        write_store(&ca, root);
        // The file "api.crt" actually certifies a *different* identity.
        write_svid(
            &ca,
            root,
            "spiffe://demo.flor/service/alpha/other",
            Kind::Service,
            "api",
        );
        write_artifact(
            root,
            json!({
                "schema_version": "1.0",
                "kind": "link",
                "transport_endpoint": { "type": "quic" },
                "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "127.0.0.1:4433" } ] },
                "workloads": [
                    { "spiffe_id": "spiffe://demo.flor/service/alpha/api",
                      "io": [ { "kind": "tcp", "upstream": "127.0.0.1:8000" } ] }
                ]
            }),
        );

        let Err(err) = ConfigBundle::load(root, "flor") else {
            panic!("expected a cert/id mismatch error");
        };
        assert!(format!("{err:?}").contains("certifies"), "{err:?}");
    }

    #[test]
    fn resolve_endpoint_addr_guards_the_single_udp_invariant() {
        // The single-udp-adapter shape is enforced in validation, so these
        // cases never reach `resolve_endpoint_addr` through `load`. This covers
        // the defensive guard directly.
        let udp = |name: &str, listen: Option<&str>| Adapter::Udp {
            name: name.to_string(),
            listen: listen.map(|a| a.parse().unwrap()),
        };

        // Happy path: one udp adapter, listen honored / defaulted.
        assert_eq!(
            resolve_endpoint_addr(&[udp("wire", Some("127.0.0.1:4433"))])
                .unwrap()
                .to_string(),
            "127.0.0.1:4433"
        );
        assert_eq!(
            resolve_endpoint_addr(&[udp("wire", None)])
                .unwrap()
                .to_string(),
            "0.0.0.0:0"
        );

        // Defensive arm: anything but a single udp adapter is an invariant
        // violation (validation should have rejected it first).
        for adapters in [
            vec![],
            vec![udp("wire", None), udp("wire2", None)],
            vec![Adapter::Florio {
                name: "io".to_string(),
                socket: "/run/flor.sock".into(),
            }],
        ] {
            let Err(err) = resolve_endpoint_addr(&adapters) else {
                panic!("expected a single-udp-adapter error for {adapters:?}");
            };
            assert!(format!("{err:?}").contains("exactly one udp"), "{err:?}");
        }
    }

    #[test]
    fn loads_a_link_vertex_without_workloads() {
        // The trust domain comes from the store, not from the payload's SPIFFE
        // IDs, so a workload-less link vertex is simply one with no bindings.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let ca = Ca::init(&td(), day()).unwrap();
        write_store(&ca, root);
        write_artifact(
            root,
            json!({
                "schema_version": "1.0",
                "kind": "link",
                "transport_endpoint": { "type": "quic" },
                "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "127.0.0.1:4433" } ] },
                "workloads": []
            }),
        );

        let bundle = ConfigBundle::load(root, "flor").unwrap();
        assert_eq!(bundle.trust_bundle.0.trust_domain(), &td());
        assert!(bundle.socks5_bindings.0.is_empty());
        assert!(bundle.tcp_direct_bindings.0.is_empty());
    }

    #[test]
    fn errors_on_missing_vertex_config() {
        // No `mgmt/flor.json` under the root.
        let dir = tempdir().unwrap();
        let Err(err) = ConfigBundle::load(dir.path(), "flor") else {
            panic!("expected a missing-config error");
        };
        assert!(
            format!("{err:?}").contains("Failed to read vertex config"),
            "{err:?}"
        );
    }

    #[test]
    fn errors_on_missing_trust_domain_record() {
        // A valid artifact is not enough: without `rete.json` nothing says which
        // rete this scope belongs to, and the artifact must not be asked.
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_artifact(root, one_workload_link());

        let Err(err) = ConfigBundle::load(root, "flor") else {
            panic!("expected a missing-record error");
        };
        assert!(
            format!("{err:?}").contains("trust-domain record"),
            "{err:?}"
        );
    }

    #[test]
    fn errors_on_missing_ca_cert() {
        // The store knows its trust domain but holds no CA to anchor it.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let ca = Ca::init(&td(), day()).unwrap();
        write_store(&ca, root);
        std::fs::remove_file(root.join("ca.crt")).unwrap();
        write_artifact(root, one_workload_link());

        let Err(err) = ConfigBundle::load(root, "flor") else {
            panic!("expected a missing-CA error");
        };
        assert!(format!("{err:?}").contains("rete CA"), "{err:?}");
    }

    #[test]
    fn errors_on_missing_key_file() {
        // The workload cert is present but its private key is missing.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let ca = Ca::init(&td(), day()).unwrap();
        write_store(&ca, root);
        write_svid(
            &ca,
            root,
            "spiffe://demo.flor/service/alpha/api",
            Kind::Service,
            "api",
        );
        std::fs::remove_file(root.join("certs/api.key")).unwrap();
        write_artifact(root, one_workload_link());

        let Err(err) = ConfigBundle::load(root, "flor") else {
            panic!("expected a missing-key error");
        };
        assert!(
            format!("{err:?}").contains("Failed to read the key"),
            "{err:?}"
        );
    }

    #[test]
    fn errors_on_unparsable_workload_svid() {
        // Cert and key files exist but are not valid PEM material.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let ca = Ca::init(&td(), day()).unwrap();
        write_store(&ca, root);
        let certs = root.join("certs");
        std::fs::create_dir_all(&certs).unwrap();
        std::fs::write(certs.join("api.crt"), b"not a pem cert").unwrap();
        std::fs::write(certs.join("api.key"), b"not a pem key").unwrap();
        write_artifact(root, one_workload_link());

        let Err(err) = ConfigBundle::load(root, "flor") else {
            panic!("expected an SVID-load error");
        };
        assert!(format!("{err:?}").contains("SVID"), "{err:?}");
    }

    #[test]
    fn errors_when_a_workload_is_absent_from_the_store() {
        // The artifact names a principal the node holds no material for.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let ca = Ca::init(&td(), day()).unwrap();
        write_store(&ca, root);
        write_artifact(root, one_workload_link());

        let Err(err) = ConfigBundle::load(root, "flor") else {
            panic!("expected an unresolved-identity error");
        };
        let msg = format!("{err:?}");
        assert!(
            msg.contains("spiffe://demo.flor/service/alpha/api"),
            "{msg}"
        );
    }

    #[test]
    fn load_rejects_invalid_artifact() {
        // `load` must run validation, not just parse: a workload with no io
        // channels parses fine but is semantically invalid.
        let dir = tempdir().unwrap();
        let root = dir.path();
        write_artifact(
            root,
            json!({
                "schema_version": "1.0",
                "kind": "link",
                "transport_endpoint": { "type": "quic" },
                "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "127.0.0.1:4433" } ] },
                "workloads": [
                    { "spiffe_id": "spiffe://demo.flor/service/alpha/api",
                      "io": [] }
                ]
            }),
        );

        let Err(err) = ConfigBundle::load(root, "flor") else {
            panic!("expected a validation error");
        };
        assert!(format!("{err:?}").contains("io channels"), "{err:?}");
    }

    #[test]
    fn load_reports_upgrade_for_newer_minor_with_unknown_envelope_field() {
        // A 1.1 producer added an envelope claim our strict schema rejects. The
        // load must report an actionable upgrade error, not a serde unknown-field.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let mut env = envelope_1_0(one_workload_link());
        env["schema_version"] = json!("1.1");
        env["future_claim"] = json!(true);
        write_envelope(root, env);

        let Err(err) = ConfigBundle::load(root, "flor") else {
            panic!("expected an unsupported-schema error");
        };
        let msg = format!("{err:?}");
        assert!(msg.contains("unsupported schema"), "{msg}");
        assert!(msg.contains("upgrade"), "{msg}");
        assert!(!msg.contains("unknown field"), "leaked serde error: {msg}");
    }

    #[test]
    fn load_reports_upgrade_for_newer_minor_with_unknown_payload_field() {
        // Same, but the newer field is inside the payload (its own
        // `deny_unknown_fields`) — the diagnosis must still be version skew.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let mut payload = one_workload_link();
        payload["future_payload_field"] = json!(true);
        let mut env = envelope_1_0(payload);
        env["schema_version"] = json!("1.1");
        write_envelope(root, env);

        let Err(err) = ConfigBundle::load(root, "flor") else {
            panic!("expected an unsupported-schema error");
        };
        let msg = format!("{err:?}");
        assert!(msg.contains("upgrade"), "{msg}");
        assert!(!msg.contains("unknown field"), "leaked serde error: {msg}");
    }

    #[test]
    fn load_reports_upgrade_for_newer_payload_minor_alone() {
        // The payload family versions independently, so a *current* envelope
        // does not vouch for the payload. Nothing here fails the strict parse —
        // only the payload gate stands between us and applying an artifact whose
        // rules we do not implement.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let mut payload = one_workload_link();
        payload["schema_version"] = json!("1.1");
        write_envelope(root, envelope_1_0(payload));

        let Err(err) = ConfigBundle::load(root, "flor") else {
            panic!("expected an unsupported-schema error");
        };
        let msg = format!("{err:?}");
        assert!(msg.contains("vertex payload"), "{msg}");
        assert!(msg.contains("upgrade"), "{msg}");
    }

    #[test]
    fn load_reports_upgrade_for_newer_payload_minor_with_unknown_payload_field() {
        // Same skew, but the 1.1 payload also carries the field that minor added,
        // so the strict parse fails first and the diagnosis falls to the probe.
        // The envelope is current, so only the payload ladder can explain it.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let mut payload = one_workload_link();
        payload["schema_version"] = json!("1.1");
        payload["future_payload_field"] = json!(true);
        write_envelope(root, envelope_1_0(payload));

        let Err(err) = ConfigBundle::load(root, "flor") else {
            panic!("expected an unsupported-schema error");
        };
        let msg = format!("{err:?}");
        assert!(msg.contains("vertex payload"), "{msg}");
        assert!(msg.contains("upgrade"), "{msg}");
        assert!(!msg.contains("unknown field"), "leaked serde error: {msg}");
    }

    #[test]
    fn load_preserves_parse_error_for_unknown_field_at_supported_version() {
        // Unknown claim at the *supported* version 1.0 → a mis-stamped or corrupt
        // artifact, not version skew: the strict parse error must be preserved,
        // not masked as an upgrade prompt.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let mut env = envelope_1_0(one_workload_link());
        env["surprise"] = json!(true);
        write_envelope(root, env);

        let Err(err) = ConfigBundle::load(root, "flor") else {
            panic!("expected a parse error");
        };
        let msg = format!("{err:?}");
        assert!(msg.contains("Failed to parse"), "{msg}");
        assert!(
            !msg.contains("upgrade"),
            "misreported as version skew: {msg}"
        );
    }
}
