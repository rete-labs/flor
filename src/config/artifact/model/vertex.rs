// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Vertex artifact payload types — the typed configs a vertex consumes.
//!
//! [`VertexMgmtPayload`] (the mgmt config: connection manager, workloads,
//! links, ingress/egress) is defined here; the ctrl payload joins it later.
//! One mgmt struct serves both vertex engines — per ADR-0010 the mgmt payload
//! is field-identical for `link` and `mesh`, so [`VertexKind`] is a plain
//! discriminator field, not a tagged union. Variant-bearing pieces are
//! internally tagged: adapters and link rules on `type`, io channels on
//! `kind`. An io channel's direction is intrinsic to its `kind` (no
//! `direction` field) — see [`IoChannel::direction`].

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::core::identity::SpiffeId;

use super::super::version::{self, Contract};
use super::envelope::{ArtifactKind, Payload, PlaneTag};

/// Which forwarding engine a vertex runs. A plain discriminator: the mgmt
/// payload is field-identical across both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VertexKind {
    Link,
    Mesh,
}

/// A vertex's compiled mgmt configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VertexMgmtPayload {
    /// `major.minor` of the vertex payload-family contract this content uses —
    /// the family's own ladder, independent of the envelope's. Declared first so
    /// it serializes first, as the C0 artifact examples show it.
    pub schema_version: String,
    /// Which engine this vertex runs.
    pub kind: VertexKind,
    /// Scope-relative path to the rete CA certificate.
    pub ca_cert_path: PathBuf,
    /// The local transport the vertex terminates.
    pub transport_endpoint: TransportEndpoint,
    /// Local transport mechanisms a link can dial over.
    pub connection_manager: ConnectionManager,
    /// The communicating principals (mTLS workloads) wired into this vertex.
    pub workloads: Vec<Workload>,
    /// The in-layer adjacency table (peers and how to dial them).
    #[serde(default)]
    pub links: Vec<LinkRule>,
    /// Per-target allow-lists for inbound (peer-to-local) sessions.
    #[serde(default)]
    pub ingress: Vec<Acl>,
    /// Per-target allow-lists for outbound (local-to-peer) sessions.
    #[serde(default)]
    pub egress: Vec<Acl>,
}

impl Payload for VertexMgmtPayload {
    const PLANE: PlaneTag = PlaneTag::Mgmt;
    const KIND: ArtifactKind = ArtifactKind::Vertex;
    const FAMILY: Contract = version::VERTEX;

    fn schema_version(&self) -> &str {
        &self.schema_version
    }
}

/// The local transport a vertex terminates. Internally tagged on `type`;
/// unknown types fail closed.
///
/// Kept tagged (`{ "type": "quic" }`, not a bare `"quic"` string) so a transport
/// can grow config — e.g. `{ "type": "quic", "idle_timeout": … }` — without a
/// wire-format change, and so every variant-bearing node stays uniformly tagged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransportEndpoint {
    Quic,
}

/// The connection manager's table of local transport mechanisms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionManager {
    pub adapters: Vec<Adapter>,
}

/// A local transport mechanism a link references by `name`. Internally tagged
/// on `type`; unknown types fail closed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Adapter {
    /// A UDP socket that terminates the wire; carries an optional bind address
    /// (absent for initiator-only nodes).
    Udp {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        listen: Option<SocketAddr>,
    },
    /// A FlorIO socket that delegates dialing to a layer below.
    Florio { name: String, socket: PathBuf },
}

impl Adapter {
    /// The adapter's local name (the handle a link's `via` references).
    pub fn name(&self) -> &str {
        match self {
            Adapter::Udp { name, .. } | Adapter::Florio { name, .. } => name,
        }
    }
}

/// A communicating principal wired into the vertex, keyed by its SPIFFE ID —
/// an initiator (inbound io), a target (outbound io), or both.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    #[serde(with = "super::sid")]
    pub spiffe_id: SpiffeId,
    pub identity: Identity,
    pub io: Vec<IoChannel>,
}

/// A workload's on-disk identity material (scope-relative paths).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub cert_path: PathBuf,
    pub priv_path: PathBuf,
}

/// How a workload is wired into flor locally. Internally tagged on `kind`;
/// direction is intrinsic to the kind (no `direction` field), and unknown
/// fields fail closed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IoChannel {
    /// Inbound: flor accepts SOCKS5 here and originates on the workload's behalf.
    Socks5 { listen: SocketAddr },
    /// Outbound: flor delivers inbound connections to this upstream.
    Tcp { upstream: SocketAddr },
    /// Bidirectional: a recursive flor layer.
    Florio { socket: PathBuf },
}

impl IoChannel {
    /// The channel's direction, derived from its kind.
    pub fn direction(&self) -> Direction {
        match self {
            IoChannel::Socks5 { .. } => Direction::Inbound,
            IoChannel::Tcp { .. } => Direction::Outbound,
            IoChannel::Florio { .. } => Direction::Bidirectional,
        }
    }
}

/// How a workload connects to flor — derived from an [`IoChannel`]'s kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
    Bidirectional,
}

/// A `links` rule. Internally tagged on `type`; unknown types fail closed
/// (no `#[serde(other)]`), so an unrecognised rule is an error, not a silent skip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum LinkRule {
    /// An explicit list of links — the members are enumerated directly (as
    /// opposed to a future pattern/rule-matched set).
    List { members: Vec<LinkMember> },
}

/// A single link: a named handle to a peer over one adapter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkMember {
    /// The local forwarding handle (peers may appear under several names).
    pub name: String,
    /// The remote peer's identity (for link-layer mTLS).
    #[serde(with = "super::sid")]
    pub peer: SpiffeId,
    /// The adapter and adapter-specific dial info.
    pub via: Via,
}

/// A link's conduit: which adapter to dial over, plus adapter-type-specific
/// dial info. Internally tagged on `type`; the tag must match the referenced
/// adapter's type (cross-checked at validation). A new adapter family adds a
/// variant here, so dial shapes stay typed rather than a bag of optionals.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Via {
    /// Dial the peer at `addr` over the named UDP adapter (which terminates the wire).
    Udp { adapter: String, addr: SocketAddr },
    /// Delegate dialing to the named FlorIO adapter (no wire address — it hands
    /// off to the layer below).
    Florio { adapter: String },
}

impl Via {
    /// The [`Adapter`] name this link dials over.
    pub fn adapter(&self) -> &str {
        match self {
            Via::Udp { adapter, .. } | Via::Florio { adapter, .. } => adapter,
        }
    }
}

/// A flat allow-list: which principal identities may reach a given target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acl {
    #[serde(with = "super::sid")]
    pub target: SpiffeId,
    #[serde(with = "super::sid::vec")]
    pub allow: Vec<SpiffeId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    /// The exact C0 user-node link payload from validate-and-compile.mdx.
    fn user_node() -> Value {
        json!({
            "schema_version": "1.0",
            "kind": "link",
            "ca_cert_path": "ca.crt",
            "transport_endpoint": { "type": "quic" },
            "connection_manager": { "adapters": [ { "name": "wire", "type": "udp" } ] },
            "workloads": [
                {
                    "spiffe_id": "spiffe://rete-lovers/node/alice-laptop",
                    "identity": { "cert_path": "alice-laptop.crt", "priv_path": "alice-laptop.key" },
                    "io": [ { "kind": "socks5", "listen": "127.0.0.1:1081" } ]
                },
                {
                    "spiffe_id": "spiffe://rete-lovers/user/alice",
                    "identity": { "cert_path": "alice.crt", "priv_path": "alice.key" },
                    "io": [ { "kind": "socks5", "listen": "127.0.0.1:1080" } ]
                }
            ],
            "links": [
                { "type": "list", "members": [
                    { "name": "coordinator", "peer": "spiffe://rete-lovers/service/coordinator", "via": { "type": "udp", "adapter": "wire", "addr": "9.10.11.12:4433" } },
                    { "name": "api",           "peer": "spiffe://rete-lovers/service/api",           "via": { "type": "udp", "adapter": "wire", "addr": "1.2.3.4:4433" } },
                    { "name": "kafka",         "peer": "spiffe://rete-lovers/service/kafka",         "via": { "type": "udp", "adapter": "wire", "addr": "5.6.7.8:4433" } }
                ] }
            ],
            "egress": [
                { "target": "spiffe://rete-lovers/service/coordinator", "allow": ["spiffe://rete-lovers/node/alice-laptop"] },
                { "target": "spiffe://rete-lovers/service/api",           "allow": ["spiffe://rete-lovers/user/alice"] },
                { "target": "spiffe://rete-lovers/service/kafka",         "allow": ["spiffe://rete-lovers/user/alice"] }
            ]
        })
    }

    /// The exact C0 server-node link payload from validate-and-compile.mdx.
    fn server_node() -> Value {
        json!({
            "schema_version": "1.0",
            "kind": "link",
            "ca_cert_path": "ca.crt",
            "transport_endpoint": { "type": "quic" },
            "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "0.0.0.0:4433" } ] },
            "workloads": [
                {
                    "spiffe_id": "spiffe://rete-lovers/node/alpha",
                    "identity": { "cert_path": "alpha.crt", "priv_path": "alpha.key" },
                    "io": [ { "kind": "socks5", "listen": "127.0.0.1:1080" } ]
                },
                {
                    "spiffe_id": "spiffe://rete-lovers/service/api",
                    "identity": { "cert_path": "api.crt", "priv_path": "api.key" },
                    "io": [
                        { "kind": "tcp",    "upstream": "127.0.0.1:8000" },
                        { "kind": "socks5", "listen":   "127.0.0.1:18000" }
                    ]
                },
                {
                    "spiffe_id": "spiffe://rete-lovers/service/alpha/ssh",
                    "identity": { "cert_path": "ssh.crt", "priv_path": "ssh.key" },
                    "io": [ { "kind": "tcp", "upstream": "0.0.0.0:22" } ]
                }
            ],
            "ingress": [
                { "target": "spiffe://rete-lovers/service/api",       "allow": ["spiffe://rete-lovers/user/alice", "spiffe://rete-lovers/user/bob"] },
                { "target": "spiffe://rete-lovers/service/alpha/ssh", "allow": ["spiffe://rete-lovers/user/bob"] }
            ],
            "links": [
                { "type": "list", "members": [
                    { "name": "coordinator", "peer": "spiffe://rete-lovers/service/coordinator", "via": { "type": "udp", "adapter": "wire", "addr": "9.10.11.12:4433" } },
                    { "name": "mongodb",       "peer": "spiffe://rete-lovers/service/mongodb",       "via": { "type": "udp", "adapter": "wire", "addr": "5.6.7.8:4433" } }
                ] }
            ],
            "egress": [
                { "target": "spiffe://rete-lovers/service/coordinator", "allow": ["spiffe://rete-lovers/node/alpha"] },
                { "target": "spiffe://rete-lovers/service/mongodb",       "allow": ["spiffe://rete-lovers/service/api"] }
            ]
        })
    }

    #[test]
    fn parses_user_node_payload() {
        let p: VertexMgmtPayload = serde_json::from_value(user_node()).unwrap();
        assert_eq!(p.kind, VertexKind::Link);
        assert_eq!(p.ca_cert_path, PathBuf::from("ca.crt"));
        assert_eq!(p.transport_endpoint, TransportEndpoint::Quic);

        // Single UDP adapter, no listen (initiator-only).
        assert_eq!(p.connection_manager.adapters.len(), 1);
        match &p.connection_manager.adapters[0] {
            Adapter::Udp { name, listen } => {
                assert_eq!(name, "wire");
                assert!(listen.is_none());
            }
            other => panic!("expected udp adapter, got {other:?}"),
        }

        // Two workloads, each a SOCKS5 (inbound) principal.
        assert_eq!(p.workloads.len(), 2);
        let w0 = &p.workloads[0];
        assert_eq!(
            w0.spiffe_id.to_string(),
            "spiffe://rete-lovers/node/alice-laptop"
        );
        assert_eq!(w0.identity.cert_path, PathBuf::from("alice-laptop.crt"));
        assert_eq!(w0.io.len(), 1);
        assert_eq!(w0.io[0].direction(), Direction::Inbound);
        match &w0.io[0] {
            IoChannel::Socks5 { listen } => assert_eq!(listen.to_string(), "127.0.0.1:1081"),
            other => panic!("expected socks5, got {other:?}"),
        }

        // One enum link rule with three members.
        assert_eq!(p.links.len(), 1);
        let LinkRule::List { members } = &p.links[0];
        assert_eq!(members.len(), 3);
        assert_eq!(members[0].name, "coordinator");
        assert_eq!(
            members[0].peer.to_string(),
            "spiffe://rete-lovers/service/coordinator"
        );
        match &members[0].via {
            Via::Udp { adapter, addr } => {
                assert_eq!(adapter, "wire");
                assert_eq!(addr.to_string(), "9.10.11.12:4433");
            }
            other => panic!("expected udp via, got {other:?}"),
        }

        // egress present, ingress absent -> default empty.
        assert_eq!(p.egress.len(), 3);
        assert!(p.ingress.is_empty());
        assert_eq!(
            p.egress[1].target.to_string(),
            "spiffe://rete-lovers/service/api"
        );
        assert_eq!(p.egress[1].allow.len(), 1);
        assert_eq!(
            p.egress[1].allow[0].to_string(),
            "spiffe://rete-lovers/user/alice"
        );
    }

    #[test]
    fn parses_server_node_payload() {
        let p: VertexMgmtPayload = serde_json::from_value(server_node()).unwrap();
        assert_eq!(p.kind, VertexKind::Link);

        // Adapter binds a listen address (server accepts inbound QUIC).
        match &p.connection_manager.adapters[0] {
            Adapter::Udp { listen, .. } => {
                assert_eq!(
                    listen.map(|a| a.to_string()),
                    Some("0.0.0.0:4433".to_string())
                )
            }
            other => panic!("expected udp adapter, got {other:?}"),
        }

        // The api workload is both a target (tcp) and a principal (socks5).
        assert_eq!(p.workloads.len(), 3);
        let api = &p.workloads[1];
        assert_eq!(
            api.spiffe_id.to_string(),
            "spiffe://rete-lovers/service/api"
        );
        assert_eq!(api.io.len(), 2);
        assert_eq!(api.io[0].direction(), Direction::Outbound);
        match &api.io[0] {
            IoChannel::Tcp { upstream } => assert_eq!(upstream.to_string(), "127.0.0.1:8000"),
            other => panic!("expected tcp, got {other:?}"),
        }
        assert_eq!(api.io[1].direction(), Direction::Inbound);

        assert_eq!(p.ingress.len(), 2);
        assert_eq!(p.ingress[0].allow.len(), 2);
        assert_eq!(p.egress.len(), 2);
    }

    #[test]
    fn round_trips_through_json() {
        let p: VertexMgmtPayload = serde_json::from_value(server_node()).unwrap();
        let back: VertexMgmtPayload =
            serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn parses_mesh_payload() {
        // Same struct, `kind: mesh`.
        let v = json!({
            "schema_version": "1.0",
            "kind": "mesh",
            "ca_cert_path": "ca.crt",
            "transport_endpoint": { "type": "quic" },
            "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "0.0.0.0:4433" } ] },
            "workloads": [],
            "links": [
                { "type": "list", "members": [
                    { "name": "beta", "peer": "spiffe://rete-lovers/vertex/beta/rete", "via": { "type": "udp", "adapter": "wire", "addr": "10.0.0.7:5544" } }
                ] }
            ]
        });
        let p: VertexMgmtPayload = serde_json::from_value(v).unwrap();
        assert_eq!(p.kind, VertexKind::Mesh);
        assert!(p.workloads.is_empty());
        assert!(p.ingress.is_empty() && p.egress.is_empty());
    }

    #[test]
    fn florio_adapter_and_io_parse() {
        // Exercise the FlorIO variants (socket-bearing, bidirectional).
        let v = json!({
            "schema_version": "1.0",
            "kind": "mesh",
            "ca_cert_path": "ca.crt",
            "transport_endpoint": { "type": "quic" },
            "connection_manager": { "adapters": [ { "name": "io", "type": "florio", "socket": "/run/flor.sock" } ] },
            "workloads": [
                { "spiffe_id": "spiffe://rete-lovers/vertex/alpha/rete",
                  "identity": { "cert_path": "rete.crt", "priv_path": "rete.key" },
                  "io": [ { "kind": "florio", "socket": "/run/wl.sock" } ] }
            ],
            "links": [
                { "type": "list", "members": [
                    { "name": "beta", "peer": "spiffe://rete-lovers/vertex/beta/rete", "via": { "type": "florio", "adapter": "io" } }
                ] }
            ]
        });
        let p: VertexMgmtPayload = serde_json::from_value(v).unwrap();
        match &p.connection_manager.adapters[0] {
            Adapter::Florio { name, socket } => {
                assert_eq!(name, "io");
                assert_eq!(socket, &PathBuf::from("/run/flor.sock"));
            }
            other => panic!("expected florio adapter, got {other:?}"),
        }
        assert_eq!(p.workloads[0].io[0].direction(), Direction::Bidirectional);
        // FlorIO link carries no wire address.
        let LinkRule::List { members } = &p.links[0];
        assert_eq!(
            members[0].via,
            Via::Florio {
                adapter: "io".to_string()
            }
        );
        assert_eq!(members[0].via.adapter(), "io");
    }

    #[test]
    fn rejects_unknown_link_rule_type() {
        let mut v = user_node();
        v["links"][0]["type"] = json!("regex");
        let err = serde_json::from_value::<VertexMgmtPayload>(v).unwrap_err();
        assert!(err.is_data(), "{err}");
    }

    #[test]
    fn rejects_missing_required_field() {
        let mut v = user_node();
        v.as_object_mut().unwrap().remove("ca_cert_path");
        let err = serde_json::from_value::<VertexMgmtPayload>(v).unwrap_err();
        assert!(err.to_string().contains("ca_cert_path"), "{err}");
    }

    #[test]
    fn rejects_malformed_spiffe_id() {
        let mut v = user_node();
        v["links"][0]["members"][0]["peer"] = json!("not-a-spiffe-id");
        let err = serde_json::from_value::<VertexMgmtPayload>(v).unwrap_err();
        assert!(err.is_data(), "{err}");
    }

    #[test]
    fn rejects_udp_via_without_addr() {
        // A UDP link must carry its dial address — typed, not an optional.
        let mut v = user_node();
        v["links"][0]["members"][0]["via"] = json!({ "type": "udp", "adapter": "wire" });
        let err = serde_json::from_value::<VertexMgmtPayload>(v).unwrap_err();
        assert!(err.to_string().contains("addr"), "{err}");
    }

    #[test]
    fn rejects_via_unknown_type() {
        let mut v = user_node();
        v["links"][0]["members"][0]["via"] = json!({ "type": "wireguard", "adapter": "wg" });
        let err = serde_json::from_value::<VertexMgmtPayload>(v).unwrap_err();
        assert!(err.is_data(), "{err}");
    }

    #[test]
    fn rejects_io_channel_with_stray_direction() {
        // `direction` is intrinsic to `kind`; a stray field must fail closed.
        let mut v = user_node();
        v["workloads"][0]["io"][0]["direction"] = json!("inbound");
        let err = serde_json::from_value::<VertexMgmtPayload>(v).unwrap_err();
        assert!(err.is_data(), "{err}");
    }

    #[test]
    fn rejects_unknown_payload_field() {
        let mut v = user_node();
        v["surprise"] = json!(true);
        let err = serde_json::from_value::<VertexMgmtPayload>(v).unwrap_err();
        assert!(err.is_data(), "{err}");
    }
}
