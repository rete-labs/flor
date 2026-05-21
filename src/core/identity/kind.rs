// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Principal [`Kind`] and [`Scope`] derived from a SPIFFE ID's path.
//!
//! SPIFFE paths in Florete follow `/<kind>[/<node>]/<name>`:
//!
//! - Cluster-scoped: `/user/alice`, `/service/db`, `/node/alpha`,
//!   `/control-plane/primary`, `/management-plane/primary`.
//! - Node-scoped (only for `service` and `vertex`): `/service/alpha/db`,
//!   `/vertex/alpha/flor`.
//!
//! All six kinds are recognised from day one (see ADR-0005). The CLI segments
//! are singular and match the Rust variant names: `Kind::ControlPlane` ↔
//! `control-plane` ↔ `--kind control-plane`.

use std::fmt;
use std::str::FromStr;

use error_stack::{Report, bail};

use crate::core::identity::{Error, SpiffeId};

/// The class of principal a SPIFFE ID names.
///
/// `Kind` is the *cert-shape* axis: it determines the X.509 extension policy
/// applied at signing and how the URI is parsed. It is intentionally
/// orthogonal to [`Scope`], which is the *deployment-placement* axis (where a
/// principal lives in the cluster). Most identity-layer code (cert issuance,
/// audit, ACL evaluation) dispatches on `Kind` and doesn't care about
/// scope; deployment-layer code is where placement matters.
/// Resist the urge to merge these axes — see ADR-0005.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, clap::ValueEnum)]
pub enum Kind {
    /// A human user.
    User,
    /// A service — one or more workloads that expose endpoints.
    /// Cluster-scoped services may be backed by multiple workloads (load
    /// balanced across hosts); node-scoped services are bound to one host.
    Service,
    /// A physical or virtual host enrolled into the cluster.
    Node,
    /// A vertex — a special kind of service that provides Florete IPC.
    Vertex,
    /// A control-plane signing identity. Not used for mTLS.
    ControlPlane,
    /// A management-plane signing identity. Not used for mTLS.
    ManagementPlane,
}

impl Kind {
    /// The canonical URI / CLI segment for this kind.
    pub const fn as_segment(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Service => "service",
            Self::Node => "node",
            Self::Vertex => "vertex",
            Self::ControlPlane => "control-plane",
            Self::ManagementPlane => "management-plane",
        }
    }

    /// If this kind can be bound to a specific node, return its
    /// [`NodeScopableKind`] form; otherwise `None`. Use this at the boundary
    /// (CLI, config parsing) to safely turn an unrestricted `Kind` into the
    /// subset accepted by [`build_id_on_node`](super::build_id_on_node).
    pub const fn into_node_scopable(self) -> Option<NodeScopableKind> {
        match self {
            Self::Service => Some(NodeScopableKind::Service),
            Self::Vertex => Some(NodeScopableKind::Vertex),
            Self::User | Self::Node | Self::ControlPlane | Self::ManagementPlane => None,
        }
    }
}

/// The subset of [`Kind`] that can be bound to a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeScopableKind {
    Service,
    Vertex,
}

impl From<NodeScopableKind> for Kind {
    fn from(k: NodeScopableKind) -> Self {
        match k {
            NodeScopableKind::Service => Self::Service,
            NodeScopableKind::Vertex => Self::Vertex,
        }
    }
}

impl NodeScopableKind {
    pub const fn as_segment(self) -> &'static str {
        match self {
            Self::Service => Kind::Service.as_segment(),
            Self::Vertex => Kind::Vertex.as_segment(),
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_segment())
    }
}

impl FromStr for Kind {
    type Err = Report<Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(Self::User),
            "service" => Ok(Self::Service),
            "node" => Ok(Self::Node),
            "vertex" => Ok(Self::Vertex),
            "control-plane" => Ok(Self::ControlPlane),
            "management-plane" => Ok(Self::ManagementPlane),
            other => Err(Report::new(Error::new(format!(
                "Unknown principal kind {other:?}"
            )))),
        }
    }
}

/// Where a principal lives in the cluster — the *deployment-placement* axis,
/// orthogonal to [`Kind`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Cluster-wide principal (not bound to a specific node).
    Cluster,
    /// Node-scoped principal; carries the node's name.
    Node(String),
}

/// Project a SPIFFE ID onto its principal [`Kind`].
///
/// Only inspects the first path segment; does not validate the rest of the
/// path's shape. Use [`scope_of`] when you also need the scope.
pub fn kind_of(id: &SpiffeId) -> Result<Kind, Report<Error>> {
    let first = path_segments(id)
        .next()
        .ok_or_else(|| Report::new(Error::new("SPIFFE ID has no path segments")))?;
    first.parse()
}

/// Project a SPIFFE ID onto its [`Scope`].
///
/// Rules:
/// - `User`, `Node`, `ControlPlane`, `ManagementPlane` → cluster-scoped only
///   (path `/<kind>/<name>`).
/// - `Service`, `Vertex` → cluster-scoped (`/<kind>/<name>`) **or** node-scoped
///   (`/<kind>/<node>/<name>`).
///
/// Any other shape is an error.
pub fn scope_of(id: &SpiffeId) -> Result<Scope, Report<Error>> {
    let kind = kind_of(id)?;
    let trailing: Vec<&str> = path_segments(id).skip(1).collect();
    let node_scopable = kind.into_node_scopable().is_some();
    match (trailing.as_slice(), node_scopable) {
        ([_name], _) => Ok(Scope::Cluster),
        ([node, _name], true) => Ok(Scope::Node((*node).to_string())),
        _ => {
            let expected = if node_scopable {
                "1 (cluster) or 2 (node-scoped) trailing segments"
            } else {
                "1 trailing segment"
            };
            bail!(Error::new(format!(
                "SPIFFE ID path {:?} has wrong shape for {kind}: \
                 expected {expected}, got {} trailing segment(s)",
                id.path(),
                trailing.len(),
            )))
        }
    }
}

fn path_segments(id: &SpiffeId) -> impl Iterator<Item = &str> {
    // `SpiffeId::path()` returns "" for empty paths and "/a/b/c" otherwise.
    // `split('/')` on "/a/b" yields ["", "a", "b"]; drop the empty prefix.
    id.path().split('/').filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> SpiffeId {
        SpiffeId::new(s).expect("valid SPIFFE ID")
    }

    #[test]
    fn kind_as_segment_round_trips_through_from_str() {
        for k in [
            Kind::User,
            Kind::Service,
            Kind::Node,
            Kind::Vertex,
            Kind::ControlPlane,
            Kind::ManagementPlane,
        ] {
            assert_eq!(k.as_segment().parse::<Kind>().unwrap(), k);
            assert_eq!(k.to_string(), k.as_segment());
        }
    }

    #[test]
    fn kind_from_str_rejects_unknown() {
        let err = "users".parse::<Kind>().unwrap_err();
        assert!(
            format!("{err:?}").contains("Unknown principal kind"),
            "{err:?}"
        );
        let err = "".parse::<Kind>().unwrap_err();
        assert!(
            format!("{err:?}").contains("Unknown principal kind"),
            "{err:?}"
        );
    }

    #[test]
    fn kind_of_reads_first_segment() {
        assert_eq!(
            kind_of(&id("spiffe://demo.flor/user/alice")).unwrap(),
            Kind::User
        );
        assert_eq!(
            kind_of(&id("spiffe://demo.flor/service/db")).unwrap(),
            Kind::Service
        );
        assert_eq!(
            kind_of(&id("spiffe://demo.flor/node/alpha")).unwrap(),
            Kind::Node
        );
        assert_eq!(
            kind_of(&id("spiffe://demo.flor/vertex/alpha/flor")).unwrap(),
            Kind::Vertex
        );
        assert_eq!(
            kind_of(&id("spiffe://demo.flor/control-plane/primary")).unwrap(),
            Kind::ControlPlane,
        );
        assert_eq!(
            kind_of(&id("spiffe://demo.flor/management-plane/primary")).unwrap(),
            Kind::ManagementPlane,
        );
    }

    #[test]
    fn kind_of_rejects_empty_path() {
        let err = kind_of(&id("spiffe://demo.flor")).unwrap_err();
        assert!(
            format!("{err:?}").contains("has no path segments"),
            "{err:?}"
        );
    }

    #[test]
    fn kind_of_rejects_unknown_first_segment() {
        let err = kind_of(&id("spiffe://demo.flor/robot/r2d2")).unwrap_err();
        assert!(
            format!("{err:?}").contains("Unknown principal kind"),
            "{err:?}"
        );
        assert!(format!("{err:?}").contains("robot"), "{err:?}");
    }

    #[test]
    fn scope_of_cluster_kinds() {
        for path in [
            "spiffe://demo.flor/user/alice",
            "spiffe://demo.flor/node/alpha",
            "spiffe://demo.flor/control-plane/primary",
            "spiffe://demo.flor/management-plane/primary",
            "spiffe://demo.flor/service/db",
        ] {
            assert_eq!(scope_of(&id(path)).unwrap(), Scope::Cluster, "{path}");
        }
    }

    #[test]
    fn scope_of_node_scoped_service_and_vertex() {
        assert_eq!(
            scope_of(&id("spiffe://demo.flor/service/alpha/db")).unwrap(),
            Scope::Node("alpha".to_string()),
        );
        assert_eq!(
            scope_of(&id("spiffe://demo.flor/vertex/alpha/flor")).unwrap(),
            Scope::Node("alpha".to_string()),
        );
    }

    #[test]
    fn scope_of_rejects_extra_segments_for_cluster_kinds() {
        let err = scope_of(&id("spiffe://demo.flor/user/alice/extra")).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("wrong shape for user"), "{msg}");
        assert!(msg.contains("got 2 trailing"), "{msg}");
    }

    #[test]
    fn scope_of_rejects_too_many_segments_for_service() {
        let err = scope_of(&id("spiffe://demo.flor/service/a/b/c")).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("wrong shape for service"), "{msg}");
        assert!(msg.contains("got 3 trailing"), "{msg}");
    }

    #[test]
    fn scope_of_rejects_missing_name() {
        // `/user` alone has no name segment.
        let err = scope_of(&id("spiffe://demo.flor/user")).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("wrong shape for user"), "{msg}");
        assert!(msg.contains("got 0 trailing"), "{msg}");
    }

    #[test]
    fn scope_of_propagates_kind_error() {
        let err = scope_of(&id("spiffe://demo.flor/robot/r2d2")).unwrap_err();
        assert!(
            format!("{err:?}").contains("Unknown principal kind"),
            "{err:?}",
        );
    }
}
