// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Florete identity primitives.
//!
//! SPIFFE-native: `SpiffeId` and `TrustDomain` are re-exported directly from the
//! `spiffe` crate. We add a [`Kind`]/[`Scope`] projection over the SPIFFE path so
//! the rest of the code base can reason about principal classes without parsing
//! strings ad hoc.
//!
//! See ADR-0005 in the florete docs for the design rationale.

pub mod ca;
pub mod csr;
pub mod kind;

pub use ca::Ca;
pub use csr::keygen_csr;
pub use kind::{Kind, Scope, kind_of, scope_of};
pub use spiffe::{SpiffeId, TrustDomain};

use error_stack::{Report, ResultExt, bail};

/// Build the SPIFFE ID for a principal of the given kind, name, and optional
/// node scope. Errors if `scope_node` is set for a kind that's always
/// cluster-scoped (see [`Kind::supports_node_scope`]).
pub fn build_id(
    trust_domain: &TrustDomain,
    kind: Kind,
    name: &str,
    scope_node: Option<&str>,
) -> Result<SpiffeId, Report<Error>> {
    if scope_node.is_some() && !kind.supports_node_scope() {
        bail!(Error::new(format!(
            "Kind {kind} is always cluster-scoped, cannot be bound to a node"
        )));
    }
    let segments: Vec<&str> = match scope_node {
        Some(node) => vec![kind.as_segment(), node, name],
        None => vec![kind.as_segment(), name],
    };
    SpiffeId::from_segments(trust_domain.clone(), &segments)
        .change_context(Error::new("Failed to construct SPIFFE ID"))
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

impl Error {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn td() -> TrustDomain {
        TrustDomain::new("demo.flor").unwrap()
    }

    #[test]
    fn build_id_cluster_scoped_kinds() {
        for (kind, expected) in [
            (Kind::User, "spiffe://demo.flor/user/alice"),
            (Kind::Node, "spiffe://demo.flor/node/alpha"),
            (
                Kind::ControlPlane,
                "spiffe://demo.flor/control-plane/primary",
            ),
            (
                Kind::ManagementPlane,
                "spiffe://demo.flor/management-plane/primary",
            ),
        ] {
            let name = expected.rsplit('/').next().unwrap();
            let id = build_id(&td(), kind, name, None).unwrap();
            assert_eq!(id.to_string(), expected, "{kind:?}");
        }
    }

    #[test]
    fn build_id_service_vertex_default_to_cluster_scope() {
        let id = build_id(&td(), Kind::Service, "db", None).unwrap();
        assert_eq!(id.to_string(), "spiffe://demo.flor/service/db");
        let id = build_id(&td(), Kind::Vertex, "flor", None).unwrap();
        assert_eq!(id.to_string(), "spiffe://demo.flor/vertex/flor");
    }

    #[test]
    fn build_id_service_vertex_with_node_scope() {
        let id = build_id(&td(), Kind::Service, "db", Some("alpha")).unwrap();
        assert_eq!(id.to_string(), "spiffe://demo.flor/service/alpha/db");
        let id = build_id(&td(), Kind::Vertex, "flor", Some("alpha")).unwrap();
        assert_eq!(id.to_string(), "spiffe://demo.flor/vertex/alpha/flor");
    }

    #[test]
    fn build_id_rejects_scope_for_cluster_only_kinds() {
        for kind in [
            Kind::User,
            Kind::Node,
            Kind::ControlPlane,
            Kind::ManagementPlane,
        ] {
            let err = build_id(&td(), kind, "x", Some("alpha")).unwrap_err();
            let msg = format!("{err:?}");
            assert!(msg.contains("always cluster-scoped"), "{kind:?}: {msg}");
            // Error must not name the exception kinds — the rule lives in
            // `Kind::supports_node_scope`, not in the message.
            assert!(!msg.contains("service"), "{kind:?}: {msg}");
            assert!(!msg.contains("vertex"), "{kind:?}: {msg}");
        }
    }

    #[test]
    fn build_id_rejects_invalid_name() {
        // SPIFFE path segments cannot contain `/`.
        let err = build_id(&td(), Kind::User, "a/b", None).unwrap_err();
        assert!(
            format!("{err:?}").contains("Failed to construct SPIFFE ID"),
            "{err:?}",
        );
    }

    #[test]
    fn build_id_round_trips_through_kind_of_and_scope_of() {
        let id = build_id(&td(), Kind::Service, "db", Some("alpha")).unwrap();
        assert_eq!(kind_of(&id).unwrap(), Kind::Service);
        assert_eq!(scope_of(&id).unwrap(), Scope::Node("alpha".into()));

        let id = build_id(&td(), Kind::User, "alice", None).unwrap();
        assert_eq!(kind_of(&id).unwrap(), Kind::User);
        assert_eq!(scope_of(&id).unwrap(), Scope::Cluster);
    }
}
