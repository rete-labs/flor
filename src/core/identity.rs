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
pub mod dialable;
pub mod kind;

pub use ca::Ca;
pub use csr::keygen_csr;
pub use dialable::Dialable;
pub use kind::{Kind, NodeScopableKind, Scope, kind_of, scope_of};
pub use spiffe::{SpiffeId, TrustDomain};

use error_stack::{Report, ResultExt};

/// Build a rete-scoped SPIFFE ID: `spiffe://<td>/<kind>/<name>`.
///
/// Accepts any [`Kind`]. **Total** in the kind+scope dimension — the only
/// failure mode is name/trust-domain validation by `spiffe`.
pub fn build_id_in_rete(
    trust_domain: &TrustDomain,
    kind: Kind,
    name: &str,
) -> Result<SpiffeId, Report<Error>> {
    SpiffeId::from_segments(trust_domain.clone(), &[kind.as_segment(), name])
        .change_context(Error::new("Failed to construct SPIFFE ID"))
}

/// Build a node-scoped SPIFFE ID: `spiffe://<td>/<kind>/<node>/<name>`.
///
/// Only [`NodeScopableKind`] (service or vertex) can be passed — kinds that
/// are always rete-scoped don't type-check at this call. **Total** in the
/// kind+scope dimension.
pub fn build_id_on_node(
    trust_domain: &TrustDomain,
    kind: NodeScopableKind,
    node: &str,
    name: &str,
) -> Result<SpiffeId, Report<Error>> {
    SpiffeId::from_segments(trust_domain.clone(), &[kind.as_segment(), node, name])
        .change_context(Error::new("Failed to construct SPIFFE ID"))
}

/// Build a SPIFFE ID from a `(kind, optional node scope)` pair.
///
/// Convenience wrapper for boundary code (CLIs, YAML parsers, RPC handlers)
/// that received an untyped optional scope and needs the lib to pick the right
/// construction. If `scope` is `Some` but `kind` isn't node-scopable, returns
/// a user-facing error.
///
/// Callers that already know whether they want rete or node shape should
/// prefer the typed primitives [`build_id_in_rete`] / [`build_id_on_node`].
pub fn build_id(
    trust_domain: &TrustDomain,
    kind: Kind,
    name: &str,
    scope: Option<&str>,
) -> Result<SpiffeId, Report<Error>> {
    match scope {
        None => build_id_in_rete(trust_domain, kind, name),
        Some(node) => {
            let nsk = kind.into_node_scopable().ok_or_else(|| {
                Report::new(Error::new(format!(
                    "Kind {kind} is always rete-scoped, cannot be bound to a node"
                )))
            })?;
            build_id_on_node(trust_domain, nsk, node, name)
        }
    }
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
    fn build_id_rete_scoped_kinds() {
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
            let id = build_id_in_rete(&td(), kind, name).unwrap();
            assert_eq!(id.to_string(), expected, "{kind:?}");
        }
    }

    #[test]
    fn build_id_in_rete_accepts_service_and_vertex() {
        // The rete-shape constructor accepts any Kind, including
        // node-scopable ones, when the caller wants the rete form.
        let id = build_id_in_rete(&td(), Kind::Service, "db").unwrap();
        assert_eq!(id.to_string(), "spiffe://demo.flor/service/db");
        let id = build_id_in_rete(&td(), Kind::Vertex, "flor").unwrap();
        assert_eq!(id.to_string(), "spiffe://demo.flor/vertex/flor");
    }

    #[test]
    fn build_id_on_node_for_service_and_vertex() {
        // `build_id_on_node` takes NodeScopableKind: bad kinds (User, Node, …)
        // are unrepresentable here — the type system enforces it.
        let id = build_id_on_node(&td(), NodeScopableKind::Service, "alpha", "db").unwrap();
        assert_eq!(id.to_string(), "spiffe://demo.flor/service/alpha/db");
        let id = build_id_on_node(&td(), NodeScopableKind::Vertex, "alpha", "flor").unwrap();
        assert_eq!(id.to_string(), "spiffe://demo.flor/vertex/alpha/flor");
    }

    #[test]
    fn build_id_rejects_invalid_name() {
        // SPIFFE path segments cannot contain `/`.
        let err = build_id_in_rete(&td(), Kind::User, "a/b").unwrap_err();
        assert!(
            format!("{err:?}").contains("Failed to construct SPIFFE ID"),
            "{err:?}",
        );
    }

    #[test]
    fn build_id_round_trips_through_kind_of_and_scope_of() {
        let id = build_id_on_node(&td(), NodeScopableKind::Service, "alpha", "db").unwrap();
        assert_eq!(kind_of(&id).unwrap(), Kind::Service);
        assert_eq!(scope_of(&id).unwrap(), Scope::Node("alpha".into()));

        let id = build_id_in_rete(&td(), Kind::User, "alice").unwrap();
        assert_eq!(kind_of(&id).unwrap(), Kind::User);
        assert_eq!(scope_of(&id).unwrap(), Scope::Rete);
    }

    #[test]
    fn build_id_dispatch_picks_rete_or_node_shape() {
        let id = build_id(&td(), Kind::User, "alice", None).unwrap();
        assert_eq!(id.to_string(), "spiffe://demo.flor/user/alice");

        let id = build_id(&td(), Kind::Service, "db", None).unwrap();
        assert_eq!(id.to_string(), "spiffe://demo.flor/service/db");

        let id = build_id(&td(), Kind::Service, "db", Some("alpha")).unwrap();
        assert_eq!(id.to_string(), "spiffe://demo.flor/service/alpha/db");
    }

    #[test]
    fn build_id_dispatch_rejects_scope_for_rete_only_kinds() {
        for kind in [
            Kind::User,
            Kind::Node,
            Kind::ControlPlane,
            Kind::ManagementPlane,
        ] {
            let err = build_id(&td(), kind, "x", Some("alpha")).unwrap_err();
            assert!(
                format!("{err:?}").contains("always rete-scoped"),
                "{kind:?}: {err:?}",
            );
        }
    }

    #[test]
    fn kind_into_node_scopable() {
        assert_eq!(
            Kind::Service.into_node_scopable(),
            Some(NodeScopableKind::Service),
        );
        assert_eq!(
            Kind::Vertex.into_node_scopable(),
            Some(NodeScopableKind::Vertex),
        );
        for k in [
            Kind::User,
            Kind::Node,
            Kind::ControlPlane,
            Kind::ManagementPlane,
        ] {
            assert_eq!(k.into_node_scopable(), None, "{k:?}");
        }
    }
}
