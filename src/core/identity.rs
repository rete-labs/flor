// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Florete identity primitives.
//!
//! SPIFFE-native: `SpiffeId` and `TrustDomain` are re-exported directly from the
//! `spiffe` crate. We add a [`Kind`]/[`Scope`] projection over the SPIFFE path so
//! the rest of the code base can reason about principal classes without parsing
//! strings ad hoc. [`Store`] resolves those IDs into the material a node holds
//! for them.
//!
//! See ADR-0005 in the florete docs for the design rationale.

pub mod ca;
pub mod csr;
pub mod dialable;
pub mod kind;
pub mod store;

pub use ca::Ca;
pub use csr::keygen_csr;
pub use dialable::Dialable;
pub use kind::{Kind, NodeScopableKind, Scope, kind_of, leaf_of, scope_of};
pub use spiffe::{SpiffeId, TrustDomain, X509Bundle, X509Svid};
pub use store::Store;

use error_stack::{Report, ResultExt, bail};

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

/// Load an [`X509Svid`] from PEM material: a leaf (optionally with intermediate)
/// certificate chain and its PKCS#8 private key.
///
/// `cert_pem` may hold one or more concatenated `CERTIFICATE` blocks, leaf
/// first (the SPIFFE X.509-SVID chain order); `key_pem` must hold a single
/// `PRIVATE KEY` block. Both are converted PEM→DER and handed to
/// [`X509Svid::parse_from_der`], which validates the leaf SAN and chain.
pub fn load_svid_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<X509Svid, Report<Error>> {
    let chain_der = pem_blocks_to_der(cert_pem, "CERTIFICATE")?;
    let key_der = single_pem_block_to_der(key_pem, "PRIVATE KEY")?;
    X509Svid::parse_from_der(&chain_der, &key_der)
        .change_context(Error::new("Failed to parse X509 SVID from PEM material"))
}

/// Load an [`X509Bundle`] (trust anchors) for `trust_domain` from one or more
/// concatenated `CERTIFICATE` PEM blocks (the rete CA cert).
pub fn load_bundle_from_pem(
    trust_domain: &TrustDomain,
    ca_cert_pem: &[u8],
) -> Result<X509Bundle, Report<Error>> {
    let der = pem_blocks_to_der(ca_cert_pem, "CERTIFICATE")?;
    X509Bundle::parse_from_der(trust_domain.clone(), &der).change_context(Error::new(
        "Failed to parse X509 trust bundle from PEM material",
    ))
}

/// Decode every PEM block tagged `tag` in `pem` and concatenate their DER
/// bodies (the form both `X509Svid` and `X509Bundle` consume). Errors if no
/// block of that tag is present.
fn pem_blocks_to_der(pem: &[u8], tag: &str) -> Result<Vec<u8>, Report<Error>> {
    let blocks =
        ::pem::parse_many(pem).change_context(Error::new("Failed to parse PEM material"))?;
    let mut der = Vec::new();
    for block in blocks.into_iter().filter(|b| b.tag() == tag) {
        der.extend_from_slice(block.contents());
    }
    if der.is_empty() {
        bail!(Error::new(format!("PEM material has no {tag} block")));
    }
    Ok(der)
}

/// Decode exactly one PEM block tagged `tag` into its DER body. Errors if zero
/// or more than one such block is present.
fn single_pem_block_to_der(pem: &[u8], tag: &str) -> Result<Vec<u8>, Report<Error>> {
    let blocks =
        ::pem::parse_many(pem).change_context(Error::new("Failed to parse PEM material"))?;
    let mut matching = blocks.into_iter().filter(|b| b.tag() == tag);
    let block = matching
        .next()
        .ok_or_else(|| Report::new(Error::new(format!("PEM material has no {tag} block"))))?;
    if matching.next().is_some() {
        bail!(Error::new(format!(
            "PEM material has more than one {tag} block"
        )));
    }
    Ok(block.into_contents())
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

    fn day() -> std::time::Duration {
        std::time::Duration::from_secs(24 * 3600)
    }

    /// Mint a CA + leaf for `uri`/`kind` and return `(ca_cert_pem, leaf_pem, key_pem)`.
    fn mint(uri: &str, kind: Kind) -> (String, String, String) {
        let ca = Ca::init(&td(), day()).unwrap();
        let id = SpiffeId::new(uri).unwrap();
        let (key, csr) = keygen_csr(&id).unwrap();
        let leaf = ca.sign_csr(csr.as_bytes(), &id, kind, day()).unwrap();
        (ca.cert_pem().to_string(), leaf, key.serialize_pem())
    }

    #[test]
    fn load_svid_from_pem_recovers_spiffe_id() {
        let (_ca, leaf, key) = mint("spiffe://demo.flor/service/beta/tcp-echo", Kind::Service);
        let svid = load_svid_from_pem(leaf.as_bytes(), key.as_bytes()).unwrap();
        assert_eq!(
            svid.spiffe_id().to_string(),
            "spiffe://demo.flor/service/beta/tcp-echo"
        );
    }

    #[test]
    fn load_svid_from_pem_rejects_missing_key_block() {
        let (_ca, leaf, _key) = mint("spiffe://demo.flor/user/alice", Kind::User);
        // Feed the leaf cert where a key is expected — no PRIVATE KEY block.
        let err = load_svid_from_pem(leaf.as_bytes(), leaf.as_bytes()).unwrap_err();
        assert!(
            format!("{err:?}").contains("no PRIVATE KEY block"),
            "{err:?}"
        );
    }

    #[test]
    fn load_bundle_from_pem_holds_the_ca_authority() {
        let (ca_cert, _leaf, _key) = mint("spiffe://demo.flor/user/alice", Kind::User);
        let bundle = load_bundle_from_pem(&td(), ca_cert.as_bytes()).unwrap();
        assert_eq!(bundle.authorities().len(), 1);
        assert_eq!(bundle.trust_domain(), &td());
    }

    #[test]
    fn load_bundle_from_pem_rejects_non_cert_pem() {
        let (_ca, _leaf, key) = mint("spiffe://demo.flor/user/alice", Kind::User);
        // A PRIVATE KEY block carries no CERTIFICATE — rejected.
        let err = load_bundle_from_pem(&td(), key.as_bytes()).unwrap_err();
        assert!(
            format!("{err:?}").contains("no CERTIFICATE block"),
            "{err:?}"
        );
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
