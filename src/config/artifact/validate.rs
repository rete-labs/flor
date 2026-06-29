// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Semantic validation of compiled artifacts — the checks beyond what serde's
//! structural parse already guarantees.
//!
//! `env.validate(name)` checks the envelope identifies the expected artifact
//! (generic over the payload's declared [`Payload`] cell), then runs that
//! payload's own rules via [`ValidatePayload`]. The envelope check is written
//! once on [`Envelope`]; each payload implements only `validate_payload`.

use error_stack::{Report, ResultExt, bail};

use crate::core::identity::{Dialable, SpiffeId};

use super::Error;
use super::model::vertex::{Adapter, LinkRule, VertexKind, VertexMgmtPayload, Via};
use super::model::{Envelope, Payload};

/// A payload's own semantic rules, run after the generic envelope checks.
/// Implemented per payload type; the shared entry point is [`Envelope::validate`].
pub trait ValidatePayload: Payload {
    fn validate_payload(&self) -> Result<(), Report<Error>>;
}

impl<P: ValidatePayload> Envelope<P> {
    /// Validate this artifact is well-formed and names `expected_name`: the
    /// generic envelope checks, then the payload's own rules.
    pub fn validate(&self, expected_name: &str) -> Result<(), Report<Error>> {
        validate_envelope(self, expected_name)?;
        self.payload.validate_payload()
    }
}

impl ValidatePayload for VertexMgmtPayload {
    fn validate_payload(&self) -> Result<(), Report<Error>> {
        validate_vertex_common(self)?;
        match self.kind {
            VertexKind::Link => validate_vertex_link(self),
            // The mesh-specific rules arrive with the mesh runtime.
            VertexKind::Mesh => Ok(()),
        }
    }
}

/// Envelope-level checks, generic over any [`Payload`]: supported schema
/// version, the `(plane, kind)` the payload declares, and the expected name.
fn validate_envelope<P: Payload>(
    env: &Envelope<P>,
    expected_name: &str,
) -> Result<(), Report<Error>> {
    if env.schema_version != "1.0" {
        bail!(Error::new(format!(
            "Unsupported schema_version {:?}; expected \"1.0\"",
            env.schema_version
        )));
    }
    if env.plane.tag() != P::PLANE {
        bail!(Error::new(format!(
            "Artifact is on the {:?} plane, expected {:?}",
            env.plane.tag(),
            P::PLANE
        )));
    }
    if env.kind != P::KIND {
        bail!(Error::new(format!(
            "Expected a {:?} artifact, got {:?}",
            P::KIND,
            env.kind
        )));
    }
    if env.name != expected_name {
        bail!(Error::new(format!(
            "Artifact names {:?}, expected {:?}",
            env.name, expected_name
        )));
    }
    Ok(())
}

/// Checks shared by every vertex engine: all SPIFFE IDs share one trust domain,
/// each workload has io, and every link dials over a declared adapter of a
/// matching type to a dialable peer.
fn validate_vertex_common(payload: &VertexMgmtPayload) -> Result<(), Report<Error>> {
    validate_single_trust_domain(payload)?;

    for workload in &payload.workloads {
        if workload.io.is_empty() {
            bail!(Error::new(format!(
                "Workload {} has no io channels",
                workload.spiffe_id
            )));
        }
    }

    let adapters = &payload.connection_manager.adapters;
    for LinkRule::Enum { members } in &payload.links {
        for member in members {
            let adapter = adapters
                .iter()
                .find(|a| a.name() == member.via.adapter())
                .ok_or_else(|| {
                    Report::new(Error::new(format!(
                        "Link {:?} dials over undeclared adapter {:?}",
                        member.name,
                        member.via.adapter()
                    )))
                })?;
            if !via_matches_adapter(&member.via, adapter) {
                bail!(Error::new(format!(
                    "Link {:?} via type does not match the type of adapter {:?}",
                    member.name,
                    member.via.adapter()
                )));
            }
            // The peer must be a dialable identity (a service or vertex).
            Dialable::new(member.peer.clone()).change_context_lazy(|| {
                Error::new(format!("Link {:?} peer is not dialable", member.name))
            })?;
        }
    }
    Ok(())
}

/// Every SPIFFE ID across the payload (workloads, link peers, ACL targets and
/// allow-lists) must belong to a single trust domain — the rete's. (Whether
/// that domain is *our* rete's is checked elsewhere, against rete-root trust
/// metadata; here it is internal consistency only.)
fn validate_single_trust_domain(payload: &VertexMgmtPayload) -> Result<(), Report<Error>> {
    let acl_ids = payload
        .ingress
        .iter()
        .chain(&payload.egress)
        .flat_map(|acl| std::iter::once(&acl.target).chain(&acl.allow));
    let link_ids = payload
        .links
        .iter()
        .flat_map(|LinkRule::Enum { members }| members.iter().map(|m| &m.peer));
    let mut ids = payload
        .workloads
        .iter()
        .map(|w| &w.spiffe_id)
        .chain(link_ids)
        .chain(acl_ids);

    let Some(first) = ids.next() else {
        return Ok(());
    };
    let td = first.trust_domain();
    for id in ids {
        if id.trust_domain() != td {
            bail!(Error::new(format!(
                "SPIFFE ID {id} is not in the rete trust domain {td}"
            )));
        }
    }
    Ok(())
}

/// Link-vertex rules: the connection manager is exactly one `udp` adapter, and
/// every egress target has a direct link to dial it (the degenerate 1-1 routing
/// — a mesh vertex reaches targets via its ctrl forwarding table instead).
fn validate_vertex_link(payload: &VertexMgmtPayload) -> Result<(), Report<Error>> {
    // A link vertex is one transport endpoint over one medium — by design, a
    // single QUIC endpoint over a single udp socket. It never aggregates
    // sockets (that is the mesh layer's job, via parallel link-vertices) and
    // never terminates FlorIO (that is mesh-flor reaching down to link-flor).
    match payload.connection_manager.adapters.as_slice() {
        [Adapter::Udp { .. }] => {}
        _ => bail!(Error::new(
            "A link vertex must declare exactly one udp connection-manager adapter"
        )),
    }

    let link_peers: Vec<&SpiffeId> = payload
        .links
        .iter()
        .flat_map(|LinkRule::Enum { members }| members.iter().map(|m| &m.peer))
        .collect();
    for acl in &payload.egress {
        if !link_peers.iter().any(|peer| **peer == acl.target) {
            bail!(Error::new(format!(
                "Egress target {} has no link to dial it",
                acl.target
            )));
        }
    }
    Ok(())
}

/// Whether a `via`'s transport matches the type of the adapter it references.
fn via_matches_adapter(via: &Via, adapter: &Adapter) -> bool {
    matches!(
        (via, adapter),
        (Via::Udp { .. }, Adapter::Udp { .. }) | (Via::Florio { .. }, Adapter::Florio { .. })
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    /// A minimal, valid C0 link payload: one tcp service, one link to a peer it
    /// may egress to over the declared udp adapter.
    fn valid_payload() -> Value {
        json!({
            "kind": "link",
            "ca_cert_path": "ca.crt",
            "transport_endpoint": { "type": "quic" },
            "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "0.0.0.0:4433" } ] },
            "workloads": [
                {
                    "spiffe_id": "spiffe://demo.flor/service/alpha/api",
                    "identity": { "cert_path": "api.crt", "priv_path": "api.key" },
                    "io": [ { "kind": "tcp", "upstream": "127.0.0.1:8000" } ]
                }
            ],
            "links": [
                { "type": "enum", "members": [
                    { "name": "mongodb", "peer": "spiffe://demo.flor/service/mongodb", "via": { "type": "udp", "adapter": "wire", "addr": "5.6.7.8:4433" } }
                ] }
            ],
            "egress": [
                { "target": "spiffe://demo.flor/service/mongodb", "allow": ["spiffe://demo.flor/service/alpha/api"] }
            ]
        })
    }

    /// Wrap a payload in a well-formed mgmt vertex envelope named `flor`.
    fn envelope_with(payload: Value) -> Value {
        json!({
            "schema_version": "1.0",
            "plane": "mgmt",
            "kind": "vertex",
            "version": 42,
            "node": "alpha",
            "name": "flor",
            "generated_at": "2026-04-20T12:00:00Z",
            "payload": payload,
            "signature": { "alg": "ed25519", "key_id": "spiffe://demo.flor/management-plane/primary", "value": "sig" }
        })
    }

    fn parse(v: Value) -> Envelope<VertexMgmtPayload> {
        serde_json::from_value(v).expect("envelope json deserializes")
    }

    #[test]
    fn valid_link_envelope_passes() {
        parse(envelope_with(valid_payload()))
            .validate("flor")
            .unwrap();
    }

    // --- envelope rules (generic over the payload's declared cell) ---

    #[test]
    fn rejects_wrong_schema_version() {
        let mut v = envelope_with(valid_payload());
        v["schema_version"] = json!("0.9");
        let err = parse(v).validate("flor").unwrap_err();
        assert!(format!("{err:?}").contains("schema_version"), "{err:?}");
    }

    #[test]
    fn rejects_non_mgmt_plane() {
        let mut v = envelope_with(valid_payload());
        v["plane"] = json!({ "ctrl": { "obeys_mgmt_version": 1 } });
        let err = parse(v).validate("flor").unwrap_err();
        assert!(
            format!("{err:?}").to_lowercase().contains("mgmt"),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_non_vertex_kind() {
        let mut v = envelope_with(valid_payload());
        v["kind"] = json!("agent");
        let err = parse(v).validate("flor").unwrap_err();
        assert!(
            format!("{err:?}").to_lowercase().contains("vertex"),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_name_mismatch() {
        let err = parse(envelope_with(valid_payload()))
            .validate("other")
            .unwrap_err();
        assert!(format!("{err:?}").contains("flor"), "{err:?}");
    }

    // --- common vertex rules (apply to link and mesh alike) ---

    #[test]
    fn rejects_workload_without_io() {
        let mut p = valid_payload();
        p["workloads"][0]["io"] = json!([]);
        let err = parse(envelope_with(p)).validate("flor").unwrap_err();
        assert!(format!("{err:?}").contains("io channels"), "{err:?}");
    }

    #[test]
    fn rejects_undeclared_via_adapter() {
        let mut p = valid_payload();
        p["links"][0]["members"][0]["via"]["adapter"] = json!("nope");
        let err = parse(envelope_with(p)).validate("flor").unwrap_err();
        assert!(format!("{err:?}").contains("adapter"), "{err:?}");
    }

    #[test]
    fn rejects_via_type_adapter_mismatch() {
        // `florio` via referencing the declared udp adapter `wire`.
        let mut p = valid_payload();
        p["links"][0]["members"][0]["via"] = json!({ "type": "florio", "adapter": "wire" });
        let err = parse(envelope_with(p)).validate("flor").unwrap_err();
        assert!(format!("{err:?}").contains("does not match"), "{err:?}");
    }

    #[test]
    fn rejects_non_dialable_peer() {
        // A user is not a dialable kind (only service/vertex are).
        let mut p = valid_payload();
        p["links"][0]["members"][0]["peer"] = json!("spiffe://demo.flor/user/alice");
        let err = parse(envelope_with(p)).validate("flor").unwrap_err();
        assert!(format!("{err:?}").contains("dialable"), "{err:?}");
    }

    // --- link-only rule ---

    #[test]
    fn rejects_link_with_multiple_adapters() {
        // A link vertex is one transport over one medium; two adapters is not a
        // valid link artifact (socket aggregation is a mesh-layer concern).
        let mut p = valid_payload();
        p["connection_manager"]["adapters"] = json!([
            { "name": "wire",  "type": "udp", "listen": "0.0.0.0:4433" },
            { "name": "wire2", "type": "udp", "listen": "0.0.0.0:4434" }
        ]);
        let err = parse(envelope_with(p)).validate("flor").unwrap_err();
        assert!(format!("{err:?}").contains("exactly one udp"), "{err:?}");
    }

    #[test]
    fn rejects_link_with_florio_adapter() {
        // FlorIO is mesh-flor reaching down to link-flor; a link vertex never
        // terminates it. Its link must dial over a udp adapter.
        let mut p = valid_payload();
        p["connection_manager"]["adapters"] = json!([
            { "name": "io", "type": "florio", "socket": "/run/flor.sock" }
        ]);
        p["links"][0]["members"][0]["via"] = json!({ "type": "florio", "adapter": "io" });
        let err = parse(envelope_with(p)).validate("flor").unwrap_err();
        assert!(format!("{err:?}").contains("exactly one udp"), "{err:?}");
    }

    #[test]
    fn rejects_link_with_no_adapters() {
        // A link vertex needs its one wire socket.
        let mut p = valid_payload();
        p["connection_manager"]["adapters"] = json!([]);
        p["links"] = json!([]);
        p["egress"] = json!([]);
        let err = parse(envelope_with(p)).validate("flor").unwrap_err();
        assert!(format!("{err:?}").contains("exactly one udp"), "{err:?}");
    }

    #[test]
    fn rejects_egress_target_without_link() {
        let mut p = valid_payload();
        p["egress"][0]["target"] = json!("spiffe://demo.flor/service/unlinked");
        let err = parse(envelope_with(p)).validate("flor").unwrap_err();
        assert!(format!("{err:?}").contains("Egress target"), "{err:?}");
    }

    #[test]
    fn rejects_mixed_trust_domains() {
        // A link peer in a different trust domain than the workloads.
        let mut p = valid_payload();
        p["links"][0]["members"][0]["peer"] = json!("spiffe://other.flor/service/mongodb");
        p["egress"][0]["target"] = json!("spiffe://other.flor/service/mongodb");
        let err = parse(envelope_with(p)).validate("flor").unwrap_err();
        assert!(format!("{err:?}").contains("trust domain"), "{err:?}");
    }

    // --- mesh: shares the common rules, skips the link-only one ---

    #[test]
    fn mesh_passes_with_common_rules_met() {
        let mesh = json!({
            "kind": "mesh",
            "ca_cert_path": "ca.crt",
            "transport_endpoint": { "type": "quic" },
            "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "0.0.0.0:4433" } ] },
            "workloads": [],
            "links": [
                { "type": "enum", "members": [
                    { "name": "beta", "peer": "spiffe://demo.flor/vertex/beta/rete", "via": { "type": "udp", "adapter": "wire", "addr": "10.0.0.7:5544" } }
                ] }
            ]
        });
        parse(envelope_with(mesh)).validate("flor").unwrap();
    }

    #[test]
    fn mesh_still_enforces_common_rules() {
        // The via/adapter-type check is common, so a mesh artifact fails it too.
        let mesh = json!({
            "kind": "mesh",
            "ca_cert_path": "ca.crt",
            "transport_endpoint": { "type": "quic" },
            "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "0.0.0.0:4433" } ] },
            "workloads": [],
            "links": [
                { "type": "enum", "members": [
                    { "name": "beta", "peer": "spiffe://demo.flor/vertex/beta/rete", "via": { "type": "florio", "adapter": "wire" } }
                ] }
            ]
        });
        let err = parse(envelope_with(mesh)).validate("flor").unwrap_err();
        assert!(format!("{err:?}").contains("does not match"), "{err:?}");
    }

    #[test]
    fn mesh_skips_link_only_rule() {
        // An egress target with no direct link is fine for mesh (it routes via
        // the forwarding table), so the link-only check does not apply.
        let mesh = json!({
            "kind": "mesh",
            "ca_cert_path": "ca.crt",
            "transport_endpoint": { "type": "quic" },
            "connection_manager": { "adapters": [] },
            "workloads": [],
            "egress": [
                { "target": "spiffe://demo.flor/service/far-away", "allow": ["spiffe://demo.flor/user/alice"] }
            ]
        });
        parse(envelope_with(mesh)).validate("flor").unwrap();
    }
}
