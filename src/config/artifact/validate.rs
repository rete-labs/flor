// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Semantic validation of compiled artifacts — the checks beyond what serde's
//! structural parse already guarantees.
//!
//! Consumers differ in what they know about the artifact they asked for, so
//! there is **one entry point**, [`Envelope::validate`], and each check is
//! opted into through [`Expect`] by the consumer that can make it:
//!
//! - the envelope contract's own version ladder runs by default. It is not a
//!   claim about this consumer's context but what makes the rest of the struct
//!   readable at all, so only a relay — which reads the frozen routing core and
//!   nothing else, and never gates (ADR-0012) — waives it, with
//!   [`Expect::skip_envelope_schema_version`].
//! - `name`, `plane` and `node` are claims the caller's context supplies, and
//!   are checked only against what it states. A claim a consumer cannot know is
//!   left unset: a workload is handed its config and has no independent notion
//!   of the node it runs on, so it does not state one.
//! - [`Expect::check_payload`] adds the payload type's own claims — the plane its
//!   family lives on, that family's version ladder, and the payload's rules
//!   ([`ValidatePayload`]). It exists only where the payload parses, so `flor
//!   agent` handing down an artifact whose payload it does not know, or a relay
//!   moving one on the frozen core alone, simply leaves it off.
//!
//! No consumer is asked to gate a claim it cannot interpret, and none has to
//! restate one the payload type already fixes.
//!
//! This is **currently fail-fast**: it returns on the first problem. That is
//! enough for the consumer-side gate (flor loading an artifact the operator
//! already ran through `retectl validate`, and which — per ADR-0011 — the agent
//! has vouched for): its job here is a go/no-go decision, not the authoring UX.
//! Collecting and reporting *all* problems at once (as `retectl validate` does)
//! is a planned improvement — tracked in #53.

use error_stack::{Report, ResultExt, bail};

use crate::core::identity::{Dialable, SpiffeId};

use super::Error;
use super::model::vertex::{Adapter, LinkRule, VertexKind, VertexMgmtPayload, Via};
use super::model::{Envelope, Payload, PlaneTag};
use super::version;

/// A payload's own semantic rules, run after the generic envelope checks.
/// Implemented per payload type; the shared entry point is [`Envelope::validate`].
pub trait ValidatePayload: Payload {
    fn validate_payload(&self) -> Result<(), Report<Error>>;
}

/// The payload half, held as a plain function so [`Envelope::validate`] can run
/// it without a [`ValidatePayload`] bound of its own — the bound sits on
/// [`Expect::check_payload`], the only place that can install one.
type PayloadCheck<P> = fn(&Envelope<P>) -> Result<(), Report<Error>>;

/// What a consumer expects of an artifact. Each check is chosen by the consumer
/// that can make it: a claim it cannot know is left unset, a check it cannot
/// perform is left off.
pub struct Expect<'a, P> {
    name: &'a str,
    node: Option<&'a str>,
    plane: Option<PlaneTag>,
    payload: Option<PayloadCheck<P>>,
    envelope_schema_version: bool,
}

impl<'a, P> Expect<'a, P> {
    /// The name the artifact was addressed by — every consumer has one, since
    /// `name` is the whole of dispatch, and checking it is defence-in-depth
    /// against being handed an artifact it did not ask for.
    pub fn new(name: &'a str) -> Self {
        Self {
            name,
            node: None,
            plane: None,
            payload: None,
            envelope_schema_version: true,
        }
    }

    /// The node this artifact must be projected for. Stated only by a consumer
    /// that knows the node independently of the artifact — the compiler's
    /// self-check, and the agent's own node; one that is handed its config and
    /// has no independent notion of its node leaves it unset.
    pub fn check_node(mut self, node: &'a str) -> Self {
        self.node = Some(node);
        self
    }

    /// The plane this artifact must be on, for a consumer whose `P` cannot say.
    /// [`check_payload`](Expect::check_payload) pins the plane from the payload
    /// type itself, so a consumer that opts into that need not state one here.
    pub fn check_plane(mut self, plane: PlaneTag) -> Self {
        self.plane = Some(plane);
        self
    }

    /// Also check everything the payload type claims: that this artifact is on
    /// the plane its family lives on, that family's own version ladder, and the
    /// payload's rules ([`ValidatePayload`]).
    ///
    /// The bound is what makes this half opt-in rather than skippable — a
    /// consumer that cannot parse the payload has no `P` that satisfies it.
    pub fn check_payload(mut self) -> Self
    where
        P: ValidatePayload,
    {
        self.payload = Some(validate_payload_claims::<P>);
        self
    }

    /// Accept an envelope schema version this build does not speak.
    pub fn skip_envelope_schema_version(mut self) -> Self {
        self.envelope_schema_version = false;
        self
    }
}

/// The payload type's own claims, installed by [`Expect::check_payload`].
fn validate_payload_claims<P: ValidatePayload>(env: &Envelope<P>) -> Result<(), Report<Error>> {
    // The `(plane, family)` cell a payload lives in is the payload type's to
    // state, never the caller's: no consumer may widen it by expecting another.
    if env.plane.tag() != P::PLANE {
        bail!(Error::new(format!(
            "Artifact is on the {:?} plane, but its payload family lives on the {:?} plane",
            env.plane.tag(),
            P::PLANE
        )));
    }
    // The payload family's ladder, independent of the envelope's — gated here
    // rather than in each `validate_payload`, so no payload can skip it.
    version::ensure_supported(&P::FAMILY, env.payload.schema_version())?;
    env.payload.validate_payload()
}

impl<P> Envelope<P> {
    /// Validate this artifact against what its consumer [expects](Expect).
    pub fn validate(&self, expect: Expect<'_, P>) -> Result<(), Report<Error>> {
        if expect.envelope_schema_version {
            version::ensure_supported(&version::ENVELOPE, &self.schema_version)?;
        }
        if let Some(plane) = expect.plane
            && self.plane.tag() != plane
        {
            bail!(Error::new(format!(
                "Artifact is on the {:?} plane, expected {:?}",
                self.plane.tag(),
                plane
            )));
        }
        // `name` is addressing: it says which artifact this is. It claims
        // nothing about the payload's schema, and no consumer may infer one from
        // it — a workload otherwise uses its name for logging.
        if self.name != expect.name {
            bail!(Error::new(format!(
                "Artifact names {:?}, expected {:?}",
                self.name, expect.name
            )));
        }
        if let Some(node) = expect.node
            && self.node != node
        {
            bail!(Error::new(format!(
                "Artifact is projected for node {:?}, expected {:?}",
                self.node, node
            )));
        }
        match expect.payload {
            Some(check) => check(self),
            None => Ok(()),
        }
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
    for LinkRule::List { members } in &payload.links {
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
        .flat_map(|LinkRule::List { members }| members.iter().map(|m| &m.peer));
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
        .flat_map(|LinkRule::List { members }| members.iter().map(|m| &m.peer))
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
            "schema_version": "1.0",
            "kind": "link",
            "transport_endpoint": { "type": "quic" },
            "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "0.0.0.0:4433" } ] },
            "workloads": [
                {
                    "spiffe_id": "spiffe://demo.flor/service/alpha/api",
                    "io": [ { "kind": "tcp", "upstream": "127.0.0.1:8000" } ]
                }
            ],
            "links": [
                { "type": "list", "members": [
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
            .validate(Expect::new("flor").check_payload())
            .unwrap();
    }

    // --- envelope rules (generic over the payload's declared cell) ---

    #[test]
    fn rejects_wrong_envelope_schema_version() {
        let mut v = envelope_with(valid_payload());
        v["schema_version"] = json!("0.9");
        let err = parse(v)
            .validate(Expect::new("flor").check_payload())
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("schema_version"), "{msg}");
        assert!(msg.contains("envelope"), "{msg}");
    }

    #[test]
    fn a_relay_moves_an_envelope_schema_version_it_does_not_speak() {
        // Relays never gate (ADR-0012): the routing core is frozen across every
        // envelope version, so a consumer reading only that still checks its
        // claims on an artifact this build could not otherwise interpret.
        let mut v = envelope_with(valid_payload());
        v["schema_version"] = json!("9.0");
        let env: Envelope<Value> = serde_json::from_value(v).expect("envelope json deserializes");
        env.validate(
            Expect::new("flor")
                .check_plane(PlaneTag::Mgmt)
                .check_node("alpha")
                .skip_envelope_schema_version(),
        )
        .unwrap();

        // Waiving the ladder waives nothing else.
        assert!(
            env.validate(Expect::new("other").skip_envelope_schema_version())
                .is_err()
        );
    }

    #[test]
    fn rejects_wrong_payload_schema_version() {
        // The payload family versions on its own ladder, so a current envelope
        // does not vouch for the payload's minor.
        let mut p = valid_payload();
        p["schema_version"] = json!("1.9");
        let err = parse(envelope_with(p))
            .validate(Expect::new("flor").check_payload())
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("vertex payload"), "{msg}");
        assert!(msg.contains("upgrade"), "{msg}");
    }

    #[test]
    fn the_two_ladders_are_independent() {
        // Each gate rejects on its own claim and ignores the other's. Were they
        // one ladder, a bump on either side would have to move both.
        let mut v = envelope_with(valid_payload());
        v["schema_version"] = json!("2.0");
        v["payload"]["schema_version"] = json!("1.0");
        let err = parse(v)
            .validate(Expect::new("flor").check_payload())
            .unwrap_err();
        assert!(format!("{err:?}").contains("envelope"), "{err:?}");

        let mut v = envelope_with(valid_payload());
        v["schema_version"] = json!("1.0");
        v["payload"]["schema_version"] = json!("2.0");
        let err = parse(v)
            .validate(Expect::new("flor").check_payload())
            .unwrap_err();
        assert!(format!("{err:?}").contains("vertex payload"), "{err:?}");
    }

    #[test]
    fn rejects_non_mgmt_plane() {
        let mut v = envelope_with(valid_payload());
        v["plane"] = json!({ "ctrl": { "obeys_mgmt_version": 1 } });
        let err = parse(v)
            .validate(Expect::new("flor").check_payload())
            .unwrap_err();
        assert!(
            format!("{err:?}").to_lowercase().contains("mgmt"),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_name_mismatch() {
        let err = parse(envelope_with(valid_payload()))
            .validate(Expect::new("other").check_payload())
            .unwrap_err();
        assert!(format!("{err:?}").contains("flor"), "{err:?}");
    }

    // --- the payload-agnostic half, as the agent uses it ---

    #[test]
    fn claims_validate_over_an_unparsed_payload() {
        // The supervisor's case: it knows the envelope and nothing else. A
        // payload it cannot parse — here, one that is not even a vertex payload
        // — must not stop it from checking every claim the frozen core makes.
        let mut v = envelope_with(valid_payload());
        v["payload"] = json!({ "some-future-workload": { "we": "cannot parse this" } });
        let env: Envelope<Value> = serde_json::from_value(v).expect("envelope json deserializes");
        env.validate(
            Expect::new("flor")
                .check_plane(PlaneTag::Mgmt)
                .check_node("alpha"),
        )
        .unwrap();
    }

    #[test]
    fn rejects_node_mismatch() {
        // A caller that knows its node rejects an artifact projected for
        // another one; the same artifact passes when the caller doesn't know.
        let env = parse(envelope_with(valid_payload()));
        let err = env
            .validate(
                Expect::new("flor")
                    .check_plane(PlaneTag::Mgmt)
                    .check_node("beta"),
            )
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("alpha") && msg.contains("beta"), "{msg}");

        env.validate(Expect::new("flor").check_plane(PlaneTag::Mgmt))
            .unwrap();
    }

    #[test]
    fn the_plane_is_checked_only_against_a_caller_that_stated_one() {
        // A consumer whose `P` says nothing, and which does not state a plane
        // either, is asking for the remaining claims alone.
        let mut v = envelope_with(valid_payload());
        v["plane"] = json!({ "ctrl": { "obeys_mgmt_version": 1 } });
        let env: Envelope<Value> = serde_json::from_value(v).expect("envelope json deserializes");
        env.validate(Expect::new("flor")).unwrap();
        assert!(
            env.validate(Expect::new("flor").check_plane(PlaneTag::Mgmt))
                .is_err()
        );
    }

    #[test]
    fn the_payload_check_pins_the_plane_its_family_lives_on() {
        // The `(plane, family)` cell is the payload type's to state: a consumer
        // that opts into the payload check cannot widen it by expecting the
        // ctrl plane, even though the artifact agrees with it.
        let mut v = envelope_with(valid_payload());
        v["plane"] = json!({ "ctrl": { "obeys_mgmt_version": 1 } });
        let err = parse(v)
            .validate(
                Expect::new("flor")
                    .check_plane(PlaneTag::Ctrl)
                    .check_payload(),
            )
            .unwrap_err();
        assert!(
            format!("{err:?}").to_lowercase().contains("mgmt"),
            "{err:?}"
        );
    }

    #[test]
    fn claims_ignore_the_payload_family_ladder() {
        // The payload's own version is not the agent's to gate: an artifact
        // stamped at an unsupported payload minor still passes the claims
        // check, and is rejected only by the consumer that parses it.
        let mut p = valid_payload();
        p["schema_version"] = json!("1.9");
        let env = parse(envelope_with(p));
        env.validate(
            Expect::new("flor")
                .check_plane(PlaneTag::Mgmt)
                .check_node("alpha"),
        )
        .unwrap();
        assert!(env.validate(Expect::new("flor").check_payload()).is_err());
    }

    // --- common vertex rules (apply to link and mesh alike) ---

    #[test]
    fn rejects_workload_without_io() {
        let mut p = valid_payload();
        p["workloads"][0]["io"] = json!([]);
        let err = parse(envelope_with(p))
            .validate(Expect::new("flor").check_payload())
            .unwrap_err();
        assert!(format!("{err:?}").contains("io channels"), "{err:?}");
    }

    #[test]
    fn rejects_undeclared_via_adapter() {
        let mut p = valid_payload();
        p["links"][0]["members"][0]["via"]["adapter"] = json!("nope");
        let err = parse(envelope_with(p))
            .validate(Expect::new("flor").check_payload())
            .unwrap_err();
        assert!(format!("{err:?}").contains("adapter"), "{err:?}");
    }

    #[test]
    fn rejects_via_type_adapter_mismatch() {
        // `florio` via referencing the declared udp adapter `wire`.
        let mut p = valid_payload();
        p["links"][0]["members"][0]["via"] = json!({ "type": "florio", "adapter": "wire" });
        let err = parse(envelope_with(p))
            .validate(Expect::new("flor").check_payload())
            .unwrap_err();
        assert!(format!("{err:?}").contains("does not match"), "{err:?}");
    }

    #[test]
    fn rejects_non_dialable_peer() {
        // A user is not a dialable kind (only service/vertex are).
        let mut p = valid_payload();
        p["links"][0]["members"][0]["peer"] = json!("spiffe://demo.flor/user/alice");
        let err = parse(envelope_with(p))
            .validate(Expect::new("flor").check_payload())
            .unwrap_err();
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
        let err = parse(envelope_with(p))
            .validate(Expect::new("flor").check_payload())
            .unwrap_err();
        assert!(format!("{err:?}").contains("exactly one udp"), "{err:?}");
    }

    #[test]
    fn rejects_link_with_florio_adapter() {
        // FlorIO is mesh-flor reaching down to link-flor; a link vertex never
        // terminates it. Its link must dial over a udp adapter.
        let mut p = valid_payload();
        p["connection_manager"]["adapters"] = json!([
            { "name": "io", "type": "florio", "vertex": "public" }
        ]);
        p["links"][0]["members"][0]["via"] = json!({ "type": "florio", "adapter": "io" });
        let err = parse(envelope_with(p))
            .validate(Expect::new("flor").check_payload())
            .unwrap_err();
        assert!(format!("{err:?}").contains("exactly one udp"), "{err:?}");
    }

    #[test]
    fn rejects_link_with_no_adapters() {
        // A link vertex needs its one wire socket.
        let mut p = valid_payload();
        p["connection_manager"]["adapters"] = json!([]);
        p["links"] = json!([]);
        p["egress"] = json!([]);
        let err = parse(envelope_with(p))
            .validate(Expect::new("flor").check_payload())
            .unwrap_err();
        assert!(format!("{err:?}").contains("exactly one udp"), "{err:?}");
    }

    #[test]
    fn rejects_egress_target_without_link() {
        let mut p = valid_payload();
        p["egress"][0]["target"] = json!("spiffe://demo.flor/service/unlinked");
        let err = parse(envelope_with(p))
            .validate(Expect::new("flor").check_payload())
            .unwrap_err();
        assert!(format!("{err:?}").contains("Egress target"), "{err:?}");
    }

    #[test]
    fn rejects_mixed_trust_domains() {
        // A link peer in a different trust domain than the workloads.
        let mut p = valid_payload();
        p["links"][0]["members"][0]["peer"] = json!("spiffe://other.flor/service/mongodb");
        p["egress"][0]["target"] = json!("spiffe://other.flor/service/mongodb");
        let err = parse(envelope_with(p))
            .validate(Expect::new("flor").check_payload())
            .unwrap_err();
        assert!(format!("{err:?}").contains("trust domain"), "{err:?}");
    }

    // --- mesh: shares the common rules, skips the link-only one ---

    #[test]
    fn mesh_passes_with_common_rules_met() {
        let mesh = json!({
            "schema_version": "1.0",
            "kind": "mesh",
            "transport_endpoint": { "type": "quic" },
            "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "0.0.0.0:4433" } ] },
            "workloads": [],
            "links": [
                { "type": "list", "members": [
                    { "name": "beta", "peer": "spiffe://demo.flor/vertex/beta/rete", "via": { "type": "udp", "adapter": "wire", "addr": "10.0.0.7:5544" } }
                ] }
            ]
        });
        parse(envelope_with(mesh))
            .validate(Expect::new("flor").check_payload())
            .unwrap();
    }

    #[test]
    fn mesh_still_enforces_common_rules() {
        // The via/adapter-type check is common, so a mesh artifact fails it too.
        let mesh = json!({
            "schema_version": "1.0",
            "kind": "mesh",
            "transport_endpoint": { "type": "quic" },
            "connection_manager": { "adapters": [ { "name": "wire", "type": "udp", "listen": "0.0.0.0:4433" } ] },
            "workloads": [],
            "links": [
                { "type": "list", "members": [
                    { "name": "beta", "peer": "spiffe://demo.flor/vertex/beta/rete", "via": { "type": "florio", "adapter": "wire" } }
                ] }
            ]
        });
        let err = parse(envelope_with(mesh))
            .validate(Expect::new("flor").check_payload())
            .unwrap_err();
        assert!(format!("{err:?}").contains("does not match"), "{err:?}");
    }

    #[test]
    fn mesh_skips_link_only_rule() {
        // An egress target with no direct link is fine for mesh (it routes via
        // the forwarding table), so the link-only check does not apply.
        let mesh = json!({
            "schema_version": "1.0",
            "kind": "mesh",
            "transport_endpoint": { "type": "quic" },
            "connection_manager": { "adapters": [] },
            "workloads": [],
            "egress": [
                { "target": "spiffe://demo.flor/service/far-away", "allow": ["spiffe://demo.flor/user/alice"] }
            ]
        });
        parse(envelope_with(mesh))
            .validate(Expect::new("flor").check_payload())
            .unwrap();
    }
}
