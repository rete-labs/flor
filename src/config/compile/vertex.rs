// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Projection of the resolved [`Plan`] onto one node's vertex artifact.
//!
//! Per-node filtering is the whole point: a node's artifact carries only the
//! identity material and ACL rows its own workloads need. Three tables fall out
//! of the plan, and the doc's terms name them from flor's point of view:
//!
//! - `ingress` — which remote principals may initiate to a target hosted *here*.
//!   This is the authoritative access-control gate.
//! - `egress` — which local principals may initiate to a given remote target. A
//!   local convenience filter, so a disallowed SOCKS5 request fails fast; the
//!   target's `ingress` is what actually enforces.
//! - `links` — how to dial each of those targets. In C0 every tunnel is a direct
//!   QUIC connection, so the links table *is* the (degenerate, 1-1) routing.

use std::collections::{BTreeMap, BTreeSet};

use error_stack::Report;

use crate::config::artifact::model::vertex::{
    Acl, Adapter, ConnectionManager, LinkMember, LinkRule, TransportEndpoint, Via, Workload,
};
use crate::config::artifact::{
    ArtifactKind, Envelope, Plane, Signature, VertexKind, VertexMgmtPayload,
};
use crate::core::identity::SpiffeId;

use super::plan::{NodePlan, Plan, Principal, Target};
use super::{CompileOpts, Error, NodeVertexArtifact};

/// The compiled-artifact contract version this compiler emits.
const SCHEMA_VERSION: &str = "1.0";

/// The rete CA, as the flat install root holds it.
const CA_CERT_FILE: &str = "ca.crt";

/// A link vertex has exactly one adapter — one QUIC endpoint over one UDP
/// socket. Its name is a local handle each link's `via` references.
const WIRE_ADAPTER: &str = "wire";

/// Signing is not implemented yet: artifacts name the rete's mgmt signer but
/// carry no signature. The agent — the sole verifier — lands with `flor agent`.
const SIGNATURE_ALG_NONE: &str = "none";
const SIGNATURE_UNSIGNED: &str = "unsigned";

/// Project one node's vertex artifact out of the resolved rete.
pub fn project(
    plan: &Plan,
    node: &str,
    node_plan: &NodePlan,
    opts: &CompileOpts,
) -> Result<NodeVertexArtifact, Report<Error>> {
    let locals: Vec<&Principal> = plan.principals.iter().filter(|p| p.node == node).collect();

    // Every target a local principal may reach, with the local principals that
    // may reach it. Keyed by service name so the tables come out sorted.
    let mut reachable: BTreeMap<&str, (&Target, Vec<&SpiffeId>)> = BTreeMap::new();
    for target in plan.targets.values() {
        let allow: Vec<&SpiffeId> = locals
            .iter()
            .filter(|p| grants_access(&p.granted, &target.groups))
            .map(|p| &p.id)
            .collect();
        if !allow.is_empty() {
            reachable.insert(&target.name, (target, allow));
        }
    }

    let payload = VertexMgmtPayload {
        kind: VertexKind::Link,
        ca_cert_path: CA_CERT_FILE.into(),
        transport_endpoint: TransportEndpoint::Quic,
        connection_manager: ConnectionManager {
            adapters: vec![Adapter::Udp {
                name: WIRE_ADAPTER.to_string(),
                listen: node_plan.listen(),
            }],
        },
        workloads: locals
            .iter()
            .map(|p| Workload {
                spiffe_id: p.id.clone(),
                identity: p.identity.clone(),
                io: p.io.clone(),
            })
            .collect(),
        links: links(&reachable),
        ingress: ingress(plan, node),
        egress: egress(&reachable),
    };

    Ok(NodeVertexArtifact {
        node: node.to_string(),
        vertex_name: node_plan.vertex_name.clone(),
        envelope: Envelope {
            schema_version: SCHEMA_VERSION.to_string(),
            plane: Plane::Mgmt,
            kind: ArtifactKind::Vertex,
            version: opts.version,
            node: node.to_string(),
            name: node_plan.vertex_name.clone(),
            generated_at: opts.generated_at.clone(),
            payload,
            signature: Signature {
                alg: SIGNATURE_ALG_NONE.to_string(),
                key_id: plan.signer_key_id.clone(),
                value: SIGNATURE_UNSIGNED.to_string(),
            },
        },
    })
}

/// How to dial each reachable target: one member per target, over the single
/// wire adapter, at the target's host-node address.
fn links(reachable: &BTreeMap<&str, (&Target, Vec<&SpiffeId>)>) -> Vec<LinkRule> {
    if reachable.is_empty() {
        return Vec::new();
    }
    let members = reachable
        .values()
        .map(|(target, _)| LinkMember {
            name: target.name.clone(),
            peer: target.id.clone(),
            via: Via::Udp {
                adapter: WIRE_ADAPTER.to_string(),
                addr: target.addr,
            },
        })
        .collect();
    vec![LinkRule::List { members }]
}

/// Which local principals may initiate to each reachable target.
fn egress(reachable: &BTreeMap<&str, (&Target, Vec<&SpiffeId>)>) -> Vec<Acl> {
    reachable
        .values()
        .map(|(target, allow)| Acl {
            target: target.id.clone(),
            allow: sorted_ids(allow.iter().copied()),
        })
        .collect()
}

/// Which principals — from anywhere in the rete — may initiate to each target
/// hosted on this node. A target nobody may reach gets no row: an absent target
/// denies just as an empty allow-list would, and says so with less noise.
fn ingress(plan: &Plan, node: &str) -> Vec<Acl> {
    plan.targets
        .values()
        .filter(|target| target.node == node)
        .filter_map(|target| {
            let allow = sorted_ids(
                plan.principals
                    .iter()
                    .filter(|p| grants_access(&p.granted, &target.groups))
                    .map(|p| &p.id),
            );
            (!allow.is_empty()).then(|| Acl {
                target: target.id.clone(),
                allow,
            })
        })
        .collect()
}

/// Whether any group a principal's roles grant gates access to this target.
fn grants_access(granted: &BTreeSet<String>, target_groups: &BTreeSet<String>) -> bool {
    granted.intersection(target_groups).next().is_some()
}

/// Sort and de-duplicate an allow-list. A user with several devices appears once
/// per device in the plan, but names a single identity in an ACL.
fn sorted_ids<'a>(ids: impl Iterator<Item = &'a SpiffeId>) -> Vec<SpiffeId> {
    let mut out: Vec<SpiffeId> = ids.cloned().collect();
    out.sort_by_key(|id| id.to_string());
    out.dedup();
    out
}
