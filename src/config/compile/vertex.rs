// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Projection of the resolved [`Plan`] onto one node's vertex artifact.
//!
//! Per-node filtering is the whole point: a node's artifact carries only the
//! identity references (SPIFFE IDs and cert/key paths, not the SVID material
//! itself) and ACL rows its own workloads need. Three tables fall out of the
//! plan, and the doc's terms name them from flor's point of view:
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

use super::plan::{NodePlan, Plan, Target, TlsPrincipal};
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
    let locals: Vec<&TlsPrincipal> = plan
        .tls_principals
        .iter()
        .filter(|p| p.node == node)
        .collect();
    let reach = reachable(plan, node);

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
        links: links(&reach),
        ingress: ingress(plan, node),
        egress: egress(&reach),
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

/// Every target a principal local to `node` may reach, paired with the local
/// principals that may reach it. Keyed by service name so the projected tables
/// come out sorted.
///
/// This is the shared core of `links` and `egress`: both are just a view of it,
/// so a target absent here appears in neither table.
fn reachable<'a>(plan: &'a Plan, node: &str) -> BTreeMap<&'a str, (&'a Target, Vec<&'a SpiffeId>)> {
    let locals: Vec<&TlsPrincipal> = plan
        .tls_principals
        .iter()
        .filter(|p| p.node == node)
        .collect();

    let mut reachable = BTreeMap::new();
    for target in plan.targets.values() {
        let allow: Vec<&SpiffeId> = locals
            .iter()
            .filter(|p| grants_access(&p.granted, &target.groups))
            .map(|p| &p.id)
            .collect();
        if !allow.is_empty() {
            reachable.insert(target.name.as_str(), (target, allow));
        }
    }
    reachable
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
                addr: target.link_addr,
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
                plan.tls_principals
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::config::artifact::model::vertex::{Identity, IoChannel};
    use crate::core::identity::{Kind, TrustDomain, build_id_in_rete};

    use super::*;

    fn td() -> TrustDomain {
        TrustDomain::new("rete-lovers").unwrap()
    }

    fn user_id(name: &str) -> SpiffeId {
        build_id_in_rete(&td(), Kind::User, name).unwrap()
    }

    fn svc_id(name: &str) -> SpiffeId {
        build_id_in_rete(&td(), Kind::Service, name).unwrap()
    }

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn identity() -> Identity {
        Identity {
            cert_path: "x.crt".into(),
            priv_path: "x.key".into(),
        }
    }

    fn target(name: &str, node: &str, addr: &str, groups: &[&str]) -> Target {
        Target {
            name: name.to_string(),
            id: svc_id(name),
            node: node.to_string(),
            link_addr: addr.parse().unwrap(),
            groups: set(groups),
        }
    }

    /// A three-node topology: `alice` on `laptop` may reach `api` (group `api`);
    /// `api` on `alpha` may reach `mongodb` (group `db`); `mongodb` is on `beta`.
    fn plan() -> Plan {
        let mut targets = BTreeMap::new();
        targets.insert(
            "api".into(),
            target("api", "alpha", "1.2.3.4:4433", &["api"]),
        );
        targets.insert(
            "mongodb".into(),
            target("mongodb", "beta", "5.6.7.8:4433", &["db"]),
        );

        let alice = TlsPrincipal {
            id: user_id("alice"),
            node: "laptop".into(),
            granted: set(&["api"]),
            identity: identity(),
            io: vec![IoChannel::Socks5 {
                listen: "127.0.0.1:1080".parse().unwrap(),
            }],
        };
        let api = TlsPrincipal {
            id: svc_id("api"),
            node: "alpha".into(),
            granted: set(&["db"]),
            identity: identity(),
            io: vec![IoChannel::Tcp {
                upstream: "127.0.0.1:8000".parse().unwrap(),
            }],
        };

        Plan {
            trust_domain: td(),
            signer_key_id: build_id_in_rete(&td(), Kind::ManagementPlane, "primary").unwrap(),
            nodes: BTreeMap::new(),
            targets,
            tls_principals: vec![alice, api],
        }
    }

    #[test]
    fn grants_access_is_group_intersection() {
        assert!(grants_access(&set(&["api", "db"]), &set(&["db"])));
        assert!(!grants_access(&set(&["api"]), &set(&["db"])));
        assert!(!grants_access(&set(&[]), &set(&["db"])));
    }

    #[test]
    fn reachable_keeps_only_targets_a_local_may_reach() {
        let p = plan();

        // laptop hosts alice (grants `api`): reaches api, not mongodb (`db`).
        let reach = reachable(&p, "laptop");
        assert_eq!(reach.keys().copied().collect::<Vec<_>>(), ["api"]);
        let (target, allow) = &reach["api"];
        assert_eq!(target.node, "alpha");
        assert_eq!(*allow, vec![&user_id("alice")]);

        // alpha hosts api (grants `db`): reaches mongodb, not itself.
        let reach = reachable(&p, "alpha");
        assert_eq!(reach.keys().copied().collect::<Vec<_>>(), ["mongodb"]);
    }

    #[test]
    fn reachable_is_empty_for_a_node_with_no_locals() {
        // beta hosts no principal in this plan, so it may reach nothing.
        assert!(reachable(&plan(), "beta").is_empty());
    }

    #[test]
    fn links_dial_each_reachable_target_over_the_wire_adapter() {
        let p = plan();
        let reach = reachable(&p, "laptop");
        let rules = links(&reach);
        let LinkRule::List { members } = &rules[0];
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].name, "api");
        assert_eq!(members[0].peer, svc_id("api"));
        let Via::Udp { adapter, addr } = &members[0].via else {
            panic!("expected a udp via");
        };
        assert_eq!(adapter, WIRE_ADAPTER);
        assert_eq!(*addr, "1.2.3.4:4433".parse().unwrap());
    }

    #[test]
    fn links_are_empty_when_nothing_is_reachable() {
        assert!(links(&reachable(&plan(), "beta")).is_empty());
    }

    #[test]
    fn egress_lists_local_initiators_per_target() {
        let egress = egress(&reachable(&plan(), "laptop"));
        assert_eq!(egress.len(), 1);
        assert_eq!(egress[0].target, svc_id("api"));
        assert_eq!(egress[0].allow, vec![user_id("alice")]);
    }

    #[test]
    fn ingress_gates_targets_hosted_here_by_any_rete_principal() {
        let p = plan();

        // On alpha, api is hosted here and alice (from laptop) may initiate to it.
        let acls = ingress(&p, "alpha");
        assert_eq!(acls.len(), 1);
        assert_eq!(acls[0].target, svc_id("api"));
        assert_eq!(acls[0].allow, vec![user_id("alice")]);

        // laptop hosts no target, so nothing may initiate to it.
        assert!(ingress(&p, "laptop").is_empty());
    }
}
