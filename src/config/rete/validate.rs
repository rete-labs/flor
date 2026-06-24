// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Validation rules run on the merged `RepoModel`.
//!
//! Some checks are enforced during parsing/merging or subsumed by other rules.
//! Enrollment log and mgmt-plane signer cert checks are deferred.

use std::fmt;

use super::merge::RepoModel;
use super::model::{VertexKind, VertexType};

const SVC_CONFIG_SERVER: &str = "config-server";
const SVC_CONFIG_PUBLISHER: &str = "config-publisher";
const GROUP_CONFIG_READ: &str = "config-read";
const GROUP_CONFIG_WRITE: &str = "config-write";
const ROLE_NODE: &str = "node";
const ROLE_OPERATOR: &str = "operator";

/// A single validation rule violation found in the rete config.
pub struct Violation {
    pub rule: Rule,
    pub message: String,
}

/// The validation rule that was violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Every referenced node/service/group/role name exists.
    CrossReferences,
    /// User, service, and node names are globally unique (no cross-kind collision).
    PrincipalRegistry,
    /// Every service's `at` field names a known node.
    ServicePlacement,
    /// Config-server and config-publisher coexist on one reachable mgmt node.
    ManagementNodeIntegrity,
    /// Reserved roles and groups are present with canonical definitions.
    ReservedNameProtection,
    /// At least one user holds the `operator` role.
    OperatorPresence,
    /// Every node has a link-vertex; workload-hosting nodes have a reachable address.
    VertexGraphReachability,
    /// `via` references resolve; absent `via` is only valid on single-vertex nodes.
    WorkloadVertexBinding,
    /// Services without `roles` may only be targets (no socks5_proxy without roles).
    PrincipalRoleCoherence,
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Rule::CrossReferences => "cross-references",
            Rule::PrincipalRegistry => "principal registry",
            Rule::ServicePlacement => "service placement",
            Rule::ManagementNodeIntegrity => "management-node integrity",
            Rule::ReservedNameProtection => "reserved-name protection",
            Rule::OperatorPresence => "operator presence",
            Rule::VertexGraphReachability => "vertex graph reachability",
            Rule::WorkloadVertexBinding => "workload vertex binding",
            Rule::PrincipalRoleCoherence => "principal role coherence",
        };
        f.write_str(s)
    }
}

/// Run all validation rules against the merged model and return every violation found.
///
/// An empty vec means the config is valid.
pub fn validate(model: &RepoModel) -> Vec<Violation> {
    let mut out = Vec::new();
    check_cross_references(model, &mut out);
    check_principal_registry(model, &mut out);
    check_service_placement(model, &mut out);
    check_management_node_integrity(model, &mut out);
    check_reserved_name_protection(model, &mut out);
    check_operator_presence(model, &mut out);
    check_vertex_graph_reachability(model, &mut out);
    check_workload_vertex_binding(model, &mut out);
    check_principal_role_coherence(model, &mut out);
    out
}

// ---------------------------------------------------------------------------
// Rule::CrossReferences
// ---------------------------------------------------------------------------

fn check_cross_references(model: &RepoModel, out: &mut Vec<Violation>) {
    // Service `at` and `via` resolved under `Rule::ServicePlacement` and `Rule::WorkloadVertexBinding` respectively.
    // Here we check role `allow` lists and user `roles` / `nodes.at` references
    // that are not covered by more specific rules.

    for (role_name, role_def) in &model.roles {
        check_refs(
            role_def.allow.iter().map(String::as_str),
            &model.groups,
            Rule::CrossReferences,
            |name| format!("Role '{role_name}' references undefined group '{name}'"),
            out,
        );
    }

    for (user_name, user_def) in &model.users {
        check_refs(
            user_def.roles.iter().map(String::as_str),
            &model.roles,
            Rule::CrossReferences,
            |name| format!("User '{user_name}' references undefined role '{name}'"),
            out,
        );
        check_refs(
            user_def.nodes.iter().map(|e| e.at.as_str()),
            &model.nodes,
            Rule::CrossReferences,
            |name| format!("User '{user_name}' references undefined node '{name}'"),
            out,
        );
    }

    for (svc_name, svc_def) in &model.services {
        check_refs(
            svc_def.groups.iter().map(String::as_str),
            &model.groups,
            Rule::CrossReferences,
            |name| format!("Service '{svc_name}' references undefined group '{name}'"),
            out,
        );
        check_refs(
            svc_def.roles.iter().map(String::as_str),
            &model.roles,
            Rule::CrossReferences,
            |name| format!("Service '{svc_name}' references undefined role '{name}'"),
            out,
        );
    }
}

fn check_refs<'a, V>(
    names: impl Iterator<Item = &'a str>,
    map: &std::collections::HashMap<String, V>,
    rule: Rule,
    make_msg: impl Fn(&str) -> String,
    out: &mut Vec<Violation>,
) {
    for name in names {
        if !map.contains_key(name) {
            out.push(Violation {
                rule,
                message: make_msg(name),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Rule::PrincipalRegistry — cross-kind name uniqueness
// ---------------------------------------------------------------------------

fn check_principal_registry(model: &RepoModel, out: &mut Vec<Violation>) {
    // Users, services, and nodes must not share a name across kinds.
    for name in model.users.keys() {
        if model.services.contains_key(name) {
            out.push(Violation {
                rule: Rule::PrincipalRegistry,
                message: format!("Name '{name}' is used by both a user and a service"),
            });
        }
        if model.nodes.contains_key(name) {
            out.push(Violation {
                rule: Rule::PrincipalRegistry,
                message: format!("Name '{name}' is used by both a user and a node"),
            });
        }
    }
    for name in model.services.keys() {
        if model.nodes.contains_key(name) {
            out.push(Violation {
                rule: Rule::PrincipalRegistry,
                message: format!("Name '{name}' is used by both a service and a node"),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Rule::ServicePlacement
// ---------------------------------------------------------------------------

fn check_service_placement(model: &RepoModel, out: &mut Vec<Violation>) {
    for (svc_name, svc_def) in &model.services {
        check_refs(
            std::iter::once(svc_def.at.as_str()),
            &model.nodes,
            Rule::ServicePlacement,
            |name| format!("Service '{svc_name}' is placed `at` undefined node '{name}'"),
            out,
        );
    }
}

// ---------------------------------------------------------------------------
// Rule::ManagementNodeIntegrity
// ---------------------------------------------------------------------------

fn check_management_node_integrity(model: &RepoModel, out: &mut Vec<Violation>) {
    let config_server = model.services.get(SVC_CONFIG_SERVER);
    let config_publisher = model.services.get(SVC_CONFIG_PUBLISHER);

    if config_server.is_none() {
        out.push(Violation {
            rule: Rule::ManagementNodeIntegrity,
            message: format!("Service '{SVC_CONFIG_SERVER}' is missing"),
        });
    }
    if config_publisher.is_none() {
        out.push(Violation {
            rule: Rule::ManagementNodeIntegrity,
            message: format!("Service '{SVC_CONFIG_PUBLISHER}' is missing"),
        });
    }
    let (Some(cs), Some(cp)) = (config_server, config_publisher) else {
        return;
    };

    // config-server must be in config-read group
    if !cs.groups.iter().any(|g| g == GROUP_CONFIG_READ) {
        out.push(Violation {
            rule: Rule::ManagementNodeIntegrity,
            message: format!(
                "Service '{SVC_CONFIG_SERVER}' must belong to group '{GROUP_CONFIG_READ}'"
            ),
        });
    }

    // config-publisher must be in config-write group
    if !cp.groups.iter().any(|g| g == GROUP_CONFIG_WRITE) {
        out.push(Violation {
            rule: Rule::ManagementNodeIntegrity,
            message: format!(
                "Service '{SVC_CONFIG_PUBLISHER}' must belong to group '{GROUP_CONFIG_WRITE}'"
            ),
        });
    }

    // Both must be on the same node
    if cs.at != cp.at {
        out.push(Violation {
            rule: Rule::ManagementNodeIntegrity,
            message: format!(
                "Config-server is on node '{}' but config-publisher is on node '{}'; \
                 both must be on the same management node",
                cs.at, cp.at
            ),
        });
        // Can't check the node's reachability without knowing which node is the mgmt node
        return;
    }

    let mgmt_node_name = &cs.at;

    // The management node must have a publicly-reachable QUIC link-vertex
    match model.nodes.get(mgmt_node_name) {
        None => {
            // Already caught by `Rule::ServicePlacement`; skip to avoid duplicating the message
        }
        Some(node_def) => {
            let has_reachable_quic_link = node_def.vertices.iter().any(|v| {
                v.kind == VertexKind::Link
                    && v.vertex_type == VertexType::Quic
                    && v.address.is_some()
            });
            if !has_reachable_quic_link {
                out.push(Violation {
                    rule: Rule::ManagementNodeIntegrity,
                    message: format!(
                        "Management node '{mgmt_node_name}' must have a \
                         kind: link, type: quic vertex with a public `address`"
                    ),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rule::ReservedNameProtection
// ---------------------------------------------------------------------------

fn check_reserved_name_protection(model: &RepoModel, out: &mut Vec<Violation>) {
    // Reserved roles
    match model.roles.get(ROLE_NODE) {
        None => out.push(Violation {
            rule: Rule::ReservedNameProtection,
            message: format!("Reserved role '{ROLE_NODE}' is missing"),
        }),
        Some(def) => {
            if def.allow != [GROUP_CONFIG_READ] {
                out.push(Violation {
                    rule: Rule::ReservedNameProtection,
                    message: format!(
                        "Reserved role '{ROLE_NODE}' must have `allow: [{GROUP_CONFIG_READ}]`, \
                         got: {:?}",
                        def.allow
                    ),
                });
            }
        }
    }

    match model.roles.get(ROLE_OPERATOR) {
        None => out.push(Violation {
            rule: Rule::ReservedNameProtection,
            message: format!("Reserved role '{ROLE_OPERATOR}' is missing"),
        }),
        Some(def) => {
            if def.allow != [GROUP_CONFIG_WRITE] {
                out.push(Violation {
                    rule: Rule::ReservedNameProtection,
                    message: format!(
                        "Reserved role '{ROLE_OPERATOR}' must have `allow: [{GROUP_CONFIG_WRITE}]`, \
                         got: {:?}",
                        def.allow
                    ),
                });
            }
        }
    }

    // Reserved groups
    if !model.groups.contains_key(GROUP_CONFIG_READ) {
        out.push(Violation {
            rule: Rule::ReservedNameProtection,
            message: format!("Reserved group '{GROUP_CONFIG_READ}' is missing"),
        });
    }
    if !model.groups.contains_key(GROUP_CONFIG_WRITE) {
        out.push(Violation {
            rule: Rule::ReservedNameProtection,
            message: format!("Reserved group '{GROUP_CONFIG_WRITE}' is missing"),
        });
    }
}

// ---------------------------------------------------------------------------
// Rule::OperatorPresence
// ---------------------------------------------------------------------------

fn check_operator_presence(model: &RepoModel, out: &mut Vec<Violation>) {
    let has_operator = model
        .users
        .values()
        .any(|u| u.roles.iter().any(|r| r == ROLE_OPERATOR));

    if !has_operator {
        out.push(Violation {
            rule: Rule::OperatorPresence,
            message: "No user has the 'operator' role; \
                      at least one operator is required to push new rete state"
                .into(),
        });
    }
}

// ---------------------------------------------------------------------------
// Rule::VertexGraphReachability
// ---------------------------------------------------------------------------

fn check_vertex_graph_reachability(model: &RepoModel, out: &mut Vec<Violation>) {
    // Build the set of nodes that host at least one non-config-read workload service.
    let workload_nodes: std::collections::HashSet<&str> = model
        .services
        .values()
        .filter(|svc| !svc.groups.iter().any(|g| g == GROUP_CONFIG_READ))
        .map(|svc| svc.at.as_str())
        .collect();

    for (node_name, node_def) in &model.nodes {
        // Must have at least one link-vertex of any type.
        let has_any_link = node_def.vertices.iter().any(|v| v.kind == VertexKind::Link);
        if !has_any_link {
            out.push(Violation {
                rule: Rule::VertexGraphReachability,
                message: format!("Node '{node_name}' has no link-vertex"),
            });
            continue;
        }

        // C0: every node must have exactly one kind:link, type:quic vertex.
        let quic_links: Vec<_> = node_def
            .vertices
            .iter()
            .filter(|v| v.kind == VertexKind::Link && v.vertex_type == VertexType::Quic)
            .collect();

        if quic_links.is_empty() {
            out.push(Violation {
                rule: Rule::VertexGraphReachability,
                message: format!(
                    "Node '{node_name}' has no link-vertex of type quic; \
                     C0 requires kind: link, type: quic"
                ),
            });
            continue;
        }

        if quic_links.len() > 1 {
            out.push(Violation {
                rule: Rule::VertexGraphReachability,
                message: format!(
                    "Node '{node_name}' has {} link-vertices of type quic; \
                     C0 requires exactly one",
                    quic_links.len()
                ),
            });
        }

        // Workload-hosting nodes must have a public address on their quic link-vertex.
        if workload_nodes.contains(node_name.as_str()) {
            let has_address = quic_links.iter().any(|v| v.address.is_some());
            if !has_address {
                out.push(Violation {
                    rule: Rule::VertexGraphReachability,
                    message: format!(
                        "Node '{node_name}' hosts workload services but its \
                         link-vertex has no public `address` (initiator-only \
                         nodes cannot host services)"
                    ),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rule::WorkloadVertexBinding
// ---------------------------------------------------------------------------

fn check_workload_vertex_binding(model: &RepoModel, out: &mut Vec<Violation>) {
    // Services
    for (svc_name, svc_def) in &model.services {
        let Some(node_def) = model.nodes.get(&svc_def.at) else {
            // Already flagged by `Rule::ServicePlacement`
            continue;
        };
        check_via_resolution(
            &format!("Service '{svc_name}'"),
            svc_def.via.as_deref(),
            node_def,
            out,
            Rule::WorkloadVertexBinding,
        );
    }

    // User device entries
    for (user_name, user_def) in &model.users {
        for node_entry in &user_def.nodes {
            let Some(node_def) = model.nodes.get(&node_entry.at) else {
                // Already flagged by `Rule::CrossReferences`
                continue;
            };
            check_via_resolution(
                &format!("User '{user_name}' (node entry `at: {}`)", node_entry.at),
                node_entry.via.as_deref(),
                node_def,
                out,
                Rule::WorkloadVertexBinding,
            );
        }
    }
}

fn check_via_resolution(
    subject: &str,
    via: Option<&str>,
    node_def: &super::model::Node,
    out: &mut Vec<Violation>,
    rule: Rule,
) {
    let vertex_names: Vec<&str> = node_def.vertices.iter().map(|v| v.name.as_str()).collect();

    if let Some(via_name) = via {
        if !vertex_names.contains(&via_name) {
            out.push(Violation {
                rule,
                message: format!(
                    "{subject} specifies `via: {via_name}` but that vertex \
                     does not exist; available: [{}]",
                    vertex_names.join(", ")
                ),
            });
        }
    } else if vertex_names.len() > 1 {
        // Multiple vertices and no `via` — ambiguous in C1+; currently always
        // valid in C0 (every node has exactly one vertex) but we enforce the
        // rule now so configs that work today remain valid in C1.
        out.push(Violation {
            rule,
            message: format!(
                "{subject} must specify `via:` to disambiguate among [{}]",
                vertex_names.join(", ")
            ),
        });
    }
}

// ---------------------------------------------------------------------------
// Rule::PrincipalRoleCoherence
// ---------------------------------------------------------------------------

fn check_principal_role_coherence(model: &RepoModel, out: &mut Vec<Violation>) {
    // A service that acts as a client (has `socks5_proxy`) must declare `roles`.
    // Services without `roles` may only be targets.
    for (svc_name, svc_def) in &model.services {
        if svc_def.socks5_proxy.is_some() && svc_def.roles.is_empty() {
            out.push(Violation {
                rule: Rule::PrincipalRoleCoherence,
                message: format!(
                    "Service '{svc_name}' has `socks5_proxy` (acts as a client) \
                     but declares no `roles`; add a `roles:` entry to grant egress access"
                ),
            });
        }
    }
}
