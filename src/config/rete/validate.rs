// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Validation rules run on the merged `RepoModel`.
//!
//! Some checks are enforced during parsing/merging or subsumed by other rules.
//! Enrollment log and mgmt-plane signer cert checks are deferred.

use std::fmt;

use super::model::{RepoModel, VertexKind, VertexType};

use super::reserved::{
    GROUP_COORDINATOR_PUBLISH, GROUP_COORDINATOR_SYNC, ROLE_NODE, ROLE_OPERATOR, SVC_COORDINATOR,
    SVC_COORDINATOR_PUBLISHER,
};

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
    /// Coordinator and coordinator-publisher coexist on one reachable mgmt node.
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
    /// No two local SOCKS5 listeners on a node share an address.
    LocalPortUniqueness,
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
            Rule::LocalPortUniqueness => "local-port uniqueness",
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
    check_local_port_uniqueness(model, &mut out);
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
    let coordinator = model.services.get(SVC_COORDINATOR);
    let coordinator_publisher = model.services.get(SVC_COORDINATOR_PUBLISHER);

    if coordinator.is_none() {
        out.push(Violation {
            rule: Rule::ManagementNodeIntegrity,
            message: format!("Service '{SVC_COORDINATOR}' is missing"),
        });
    }
    if coordinator_publisher.is_none() {
        out.push(Violation {
            rule: Rule::ManagementNodeIntegrity,
            message: format!("Service '{SVC_COORDINATOR_PUBLISHER}' is missing"),
        });
    }
    let (Some(cs), Some(cp)) = (coordinator, coordinator_publisher) else {
        return;
    };

    // coordinator must be in coordinator-sync group
    if !cs.groups.iter().any(|g| g == GROUP_COORDINATOR_SYNC) {
        out.push(Violation {
            rule: Rule::ManagementNodeIntegrity,
            message: format!(
                "Service '{SVC_COORDINATOR}' must belong to group '{GROUP_COORDINATOR_SYNC}'"
            ),
        });
    }

    // coordinator-publisher must be in coordinator-publish group
    if !cp.groups.iter().any(|g| g == GROUP_COORDINATOR_PUBLISH) {
        out.push(Violation {
            rule: Rule::ManagementNodeIntegrity,
            message: format!(
                "Service '{SVC_COORDINATOR_PUBLISHER}' must belong to group '{GROUP_COORDINATOR_PUBLISH}'"
            ),
        });
    }

    // Both must be on the same node
    if cs.at != cp.at {
        out.push(Violation {
            rule: Rule::ManagementNodeIntegrity,
            message: format!(
                "Coordinator is on node '{}' but coordinator-publisher is on node '{}'; \
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
            if def.allow != [GROUP_COORDINATOR_SYNC] {
                out.push(Violation {
                    rule: Rule::ReservedNameProtection,
                    message: format!(
                        "Reserved role '{ROLE_NODE}' must have `allow: [{GROUP_COORDINATOR_SYNC}]`, \
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
            if def.allow != [GROUP_COORDINATOR_PUBLISH] {
                out.push(Violation {
                    rule: Rule::ReservedNameProtection,
                    message: format!(
                        "Reserved role '{ROLE_OPERATOR}' must have `allow: [{GROUP_COORDINATOR_PUBLISH}]`, \
                         got: {:?}",
                        def.allow
                    ),
                });
            }
        }
    }

    // Reserved groups
    if !model.groups.contains_key(GROUP_COORDINATOR_SYNC) {
        out.push(Violation {
            rule: Rule::ReservedNameProtection,
            message: format!("Reserved group '{GROUP_COORDINATOR_SYNC}' is missing"),
        });
    }
    if !model.groups.contains_key(GROUP_COORDINATOR_PUBLISH) {
        out.push(Violation {
            rule: Rule::ReservedNameProtection,
            message: format!("Reserved group '{GROUP_COORDINATOR_PUBLISH}' is missing"),
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
    // Build the set of nodes that host at least one non-management workload service.
    // Both coordinator-sync (coordinator) and coordinator-publish (coordinator-publisher) are management
    // infrastructure; their node's address requirement is enforced by ManagementNodeIntegrity.
    let workload_nodes: std::collections::HashSet<&str> = model
        .services
        .values()
        .filter(|svc| {
            !svc.groups
                .iter()
                .any(|g| g == GROUP_COORDINATOR_SYNC || g == GROUP_COORDINATOR_PUBLISH)
        })
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

// ---------------------------------------------------------------------------
// Rule::LocalPortUniqueness
// ---------------------------------------------------------------------------

fn check_local_port_uniqueness(model: &RepoModel, out: &mut Vec<Violation>) {
    // Services and user devices each declare a loopback SOCKS5 listener. On a
    // given node no two may share an address, or the second would fail to bind.
    // (The node agent's listener is allocated by the compiler to avoid these,
    // so it never participates.)
    use std::collections::HashMap;
    use std::collections::hash_map::Entry;
    use std::net::SocketAddr;

    // (node, listen) -> the subject that first claimed it.
    let mut claimed: HashMap<(&str, SocketAddr), String> = HashMap::new();

    let listeners = model
        .services
        .iter()
        .filter_map(|(name, svc)| {
            svc.socks5_proxy
                .map(|listen| (svc.at.as_str(), listen, format!("service '{name}'")))
        })
        .chain(model.users.iter().flat_map(|(name, user)| {
            user.nodes.iter().map(move |entry| {
                (
                    entry.at.as_str(),
                    entry.socks5_proxy,
                    format!("user '{name}' (device on '{}')", entry.at),
                )
            })
        }));

    for (node, listen, subject) in listeners {
        match claimed.entry((node, listen)) {
            Entry::Occupied(prior) => out.push(Violation {
                rule: Rule::LocalPortUniqueness,
                message: format!(
                    "SOCKS5 listener {listen} on node '{node}' is claimed by both \
                     {} and {subject}",
                    prior.get()
                ),
            }),
            Entry::Vacant(slot) => {
                slot.insert(subject);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use super::super::model::{
        Ca, Group, MgmtSigners, Node, RepoModel, Rete, Role, Service, Signers, User, UserNode,
        Vertex, VertexKind, VertexType,
    };
    use super::{Rule, Violation, validate};

    fn make_rete() -> Rete {
        Rete {
            name: "test-rete".into(),
            ca: Ca {
                cert: PathBuf::from("ca.pem"),
                validity_days: None,
            },
            signers: Signers {
                mgmt: MgmtSigners {
                    validity_days: None,
                    keys: vec![],
                },
            },
            tls_principals: None,
        }
    }

    fn quic_link_vertex(name: &str, address: Option<&str>) -> Vertex {
        Vertex {
            name: name.into(),
            kind: VertexKind::Link,
            vertex_type: VertexType::Quic,
            address: address.map(|a| a.parse().unwrap()),
        }
    }

    fn node_with_quic_link(vertex_name: &str, address: Option<&str>) -> Node {
        Node {
            vertices: vec![quic_link_vertex(vertex_name, address)],
        }
    }

    fn mgmt_service(node: &str, groups: Vec<&str>) -> Service {
        Service {
            at: node.into(),
            via: None,
            addr: "127.0.0.1:9000".parse().unwrap(),
            socks5_proxy: None,
            groups: groups.into_iter().map(String::from).collect(),
            roles: vec![],
            scope: None,
        }
    }

    fn minimal_valid_model() -> RepoModel {
        let mut nodes = HashMap::new();
        nodes.insert(
            "mgmt".into(),
            node_with_quic_link("quic0", Some("1.2.3.4:4433")),
        );

        let mut services = HashMap::new();
        services.insert(
            "coordinator".into(),
            mgmt_service("mgmt", vec!["coordinator-sync"]),
        );
        services.insert(
            "coordinator-publisher".into(),
            mgmt_service("mgmt", vec!["coordinator-publish"]),
        );

        let mut groups: HashMap<String, Option<Group>> = HashMap::new();
        groups.insert("coordinator-sync".into(), None);
        groups.insert("coordinator-publish".into(), None);

        let mut roles = HashMap::new();
        roles.insert(
            "node".into(),
            Role {
                allow: vec!["coordinator-sync".into()],
            },
        );
        roles.insert(
            "operator".into(),
            Role {
                allow: vec!["coordinator-publish".into()],
            },
        );

        let mut users = HashMap::new();
        users.insert(
            "alice".into(),
            User {
                roles: vec!["operator".into()],
                nodes: vec![],
            },
        );

        RepoModel {
            rete: make_rete(),
            nodes,
            services,
            groups,
            roles,
            users,
        }
    }

    fn count(violations: &[Violation], rule: Rule) -> usize {
        violations.iter().filter(|v| v.rule == rule).count()
    }

    // -----------------------------------------------------------------------
    // Happy path
    // -----------------------------------------------------------------------

    #[test]
    fn valid_model_has_no_violations() {
        let model = minimal_valid_model();
        let violations = validate(&model);
        assert!(
            violations.is_empty(),
            "expected no violations, got: {:?}",
            violations.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    // -----------------------------------------------------------------------
    // Rule::CrossReferences
    // -----------------------------------------------------------------------

    #[test]
    fn cross_references_role_allow_undefined_group() {
        let mut model = minimal_valid_model();
        model.roles.insert(
            "bad-role".into(),
            Role {
                allow: vec!["nonexistent-group".into()],
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::CrossReferences), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::CrossReferences)
                .unwrap()
                .message
                .contains("nonexistent-group")
        );
    }

    #[test]
    fn cross_references_user_undefined_role() {
        let mut model = minimal_valid_model();
        model.users.insert(
            "bob".into(),
            User {
                roles: vec!["ghost-role".into()],
                nodes: vec![],
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::CrossReferences), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::CrossReferences)
                .unwrap()
                .message
                .contains("ghost-role")
        );
    }

    #[test]
    fn cross_references_user_undefined_node() {
        let mut model = minimal_valid_model();
        model.users.insert(
            "bob".into(),
            User {
                roles: vec![],
                nodes: vec![UserNode {
                    at: "ghost-node".into(),
                    via: None,
                    socks5_proxy: "127.0.0.1:1080".parse().unwrap(),
                }],
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::CrossReferences), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::CrossReferences)
                .unwrap()
                .message
                .contains("ghost-node")
        );
    }

    #[test]
    fn cross_references_service_undefined_group() {
        let mut model = minimal_valid_model();
        model.services.insert(
            "my-svc".into(),
            Service {
                at: "mgmt".into(),
                via: None,
                addr: "127.0.0.1:8080".parse().unwrap(),
                socks5_proxy: None,
                groups: vec!["ghost-group".into()],
                roles: vec![],
                scope: None,
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::CrossReferences), 1);
        assert!(violations[0].message.contains("ghost-group"));
    }

    #[test]
    fn cross_references_service_undefined_role() {
        let mut model = minimal_valid_model();
        model.services.insert(
            "my-svc".into(),
            Service {
                at: "mgmt".into(),
                via: None,
                addr: "127.0.0.1:8080".parse().unwrap(),
                socks5_proxy: None,
                groups: vec![],
                roles: vec!["ghost-role".into()],
                scope: None,
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::CrossReferences), 1);
        assert!(violations[0].message.contains("ghost-role"));
    }

    // -----------------------------------------------------------------------
    // Rule::PrincipalRegistry
    // -----------------------------------------------------------------------

    #[test]
    fn principal_registry_user_service_name_collision() {
        let mut model = minimal_valid_model();
        model.services.insert(
            "alice".into(),
            Service {
                at: "mgmt".into(),
                via: None,
                addr: "127.0.0.1:8080".parse().unwrap(),
                socks5_proxy: None,
                groups: vec![],
                roles: vec![],
                scope: None,
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::PrincipalRegistry), 1);
        assert!(
            violations
                .iter()
                .any(|v| v.rule == Rule::PrincipalRegistry && v.message.contains("alice"))
        );
    }

    #[test]
    fn principal_registry_user_node_name_collision() {
        let mut model = minimal_valid_model();
        model.nodes.insert(
            "alice".into(),
            node_with_quic_link("quic0", Some("1.2.3.4:4433")),
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::PrincipalRegistry), 1);
        assert!(
            violations
                .iter()
                .any(|v| v.rule == Rule::PrincipalRegistry && v.message.contains("alice"))
        );
    }

    #[test]
    fn principal_registry_service_node_name_collision() {
        let mut model = minimal_valid_model();
        model.nodes.insert(
            "coordinator".into(),
            node_with_quic_link("quic0", Some("5.6.7.8:4433")),
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::PrincipalRegistry), 1);
        assert!(
            violations
                .iter()
                .any(|v| v.rule == Rule::PrincipalRegistry && v.message.contains("coordinator"))
        );
    }

    // -----------------------------------------------------------------------
    // Rule::ServicePlacement
    // -----------------------------------------------------------------------

    #[test]
    fn service_placement_undefined_node() {
        let mut model = minimal_valid_model();
        model.services.insert(
            "orphan-svc".into(),
            Service {
                at: "nonexistent-node".into(),
                via: None,
                addr: "127.0.0.1:8080".parse().unwrap(),
                socks5_proxy: None,
                groups: vec![],
                roles: vec![],
                scope: None,
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::ServicePlacement), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::ServicePlacement)
                .unwrap()
                .message
                .contains("nonexistent-node")
        );
    }

    // -----------------------------------------------------------------------
    // Rule::ManagementNodeIntegrity
    // -----------------------------------------------------------------------

    #[test]
    fn management_node_integrity_missing_coordinator() {
        let mut model = minimal_valid_model();
        model.services.remove("coordinator");
        let violations = validate(&model);
        assert!(count(&violations, Rule::ManagementNodeIntegrity) >= 1);
        assert!(
            violations
                .iter()
                .any(|v| v.rule == Rule::ManagementNodeIntegrity
                    && v.message.contains("coordinator"))
        );
    }

    #[test]
    fn management_node_integrity_missing_coordinator_publisher() {
        let mut model = minimal_valid_model();
        model.services.remove("coordinator-publisher");
        let violations = validate(&model);
        assert!(count(&violations, Rule::ManagementNodeIntegrity) >= 1);
        assert!(
            violations
                .iter()
                .any(|v| v.rule == Rule::ManagementNodeIntegrity
                    && v.message.contains("coordinator-publisher"))
        );
    }

    #[test]
    fn management_node_integrity_server_not_in_coordinator_sync_group() {
        let mut model = minimal_valid_model();
        model
            .services
            .insert("coordinator".into(), mgmt_service("mgmt", vec![]));
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::ManagementNodeIntegrity), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::ManagementNodeIntegrity)
                .unwrap()
                .message
                .contains("coordinator-sync")
        );
    }

    #[test]
    fn management_node_integrity_publisher_not_in_coordinator_publish_group() {
        let mut model = minimal_valid_model();
        model
            .services
            .insert("coordinator-publisher".into(), mgmt_service("mgmt", vec![]));
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::ManagementNodeIntegrity), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::ManagementNodeIntegrity)
                .unwrap()
                .message
                .contains("coordinator-publish")
        );
    }

    #[test]
    fn management_node_integrity_server_and_publisher_on_different_nodes() {
        let mut model = minimal_valid_model();
        model.nodes.insert(
            "other".into(),
            node_with_quic_link("quic0", Some("9.9.9.9:4433")),
        );
        model.services.insert(
            "coordinator-publisher".into(),
            mgmt_service("other", vec!["coordinator-publish"]),
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::ManagementNodeIntegrity), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::ManagementNodeIntegrity)
                .unwrap()
                .message
                .contains("same management node")
        );
    }

    #[test]
    fn management_node_integrity_mgmt_node_no_public_quic_link() {
        let mut model = minimal_valid_model();
        model
            .nodes
            .insert("mgmt".into(), node_with_quic_link("quic0", None));
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::ManagementNodeIntegrity), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::ManagementNodeIntegrity)
                .unwrap()
                .message
                .contains("public `address`")
        );
    }

    // -----------------------------------------------------------------------
    // Rule::ReservedNameProtection
    // -----------------------------------------------------------------------

    #[test]
    fn reserved_name_protection_missing_node_role() {
        let mut model = minimal_valid_model();
        model.roles.remove("node");
        let violations = validate(&model);
        assert!(count(&violations, Rule::ReservedNameProtection) >= 1);
        assert!(
            violations
                .iter()
                .any(|v| v.rule == Rule::ReservedNameProtection && v.message.contains("'node'"))
        );
    }

    #[test]
    fn reserved_name_protection_node_role_wrong_allow() {
        let mut model = minimal_valid_model();
        model.roles.insert(
            "node".into(),
            Role {
                allow: vec!["coordinator-publish".into()],
            },
        );
        let violations = validate(&model);
        assert!(count(&violations, Rule::ReservedNameProtection) >= 1);
        assert!(
            violations
                .iter()
                .any(|v| v.rule == Rule::ReservedNameProtection && v.message.contains("'node'"))
        );
    }

    #[test]
    fn reserved_name_protection_missing_operator_role() {
        let mut model = minimal_valid_model();
        model.roles.remove("operator");
        let violations = validate(&model);
        assert!(count(&violations, Rule::ReservedNameProtection) >= 1);
        assert!(violations.iter().any(|v| v.rule == Rule::ReservedNameProtection
            && v.message.contains("'operator'")));
    }

    #[test]
    fn reserved_name_protection_operator_role_wrong_allow() {
        let mut model = minimal_valid_model();
        model.roles.insert(
            "operator".into(),
            Role {
                allow: vec!["coordinator-sync".into()],
            },
        );
        let violations = validate(&model);
        assert!(count(&violations, Rule::ReservedNameProtection) >= 1);
        assert!(violations.iter().any(|v| v.rule == Rule::ReservedNameProtection
            && v.message.contains("'operator'")));
    }

    #[test]
    fn reserved_name_protection_missing_coordinator_sync_group() {
        let mut model = minimal_valid_model();
        model.groups.remove("coordinator-sync");
        let violations = validate(&model);
        assert!(count(&violations, Rule::ReservedNameProtection) >= 1);
        assert!(
            violations
                .iter()
                .any(|v| v.rule == Rule::ReservedNameProtection
                    && v.message.contains("coordinator-sync"))
        );
    }

    #[test]
    fn reserved_name_protection_missing_coordinator_publish_group() {
        let mut model = minimal_valid_model();
        model.groups.remove("coordinator-publish");
        let violations = validate(&model);
        assert!(count(&violations, Rule::ReservedNameProtection) >= 1);
        assert!(
            violations
                .iter()
                .any(|v| v.rule == Rule::ReservedNameProtection
                    && v.message.contains("coordinator-publish"))
        );
    }

    // -----------------------------------------------------------------------
    // Rule::OperatorPresence
    // -----------------------------------------------------------------------

    #[test]
    fn operator_presence_no_user_holds_operator_role() {
        let mut model = minimal_valid_model();
        model.users.insert(
            "alice".into(),
            User {
                roles: vec![],
                nodes: vec![],
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::OperatorPresence), 1);
    }

    #[test]
    fn operator_presence_at_least_one_operator_passes() {
        let model = minimal_valid_model();
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::OperatorPresence), 0);
    }

    // -----------------------------------------------------------------------
    // Rule::VertexGraphReachability
    // -----------------------------------------------------------------------

    #[test]
    fn vertex_graph_reachability_node_with_no_link_vertex() {
        let mut model = minimal_valid_model();
        model.nodes.insert(
            "no-link".into(),
            Node {
                vertices: vec![Vertex {
                    name: "mesh0".into(),
                    kind: VertexKind::Mesh,
                    vertex_type: VertexType::Udp,
                    address: None,
                }],
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::VertexGraphReachability), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::VertexGraphReachability)
                .unwrap()
                .message
                .contains("no link-vertex")
        );
    }

    #[test]
    fn vertex_graph_reachability_node_with_no_quic_link_vertex() {
        let mut model = minimal_valid_model();
        model.nodes.insert(
            "udp-only".into(),
            Node {
                vertices: vec![Vertex {
                    name: "link0".into(),
                    kind: VertexKind::Link,
                    vertex_type: VertexType::Udp,
                    address: Some("1.2.3.4:5000".parse().unwrap()),
                }],
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::VertexGraphReachability), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::VertexGraphReachability)
                .unwrap()
                .message
                .contains("type quic")
        );
    }

    #[test]
    fn vertex_graph_reachability_multiple_quic_link_vertices() {
        let mut model = minimal_valid_model();
        model.nodes.insert(
            "dual-quic".into(),
            Node {
                vertices: vec![
                    quic_link_vertex("quic0", Some("1.2.3.4:4433")),
                    quic_link_vertex("quic1", Some("5.6.7.8:4433")),
                ],
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::VertexGraphReachability), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::VertexGraphReachability)
                .unwrap()
                .message
                .contains("exactly one")
        );
    }

    #[test]
    fn vertex_graph_reachability_workload_node_no_public_address() {
        let mut model = minimal_valid_model();
        model
            .nodes
            .insert("worker".into(), node_with_quic_link("quic0", None));
        // Service with no management groups → worker is a workload node
        model.services.insert(
            "my-app".into(),
            Service {
                at: "worker".into(),
                via: None,
                addr: "127.0.0.1:8080".parse().unwrap(),
                socks5_proxy: None,
                groups: vec![],
                roles: vec![],
                scope: None,
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::VertexGraphReachability), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::VertexGraphReachability)
                .unwrap()
                .message
                .contains("no public `address`")
        );
    }

    // -----------------------------------------------------------------------
    // Rule::WorkloadVertexBinding
    // -----------------------------------------------------------------------

    #[test]
    fn workload_vertex_binding_service_via_undefined_vertex() {
        let mut model = minimal_valid_model();
        model.services.insert(
            "my-svc".into(),
            Service {
                at: "mgmt".into(),
                via: Some("ghost-vertex".into()),
                addr: "127.0.0.1:8080".parse().unwrap(),
                socks5_proxy: None,
                groups: vec![],
                roles: vec![],
                scope: None,
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::WorkloadVertexBinding), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::WorkloadVertexBinding)
                .unwrap()
                .message
                .contains("ghost-vertex")
        );
    }

    #[test]
    fn workload_vertex_binding_service_multi_vertex_node_without_via() {
        let mut model = minimal_valid_model();
        model.nodes.insert(
            "multi".into(),
            Node {
                vertices: vec![
                    quic_link_vertex("quic0", Some("1.2.3.4:4433")),
                    Vertex {
                        name: "mesh0".into(),
                        kind: VertexKind::Mesh,
                        vertex_type: VertexType::Udp,
                        address: None,
                    },
                ],
            },
        );
        model.services.insert(
            "my-svc".into(),
            Service {
                at: "multi".into(),
                via: None,
                addr: "127.0.0.1:8080".parse().unwrap(),
                socks5_proxy: None,
                groups: vec![],
                roles: vec![],
                scope: None,
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::WorkloadVertexBinding), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::WorkloadVertexBinding)
                .unwrap()
                .message
                .contains("via:")
        );
    }

    #[test]
    fn workload_vertex_binding_user_via_undefined_vertex() {
        let mut model = minimal_valid_model();
        model.users.insert(
            "bob".into(),
            User {
                roles: vec![],
                nodes: vec![UserNode {
                    at: "mgmt".into(),
                    via: Some("ghost-vertex".into()),
                    socks5_proxy: "127.0.0.1:1080".parse().unwrap(),
                }],
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::WorkloadVertexBinding), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::WorkloadVertexBinding)
                .unwrap()
                .message
                .contains("ghost-vertex")
        );
    }

    #[test]
    fn workload_vertex_binding_user_multi_vertex_node_without_via() {
        let mut model = minimal_valid_model();
        model.nodes.insert(
            "multi".into(),
            Node {
                vertices: vec![
                    quic_link_vertex("quic0", Some("1.2.3.4:4433")),
                    Vertex {
                        name: "mesh0".into(),
                        kind: VertexKind::Mesh,
                        vertex_type: VertexType::Udp,
                        address: None,
                    },
                ],
            },
        );
        model.users.insert(
            "bob".into(),
            User {
                roles: vec![],
                nodes: vec![UserNode {
                    at: "multi".into(),
                    via: None,
                    socks5_proxy: "127.0.0.1:1080".parse().unwrap(),
                }],
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::WorkloadVertexBinding), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::WorkloadVertexBinding)
                .unwrap()
                .message
                .contains("via:")
        );
    }

    // -----------------------------------------------------------------------
    // Rule::PrincipalRoleCoherence
    // -----------------------------------------------------------------------

    #[test]
    fn principal_role_coherence_socks5_proxy_without_roles() {
        let mut model = minimal_valid_model();
        model.services.insert(
            "client-svc".into(),
            Service {
                at: "mgmt".into(),
                via: None,
                addr: "127.0.0.1:8080".parse().unwrap(),
                socks5_proxy: Some("127.0.0.1:1080".parse().unwrap()),
                groups: vec![],
                roles: vec![],
                scope: None,
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::PrincipalRoleCoherence), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::PrincipalRoleCoherence)
                .unwrap()
                .message
                .contains("client-svc")
        );
    }

    #[test]
    fn principal_role_coherence_socks5_proxy_with_roles_passes() {
        let mut model = minimal_valid_model();
        model.services.insert(
            "client-svc".into(),
            Service {
                at: "mgmt".into(),
                via: None,
                addr: "127.0.0.1:8080".parse().unwrap(),
                socks5_proxy: Some("127.0.0.1:1080".parse().unwrap()),
                groups: vec![],
                roles: vec!["node".into()],
                scope: None,
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::PrincipalRoleCoherence), 0);
    }

    // -----------------------------------------------------------------------
    // Rule::LocalPortUniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn local_port_uniqueness_two_users_on_a_node_share_a_port() {
        let mut model = minimal_valid_model();
        for name in ["bob", "carol"] {
            model.users.insert(
                name.into(),
                User {
                    roles: vec![],
                    nodes: vec![UserNode {
                        at: "mgmt".into(),
                        via: None,
                        socks5_proxy: "127.0.0.1:1080".parse().unwrap(),
                    }],
                },
            );
        }
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::LocalPortUniqueness), 1);
        assert!(
            violations
                .iter()
                .find(|v| v.rule == Rule::LocalPortUniqueness)
                .unwrap()
                .message
                .contains("127.0.0.1:1080")
        );
    }

    #[test]
    fn local_port_uniqueness_user_and_service_share_a_port() {
        let mut model = minimal_valid_model();
        model.services.insert(
            "client-svc".into(),
            Service {
                at: "mgmt".into(),
                via: None,
                addr: "127.0.0.1:8080".parse().unwrap(),
                socks5_proxy: Some("127.0.0.1:1080".parse().unwrap()),
                groups: vec![],
                roles: vec!["node".into()],
                scope: None,
            },
        );
        model.users.insert(
            "bob".into(),
            User {
                roles: vec![],
                nodes: vec![UserNode {
                    at: "mgmt".into(),
                    via: None,
                    socks5_proxy: "127.0.0.1:1080".parse().unwrap(),
                }],
            },
        );
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::LocalPortUniqueness), 1);
    }

    #[test]
    fn local_port_uniqueness_same_port_on_different_nodes_passes() {
        let mut model = minimal_valid_model();
        model.nodes.insert(
            "other".into(),
            node_with_quic_link("quic0", Some("9.9.9.9:4433")),
        );
        for (name, at) in [("bob", "mgmt"), ("carol", "other")] {
            model.users.insert(
                name.into(),
                User {
                    roles: vec![],
                    nodes: vec![UserNode {
                        at: at.into(),
                        via: None,
                        socks5_proxy: "127.0.0.1:1080".parse().unwrap(),
                    }],
                },
            );
        }
        let violations = validate(&model);
        assert_eq!(count(&violations, Rule::LocalPortUniqueness), 0);
    }
}
