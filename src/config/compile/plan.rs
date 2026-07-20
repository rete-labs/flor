// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! The resolved rete: everything the per-node projection needs, computed once.
//!
//! [`Plan::build`] does the work that is rete-wide rather than node-local —
//! naming every principal and target with its SPIFFE ID, expanding roles to the
//! groups they grant, resolving each service to the wire address that dials it,
//! and allocating the local SOCKS5 ports the source never spells out. The
//! per-node projection ([`super::vertex`]) then only filters and formats.
//!
//! Ordering is deliberate: the source model's collections are `HashMap`s, so
//! every collection here is a `BTree*` or an explicitly sorted `Vec`. Same
//! input, same output — the determinism the compile step promises.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use error_stack::{Report, ResultExt, bail};

use crate::config::artifact::model::vertex::{Identity, IoChannel};
use crate::config::rete::model::{Node, RepoModel, Service, ServiceScope, VertexKind, VertexType};
use crate::core::identity::{
    Kind, NodeScopableKind, SpiffeId, TrustDomain, build_id_in_rete, build_id_on_node,
};

use super::Error;

/// The whole rete, resolved.
#[derive(Debug)]
pub struct Plan {
    /// The rete's trust domain (its name).
    pub trust_domain: TrustDomain,
    /// SPIFFE ID of the mgmt signer whose key signs these artifacts.
    pub signer_key_id: SpiffeId,
    /// Every node, by name.
    pub nodes: BTreeMap<String, NodePlan>,
    /// Every service as a dialable target, by service name.
    pub targets: BTreeMap<String, Target>,
    /// Every principal in the rete, sorted by SPIFFE ID then by node.
    ///
    /// A multi-device user contributes one entry per device node: same identity,
    /// different local io.
    pub principals: Vec<Principal>,
}

/// A node's link vertex — the one artifact C0 compiles per node.
#[derive(Debug)]
pub struct NodePlan {
    /// The vertex's name in `nodes.yaml`; also the artifact's `name` and filename.
    pub vertex_name: String,
    /// Where peers reach this node. `None` for initiator-only nodes (no
    /// `address` — laptops behind NAT).
    pub address: Option<SocketAddr>,
}

impl NodePlan {
    /// What the wire adapter binds: the declared port on an unspecified host.
    ///
    /// `nodes.yaml` states where peers *reach* the node; the public IP may not
    /// exist on any local NIC (NAT, load balancer, floating address), so what
    /// the socket binds is the compiler's business.
    pub fn listen(&self) -> Option<SocketAddr> {
        self.address.map(|address| {
            let host = match address {
                SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            };
            SocketAddr::new(host, address.port())
        })
    }
}

/// A principal as wired into one node's vertex.
#[derive(Debug)]
pub struct Principal {
    pub id: SpiffeId,
    /// The node holding this principal's identity material.
    pub node: String,
    /// The groups this principal's roles grant it — what it may reach.
    pub granted: BTreeSet<String>,
    /// Scope-relative cert and key, resolved by the agent against the rete root.
    pub identity: Identity,
    /// How the principal is wired into flor locally.
    pub io: Vec<IoChannel>,
}

/// A service seen from the outside: who may reach it, and how to dial it.
#[derive(Debug)]
pub struct Target {
    /// The service's name in `services.yaml`; also its local forwarding handle.
    pub name: String,
    pub id: SpiffeId,
    /// The node hosting it.
    pub node: String,
    /// The host node's declared address — what an initiator's link dials.
    pub addr: SocketAddr,
    /// The groups gating inbound access to it.
    pub groups: BTreeSet<String>,
}

impl Plan {
    /// Resolve a validated model. Errors here are either source facts the
    /// validator does not cover yet (an empty signer list) or C0 invariants it
    /// guarantees (exactly one quic link-vertex per node) that we decline to
    /// assume rather than panic on.
    pub fn build(model: &RepoModel) -> Result<Self, Report<Error>> {
        let trust_domain = TrustDomain::new(&model.rete.name).change_context_lazy(|| {
            Error::new(format!("Invalid rete name '{}'", model.rete.name))
        })?;
        let signer_key_id = signer_key_id(model, &trust_domain)?;

        let mut nodes = BTreeMap::new();
        for (name, node) in &model.nodes {
            nodes.insert(name.clone(), node_plan(name, node)?);
        }

        let mut targets = BTreeMap::new();
        for (name, service) in &model.services {
            let host = nodes.get(&service.at).ok_or_else(|| {
                Error::new(format!(
                    "Service '{name}' is placed at unknown node '{}'",
                    service.at
                ))
            })?;
            let addr = host.address.ok_or_else(|| {
                Error::new(format!(
                    "Service '{name}' is hosted on initiator-only node '{}', \
                     whose link-vertex declares no `address`",
                    service.at
                ))
            })?;

            targets.insert(
                name.clone(),
                Target {
                    name: name.clone(),
                    id: service_id(&trust_domain, name, service)?,
                    node: service.at.clone(),
                    addr,
                    groups: service.groups.iter().cloned().collect(),
                },
            );
        }

        let mut principals = Vec::new();
        for node in nodes.keys() {
            principals.extend(node_principals(model, &trust_domain, node)?);
        }
        principals.sort_by_key(|p| (p.id.to_string(), p.node.clone()));

        Ok(Plan {
            trust_domain,
            signer_key_id,
            nodes,
            targets,
            principals,
        })
    }
}

/// The mgmt signer that signs this rete's artifacts: the first key in
/// `rete.signers.mgmt.keys`. Without one there is no signing identity to name,
/// so no well-formed envelope can be produced.
fn signer_key_id(model: &RepoModel, td: &TrustDomain) -> Result<SpiffeId, Report<Error>> {
    let Some(key) = model.rete.signers.mgmt.keys.first() else {
        bail!(Error::new(
            "`rete.signers.mgmt.keys` is empty; at least one mgmt signer is \
             required to sign compiled artifacts"
        ));
    };
    build_id_in_rete(td, Kind::ManagementPlane, &key.name).change_context_lazy(|| {
        Error::new(format!(
            "Failed to build SPIFFE ID for signer '{}'",
            key.name
        ))
    })
}

/// A service's SPIFFE ID: rete-scoped by default, node-scoped under `scope: node`.
fn service_id(td: &TrustDomain, name: &str, service: &Service) -> Result<SpiffeId, Report<Error>> {
    match service.scope {
        Some(ServiceScope::Node) => {
            build_id_on_node(td, NodeScopableKind::Service, &service.at, name)
        }
        _ => build_id_in_rete(td, Kind::Service, name),
    }
    .change_context_lazy(|| Error::new(format!("Failed to build SPIFFE ID for service '{name}'")))
}

/// A node's single C0 link vertex.
fn node_plan(name: &str, node: &Node) -> Result<NodePlan, Report<Error>> {
    let mut links = node
        .vertices
        .iter()
        .filter(|v| v.kind == VertexKind::Link && v.vertex_type == VertexType::Quic);

    let Some(vertex) = links.next() else {
        bail!(Error::new(format!(
            "Node '{name}' has no `kind: link, type: quic` vertex"
        )));
    };
    if links.next().is_some() {
        bail!(Error::new(format!(
            "Node '{name}' has more than one `kind: link, type: quic` vertex; \
             C0 requires exactly one"
        )));
    }

    Ok(NodePlan {
        vertex_name: vertex.name.clone(),
        address: vertex.address,
    })
}

/// Every principal whose identity material lives on `node`: the users with a
/// device here and the services hosted here.
///
/// Both name their own SOCKS5 port — services in `services.yaml`, users in each
/// device entry under `users.yaml` — so nothing is allocated here; uniqueness of
/// those ports is a validator concern ([`super::super::rete::validate`]).
fn node_principals(
    model: &RepoModel,
    td: &TrustDomain,
    node: &str,
) -> Result<Vec<Principal>, Report<Error>> {
    let mut local_services: Vec<(&String, &Service)> = model
        .services
        .iter()
        .filter(|(_, svc)| svc.at == node)
        .collect();
    local_services.sort_by_key(|(name, _)| *name);

    // Users with a device on this node, paired with that device's declared port.
    let mut local_users: Vec<(&String, SocketAddr)> = model
        .users
        .iter()
        .filter_map(|(name, user)| {
            user.nodes
                .iter()
                .find(|entry| entry.at == node)
                .map(|entry| (name, entry.socks5_proxy))
        })
        .collect();
    local_users.sort_by_key(|(name, _)| *name);

    let mut out = Vec::new();

    for (name, listen) in local_users {
        let id = build_id_in_rete(td, Kind::User, name).change_context_lazy(|| {
            Error::new(format!("Failed to build SPIFFE ID for user '{name}'"))
        })?;
        out.push(Principal {
            id,
            node: node.to_string(),
            granted: granted_groups(model, &model.users[name].roles),
            identity: identity_of(name),
            io: vec![IoChannel::Socks5 { listen }],
        });
    }

    // Services hosted here: a target over `tcp`, and an initiator too when they
    // declare a SOCKS5 port.
    for (name, svc) in local_services {
        let mut io = vec![IoChannel::Tcp { upstream: svc.addr }];
        if let Some(listen) = svc.socks5_proxy {
            io.push(IoChannel::Socks5 { listen });
        }

        out.push(Principal {
            id: service_id(td, name, svc)?,
            node: node.to_string(),
            granted: granted_groups(model, &svc.roles),
            identity: identity_of(name),
            io,
        });
    }

    Ok(out)
}

/// The groups `roles` grant, unioned. Roles are YAML-only: they exist to be
/// expanded here, never resolved on the vertex hot path.
fn granted_groups(model: &RepoModel, roles: &[String]) -> BTreeSet<String> {
    roles
        .iter()
        .filter_map(|role| model.roles.get(role))
        .flat_map(|role| role.allow.iter().cloned())
        .collect()
}

/// A principal's identity material: bare filenames, resolved by the agent
/// against the (flat) rete install root.
fn identity_of(name: &str) -> Identity {
    Identity {
        cert_path: format!("{name}.crt").into(),
        priv_path: format!("{name}.key").into(),
    }
}
