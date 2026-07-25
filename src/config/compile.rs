// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! The compile step: project the merged rete source into per-node artifacts.
//!
//! `retectl compile` runs after `retectl validate` — [`compile`] assumes a model
//! the [validator](super::rete::validate) accepted and turns it into one
//! [`Envelope<VertexMgmtPayload>`](super::artifact::Envelope) per node, ready to
//! be written under `<repo>/.flor/compiled/<node>/mgmt/<vertex>.json`.
//!
//! Two stages, mirroring what the compiled artifact needs to say:
//! - [`plan`] resolves the whole rete once — SPIFFE IDs, role→group expansion,
//!   local port allocation, per-node placement.
//! - [`vertex`] projects that resolved view onto a single node, keeping only the
//!   identity references and ACL rows relevant to its own workloads.
//!
//! The projection is pure and deterministic: the source model's collections are
//! `HashMap`s, whose iteration order is *not* stable, so every list this module
//! emits is explicitly sorted. The one module that touches disk is [`layout`],
//! which owns the compiled tree's on-disk layout.
//!
//! Signing is not implemented yet — artifacts carry a placeholder [`Signature`]
//! naming the rete's first mgmt signer, as `scripts/dev-bootstrap.sh` does by
//! hand. Nothing verifies signatures today; the agent (the sole verifier) lands
//! with `flor agent`.

pub mod layout;
pub mod plan;
pub mod version;
pub mod vertex;

use std::path::PathBuf;

use error_stack::{Report, ResultExt};

use super::artifact::{Envelope, VertexMgmtPayload};
use super::rete::RepoModel;

pub use plan::Plan;

/// Knobs the caller (the CLI) supplies; everything else is derived from the model.
#[derive(Debug, Clone)]
pub struct CompileOpts {
    /// Monotonic per-compilation number, rete-wide (rollback-attack defence).
    pub version: u64,
    /// Compile timestamp, RFC 3339.
    pub generated_at: String,
}

/// One compiled artifact, with the tree location it belongs at.
#[derive(Debug, Clone)]
pub struct NodeVertexArtifact {
    pub node: String,
    pub vertex_name: String,
    pub envelope: Envelope<VertexMgmtPayload>,
}

impl NodeVertexArtifact {
    /// Where this artifact lives, relative to the compiled tree root:
    /// `<node>/mgmt/<vertex>.json`. C0's mgmt set is flat — one `<name>.json`
    /// per workload — so there is no `vertices/` subdirectory.
    pub fn path(&self) -> PathBuf {
        PathBuf::from(&self.node)
            .join("mgmt")
            .join(format!("{}.json", self.vertex_name))
    }

    /// This artifact's on-disk form: the envelope as pretty JSON, newline-ended.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let mut json = serde_json::to_string_pretty(&self.envelope)?;
        json.push('\n');
        Ok(json)
    }
}

/// Compile a validated model into one artifact per node.
///
/// Every node is recompiled on every run, so the whole rete lands at one
/// version. Every artifact is checked against the artifact schema's own semantic
/// rules before being returned — the compiler never emits a payload `flor` would
/// reject.
pub fn compile(
    model: &RepoModel,
    opts: &CompileOpts,
) -> Result<Vec<NodeVertexArtifact>, Report<Error>> {
    let plan = Plan::build(model)?;

    let mut artifacts = Vec::new();
    for (node, node_plan) in &plan.nodes {
        let artifact = vertex::project(&plan, node, node_plan, opts)?;
        artifact
            .envelope
            .validate(&artifact.vertex_name)
            .change_context_lazy(|| {
                Error::new(format!("Compiled artifact for node '{node}' is malformed"))
            })?;
        artifacts.push(artifact);
    }
    Ok(artifacts)
}

/// A compile failure.
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
    use std::net::SocketAddr;

    use crate::config::artifact::model::vertex::{Adapter, IoChannel, LinkRule};
    use crate::config::artifact::{Plane, version};
    use crate::config::rete::{LoadOpts, load};

    use super::*;

    /// The worked C0 topology from validate-and-compile.mdx / source-layout.mdx:
    /// a management node, two server nodes, and three user devices.
    const RETE_LOVERS: &str = r#"
rete:
  name: rete-lovers
  ca:
    cert: certs/ca.crt
  signers:
    mgmt:
      keys:
        - { name: primary, cert: certs/management-planes/primary.crt }

nodes:
  mgmt01:
    vertices:
      - { name: public, kind: link, type: quic, address: "9.10.11.12:4433" }
  alpha:
    vertices:
      - { name: public, kind: link, type: quic, address: "1.2.3.4:4433" }
  beta:
    vertices:
      - { name: public, kind: link, type: quic, address: "5.6.7.8:4433" }
  alice-laptop:
    vertices:
      - { name: flor, kind: link, type: quic }
  bob-workstation:
    vertices:
      - { name: flor, kind: link, type: quic }
  fyodor-laptop:
    vertices:
      - { name: flor, kind: link, type: quic }

services:
  coordinator:
    at: mgmt01
    addr: "127.0.0.1:9000"
    groups: [coordinator-sync]
  coordinator-publisher:
    at: mgmt01
    addr: "127.0.0.1:9001"
    groups: [coordinator-publish]
  api:
    at: alpha
    addr: "127.0.0.1:8000"
    socks5_proxy: "127.0.0.1:18000"
    groups: [api]
    roles: [api-backend]
  ssh:
    at: alpha
    scope: node
    addr: "0.0.0.0:22"
    groups: [admin]
  mongodb:
    at: beta
    addr: "127.0.0.1:27017"
    groups: [db]
  kafka:
    at: beta
    addr: "127.0.0.1:9092"
    groups: [brokers]

groups:
  coordinator-sync:
  coordinator-publish:
  api:
  db:
  brokers:
  admin:

roles:
  node: { allow: [coordinator-sync] }
  operator: { allow: [coordinator-publish] }
  devops: { allow: [api, db, brokers, admin] }
  developer: { allow: [api, brokers] }
  api-backend: { allow: [db, brokers] }

users:
  fyodor:
    roles: [operator]
    nodes:
      - { at: fyodor-laptop, socks5_proxy: "127.0.0.1:1080" }
  alice:
    roles: [developer]
    nodes:
      - { at: alice-laptop, socks5_proxy: "127.0.0.1:1080" }
  bob:
    roles: [devops]
    nodes:
      - { at: bob-workstation, socks5_proxy: "127.0.0.1:1080" }
"#;

    fn model(yaml: &str) -> RepoModel {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("rete.yaml"), yaml).expect("write rete.yaml");
        load(&LoadOpts {
            repo: dir.path().to_path_buf(),
            files: vec![],
        })
        .expect("load")
    }

    fn opts() -> CompileOpts {
        CompileOpts {
            version: 42,
            generated_at: "2026-04-20T12:00:00Z".into(),
        }
    }

    fn all(yaml: &str) -> Vec<NodeVertexArtifact> {
        compile(&model(yaml), &opts()).expect("compile")
    }

    fn node<'a>(artifacts: &'a [NodeVertexArtifact], name: &str) -> &'a NodeVertexArtifact {
        artifacts
            .iter()
            .find(|a| a.node == name)
            .unwrap_or_else(|| panic!("no artifact for node '{name}'"))
    }

    /// The SOCKS5 listen of the workload named by `id`, as `"ip:port"`.
    fn socks5_of(artifact: &NodeVertexArtifact, id: &str) -> String {
        let workload = artifact
            .envelope
            .payload
            .workloads
            .iter()
            .find(|w| w.spiffe_id.to_string() == id)
            .unwrap_or_else(|| panic!("no workload {id}"));
        workload
            .io
            .iter()
            .find_map(|io| match io {
                IoChannel::Socks5 { listen } => Some(listen.to_string()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("workload {id} has no socks5 channel"))
    }

    /// The allow-list of the ACL row targeting `id`, as sorted SPIFFE strings.
    fn allow_of(acls: &[crate::config::artifact::model::vertex::Acl], id: &str) -> Vec<String> {
        acls.iter()
            .find(|acl| acl.target.to_string() == id)
            .unwrap_or_else(|| panic!("no acl row for {id}"))
            .allow
            .iter()
            .map(|a| a.to_string())
            .collect()
    }

    fn link_names(artifact: &NodeVertexArtifact) -> Vec<String> {
        artifact
            .envelope
            .payload
            .links
            .iter()
            .flat_map(|LinkRule::List { members }| members.iter().map(|m| m.name.clone()))
            .collect()
    }

    fn adapter_listen(artifact: &NodeVertexArtifact) -> Option<SocketAddr> {
        match &artifact.envelope.payload.connection_manager.adapters[..] {
            [Adapter::Udp { listen, .. }] => *listen,
            other => panic!("expected exactly one udp adapter, got {other:?}"),
        }
    }

    #[test]
    fn compiles_one_artifact_per_node() {
        let artifacts = all(RETE_LOVERS);
        let mut nodes: Vec<&str> = artifacts.iter().map(|a| a.node.as_str()).collect();
        nodes.sort_unstable();
        assert_eq!(
            nodes,
            [
                "alice-laptop",
                "alpha",
                "beta",
                "bob-workstation",
                "fyodor-laptop",
                "mgmt01"
            ]
        );

        // The artifact is named for the node's vertex, and lands where the agent
        // looks for it.
        assert_eq!(
            node(&artifacts, "alpha").path(),
            PathBuf::from("alpha/mgmt/public.json")
        );
        assert_eq!(
            node(&artifacts, "alice-laptop").path(),
            PathBuf::from("alice-laptop/mgmt/flor.json")
        );
    }

    #[test]
    fn envelope_carries_the_compile_claims() {
        let artifacts = all(RETE_LOVERS);
        let env = &node(&artifacts, "alpha").envelope;
        assert_eq!(env.schema_version, "1.0");
        assert_eq!(env.plane, Plane::Mgmt);
        assert_eq!(env.version, 42);
        assert_eq!(env.node, "alpha");
        assert_eq!(env.name, "public");
        assert_eq!(env.generated_at, "2026-04-20T12:00:00Z");
        // Signing is not implemented yet: the signer is named, nothing is signed.
        assert_eq!(
            env.signature.key_id.to_string(),
            "spiffe://rete-lovers/management-plane/primary"
        );
        assert_eq!(env.signature.alg, "none");
    }

    #[test]
    fn both_schema_ladders_are_stamped_from_the_contract_constants() {
        // Producer and consumer must read one source of truth, so what the
        // compiler stamps is exactly what the consumer's gate accepts.
        let artifacts = all(RETE_LOVERS);
        let env = &node(&artifacts, "alpha").envelope;
        assert_eq!(env.schema_version, version::ENVELOPE.stamp());
        assert_eq!(env.payload.schema_version, version::VERTEX.stamp());
        // Whatever it stamped, the artifact passes its own gate — `compile`
        // already validates every artifact, so this pins the round trip.
        env.validate("public").unwrap();
    }

    /// The user-node payload from validate-and-compile.mdx: an initiator-only
    /// device, its own agent principal beside the user's.
    #[test]
    fn user_node_is_an_initiator_only_device() {
        let artifacts = all(RETE_LOVERS);
        let alice = node(&artifacts, "alice-laptop");
        let payload = &alice.envelope.payload;

        // No `address` in nodes.yaml -> nothing to bind.
        assert_eq!(adapter_listen(alice), None);

        // The device carries just its user, whose device declares its own SOCKS5
        // port. There is no synthesized node-agent principal.
        assert_eq!(
            socks5_of(alice, "spiffe://rete-lovers/user/alice"),
            "127.0.0.1:1080"
        );
        assert_eq!(payload.workloads.len(), 1);

        // A device hosts no services, so nothing may initiate *to* it.
        assert!(payload.ingress.is_empty());

        // `developer` grants api + brokers; nothing here grants coordinator-sync.
        assert_eq!(link_names(alice), ["api", "kafka"]);
        assert_eq!(
            allow_of(&payload.egress, "spiffe://rete-lovers/service/api"),
            ["spiffe://rete-lovers/user/alice"]
        );
        // mongodb is in `db`, which `developer` does not grant.
        assert!(
            !link_names(alice).contains(&"mongodb".to_string()),
            "alice must not be able to dial mongodb"
        );
    }

    /// The server-node payload from validate-and-compile.mdx.
    #[test]
    fn server_node_serves_targets_and_initiates() {
        let artifacts = all(RETE_LOVERS);
        let alpha = node(&artifacts, "alpha");
        let payload = &alpha.envelope.payload;

        // The declared public address becomes a bind on an unspecified host.
        assert_eq!(
            adapter_listen(alpha),
            Some("0.0.0.0:4433".parse::<SocketAddr>().unwrap())
        );

        // api is both a target (tcp upstream) and an initiator (its own socks5).
        let api = payload
            .workloads
            .iter()
            .find(|w| w.spiffe_id.to_string() == "spiffe://rete-lovers/service/api")
            .expect("api workload");
        assert_eq!(
            api.io,
            [
                IoChannel::Tcp {
                    upstream: "127.0.0.1:8000".parse().unwrap()
                },
                IoChannel::Socks5 {
                    listen: "127.0.0.1:18000".parse().unwrap()
                },
            ]
        );

        // Ingress is the authoritative gate: roles expanded to explicit IDs.
        assert_eq!(
            allow_of(&payload.ingress, "spiffe://rete-lovers/service/api"),
            [
                "spiffe://rete-lovers/user/alice",
                "spiffe://rete-lovers/user/bob"
            ]
        );
        assert_eq!(
            allow_of(&payload.ingress, "spiffe://rete-lovers/service/alpha/ssh"),
            ["spiffe://rete-lovers/user/bob"]
        );

        // api's `api-backend` role reaches db + brokers. With no node-agent
        // principal, nothing on this node grants coordinator-sync.
        assert_eq!(
            allow_of(&payload.egress, "spiffe://rete-lovers/service/mongodb"),
            ["spiffe://rete-lovers/service/api"]
        );
        assert_eq!(link_names(alpha), ["kafka", "mongodb"]);
    }

    #[test]
    fn node_scoped_service_gets_a_node_scoped_id() {
        let artifacts = all(RETE_LOVERS);
        let ssh = node(&artifacts, "alpha")
            .envelope
            .payload
            .workloads
            .iter()
            .find(|w| w.spiffe_id.to_string().ends_with("/ssh"))
            .expect("ssh workload");
        assert_eq!(
            ssh.spiffe_id.to_string(),
            "spiffe://rete-lovers/service/alpha/ssh"
        );
    }

    #[test]
    fn artifacts_carry_no_filesystem_references() {
        // The shape the design mandates: principals are named by SPIFFE ID and
        // nothing else, so the same signed JSON is valid wherever the node's
        // scope root lives. Asserted over the serialized form, since it is the
        // wire bytes — not the Rust types — that a consumer is handed.
        let artifacts = all(RETE_LOVERS);
        let json: serde_json::Value =
            serde_json::to_value(&node(&artifacts, "alpha").envelope).unwrap();

        // Dispatch is by `name`; the envelope claims no `kind`.
        assert!(json.get("kind").is_none(), "{json}");
        assert_eq!(json["name"], "public");

        let payload = &json["payload"];
        assert!(payload.get("ca_cert_path").is_none(), "{payload}");
        for workload in payload["workloads"].as_array().unwrap() {
            assert!(workload.get("identity").is_none(), "{workload}");
            assert!(workload["spiffe_id"].is_string(), "{workload}");
        }
        // The payload keeps its own engine discriminator — a different axis.
        assert_eq!(payload["kind"], "link");
    }

    #[test]
    fn coordinator_ingress_is_not_auto_populated_by_nodes() {
        let artifacts = all(RETE_LOVERS);
        let ingress = &node(&artifacts, "mgmt01").envelope.payload.ingress;
        // With no synthesized node-agent principal, nothing holds the reserved
        // `node` role, so the coordinator (gated by coordinator-sync) has no
        // ingress row at all.
        assert!(
            ingress
                .iter()
                .all(|acl| acl.target.to_string() != "spiffe://rete-lovers/service/coordinator"),
            "coordinator must have no ingress row"
        );
        // The operator still reaches the coordinator-publisher.
        assert_eq!(
            allow_of(
                ingress,
                "spiffe://rete-lovers/service/coordinator-publisher"
            ),
            ["spiffe://rete-lovers/user/fyodor"]
        );
    }

    #[test]
    fn compiling_twice_produces_identical_artifacts() {
        // The source model is HashMap-backed; the output must not be.
        let first = all(RETE_LOVERS);
        let second = all(RETE_LOVERS);
        let json = |artifacts: &[NodeVertexArtifact]| {
            artifacts
                .iter()
                .map(|a| serde_json::to_string(&a.envelope).unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(json(&first), json(&second));
    }

    #[test]
    fn compiling_without_a_mgmt_signer_is_an_error() {
        // Nothing could sign the artifacts, so there is no key_id to name.
        let yaml = RETE_LOVERS.replace(
            "        - { name: primary, cert: certs/management-planes/primary.crt }",
            "",
        );
        let err = compile(&model(&yaml), &opts()).expect_err("empty signer list must fail");
        assert!(
            format!("{err:?}").contains("`rete.signers.mgmt.keys` is empty"),
            "{err:?}"
        );
    }
}
