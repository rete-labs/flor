// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! The signed artifact envelope: flat claims, a typed `payload`, and a
//! signature.
//!
//! [`Envelope`] is generic over its payload `P`, so one shape serves every
//! artifact. The concrete payload is keyed by the `(plane, kind)` pair, not
//! `kind` alone — `Envelope<VertexMgmtPayload>` (mgmt+vertex) now,
//! `Envelope<AgentMgmtPayload>` (mgmt+agent) and `Envelope<VertexCtrlPayload>`
//! (ctrl+vertex) later — with no change here. Per-`kind` data lives in the
//! payload (`P`); per-`plane` data rides on the [`Plane`] discriminator itself
//! (ctrl's `obeys_mgmt_version`); the remaining claims are universal. This is
//! the architecture seam ADR-0010 describes: identity is `(node, plane, kind,
//! name)`, carried as claims beside the payload.

use serde::{Deserialize, Serialize};

use crate::core::identity::SpiffeId;

use super::super::version::Contract;

/// A signed compiled artifact: flat claims beside a typed `payload`.
///
/// A closed metadata schema: every claim is enumerated and unknown fields are
/// rejected, so a typo or stray claim fails loudly rather than parsing silently.
/// The schema evolves by a `schema_version` bump plus an explicit field, never
/// an open field bag.
///
/// Deserializing an `Envelope` does **not** by itself gate `schema_version`. For
/// the recommended fail-closed loading path: parse the bytes, then call
/// `Envelope::validate` (the authoritative `schema_version` check plus the
/// payload rules). If the strict parse itself *fails*, run
/// [`version::precheck_schema_version`](super::super::version::precheck_schema_version)
/// on the bytes to tell an unsupported-schema artifact (report a clear "upgrade
/// flor" error) apart from a malformed one (surface the parse error).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope<P> {
    /// `major.minor` of the **envelope** contract only (e.g. `"1.0"`) — the
    /// claims, the signature canonicalization, and the relays' frozen routing
    /// core within it. Payload schemas ride their own ladders inside `payload`
    /// (see [`Payload::FAMILY`]).
    pub schema_version: String,
    /// Whose authority signed this — `mgmt` or `ctrl`.
    pub plane: Plane,
    /// Which Florete process consumes this.
    pub kind: ArtifactKind,
    /// Monotonic per-compilation number (rollback-attack defence).
    pub version: u64,
    /// The node this artifact is projected for.
    pub node: String,
    /// The artifact's name within its `(node, kind)` space. With
    /// `(node, plane, kind)` it identifies the artifact.
    pub name: String,
    /// Compile timestamp (RFC 3339; kept as an opaque string, not parsed).
    pub generated_at: String,
    /// The typed, plane/kind-specific payload.
    pub payload: P,
    /// The producer's signature over the canonical envelope sans this field.
    pub signature: Signature,
}

/// Whose authority signed an artifact — the trust-root axis — carrying that
/// plane's own metadata. `mgmt` carries nothing; `ctrl` carries
/// `obeys_mgmt_version`, common to every ctrl artifact regardless of `kind`.
///
/// Externally tagged: the metadata-free `mgmt` stays a bare string while `ctrl`
/// nests, keeping the common case clean and the conditional field representable
/// under the envelope's closed schema — a flattened variant would disable
/// `deny_unknown_fields`: `"mgmt"` / `{ "ctrl": { "obeys_mgmt_version": 42 } }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Plane {
    Mgmt,
    Ctrl {
        /// The mgmt `version` this ctrl decision obeys; the verifier rejects a
        /// ctrl artifact older than the mgmt it currently holds (rollback
        /// defence).
        obeys_mgmt_version: u64,
    },
}

impl Plane {
    /// This plane's discriminant, dropping any per-plane metadata — so a
    /// payload can declare which plane it rides on (see [`Payload`]) as a const.
    pub fn tag(&self) -> PlaneTag {
        match self {
            Plane::Mgmt => PlaneTag::Mgmt,
            Plane::Ctrl { .. } => PlaneTag::Ctrl,
        }
    }
}

/// [`Plane`] without its per-plane metadata — the bare trust-root discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneTag {
    Mgmt,
    Ctrl,
}

/// Which Florete process an artifact is consumed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Agent,
    Vertex,
}

/// Binds a typed payload to the `(plane, kind)` envelope cell it rides in and to
/// the contract its own schema versions on, so envelope checks can be written
/// once, generically. Each payload type maps to exactly one cell (mgmt+vertex,
/// ctrl+vertex, mgmt+agent, …).
pub trait Payload {
    const PLANE: PlaneTag;
    const KIND: ArtifactKind;

    /// The payload-family contract this payload's schema versions on — a ladder
    /// independent of the envelope's ([`version`](super::super::version)).
    ///
    /// A family is everything one consumer parses *jointly*, so it spans planes:
    /// `VertexMgmtPayload` and the future `VertexCtrlPayload` name the same
    /// contract, because the join rules between them are versioned by it too.
    const FAMILY: Contract;

    /// The family minor this artifact's content is stamped at — the value the
    /// generic gate checks against [`FAMILY`](Payload::FAMILY).
    fn schema_version(&self) -> &str;
}

/// A producer signature over the artifact.
///
/// Parsed structurally, not verified here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// Signature algorithm, e.g. `"ed25519"`.
    pub alg: String,
    /// SPIFFE ID of the signing principal (a mgmt- or control-plane identity).
    #[serde(with = "super::sid")]
    pub key_id: SpiffeId,
    /// Opaque signature value (base64; not decoded).
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    /// A minimal, well-formed vertex envelope with an opaque payload.
    fn minimal() -> Value {
        json!({
            "schema_version": "1.0",
            "plane": "mgmt",
            "kind": "vertex",
            "version": 42,
            "node": "alpha",
            "name": "flor",
            "generated_at": "2026-04-20T12:00:00Z",
            "payload": { "anything": true },
            "signature": {
                "alg": "ed25519",
                "key_id": "spiffe://rete-lovers/management-plane/primary",
                "value": "<base64>"
            }
        })
    }

    #[test]
    fn deserializes_all_envelope_claims() {
        let env: Envelope<Value> = serde_json::from_value(minimal()).unwrap();
        assert_eq!(env.schema_version, "1.0");
        assert_eq!(env.plane, Plane::Mgmt);
        assert_eq!(env.kind, ArtifactKind::Vertex);
        assert_eq!(env.version, 42);
        assert_eq!(env.node, "alpha");
        assert_eq!(env.name, "flor");
        assert_eq!(env.generated_at, "2026-04-20T12:00:00Z");
        assert_eq!(env.signature.alg, "ed25519");
        assert_eq!(
            env.signature.key_id.to_string(),
            "spiffe://rete-lovers/management-plane/primary"
        );
        assert_eq!(env.signature.value, "<base64>");
        // Payload is left entirely to `P`.
        assert_eq!(env.payload, json!({ "anything": true }));
    }

    #[test]
    fn agent_artifact_is_named_agent() {
        // The agent envelope is the same shape, named "agent" (one per node).
        let mut v = minimal();
        let obj = v.as_object_mut().unwrap();
        obj.insert("kind".into(), json!("agent"));
        obj.insert("name".into(), json!("agent"));
        let env: Envelope<Value> = serde_json::from_value(v).unwrap();
        assert_eq!(env.kind, ArtifactKind::Agent);
        assert_eq!(env.name, "agent");
    }

    #[test]
    fn round_trips_through_json() {
        let env: Envelope<Value> = serde_json::from_value(minimal()).unwrap();
        let json = serde_json::to_string(&env).unwrap();
        let back: Envelope<Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, env);
    }

    #[test]
    fn rejects_missing_required_field() {
        let mut v = minimal();
        v.as_object_mut().unwrap().remove("name");
        let err = serde_json::from_value::<Envelope<Value>>(v).unwrap_err();
        assert!(err.to_string().contains("name"), "{err}");
    }

    #[test]
    fn rejects_unknown_field() {
        // Closed schema: an unexpected claim fails loudly, not silently.
        let mut v = minimal();
        v["surprise"] = json!(true);
        let err = serde_json::from_value::<Envelope<Value>>(v).unwrap_err();
        assert!(err.is_data(), "{err}");
    }

    #[test]
    fn ctrl_plane_carries_obeys_mgmt_version() {
        // The ctrl-plane metadata rides on the discriminator, not the payload.
        let mut v = minimal();
        v["plane"] = json!({ "ctrl": { "obeys_mgmt_version": 17 } });
        let env: Envelope<Value> = serde_json::from_value(v).unwrap();
        assert_eq!(
            env.plane,
            Plane::Ctrl {
                obeys_mgmt_version: 17
            }
        );
    }

    #[test]
    fn ctrl_plane_requires_obeys_mgmt_version() {
        // `obeys` is intrinsic to ctrl-ness: a ctrl artifact can't omit it.
        let mut v = minimal();
        v["plane"] = json!({ "ctrl": {} });
        let err = serde_json::from_value::<Envelope<Value>>(v).unwrap_err();
        assert!(err.to_string().contains("obeys_mgmt_version"), "{err}");
    }

    #[test]
    fn rejects_unknown_plane() {
        let mut v = minimal();
        v["plane"] = json!("data");
        let err = serde_json::from_value::<Envelope<Value>>(v).unwrap_err();
        assert!(err.is_data(), "{err}");
    }

    #[test]
    fn rejects_malformed_key_id() {
        let mut v = minimal();
        v["signature"]["key_id"] = json!("not-a-spiffe-id");
        let err = serde_json::from_value::<Envelope<Value>>(v).unwrap_err();
        assert!(err.is_data(), "{err}");
    }
}
