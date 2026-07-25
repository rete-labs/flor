// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Schema-version compatibility gates for compiled artifacts.
//!
//! A `schema_version` is the `major.minor` version of *one* contract, and an
//! artifact carries several on independent ladders (ADR-0012, Version the
//! Compiled-Artifact Contract):
//!
//! - the **envelope contract** ([`ENVELOPE`]) — the claims, the signature
//!   canonicalization, and the relays' frozen routing core within it. One
//!   ladder for every artifact of either plane, deliberately near-frozen.
//! - a **payload-family contract** per family ([`VERTEX`], and the agent
//!   family's when that payload lands) — carried *inside* `payload`, gated by
//!   that family's consumer, evolving at its own pace. A family is everything
//!   one consumer parses jointly: the vertex family spans its mgmt payload, its
//!   C1+ ctrl payload, and the join rules between them, so those payloads share
//!   one ladder. One number per family, never one per plane — a per-plane split
//!   would leave the security-critical join unversioned.
//!
//! Not every enveloped payload versions on a flor contract: an **opaque
//! workload config** (the coordinator's, from C0) owns its schema and its ladder
//! entirely, gated by its own consumer at startup. Such a payload names no
//! [`Contract`] here.
//!
//! Every ladder gates identically — **one-directional and fail-closed**:
//!
//! - A **different major** is incompatible in either direction — reject.
//! - A **newer minor** than this build knows is rejected (asking the operator
//!   to upgrade flor), *not* silently accepted. Combined with the envelope's
//!   `deny_unknown_fields`, a newer producer can only add fields under a version
//!   bump; ignoring them would risk dropping a restriction the newer schema
//!   introduced (a security artifact must fail *closed*, never open).
//! - An **older-or-equal minor** within the known major is accepted, so a newer
//!   flor keeps reading older artifacts — the direction rolling upgrades need.
//!
//! Evolution is therefore: teach flor the new fields, then bump that contract's
//! minor. That build reads both the old and the new minor; nodes still on the
//! old build reject the new artifact with a clear upgrade error instead of
//! misinterpreting it. Because the ladders are independent, a node routinely
//! holds an artifact whose envelope and payload sit at different minors.
//!
//! This module is the consumer half of the policy; the producer half is that
//! each artifact is stamped with the *lowest* minor its content actually uses —
//! never the producer's newest — so skew bites only nodes a new construct
//! actually touches. Both ladders sit at 1.0 today, so that stamp is
//! unconditionally 1.0 and the compiler emits it directly ([`Contract::stamp`]);
//! computing it per artifact becomes real work at the first minor bump. How skew
//! is then managed differs per plane (mgmt rolls out consumers-first; the B1+
//! ctrl producer emits within each consumer's advertised ceiling; relays never
//! gate) — see the ADR.

use error_stack::{Report, bail};
use serde::Deserialize;

use super::Error;
use super::model::Payload;

/// One versioned contract: the `major.minor` of a schema this build speaks.
///
/// `name` exists for the error message alone — with several ladders in one
/// artifact, "unsupported schema_version" is only actionable if it says *which*
/// contract rejected it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contract {
    /// How this contract is named in operator-facing errors, e.g. `"envelope"`.
    pub name: &'static str,
    /// Major this build speaks. A different major is incompatible.
    pub major: u64,
    /// Highest minor of `major` this build understands. Older-or-equal minors
    /// are accepted; a newer minor is rejected (fail-closed).
    pub minor: u64,
}

impl Contract {
    /// This contract's version as a producer stamps it into an artifact.
    pub fn stamp(&self) -> String {
        format!("{}.{}", self.major, self.minor)
    }
}

/// The envelope contract — one ladder for every artifact, both planes.
pub const ENVELOPE: Contract = Contract {
    name: "envelope",
    major: 1,
    minor: 0,
};

/// The vertex payload-family contract: the mgmt payload, the C1+ ctrl payload,
/// and the join rules between them.
pub const VERTEX: Contract = Contract {
    name: "vertex payload",
    major: 1,
    minor: 0,
};

/// A parsed `major.minor` schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SchemaVersion {
    major: u64,
    minor: u64,
}

impl SchemaVersion {
    fn parse(s: &str) -> Result<Self, Report<Error>> {
        let mut parts = s.split('.');
        let (Some(major), Some(minor), None) = (parts.next(), parts.next(), parts.next()) else {
            bail!(Error::new(format!(
                "Malformed schema_version {s:?}; expected \"MAJOR.MINOR\""
            )));
        };
        let parse_component = |part: &str, which: &str| {
            part.parse::<u64>().map_err(|_| {
                Report::new(Error::new(format!(
                    "Malformed schema_version {s:?}; {which} is not a number"
                )))
            })
        };
        Ok(Self {
            major: parse_component(major, "major")?,
            minor: parse_component(minor, "minor")?,
        })
    }
}

/// Check a `schema_version` string against the version of `contract` this build
/// speaks, per the module's fail-closed policy.
pub fn ensure_supported(contract: &Contract, schema_version: &str) -> Result<(), Report<Error>> {
    let Contract { name, major, minor } = *contract;
    let v = SchemaVersion::parse(schema_version)?;
    if v.major != major {
        bail!(Error::new(format!(
            "Unsupported {name} schema_version {schema_version:?}: this flor speaks \
             the {major}.x {name} contract, and major {} is incompatible",
            v.major
        )));
    }
    if v.minor > minor {
        bail!(Error::new(format!(
            "Unsupported {name} schema_version {schema_version:?}: this flor \
             understands up to {major}.{minor} — upgrade flor to consume it"
        )));
    }
    Ok(())
}

/// Extracts the `schema_version`s from raw artifact bytes — the envelope's and
/// the payload family's — and checks each present one with [`ensure_supported`],
/// erroring on an unsupported version.
///
/// Both ladders are probed because either can be the reason a strict parse
/// failed: a newer *payload* minor adds a field the payload's `deny_unknown_fields`
/// rejects while the envelope reads perfectly.
///
/// Best-effort by design, so it does not on its own guarantee a supported
/// version: if the bytes don't parse as JSON or carry no `schema_version`, it
/// returns `Ok` rather than an error.
pub fn precheck_schema_version<P: Payload>(bytes: &[u8]) -> Result<(), Report<Error>> {
    /// Only the two version claims, each optional: the probe must survive bytes
    /// too malformed for the strict parse, which is the whole point of running it.
    #[derive(Deserialize)]
    struct Probe {
        schema_version: Option<String>,
        payload: Option<PayloadProbe>,
    }

    #[derive(Deserialize)]
    struct PayloadProbe {
        schema_version: Option<String>,
    }

    let Ok(probe) = serde_json::from_slice::<Probe>(bytes) else {
        return Ok(());
    };
    if let Some(v) = &probe.schema_version {
        ensure_supported(&ENVELOPE, v)?;
    }
    if let Some(v) = probe.payload.and_then(|p| p.schema_version) {
        ensure_supported(&P::FAMILY, &v)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::model::VertexMgmtPayload;
    use super::*;

    /// A reference contract at an explicit minor, so the policy is testable at
    /// minors no shipped contract sits at (yet).
    fn at(major: u64, minor: u64) -> Contract {
        Contract {
            name: "test",
            major,
            minor,
        }
    }

    #[test]
    fn accepts_the_current_version_of_every_contract() {
        for contract in [ENVELOPE, VERTEX] {
            ensure_supported(&contract, &contract.stamp()).unwrap();
        }
    }

    #[test]
    fn accepts_older_and_equal_minors_within_the_major() {
        // A build that knows 1.2 reads 1.0/1.1/1.2 (rolling-upgrade direction).
        for v in ["1.0", "1.1", "1.2"] {
            ensure_supported(&at(1, 2), v).unwrap();
        }
    }

    #[test]
    fn rejects_a_newer_minor() {
        let err = ensure_supported(&at(1, 0), "1.1").unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("schema_version"), "{msg}");
        assert!(msg.contains("upgrade"), "{msg}");
    }

    #[test]
    fn rejects_a_different_major() {
        for v in ["2.0", "0.9"] {
            let err = ensure_supported(&at(1, 0), v).unwrap_err();
            assert!(format!("{err:?}").contains("incompatible"), "{v}: {err:?}");
        }
    }

    #[test]
    fn names_the_contract_that_rejected() {
        // With several ladders in one artifact, the error must say which one
        // failed — otherwise "upgrade flor" points at nothing in particular.
        let err = ensure_supported(&VERTEX, "1.9").unwrap_err();
        assert!(format!("{err:?}").contains("vertex payload"), "{err:?}");

        let err = ensure_supported(&ENVELOPE, "1.9").unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("envelope"), "{msg}");
        assert!(!msg.contains("vertex"), "{msg}");
    }

    #[test]
    fn rejects_malformed_versions() {
        for v in ["1", "1.0.0", "x.y", "1.x", "", "1."] {
            let err = ensure_supported(&ENVELOPE, v).unwrap_err();
            assert!(
                format!("{err:?}").contains("Malformed schema_version"),
                "{v:?}: {err:?}"
            );
        }
    }

    #[test]
    fn probe_gates_bytes_by_envelope_version() {
        // Valid JSON with an unsupported version → clean upgrade error.
        let bytes = br#"{ "schema_version": "2.0", "other": true }"#;
        assert!(precheck_schema_version::<VertexMgmtPayload>(bytes).is_err());

        // Valid JSON at a supported version → ok (ignores other fields).
        let bytes = br#"{ "schema_version": "1.0", "other": true }"#;
        precheck_schema_version::<VertexMgmtPayload>(bytes).unwrap();

        // No schema_version / not JSON → defer to the strict parse (Ok here).
        precheck_schema_version::<VertexMgmtPayload>(br#"{ "no_version": true }"#).unwrap();
        precheck_schema_version::<VertexMgmtPayload>(b"not json at all").unwrap();
    }

    #[test]
    fn probe_gates_bytes_by_payload_version() {
        // A current envelope carrying a newer payload minor: the ladders are
        // independent, so the payload one must be probed on its own. This is the
        // case that would otherwise surface as a raw unknown-field parse error.
        let bytes = br#"{ "schema_version": "1.0", "payload": { "schema_version": "1.9" } }"#;
        let err = precheck_schema_version::<VertexMgmtPayload>(bytes).unwrap_err();
        assert!(format!("{err:?}").contains("vertex payload"), "{err:?}");

        // A payload with no version claim leaves the probe with nothing to gate.
        let bytes = br#"{ "schema_version": "1.0", "payload": { "kind": "link" } }"#;
        precheck_schema_version::<VertexMgmtPayload>(bytes).unwrap();

        // Both current → ok.
        let bytes = br#"{ "schema_version": "1.0", "payload": { "schema_version": "1.0" } }"#;
        precheck_schema_version::<VertexMgmtPayload>(bytes).unwrap();
    }

    #[test]
    fn probe_stays_lenient_about_shapes_it_cannot_read() {
        // The probe only runs on bytes the strict parse already rejected, so it
        // meets arbitrary shapes. Anything it cannot read is *not* its verdict to
        // give: it must defer (Ok) and let the parse error stand, never invent an
        // upgrade prompt.
        for bytes in [
            &br#"{ "payload": 5 }"#[..],
            &br#"{ "payload": [1, 2] }"#[..],
            &br#"{ "schema_version": 1.0 }"#[..],
            &b"[]"[..],
        ] {
            precheck_schema_version::<VertexMgmtPayload>(bytes)
                .unwrap_or_else(|e| panic!("{}: {e:?}", String::from_utf8_lossy(bytes)));
        }
    }
}
