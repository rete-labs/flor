// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! Serde glue for [`SpiffeId`], which has no native serde impl in `spiffe` 0.15.
//!
//! The top-level [`serialize`]/[`deserialize`] pair is a `#[serde(with = …)]`
//! module for a bare `SpiffeId` field; the nested [`vec`] module is the same
//! for a `Vec<SpiffeId>`. Serialization renders the canonical URI string;
//! deserialization parses it via [`SpiffeId::new`], flattening the parse error
//! to a string because an `error_stack::Report` cannot cross the
//! [`serde::de::Error`] boundary.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::core::identity::SpiffeId;

/// Serialize a [`SpiffeId`] as its canonical URI string.
pub fn serialize<S>(id: &SpiffeId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&id.to_string())
}

/// Deserialize a [`SpiffeId`] from a URI string.
pub fn deserialize<'de, D>(deserializer: D) -> Result<SpiffeId, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    SpiffeId::new(&s).map_err(serde::de::Error::custom)
}

/// `#[serde(with = "…sid::vec")]` glue for a `Vec<SpiffeId>`.
pub mod vec {
    use super::*;

    /// Serialize a `Vec<SpiffeId>` as a JSON array of canonical URI strings.
    pub fn serialize<S>(ids: &[SpiffeId], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let strs: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        strs.serialize(serializer)
    }

    /// Deserialize a `Vec<SpiffeId>`, rejecting the whole list if any element
    /// fails to parse.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<SpiffeId>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strs = Vec::<String>::deserialize(deserializer)?;
        strs.iter()
            .map(|s| SpiffeId::new(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct One {
        #[serde(with = "super")]
        id: SpiffeId,
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Many {
        #[serde(with = "super::vec")]
        ids: Vec<SpiffeId>,
    }

    fn sid(s: &str) -> SpiffeId {
        SpiffeId::new(s).expect("valid SPIFFE ID")
    }

    #[test]
    fn round_trips_single_ids() {
        for uri in [
            "spiffe://demo.flor/user/alice",
            "spiffe://rete-lovers/service/api",
            "spiffe://demo.flor/service/alpha/db",
            "spiffe://demo.flor/vertex/alpha/flor",
            "spiffe://demo.flor/management-plane/primary",
        ] {
            let value = One { id: sid(uri) };
            let json = serde_json::to_string(&value).unwrap();
            // Serializes as the bare canonical URI string.
            assert_eq!(json, format!("{{\"id\":\"{uri}\"}}"), "{uri}");
            let back: One = serde_json::from_str(&json).unwrap();
            assert_eq!(back, value, "{uri}");
        }
    }

    #[test]
    fn deserialize_accepts_dotted_trust_domain() {
        let back: One =
            serde_json::from_str("{\"id\":\"spiffe://demo.flor/service/api\"}").unwrap();
        assert_eq!(back.id, sid("spiffe://demo.flor/service/api"));
    }

    #[test]
    fn deserialize_rejects_malformed_single() {
        let err = serde_json::from_str::<One>("{\"id\":\"not-a-spiffe-id\"}").unwrap_err();
        assert!(err.is_data(), "{err}");
    }

    #[test]
    fn round_trips_id_vec() {
        let value = Many {
            ids: vec![
                sid("spiffe://demo.flor/user/alice"),
                sid("spiffe://demo.flor/service/api"),
            ],
        };
        let json = serde_json::to_string(&value).unwrap();
        let back: Many = serde_json::from_str(&json).unwrap();
        assert_eq!(back, value);
    }

    #[test]
    fn deserialize_empty_vec() {
        let back: Many = serde_json::from_str("{\"ids\":[]}").unwrap();
        assert!(back.ids.is_empty());
    }

    #[test]
    fn deserialize_rejects_malformed_in_vec() {
        let err =
            serde_json::from_str::<Many>("{\"ids\":[\"spiffe://demo.flor/user/alice\",\"bogus\"]}")
                .unwrap_err();
        assert!(err.is_data(), "{err}");
    }
}
