// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! A deserializable map that rejects duplicate keys at parse time.

use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::marker::PhantomData;

use serde::Deserialize;
use serde::de;

/// A map that errors on a second occurrence of any key during YAML deserialization,
/// rather than silently overwriting the first value.
///
/// Backed by `HashMap<K, V>` at runtime. Used in `ConfigFragment` so that a YAML file
/// containing two `services.api` entries is rejected at parse time
/// (duplicate keys are a hard error, never last-wins).
#[derive(Debug)]
pub struct UniqueMap<K, V>(HashMap<K, V>);

impl<K, V> IntoIterator for UniqueMap<K, V> {
    type Item = (K, V);
    type IntoIter = std::collections::hash_map::IntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'de, K, V> Deserialize<'de> for UniqueMap<K, V>
where
    K: Deserialize<'de> + Hash + Eq + fmt::Display,
    V: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(UniqueMapVisitor(PhantomData))
    }
}

struct UniqueMapVisitor<K, V>(PhantomData<fn() -> (K, V)>);

impl<'de, K, V> de::Visitor<'de> for UniqueMapVisitor<K, V>
where
    K: Deserialize<'de> + Hash + Eq + fmt::Display,
    V: Deserialize<'de>,
{
    type Value = UniqueMap<K, V>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a map with unique keys")
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut map: HashMap<K, V> = HashMap::new();
        while let Some(key) = access.next_key::<K>()? {
            if map.contains_key(&key) {
                return Err(de::Error::custom(format!("Duplicate key `{key}`")));
            }
            let value = access.next_value::<V>()?;
            map.insert(key, value);
        }
        Ok(UniqueMap(map))
    }
}
