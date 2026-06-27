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

#[cfg(test)]
mod tests {
    use super::UniqueMap;

    fn parse_str_map(yaml: &str) -> Result<UniqueMap<String, String>, String> {
        serde_yaml_ng::from_str::<UniqueMap<String, String>>(yaml).map_err(|e| e.to_string())
    }

    #[test]
    fn unique_keys_deserialize_ok() {
        let map = parse_str_map("a: foo\nb: bar").unwrap();
        let mut entries: Vec<_> = map.into_iter().collect();
        entries.sort_by_key(|(k, _)| k.clone());
        assert_eq!(
            entries,
            vec![("a".into(), "foo".into()), ("b".into(), "bar".into())]
        );
    }

    #[test]
    fn empty_map_deserializes_ok() {
        let map = parse_str_map("{}").unwrap();
        assert_eq!(map.into_iter().count(), 0);
    }

    #[test]
    fn duplicate_key_returns_error() {
        let result = parse_str_map("key: first\nkey: second");
        assert!(result.is_err(), "expected duplicate key error");
        assert!(
            result.unwrap_err().contains("Duplicate key `key`"),
            "error message should name the duplicate key"
        );
    }

    #[test]
    fn into_iter_yields_all_entries() {
        let map = serde_yaml_ng::from_str::<UniqueMap<String, i32>>("x: 1\ny: 2\nz: 3").unwrap();
        let mut keys: Vec<String> = map.into_iter().map(|(k, _)| k).collect();
        keys.sort();
        assert_eq!(keys, vec!["x", "y", "z"]);
    }
}
