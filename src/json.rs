//! Reject duplicate keys at every depth before typed decoding.
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::{collections::BTreeSet, fmt};

struct Unique;
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(Unique)
    }
}
impl<'de> Visitor<'de> for Unique {
    type Value = Unique;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON without duplicate keys")
    }
    fn visit_bool<E>(self, _: bool) -> Result<Unique, E> {
        Ok(Unique)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Unique, E> {
        Ok(Unique)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Unique, E> {
        Ok(Unique)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Unique, E> {
        Ok(Unique)
    }
    fn visit_str<E>(self, _: &str) -> Result<Unique, E> {
        Ok(Unique)
    }
    fn visit_unit<E>(self) -> Result<Unique, E> {
        Ok(Unique)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
        while a.next_element::<Unique>()?.is_some() {}
        Ok(Unique)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = a.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate key"));
            }
            a.next_value::<Unique>()?;
        }
        Ok(Unique)
    }
}

pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> crate::Result<T> {
    serde_json::from_slice::<Unique>(bytes).map_err(|_| crate::Error::Malformed)?;
    serde_json::from_slice(bytes).map_err(|_| crate::Error::Malformed)
}
