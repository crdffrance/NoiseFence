//! Parse attribute names case-insensitively without letting duplicate names
//! silently overwrite each other. Values (including schema URIs) keep their case.
use super::{INVALID, LIMIT, MAX_BODY_BYTES, Result, SYNTAX};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use std::fmt;
struct Input(Value);
struct InputVisitor;
impl<'de> Visitor<'de> for InputVisitor {
    type Value = Input;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SCIM JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Input, E> {
        Ok(Input(Value::Bool(v)))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Input, E> {
        Ok(Input(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Input, E> {
        Ok(Input(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Input, E> {
        Number::from_f64(v)
            .map(|v| Input(Value::Number(v)))
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Input, E> {
        Ok(Input(v.into()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Input, E> {
        Ok(Input(v.into()))
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Input, E> {
        Ok(Input(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Input, A::Error> {
        let mut values = Vec::new();
        while let Some(Input(value)) = seq.next_element()? {
            values.push(value);
        }
        Ok(Input(Value::Array(values)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Input, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 256 || !key.is_ascii() {
                return Err(de::Error::custom("invalid attribute name"));
            }
            let key = key.to_ascii_lowercase();
            if values.contains_key(&key) {
                return Err(de::Error::custom("ambiguous attribute"));
            }
            values.insert(key, map.next_value::<Input>()?.0);
        }
        Ok(Input(Value::Object(values)))
    }
}
impl<'de> Deserialize<'de> for Input {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        d.deserialize_any(InputVisitor)
    }
}
pub(super) fn decode(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(LIMIT);
    }
    let value = serde_json::from_slice::<Input>(bytes)
        .map_err(|_| SYNTAX)?
        .0;
    fn depth(value: &Value, n: usize) -> bool {
        n <= 12
            && match value {
                Value::Object(v) => v.values().all(|v| depth(v, n + 1)),
                Value::Array(v) => v.iter().all(|v| depth(v, n + 1)),
                _ => true,
            }
    }
    if !depth(&value, 0) {
        return Err(LIMIT);
    }
    Ok(value)
}
pub(super) fn object(value: Value) -> Result<Map<String, Value>> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(INVALID),
    }
}
pub(super) fn optional(
    map: &mut Map<String, Value>,
    key: &str,
    max: usize,
) -> Result<Option<String>> {
    match map.remove(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(v)) if v.is_empty() => Ok(None),
        Some(Value::String(v)) if crate::identity::text(&v, max) => Ok(Some(v)),
        _ => Err(INVALID),
    }
}
pub(super) fn required(map: &mut Map<String, Value>, key: &str, max: usize) -> Result<String> {
    optional(map, key, max)?.ok_or(INVALID)
}
pub(super) fn list(map: &mut Map<String, Value>, key: &str, max: usize) -> Result<Vec<Value>> {
    match map.remove(key) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(v)) if v.len() <= max => Ok(v),
        Some(Value::Array(_)) => Err(LIMIT),
        _ => Err(INVALID),
    }
}
pub(super) fn boolean(map: &mut Map<String, Value>, key: &str) -> Result<Option<bool>> {
    match map.remove(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(v)) => Ok(Some(v)),
        _ => Err(INVALID),
    }
}
pub(super) fn exhausted(map: &Map<String, Value>) -> Result<()> {
    if map.is_empty() { Ok(()) } else { Err(INVALID) }
}
pub(super) fn schema(map: &mut Map<String, Value>, expected: &str) -> Result<()> {
    if map.remove("schemas") == Some(serde_json::json!([expected])) {
        Ok(())
    } else {
        Err(INVALID)
    }
}
