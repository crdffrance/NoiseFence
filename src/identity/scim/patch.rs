use super::{
    Data, INVALID, LIMIT, MAX_MEMBERS, MAX_OPERATIONS, MUTABILITY, PATCH_SCHEMA, PATH,
    ResourceType, Result, TARGET, json, query,
};
use serde_json::{Map, Value};
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Add,
    Replace,
    Remove,
}
struct Path {
    attribute: String,
    selector: Option<(String, String)>,
    sub: Option<String>,
}
impl Path {
    fn parse(kind: ResourceType, raw: &str) -> Result<Self> {
        if raw.len() > 2048 {
            return Err(PATH);
        }
        let raw = raw
            .strip_prefix(&format!("{}:", kind.schema()))
            .unwrap_or(raw);
        let (attribute, selector, sub) = if let Some(start) = raw.find('[') {
            let tail = &raw[start + 1..];
            // Deserialize a quoted literal so ] and escaped quotes inside its
            // value cannot terminate a filter or inject another path segment.
            let (key, literal) = query::equality(tail).map_err(|_| PATH)?;
            let mut stream = serde_json::Deserializer::from_str(literal).into_iter::<String>();
            let value = stream.next().ok_or(PATH)?.map_err(|_| PATH)?;
            let remaining = literal[stream.byte_offset()..]
                .trim_start()
                .strip_prefix(']')
                .ok_or(PATH)?;
            let sub = if remaining.is_empty() {
                None
            } else {
                Some(
                    remaining
                        .strip_prefix('.')
                        .ok_or(PATH)?
                        .to_ascii_lowercase(),
                )
            };
            (raw[..start].to_ascii_lowercase(), Some((key, value)), sub)
        } else {
            let (attribute, sub) = raw
                .split_once('.')
                .map_or((raw, None), |(a, s)| (a, Some(s.to_ascii_lowercase())));
            (attribute.to_ascii_lowercase(), None, sub)
        };
        if matches!(attribute.as_str(), "id" | "meta" | "schemas" | "groups") {
            return Err(MUTABILITY);
        }
        let allowed = match kind {
            ResourceType::User => matches!(
                attribute.as_str(),
                "username" | "externalid" | "displayname" | "active" | "name" | "emails"
            ),
            ResourceType::Group => {
                matches!(attribute.as_str(), "externalid" | "displayname" | "members")
            }
        };
        if !allowed {
            return Err(PATH);
        }
        if let Some((key, value)) = &selector
            && (!crate::identity::text(value, 320)
                || !match attribute.as_str() {
                    "emails" => matches!(key.as_str(), "type" | "value"),
                    "members" => key == "value",
                    _ => false,
                })
        {
            return Err(PATH);
        }
        if let Some(sub) = &sub
            && !match attribute.as_str() {
                "name" => matches!(
                    sub.as_str(),
                    "formatted"
                        | "familyname"
                        | "givenname"
                        | "middlename"
                        | "honorificprefix"
                        | "honorificsuffix"
                ),
                "emails" => {
                    selector.is_some() && matches!(sub.as_str(), "value" | "type" | "primary")
                }
                _ => false,
            }
        {
            return Err(PATH);
        }
        Ok(Self {
            attribute,
            selector,
            sub,
        })
    }
}
pub(super) fn apply(previous: &Data, bytes: &[u8]) -> Result<Data> {
    let mut envelope = json::object(json::decode(bytes)?)?;
    json::schema(&mut envelope, PATCH_SCHEMA)?;
    let operations = json::list(&mut envelope, "operations", MAX_OPERATIONS)?;
    json::exhausted(&envelope)?;
    if operations.is_empty() {
        return Err(INVALID);
    }
    let mut draft = previous.normalized()?;
    for operation in operations {
        let mut operation = json::object(operation)?;
        let op = match json::required(&mut operation, "op", 7)?
            .to_ascii_lowercase()
            .as_str()
        {
            "add" => Op::Add,
            "replace" => Op::Replace,
            "remove" => Op::Remove,
            _ => return Err(INVALID),
        };
        let raw_path = json::optional(&mut operation, "path", 2048)?;
        let value = operation.remove("value");
        json::exhausted(&operation)?;
        if op != Op::Remove && value.is_none() {
            return Err(INVALID);
        }
        if op == Op::Remove && value.is_some() {
            return Err(INVALID);
        }
        if let Some(raw) = raw_path {
            mutate(
                &mut draft,
                previous.kind(),
                op,
                &Path::parse(previous.kind(), &raw)?,
                value,
            )?;
        } else {
            if op == Op::Remove {
                return Err(PATH);
            }
            let values = json::object(value.ok_or(INVALID)?)?;
            if values.is_empty() {
                return Err(INVALID);
            }
            for (key, value) in values {
                mutate(
                    &mut draft,
                    previous.kind(),
                    op,
                    &Path::parse(previous.kind(), &key)?,
                    Some(value),
                )?;
            }
        }
        // Reject invalid intermediate operations without exposing any change.
        // Complexity is bounded after each op, not only at request completion.
        let checked = Data::from_value(previous.kind(), Value::Object(draft))?;
        draft = checked.normalized()?;
    }
    Data::from_value(previous.kind(), Value::Object(draft))
}
fn mutate(
    draft: &mut Map<String, Value>,
    kind: ResourceType,
    op: Op,
    path: &Path,
    value: Option<Value>,
) -> Result<()> {
    if op == Op::Remove
        && ((kind == ResourceType::User && path.attribute == "username")
            || (kind == ResourceType::Group && path.attribute == "displayname"))
    {
        return Err(MUTABILITY);
    }
    if let Some(selector) = &path.selector {
        return filtered(draft, op, path, selector, value);
    }
    if let Some(sub) = &path.sub {
        let entry = draft
            .entry(path.attribute.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let object = entry.as_object_mut().ok_or(INVALID)?;
        if op == Op::Remove {
            if object.remove(sub).is_none() {
                return Err(TARGET);
            }
        } else {
            object.insert(sub.clone(), value.ok_or(INVALID)?);
        }
        return Ok(());
    }
    if op == Op::Remove {
        if draft
            .remove(&path.attribute)
            .is_none_or(|v| v.as_array().is_some_and(|a| a.is_empty()))
        {
            return Err(TARGET);
        }
    } else if op == Op::Add && matches!(path.attribute.as_str(), "emails" | "members") {
        let incoming = value.ok_or(INVALID)?.as_array().cloned().ok_or(INVALID)?;
        let max = if path.attribute == "emails" {
            32
        } else {
            MAX_MEMBERS
        };
        if incoming.len() > max {
            return Err(LIMIT);
        }
        let mut new = Vec::with_capacity(incoming.len());
        for item in incoming {
            let explicit_false = item.get("primary") == Some(&Value::Bool(false));
            let seed = if kind == ResourceType::User {
                serde_json::json!({"schemas":[kind.schema()],"username":"scim-patch","emails":[item]})
            } else {
                serde_json::json!({"schemas":[kind.schema()],"displayname":"SCIM patch","members":[item]})
            };
            let parsed = Data::from_value(kind, seed)?.normalized()?;
            let mut item = parsed
                .get(&path.attribute)
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .cloned()
                .ok_or(INVALID)?;
            if explicit_false && path.attribute == "emails" {
                item["primary"] = Value::Bool(false);
            }
            new.push(item);
        }
        let array = draft
            .entry(path.attribute.clone())
            .or_insert_with(|| Value::Array(vec![]))
            .as_array_mut()
            .ok_or(INVALID)?;
        if path.attribute == "emails" {
            primary(array, &new)?;
        }
        for item in new {
            if path.attribute == "emails" {
                if let Some(existing) = array
                    .iter_mut()
                    .find(|v| v.get("value") == item.get("value"))
                {
                    existing
                        .as_object_mut()
                        .ok_or(INVALID)?
                        .extend(json::object(item)?);
                } else {
                    array.push(item);
                }
            } else if !array.contains(&item) {
                array.push(item);
            }
            if array.len() > max {
                return Err(LIMIT);
            }
        }
    } else if op == Op::Add && path.attribute == "name" {
        let values = json::object(value.ok_or(INVALID)?)?;
        let target = draft
            .entry("name")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or(INVALID)?;
        target.extend(values);
    } else {
        draft.insert(path.attribute.clone(), value.ok_or(INVALID)?);
    }
    Ok(())
}
fn primary(array: &mut [Value], new: &[Value]) -> Result<()> {
    let count = new
        .iter()
        .filter(|v| v.get("primary") == Some(&Value::Bool(true)))
        .count();
    if count > 1 {
        return Err(INVALID);
    }
    if count == 1 {
        for value in array {
            value.as_object_mut().ok_or(INVALID)?.remove("primary");
        }
    }
    Ok(())
}
fn filtered(
    draft: &mut Map<String, Value>,
    op: Op,
    path: &Path,
    selector: &(String, String),
    value: Option<Value>,
) -> Result<()> {
    let array = draft
        .get_mut(&path.attribute)
        .and_then(Value::as_array_mut)
        .ok_or(TARGET)?;
    let indices: Vec<_> = array
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            query::selected(v, &selector.0, &selector.1, path.attribute == "members").then_some(i)
        })
        .collect();
    if indices.is_empty() {
        return Err(TARGET);
    }
    if let Some(sub) = &path.sub {
        if sub == "primary" && value == Some(Value::Bool(true)) {
            if indices.len() != 1 {
                return Err(INVALID);
            }
            for item in array.iter_mut() {
                item.as_object_mut().ok_or(INVALID)?.remove("primary");
            }
        }
        for index in indices {
            let object = array[index].as_object_mut().ok_or(INVALID)?;
            if op == Op::Remove {
                if object.remove(sub).is_none() {
                    return Err(TARGET);
                }
            } else {
                object.insert(sub.clone(), value.clone().ok_or(INVALID)?);
            }
        }
    } else if op == Op::Remove {
        for index in indices.into_iter().rev() {
            array.remove(index);
        }
    } else {
        // Replacing a selected membership's immutable value would obscure
        // removals in a review. Clients use explicit remove followed by add.
        if path.attribute == "members" {
            return Err(MUTABILITY);
        }
        let replacement = json::object(value.ok_or(INVALID)?)?;
        if replacement.get("primary") == Some(&Value::Bool(true)) {
            if indices.len() != 1 {
                return Err(INVALID);
            }
            for item in array.iter_mut() {
                item.as_object_mut().ok_or(INVALID)?.remove("primary");
            }
        }
        for index in indices {
            if op == Op::Add {
                array[index]
                    .as_object_mut()
                    .ok_or(INVALID)?
                    .extend(replacement.clone());
            } else {
                array[index] = Value::Object(replacement.clone());
            }
        }
    }
    Ok(())
}
