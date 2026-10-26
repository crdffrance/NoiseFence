use super::{Error, INVALID, MAX_PAGE, Resource, ResourceType, Result, resource};
use serde_json::{Value, json};
const FILTER: Error = Error::new(
    400,
    "invalidFilter",
    "Only one supported SCIM equality filter is allowed.",
);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    attribute: String,
    value: Value,
}
impl Filter {
    pub(crate) fn parts(&self) -> (&str, &Value) {
        (&self.attribute, &self.value)
    }
    pub fn parse(kind: ResourceType, value: &str) -> Result<Self> {
        let (attribute, raw) = equality(value)?;
        let value: Value = serde_json::from_str(raw).map_err(|_| FILTER)?;
        let supported = matches!(attribute.as_str(), "id" | "externalid" | "displayname")
            || (kind == ResourceType::User && matches!(attribute.as_str(), "username" | "active"));
        if !supported {
            return Err(FILTER);
        }
        if attribute == "active" {
            if !value.is_boolean() {
                return Err(FILTER);
            }
        } else {
            let text = value.as_str().ok_or(FILTER)?;
            if !crate::identity::text(text, 256) {
                return Err(FILTER);
            }
            if attribute == "username" {
                resource::login_key(text).map_err(|_| FILTER)?;
            }
        }
        Ok(Self { attribute, value })
    }
    /// Repository queries may use parameterized indexes instead. This is the
    /// reference predicate: externalId and id are case-exact, userName is not.
    pub fn matches(&self, resource: &Resource) -> bool {
        let data = resource.data();
        match self.attribute.as_str() {
            "id" => self.value.as_str() == Some(resource.id()),
            "externalid" => self
                .value
                .as_str()
                .is_some_and(|v| data.external_id() == Some(v)),
            "username" => self
                .value
                .as_str()
                .is_some_and(|v| data.user_name_key().as_deref() == Some(&v.to_ascii_lowercase())),
            "displayname" => self.value.as_str().is_some_and(|v| {
                data.display_name
                    .as_deref()
                    .is_some_and(|s| s.to_lowercase() == v.to_lowercase())
            }),
            "active" => self.value.as_bool().is_some_and(|v| data.active == Some(v)),
            _ => false,
        }
    }
}
pub(super) fn equality(raw: &str) -> Result<(String, &str)> {
    if raw.len() > 2048 {
        return Err(FILTER);
    }
    let raw = raw.trim();
    let (attribute, rest) = raw.split_once(char::is_whitespace).ok_or(FILTER)?;
    let (op, rest) = rest
        .trim_start()
        .split_once(char::is_whitespace)
        .ok_or(FILTER)?;
    if !op.eq_ignore_ascii_case("eq")
        || attribute.is_empty()
        || !attribute.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(FILTER);
    }
    Ok((attribute.to_ascii_lowercase(), rest.trim()))
}
#[derive(Clone, Debug)]
pub struct ListQuery {
    pub filter: Option<Filter>,
    pub start_index: usize,
    pub count: usize,
}
impl ListQuery {
    /// Raw URL decoding belongs to the router. Reject duplicate and unsupported
    /// arguments instead of pretending an ignored filter or projection applied.
    pub fn parse(kind: ResourceType, args: &[(String, String)]) -> Result<Self> {
        if args.len() > 3 {
            return Err(INVALID);
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut result = Self {
            filter: None,
            start_index: 1,
            count: MAX_PAGE,
        };
        for (key, value) in args {
            if value.len() > 2048 || !seen.insert(key) {
                return Err(INVALID);
            }
            match key.as_str() {
                "filter" => result.filter = Some(Filter::parse(kind, value)?),
                "startIndex" => {
                    result.start_index =
                        usize::try_from(integer(value)?.max(1)).unwrap_or(usize::MAX)
                }
                "count" => result.count = integer(value)?.clamp(0, MAX_PAGE as i64) as usize,
                _ => return Err(INVALID),
            }
        }
        Ok(result)
    }
    /// Format an already authorized, filtered page from the selected repository.
    /// Count zero asks for totals only; item count is the actual returned count.
    pub fn response(&self, total: usize, page: &[Resource]) -> Result<Value> {
        let remaining = total.saturating_sub(self.start_index.saturating_sub(1));
        if page.len() != remaining.min(self.count) {
            return Err(INVALID);
        }
        Ok(
            json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults":total,"startIndex":self.start_index,"itemsPerPage":page.len(),
            "Resources":page.iter().map(Resource::document).collect::<Vec<_>>() }),
        )
    }
}
fn integer(value: &str) -> Result<i64> {
    if value.is_empty()
        || value.len() > 16
        || !value
            .strip_prefix('-')
            .unwrap_or(value)
            .bytes()
            .all(|b| b.is_ascii_digit())
    {
        return Err(INVALID);
    }
    value.parse().map_err(|_| INVALID)
}
// Used by PATCH selectors. The array element and literal are compared as SCIM
// attributes, not as directory mailbox identities (whose local part is exact).
pub(super) fn selected(value: &Value, attribute: &str, expected: &str, case_exact: bool) -> bool {
    value
        .get(attribute)
        .and_then(Value::as_str)
        .is_some_and(|v| {
            if case_exact {
                v == expected
            } else {
                v.to_lowercase() == expected.to_lowercase()
            }
        })
}
