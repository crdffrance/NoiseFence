use super::{
    GROUP_SCHEMA, INVALID, LIMIT, MAX_BODY_BYTES, MAX_MEMBERS, Result, STALE, USER_SCHEMA, json,
};
use crate::identity::{
    directory::{self, Activity, Member, Provider, Source},
    mailbox,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json as value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ResourceType {
    User,
    Group,
}
impl ResourceType {
    pub fn schema(self) -> &'static str {
        match self {
            Self::User => USER_SCHEMA,
            Self::Group => GROUP_SCHEMA,
        }
    }
    pub fn endpoint(self) -> &'static str {
        match self {
            Self::User => "Users",
            Self::Group => "Groups",
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Group => "Group",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Email {
    pub value: String,
    pub kind: Option<String>,
    pub primary: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Data {
    pub(super) kind: ResourceType,
    pub(super) external_id: Option<String>,
    pub(super) user_name: Option<String>,
    pub(super) display_name: Option<String>,
    pub(super) name: BTreeMap<String, String>,
    pub(super) active: Option<bool>,
    pub(super) emails: Vec<Email>,
    pub(super) members: BTreeSet<Member>,
}
/// The first provisioning profile deliberately restricts login identifiers to
/// visible ASCII. This subset has unambiguous UsernameCaseMapped comparison.
/// Unicode display names and explicit email aliases remain supported. Expanding
/// userName requires a qualified PRECIS implementation, not ad-hoc lowercasing.
pub(super) fn login_key(value: &str) -> Result<String> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(INVALID);
    }
    Ok(value.to_ascii_lowercase())
}
pub(super) fn id(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value)
}
impl Data {
    pub fn parse(kind: ResourceType, bytes: &[u8]) -> Result<Self> {
        Self::from_value(kind, json::decode(bytes)?)
    }
    pub(super) fn from_value(kind: ResourceType, value: Value) -> Result<Self> {
        let mut map = json::object(value)?;
        json::schema(&mut map, kind.schema())?;
        // These attributes are assigned only by the server. They cannot change
        // resource identity, its version or group membership through a User.
        map.remove("id");
        map.remove("meta");
        if kind == ResourceType::User {
            map.remove("groups");
        }
        let external_id = json::optional(&mut map, "externalid", 256)?;
        let display_name = json::optional(&mut map, "displayname", 200)?;
        let mut result = Self {
            kind,
            external_id,
            display_name,
            user_name: None,
            name: BTreeMap::new(),
            active: None,
            emails: vec![],
            members: BTreeSet::new(),
        };
        if kind == ResourceType::User {
            let user_name = json::required(&mut map, "username", 256)?;
            login_key(&user_name)?;
            result.user_name = Some(user_name);
            result.active = json::boolean(&mut map, "active")?;
            if let Some(value) = map.remove("name").filter(|v| !v.is_null()) {
                let mut name = json::object(value)?;
                for key in [
                    "formatted",
                    "familyname",
                    "givenname",
                    "middlename",
                    "honorificprefix",
                    "honorificsuffix",
                ] {
                    if let Some(value) = json::optional(&mut name, key, 200)? {
                        result.name.insert(key.into(), value);
                    }
                }
                json::exhausted(&name)?;
            }
            let mut seen = BTreeSet::new();
            let mut primary = false;
            for value in json::list(&mut map, "emails", 32)? {
                let mut email = json::object(value)?;
                let value =
                    mailbox(&json::required(&mut email, "value", 320)?).map_err(|_| INVALID)?;
                let kind = json::optional(&mut email, "type", 40)?;
                let is_primary = json::boolean(&mut email, "primary")?.unwrap_or(false);
                // display is read-only in the multi-valued core attributes.
                email.remove("display");
                json::exhausted(&email)?;
                if !seen.insert(value.clone()) || (primary && is_primary) {
                    return Err(INVALID);
                }
                primary |= is_primary;
                result.emails.push(Email {
                    value,
                    kind,
                    primary: is_primary,
                });
            }
        } else {
            if result.display_name.is_none() {
                return Err(INVALID);
            }
            for value in json::list(&mut map, "members", MAX_MEMBERS)? {
                let mut member = json::object(value)?;
                let value = json::required(&mut member, "value", 36)?;
                if !id(&value) {
                    return Err(INVALID);
                }
                let kind = json::optional(&mut member, "type", 5)?.unwrap_or_else(|| "User".into());
                // Reference URLs and names are non-authoritative hints. Never
                // fetch them, derive scope from them, or infer an identity.
                json::optional(&mut member, "$ref", 2048)?;
                json::optional(&mut member, "display", 200)?;
                json::exhausted(&member)?;
                let member = match kind.as_str() {
                    "User" => Member::Person(value),
                    "Group" => Member::Group(value),
                    _ => return Err(INVALID),
                };
                result.members.insert(member);
            }
        }
        json::exhausted(&map)?;
        if serde_json::to_vec(&result).map_err(|_| INVALID)?.len() > MAX_BODY_BYTES {
            return Err(LIMIT);
        }
        Ok(result)
    }
    pub fn kind(&self) -> ResourceType {
        self.kind
    }
    pub fn user_name_key(&self) -> Option<String> {
        self.user_name.as_deref().map(|v| v.to_ascii_lowercase())
    }
    pub fn external_id(&self) -> Option<&str> {
        self.external_id.as_deref()
    }
    pub fn members(&self) -> &BTreeSet<Member> {
        &self.members
    }
    pub fn activity(&self) -> Activity {
        match self.active {
            Some(true) => Activity::Active,
            Some(false) => Activity::Inactive,
            None => Activity::Unknown,
        }
    }
    pub(super) fn label(&self) -> String {
        self.display_name
            .clone()
            .or_else(|| self.name.get("formatted").cloned())
            .unwrap_or_else(|| {
                let full = ["givenname", "familyname"]
                    .into_iter()
                    .filter_map(|k| self.name.get(k))
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ");
                if !full.is_empty() && full.len() <= 200 {
                    full
                } else {
                    self.user_name
                        .as_deref()
                        .unwrap_or("Unnamed identity")
                        .chars()
                        .take(200)
                        .collect()
                }
            })
    }
    /// Canonical writable representation, also used as the private PATCH draft.
    pub fn document(&self) -> Value {
        let mut map = Map::new();
        map.insert("schemas".into(), value!([self.kind.schema()]));
        if let Some(v) = &self.external_id {
            map.insert("externalId".into(), value!(v));
        }
        if let Some(v) = &self.display_name {
            map.insert("displayName".into(), value!(v));
        }
        if let Some(v) = &self.user_name {
            map.insert("userName".into(), value!(v));
        }
        if let Some(v) = self.active {
            map.insert("active".into(), value!(v));
        }
        if !self.name.is_empty() {
            map.insert(
                "name".into(),
                Value::Object(
                    self.name
                        .iter()
                        .map(|(k, v)| (camel(k).into(), value!(v)))
                        .collect(),
                ),
            );
        }
        if !self.emails.is_empty() {
            map.insert(
                "emails".into(),
                Value::Array(
                    self.emails
                        .iter()
                        .map(|e| {
                            let mut v = Map::from_iter([("value".into(), value!(e.value))]);
                            if let Some(kind) = &e.kind {
                                v.insert("type".into(), value!(kind));
                            }
                            if e.primary {
                                v.insert("primary".into(), value!(true));
                            }
                            Value::Object(v)
                        })
                        .collect(),
                ),
            );
        }
        if self.kind == ResourceType::Group {
            map.insert(
                "members".into(),
                Value::Array(
                    self.members
                        .iter()
                        .map(|m| match m {
                            Member::Person(id) => value!({"value":id,"type":"User"}),
                            Member::Group(id) => value!({"value":id,"type":"Group"}),
                        })
                        .collect(),
                ),
            );
        }
        Value::Object(map)
    }
    pub(super) fn normalized(&self) -> Result<Map<String, Value>> {
        json::object(json::decode(
            &serde_json::to_vec(&self.document()).map_err(|_| INVALID)?,
        )?)
    }
}
fn camel(key: &str) -> &str {
    match key {
        "familyname" => "familyName",
        "givenname" => "givenName",
        "middlename" => "middleName",
        "honorificprefix" => "honorificPrefix",
        "honorificsuffix" => "honorificSuffix",
        _ => key,
    }
}
/// A source is bound at creation, never taken from provisioning JSON. Decoding a
/// durable row also validates this binding and all resource data before use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    source_id: String,
    source_sha256: String,
    id: String,
    version: u64,
    created: i64,
    modified: i64,
    data: Data,
}
impl Resource {
    pub fn create(source: &Source, data: Data, now: i64) -> Result<Self> {
        Self::source(source)?;
        let result = Self {
            source_id: source.id.clone(),
            source_sha256: super::staging::source_digest(source)?,
            id: uuid::Uuid::new_v4().to_string(),
            version: 1,
            created: now,
            modified: now,
            data,
        };
        result.validate(source)?;
        Ok(result)
    }
    pub fn source_id(&self) -> &str {
        &self.source_id
    }
    pub(super) fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn data(&self) -> &Data {
        &self.data
    }
    pub fn modified(&self) -> i64 {
        self.modified
    }
    pub fn etag(&self) -> String {
        format!("W/\"{}:{}\"", self.id, self.version)
    }
    pub fn precondition(&self, expected: Option<&str>) -> Result<()> {
        if expected.is_some_and(|v| v != "*" && v != self.etag()) {
            Err(STALE)
        } else {
            Ok(())
        }
    }
    pub fn replace(&self, bytes: &[u8], expected: Option<&str>, now: i64) -> Result<Self> {
        self.changed(Data::parse(self.data.kind, bytes)?, expected, now)
    }
    pub fn patch(&self, bytes: &[u8], expected: Option<&str>, now: i64) -> Result<Self> {
        self.precondition(expected)?;
        self.changed(super::patch::apply(&self.data, bytes)?, expected, now)
    }
    pub(super) fn changed(&self, data: Data, expected: Option<&str>, now: i64) -> Result<Self> {
        self.precondition(expected)?;
        if now < self.modified || !(1..=253402300799).contains(&now) {
            return Err(INVALID);
        }
        if data == self.data {
            return Ok(self.clone());
        }
        let mut next = self.clone();
        next.version = self
            .version
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(LIMIT)?;
        next.modified = now;
        next.data = data;
        Ok(next)
    }
    pub(crate) fn storage_base(&self, source: &Source) -> Result<String> {
        let mut base = self.clone();
        base.data.members.clear();
        String::from_utf8(base.encode(source)?).map_err(|_| INVALID)
    }
    pub(crate) fn with_stored_members(
        mut self,
        source: &Source,
        members: BTreeSet<Member>,
    ) -> Result<Self> {
        if !self.data.members.is_empty()
            || members.len() > MAX_MEMBERS
            || (self.data.kind == ResourceType::User && !members.is_empty())
        {
            return Err(INVALID);
        }
        self.data.members = members;
        self.validate(source)?;
        Ok(self)
    }
    pub(crate) fn membership_removed(&self, now: i64) -> Result<Self> {
        if self.data.kind != ResourceType::Group
            || !self.data.members.is_empty()
            || now < self.modified
            || now > 253402300799
        {
            return Err(INVALID);
        }
        let mut next = self.clone();
        next.version = self
            .version
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(LIMIT)?;
        next.modified = now;
        Ok(next)
    }
    pub fn document(&self) -> Value {
        let mut body = self.data.document();
        body["id"] = value!(self.id);
        body["meta"] = value!({"resourceType":self.data.kind.name(),"version":self.etag(),
            "created":mail_parser::DateTime::from_timestamp(self.created).to_rfc3339(),
            "lastModified":mail_parser::DateTime::from_timestamp(self.modified).to_rfc3339()});
        body
    }
    pub fn encode(&self, source: &Source) -> Result<Vec<u8>> {
        self.validate(source)?;
        let bytes = serde_json::to_vec(self).map_err(|_| INVALID)?;
        if bytes.len() > MAX_BODY_BYTES + 1024 {
            return Err(LIMIT);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], source: &Source) -> Result<Self> {
        if bytes.len() > MAX_BODY_BYTES + 1024 {
            return Err(LIMIT);
        }
        // Only this source-aware entry point can reconstruct a durable row;
        // Resource intentionally has no public Deserialize implementation.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            source_id: String,
            source_sha256: String,
            id: String,
            version: u64,
            created: i64,
            modified: i64,
            data: Data,
        }
        let row: Stored = serde_json::from_slice(bytes).map_err(|_| INVALID)?;
        let value = Self {
            source_id: row.source_id,
            source_sha256: row.source_sha256,
            id: row.id,
            version: row.version,
            created: row.created,
            modified: row.modified,
            data: row.data,
        };
        value.validate(source)?;
        Ok(value)
    }
    fn source(source: &Source) -> Result<()> {
        source.validate().map_err(|_| INVALID)?;
        if source.provider != Provider::Scim {
            return Err(INVALID);
        }
        Ok(())
    }
    pub fn validate(&self, source: &Source) -> Result<()> {
        Self::source(source)?;
        if self.source_id != source.id
            || self.source_sha256 != super::staging::source_digest(source)?
            || !id(&self.id)
            || !(1..=i64::MAX as u64).contains(&self.version)
            || !(1..=253402300799).contains(&self.created)
            || self.modified < self.created
            || self.modified > 253402300799
        {
            return Err(INVALID);
        }
        if Data::from_value(self.data.kind, Value::Object(self.data.normalized()?))? != self.data {
            return Err(INVALID);
        }
        Ok(())
    }
    pub(super) fn person(&self) -> directory::Person {
        directory::Person {
            id: self.id.clone(),
            display_name: self.data.label(),
            kind: directory::Kind::Person,
            activity: self.data.activity(),
            addresses: self.data.emails.iter().map(|e| e.value.clone()).collect(),
            protected_roles: BTreeSet::new(),
        }
    }
    pub(super) fn group(&self) -> directory::Group {
        directory::Group {
            id: self.id.clone(),
            display_name: self.data.label(),
            activity: Activity::Unknown,
            addresses: BTreeSet::new(),
            protected: false,
        }
    }
}
