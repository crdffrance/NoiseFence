//! Bounded SCIM provisioning primitives. These do not install an HTTP endpoint,
//! authorize a client, persist a mutation or publish a directory. The selected
//! management repository must transact source authorization, uniqueness and
//! resource changes before acknowledging a request. See docs/identity-scim.md.
mod json;
mod patch;
mod query;
mod resource;
mod staging;

pub use query::{Filter, ListQuery};
pub use resource::{Data, Resource, ResourceType};
pub use staging::{Candidate, Revision};

pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
pub const MAX_OPERATIONS: usize = 100;
pub const MAX_MEMBERS: usize = 4096;
pub const MAX_PAGE: usize = 100;
pub type Result<T> = std::result::Result<T, Error>;

/// Only constant explanations: provider JSON, identifiers and credentials must
/// not appear in error bodies or logs. Transport failures are handled separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub status: u16,
    pub scim_type: &'static str,
    pub detail: &'static str,
}
impl Error {
    pub const fn new(status: u16, scim_type: &'static str, detail: &'static str) -> Self {
        Self {
            status,
            scim_type,
            detail,
        }
    }
    pub fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": self.status.to_string(), "scimType": self.scim_type,
            "detail": self.detail
        })
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.detail)
    }
}
impl std::error::Error for Error {}
pub(crate) const INVALID: Error = Error::new(
    400,
    "invalidValue",
    "Invalid or unsupported SCIM attribute value.",
);
pub(crate) const SYNTAX: Error =
    Error::new(400, "invalidSyntax", "Invalid or ambiguous SCIM JSON.");
pub(crate) const PATH: Error = Error::new(400, "invalidPath", "Unsupported SCIM attribute path.");
pub(crate) const TARGET: Error = Error::new(400, "noTarget", "No matching SCIM attribute value.");
pub(crate) const LIMIT: Error =
    Error::new(413, "tooMany", "SCIM complexity or size limit exceeded.");
pub(crate) const MUTABILITY: Error = Error::new(
    400,
    "mutability",
    "Required or read-only SCIM attribute cannot be changed.",
);
pub(crate) const STALE: Error = Error::new(
    412,
    "invalidVers",
    "SCIM resource version changed; read the resource again.",
);

#[cfg(test)]
mod tests;
