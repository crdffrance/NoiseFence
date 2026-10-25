//! Discovery describes the implemented restricted profile, not a full IdP suite.
use super::{INVALID, NOT_FOUND};
use crate::identity::scim::{self, ResourceType};
use serde_json::{Value, json};
const PREFIX: &str = "urn:ietf:params:scim:schemas:core:2.0:";
fn attribute(
    name: &str,
    kind: &str,
    required: bool,
    multi: bool,
    mutable: &str,
    exact: bool,
    unique: &str,
) -> Value {
    json!({"name":name,"type":kind,"multiValued":multi,"description":format!("Supported {name} attribute."),"required":required,"caseExact":exact,"mutability":mutable,"returned":"default","uniqueness":unique})
}
fn schema(kind: ResourceType, base: &str) -> Value {
    let mut attributes = vec![
        attribute("id", "string", false, false, "readOnly", true, "server"),
        attribute(
            "externalId",
            "string",
            false,
            false,
            "readWrite",
            true,
            "none",
        ),
        attribute(
            "displayName",
            "string",
            kind == ResourceType::Group,
            false,
            "readWrite",
            false,
            "none",
        ),
    ];
    if kind == ResourceType::User {
        attributes.push(attribute(
            "userName",
            "string",
            true,
            false,
            "readWrite",
            false,
            "server",
        ));
        attributes.push(attribute(
            "active",
            "boolean",
            false,
            false,
            "readWrite",
            false,
            "none",
        ));
        let mut name = attribute("name", "complex", false, false, "readWrite", false, "none");
        name["subAttributes"] = json!(
            [
                "formatted",
                "givenName",
                "familyName",
                "middleName",
                "honorificPrefix",
                "honorificSuffix"
            ]
            .map(|name| attribute(
                name,
                "string",
                false,
                false,
                "readWrite",
                false,
                "none"
            ))
        );
        attributes.push(name);
        let mut emails = attribute("emails", "complex", false, true, "readWrite", false, "none");
        emails["subAttributes"] = json!([
            attribute("value", "string", true, false, "readWrite", false, "none"),
            attribute("type", "string", false, false, "readWrite", false, "none"),
            attribute(
                "primary",
                "boolean",
                false,
                false,
                "readWrite",
                false,
                "none"
            ),
        ]);
        attributes.push(emails);
    } else {
        let mut members = attribute(
            "members",
            "complex",
            false,
            true,
            "readWrite",
            false,
            "none",
        );
        let mut types = attribute("type", "string", false, false, "immutable", true, "none");
        types["canonicalValues"] = json!(["User", "Group"]);
        members["subAttributes"] = json!([
            attribute("value", "string", true, false, "immutable", true, "none"),
            types
        ]);
        attributes.push(members);
    }
    json!({"schemas":[format!("{PREFIX}Schema")],"id":kind.schema(),"name":kind.name(),"description":"NoiseFence restricted provisioning profile. See deployment documentation for supported attributes and filters; provisioning does not grant mailbox or console access.","attributes":attributes,"meta":{"resourceType":"Schema","location":format!("{base}/Schemas/{}",kind.schema())}})
}
fn resource_type(kind: ResourceType, base: &str) -> Value {
    json!({"schemas":[format!("{PREFIX}ResourceType")],"id":kind.name(),"name":kind.name(),"description":"Staged directory identity; administrator review required before runtime use.","endpoint":format!("/{}",kind.endpoint()),"schema":kind.schema(),"schemaExtensions":[],"meta":{"resourceType":"ResourceType","location":format!("{base}/ResourceTypes/{}",kind.name())}})
}
pub(super) fn get(
    base: &str,
    endpoint: &str,
    id: Option<&str>,
    args: &[(String, String)],
) -> scim::Result<Value> {
    if endpoint == "ServiceProviderConfig" {
        if id.is_some() {
            return Err(NOT_FOUND);
        }
        if !args.is_empty() {
            return Err(INVALID);
        }
        return Ok(json!({"schemas":[format!("{PREFIX}ServiceProviderConfig")],
            "documentationUri":"https://github.com/crdffrance/NoiseFence/blob/master/docs/identity-scim.md",
            "patch":{"supported":true},"bulk":{"supported":false,"maxOperations":0,"maxPayloadSize":0},
            "filter":{"supported":true,"maxResults":scim::MAX_PAGE},"changePassword":{"supported":false},"sort":{"supported":false},"etag":{"supported":true},
            "authenticationSchemes":[{"type":"oauthbearertoken","name":"Source-scoped bearer","description":"Administrator-issued expiring bearer bound to one NoiseFence source. No OAuth authorization endpoint is provided.","specUri":"https://www.rfc-editor.org/rfc/rfc6750.html","primary":true}],
            "meta":{"resourceType":"ServiceProviderConfig","location":format!("{base}/ServiceProviderConfig")}}));
    }
    let resources: Vec<_> = [ResourceType::User, ResourceType::Group]
        .into_iter()
        .map(|kind| {
            if endpoint == "ResourceTypes" {
                resource_type(kind, base)
            } else {
                schema(kind, base)
            }
        })
        .collect();
    if let Some(id) = id {
        if !args.is_empty() {
            return Err(INVALID);
        }
        return resources
            .into_iter()
            .find(|r| r["id"] == id)
            .ok_or(NOT_FOUND);
    }
    if args
        .iter()
        .any(|(name, _)| !matches!(name.as_str(), "startIndex" | "count"))
    {
        return Err(INVALID);
    }
    let query = scim::ListQuery::parse(ResourceType::User, args)?;
    let total = resources.len();
    let page: Vec<_> = resources
        .into_iter()
        .skip(query.start_index.saturating_sub(1))
        .take(query.count)
        .collect();
    Ok(
        json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":total,"startIndex":query.start_index,"itemsPerPage":page.len(),"Resources":page}),
    )
}
