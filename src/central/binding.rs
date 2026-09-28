//! Runtime database identity, independent of the hostname or database name.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub instance: String,
    pub source_digest: String,
}
pub const HEADER: &str = "x-noisefence-management-authority";

pub(crate) fn header_value(
    binding: Option<&Binding>,
) -> Result<Option<reqwest::header::HeaderValue>> {
    binding
        .map(|binding| {
            binding.validate()?;
            Ok(reqwest::header::HeaderValue::from_str(&format!(
                "{}:{}",
                binding.instance, binding.source_digest
            ))?)
        })
        .transpose()
}
pub(crate) fn check_headers(
    headers: &reqwest::header::HeaderMap,
    binding: Option<&Binding>,
) -> Result<()> {
    let expected = header_value(binding)?;
    let mut values = headers.get_all(HEADER).iter();
    ensure!(
        values.next() == expected.as_ref() && values.next().is_none(),
        "Management database authority mismatch"
    );
    Ok(())
}
pub(crate) fn request(
    request: reqwest::RequestBuilder,
    binding: Option<&Binding>,
) -> Result<reqwest::RequestBuilder> {
    Ok(match header_value(binding)? {
        Some(value) => request.header(HEADER, value),
        None => request,
    })
}
pub(crate) async fn selected(store: &crate::store::Store) -> Result<Option<Binding>> {
    store
        .read(|db| Ok(super::selection::Selection::read(db)?.map(|s| s.database)))
        .await
}

impl Binding {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            uuid::Uuid::parse_str(&self.instance).is_ok_and(|id| id.to_string() == self.instance)
                && crate::compatibility::valid_hash(&self.source_digest),
            "Invalid central database binding"
        );
        Ok(())
    }

    pub(super) fn hook(&self) -> deadpool_postgres::Hook {
        let binding = self.clone();
        let schema = crate::message::digest(include_bytes!("schema.sql"));
        deadpool_postgres::Hook::async_fn(move |client, _| {
            let binding = binding.clone();
            let schema = schema.clone();
            Box::pin(async move {
                // Pool hooks are not covered by deadpool's create/recycle
                // timeouts. Give this indexed identity check its own deadline.
                let verified = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    client.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.migration_state WHERE id=1 AND source_digest=$1 AND report->>'instance'=$2 AND activated_at IS NOT NULL) AND EXISTS(SELECT 1 FROM noisefence.schema_migrations WHERE version=1 AND sha256=$3) AND NOT EXISTS(SELECT 1 FROM noisefence.schema_migrations WHERE version<>1)", &[&binding.source_digest,&binding.instance,&schema]).await.map(|row|row.get::<_,bool>(0))
                }).await;
                match verified {
                    Ok(Ok(true)) => Ok(()),
                    _ => Err(deadpool_postgres::HookError::message(
                        "Central database binding is unavailable or does not match",
                    )),
                }
            })
        })
    }
}
