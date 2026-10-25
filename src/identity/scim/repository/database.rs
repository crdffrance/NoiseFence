use anyhow::{Context, Result};
use std::future::Future;
#[derive(Clone)]
pub(crate) enum Param {
    Text(Option<String>),
    Integer(Option<i64>),
}
impl From<&str> for Param {
    fn from(v: &str) -> Self {
        Self::Text(Some(v.into()))
    }
}
impl From<String> for Param {
    fn from(v: String) -> Self {
        Self::Text(Some(v))
    }
}
impl From<i64> for Param {
    fn from(v: i64) -> Self {
        Self::Integer(Some(v))
    }
}
#[derive(Clone)]
pub(crate) enum Cell {
    Text(String),
    Integer(i64),
    Null,
}
pub(crate) struct Row(pub Vec<Cell>);
impl Row {
    pub fn text(&self, i: usize) -> Result<&str> {
        match self.0.get(i) {
            Some(Cell::Text(v)) => Ok(v),
            _ => anyhow::bail!("Invalid SCIM text column"),
        }
    }
    pub fn integer(&self, i: usize) -> Result<i64> {
        match self.0.get(i) {
            Some(Cell::Integer(v)) => Ok(*v),
            _ => anyhow::bail!("Invalid SCIM integer column"),
        }
    }
}
pub(crate) trait Database {
    fn query<'a>(
        &'a mut self,
        sql: &'a str,
        params: &'a [Param],
    ) -> impl Future<Output = Result<Vec<Row>>> + Send + 'a;
    fn execute<'a>(
        &'a mut self,
        sql: &'a str,
        params: &'a [Param],
    ) -> impl Future<Output = Result<u64>> + Send + 'a;
}
pub(crate) async fn scalar(db: &mut impl Database, sql: &str, params: &[Param]) -> Result<i64> {
    let rows = db.query(sql, params).await?;
    rows.first().context("Missing SCIM aggregate")?.integer(0)
}
