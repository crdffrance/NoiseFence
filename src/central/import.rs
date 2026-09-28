//! Offline migration primitives and explicit final authority activation.
mod activation;
pub mod frozen;
pub mod installation;
mod locks;
pub mod offline;
pub mod session;
pub use locks::SourceLocks;
pub(crate) mod json_equivalence;
mod parity;
mod staged;
mod status;
pub use staged::{PreparedImport, StagedImport};
pub use status::ImportStatus;
mod reconcile;
pub use reconcile::{ReconciledSpools, ReconciliationReport};
mod spool;
pub use spool::{Mirror, MirrorLog, SpoolSnapshot};
mod delivery_ids;
pub use delivery_ids::DeliveryIdentities;
mod policy;
pub use policy::PolicySnapshot;
mod quality;
use super::{Central, database_error};
use anyhow::{Context, Result, ensure};
pub use quality::QualitySnapshot;
use serde_json::Value;

struct Table {
    name: &'static str,
    sqlite: &'static str,
    columns: &'static str,
    types: &'static str,
    insert: &'static str,
    select: &'static str,
    order: &'static str,
}
const TABLES: &[Table] = &[
    Table {
        name: "users",
        sqlite: "SELECT json_object('username',u.username,'password',u.password,'admin',json(CASE u.admin WHEN 0 THEN 'false' ELSE 'true' END),'disabled',json(CASE u.disabled WHEN 0 THEN 'false' ELSE 'true' END),'version',coalesce(v.version,0)) FROM users u LEFT JOIN console_user_versions v ON v.username=u.username ORDER BY u.username",
        columns: "username,password,admin,disabled,version",
        types: "username text,password text,admin boolean,disabled boolean,version bigint",
        insert: "username,password,admin,disabled,version",
        select: "username,password,admin,disabled,version",
        order: "username COLLATE \"C\"",
    },
    Table {
        name: "grants",
        sqlite: "SELECT json_object('username',username,'address',address) FROM grants ORDER BY username,address",
        columns: "username,address",
        types: "username text,address text",
        insert: "username,address",
        select: "username,address",
        order: "username COLLATE \"C\",address COLLATE \"C\"",
    },
    Table {
        name: "sessions",
        sqlite: "SELECT json_object('token_hash',s.token_hash,'username',s.username,'csrf',s.csrf,'expires',s.expires,'mfa_verified',json(CASE WHEN m.token_hash IS NULL THEN 'false' ELSE 'true' END)) FROM sessions s LEFT JOIN mfa_sessions m ON m.token_hash=s.token_hash ORDER BY s.token_hash",
        columns: "token_hash,username,csrf,expires,mfa_verified",
        types: "token_hash text,username text,csrf text,expires bigint,mfa_verified boolean",
        insert: "token_hash,username,csrf,expires,mfa_verified",
        select: "token_hash,username,csrf,expires,mfa_verified",
        order: "token_hash COLLATE \"C\"",
    },
    Table {
        name: "mfa_credentials",
        sqlite: "SELECT json_object('username',username,'secret',lower(hex(secret)),'enabled',json(CASE enabled WHEN 0 THEN 'false' ELSE 'true' END),'pending_until',pending_until,'last_step',last_step) FROM mfa_credentials ORDER BY username",
        columns: "username,secret,enabled,pending_until,last_step",
        types: "username text,secret text,enabled boolean,pending_until bigint,last_step bigint",
        insert: "username,decode(secret,'hex'),enabled,pending_until,last_step",
        select: "username,encode(secret,'hex') AS secret,enabled,pending_until,last_step",
        order: "username COLLATE \"C\"",
    },
    Table {
        name: "mfa_recovery",
        sqlite: "SELECT json_object('username',username,'digest',digest) FROM mfa_recovery ORDER BY username,digest",
        columns: "username,digest",
        types: "username text,digest text",
        insert: "username,digest",
        select: "username,digest",
        order: "username COLLATE \"C\",digest COLLATE \"C\"",
    },
    Table {
        name: "mfa_attempts",
        sqlite: "SELECT json_object('username',username,'until',until,'attempts',attempts) FROM mfa_attempts ORDER BY username",
        columns: "username,until,attempts",
        types: "username text,until bigint,attempts integer",
        insert: "username,until,attempts",
        select: "username,until,attempts",
        order: "username COLLATE \"C\"",
    },
    Table {
        name: "invitations",
        sqlite: "SELECT json_object('id',id,'token_hash',token_hash,'username',username,'admin',json(CASE admin WHEN 0 THEN 'false' ELSE 'true' END),'addresses',json(addresses),'creator',creator,'creator_version',creator_version,'created',created,'expires',expires,'version',version,'revoked',revoked,'accepted',accepted) FROM console_invitations ORDER BY id",
        columns: "id,token_hash,username,admin,addresses,creator,creator_version,created,expires,version,revoked,accepted",
        types: "id text,token_hash text,username text,admin boolean,addresses jsonb,creator text,creator_version bigint,created bigint,expires bigint,version bigint,revoked bigint,accepted bigint",
        insert: "id,token_hash,username,admin,addresses,creator,creator_version,created,expires,version,revoked,accepted",
        select: "id,token_hash,username,admin,addresses,creator,creator_version,created,expires,version,revoked,accepted",
        order: "id COLLATE \"C\"",
    },
];

/// Sensitive in-memory snapshot: deliberately has no Debug or Serialize API.
/// The final offline importer must hold the daemon/worker locks throughout its
/// complete snapshot, copy, verification and activation sequence.
pub struct AccountsSnapshot {
    tables: Vec<Vec<Value>>,
}
impl AccountsSnapshot {
    /// Read all account state from the caller's consistent SQLite transaction.
    /// The original external MFA key is required whenever sealed records exist.
    pub fn capture(tx: &rusqlite::Transaction<'_>, key: Option<&crate::mfa::Key>) -> Result<Self> {
        ensure!(
            tx.prepare("PRAGMA foreign_key_check")?
                .query([])?
                .next()?
                .is_none(),
            "Migration source has inconsistent foreign keys"
        );
        ensure!(
            tx.query_row("SELECT count(*) FROM mfa_credentials WHERE length(secret)<>48 OR length(username)>100", [], |r| r.get::<_, i64>(0))? == 0,
            "Invalid sealed factor in migration source"
        );
        ensure!(
            tx.query_row(
                "SELECT count(*) FROM users WHERE admin NOT IN (0,1) OR disabled NOT IN (0,1)",
                [],
                |r| r.get::<_, i64>(0)
            )? == 0
                && tx.query_row(
                    "SELECT count(*) FROM mfa_credentials WHERE enabled NOT IN (0,1)",
                    [],
                    |r| r.get::<_, i64>(0)
                )? == 0
                && tx.query_row(
                    "SELECT count(*) FROM console_invitations WHERE admin NOT IN (0,1)",
                    [],
                    |r| r.get::<_, i64>(0)
                )? == 0,
            "Invalid account boolean in migration source"
        );
        let mut factors = tx.prepare("SELECT username,secret FROM mfa_credentials LIMIT 1001")?;
        let mut rows = factors.query([])?;
        let mut count = 0;
        while let Some(row) = rows.next()? {
            count += 1;
            ensure!(count <= 1000, "Migration account limit exceeded");
            let username: String = row.get(0)?;
            let sealed: Vec<u8> = row.get(1)?;
            key.context("Restore the original MFA key before importing accounts")?
                .open_secret(&username, &sealed)?;
        }
        let tables = capture_tables(tx, TABLES, 16 * 1024 * 1024, 256 * 1024)?;
        ensure!(tables[0].len() <= 1000, "Migration account limit exceeded");
        Ok(Self { tables })
    }
}
impl Central {
    /// Copy account state into an unused destination, compare every projected
    /// value, and commit all seven tables together. No source data is modified.
    /// This is a development primitive, not a complete migration or activation.
    pub async fn import_accounts(&self, snapshot: &AccountsSnapshot) -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let mut db = self
                .ingestion
                .get()
                .await
                .map_err(|_| anyhow::anyhow!("Migration database unavailable"))?;
            let tx = db.transaction().await.map_err(database_error)?;
            super::admin::management_lock(&tx).await?;
            // Block both account mutations and authentication during the copy.
            // These names are compile-time constants, never imported identifiers.
            let names = TABLES
                .iter()
                .map(|t| format!("noisefence.{}", t.name))
                .collect::<Vec<_>>()
                .join(",");
            tx.batch_execute(&format!(
                "LOCK TABLE {names},noisefence.sources IN ACCESS EXCLUSIVE MODE"
            ))
            .await
            .map_err(database_error)?;
            let sources: i64 = tx
                .query_one("SELECT count(*) FROM noisefence.sources", &[])
                .await
                .map_err(database_error)?
                .get(0);
            ensure!(
                sources == 0,
                "Account import requires an unused central destination"
            );
            for table in TABLES {
                let count: i64 = tx
                    .query_one(
                        &format!("SELECT count(*) FROM noisefence.{}", table.name),
                        &[],
                    )
                    .await
                    .map_err(database_error)?
                    .get(0);
                ensure!(count == 0, "Account import destination is not empty");
            }
            copy_tables(&tx, TABLES, &snapshot.tables).await?;
            tx.commit().await.map_err(database_error)?;
            Ok(())
        })
        .await
        .context("Account migration deadline exceeded")?
    }
}

fn capture_tables(
    tx: &rusqlite::Transaction<'_>,
    specs: &[Table],
    max_bytes: usize,
    max_row: usize,
) -> Result<Vec<Vec<Value>>> {
    let mut tables = Vec::new();
    let mut bytes = 0;
    let mut total = 0;
    for table in specs {
        // Bound each transferred row before SQLite copies it into Rust.
        let query = format!(
            "WITH snapshot_row(payload) AS ({}) SELECT CASE WHEN length(CAST(payload AS BLOB))<={max_row} THEN payload END FROM snapshot_row LIMIT 100001",
            table.sqlite
        );
        let mut statement = tx.prepare(&query)?;
        let mut rows = statement.query([])?;
        let mut values = Vec::new();
        while let Some(row) = rows.next()? {
            let raw: String = row
                .get::<_, Option<String>>(0)?
                .context("Migration row exceeds bounds")?;
            bytes += raw.len();
            total += 1;
            ensure!(
                raw.len() <= max_row && bytes <= max_bytes && total <= 100_000,
                "Migration snapshot exceeds bounds"
            );
            values.push(serde_json::from_str(&raw)?);
        }
        tables.push(values);
    }
    Ok(tables)
}

async fn copy_tables(
    tx: &deadpool_postgres::Transaction<'_>,
    specs: &[Table],
    tables: &[Vec<Value>],
) -> Result<()> {
    for (table, values) in specs.iter().zip(tables) {
        for chunk in values.chunks(250) {
            let payload = Value::Array(chunk.to_vec());
            tx.execute(
                &format!(
                    "INSERT INTO noisefence.{}({}) SELECT {} FROM jsonb_to_recordset($1) AS r({})",
                    table.name, table.columns, table.insert, table.types
                ),
                &[&payload],
            )
            .await
            .map_err(database_error)?;
        }
    }
    verify_tables(tx, specs, tables).await
}

async fn verify_tables(
    tx: &deadpool_postgres::Transaction<'_>,
    specs: &[Table],
    tables: &[Vec<Value>],
) -> Result<()> {
    ensure!(
        specs.len() == tables.len(),
        "Migration table count mismatch"
    );
    // Check inside the same transaction, including MFA flags, sealed
    // bytes, invitation provenance and monotonic account versions.
    for (table, expected) in specs.iter().zip(tables) {
        let statement = tx
            .prepare(&format!(
                "SELECT to_jsonb(r) FROM (SELECT {} FROM noisefence.{} ORDER BY {}) r",
                table.select, table.name, table.order
            ))
            .await
            .map_err(database_error)?;
        let portal = tx.bind(&statement, &[]).await.map_err(database_error)?;
        let mut offset = 0;
        loop {
            let rows = tx
                .query_portal(&portal, 250)
                .await
                .map_err(database_error)?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let actual: Value = row.get(0);
                ensure!(
                    expected
                        .get(offset)
                        .is_some_and(|v| json_equivalence::equal(v, &actual)),
                    "Migration parity mismatch in {}",
                    table.name
                );
                offset += 1;
            }
        }
        ensure!(offset == expected.len(), "Migration row count mismatch");
    }
    Ok(())
}
