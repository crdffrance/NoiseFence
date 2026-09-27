//! Central management persistence. SMTP queues and body replication remain local.
pub mod accounts;
pub mod adaptive;
pub mod admin;
pub mod commands;
pub mod diagnostics;
pub mod feedback;
pub mod history;
pub mod invitations;
pub mod learning;
pub mod logs;
pub mod mfa;
pub mod nodes;
pub mod outbox;
pub mod policies;
pub mod quality;
pub mod research;
pub mod research_worker;
pub mod search;
mod settings;
pub mod transport;
pub use settings::Settings;

use anyhow::{Result, ensure};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime, Timeouts};
use std::{io::Read, sync::Arc, time::Duration};
use tokio_postgres_rustls::MakeRustlsConnect;

#[derive(Clone)]
pub struct Central {
    // Separate pools prevent long console reads from starving durable ingestion.
    pub(crate) interactive: Pool,
    pub(crate) ingestion: Pool,
}

/// PostgreSQL may include submitted values in error details. Only expose SQLSTATE.
pub(crate) fn database_error(error: tokio_postgres::Error) -> anyhow::Error {
    match error.code() {
        Some(code) => anyhow::anyhow!(
            "Central database operation failed (SQLSTATE {})",
            code.code()
        ),
        None => anyhow::anyhow!("Central database connection unavailable"),
    }
}

impl Central {
    /// Creates lazy, bounded pools. SMTP startup does not wait for PostgreSQL.
    pub fn new(settings: &Settings) -> Result<Self> {
        settings.validate()?;
        let mut config = tokio_postgres::Config::new();
        config.host(&settings.host).port(settings.port)
            .dbname(&settings.database).user(&settings.username)
            .application_name("noisefence-management")
            .connect_timeout(Duration::from_secs(3))
            .options("-c search_path=noisefence,pg_catalog -c statement_timeout=3000 -c lock_timeout=500 -c idle_in_transaction_session_timeout=10000");
        if let Some(password) = settings.password()? {
            config.password(password);
        }
        let local = settings.host.starts_with('/') || settings.allow_loopback_plaintext;
        config.ssl_mode(if local {
            tokio_postgres::config::SslMode::Disable
        } else {
            tokio_postgres::config::SslMode::Require
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = &settings.ca_file {
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= 1024 * 1024,
                "Database CA bundle exceeds limit"
            );
            let certs = rustls_pemfile::certs(&mut bytes.as_slice())
                .collect::<std::result::Result<Vec<_>, _>>()?;
            ensure!(!certs.is_empty(), "Empty database CA bundle");
            for cert in certs {
                roots.add(cert)?;
            }
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let build = |capacity| -> Result<Pool> {
            let manager = Manager::from_config(
                config.clone(),
                MakeRustlsConnect::new(tls.clone()),
                ManagerConfig {
                    recycling_method: RecyclingMethod::Fast,
                },
            );
            Ok(Pool::builder(manager)
                .max_size(capacity)
                .runtime(Runtime::Tokio1)
                .timeouts(Timeouts {
                    wait: Some(Duration::from_secs(2)),
                    create: Some(Duration::from_secs(4)),
                    recycle: Some(Duration::from_secs(2)),
                })
                .build()?)
        };
        Ok(Self {
            interactive: build(settings.max_connections)?,
            ingestion: build(2)?,
        })
    }

    pub async fn health(&self) -> Result<()> {
        let db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central database pool unavailable"))?;
        let value: i32 = db
            .query_one("SELECT 1::integer", &[])
            .await
            .map_err(database_error)?
            .get(0);
        ensure!(value == 1, "Central database health mismatch");
        Ok(())
    }

    /// Explicit administrator action; never run DDL in an SMTP transaction.
    pub async fn migrate(&self) -> Result<()> {
        let mut db = self
            .ingestion
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central migration connection unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        tx.query_one("SELECT pg_advisory_xact_lock(719021428123::bigint)", &[])
            .await
            .map_err(database_error)?;
        tx.batch_execute("CREATE SCHEMA IF NOT EXISTS noisefence; CREATE TABLE IF NOT EXISTS noisefence.schema_migrations(version integer PRIMARY KEY, sha256 text NOT NULL, applied_at bigint NOT NULL)").await.map_err(database_error)?;
        let schema = include_str!("schema.sql");
        let digest = crate::message::digest(schema.as_bytes());
        if let Some(row) = tx
            .query_opt(
                "SELECT sha256 FROM noisefence.schema_migrations WHERE version=1",
                &[],
            )
            .await
            .map_err(database_error)?
        {
            ensure!(
                row.get::<_, String>(0) == digest,
                "Central schema migration checksum mismatch"
            );
        } else {
            tx.batch_execute(schema).await.map_err(database_error)?;
            tx.execute(
                "INSERT INTO noisefence.schema_migrations VALUES(1,$1,$2)",
                &[&digest, &crate::now()],
            )
            .await
            .map_err(database_error)?;
        }
        let latest: i32 = tx
            .query_one("SELECT MAX(version) FROM noisefence.schema_migrations", &[])
            .await
            .map_err(database_error)?
            .get(0);
        ensure!(latest == 1, "Central schema is newer than this application");
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
}
