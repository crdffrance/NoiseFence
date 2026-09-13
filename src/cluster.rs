//! Autonomous SMTP nodes, a single configuration authority, and durable metadata exchange.
pub mod artifacts;
pub mod budget;
pub mod history;
pub mod protocol;
pub mod worker;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Coordinator,
    Worker,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub role: Role,
    pub node_id: String,
    pub coordinator_url: Option<String>,
    pub credential_file: Option<PathBuf>,
    #[serde(default = "poll")]
    pub poll_seconds: u64,
    #[serde(default = "stale")]
    pub max_stale_seconds: i64,
    #[serde(default)]
    pub allow_loopback_http: bool,
}
fn poll() -> u64 {
    10
}
fn stale() -> i64 {
    86400
}
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 40
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b))
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(valid_id(&self.node_id), "Identifiant de nœud invalide.");
        ensure!(
            (2..=300).contains(&self.poll_seconds)
                && (60..=7 * 86400).contains(&self.max_stale_seconds),
            "Délais de synchronisation invalides."
        );
        match self.role {
            Role::Coordinator => ensure!(
                self.coordinator_url.is_none() && self.credential_file.is_none(),
                "Le coordinateur ne possède pas de serveur amont."
            ),
            Role::Worker => {
                let url = reqwest::Url::parse(self.coordinator_url.as_deref().unwrap_or_default())?;
                let local = matches!(url.host_str(), Some("127.0.0.1" | "[::1]"));
                ensure!(
                    url.scheme() == "https"
                        || (self.allow_loopback_http && local && url.scheme() == "http"),
                    "La synchronisation exige HTTPS (HTTP réservé aux essais loopback explicites)."
                );
                ensure!(
                    url.username().is_empty()
                        && url.password().is_none()
                        && url.query().is_none()
                        && url.fragment().is_none()
                        && url.path() == "/",
                    "Utilisez l’origine HTTPS du coordinateur sans chemin ni identifiants."
                );
                ensure!(
                    self.credential_file
                        .as_ref()
                        .is_some_and(|p| p.is_absolute()),
                    "Fichier privé d’identité du nœud requis."
                );
            }
        }
        Ok(())
    }
}
pub fn is_worker(config: &crate::config::Config) -> bool {
    config
        .cluster
        .as_ref()
        .is_some_and(|c| c.role == Role::Worker)
}
pub async fn prepare(config: &crate::config::Config, store: &crate::store::Store) -> Result<()> {
    if config.cluster.is_none() {
        store.read(|db| {
            ensure!(!db.query_row("SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key='role')", [], |r| r.get::<_, bool>(0))?,
                "Ce stockage appartient à un cluster ; sa configuration de nœud est obligatoire.");
            Ok(())
        }).await?;
        return Ok(());
    }
    let settings = config.cluster.as_ref().unwrap().clone();
    store.run(move|db| {
        use rusqlite::OptionalExtension;
        let tx=db.transaction()?;
        let role=if settings.role==Role::Worker {"worker"} else {"coordinator"};
        let previous:Option<String>=tx.query_row("SELECT value FROM cluster_state WHERE key='node_id'",[],|r|r.get(0)).optional()?;
        ensure!(previous.as_ref().is_none_or(|id|id==&settings.node_id),"Ce stockage appartient à un autre nœud.");
        let previous_role:Option<String>=tx.query_row("SELECT value FROM cluster_state WHERE key='role'",[],|r|r.get(0)).optional()?;
        ensure!(previous_role.as_ref().is_none_or(|r|r==role),"Changement de rôle interdit sur une file existante.");
        tx.execute("INSERT OR REPLACE INTO cluster_state VALUES('role',?1)",[role])?;
        tx.execute("INSERT OR REPLACE INTO cluster_state VALUES('node_id',?1)",[&settings.node_id])?;
        if previous.is_none() && settings.role==Role::Worker {
            ensure!(tx.query_row("SELECT COUNT(*) FROM messages",[],|r|r.get::<_,i64>(0))?==0,"Un nouveau nœud exige une file vide ; ne clonez jamais la base d’un autre serveur.");
            tx.execute("UPDATE cluster_sequence SET value=value+1",[])?;
            tx.execute("INSERT OR IGNORE INTO cluster_dirty SELECT id,(SELECT value FROM cluster_sequence) FROM messages WHERE NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=messages.id)",[])?;
        }
        if tx.query_row("PRAGMA user_version",[],|r|r.get::<_,i64>(0))?<3 {tx.execute_batch("PRAGMA user_version=3")?;}tx.commit()?;Ok(())
    }).await?;
    if is_worker(config) {
        budget::enable_worker(&config.data_dir)?;
    }
    Ok(())
}
pub async fn run(
    control: Arc<crate::control::Controller>,
    stop: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    if is_worker(&control.base) {
        worker::run(control, stop).await
    } else {
        let mut stop = stop;
        let _ = stop.changed().await;
        Ok(())
    }
}

/// A new node exposes health but never accepts MAIL before its first validated policy.
pub fn waiting_config(base: &crate::config::Config) -> crate::config::Config {
    let mut c = base.clone();
    c.filter.model = None;
    c.filter.semantic = None;
    c.filter.authentication = false;
    c.filter.spamhaus_key_env = None;
    c.filter.arc_key = None;
    c.filter.mode = crate::config::Mode::Observe;
    c.actions = None;
    c.custom_filtering = None;
    c.fusion = None;
    c.llm = None;
    c.protection = None;
    c.native_filter = None;
    c.quality = None;
    c.mailing = None;
    c.antivirus = None;
    c.signatures = None;
    c.vision = None;
    c.smtp_policy = None;
    c.rbl = None;
    c
}
