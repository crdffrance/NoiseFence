//! Validated, durable console configuration; one coherent snapshot per SMTP transaction.
use crate::{
    config::{Config, Domain, Mode},
    engine::Engine,
    store::Store,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, RwLock},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Gateway {
    pub id: String,
    pub name: String,
    pub hosts: Vec<String>,
    pub port: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManagedDomain {
    pub name: String,
    pub gateway: Option<String>,
    pub enabled: bool,
    pub accept_all_recipients: bool,
    pub recipients: Vec<String>,
    pub aliases: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Filters {
    pub mode: Mode,
    pub threshold: f64,
    pub authentication: bool,
    pub antivirus: bool,
    pub signatures: bool,
    pub semantic: bool,
    pub vision: bool,
    pub llm: bool,
    pub smtp_policy: bool,
    pub smtp_policy_scoring: bool,
    pub vision_scoring: bool,
    pub reputation: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub gateways: Vec<Gateway>,
    pub domains: Vec<ManagedDomain>,
    pub filters: Filters,
}
impl Settings {
    pub fn from_config(config: &Config) -> Self {
        let mut gateways: Vec<Gateway> = Vec::new();
        let domains = config
            .domains
            .iter()
            .map(|d| {
                let gateway = if d.next_hops.is_empty() {
                    None
                } else {
                    let port = config.relay.port;
                    let hosts: Vec<_> = d.next_hops.iter().map(|h| h.to_owned()).collect();
                    let index = gateways
                        .iter()
                        .position(|g| g.hosts == hosts && g.port == port)
                        .unwrap_or_else(|| {
                            let index = gateways.len();
                            gateways.push(Gateway {
                                id: format!("gateway-{}", index + 1),
                                name: format!("Relais {}", index + 1),
                                hosts,
                                port,
                            });
                            index
                        });
                    Some(gateways[index].id.clone())
                };
                ManagedDomain {
                    name: d.name.clone(),
                    gateway,
                    enabled: true,
                    accept_all_recipients: d.accept_all_recipients,
                    recipients: d.recipients.clone(),
                    aliases: d.aliases.clone(),
                }
            })
            .collect();
        Self {
            gateways,
            domains,
            filters: Filters {
                mode: config.filter.mode,
                threshold: config.filter.threshold,
                authentication: config.filter.authentication,
                antivirus: config.antivirus.is_some(),
                signatures: config.signatures.is_some(),
                semantic: config.filter.semantic.is_some(),
                vision: config.vision.is_some(),
                llm: config
                    .llm
                    .as_ref()
                    .is_some_and(|c| c.monthly_budget_micro_eur > 0),
                smtp_policy: config.smtp_policy.is_some(),
                smtp_policy_scoring: config
                    .smtp_policy
                    .as_ref()
                    .is_some_and(|c| c.contribute_to_score),
                vision_scoring: config
                    .vision
                    .as_ref()
                    .is_some_and(|c| c.contribute_to_score),
                reputation: config.filter.spamhaus_key_env.is_some(),
            },
        }
    }
    pub fn effective(&self, base: &Config) -> Result<Config> {
        ensure!(
            self.domains.len() <= 100 && self.gateways.len() <= 100,
            "Maximum : 100 domaines et 100 passerelles."
        );
        let mut ids = HashSet::new();
        for g in &self.gateways {
            ensure!(
                !g.id.is_empty()
                    && g.id.len() <= 64
                    && g.id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                    && ids.insert(&g.id),
                "Identifiant de passerelle invalide ou dupliqué."
            );
            ensure!(
                !g.name.trim().is_empty()
                    && g.name.len() <= 100
                    && !g.name.chars().any(char::is_control),
                "Nom de passerelle invalide."
            );
            ensure!(
                (1..=8).contains(&g.hosts.len())
                    && g.port > 0
                    && g.hosts
                        .iter()
                        .all(|h| crate::config::endpoint(h, g.port).is_some()),
                "Une passerelle nécessite 1 à 8 noms de serveurs et un port valide."
            );
        }
        let mut cfg = base.clone();
        let mut names = HashSet::new();
        let mut active = Vec::new();
        for d in &self.domains {
            ensure!(
                crate::config::valid_domain(&d.name)
                    && d.name == d.name.to_ascii_lowercase()
                    && names.insert(&d.name),
                "Nom de domaine invalide ou dupliqué (utiliser le format ASCII/punycode)."
            );
            ensure!(
                d.recipients.len() <= 1000 && d.aliases.len() <= 1000,
                "Trop d’adresses ou d’alias dans ce domaine."
            );
            let next_hops = match &d.gateway {
                Some(id) => self
                    .gateways
                    .iter()
                    .find(|g| &g.id == id)
                    .context("Passerelle référencée introuvable.")?
                    .hosts
                    .iter()
                    .map(|h| {
                        let g = self.gateways.iter().find(|g| &g.id == id).unwrap();
                        if h.contains(':') || g.port == base.relay.port {
                            h.clone()
                        } else {
                            format!("{h}:{}", g.port)
                        }
                    })
                    .collect(),
                None => Vec::new(),
            };
            // Disabled domains retain syntactically valid addresses; enabling also validates routing.
            let domain = Domain {
                name: d.name.clone(),
                next_hops,
                accept_all_recipients: d.accept_all_recipients,
                recipients: d.recipients.clone(),
                aliases: d.aliases.clone(),
            };
            if d.enabled {
                active.push(domain);
            } else {
                ensure!(
                    d.recipients.iter().all(|r| crate::config::valid_address(r)
                        && r.rsplit_once('@').unwrap().1.eq_ignore_ascii_case(&d.name))
                        && d.aliases
                            .iter()
                            .all(|(a, b)| crate::config::valid_address(a)
                                && a.rsplit_once('@').unwrap().1.eq_ignore_ascii_case(&d.name)
                                && crate::config::valid_address(b)),
                    "Adresse ou alias invalide."
                );
            }
        }
        cfg.domains = active;
        let f = &self.filters;
        let available = Self::from_config(base).filters;
        for (enabled, exists, name) in [
            (f.antivirus, available.antivirus, "antivirus"),
            (f.signatures, available.signatures, "signatures"),
            (f.semantic, available.semantic, "modèle multilingue"),
            (f.vision, available.vision, "OCR"),
            (f.llm, available.llm, "LLM"),
            (f.smtp_policy, available.smtp_policy, "politique SMTP"),
            (f.reputation, available.reputation, "réputation DQS"),
        ] {
            ensure!(
                !enabled || exists,
                "Le connecteur {name} doit être installé et configuré sur le serveur."
            );
        }
        cfg.filter.mode = f.mode;
        cfg.filter.threshold = f.threshold;
        cfg.filter.authentication = f.authentication;
        if !f.antivirus {
            cfg.antivirus = None;
        }
        if !f.signatures {
            cfg.signatures = None;
        }
        if !f.semantic {
            cfg.filter.semantic = None;
        }
        if !f.vision {
            cfg.vision = None;
        }
        if !f.llm {
            cfg.llm = None;
        }
        if !f.smtp_policy {
            cfg.smtp_policy = None;
        }
        if !f.reputation {
            cfg.filter.spamhaus_key_env = None;
        }
        if let Some(p) = &mut cfg.smtp_policy {
            p.contribute_to_score = f.smtp_policy_scoring;
        }
        if let Some(v) = &mut cfg.vision {
            v.contribute_to_score = f.vision_scoring;
        }
        cfg.validate()?;
        Ok(cfg)
    }
}

pub struct Snapshot {
    pub revision: i64,
    pub settings: Settings,
    pub config: Arc<Config>,
    pub engine: Arc<Engine>,
}
pub struct Controller {
    pub base: Arc<Config>,
    pub store: Store,
    template: Arc<Engine>,
    active: RwLock<Arc<Snapshot>>,
    applying: Arc<tokio::sync::Semaphore>,
}
impl Controller {
    pub async fn load(base: Arc<Config>, store: Store) -> Result<Arc<Self>> {
        let saved = store
            .run(|db| {
                Ok(db
                    .query_row(
                        "SELECT id,settings FROM console_revisions ORDER BY id DESC LIMIT 1",
                        [],
                        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                    )
                    .optional()?)
            })
            .await?;
        let (revision, settings) = match saved {
            Some((id, raw)) => (id, serde_json::from_str(&raw)?),
            None => (0, Settings::from_config(&base)),
        };
        let effective = if revision == 0 {
            (*base).clone()
        } else {
            settings.effective(&base)?
        };
        let config = Arc::new(effective);
        let seed = base.clone();
        let cfg = config.clone();
        let (template, engine) = tokio::task::spawn_blocking(move || -> Result<_> {
            let template = Arc::new(Engine::new(seed)?);
            let engine = if revision == 0 {
                template.clone()
            } else {
                Arc::new(template.reconfigure(cfg)?)
            };
            Ok((template, engine))
        })
        .await??;
        Ok(Arc::new(Self {
            base,
            store,
            template,
            active: RwLock::new(Arc::new(Snapshot {
                revision,
                settings,
                config,
                engine,
            })),
            applying: Arc::new(tokio::sync::Semaphore::new(1)),
        }))
    }
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.active.read().unwrap().clone()
    }
    /// The owned task completes persistence + activation even if the HTTP client disconnects.
    pub async fn apply(
        self: &Arc<Self>,
        revision: i64,
        settings: Settings,
        username: String,
    ) -> Result<i64> {
        let this = self.clone();
        tokio::spawn(async move {
            let _permit=this.applying.clone().try_acquire_owned().context("Une modification est déjà en cours.")?;
            ensure!(revision==this.snapshot().revision,"Configuration modifiée dans une autre session. Rechargez avant d’enregistrer.");
            let config=Arc::new(settings.effective(&this.base)?);
            let template=this.template.clone(); let cfg=config.clone();
            let engine=Arc::new(tokio::task::spawn_blocking(move||template.reconfigure(cfg)).await??);
            let raw=serde_json::to_string(&settings)?;
            ensure!(raw.len()<=128*1024,"Configuration trop volumineuse.");
            let id=this.store.run(move|db| {
                let tx=db.transaction()?;
                let current:i64=tx.query_row("SELECT COALESCE(MAX(id),0) FROM console_revisions",[],|r|r.get(0))?;
                ensure!(current==revision,"Configuration modifiée dans une autre session.");
                let enabled:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE username=?1 AND admin=1 AND disabled=0)",[&username],|r|r.get(0))?;
                ensure!(enabled,"Droits administrateur révoqués.");
                tx.execute("INSERT INTO console_revisions(created,username,settings) VALUES(?1,?2,?3)",params![crate::now(),username,raw])?;
                let id=tx.last_insert_rowid();
                tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'configuration',?3)",params![crate::now(),username,id.to_string()])?;
                tx.execute("DELETE FROM console_revisions WHERE id NOT IN (SELECT id FROM console_revisions ORDER BY id DESC LIMIT 100)",[])?;
                tx.commit()?;Ok(id)
            }).await?;
            *this.active.write().unwrap()=Arc::new(Snapshot{revision:id,settings,config,engine});
            Ok(id)
        }).await?
    }
}

/// CLI tools consume the same persisted policy as the daemon, without initializing detectors.
pub fn effective_from_disk(base: Arc<Config>) -> Result<Arc<Config>> {
    let path = base.data_dir.join("state.sqlite3");
    if !path.exists() {
        return Ok(base);
    }
    let db =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    db.busy_timeout(std::time::Duration::from_secs(10))?;
    let exists: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='console_revisions')",[],|r|r.get(0))?;
    if !exists {
        return Ok(base);
    }
    let raw: Option<String> = db
        .query_row(
            "SELECT settings FROM console_revisions ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    match raw {
        Some(raw) => Ok(Arc::new(
            serde_json::from_str::<Settings>(&raw)?.effective(&base)?,
        )),
        None => Ok(base),
    }
}
