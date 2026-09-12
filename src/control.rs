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
    #[serde(default)]
    pub rule_weights: BTreeMap<String, f64>,
    pub mode: Mode,
    pub threshold: f64,
    #[serde(default)]
    pub require_corroboration: bool,
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
    #[serde(default)]
    pub rbl: Option<crate::rbl::Settings>,
    #[serde(default)]
    pub detection: Option<crate::management::Detection>,
    #[serde(default)]
    pub preferences: crate::preferences::Settings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_filtering: Option<crate::custom_filtering::Policy>,
    pub gateways: Vec<Gateway>,
    pub domains: Vec<ManagedDomain>,
    pub filters: Filters,
    #[serde(default)]
    pub actions: Option<crate::actions::Policy>,
    #[serde(default)]
    pub protection: Option<crate::protection::Policy>,
    #[serde(default)]
    pub mailing: Option<crate::mailing::Policy>,
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
            rbl: Some(config.rbl.clone().unwrap_or_default()),
            detection: Some(crate::management::Detection::from_config(config)),
            preferences: config.preferences.clone(),
            custom_filtering: config.custom_filtering.clone(),
            gateways,
            domains,
            protection: config.protection.as_ref().map(|c| c.policy.clone()),
            mailing: config.mailing.as_ref().map(|c| c.policy.clone()),
            actions: config.actions.clone(),
            filters: Filters {
                rule_weights: config.filter.rule_weights.clone(),
                mode: config.filter.mode,
                threshold: config.filter.threshold,
                require_corroboration: config.filter.require_corroboration,
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
    pub fn available(base: &Config) -> Filters {
        let mut f = Self::from_config(base).filters;
        f.reputation |= crate::management::key_present(&base.data_dir, "spamhaus");
        f.llm = base.llm.is_some();
        f
    }
    pub fn hydrate(&mut self, base: &Config) {
        self.rbl
            .get_or_insert_with(|| base.rbl.clone().unwrap_or_default());
        self.detection
            .get_or_insert_with(|| crate::management::Detection::from_config(base));
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
        if let Some(d) = &self.detection {
            d.apply(&mut cfg)?;
        }
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
        let available = Self::available(base);
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
        cfg.actions = self.actions.clone();
        cfg.custom_filtering = self.custom_filtering.clone();
        cfg.filter.rule_weights = f.rule_weights.clone();
        cfg.filter.mode = f.mode;
        cfg.filter.threshold = f.threshold;
        cfg.filter.require_corroboration = f.require_corroboration;
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
        if f.reputation && cfg.filter.spamhaus_key_env.is_none() {
            cfg.filter.spamhaus_key_env = Some(crate::management::WEB_DQS.into());
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
        match (&self.protection, &mut cfg.protection) {
            (Some(policy), Some(settings)) => {
                policy.validate()?;
                settings.policy = policy.clone();
            }
            (Some(_), None) => anyhow::bail!("La protection doit être installée sur le serveur."),
            (None, _) => cfg.protection = None,
        }
        match (&self.mailing, &mut cfg.mailing) {
            (Some(policy), Some(settings)) => settings.policy = policy.clone(),
            (Some(_), None) => {
                anyhow::bail!("La catégorisation PUB doit être installée sur le serveur.")
            }
            (None, _) => cfg.mailing = None,
        }
        if let Some(rbl) = &self.rbl {
            crate::management::validate_rbl(rbl, base)?;
            cfg.rbl = Some(rbl.clone());
        }
        cfg.preferences = self.preferences.clone();
        cfg.validate()?;
        Ok(cfg)
    }
}

pub struct Snapshot {
    pub rbl: Arc<crate::rbl::Runtime>,
    pub revision: i64,
    pub settings: Settings,
    pub config: Arc<Config>,
    pub engine: Arc<Engine>,
}

impl Controller {
    pub fn cluster_digest(&self) -> String {
        self.cluster_hash.read().unwrap().clone()
    }
    pub fn cluster_ready(&self) -> bool {
        !crate::cluster::is_worker(&self.base)
            || self
                .cluster_until
                .load(std::sync::atomic::Ordering::Acquire)
                >= crate::now()
    }
    pub async fn publication(&self) -> Result<Arc<crate::cluster::artifacts::Publication>> {
        ensure!(
            self.base
                .cluster
                .as_ref()
                .is_some_and(|c| c.role == crate::cluster::Role::Coordinator),
            "Not a coordinator"
        );
        let mut cache = self.publication.lock().await;
        let snapshot = self.snapshot();
        if let Some(value) = &*cache
            && value.bundle.revision == snapshot.revision
        {
            return Ok(value.clone());
        }
        let publication = tokio::task::spawn_blocking(move || {
            let publication = crate::cluster::artifacts::capture(
                &snapshot.config,
                snapshot.settings.clone(),
                snapshot.revision,
            )?;
            snapshot.engine.validate_cluster_publication(&publication)?;
            Ok::<_, anyhow::Error>(publication)
        })
        .await??;
        let value = Arc::new(publication);
        *cache = Some(value.clone());
        Ok(value)
    }
    pub async fn apply_cluster(
        self: &Arc<Self>,
        bundle: crate::cluster::artifacts::Bundle,
        keys_hash: String,
        server_time: i64,
    ) -> Result<()> {
        ensure!(crate::cluster::is_worker(&self.base), "Not a worker");
        bundle.validate()?;
        let this = self.clone();
        tokio::spawn(async move {
            let _permit=this.applying.clone().acquire_owned().await?;
            let current=this.snapshot();
            ensure!(bundle.revision>=current.revision,"Older authority revision refused");
            ensure!(server_time<=crate::now()+300 && server_time>=crate::now()-300,"Clock skew");
            let changed=this.cluster_digest()!=bundle.digest || *this.cluster_keys.read().unwrap()!=keys_hash;
            let mut next=None;
            if changed {
                let base=this.base.clone();let candidate=bundle.clone();
                let config=Arc::new(tokio::task::spawn_blocking(move||crate::cluster::artifacts::materialize(&base,&candidate,false)).await??);
                let models_changed=cluster_model_identity(&config)!=cluster_model_identity(&current.config);
                if models_changed {
                    let retired=this.retired.lock().unwrap();
                    ensure!(retired.as_ref().is_none_or(|engine|engine.strong_count()==0),"Le modèle précédent termine encore des sessions SMTP ; nouvelle activation différée.");
                }
                let template=current.engine.clone();let cfg=config.clone();
                let engine=Arc::new(tokio::task::spawn_blocking(move||if models_changed {template.reload_cluster_models(cfg)}else{template.reconfigure(cfg)}).await??);
                let rbl=Arc::new(current.rbl.reconfigure(config.rbl.as_ref(),crate::management::dqs_key(&config)?.as_deref())?);
                next=Some((config,engine,rbl,models_changed));
            }
            let raw=serde_json::to_string(&bundle)?;
            ensure!(raw.len()<=768*1024,"Configuration de cluster trop volumineuse.");
            let keys=keys_hash.clone();
            this.store.run(move|db|{
                let tx=db.transaction()?;
                for (key,value) in [("bundle",raw),("last_sync",server_time.to_string()),("keys_hash",keys)] {tx.execute("INSERT OR REPLACE INTO cluster_state VALUES(?1,?2)",params![key,value])?;}
                tx.commit()?;Ok(())
            }).await?;
            if let Some((config,engine,rbl,models_changed))=next {
                engine.activate_limits();rbl.activate();
                if models_changed {*this.retired.lock().unwrap()=Some(Arc::downgrade(&current.engine));}
                *this.template.write().unwrap()=engine.clone();
                *this.active.write().unwrap()=Arc::new(Snapshot{revision:bundle.revision,settings:bundle.settings,config,engine,rbl});
            }
            *this.cluster_hash.write().unwrap()=bundle.digest;
            *this.cluster_keys.write().unwrap()=keys_hash;
            this.cluster_until.store(server_time+this.base.cluster.as_ref().unwrap().max_stale_seconds,std::sync::atomic::Ordering::Release);
            Ok(())
        }).await?
    }
}
fn cluster_model_identity(config: &Config) -> String {
    crate::message::digest(&serde_json::to_vec(&serde_json::json!({
        "model":config.filter.model,"semantic":config.filter.semantic,"threshold":config.filter.threshold,
        "native":config.native_filter.as_ref().map(|n|(&n.bayes_model,&n.adaptive)),
        "fusion":config.fusion,"quality":config.quality,
    })).expect("model identity"))
}
pub struct Controller {
    pub base: Arc<Config>,
    pub store: Store,
    template: RwLock<Arc<Engine>>,
    publication: tokio::sync::Mutex<Option<Arc<crate::cluster::artifacts::Publication>>>,
    cluster_until: std::sync::atomic::AtomicI64,
    cluster_hash: RwLock<String>,
    cluster_keys: RwLock<String>,
    retired: std::sync::Mutex<Option<std::sync::Weak<Engine>>>,
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
        let (revision, mut settings): (i64, Settings) = match saved {
            Some((id, raw)) => (id, serde_json::from_str(&raw)?),
            None => (0, Settings::from_config(&base)),
        };
        settings.hydrate(&base);
        let clustered = if crate::cluster::is_worker(&base) {
            store
                .read(|db| {
                    Ok(db
                        .query_row(
                            "SELECT value FROM cluster_state WHERE key='bundle'",
                            [],
                            |r| r.get::<_, String>(0),
                        )
                        .optional()?)
                })
                .await?
                .map(|raw| serde_json::from_str::<crate::cluster::artifacts::Bundle>(&raw))
                .transpose()?
        } else {
            None
        };
        let revision = clustered.as_ref().map_or(revision, |b| b.revision);
        let effective = if let Some(bundle) = &clustered {
            settings = bundle.settings.clone();
            crate::cluster::artifacts::materialize(&base, bundle, true)?
        } else if crate::cluster::is_worker(&base) {
            crate::cluster::waiting_config(&base)
        } else if revision == 0 {
            (*base).clone()
        } else {
            settings.effective(&base)?
        };
        let (last_sync, key_hash) = store
            .read(|db| {
                let last = db
                    .query_row(
                        "SELECT value FROM cluster_state WHERE key='last_sync'",
                        [],
                        |r| r.get::<_, String>(0),
                    )
                    .optional()?
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
                let keys = db
                    .query_row(
                        "SELECT value FROM cluster_state WHERE key='keys_hash'",
                        [],
                        |r| r.get::<_, String>(0),
                    )
                    .optional()?
                    .unwrap_or_default();
                Ok((last, keys))
            })
            .await?;
        let cluster_until = if clustered.is_some() {
            last_sync.saturating_add(base.cluster.as_ref().map_or(0, |c| c.max_stale_seconds))
        } else {
            0
        };
        let config = Arc::new(effective);
        let seed = if crate::cluster::is_worker(&base) {
            config.clone()
        } else {
            base.clone()
        };
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
        let rbl = Arc::new(crate::rbl::Runtime::with_dqs_key(
            config.rbl.as_ref(),
            crate::management::dqs_key(&config)?.as_deref(),
        )?);
        engine.activate_limits();
        Ok(Arc::new(Self {
            base,
            store,
            template: RwLock::new(template),
            publication: tokio::sync::Mutex::new(None),
            cluster_until: std::sync::atomic::AtomicI64::new(cluster_until),
            cluster_hash: RwLock::new(
                clustered
                    .as_ref()
                    .map(|b| b.digest.clone())
                    .unwrap_or_default(),
            ),
            cluster_keys: RwLock::new(key_hash),
            retired: std::sync::Mutex::new(None),
            active: RwLock::new(Arc::new(Snapshot {
                rbl,
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
        self.apply_authorized(revision, settings, username, None)
            .await
    }
    pub async fn apply_session(
        self: &Arc<Self>,
        revision: i64,
        settings: Settings,
        username: String,
        token_hash: String,
    ) -> Result<i64> {
        self.apply_authorized(revision, settings, username, Some(("*".into(), token_hash)))
            .await
    }
    pub async fn apply_preferences(
        self: &Arc<Self>,
        revision: i64,
        scope: String,
        preference: Option<crate::preferences::Preference>,
        username: String,
        token_hash: String,
    ) -> Result<i64> {
        let snapshot = self.snapshot();
        ensure!(
            snapshot.revision == revision,
            "Configuration modifiée. Rechargez les préférences."
        );
        ensure!(
            snapshot.settings.preferences.enabled,
            "Personnalisation désactivée par l’administrateur."
        );
        let mut settings = snapshot.settings.clone();
        if let Some(p) = preference {
            settings.preferences.mailboxes.insert(scope.clone(), p);
        } else {
            settings.preferences.mailboxes.remove(&scope);
        }
        self.apply_authorized(revision, settings, username, Some((scope, token_hash)))
            .await
    }
    async fn apply_authorized(
        self: &Arc<Self>,
        revision: i64,
        mut settings: Settings,
        username: String,
        delegated: Option<(String, String)>,
    ) -> Result<i64> {
        ensure!(
            !crate::cluster::is_worker(&self.base),
            "Modifiez les réglages depuis la console centrale."
        );
        settings.hydrate(&self.base);
        let this = self.clone();
        tokio::spawn(async move {
            let _permit=this.applying.clone().try_acquire_owned().context("Une modification est déjà en cours.")?;
            ensure!(revision==this.snapshot().revision,"Configuration modifiée dans une autre session. Rechargez avant d’enregistrer.");
            let config=Arc::new(settings.effective(&this.base)?);
            let rbl=Arc::new(this.snapshot().rbl.reconfigure(config.rbl.as_ref(),crate::management::dqs_key(&config)?.as_deref())?);
            let template=this.template.read().unwrap().clone(); let cfg=config.clone();
            let engine=Arc::new(tokio::task::spawn_blocking(move||template.reconfigure(cfg)).await??);
            let raw=serde_json::to_string(&settings)?;
            ensure!(raw.len()<=128*1024,"Configuration trop volumineuse.");
            let id=this.store.run(move|db| {
                let tx=db.transaction()?;
                let current:i64=tx.query_row("SELECT COALESCE(MAX(id),0) FROM console_revisions",[],|r|r.get(0))?;
                ensure!(current==revision,"Configuration modifiée dans une autre session.");
                if let Some((scope,hash))=&delegated {
                    let admin:Option<bool>=tx.query_row("SELECT u.admin FROM users u JOIN sessions s ON s.username=u.username WHERE u.username=?1 AND s.token_hash=?2 AND s.expires>?3 AND u.disabled=0",params![username,hash,crate::now()],|r|r.get(0)).optional()?;
                    let admin=admin.context("Session expirée ou compte désactivé.")?;
                    let grants=tx.prepare("SELECT address FROM grants WHERE username=?1")?.query_map([&username],|r|r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
                    ensure!(if scope=="*" {admin}else{crate::preferences::permitted(scope,admin,&grants)},"Cette adresse n’est pas autorisée.");
                } else {
                let enabled:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE username=?1 AND admin=1 AND disabled=0)",[&username],|r|r.get(0))?;
                ensure!(enabled,"Droits administrateur révoqués.");
                }
                tx.execute("INSERT INTO console_revisions(created,username,settings) VALUES(?1,?2,?3)",params![crate::now(),username,raw])?;
                let id=tx.last_insert_rowid();
                tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'configuration',?3)",params![crate::now(),username,id.to_string()])?;
                tx.execute("DELETE FROM console_revisions WHERE id NOT IN (SELECT id FROM console_revisions ORDER BY id DESC LIMIT 100)",[])?;
                tx.commit()?;Ok(id)
            }).await?;
            engine.activate_limits();rbl.activate();
            *this.active.write().unwrap()=Arc::new(Snapshot{revision:id,settings,config,engine,rbl});
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
    if crate::cluster::is_worker(&base) {
        let exists: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='cluster_state')", [], |r| r.get(0))?;
        if exists {
            let raw: Option<String> = db
                .query_row(
                    "SELECT value FROM cluster_state WHERE key='bundle'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(raw) = raw {
                return Ok(Arc::new(crate::cluster::artifacts::materialize(
                    &base,
                    &serde_json::from_str(&raw)?,
                    true,
                )?));
            }
        }
        return Ok(Arc::new(crate::cluster::waiting_config(&base)));
    }
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
