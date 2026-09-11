//! Additional detectors are observations, never an uncalibrated change to delivery.
mod campaign;
mod context;
mod local;
mod providers;
pub mod redirects;
use anyhow::{Result, ensure};
pub use local::{Feed, canonical_url, local_checks};
pub use providers::{Provider, key_present, quota_usage, save_key};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path, sync::Arc, time::Instant};

pub const VERSION: &str = "protection-1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub identity: bool,
    pub links: bool,
    pub campaigns: bool,
    pub crdf: bool,
    pub virustotal: bool,
    /// None inherits the bootstrap budget; zero explicitly removes a limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crdf_quota: Option<Quota>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virustotal_quota: Option<Quota>,
    /// Active HTTP requests; separate from passive link inspection.
    pub follow_urls: bool,
    pub protected_names: Vec<Identity>,
    /// Exact domains only; neither setting bypasses authentication or malware checks.
    pub reply_exceptions: Vec<String>,
    pub link_exceptions: Vec<String>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            identity: true,
            links: true,
            campaigns: true,
            crdf: false,
            virustotal: false,
            crdf_quota: None,
            virustotal_quota: None,
            follow_urls: false,
            protected_names: vec![],
            reply_exceptions: vec![],
            link_exceptions: vec![],
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub name: String,
    pub domain: String,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protected_names.len() <= 100
                && self.reply_exceptions.len() <= 100
                && self.link_exceptions.len() <= 100,
            "Maximum : 100 entrées par liste de protection."
        );
        for identity in &self.protected_names {
            ensure!(
                (3..=100).contains(&identity.name.len())
                    && !identity.name.chars().any(char::is_control)
                    && crate::config::valid_domain(&identity.domain),
                "Identité protégée invalide."
            );
        }
        for domain in self.reply_exceptions.iter().chain(&self.link_exceptions) {
            ensure!(
                crate::config::valid_domain(domain)
                    && domain.contains('.')
                    && domain == &domain.to_ascii_lowercase(),
                "Exception : nom de domaine exact requis."
            );
        }
        Ok(())
    }
}
/// Per-provider, fixed UTC windows. Zero means unlimited, never disabled.
/// Both fields are required so a malformed override cannot silently lift a cap.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Quota {
    pub minute: u32,
    pub day: u32,
}
impl Quota {
    fn exhausted(self, minute_used: i64, day_used: i64) -> bool {
        (self.minute != 0 && minute_used >= i64::from(self.minute))
            || (self.day != 0 && day_used >= i64::from(self.day))
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub policy: Policy,
    pub timeout_ms: u64,
    pub max_parallel: usize,
    pub crdf_per_minute: u32,
    pub crdf_per_day: u32,
    pub virustotal_per_minute: u32,
    pub virustotal_per_day: u32,
    pub url_resolution: redirects::Settings,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            policy: Policy::default(),
            timeout_ms: 1200,
            max_parallel: 2,
            crdf_per_minute: 2,
            crdf_per_day: 200,
            virustotal_per_minute: 4,
            virustotal_per_day: 500,
            url_resolution: Default::default(),
        }
    }
}
impl Settings {
    pub fn bootstrap_quota(&self, provider: Provider) -> Quota {
        match provider {
            Provider::Crdf => Quota {
                minute: self.crdf_per_minute,
                day: self.crdf_per_day,
            },
            Provider::Virustotal => Quota {
                minute: self.virustotal_per_minute,
                day: self.virustotal_per_day,
            },
        }
    }
    pub fn quota(&self, provider: Provider, policy: &Policy) -> Quota {
        let custom = match provider {
            Provider::Crdf => policy.crdf_quota,
            Provider::Virustotal => policy.virustotal_quota,
        };
        custom.unwrap_or_else(|| self.bootstrap_quota(provider))
    }
    pub fn validate(&self) -> Result<()> {
        self.policy.validate()?;
        self.url_resolution.validate()?;
        ensure!(
            (100..=2000).contains(&self.timeout_ms) && (1..=8).contains(&self.max_parallel),
            "Invalid protection capacity/deadline"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    #[default]
    Disabled,
    Complete,
    NotConfigured,
    NotRun,
    Unknown,
    Limited,
    Busy,
    Unavailable,
    Quota,
    Stale,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub family: String,
    /// Digest links evidence across detectors without retaining URLs or mailbox identities.
    pub indicator: String,
    pub sources: Vec<String>,
    pub detail: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProviderReport {
    pub status: Status,
    pub checked: usize,
    pub malicious: usize,
    pub suspicious: usize,
    pub unknown: usize,
    pub cache_hits: usize,
    pub elapsed_ms: u64,
    #[serde(default)]
    pub omitted: usize,
    #[serde(default)]
    pub failure: Option<providers::Failure>,
    /// Per-target observations. A host-root lookup never attests a particular page.
    #[serde(default)]
    pub observations: Vec<ProviderObservation>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderObservation {
    pub indicator_sha256: String,
    pub scope: String,
    pub verdict: String,
    pub queried_at: i64,
    pub cached: bool,
    pub cache_max_age_seconds: u32,
    /// None means the provider did not attest the age of its underlying analysis.
    pub analysis_max_age_seconds: Option<u32>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub version: String,
    pub observation_only: bool,
    pub local_status: Status,
    pub feed_status: Status,
    pub campaign_status: Status,
    pub campaign_match: bool,
    pub campaign_conflict: bool,
    pub authenticated_sender: bool,
    pub crdf: ProviderReport,
    pub virustotal: ProviderReport,
    pub findings: Vec<Finding>,
    /// Families rather than votes: CRDF, VT and QR evidence for one URL are not independent.
    pub families: Vec<String>,
    pub elapsed_ms: u64,
    #[serde(default)]
    pub url_resolution: Option<redirects::Report>,
}
impl Report {
    pub fn add(&mut self, id: &str, family: &str, indicator: &str, source: &str, detail: &str) {
        let digest = crate::message::digest(indicator.as_bytes());
        if let Some(f) = self
            .findings
            .iter_mut()
            .find(|f| f.id == id && f.indicator == digest)
        {
            if !f.sources.iter().any(|s| s == source) {
                f.sources.push(source.into());
            }
        } else if self.findings.len() < 48 {
            self.findings.push(Finding {
                id: id.into(),
                family: family.into(),
                indicator: digest,
                sources: vec![source.into()],
                detail: detail.into(),
            });
        }
        self.families = self
            .findings
            .iter()
            .map(|f| f.family.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
    }
}
#[derive(Default)]
pub struct Targets {
    pub context: Vec<context::Hint>,
    pub domains: BTreeSet<String>,
    pub destination_domains: BTreeSet<String>,
    pub hashes: BTreeSet<String>,
    pub urls: Vec<String>,
    pub urls_truncated: bool,
}

pub struct Runtime {
    providers: Arc<providers::Client>,
    root: std::path::PathBuf,
    feed: std::sync::Mutex<(Instant, Arc<Feed>)>,
    redirects: redirects::Resolver,
}
impl Runtime {
    pub fn new(config: &Settings, root: &Path) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            redirects: redirects::Resolver::new(config.url_resolution.clone())?,
            providers: Arc::new(providers::Client::new(config, root)?),
            root: root.into(),
            feed: std::sync::Mutex::new((Instant::now(), Arc::new(Feed::load(root)))),
        })
    }
    pub fn local(
        &self,
        raw: &[u8],
        visual: &str,
        config: &crate::config::Config,
    ) -> (Report, Targets) {
        let feed = {
            let mut cache = self.feed.lock().unwrap();
            if cache.0.elapsed().as_secs() >= 60 {
                *cache = (Instant::now(), Arc::new(Feed::load(&self.root)));
            }
            cache.1.clone()
        };
        let (report, mut targets) = local_checks(
            raw,
            visual,
            config,
            &config.protection.as_ref().unwrap().policy,
            &feed,
        );
        context::collect(
            raw,
            visual,
            &mut targets,
            &config.protection.as_ref().unwrap().policy,
            &report,
        );
        (report, targets)
    }
    pub async fn observe(
        &self,
        scan: &mut crate::engine::Scan,
        mut targets: Targets,
        policy: &Policy,
        scopes: &[String],
    ) {
        let started = Instant::now();
        let Some(report) = &mut scan.protection else {
            return;
        };
        // Follow first, so the existing provider budgets also cover discovered
        // destinations. Complete URLs stay local; providers receive host names.
        if policy.follow_urls {
            let (resolution, visited) = self
                .redirects
                .inspect(&targets.urls, targets.urls_truncated)
                .await;
            let feed = self.feed.lock().unwrap().1.clone();
            let last_hops: BTreeSet<_> = resolution
                .chains
                .iter()
                .filter_map(|chain| chain.hops.last().map(|hop| &hop.url_sha256))
                .collect();
            for url in &visited {
                if let Ok(parsed) = reqwest::Url::parse(url)
                    && let Some(host) = parsed.host_str()
                {
                    if local::public_domain(host) {
                        targets.domains.insert(host.into());
                        if last_hops.contains(&crate::message::digest(url.as_bytes())) {
                            targets.destination_domains.insert(host.into());
                        }
                    }
                    if policy.links && feed.contains(url) {
                        report.add(
                            "known_phishing_url",
                            "link_reputation",
                            host,
                            "redirect",
                            "Destination de redirection présente dans la base locale de phishing",
                        );
                    }
                }
            }
            context::apply(&targets.context, &resolution, policy, report);
            report.url_resolution = Some(resolution);
        }
        let (crdf, vt, campaign) = tokio::join!(
            self.providers
                .inspect(Provider::Crdf, policy.crdf, &targets, policy),
            self.providers
                .inspect(Provider::Virustotal, policy.virustotal, &targets, policy),
            campaign::inspect(
                &self.root,
                policy.campaigns,
                scopes,
                scan.campaign_simhash.as_deref(),
                &scan.fingerprint,
                scan.features.len()
            ),
        );
        report.crdf = crdf.0;
        report.virustotal = vt.0;
        for (provider, hits) in [("crdf", crdf.1), ("virustotal", vt.1)] {
            for (indicator, file) in hits {
                report.add(
                    "known_malicious_indicator",
                    if file {
                        "attachment"
                    } else {
                        "link_reputation"
                    },
                    &indicator,
                    provider,
                    "Indicateur signalé dans un rapport de réputation existant",
                );
            }
        }
        report.campaign_status = campaign.0;
        report.campaign_match = campaign.1;
        report.campaign_conflict = campaign.2;
        if campaign.1 && !campaign.2 {
            report.add(
                "confirmed_campaign",
                "campaign",
                &scan.fingerprint,
                "local_feedback",
                "Ressemblance avec une campagne confirmée par un administrateur dans ce domaine",
            );
        }
        report.authenticated_sender = scan.evidence.as_ref().is_some_and(|e| {
            e.authentication.dmarc_spf == Some(crate::evidence::AuthResult::Pass)
                || e.authentication.dmarc_dkim == Some(crate::evidence::AuthResult::Pass)
        });
        report.elapsed_ms += started.elapsed().as_millis() as u64;
    }
}
