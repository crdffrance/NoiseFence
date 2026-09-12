use super::{Policy, ProviderReport, Quota, Settings, Status, Targets};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Crdf,
    Virustotal,
}
impl Provider {
    pub fn name(self) -> &'static str {
        match self {
            Self::Crdf => "crdf",
            Self::Virustotal => "virustotal",
        }
    }
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "crdf" => Ok(Self::Crdf),
            "virustotal" => Ok(Self::Virustotal),
            _ => anyhow::bail!("Fournisseur inconnu"),
        }
    }
}
#[derive(Debug, Serialize)]
pub struct QuotaUsage {
    pub minute_used: i64,
    pub day_used: i64,
    pub minute_resets_at: i64,
    pub day_resets_at: i64,
    pub cooldown_until: Option<i64>,
}
/// Read aggregate counters only. Never expose cache identifiers or credentials.
pub fn quota_usage(root: &Path, provider: Provider) -> Result<QuotaUsage> {
    let now = crate::now();
    let mut usage = QuotaUsage {
        minute_used: 0,
        day_used: 0,
        minute_resets_at: (now / 60 + 1) * 60,
        day_resets_at: (now / 86400 + 1) * 86400,
        cooldown_until: None,
    };
    let path = root.join("protection/reputation.sqlite3");
    if !path.try_exists()? {
        return Ok(usage);
    }
    let db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    db.busy_timeout(Duration::from_millis(100))?;
    let row: Option<(i64, i64, i64, i64)> = db
        .query_row(
            "SELECT day,day_used,minute,minute_used FROM quota WHERE provider=?1",
            [provider.name()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    if let Some((day, du, minute, mu)) = row {
        if day == now / 86400 {
            usage.day_used = du;
        }
        if minute == now / 60 {
            usage.minute_used = mu;
        }
    }
    if let Ok(key) = read_key(root, provider) {
        let credential = crate::message::digest(format!("{}:{key}", provider.name()).as_bytes());
        usage.cooldown_until = db
            .query_row(
                "SELECT expires FROM cooldown WHERE key=?1 AND expires>?2",
                params![credential, now],
                |r| r.get(0),
            )
            .optional()?;
    }
    Ok(usage)
}
fn key_path(root: &Path, provider: Provider) -> PathBuf {
    root.join("protection")
        .join(format!("{}.key", provider.name()))
}
pub fn key_present(root: &Path, provider: Provider) -> bool {
    read_key(root, provider).is_ok()
}
fn read_key(root: &Path, provider: Provider) -> Result<String> {
    let file = std::fs::File::open(key_path(root, provider))?;
    ensure!(
        file.metadata()?.permissions().mode() & 0o077 == 0,
        "Unsafe secret permissions"
    );
    let mut key = String::new();
    file.take(257).read_to_string(&mut key)?;
    let key = key.trim();
    ensure!(
        (16..=256).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_graphic()),
        "Invalid provider key"
    );
    Ok(key.into())
}
pub fn save_key(root: &Path, provider: Provider, key: &str) -> Result<()> {
    ensure!(
        (16..=256).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_graphic()),
        "La clé doit contenir 16 à 256 caractères sans espace."
    );
    let folder = root.join("protection");
    std::fs::create_dir_all(&folder)?;
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700))?;
    let temporary = folder.join(format!(".key-{}", uuid::Uuid::new_v4()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(key.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, key_path(root, provider))?;
        std::fs::File::open(&folder)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Verdict {
    Unknown,
    NoHit,
    Suspicious,
    Malicious,
    Stale,
}
struct Lookup {
    verdict: Option<Verdict>,
    status: Status,
    cached: bool,
    failure: Option<Failure>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Storage,
    Timeout,
    Network,
    Authentication,
    RateLimit,
    Http,
    ResponseLimit,
    InvalidResponse,
}
fn network_failure(error: &reqwest::Error) -> (Failure, bool) {
    (
        if error.is_timeout() {
            Failure::Timeout
        } else {
            Failure::Network
        },
        false,
    )
}
enum Reservation {
    Cached(Verdict),
    Fetch,
    Quota,
}

#[derive(Clone)]
pub struct Client {
    root: PathBuf,
    config: Settings,
    http: reqwest::Client,
    db: Arc<Mutex<Connection>>,
    gate: Arc<tokio::sync::Semaphore>,
    requests: Arc<tokio::sync::Semaphore>,
    #[cfg(test)]
    endpoint_override: Option<String>,
}
impl Client {
    pub fn new(config: &Settings, root: &Path) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let folder = root.join("protection");
        std::fs::create_dir_all(&folder)?;
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700))?;
        let db = Connection::open(folder.join("reputation.sqlite3"))?;
        db.busy_timeout(Duration::from_millis(100))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS quota(provider TEXT PRIMARY KEY,day INTEGER,day_used INTEGER,minute INTEGER,minute_used INTEGER);
        CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY,expires INTEGER,verdict TEXT);
        CREATE TABLE IF NOT EXISTS cooldown(key TEXT PRIMARY KEY,expires INTEGER);")?;
        Ok(Self {
            #[cfg(test)]
            endpoint_override: None,
            root: root.into(),
            config: config.clone(),
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .connect_timeout(Duration::from_millis(500))
                .timeout(Duration::from_millis(config.timeout_ms))
                .user_agent("NoiseFence/1 Reputation-check")
                .build()?,
            db: Arc::new(Mutex::new(db)),
            gate: Arc::new(tokio::sync::Semaphore::new(config.max_parallel)),
            requests: Arc::new(tokio::sync::Semaphore::new(config.max_parallel)),
        })
    }
    async fn reserve(
        &self,
        provider: Provider,
        cache_key: String,
        credential_id: String,
        quota: Quota,
    ) -> Result<Reservation> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || -> Result<Reservation> {
            let mut db = db
                .lock()
                .map_err(|_| anyhow::anyhow!("Provider budget lock"))?;
            let tx = db.transaction()?;
            let now = crate::now();
            let cached: Option<String> = tx
                .query_row(
                    "SELECT verdict FROM cache WHERE key=?1 AND expires>?2",
                    params![cache_key, now],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(value) = cached {
                return Ok(Reservation::Cached(serde_json::from_str(&value)?));
            }
            let cooling: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM cooldown WHERE key=?1 AND expires>?2)",
                params![credential_id, now],
                |r| r.get(0),
            )?;
            if cooling {
                return Ok(Reservation::Quota);
            }
            let previous: Option<(i64, i64, i64, i64)> = tx
                .query_row(
                    "SELECT day,day_used,minute,minute_used FROM quota WHERE provider=?1",
                    [provider.name()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            let day = now / 86400;
            let minute = now / 60;
            let (used_day, used_minute) = previous
                .map(|(d, du, m, mu)| {
                    (
                        if d == day { du } else { 0 },
                        if m == minute { mu } else { 0 },
                    )
                })
                .unwrap_or((0, 0));
            if quota.exhausted(used_minute, used_day) {
                return Ok(Reservation::Quota);
            }
            tx.execute(
                "INSERT OR REPLACE INTO quota VALUES(?1,?2,?3,?4,?5)",
                params![
                    provider.name(),
                    day,
                    used_day.saturating_add(1),
                    minute,
                    used_minute.saturating_add(1)
                ],
            )?;
            tx.commit()?;
            Ok(Reservation::Fetch)
        })
        .await?
    }
    async fn remember(
        &self,
        key: String,
        credential: String,
        verdict: Option<Verdict>,
        backoff: bool,
    ) -> Result<()> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move||->Result<()>{
            let db=db.lock().map_err(|_|anyhow::anyhow!("Provider cache lock"))?;let now=crate::now();
            db.execute("DELETE FROM cache WHERE expires<=?1",[now])?;
            db.execute("DELETE FROM cooldown WHERE expires<=?1",[now])?;
            if backoff {db.execute("INSERT OR REPLACE INTO cooldown VALUES(?1,?2)",params![credential,now+300])?;}
            if let Some(verdict)=verdict {
                db.execute("DELETE FROM cache WHERE key IN (SELECT key FROM cache ORDER BY expires LIMIT MAX(0,(SELECT COUNT(*) FROM cache)-9999))",[])?;
                db.execute("INSERT OR REPLACE INTO cache VALUES(?1,?2,?3)",params![key,now+if matches!(verdict,Verdict::Unknown|Verdict::Stale){300}else{1800},serde_json::to_string(&verdict)?])?;
            }Ok(())
        }).await?
    }
    fn request(
        &self,
        provider: Provider,
        key: &str,
        indicator: &str,
        file: bool,
    ) -> reqwest::RequestBuilder {
        let endpoint = match provider {
            Provider::Crdf => "https://threatcenter.crdf.fr/api/v1/search_urls.json".to_owned(),
            Provider::Virustotal => format!(
                "https://www.virustotal.com/api/v3/{}/{indicator}",
                if file { "files" } else { "domains" }
            ),
        };
        #[cfg(test)]
        let endpoint = self.endpoint_override.clone().unwrap_or(endpoint);
        match provider {
            Provider::Crdf => self
                .http
                .post(endpoint)
                .header("X-API-Key", key)
                .json(&serde_json::json!({"method":"search_urls","urls":[crdf_url(indicator)]})),
            Provider::Virustotal => self.http.get(endpoint).header("x-apikey", key),
        }
    }
    async fn query(
        &self,
        provider: Provider,
        key: &str,
        indicator: &str,
        file: bool,
        quota: Quota,
    ) -> Lookup {
        let credential = crate::message::digest(format!("{}:{key}", provider.name()).as_bytes());
        let cache_indicator = match provider {
            Provider::Crdf => crdf_url(indicator),
            Provider::Virustotal => indicator.to_owned(),
        };
        let cache_key = crate::message::digest(
            format!("target-bound-1:{credential}:{file}:{cache_indicator}").as_bytes(),
        );
        match self
            .reserve(provider, cache_key.clone(), credential.clone(), quota)
            .await
        {
            Ok(Reservation::Cached(verdict)) => {
                return Lookup {
                    verdict: Some(verdict),
                    status: Status::Complete,
                    cached: true,
                    failure: None,
                };
            }
            Ok(Reservation::Quota) => {
                return Lookup {
                    verdict: None,
                    status: Status::Quota,
                    cached: false,
                    failure: None,
                };
            }
            Err(_) => {
                return Lookup {
                    verdict: None,
                    status: Status::Unavailable,
                    cached: false,
                    failure: Some(Failure::Storage),
                };
            }
            Ok(Reservation::Fetch) => {}
        }
        let request = self.request(provider, key, indicator, file);
        let result = async {
            let _slot = self
                .requests
                .acquire()
                .await
                .map_err(|_| (Failure::Network, false))?;
            let mut response = request.send().await.map_err(|e| network_failure(&e))?;
            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND && provider == Provider::Virustotal {
                return Ok(Some(Verdict::Unknown));
            }
            if !status.is_success() {
                return Err(match status.as_u16() {
                    401 | 403 => (Failure::Authentication, true),
                    429 => (Failure::RateLimit, true),
                    _ => (Failure::Http, false),
                });
            }
            if response.content_length().is_some_and(|n| n > 256 * 1024) {
                return Err((Failure::ResponseLimit, false));
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|e| network_failure(&e))? {
                if bytes.len() + chunk.len() > 256 * 1024 {
                    return Err((Failure::ResponseLimit, false));
                }
                bytes.extend_from_slice(&chunk);
            }
            let body: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| (Failure::InvalidResponse, false))?;
            match provider {
                Provider::Crdf => parse_crdf(&body, indicator),
                Provider::Virustotal => parse_vt_for(&body, indicator, file),
            }
            .map(Some)
            .map_err(|_| (Failure::InvalidResponse, true))
        }
        .await;
        match result {
            Ok(verdict) => {
                let _ = self.remember(cache_key, credential, verdict, false).await;
                Lookup {
                    verdict,
                    status: Status::Complete,
                    cached: false,
                    failure: None,
                }
            }
            Err((failure, backoff)) => {
                let _ = self.remember(cache_key, credential, None, backoff).await;
                Lookup {
                    verdict: None,
                    status: Status::Unavailable,
                    cached: false,
                    failure: Some(failure),
                }
            }
        }
    }
    pub async fn inspect(
        &self,
        provider: Provider,
        enabled: bool,
        targets: &Targets,
        policy: &Policy,
    ) -> (ProviderReport, Vec<(String, bool)>) {
        if !enabled {
            return (Default::default(), vec![]);
        }
        let started = Instant::now();
        let mut report = ProviderReport {
            status: Status::NotConfigured,
            ..Default::default()
        };
        let root = self.root.clone();
        let key = tokio::task::spawn_blocking(move || read_key(&root, provider)).await;
        let Ok(Ok(key)) = key else {
            return (report, vec![]);
        };
        let Ok(_permit) = self.gate.try_acquire() else {
            report.status = Status::Busy;
            return (report, vec![]);
        };
        let mut hits = Vec::new();
        report.status = Status::Complete;
        let mut planned = 0;
        let work = async {
            let mut seen = std::collections::BTreeSet::new();
            let indicators: Vec<_> = targets
                .destination_domains
                .iter()
                .chain(targets.domains.iter())
                .filter(|s| super::local::public_domain(s))
                .filter(|s| seen.insert(s.as_str()))
                .map(|s| (s, false))
                .chain(
                    targets
                        .hashes
                        .iter()
                        .filter(|s| {
                            provider == Provider::Virustotal
                                && s.len() == 64
                                && s.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                        .map(|s| (s, true)),
                )
                .collect();
            report.omitted = indicators.len().saturating_sub(12);
            planned = indicators.len().min(12);
            let priority_end = indicators
                .iter()
                .take(planned)
                .take_while(|(indicator, file)| {
                    !file && targets.destination_domains.contains(*indicator)
                })
                .count();
            let mut priority_finished = priority_end == 0;
            let mut scheduled = 0;
            let mut remaining = indicators.into_iter().take(12);
            let quota = self.config.quota(provider, policy);
            let mut tasks = tokio::task::JoinSet::new();
            let mut may_schedule = true;
            loop {
                while may_schedule && tasks.len() < 3 {
                    // Final destinations reserve scarce quota before origins.
                    if !priority_finished && scheduled == priority_end {
                        break;
                    }
                    let Some((indicator, file)) = remaining.next() else {
                        break;
                    };
                    scheduled += 1;
                    let client = self.clone();
                    let key = key.clone();
                    let indicator = indicator.clone();
                    tasks.spawn(async move {
                        let result = client.query(provider, &key, &indicator, file, quota).await;
                        (indicator, file, result)
                    });
                }
                let Some(completed) = tasks.join_next().await else {
                    break;
                };
                if tasks.is_empty() && scheduled == priority_end {
                    priority_finished = true;
                }
                let Ok((indicator, file, result)) = completed else {
                    report.status = Status::Unavailable;
                    report.failure = Some(Failure::Network);
                    may_schedule = false;
                    continue;
                };
                if result.status != Status::Complete {
                    report.status = result.status;
                    report.failure = result.failure;
                    may_schedule = false;
                    continue;
                }
                report.checked += 1;
                report.cache_hits += usize::from(result.cached);
                if let Some(verdict) = result.verdict {
                    let cache_age = if result.cached {
                        if matches!(verdict, Verdict::Unknown | Verdict::Stale) {
                            300
                        } else {
                            1800
                        }
                    } else {
                        0
                    };
                    report.observations.push(super::ProviderObservation {
                        indicator_sha256: crate::message::digest(indicator.as_bytes()),
                        scope: if file {
                            "file"
                        } else if provider == Provider::Crdf {
                            "host_lookup"
                        } else {
                            "domain"
                        }
                        .into(),
                        verdict: serde_json::to_value(verdict)
                            .expect("verdict")
                            .as_str()
                            .unwrap()
                            .into(),
                        queried_at: crate::now(),
                        cached: result.cached,
                        cache_max_age_seconds: cache_age,
                        analysis_max_age_seconds: (provider == Provider::Virustotal
                            && verdict != Verdict::Stale
                            && verdict != Verdict::Unknown)
                            .then_some(7 * 86400 + cache_age),
                    });
                }
                match result.verdict {
                    Some(Verdict::Malicious) => {
                        report.malicious += 1;
                        hits.push((indicator, file));
                    }
                    Some(Verdict::Suspicious) => report.suspicious += 1,
                    Some(Verdict::Unknown) => report.unknown += 1,
                    Some(Verdict::Stale) => {
                        report.unknown += 1;
                        if report.status == Status::Complete {
                            report.status = Status::Stale;
                        }
                    }
                    _ => {}
                }
            }
        };
        if tokio::time::timeout(Duration::from_millis(self.config.timeout_ms), work)
            .await
            .is_err()
        {
            report.status = Status::Unavailable;
            report.failure = Some(Failure::Timeout);
        }
        report.omitted += planned.saturating_sub(report.checked);
        if report.omitted > 0 && report.status == Status::Complete {
            report.status = Status::Limited;
        }
        report.elapsed_ms = started.elapsed().as_millis() as u64;
        hits.sort();
        (report, hits)
    }
}
// CRDF validates URL syntax even for a domain lookup. Never send message paths,
// parameters or fragments: this synthetic root contains only the public host.
fn crdf_url(domain: &str) -> String {
    format!("https://{domain}/")
}
fn parse_crdf(body: &serde_json::Value, indicator: &str) -> Result<Verdict> {
    ensure!(
        body.get("error").and_then(|v| v.as_bool()) == Some(false),
        "CRDF error"
    );
    let entries = body["data"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("CRDF schema"))?;
    ensure!(entries.len() == 1, "CRDF count mismatch");
    let entry = &entries[0];
    ensure!(
        entry["url"].as_str() == Some(crdf_url(indicator).as_str())
            && entry["error"].as_bool() == Some(false),
        "CRDF mismatch"
    );
    match entry["in_database"].as_bool() {
        Some(false) => Ok(Verdict::Unknown),
        Some(true) => {
            let record = &entry["data"];
            let blacklisted = match record["isBlacklisted"]
                .as_str()
                .map(str::to_owned)
                .or_else(|| record["isBlacklisted"].as_u64().map(|n| n.to_string()))
                .as_deref()
            {
                Some("1") => true,
                Some("0") => false,
                _ => anyhow::bail!("CRDF invalid blacklist state"),
            };
            let category = record["category"]
                .as_str()
                .unwrap_or_default()
                .to_lowercase();
            if blacklisted
                && ["malicious", "malware", "phishing"]
                    .iter()
                    .any(|c| category.contains(c))
            {
                // A matching malicious page is not proof against every URL of a shared host.
                let scope = record["url"]
                    .as_str()
                    .and_then(|u| reqwest::Url::parse(u).ok());
                let Some(scope) = scope else {
                    return Ok(Verdict::Suspicious);
                };
                ensure!(
                    scope.host_str() == Some(indicator)
                        && record["domainName"].as_str().is_none_or(|d| d == indicator),
                    "CRDF record target mismatch"
                );
                Ok(
                    if scope.path() != "/" || scope.query().is_some() || scope.fragment().is_some()
                    {
                        Verdict::Suspicious
                    } else {
                        Verdict::Malicious
                    },
                )
            } else if blacklisted {
                Ok(Verdict::Suspicious)
            } else {
                Ok(Verdict::NoHit)
            }
        }
        _ => anyhow::bail!("CRDF missing lookup state"),
    }
}
fn parse_vt(body: &serde_json::Value) -> Result<Verdict> {
    let attrs = &body["data"]["attributes"];
    let observed = attrs["last_analysis_date"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("VT missing analysis date"))?;
    if observed < crate::now() - 7 * 86400 || observed > crate::now() + 300 {
        return Ok(Verdict::Stale);
    }
    let malicious = attrs["last_analysis_stats"]["malicious"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("VT schema"))?;
    let suspicious = attrs["last_analysis_stats"]["suspicious"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("VT schema"))?;
    ensure!(
        malicious <= 10000 && suspicious <= 10000,
        "VT invalid count"
    );
    Ok(if malicious >= 3 {
        Verdict::Malicious
    } else if malicious + suspicious > 0 {
        Verdict::Suspicious
    } else {
        Verdict::NoHit
    })
}

fn parse_vt_for(body: &serde_json::Value, indicator: &str, file: bool) -> Result<Verdict> {
    ensure!(
        body["data"]["id"].as_str() == Some(indicator)
            && body["data"]["type"].as_str() == Some(if file { "file" } else { "domain" }),
        "VT response target mismatch"
    );
    parse_vt(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn provider_identity_and_scope_are_verified_before_recording_a_hit() {
        let mut vt = json!({"data":{"id":"example.org","type":"domain","attributes":{"last_analysis_date":crate::now(),"last_analysis_stats":{"malicious":3,"suspicious":0}}}});
        assert_eq!(
            parse_vt_for(&vt, "example.org", false).unwrap(),
            Verdict::Malicious
        );
        assert!(parse_vt_for(&vt, "other.org", false).is_err());
        assert!(parse_vt_for(&vt, "example.org", true).is_err());
        vt["data"]["attributes"]["last_analysis_date"] = json!(crate::now() - 8 * 86400);
        assert_eq!(
            parse_vt_for(&vt, "example.org", false).unwrap(),
            Verdict::Stale
        );
        let mut crdf = json!({"error":false,"data":[{"url":"https://example.org/","error":false,"in_database":true,"data":{"isBlacklisted":"1","category":"Malicious:URL"}}]});
        assert_eq!(
            parse_crdf(&crdf, "example.org").unwrap(),
            Verdict::Suspicious,
            "Missing record scope cannot attest a whole host"
        );
        crdf["data"][0]["data"]["url"] = json!("https://other.org/");
        assert!(parse_crdf(&crdf, "example.org").is_err());
        crdf["data"][0]["data"]["url"] = json!("https://example.org/specific-page");
        assert_eq!(
            parse_crdf(&crdf, "example.org").unwrap(),
            Verdict::Suspicious
        );
    }
    #[test]
    fn provider_errors_unknowns_and_low_consensus_never_become_malicious() {
        assert!(
            parse_crdf(
                &json!({"error":true,"data":[{"in_database":true}]}),
                "evil.com"
            )
            .is_err()
        );
        assert_eq!(parse_crdf(&json!({"error":false,"data":[{"url":"https://evil.com/","error":false,"in_database":false}]}),"evil.com").unwrap(),Verdict::Unknown);
        let mut body = json!({"error":false,"data":[{"url":"https://evil.com/","error":false,"in_database":true,"data":{"url":"https://evil.com/","isBlacklisted":"1","category":"Malicious:URL"}}]});
        assert_eq!(parse_crdf(&body, "evil.com").unwrap(), Verdict::Malicious);
        assert!(parse_crdf(&body, "other.com").is_err());
        assert!(parse_crdf(&json!({"error":false,"data":[{"url":"evil.com","error":true,"message":"Invalid URL.","in_database":false}]}),"evil.com").is_err());
        assert!(parse_crdf(&json!({"error":false,"data":[{"url":"https://evil.com/private?token=redacted","error":false,"in_database":false}]}),"evil.com").is_err());
        body["data"][0]["data"]["url"] = json!("https://evil.com/a-single-page");
        assert_eq!(parse_crdf(&body, "evil.com").unwrap(), Verdict::Suspicious);
        body["data"][0]["data"]["isBlacklisted"] = json!("invalid");
        assert!(parse_crdf(&body, "evil.com").is_err());

        body["data"][0]["data"]["isBlacklisted"] = json!("0");
        assert_eq!(parse_crdf(&body, "evil.com").unwrap(), Verdict::NoHit);
        let mut vt = json!({"data":{"attributes":{"last_analysis_date":crate::now(),"last_analysis_stats":{"malicious":1,"suspicious":0}}}});
        assert_eq!(parse_vt(&vt).unwrap(), Verdict::Suspicious);
        vt["data"]["attributes"]["last_analysis_stats"]["malicious"] = json!(3);
        assert_eq!(parse_vt(&vt).unwrap(), Verdict::Malicious);
        vt["data"]["attributes"]["last_analysis_date"] = json!(crate::now() - 8 * 86400);
        assert_eq!(parse_vt(&vt).unwrap(), Verdict::Stale);
        assert!(parse_vt(&json!({"error":{"code":"QuotaExceededError"}})).is_err());
    }
    #[tokio::test]
    async fn budgets_survive_restart_and_cache_does_not_consume_quota() {
        let root = tempfile::tempdir().unwrap();
        let settings = Settings {
            crdf_per_minute: 1,
            crdf_per_day: 1,
            ..Default::default()
        };
        let client = Client::new(&settings, root.path()).unwrap();
        assert!(matches!(
            client
                .reserve(
                    Provider::Crdf,
                    "hash".into(),
                    "key".into(),
                    Quota { minute: 1, day: 1 }
                )
                .await
                .unwrap(),
            Reservation::Fetch
        ));
        client
            .remember("hash".into(), "key".into(), Some(Verdict::Unknown), false)
            .await
            .unwrap();
        assert!(matches!(
            client
                .reserve(
                    Provider::Crdf,
                    "hash".into(),
                    "key".into(),
                    Quota { minute: 1, day: 1 }
                )
                .await
                .unwrap(),
            Reservation::Cached(Verdict::Unknown)
        ));
        drop(client);
        let client = Client::new(&settings, root.path()).unwrap();
        assert!(matches!(
            client
                .reserve(
                    Provider::Crdf,
                    "different".into(),
                    "key".into(),
                    Quota { minute: 1, day: 1 }
                )
                .await
                .unwrap(),
            Reservation::Quota
        ));
    }
    #[tokio::test]
    async fn cooldown_and_absent_keys_are_explicit() {
        let root = tempfile::tempdir().unwrap();
        let client = Client::new(&Settings::default(), root.path()).unwrap();
        let (report, hits) = client
            .inspect(
                Provider::Crdf,
                true,
                &Targets::default(),
                &Policy::default(),
            )
            .await;
        assert_eq!(report.status, Status::NotConfigured);
        assert!(hits.is_empty());
        client
            .remember("hash".into(), "key".into(), None, true)
            .await
            .unwrap();
        assert!(matches!(
            client
                .reserve(
                    Provider::Crdf,
                    "different".into(),
                    "key".into(),
                    Quota { minute: 1, day: 1 }
                )
                .await
                .unwrap(),
            Reservation::Quota
        ));
    }
    #[tokio::test]
    async fn unlimited_and_changed_limits_keep_usage_and_provider_cooldown() {
        let root = tempfile::tempdir().unwrap();
        let client = Arc::new(Client::new(&Settings::default(), root.path()).unwrap());
        let unlimited = Quota { minute: 0, day: 0 };
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..64 {
            let client = client.clone();
            tasks.spawn(async move {
                client
                    .reserve(
                        Provider::Crdf,
                        format!("indicator-{i}"),
                        "key".into(),
                        Quota { minute: 0, day: 7 },
                    )
                    .await
                    .unwrap()
            });
        }
        let mut fetched = 0;
        while let Some(result) = tasks.join_next().await {
            fetched += usize::from(matches!(result.unwrap(), Reservation::Fetch));
        }
        assert_eq!(fetched, 7);
        assert!(matches!(
            client
                .reserve(Provider::Crdf, "extra".into(), "key".into(), unlimited)
                .await
                .unwrap(),
            Reservation::Fetch
        ));
        assert_eq!(
            quota_usage(root.path(), Provider::Crdf).unwrap().day_used,
            8
        );
        assert!(matches!(
            client
                .reserve(
                    Provider::Crdf,
                    "extra".into(),
                    "key".into(),
                    Quota { minute: 0, day: 7 }
                )
                .await
                .unwrap(),
            Reservation::Quota
        ));
        // Provider refusal still pauses an unlimited account; existing cache remains useful.
        client
            .remember("cached".into(), "key".into(), Some(Verdict::NoHit), true)
            .await
            .unwrap();
        assert!(matches!(
            client
                .reserve(Provider::Crdf, "extra".into(), "key".into(), unlimited)
                .await
                .unwrap(),
            Reservation::Quota
        ));
        assert!(matches!(
            client
                .reserve(Provider::Crdf, "cached".into(), "key".into(), unlimited)
                .await
                .unwrap(),
            Reservation::Cached(Verdict::NoHit)
        ));
        drop(client);
        let resumed = Client::new(&Settings::default(), root.path()).unwrap();
        assert_eq!(
            quota_usage(root.path(), Provider::Crdf).unwrap().day_used,
            8
        );
        assert!(matches!(
            resumed
                .reserve(Provider::Crdf, "extra".into(), "key".into(), unlimited)
                .await
                .unwrap(),
            Reservation::Quota
        ));
        assert!(matches!(
            resumed
                .reserve(
                    Provider::Virustotal,
                    "extra".into(),
                    "other-key".into(),
                    Quota { minute: 0, day: 1 }
                )
                .await
                .unwrap(),
            Reservation::Fetch
        ));
    }
    #[tokio::test]
    async fn windows_reset_independently_and_unlimited_counters_do_not_overflow() {
        let root = tempfile::tempdir().unwrap();
        let client = Client::new(&Settings::default(), root.path()).unwrap();
        let now = crate::now();
        client
            .db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO quota VALUES('crdf',?1,99,?2,99)",
                params![now / 86400, now / 60 - 1],
            )
            .unwrap();
        assert!(matches!(
            client
                .reserve(
                    Provider::Crdf,
                    "a".into(),
                    "key".into(),
                    Quota { minute: 1, day: 0 }
                )
                .await
                .unwrap(),
            Reservation::Fetch
        ));
        let usage = quota_usage(root.path(), Provider::Crdf).unwrap();
        assert_eq!(usage.day_used, 100);
        assert_eq!(usage.minute_used, 1);
        client
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE quota SET day=?1,day_used=99,minute=?2,minute_used=0",
                params![now / 86400 - 1, now / 60],
            )
            .unwrap();
        assert!(matches!(
            client
                .reserve(
                    Provider::Crdf,
                    "b".into(),
                    "key".into(),
                    Quota { minute: 0, day: 1 }
                )
                .await
                .unwrap(),
            Reservation::Fetch
        ));
        assert_eq!(
            quota_usage(root.path(), Provider::Crdf).unwrap().day_used,
            1
        );
        client
            .db
            .lock()
            .unwrap()
            .execute("UPDATE quota SET day_used=?1,minute_used=?1", [i64::MAX])
            .unwrap();
        assert!(matches!(
            client
                .reserve(
                    Provider::Crdf,
                    "c".into(),
                    "key".into(),
                    Quota { minute: 0, day: 0 }
                )
                .await
                .unwrap(),
            Reservation::Fetch
        ));
        assert_eq!(
            quota_usage(root.path(), Provider::Crdf).unwrap().day_used,
            i64::MAX
        );
    }
    #[test]
    fn credentials_are_atomic_private_and_reject_header_injection() {
        let root = tempfile::tempdir().unwrap();
        assert!(save_key(root.path(), Provider::Crdf, "secret\r\nInjection: value").is_err());
        save_key(
            root.path(),
            Provider::Crdf,
            "synthetic-provider-key-123456789",
        )
        .unwrap();
        assert!(key_present(root.path(), Provider::Crdf));
        assert_eq!(
            std::fs::metadata(key_path(root.path(), Provider::Crdf))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn server(
        status: &str,
        body: String,
        delay_ms: u64,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let status = status.to_owned();
        let work = async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 4096];
            loop {
                let n = socket.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..n]);
                if let Some(end) = request.windows(4).position(|s| s == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|s| s.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
                assert!(request.len() < 10000);
            }
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            String::from_utf8(request).unwrap()
        };
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(10), work)
                .await
                .expect("mock HTTP server did not finish within ten seconds")
        });
        (format!("http://{address}/lookup"), task)
    }
    #[tokio::test]
    async fn read_only_transport_caches_and_sends_only_one_domain() {
        let root = tempfile::tempdir().unwrap();
        let mut client = Client::new(&Settings::default(), root.path()).unwrap();
        save_key(
            root.path(),
            Provider::Crdf,
            "synthetic-key-for-transport-1234",
        )
        .unwrap();
        let (url,task)=server("200 OK",serde_json::json!({"error":false,"data":[{"url":"https://example.com/","error":false,"in_database":false}]}).to_string(),0).await;
        client.endpoint_override = Some(url);
        let mut targets = Targets::default();
        targets.domains.insert("example.com".into());
        targets.domains.insert("private.local".into());
        targets
            .hashes
            .insert("private attachment must not be sent".into());
        let (result, hits) = client
            .inspect(Provider::Crdf, true, &targets, &Policy::default())
            .await;
        assert_eq!(result.status, Status::Complete);
        assert_eq!(result.unknown, 1);
        assert!(hits.is_empty());
        let request = task.await.unwrap();
        assert!(request.starts_with("POST /lookup "));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("x-api-key: synthetic-key-for-transport-1234")
        );
        let body: serde_json::Value =
            serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"method":"search_urls","urls":["https://example.com/"]})
        );
        let (cached, _) = client
            .inspect(Provider::Crdf, true, &targets, &Policy::default())
            .await;
        assert_eq!(cached.cache_hits, 1);
    }
    #[tokio::test]
    async fn transaction_policy_changes_budget_on_the_existing_client() {
        let root = tempfile::tempdir().unwrap();
        let settings = Settings {
            crdf_per_minute: 1,
            crdf_per_day: 1,
            ..Default::default()
        };
        let mut client = Client::new(&settings, root.path()).unwrap();
        save_key(
            root.path(),
            Provider::Crdf,
            "synthetic-key-for-transport-1234",
        )
        .unwrap();
        client
            .reserve(
                Provider::Crdf,
                "old".into(),
                "old".into(),
                Quota { minute: 0, day: 0 },
            )
            .await
            .unwrap();
        let mut targets = Targets::default();
        targets.domains.insert("example.com".into());
        let (blocked, _) = client
            .inspect(Provider::Crdf, true, &targets, &Policy::default())
            .await;
        assert_eq!(blocked.status, Status::Quota);
        let (url,task) = server("200 OK",serde_json::json!({"error":false,"data":[{"url":"https://example.com/","error":false,"in_database":false}]}).to_string(),0).await;
        client.endpoint_override = Some(url);
        let policy = Policy {
            crdf_quota: Some(Quota { minute: 0, day: 0 }),
            ..Default::default()
        };
        let (report, _) = client
            .inspect(Provider::Crdf, true, &targets, &policy)
            .await;
        assert_eq!(report.status, Status::Complete);
        assert_eq!(report.checked, 1);
        task.await.unwrap();
        assert_eq!(
            quota_usage(root.path(), Provider::Crdf).unwrap().day_used,
            2
        );
        // Returning to bootstrap limits does not erase existing usage.
        targets.domains.clear();
        targets.domains.insert("example.org".into());
        assert_eq!(
            client
                .inspect(Provider::Crdf, true, &targets, &Policy::default())
                .await
                .0
                .status,
            Status::Quota
        );
    }
    #[tokio::test]
    async fn discovered_destination_precedes_original_domains_under_quota() {
        let root = tempfile::tempdir().unwrap();
        let settings = Settings {
            crdf_per_minute: 1,
            crdf_per_day: 1,
            ..Default::default()
        };
        let mut client = Client::new(&settings, root.path()).unwrap();
        save_key(
            root.path(),
            Provider::Crdf,
            "synthetic-key-for-transport-1234",
        )
        .unwrap();
        let (url, task) = server("200 OK", serde_json::json!({"error":false,"data":[{"url":"https://z-final.example.com/","error":false,"in_database":false}]}).to_string(), 0).await;
        client.endpoint_override = Some(url);
        let mut targets = Targets::default();
        for i in 0..13 {
            targets.domains.insert(format!("a{i}.example.com"));
        }
        targets.domains.insert("z-final.example.com".into());
        targets
            .destination_domains
            .insert("z-final.example.com".into());
        let (report, hits) = client
            .inspect(Provider::Crdf, true, &targets, &Policy::default())
            .await;
        assert_eq!(report.checked, 1);
        assert_eq!(report.omitted, 13); // Includes both cap exclusions and quota skips.
        assert_eq!(report.status, Status::Quota);
        assert!(hits.is_empty());
        let request = task.await.unwrap();
        let body: serde_json::Value =
            serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(
            body["urls"],
            serde_json::json!(["https://z-final.example.com/"])
        );
    }
    #[tokio::test]
    async fn quota_timeout_and_oversized_responses_never_produce_a_hit() {
        for (status, body, delay, failure) in [
            (
                "429 Too Many Requests",
                "{}".to_owned(),
                0,
                Failure::RateLimit,
            ),
            (
                "401 Unauthorized",
                "{}".to_owned(),
                0,
                Failure::Authentication,
            ),
            (
                "500 Internal Server Error",
                "{}".to_owned(),
                0,
                Failure::Http,
            ),
            (
                "200 OK",
                "x".repeat(256 * 1024 + 1),
                0,
                Failure::ResponseLimit,
            ),
            ("200 OK", "{}".to_owned(), 0, Failure::InvalidResponse),
            ("200 OK", "{}".to_owned(), 300, Failure::Timeout),
        ] {
            let root = tempfile::tempdir().unwrap();
            let mut client = Client::new(
                &Settings {
                    timeout_ms: if delay == 0 { 2000 } else { 100 },
                    ..Default::default()
                },
                root.path(),
            )
            .unwrap();
            save_key(
                root.path(),
                Provider::Virustotal,
                "synthetic-key-for-transport-1234",
            )
            .unwrap();
            let (url, task) = server(status, body, delay).await;
            client.endpoint_override = Some(url);
            let mut targets = Targets::default();
            targets.domains.insert("example.com".into());
            let start = Instant::now();
            let (report, hits) = client
                .inspect(Provider::Virustotal, true, &targets, &Policy::default())
                .await;
            assert_eq!(report.status, Status::Unavailable);
            assert_eq!(report.failure, Some(failure));
            assert_eq!(report.omitted, 1);
            assert!(hits.is_empty());
            assert!(start.elapsed() < Duration::from_secs(3));
            if delay == 0 {
                assert!(task.await.unwrap().starts_with("GET /lookup "));
            } else {
                // The deadline may expire before connect on a busy runner. The
                // mock must not remain blocked in accept after client cancellation.
                task.abort();
                let _ = task.await;
            }
        }
    }
    #[test]
    fn virustotal_uses_hash_reports_never_a_submission_endpoint() {
        let root = tempfile::tempdir().unwrap();
        let client = Client::new(&Settings::default(), root.path()).unwrap();
        let hash = "a".repeat(64);
        let request = client
            .request(Provider::Virustotal, "synthetic-key-123456789", &hash, true)
            .build()
            .unwrap();
        assert_eq!(request.method(), reqwest::Method::GET);
        assert_eq!(
            request.url().as_str(),
            format!("https://www.virustotal.com/api/v3/files/{hash}")
        );
        assert!(request.body().is_none());
    }

    #[tokio::test]
    async fn indicators_run_concurrently_with_a_shared_request_limit_and_cache() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let count = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let (a, p, c, b) = (active.clone(), peak.clone(), count.clone(), barrier);
        let app = axum::Router::new().route("/lookup", axum::routing::post(move |axum::Json(input): axum::Json<serde_json::Value>| {
            let (a,p,c,b) = (a.clone(),p.clone(),c.clone(),b.clone());
            async move {
                let current=a.fetch_add(1,Ordering::SeqCst)+1;
                p.fetch_max(current,Ordering::SeqCst);
                c.fetch_add(1,Ordering::SeqCst);
                b.wait().await;
                a.fetch_sub(1,Ordering::SeqCst);
                axum::Json(serde_json::json!({"error":false,"data":[{"url":input["urls"][0],"error":false,"in_database":false}]}))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/lookup", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let root = tempfile::tempdir().unwrap();
        let settings = Settings {
            max_parallel: 2,
            timeout_ms: 2000,
            crdf_per_minute: 0,
            crdf_per_day: 0,
            ..Default::default()
        };
        let mut client = Client::new(&settings, root.path()).unwrap();
        client.endpoint_override = Some(endpoint);
        save_key(
            root.path(),
            Provider::Crdf,
            "synthetic-key-for-concurrency-1234",
        )
        .unwrap();
        let mut targets = Targets::default();
        for i in 0..6 {
            targets.domains.insert(format!("a{i}.example.com"));
        }
        let (report, hits) = client
            .inspect(Provider::Crdf, true, &targets, &Policy::default())
            .await;
        assert_eq!(report.status, Status::Complete);
        assert_eq!(report.checked, 6);
        assert_eq!(report.omitted, 0);
        assert!(hits.is_empty());
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(count.load(Ordering::SeqCst), 6);
        let (cached, _) = client
            .inspect(Provider::Crdf, true, &targets, &Policy::default())
            .await;
        assert_eq!(cached.cache_hits, 6);
        assert_eq!(count.load(Ordering::SeqCst), 6);
        assert_eq!(client.requests.available_permits(), 2);
        server.abort();
    }
}
