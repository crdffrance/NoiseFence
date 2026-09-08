use super::{ProviderReport, Settings, Status, Targets};
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
}
enum Reservation {
    Cached(Verdict),
    Fetch,
    Quota,
}

pub struct Client {
    root: PathBuf,
    config: Settings,
    http: reqwest::Client,
    db: Arc<Mutex<Connection>>,
    gate: Arc<tokio::sync::Semaphore>,
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
                .user_agent(concat!("NoiseFence/", env!("CARGO_PKG_VERSION")))
                .build()?,
            db: Arc::new(Mutex::new(db)),
            gate: Arc::new(tokio::sync::Semaphore::new(config.max_parallel)),
        })
    }
    async fn reserve(
        &self,
        provider: Provider,
        cache_key: String,
        credential_id: String,
    ) -> Result<Reservation> {
        let db = self.db.clone();
        let (minute_limit, day_limit) = match provider {
            Provider::Crdf => (self.config.crdf_per_minute, self.config.crdf_per_day),
            Provider::Virustotal => (
                self.config.virustotal_per_minute,
                self.config.virustotal_per_day,
            ),
        };
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
            let previous: Option<(i64, u32, i64, u32)> = tx
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
            if used_day >= day_limit || used_minute >= minute_limit {
                return Ok(Reservation::Quota);
            }
            tx.execute(
                "INSERT OR REPLACE INTO quota VALUES(?1,?2,?3,?4,?5)",
                params![provider.name(), day, used_day + 1, minute, used_minute + 1],
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
                .json(&serde_json::json!({"method":"search_urls","urls":[indicator]})),
            Provider::Virustotal => self.http.get(endpoint).header("x-apikey", key),
        }
    }
    async fn query(&self, provider: Provider, key: &str, indicator: &str, file: bool) -> Lookup {
        let credential = crate::message::digest(format!("{}:{key}", provider.name()).as_bytes());
        let cache_key =
            crate::message::digest(format!("{credential}:{file}:{indicator}").as_bytes());
        match self
            .reserve(provider, cache_key.clone(), credential.clone())
            .await
        {
            Ok(Reservation::Cached(verdict)) => {
                return Lookup {
                    verdict: Some(verdict),
                    status: Status::Complete,
                    cached: true,
                };
            }
            Ok(Reservation::Quota) => {
                return Lookup {
                    verdict: None,
                    status: Status::Quota,
                    cached: false,
                };
            }
            Err(_) => {
                return Lookup {
                    verdict: None,
                    status: Status::Unavailable,
                    cached: false,
                };
            }
            Ok(Reservation::Fetch) => {}
        }
        let request = self.request(provider, key, indicator, file);
        let result = async {
            let mut response = request.send().await.map_err(|_| false)?;
            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND && provider == Provider::Virustotal {
                return Ok(Some(Verdict::Unknown));
            }
            if !status.is_success() {
                return Err(matches!(status.as_u16(), 401 | 403 | 429));
            }
            if response.content_length().is_some_and(|n| n > 256 * 1024) {
                return Err(false);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| false)? {
                if bytes.len() + chunk.len() > 256 * 1024 {
                    return Err(false);
                }
                bytes.extend_from_slice(&chunk);
            }
            let body: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| false)?;
            match provider {
                Provider::Crdf => parse_crdf(&body, indicator),
                Provider::Virustotal => parse_vt(&body),
            }
            .map(Some)
            .map_err(|_| true)
        }
        .await;
        match result {
            Ok(verdict) => {
                let _ = self.remember(cache_key, credential, verdict, false).await;
                Lookup {
                    verdict,
                    status: Status::Complete,
                    cached: false,
                }
            }
            Err(backoff) => {
                let _ = self.remember(cache_key, credential, None, backoff).await;
                Lookup {
                    verdict: None,
                    status: Status::Unavailable,
                    cached: false,
                }
            }
        }
    }
    pub async fn inspect(
        &self,
        provider: Provider,
        enabled: bool,
        targets: &Targets,
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
        let work = async {
            let indicators = targets
                .domains
                .iter()
                .filter(|s| super::local::public_domain(s))
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
                .take(12);
            for (indicator, file) in indicators {
                let result = self.query(provider, &key, indicator, file).await;
                if result.status != Status::Complete {
                    report.status = result.status;
                    break;
                }
                report.checked += 1;
                report.cache_hits += usize::from(result.cached);
                match result.verdict {
                    Some(Verdict::Malicious) => {
                        report.malicious += 1;
                        hits.push((indicator.clone(), file));
                    }
                    Some(Verdict::Suspicious) => report.suspicious += 1,
                    Some(Verdict::Unknown) => report.unknown += 1,
                    Some(Verdict::Stale) => {
                        report.unknown += 1;
                        report.status = Status::Stale;
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
        }
        report.elapsed_ms = started.elapsed().as_millis() as u64;
        (report, hits)
    }
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
        entry["url"].as_str() == Some(indicator) && entry["error"].as_bool() == Some(false),
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
                if scope.is_some_and(|u| u.path() != "/" || u.query().is_some()) {
                    Ok(Verdict::Suspicious)
                } else {
                    Ok(Verdict::Malicious)
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn provider_errors_unknowns_and_low_consensus_never_become_malicious() {
        assert!(
            parse_crdf(
                &json!({"error":true,"data":[{"in_database":true}]}),
                "evil.com"
            )
            .is_err()
        );
        assert_eq!(parse_crdf(&json!({"error":false,"data":[{"url":"evil.com","error":false,"in_database":false}]}),"evil.com").unwrap(),Verdict::Unknown);
        let mut body = json!({"error":false,"data":[{"url":"evil.com","error":false,"in_database":true,"data":{"isBlacklisted":"1","category":"Malicious:URL"}}]});
        assert_eq!(parse_crdf(&body, "evil.com").unwrap(), Verdict::Malicious);
        assert!(parse_crdf(&body, "other.com").is_err());
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
                .reserve(Provider::Crdf, "hash".into(), "key".into())
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
                .reserve(Provider::Crdf, "hash".into(), "key".into())
                .await
                .unwrap(),
            Reservation::Cached(Verdict::Unknown)
        ));
        drop(client);
        let client = Client::new(&settings, root.path()).unwrap();
        assert!(matches!(
            client
                .reserve(Provider::Crdf, "different".into(), "key".into())
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
            .inspect(Provider::Crdf, true, &Targets::default())
            .await;
        assert_eq!(report.status, Status::NotConfigured);
        assert!(hits.is_empty());
        client
            .remember("hash".into(), "key".into(), None, true)
            .await
            .unwrap();
        assert!(matches!(
            client
                .reserve(Provider::Crdf, "different".into(), "key".into())
                .await
                .unwrap(),
            Reservation::Quota
        ));
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
        let task = tokio::spawn(async move {
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
        let (url,task)=server("200 OK",serde_json::json!({"error":false,"data":[{"url":"example.com","error":false,"in_database":false}]}).to_string(),0).await;
        client.endpoint_override = Some(url);
        let mut targets = Targets::default();
        targets.domains.insert("example.com".into());
        targets.domains.insert("private.local".into());
        targets
            .hashes
            .insert("private attachment must not be sent".into());
        let (result, hits) = client.inspect(Provider::Crdf, true, &targets).await;
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
            serde_json::json!({"method":"search_urls","urls":["example.com"]})
        );
        let (cached, _) = client.inspect(Provider::Crdf, true, &targets).await;
        assert_eq!(cached.cache_hits, 1);
    }
    #[tokio::test]
    async fn quota_timeout_and_oversized_responses_never_produce_a_hit() {
        for (status, body, delay) in [
            ("429 Too Many Requests", "{}".to_owned(), 0),
            ("200 OK", "x".repeat(256 * 1024 + 1), 0),
            ("200 OK", "{}".to_owned(), 300),
        ] {
            let root = tempfile::tempdir().unwrap();
            let mut client = Client::new(
                &Settings {
                    timeout_ms: 100,
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
            let (report, hits) = client.inspect(Provider::Virustotal, true, &targets).await;
            assert_eq!(report.status, Status::Unavailable);
            assert!(hits.is_empty());
            assert!(start.elapsed() < Duration::from_secs(1));
            task.await.unwrap();
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
}
