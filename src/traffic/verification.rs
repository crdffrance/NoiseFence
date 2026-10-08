//! Opt-in challenge/response, scoped to an authenticated sender and recipient.
//! CAPTCHA is proof of interaction, never proof that a message is harmless.
use super::*;
use anyhow::Context;
use mail_parser::MimeHeaders;
use rand::RngCore;
use rusqlite::{OptionalExtension, params};
use std::time::Duration;

pub mod captcha;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptchaProvider {
    #[default]
    Turnstile,
    SelfHosted,
}
impl CaptchaProvider {
    fn is_turnstile(&self) -> bool {
        *self == Self::Turnstile
    }
}

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sender_verification_key_v1 (id INTEGER PRIMARY KEY CHECK(id=1), key BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sender_verification_v1 (
 id TEXT PRIMARY KEY,sender TEXT NOT NULL,recipient TEXT NOT NULL,created INTEGER NOT NULL,
 expires INTEGER NOT NULL,armed INTEGER NOT NULL DEFAULT 0,verified INTEGER,notified INTEGER,
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS sender_verification_expiry_v1 ON sender_verification_v1(expires);
CREATE INDEX IF NOT EXISTS sender_verification_pair_v1 ON sender_verification_v1(sender,recipient,expires);
CREATE TABLE IF NOT EXISTS sender_verification_grants_v1 (sender TEXT NOT NULL,recipient TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(sender,recipient));";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub public_origin: String,
    pub site_key: String,
    #[serde(skip_serializing_if = "CaptchaProvider::is_turnstile")]
    pub captcha_provider: CaptchaProvider,
    pub notification_from: String,
    pub relay_hosts: Vec<String>,
    pub lifetime_hours: u16,
    pub remember_days: u16,
    pub invitations_per_day: u32,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            public_origin: String::new(),
            site_key: String::new(),
            captcha_provider: CaptchaProvider::Turnstile,
            notification_from: String::new(),
            relay_hosts: Vec::new(),
            lifetime_hours: 24,
            remember_days: 30,
            invitations_per_day: 100,
        }
    }
}
impl Settings {
    pub fn available(&self, cfg: &crate::config::Config) -> bool {
        self.captcha_provider == CaptchaProvider::SelfHosted
            || cfg
                .provider_credentials
                .as_ref()
                .is_some_and(|keys| keys.get("turnstile").is_some())
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=72).contains(&self.lifetime_hours)
                && (1..=90).contains(&self.remember_days)
                && (1..=1000).contains(&self.invitations_per_day),
            "Invalid sender verification lifetime or quota"
        );
        if !self.enabled {
            return Ok(());
        }
        let url = reqwest::Url::parse(&self.public_origin)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/",
            "Verification requires an HTTPS origin"
        );
        if self.captcha_provider == CaptchaProvider::Turnstile {
            ensure!(
                (10..=256).contains(&self.site_key.len())
                    && self
                        .site_key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "Invalid Turnstile site key"
            );
        }
        ensure!(
            crate::config::valid_address(&self.notification_from),
            "Invalid notification sender"
        );
        ensure!(
            !self.relay_hosts.is_empty()
                && self.relay_hosts.len() <= 3
                && self
                    .relay_hosts
                    .iter()
                    .all(|h| crate::config::endpoint(h, 25)
                        .is_some_and(|(host, _)| crate::config::valid_domain(host))),
            "Configure explicit outbound notification relay hosts"
        );
        Ok(())
    }
}
pub fn eligible(
    raw: &[u8],
    sender: &str,
    scan: &crate::engine::Scan,
    cfg: &crate::config::Config,
) -> bool {
    if sender.is_empty()
        || !scan.complete
        || crate::mailing::category(scan, cfg.filter.threshold)
            != crate::mailing::Category::Legitimate
        || scan.antivirus.status == crate::antivirus::AntivirusStatus::Malware
    {
        return false;
    }
    let Some(e) = &scan.evidence else {
        return false;
    };
    if e.source != crate::evidence::Source::SmtpSession
        || !crate::evidence::eligibility::dmarc_pass(e)
        || crate::evidence::eligibility::authentication(
            e,
            crate::evidence::eligibility::AuthCheck::Spf,
        )
        .is_err()
        || e.authentication.spf != Some(crate::evidence::AuthResult::Pass)
    {
        return false;
    }
    let Ok((headers, _)) = crate::message::fields(raw) else {
        return false;
    };
    if headers
        .iter()
        .filter(|h| crate::message::name(h) == "from")
        .count()
        != 1
    {
        return false;
    }
    if headers.iter().any(|h| {
        matches!(
            crate::message::name(h).as_str(),
            "auto-submitted"
                | "list-id"
                | "list-unsubscribe"
                | "precedence"
                | "x-auto-response-suppress"
        )
    }) {
        return false;
    }
    let local = sender.split('@').next().unwrap_or("").to_ascii_lowercase();
    if [
        "no-reply",
        "noreply",
        "do-not-reply",
        "mailer-daemon",
        "postmaster",
        "bounce",
    ]
    .iter()
    .any(|v| local.contains(v))
    {
        return false;
    }
    let Some(message) = mail_parser::MessageParser::default().parse(raw) else {
        return false;
    };
    if message.content_type().is_some_and(|t| {
        t.c_type.eq_ignore_ascii_case("multipart")
            && t.c_subtype
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case("report"))
    }) {
        return false;
    }
    message.from().is_some_and(|a| {
        a.iter().count() == 1 && a.first().and_then(|a| a.address.as_deref()) == Some(sender)
    })
}
pub fn ticket(
    tx: &rusqlite::Transaction<'_>,
    settings: &Settings,
    sender: &str,
    recipient: &str,
    now: i64,
) -> Result<Option<String>> {
    tx.execute("DELETE FROM sender_verification_v1 WHERE id IN (SELECT id FROM sender_verification_v1 WHERE expires<?1 LIMIT 128)",[now-86400])?;
    tx.execute("DELETE FROM sender_verification_grants_v1 WHERE rowid IN (SELECT rowid FROM sender_verification_grants_v1 WHERE expires<?1 LIMIT 128)",[now])?;
    if tx.query_row("SELECT EXISTS(SELECT 1 FROM sender_verification_grants_v1 WHERE sender=?1 AND recipient=?2 AND expires>?3)",params![sender,recipient,now],|r|r.get::<_,bool>(0))? { return Ok(None); }
    // A ticket can hold multiple messages, but only one invitation per sender per day.
    if let Some(id) = tx.query_row("SELECT id FROM sender_verification_v1 WHERE sender=?1 AND recipient=?2 AND expires>?3 AND verified IS NULL ORDER BY created DESC LIMIT 1",params![sender,recipient,now],|r|r.get(0)).optional()? { return Ok(Some(id)); }
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM sender_verification_v1", [], |r| {
        r.get(0)
    })?;
    ensure!(count < 10_000, "Sender verification capacity exhausted");
    let id = uuid::Uuid::new_v4().to_string();
    tx.execute("INSERT INTO sender_verification_v1(id,sender,recipient,created,expires) VALUES(?1,?2,?3,?4,?5)",params![id,sender,recipient,now,now+i64::from(settings.lifetime_hours)*3600])?;
    Ok(Some(id))
}
fn signing_secret(db: &rusqlite::Connection) -> Result<Vec<u8>> {
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    db.execute(
        "INSERT OR IGNORE INTO sender_verification_key_v1 VALUES(1,?1)",
        [secret.as_slice()],
    )?;
    let secret: Vec<u8> = db.query_row(
        "SELECT key FROM sender_verification_key_v1 WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    Ok(secret)
}
fn capability(db: &rusqlite::Connection, id: &str) -> Result<String> {
    let secret = signing_secret(db)?;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret);
    Ok(format!(
        "{id}.{}",
        hex::encode(ring::hmac::sign(&key, id.as_bytes()).as_ref())
    ))
}
pub fn authorize(db: &rusqlite::Connection, token: &str, now: i64) -> Result<String> {
    let (id, signature) = token.split_once('.').context("Invalid verification link")?;
    ensure!(
        uuid::Uuid::parse_str(id).is_ok() && signature.len() == 64,
        "Invalid verification link"
    );
    let secret: Vec<u8> = db.query_row(
        "SELECT key FROM sender_verification_key_v1 WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    ring::hmac::verify(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret),
        id.as_bytes(),
        &hex::decode(signature)?,
    )
    .map_err(|_| anyhow::anyhow!("Invalid verification link"))?;
    ensure!(db.query_row("SELECT EXISTS(SELECT 1 FROM sender_verification_v1 WHERE id=?1 AND armed=1 AND verified IS NULL AND expires>?2)",params![id,now],|r|r.get::<_,bool>(0))?,"Verification link expired or already used");
    Ok(id.into())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arm {
    pub ids: Vec<String>,
}
pub async fn arm(store: &crate::store::Store, body: Arm) -> Result<BTreeMap<String, bool>> {
    ensure!(
        body.ids.len() <= 128 && body.ids.iter().all(|id| uuid::Uuid::parse_str(id).is_ok()),
        "Invalid verification batch"
    );
    store.run(move |db| {
        let tx=db.transaction()?; let mut results=BTreeMap::new();
        for id in body.ids {
            tx.execute("UPDATE sender_verification_v1 SET armed=1 WHERE id=?1 AND expires>?2",params![id,crate::now()])?;
            let verified=tx.query_row("SELECT verified IS NOT NULL AND expires>?2 FROM sender_verification_v1 WHERE id=?1",params![id,crate::now()],|r|r.get(0)).optional()?.unwrap_or(false);
            results.insert(id,verified);
        }
        tx.commit()?;Ok(results)
    }).await
}
pub fn validate_captcha(value: &serde_json::Value, hostname: &str, id: &str) -> Result<()> {
    ensure!(
        value["success"] == true
            && value["hostname"].as_str() == Some(hostname)
            && value["action"] == "sender_verification"
            && value["cdata"].as_str() == Some(id),
        "CAPTCHA verification failed"
    );
    Ok(())
}
pub async fn confirm(
    store: &crate::store::Store,
    cfg: &crate::config::Config,
    token: String,
    response: String,
) -> Result<()> {
    let settings = settings(cfg)
        .filter(|s| s.verification.enabled)
        .context("Sender verification disabled")?
        .verification
        .clone();
    ensure!(
        cfg.filter.mode != crate::config::Mode::Observe,
        "Observation mode"
    );
    ensure!(
        !response.is_empty() && response.len() <= 2048,
        "Invalid CAPTCHA token"
    );
    let token_copy = token.clone();
    let id = store
        .run(move |db| authorize(db, &token_copy, crate::now()))
        .await?;
    let local_proof = if settings.captcha_provider == CaptchaProvider::SelfHosted {
        Some(serde_json::from_str::<captcha::Answer>(&response)?)
    } else {
        let secret = cfg
            .provider_credentials
            .as_ref()
            .and_then(|s| s.get("turnstile"))
            .context("CAPTCHA credential unavailable")?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()?;
        let mut reply = client
            .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .json(&serde_json::json!({"secret":secret,"response":response}))
            .send()
            .await?;
        ensure!(reply.status().is_success(), "CAPTCHA provider unavailable");
        let mut bytes = Vec::new();
        while let Some(chunk) = reply.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 16384,
                "CAPTCHA reply too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        let origin = reqwest::Url::parse(&settings.public_origin)?;
        validate_captcha(
            &serde_json::from_slice(&bytes)?,
            origin.host_str().unwrap(),
            &id,
        )?;
        None
    };
    store.run(move |db| {
        let tx=db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let id=authorize(&tx,&token,crate::now())?;
        if let Some(proof)=&local_proof {
            let valid=captcha::consume(&tx,&id,proof,crate::now())?;
            if !valid { tx.commit()?; anyhow::bail!("CAPTCHA verification failed; request a new image"); }
        }
        tx.execute("DELETE FROM sender_verification_grants_v1 WHERE expires<=?1",[crate::now()])?;
        ensure!(tx.query_row("SELECT COUNT(*) FROM sender_verification_grants_v1",[],|r|r.get::<_,i64>(0))?<10000,"Verified sender capacity exhausted");
        tx.execute("INSERT INTO sender_verification_grants_v1 SELECT sender,recipient,?2 FROM sender_verification_v1 WHERE id=?1 ON CONFLICT(sender,recipient) DO UPDATE SET expires=excluded.expires",params![id,crate::now()+i64::from(settings.remember_days)*86400])?;
        tx.execute("UPDATE sender_verification_v1 SET verified=?2 WHERE id=?1",params![id,crate::now()])?;
        tx.commit()?;Ok(())
    }).await
}
/// Only enumerate local, durably replicated verification holds. No invitation
/// is armed while DATA/queue persistence is in flight.
async fn poll(
    store: &crate::store::Store,
    cfg: &crate::config::Config,
    cursor: &mut i64,
) -> Result<()> {
    let after = *cursor;
    let rows=store.run(move |db| {
        let mut q=db.prepare("SELECT d.id,m.scan FROM deliveries d JOIN messages m ON m.id=d.message_id JOIN delivery_policy p ON p.delivery_id=d.id LEFT JOIN ha_local h ON h.message_id=m.id WHERE d.status='quarantined' AND json_extract(m.scan,'$.action.reason')='sender_verification' AND m.raw_present=1 AND p.held_until>?1 AND ((h.message_id IS NULL AND NOT EXISTS(SELECT 1 FROM cluster_state WHERE key='ha_required' AND value='1')) OR h.acked>=h.generation) AND NOT EXISTS(SELECT 1 FROM cluster_origin o WHERE o.message_id=m.id) AND d.id>?2 ORDER BY d.id LIMIT 128")?;
        Ok(q.query_map(params![crate::now(),after],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }).await?;
    *cursor = rows.last().map_or(0, |(id, _)| *id);
    let holds: Vec<_> = rows
        .into_iter()
        .filter_map(|(delivery, raw)| {
            let scan: crate::engine::Scan = serde_json::from_str(&raw).ok()?;
            if scan.action.as_ref()?.reason != "sender_verification" {
                return None;
            }
            Some((delivery, scan.traffic?.verification_id?))
        })
        .collect();
    if holds.is_empty() {
        return Ok(());
    }
    let body = Arm {
        ids: holds.iter().map(|(_, id)| id.clone()).collect(),
    };
    let statuses = if crate::cluster::is_worker(cfg) {
        super::runtime::rpc(cfg, "arm", &body).await?
    } else {
        arm(store, body).await?
    };
    store.run(move |db| {
        let tx=db.transaction()?;
        for (delivery,id) in holds {
            if statuses.get(&id)!=Some(&true) { continue; }
            let changed=tx.execute("UPDATE deliveries SET status='pending',next_attempt=?2,error=NULL WHERE id=?1 AND status='quarantined' AND EXISTS(SELECT 1 FROM delivery_policy p WHERE p.delivery_id=?1 AND p.held_until>?2)",params![delivery,crate::now()])?;
            if changed==1 {
                tx.execute("UPDATE delivery_policy SET released_at=?2 WHERE delivery_id=?1",params![delivery,crate::now()])?;
                tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,'sender-verification','sender_verification_release',?2)",params![crate::now(),delivery.to_string()])?;
            }
        }
        tx.commit()?;Ok(())
    }).await?;
    store.notify_delivery();
    Ok(())
}
async fn notify(
    store: &crate::store::Store,
    cfg: &crate::config::Config,
    s: &Settings,
) -> Result<()> {
    let settings = s.clone();
    let job=store.run(move |db| {
        let tx=db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now=crate::now();
        let count:i64=tx.query_row("SELECT COUNT(*) FROM sender_verification_v1 WHERE notified>=?1",[now-86400],|r|r.get(0))?;
        if count>=i64::from(settings.invitations_per_day) { return Ok(None); }
        let row:Option<(String,String)>=tx.query_row("SELECT id,sender FROM sender_verification_v1 t WHERE armed=1 AND verified IS NULL AND expires>?1 AND notified IS NULL AND attempts<3 AND next_attempt<=?1 AND NOT EXISTS(SELECT 1 FROM sender_verification_v1 n WHERE n.sender=t.sender AND n.id!=t.id AND n.notified>=?2) ORDER BY created LIMIT 1",params![now,now-86400],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((id,sender))=row else {return Ok(None);};
        let token=capability(&tx,&id)?;
        // Reserve before SMTP: lost responses never cause an immediate repeat.
        tx.execute("UPDATE sender_verification_v1 SET attempts=attempts+1,next_attempt=?2,notified=?3 WHERE id=?1",params![id,now+3600,now])?;
        tx.commit()?;Ok(Some((id,sender,token)))
    }).await?;
    let Some((id, sender, token)) = job else {
        return Ok(());
    };
    let url = format!(
        "{}/verify-sender#{}",
        s.public_origin.trim_end_matches('/'),
        token
    );
    let raw = format!(
        "From: NoiseFence <{}>\r\nTo: <{}>\r\nDate: {}\r\nMessage-ID: <{}@{}>\r\nSubject: Confirm your message delivery\r\nAuto-Submitted: auto-replied\r\nX-Auto-Response-Suppress: All\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nA recipient uses sender verification. To request delivery, open:\r\n{}\r\n\r\nThis link expires in {} hours. Opening the link alone does not release mail.\r\nIf you did not send a message, ignore this request.\r\n",
        s.notification_from,
        sender,
        mail_parser::DateTime::from_timestamp(crate::now()).to_rfc822(),
        id,
        cfg.hostname,
        url,
        s.lifetime_hours
    );
    let job = crate::store::Job {
        delivery_id: 0,
        message_id: id.clone(),
        created: crate::now(),
        sender: String::new(),
        destination: sender,
        hosts: s.relay_hosts.clone(),
        attempts: 0,
        is_dsn: true,
    };
    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        crate::relay::deliver(cfg, &job, raw.as_bytes()),
    )
    .await;
    // An uncertain SMTP result may have been accepted: never resend automatically.
    tracing::info!(ticket=%id,delivered=matches!(outcome,Ok(crate::relay::Outcome::Delivered)),"Sender verification invitation attempted");
    Ok(())
}
pub async fn run(
    store: crate::store::Store,
    control: std::sync::Arc<crate::control::Controller>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut cursor = 0;
    loop {
        tokio::select! { _=stop.changed()=>{return Ok(());}, _=tokio::time::sleep(Duration::from_secs(15))=>{} }
        if let Err(error)=store.run(|db| {
            db.execute("DELETE FROM sender_captcha_v1 WHERE expires<=?1",[crate::now()])?;
            db.execute("DELETE FROM sender_verification_v1 WHERE id IN (SELECT id FROM sender_verification_v1 WHERE expires<?1 LIMIT 128)",[crate::now()-86400])?;
            db.execute("DELETE FROM sender_verification_grants_v1 WHERE rowid IN (SELECT rowid FROM sender_verification_grants_v1 WHERE expires<=?1 LIMIT 128)",[crate::now()])?;
            db.execute("DELETE FROM traffic_operations_v1 WHERE id IN (SELECT id FROM traffic_operations_v1 WHERE created<?1 LIMIT 128)",[crate::now()-3600])?;
            db.execute("DELETE FROM traffic_buckets_v1 WHERE key IN (SELECT key FROM traffic_buckets_v1 WHERE started<?1 LIMIT 128)",[crate::now()-3600])?;
            Ok(())
        }).await { tracing::warn!(%error,"Traffic maintenance unavailable"); }
        let cfg = control.snapshot().config.clone();
        let Some(s) = settings(&cfg).filter(|s| s.verification.enabled) else {
            continue;
        };
        if cfg.filter.mode == crate::config::Mode::Observe {
            continue;
        }
        if let Err(error) = poll(&store, &cfg, &mut cursor).await {
            tracing::warn!(%error,"Sender verification queue unavailable");
        }
        if !crate::cluster::is_worker(&cfg)
            && s.verification.available(&cfg)
            && let Err(error) = notify(&store, &cfg, &s.verification).await
        {
            tracing::warn!(%error,"Sender verification notification unavailable");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capabilities_require_arming_and_expire_and_cannot_be_replayed() {
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(SCHEMA).unwrap();
        let tx = db.transaction().unwrap();
        let id = ticket(
            &tx,
            &Settings::default(),
            "sender@example.org",
            "alice@example.org",
            100,
        )
        .unwrap()
        .unwrap();
        tx.commit().unwrap();
        let token = capability(&db, &id).unwrap();
        assert!(authorize(&db, &token, 100).is_err());
        db.execute(
            "UPDATE sender_verification_v1 SET armed=1 WHERE id=?1",
            [&id],
        )
        .unwrap();
        assert_eq!(authorize(&db, &token, 100).unwrap(), id);
        assert!(
            authorize(
                &db,
                &format!(
                    "{}.{}",
                    uuid::Uuid::new_v4(),
                    token.split_once('.').unwrap().1
                ),
                100
            )
            .is_err()
        );
        assert!(authorize(&db, &token, 100 + 86400).is_err());
        db.execute(
            "UPDATE sender_verification_v1 SET verified=101 WHERE id=?1",
            [id],
        )
        .unwrap();
        assert!(authorize(&db, &token, 102).is_err());
    }
    #[tokio::test]
    async fn only_accepted_verification_holds_are_armed_and_only_their_recipient_is_released() {
        let root = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(root.path()).unwrap();
        let mut cfg: crate::config::Config =
            toml::from_str(include_str!("../../config/development.toml")).unwrap();
        cfg.data_dir = root.path().into();
        let (ticket_id, unaccepted) = store
            .run(|db| {
                let tx = db.transaction()?;
                let ticket_id = ticket(
                    &tx,
                    &Settings::default(),
                    "sender@example.org",
                    "alice@example.test",
                    crate::now(),
                )?
                .unwrap();
                let other = ticket(
                    &tx,
                    &Settings::default(),
                    "sender@example.org",
                    "bob@example.test",
                    crate::now(),
                )?
                .unwrap();
                tx.commit()?;
                Ok((ticket_id, other))
            })
            .await
            .unwrap();
        let mut scan = crate::engine::Scan {
            action: Some(crate::actions::Applied {
                coverage: None,
                requested: crate::actions::Action::Quarantine,
                effective: crate::actions::Action::Quarantine,
                reason: "sender_verification".into(),
                quarantine_days: 1,
            }),
            traffic: Some(Report {
                verification_id: Some(ticket_id.clone()),
                enforced: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let message = uuid::Uuid::new_v4().to_string();
        store
            .enqueue(
                message.clone(),
                "sender@example.org".into(),
                vec![cfg.recipient("alice@example.test").unwrap()],
                scan.clone(),
                b"From: sender@example.org\r\nSubject: test\r\n\r\nTest\r\n".to_vec(),
            )
            .await
            .unwrap();
        scan.action.as_mut().unwrap().reason = "malware_priority".into();
        let security_message = uuid::Uuid::new_v4().to_string();
        store
            .enqueue(
                security_message.clone(),
                "sender@example.org".into(),
                vec![cfg.recipient("bob@example.test").unwrap()],
                scan,
                b"From: sender@example.org\r\nSubject: test\r\n\r\nTest\r\n".to_vec(),
            )
            .await
            .unwrap();
        let held_message = message.clone();
        store.run(move|db| {
            db.execute("INSERT INTO ha_local(message_id,generation,acked) VALUES(?1,2,1) ON CONFLICT(message_id) DO UPDATE SET generation=2,acked=1",[held_message])?;
            Ok(())
        }).await.unwrap();
        poll(&store, &cfg, &mut 0).await.unwrap();
        let t = ticket_id.clone();
        let m = message.clone();
        store
            .run(move |db| {
                assert_eq!(
                    db.query_row(
                        "SELECT armed FROM sender_verification_v1 WHERE id=?1",
                        [t],
                        |r| r.get::<_, i64>(0)
                    )?,
                    0
                );
                db.execute(
                    "UPDATE ha_local SET acked=generation WHERE message_id=?1",
                    [m],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        poll(&store, &cfg, &mut 0).await.unwrap();
        let a = ticket_id.clone();
        let b = unaccepted.clone();
        store
            .run(move |db| {
                assert_eq!(
                    db.query_row(
                        "SELECT armed FROM sender_verification_v1 WHERE id=?1",
                        [a],
                        |r| r.get::<_, i64>(0)
                    )?,
                    1
                );
                assert_eq!(
                    db.query_row(
                        "SELECT armed FROM sender_verification_v1 WHERE id=?1",
                        [b],
                        |r| r.get::<_, i64>(0)
                    )?,
                    0
                );
                Ok(())
            })
            .await
            .unwrap();
        store
            .run(move |db| {
                db.execute(
                    "UPDATE sender_verification_v1 SET verified=?2 WHERE id=?1",
                    params![ticket_id, crate::now()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        poll(&store, &cfg, &mut 0).await.unwrap();
        store
            .run(move |db| {
                assert_eq!(
                    db.query_row(
                        "SELECT status FROM deliveries WHERE message_id=?1",
                        [message],
                        |r| r.get::<_, String>(0)
                    )?,
                    "pending"
                );
                assert_eq!(
                    db.query_row(
                        "SELECT status FROM deliveries WHERE message_id=?1",
                        [security_message],
                        |r| r.get::<_, String>(0)
                    )?,
                    "quarantined"
                );
                Ok(())
            })
            .await
            .unwrap();
    }
}
