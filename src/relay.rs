use crate::{
    config::Config,
    engine::Engine,
    now,
    smtp::{Wire, line, reply},
    store::{Job, Store},
};
use anyhow::{Result, ensure};
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpStream,
    task::JoinSet,
};
use tokio_rustls::TlsConnector;

#[derive(Debug)]
pub enum Outcome {
    Delivered,
    Temporary(String),
    Permanent(String),
}
#[derive(Debug)]
pub struct Response {
    pub code: u16,
    pub lines: Vec<String>,
}
pub async fn response(io: &mut Wire) -> Result<Response> {
    let mut lines = Vec::new();
    let mut code = None;
    for _ in 0..100 {
        let b = line(io, 512, 300)
            .await?
            .ok_or_else(|| anyhow::anyhow!("SMTP upstream disconnected"))?;
        ensure!(
            b.len() >= 6
                && b[..3].iter().all(|c| c.is_ascii_digit())
                && (b[3] == b' ' || b[3] == b'-'),
            "invalid upstream reply"
        );
        let n = std::str::from_utf8(&b[..3])?.parse::<u16>()?;
        ensure!((200..600).contains(&n), "invalid reply code");
        ensure!(
            code.is_none() || code == Some(n),
            "inconsistent multiline reply"
        );
        code = Some(n);
        lines.push(String::from_utf8_lossy(&b[4..b.len() - 2]).into_owned());
        if b[3] == b' ' {
            return Ok(Response { code: n, lines });
        }
    }
    anyhow::bail!("too many upstream reply lines")
}
async fn command(io: &mut Wire, text: &str) -> Result<Response> {
    reply(io, text).await?;
    response(io).await
}
fn failure(r: &Response) -> Outcome {
    let reason = format!(
        "{} {}",
        r.code,
        crate::message::safe_value(&r.lines.join(" "))
    );
    if r.code >= 500 {
        Outcome::Permanent(reason)
    } else {
        Outcome::Temporary(reason)
    }
}
fn safe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && ip.octets()[0] != 0
                && ip.octets()[0] < 224
        }
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(|ip| safe_ip(IpAddr::V4(ip)))
            .unwrap_or(
                !ip.is_loopback()
                    && !ip.is_unspecified()
                    && !ip.is_multicast()
                    && (ip.segments()[0] & 0xfe00) != 0xfc00
                    && (ip.segments()[0] & 0xffc0) != 0xfe80,
            ),
    }
}
async fn deliver_host(cfg: &Config, job: &Job, raw: &[u8], route: &str) -> Result<Outcome> {
    let (host, port) = crate::config::endpoint(route, cfg.relay.port)
        .ok_or_else(|| anyhow::anyhow!("invalid upstream endpoint"))?;
    let addresses = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::lookup_host((host, port)),
    )
    .await??;
    let mut socket = None;
    for address in addresses.take(8) {
        let loopback_test = cfg.relay.allow_loopback_plaintext && address.ip().is_loopback();
        if !loopback_test && !safe_ip(address.ip()) {
            continue;
        }
        if let Ok(Ok(s)) =
            tokio::time::timeout(Duration::from_secs(15), TcpStream::connect(address)).await
        {
            socket = Some((s, loopback_test));
            break;
        }
    }
    let Some((socket, loopback_test)) = socket else {
        return Ok(Outcome::Temporary("Upstream connection unavailable".into()));
    };
    let mut io: Wire = BufReader::new(Box::new(socket));
    let greeting = response(&mut io).await?;
    if greeting.code != 220 {
        return Ok(failure(&greeting));
    }
    let mut ehlo = command(&mut io, &format!("EHLO {}\r\n", cfg.hostname)).await?;
    if ehlo.code != 250 {
        return Ok(failure(&ehlo));
    }
    if ehlo
        .lines
        .iter()
        .any(|l| l.eq_ignore_ascii_case("STARTTLS"))
    {
        let r = command(&mut io, "STARTTLS\r\n").await?;
        if r.code != 220 {
            return Ok(failure(&r));
        }
        ensure!(io.buffer().is_empty(), "upstream plaintext after STARTTLS");
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.to_string())?;
        let connection = tokio::time::timeout(
            Duration::from_secs(30),
            TlsConnector::from(Arc::new(tls)).connect(name, io.into_inner()),
        )
        .await??;
        io = BufReader::new(Box::new(connection));
        ehlo = command(&mut io, &format!("EHLO {}\r\n", cfg.hostname)).await?;
        if ehlo.code != 250 {
            return Ok(failure(&ehlo));
        }
    } else if cfg.relay.require_tls || !loopback_test {
        return Ok(Outcome::Temporary(
            "Verified TLS required but unavailable".into(),
        ));
    }
    let eightbit = raw.iter().any(|b| !b.is_ascii());
    let eightbit_supported = ehlo
        .lines
        .iter()
        .any(|l| l.eq_ignore_ascii_case("8BITMIME"));
    if eightbit && !eightbit_supported {
        return Ok(Outcome::Permanent(
            "556 5.6.3 Upstream does not support 8BITMIME".into(),
        ));
    }
    let size = ehlo
        .lines
        .iter()
        .find(|l| l.to_ascii_uppercase().starts_with("SIZE"));
    if let Some(limit) = size
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<usize>().ok())
        && limit > 0
        && raw.len() > limit
    {
        return Ok(Outcome::Permanent("552 5.3.4 Upstream size limit".into()));
    }
    let options = format!(
        "{}{}",
        if size.is_some() {
            format!(" SIZE={}", raw.len())
        } else {
            String::new()
        },
        if eightbit { " BODY=8BITMIME" } else { "" }
    );
    let r = command(
        &mut io,
        &format!("MAIL FROM:<{}>{}\r\n", job.sender, options),
    )
    .await?;
    if r.code != 250 {
        return Ok(failure(&r));
    }
    let r = command(&mut io, &format!("RCPT TO:<{}>\r\n", job.destination)).await?;
    if r.code != 250 && r.code != 251 {
        return Ok(failure(&r));
    }
    let r = command(&mut io, "DATA\r\n").await?;
    if r.code != 354 {
        return Ok(failure(&r));
    }
    let stuffed = dot_stuff(raw);
    tokio::time::timeout(Duration::from_secs(180), async {
        io.write_all(&stuffed).await?;
        io.write_all(b".\r\n").await?;
        io.flush().await
    })
    .await??;
    let r = response(&mut io).await?;
    // The final 250 is authoritative. A failed QUIT must never trigger redelivery.
    if r.code == 250 {
        let _ = tokio::time::timeout(Duration::from_secs(2), reply(&mut io, "QUIT\r\n")).await;
        Ok(Outcome::Delivered)
    } else {
        Ok(failure(&r))
    }
}
pub fn dot_stuff(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 100);
    let mut start = true;
    for b in raw {
        if start && *b == b'.' {
            out.push(b'.');
        }
        out.push(*b);
        start = *b == b'\n';
    }
    if !raw.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out
}
pub async fn deliver(cfg: &Config, job: &Job, raw: &[u8]) -> Outcome {
    let mut last = Outcome::Temporary("No upstream route".into());
    for host in &job.hosts {
        match tokio::time::timeout(Duration::from_secs(600), deliver_host(cfg, job, raw, host))
            .await
        {
            Ok(Ok(Outcome::Delivered)) => return Outcome::Delivered,
            Ok(Ok(o @ Outcome::Permanent(_))) => return o,
            Ok(Ok(o)) => last = o,
            _ => last = Outcome::Temporary("Upstream network, protocol or TLS failure".into()),
        }
    }
    last
}
pub fn retry_delay(attempt: u32) -> i64 {
    let base = (1800i64.saturating_mul(1i64 << attempt.saturating_sub(1).min(3))).min(14400);
    base + rand::random::<u16>() as i64 % 60
}
async fn run_job(config: Arc<Config>, store: Store, job: Job) -> Result<()> {
    if now() - job.created >= config.relay.max_queue_age_seconds {
        store
            .finish(&job, "failed", "5.4.7 Delivery time expired", 0)
            .await?;
        return Ok(());
    }
    let raw = tokio::fs::read(store.raw_path(&job.message_id)).await?;
    match deliver(&config, &job, &raw).await {
        Outcome::Delivered => {
            store.finish(&job, "delivered", "", 0).await?;
            tracing::info!(id=%job.message_id,delivery=job.delivery_id,"message delivered");
        }
        Outcome::Permanent(reason) => {
            store.finish(&job, "failed", &reason, 0).await?;
            tracing::warn!(id=%job.message_id,delivery=job.delivery_id,"permanent upstream rejection");
        }
        Outcome::Temporary(reason) => {
            store
                .finish(&job, "pending", &reason, now() + retry_delay(job.attempts))
                .await?;
            tracing::warn!(id=%job.message_id,delivery=job.delivery_id,"delivery deferred");
        }
    }
    Ok(())
}
async fn notifications(config: &Config, store: &Store, engine: &Engine) -> Result<()> {
    for job in store.failed().await? {
        if job.is_dsn || job.sender.is_empty() {
            store
                .finish(&job, "notified", "Null sender: no DSN generated", 0)
                .await?;
            continue;
        }
        let (_, domain) = job
            .sender
            .rsplit_once('@')
            .ok_or_else(|| anyhow::anyhow!("invalid persisted reverse path"))?;
        let hosts = if let Some(r) = config.recipient(&job.sender) {
            r.hosts
        } else {
            match tokio::time::timeout(
                Duration::from_secs(5),
                engine.authenticator.mx_lookup(
                    domain,
                    None::<
                        &mail_auth::common::cache::NoCache<
                            Box<str>,
                            mail_auth::RecordSet<mail_auth::MX>,
                        >,
                    >,
                ),
            )
            .await
            {
                Ok(Ok(records)) => {
                    let mut r = records.rrset.to_vec();
                    r.sort_by_key(|m| m.preference);
                    let hosts: Vec<String> = r
                        .into_iter()
                        .flat_map(|m| m.exchanges)
                        .filter(|h| h.as_ref() != ".")
                        .map(|h| h.to_string())
                        .collect();
                    if hosts.is_empty() {
                        store
                            .finish(&job, "notified", "Reverse path has Null MX", 0)
                            .await?;
                        continue;
                    }
                    hosts
                }
                Ok(Err(mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(code))))
                    if code == mail_auth::hickory_resolver::proto::op::ResponseCode::NoError
                        || code
                            == mail_auth::hickory_resolver::proto::op::ResponseCode::NXDomain =>
                {
                    vec![domain.to_string()]
                }
                _ => continue,
            }
        };
        let boundary = format!("dsn_{}", job.delivery_id);
        let raw = format!(
            "From: Mail Delivery System <{}>\r\nTo: <{}>\r\nDate: {}\r\nMessage-ID: <dsn-{}@{}>\r\nSubject: Delivery failure\r\nAuto-Submitted: auto-replied\r\nMIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=delivery-status;\r\n boundary=\"{}\"\r\n\r\n--{}\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nDelivery to {} failed. Contact postmaster with queue ID {}.\r\n\r\n--{}\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; {}\r\n\r\nFinal-Recipient: rfc822; {}\r\nAction: failed\r\nStatus: 5.0.0\r\n\r\n--{}--\r\n",
            config.relay.postmaster,
            job.sender,
            mail_parser::DateTime::from_timestamp(now()).to_rfc822(),
            job.delivery_id,
            config.hostname,
            boundary,
            boundary,
            job.destination,
            job.message_id,
            boundary,
            config.hostname,
            job.destination,
            boundary
        );
        store.enqueue_dsn(job, raw.into_bytes(), hosts).await?;
    }
    Ok(())
}
pub async fn worker(
    config: Arc<Config>,
    store: Store,
    engine: Arc<Engine>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    worker_controlled(config, store, engine, None, shutdown).await
}
pub async fn worker_controlled(
    mut config: Arc<Config>,
    store: Store,
    mut engine: Arc<Engine>,
    control: Option<Arc<crate::control::Controller>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut jobs = JoinSet::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut housekeeping = 0;
    loop {
        if *shutdown.borrow() {
            break;
        }
        if let Some(control) = &control {
            let snapshot = control.snapshot();
            config = snapshot.config.clone();
            engine = snapshot.engine.clone();
        }
        // Refill on completion or enqueue, not just on the retry poll. The poll
        // still discovers due retries and changes made by another Store instance.
        while jobs.len() < config.relay.workers {
            let Some(job) = store.claim().await? else {
                break;
            };
            jobs.spawn(run_job(config.clone(), store.clone(), job));
        }
        tokio::select! {
            _=shutdown.changed()=>break,
            _=store.wait_for_delivery()=>{},
            Some(result)=jobs.join_next(),if !jobs.is_empty()=>{match result{Ok(Ok(()))=>{},_=>{tracing::error!("delivery worker failed; stopping to recover durable claims on restart");anyhow::bail!("delivery worker failure");}}},
            _=tick.tick()=>{
                housekeeping+=1;if housekeeping%30==0 {notifications(&config,&store,&engine).await?;store.cleanup().await?;}
            }
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(30), async {
        while jobs.join_next().await.is_some() {}
    })
    .await;
    jobs.abort_all();
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dot_transparency() {
        assert_eq!(dot_stuff(b".x\r\n..x\r\n"), b"..x\r\n...x\r\n");
    }
    #[test]
    fn private_dns_routes_blocked() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
        ] {
            assert!(!safe_ip(ip.parse().unwrap()));
        }
        assert!(safe_ip("185.70.40.101".parse().unwrap()));
    }
}
