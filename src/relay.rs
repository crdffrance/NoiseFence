use crate::{
    config::Config,
    delivery_log::{self, Attempt, Event},
    engine::Engine,
    now,
    smtp::{Wire, line, reply},
    store::{Job, Store},
};
use anyhow::{Context, Result, ensure};
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpStream,
    task::JoinSet,
    time::Instant,
};
use tokio_rustls::TlsConnector;

#[derive(Debug)]
pub enum Outcome {
    Delivered,
    Temporary(String),
    Permanent(String),
}

#[derive(Debug)]
pub struct DeliveryReport {
    pub outcome: Outcome,
    pub attempts: Vec<Attempt>,
}

/// Owned by the caller of the timed future, so cancellation cannot discard
/// completed events, a partial multiline reply, or the authoritative final 250.
struct Trace {
    attempt: Attempt,
    clock: Instant,
    active: Option<Event>,
    redactor: Option<regex::Regex>,
    message_id: String,
    delivery_id: i64,
    attempt_id: uuid::Uuid,
    accepted: bool,
}

impl Trace {
    fn new(job: &Job, route: &str) -> Self {
        let patterns: Vec<_> = [&job.sender, &job.destination]
            .into_iter()
            .filter(|address| !address.is_empty())
            .map(|address| regex::escape(address))
            .collect();
        let redactor = (!patterns.is_empty()).then(|| {
            regex::RegexBuilder::new(&patterns.join("|"))
                .case_insensitive(true)
                .build()
                .expect("escaped envelope addresses form a valid regex")
        });
        let mut trace = Self {
            attempt: Attempt {
                route: String::new(),
                peer: None,
                started: now(),
                elapsed_ms: 0,
                outcome: "temporary".into(),
                events: Vec::new(),
                truncated: false,
            },
            clock: Instant::now(),
            active: None,
            redactor,
            message_id: delivery_log::sanitize_text(&job.message_id),
            delivery_id: job.delivery_id,
            attempt_id: uuid::Uuid::new_v4(),
            accepted: false,
        };
        trace.attempt.route = trace.clean(route);
        trace
    }

    fn elapsed_ms(&self) -> u64 {
        self.clock.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    fn clean(&mut self, value: &str) -> String {
        // Shared privacy processing runs before every log/truncation boundary;
        // exact envelope matching supplements redaction of OTHER mailboxes too.
        // Never pass DATA here: arbitrary private phrases are not identifiable.
        let (safe, cut) = delivery_log::sanitize_with(
            value,
            delivery_log::MAX_TEXT_BYTES,
            self.redactor.as_ref(),
        );
        self.attempt.truncated |= cut;
        safe
    }

    fn begin(&mut self, phase: &str) {
        self.flush();
        self.active = Some(Event {
            phase: phase.into(),
            elapsed_ms: self.elapsed_ms(),
            code: None,
            enhanced_code: None,
            response: None,
            detail: None,
        });
    }

    fn detail(&mut self, detail: &str) {
        let safe = self.clean(detail);
        let elapsed = self.elapsed_ms();
        if let Some(event) = &mut self.active {
            event.detail = Some(safe);
            event.elapsed_ms = elapsed;
        }
    }

    fn response_line(&mut self, line: &[u8]) {
        let text = String::from_utf8_lossy(line.strip_suffix(b"\r\n").unwrap_or(line));
        let safe = self.clean(&text);
        let elapsed = self.elapsed_ms();
        let Some(event) = &mut self.active else {
            return;
        };
        if line.len() >= 4 && line[..3].iter().all(u8::is_ascii_digit) {
            let code = std::str::from_utf8(&line[..3])
                .unwrap()
                .parse::<u16>()
                .unwrap();
            if (200..600).contains(&code) {
                event.code.get_or_insert(code);
                if event.enhanced_code.is_none() {
                    event.enhanced_code = enhanced_code(&String::from_utf8_lossy(&line[4..]));
                }
            }
        }
        let combined = match &event.response {
            Some(previous) => format!("{previous} | {safe}"),
            None => safe,
        };
        let (safe, cut) = delivery_log::sanitize(&combined, delivery_log::MAX_TEXT_BYTES);
        self.attempt.truncated |= cut;
        event.response = Some(safe);
        event.elapsed_ms = elapsed;
    }

    fn flush(&mut self) {
        let Some(event) = self.active.take() else {
            return;
        };
        tracing::info!(
            message_id = %self.message_id,
            delivery_id = self.delivery_id,
            attempt_id = %self.attempt_id,
            route = %self.attempt.route,
            peer = ?self.attempt.peer,
            phase = %event.phase,
            elapsed_ms = event.elapsed_ms,
            code = ?event.code,
            enhanced_code = ?event.enhanced_code,
            response = ?event.response,
            detail = ?event.detail,
            "outbound SMTP event"
        );
        if self.attempt.events.len() == delivery_log::MAX_EVENTS {
            self.attempt.events.pop();
            self.attempt.truncated = true;
        }
        self.attempt.events.push(event);
    }

    fn finish(mut self, outcome: &Outcome) -> Attempt {
        self.flush();
        self.attempt.elapsed_ms = self.elapsed_ms();
        self.attempt.outcome = match outcome {
            Outcome::Delivered => "delivered",
            Outcome::Temporary(_) => "temporary",
            Outcome::Permanent(_) => "permanent",
        }
        .into();
        self.attempt.sanitize();
        self.attempt
    }
}

fn enhanced_code(text: &str) -> Option<String> {
    let token = text.split_whitespace().next()?;
    let parts: Vec<_> = token.split('.').collect();
    (parts.len() == 3
        && matches!(parts[0], "2" | "4" | "5")
        && parts[1..]
            .iter()
            .all(|part| (1..=3).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit())))
    .then(|| token.to_string())
}

#[derive(Debug)]
pub struct Response {
    pub code: u16,
    pub lines: Vec<String>,
}
pub async fn response(io: &mut Wire) -> Result<Response> {
    read_response(io, None).await
}

async fn read_response(io: &mut Wire, mut trace: Option<&mut Trace>) -> Result<Response> {
    let mut lines = Vec::new();
    let mut code = None;
    for _ in 0..100 {
        let b = line(io, 512, 300)
            .await?
            .ok_or_else(|| anyhow::anyhow!("SMTP upstream disconnected"))?;
        if let Some(trace) = trace.as_deref_mut() {
            trace.response_line(&b);
        }
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
async fn command(io: &mut Wire, text: &str, phase: &str, trace: &mut Trace) -> Result<Response> {
    trace.begin(phase);
    // The command contains envelope arguments; only the remote reply is captured.
    reply(io, text).await.context("SMTP command write failed")?;
    read_response(io, Some(trace)).await
}
fn failure(r: &Response) -> Outcome {
    // Sanitize/redact the complete text at the trace boundary, before truncation.
    let reason = format!("{} {}", r.code, r.lines.join(" "));
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
async fn deliver_host(
    cfg: &Config,
    job: &Job,
    raw: &[u8],
    route: &str,
    trace: &mut Trace,
) -> Result<Outcome> {
    trace.begin("dns");
    let (host, port) = crate::config::endpoint(route, cfg.relay.port)
        .ok_or_else(|| anyhow::anyhow!("invalid upstream endpoint"))?;
    let addresses = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .context("Upstream DNS lookup timed out after 10 seconds")?
    .context("Upstream DNS lookup failed")?;
    let addresses: Vec<_> = addresses.take(8).collect();
    trace.detail(&format!(
        "Resolved addresses: {}",
        addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let mut socket = None;
    for address in addresses {
        trace.begin("connect");
        trace.attempt.peer = Some(address.ip().to_string());
        trace.detail(&format!("Connecting to {address}"));
        let loopback_test = cfg.relay.allow_loopback_plaintext && address.ip().is_loopback();
        if !loopback_test && !safe_ip(address.ip()) {
            trace.detail(&format!("Address {address} blocked by relay IP policy"));
            continue;
        }
        match tokio::time::timeout(Duration::from_secs(15), TcpStream::connect(address)).await {
            Ok(Ok(s)) => {
                trace.detail(&format!("Connected to {address}"));
                socket = Some((s, loopback_test));
                break;
            }
            Ok(Err(error)) => trace.detail(&format!("Connect to {address} failed: {error}")),
            Err(error) => trace.detail(&format!(
                "Connect to {address} timed out after 15 seconds: {error}"
            )),
        }
    }
    let Some((socket, loopback_test)) = socket else {
        return Ok(Outcome::Temporary("Upstream connection unavailable".into()));
    };
    let mut io: Wire = BufReader::new(Box::new(socket));
    trace.begin("greeting");
    let greeting = read_response(&mut io, Some(trace)).await?;
    if greeting.code != 220 {
        return Ok(failure(&greeting));
    }
    let mut ehlo = command(
        &mut io,
        &format!("EHLO {}\r\n", cfg.hostname),
        "ehlo",
        trace,
    )
    .await?;
    if ehlo.code != 250 {
        return Ok(failure(&ehlo));
    }
    if ehlo
        .lines
        .iter()
        .any(|l| l.eq_ignore_ascii_case("STARTTLS"))
    {
        let r = command(&mut io, "STARTTLS\r\n", "starttls", trace).await?;
        if r.code != 220 {
            return Ok(failure(&r));
        }
        trace.begin("tls");
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
        .await
        .context("Upstream TLS handshake timed out after 30 seconds")?
        .context("Upstream TLS handshake/certificate verification failed")?;
        let tls = connection.get_ref().1;
        trace.detail(&format!(
            "Verified TLS; protocol={:?}; cipher={:?}",
            tls.protocol_version(),
            tls.negotiated_cipher_suite().map(|suite| suite.suite())
        ));
        io = BufReader::new(Box::new(connection));
        ehlo = command(
            &mut io,
            &format!("EHLO {}\r\n", cfg.hostname),
            "ehlo_tls",
            trace,
        )
        .await?;
        if ehlo.code != 250 {
            return Ok(failure(&ehlo));
        }
    } else if cfg.relay.require_tls || !loopback_test {
        trace.begin("tls");
        trace.detail("Verified TLS required but unavailable: upstream did not advertise STARTTLS");
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
        trace.detail("Upstream does not support 8BITMIME");
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
        trace.detail("Message exceeds upstream SIZE limit");
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
        "mail_from",
        trace,
    )
    .await?;
    if r.code != 250 {
        return Ok(failure(&r));
    }
    let r = command(
        &mut io,
        &format!("RCPT TO:<{}>\r\n", job.destination),
        "rcpt_to",
        trace,
    )
    .await?;
    if r.code != 250 && r.code != 251 {
        return Ok(failure(&r));
    }
    let r = command(&mut io, "DATA\r\n", "data", trace).await?;
    if r.code != 354 {
        return Ok(failure(&r));
    }
    let stuffed = dot_stuff(raw);
    trace.detail("Transferring message data");
    tokio::time::timeout(Duration::from_secs(180), async {
        io.write_all(&stuffed).await?;
        io.write_all(b".\r\n").await?;
        io.flush().await
    })
    .await
    .context("SMTP DATA write timed out after 180 seconds")?
    .context("SMTP DATA write failed")?;
    trace.detail("Message data transferred");
    trace.begin("data_result");
    let r = read_response(&mut io, Some(trace)).await?;
    // The final 250 is authoritative. A failed QUIT must never trigger redelivery.
    if r.code == 250 {
        trace.accepted = true;
        trace.begin("quit");
        match tokio::time::timeout(Duration::from_secs(2), reply(&mut io, "QUIT\r\n")).await {
            Ok(Ok(())) => trace.detail("QUIT sent after acceptance"),
            Ok(Err(error)) => {
                trace.detail(&format!("QUIT write failed after acceptance: {error:#}"))
            }
            Err(error) => trace.detail(&format!("QUIT timed out after acceptance: {error}")),
        }
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
    deliver_traced(cfg, job, raw).await.outcome
}

pub async fn deliver_traced(cfg: &Config, job: &Job, raw: &[u8]) -> DeliveryReport {
    deliver_with_timeout(cfg, job, raw, Duration::from_secs(600)).await
}

async fn deliver_with_timeout(
    cfg: &Config,
    job: &Job,
    raw: &[u8],
    timeout: Duration,
) -> DeliveryReport {
    let mut last = Outcome::Temporary("No upstream route".into());
    let mut attempts = Vec::new();
    for host in &job.hosts {
        let mut trace = Trace::new(job, host);
        let result =
            tokio::time::timeout(timeout, deliver_host(cfg, job, raw, host, &mut trace)).await;
        last = outcome_after_attempt(&mut trace, result);
        // The saved last error is also bounded and cannot expose echoed envelopes.
        if let Outcome::Temporary(reason) | Outcome::Permanent(reason) = &mut last {
            *reason = trace.clean(reason);
        }
        attempts.push(trace.finish(&last));
        if matches!(last, Outcome::Delivered | Outcome::Permanent(_)) {
            break;
        }
    }
    DeliveryReport {
        outcome: last,
        attempts,
    }
}

fn outcome_after_attempt(
    trace: &mut Trace,
    result: Result<Result<Outcome>, tokio::time::error::Elapsed>,
) -> Outcome {
    match result {
        Ok(Ok(outcome)) => outcome,
        error => {
            let phase = trace
                .active
                .as_ref()
                .map(|e| e.phase.as_str())
                .unwrap_or("dns");
            let reason = match error {
                Ok(Err(error)) => format!("Upstream {phase} failed: {error:#}"),
                Err(error) => format!("Upstream {phase} attempt timed out: {error}"),
                Ok(Ok(_)) => unreachable!(),
            };
            trace.detail(&reason);
            if trace.accepted {
                Outcome::Delivered
            } else {
                Outcome::Temporary(trace.clean(&reason))
            }
        }
    }
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
    let report = deliver_traced(&config, &job, &raw).await;
    match report.outcome {
        Outcome::Delivered => {
            store
                .finish_with_attempts(&job, "delivered", "", 0, &report.attempts)
                .await?;
            tracing::info!(id=%job.message_id,delivery=job.delivery_id,"message delivered");
        }
        Outcome::Permanent(reason) => {
            store
                .finish_with_attempts(&job, "failed", &reason, 0, &report.attempts)
                .await?;
            tracing::warn!(id=%job.message_id,delivery=job.delivery_id,"permanent upstream rejection");
        }
        Outcome::Temporary(reason) => {
            store
                .finish_with_attempts(
                    &job,
                    "pending",
                    &reason,
                    now() + retry_delay(job.attempts),
                    &report.attempts,
                )
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

    fn trace_job() -> Job {
        Job {
            delivery_id: 7,
            message_id: "timeout-test".into(),
            created: now(),
            sender: "sender@example.org".into(),
            destination: "recipient@example.test".into(),
            hosts: vec![],
            attempts: 1,
            is_dsn: false,
        }
    }

    #[tokio::test]
    async fn outer_timeout_keeps_started_partial_replies_and_acknowledgment_phase() {
        let cfg: Config = toml::from_str(include_str!("../config/development.toml")).unwrap();
        for phase in ["ehlo", "data_result"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut job = trace_job();
            job.hosts = vec![listener.local_addr().unwrap().to_string()];
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut io: Wire = BufReader::new(Box::new(socket));
                reply(&mut io, "220 Ready\r\n").await.unwrap();
                loop {
                    let command = line(&mut io, 1024, 2).await.unwrap().unwrap();
                    if phase == "ehlo" {
                        reply(&mut io, "250-partial EHLO\r\n").await.unwrap();
                        break;
                    }
                    if command == b"DATA\r\n" {
                        reply(&mut io, "354 Send\r\n").await.unwrap();
                        while line(&mut io, 1024, 2).await.unwrap().unwrap() != b".\r\n" {}
                        reply(&mut io, "451-4.3.0 partial acknowledgment\r\n")
                            .await
                            .unwrap();
                        break;
                    }
                    reply(&mut io, "250 OK\r\n").await.unwrap();
                }
                // Keep the socket open so the outer attempt deadline cancels
                // response parsing with a partially accumulated multiline reply.
                std::future::pending::<()>().await;
                drop(io);
            });
            let started = now();
            let report = deliver_with_timeout(
                &cfg,
                &job,
                b"Subject: private\r\n\r\nprivate body\r\n",
                Duration::from_millis(500),
            )
            .await;
            server.abort();
            let Outcome::Temporary(reason) = report.outcome else {
                panic!("timeout must defer");
            };
            assert!(reason.contains(phase));
            assert!(reason.contains("timed out"));
            let attempt = &report.attempts[0];
            assert!((started..=now()).contains(&attempt.started));
            assert!(attempt.elapsed_ms >= 500);
            let event = attempt.events.last().unwrap();
            assert_eq!(event.phase, phase);
            assert!(event.response.as_ref().unwrap().contains("partial"));
            assert!(event.detail.as_ref().unwrap().contains("timed out"));
            if phase == "data_result" {
                assert_eq!(event.code, Some(451));
                assert_eq!(event.enhanced_code.as_deref(), Some("4.3.0"));
                let data = attempt.events.iter().find(|e| e.phase == "data").unwrap();
                assert_eq!(data.code, Some(354));
                assert_eq!(data.detail.as_deref(), Some("Message data transferred"));
            }
            assert!(!serde_json::to_string(attempt).unwrap().contains("private"));
        }
    }

    #[tokio::test]
    async fn acceptance_survives_outer_timeout_during_quit() {
        let mut trace = Trace::new(&trace_job(), "mx.example.test");
        trace.begin("data_result");
        trace.response_line(b"250 2.0.0 accepted\r\n");
        trace.accepted = true;
        trace.begin("quit");
        let result = tokio::time::timeout(
            Duration::from_millis(1),
            std::future::pending::<Result<Outcome>>(),
        )
        .await;
        let outcome = outcome_after_attempt(&mut trace, result);
        assert!(matches!(outcome, Outcome::Delivered));
        let attempt = trace.finish(&outcome);
        assert_eq!(attempt.outcome, "delivered");
        assert_eq!(attempt.events[0].code, Some(250));
        assert!(
            attempt.events[1]
                .detail
                .as_ref()
                .unwrap()
                .contains("quit attempt timed out")
        );
    }

    #[test]
    fn trace_caps_events_and_keeps_the_last_result() {
        let mut trace = Trace::new(&trace_job(), "mx.example.test");
        for _ in 0..40 {
            trace.begin("connect");
            trace.detail("connection failed");
        }
        trace.begin("data_result");
        trace.response_line(b"250 2.0.0 accepted\r\n");
        let attempt = trace.finish(&Outcome::Delivered);
        assert!(attempt.truncated);
        assert_eq!(attempt.events.len(), delivery_log::MAX_EVENTS);
        assert_eq!(attempt.events.last().unwrap().code, Some(250));
    }

    #[test]
    fn data_write_failure_keeps_transport_error_without_envelope_or_body() {
        let mut trace = Trace::new(&trace_job(), "mx.example.test");
        trace.begin("data");
        trace.response_line(b"354 Send\r\n");
        let error = anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "broken pipe",
        ))
        .context("SMTP DATA write failed");
        let outcome = outcome_after_attempt(&mut trace, Ok(Err(error)));
        let Outcome::Temporary(reason) = &outcome else {
            panic!("write failure must defer");
        };
        assert_eq!(
            reason,
            "Upstream data failed: SMTP DATA write failed: broken pipe"
        );
        let attempt = trace.finish(&outcome);
        assert_eq!(attempt.events[0].phase, "data");
        assert_eq!(attempt.events[0].code, Some(354));
    }

    #[test]
    fn enhanced_status_must_be_a_status_token() {
        assert_eq!(enhanced_code("5.7.1 denied"), Some("5.7.1".into()));
        for invalid in [
            "250 OK",
            "5.7777.1 invalid",
            "3.0.0 invalid",
            "5.1 bad",
            "5.1.1.1 bad",
        ] {
            assert!(enhanced_code(invalid).is_none());
        }
    }

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
