use crate::{
    config::{Config, Recipient, valid_address},
    engine::Engine,
    message,
    store::{Store, available_bytes},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;

pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}
pub type Wire = BufReader<Box<dyn Transport>>;
#[derive(Clone)]
pub struct State {
    pub config: Arc<Config>,
    pub store: Store,
    pub engine: Arc<Engine>,
    pub processing: Arc<Semaphore>,
}
pub fn tls_acceptor(config: &Config) -> Result<Option<TlsAcceptor>> {
    let Some(path) = &config.smtp.tls_cert else {
        return Ok(None);
    };
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(path)?))
        .collect::<std::io::Result<Vec<_>>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(
        config.smtp.tls_key.as_ref().unwrap(),
    )?))?
    .context("missing TLS private key")?;
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Some(TlsAcceptor::from(Arc::new(tls))))
}
/// Bounded allocation and strict CRLF termination. Used for commands, DATA and replies.
pub async fn line<R: AsyncBufRead + Unpin>(
    io: &mut R,
    limit: usize,
    seconds: u64,
) -> Result<Option<Vec<u8>>> {
    tokio::time::timeout(Duration::from_secs(seconds), async {
        let mut out = Vec::new();
        loop {
            let buf = io.fill_buf().await?;
            if buf.is_empty() {
                ensure!(out.is_empty(), "truncated SMTP line");
                return Ok(None);
            }
            let count = buf
                .iter()
                .position(|c| *c == b'\n')
                .map(|i| i + 1)
                .unwrap_or(buf.len());
            ensure!(out.len() + count <= limit, "SMTP line too long");
            let end = buf[count - 1] == b'\n';
            out.extend_from_slice(&buf[..count]);
            io.consume(count);
            if end {
                ensure!(
                    out.ends_with(b"\r\n")
                        && !out[..out.len() - 2]
                            .iter()
                            .any(|b| *b == b'\r' || *b == b'\n' || *b == 0),
                    "invalid SMTP newline or NUL"
                );
                return Ok(Some(out));
            }
        }
    })
    .await
    .context("SMTP read timeout")?
}
pub async fn reply(io: &mut Wire, text: &str) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(60), async {
        io.write_all(text.as_bytes()).await?;
        io.flush().await
    })
    .await??;
    Ok(())
}
struct Incoming(PathBuf);
impl Drop for Incoming {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
struct PeerGuard {
    ip: IpAddr,
    peers: Arc<Mutex<HashMap<IpAddr, usize>>>,
}
impl Drop for PeerGuard {
    fn drop(&mut self) {
        let mut peers = self.peers.lock().unwrap();
        if let Some(n) = peers.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                peers.remove(&self.ip);
            }
        }
    }
}
pub async fn serve(
    listener: TcpListener,
    state: State,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let tls = tls_acceptor(&state.config)?;
    let slots = Arc::new(Semaphore::new(state.config.smtp.max_connections));
    let peers = Arc::new(Mutex::new(HashMap::<IpAddr, usize>::new()));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _=shutdown.changed()=>break,
            Some(result)=tasks.join_next(), if !tasks.is_empty()=>{if let Err(e)=result {tracing::error!(error=%e,"SMTP session task failed");}},
            accepted=listener.accept()=>{
                let (mut socket,peer)=accepted?;
                let permit=slots.clone().try_acquire_owned();
                let allowed={let mut counts=peers.lock().unwrap();let n=counts.get(&peer.ip()).copied().unwrap_or(0);if n>=state.config.smtp.max_connections_per_ip || permit.is_err(){false}else{counts.insert(peer.ip(),n+1);true}};
                if !allowed {let _=tokio::time::timeout(Duration::from_secs(1),socket.write_all(b"421 4.3.2 Server busy\r\n")).await;continue;}
                let state=state.clone();let tls=tls.clone();let guard=PeerGuard{ip:peer.ip(),peers:peers.clone()};
                tasks.spawn(async move{let _permit=permit.unwrap();let _guard=guard;if let Err(error)=session(socket,peer,state,tls).await{tracing::debug!(error=%error,"SMTP session ended");}});
            }
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(30), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();
    Ok(())
}
pub fn parse_path<'a>(arg: &'a str, prefix: &str, allow_empty: bool) -> Result<(&'a str, &'a str)> {
    ensure!(
        arg.get(..prefix.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(prefix)),
        "invalid path command"
    );
    let path = arg[prefix.len()..].trim_start();
    ensure!(path.starts_with('<'), "expected angle brackets");
    let mut quoted = false;
    let mut escaped = false;
    let end = path
        .bytes()
        .enumerate()
        .skip(1)
        .find_map(|(i, b)| {
            if escaped {
                escaped = false;
            } else if quoted && b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = !quoted;
            } else if b == b'>' && !quoted {
                return Some(i);
            }
            None
        })
        .context("unterminated path")?;
    let address = &path[1..end];
    ensure!(
        (allow_empty && address.is_empty())
            || valid_address(address)
            || (prefix.eq_ignore_ascii_case("TO:") && address.eq_ignore_ascii_case("postmaster")),
        "invalid or unsupported address"
    );
    let suffix = &path[end + 1..];
    ensure!(
        suffix.is_empty() || suffix.starts_with(' '),
        "invalid path parameters"
    );
    Ok((address, suffix.trim()))
}
async fn session(
    socket: TcpStream,
    peer: SocketAddr,
    state: State,
    tls: Option<TlsAcceptor>,
) -> Result<()> {
    let cfg = &state.config;
    let mut io: Wire = BufReader::new(Box::new(socket));
    reply(&mut io, &format!("220 {} ESMTP\r\n", cfg.hostname)).await?;
    let mut helo = String::new();
    let mut extended = false;
    let mut encrypted = false;
    let mut from: Option<String> = None;
    let mut recipients: Vec<Recipient> = Vec::new();
    let mut errors = 0;
    for _ in 0..1000 {
        let bytes = match line(&mut io, 512, cfg.smtp.command_timeout_seconds).await {
            Ok(Some(b)) => b,
            Ok(None) => break,
            Err(e) => {
                let _ = reply(&mut io, "500 5.5.2 Invalid command framing\r\n").await;
                return Err(e);
            }
        };
        let command = match std::str::from_utf8(&bytes[..bytes.len() - 2]) {
            Ok(c) if c.is_ascii() => c,
            _ => {
                reply(&mut io, "500 5.5.2 ASCII command required\r\n").await?;
                break;
            }
        };
        let (verb, arg) = command.split_once(' ').unwrap_or((command, ""));
        match verb.to_ascii_uppercase().as_str() {
            "EHLO" | "HELO" => {
                if arg.is_empty() || arg.len() > 255 || arg.bytes().any(|b| b <= 32 || b == 127) {
                    reply(&mut io, "501 5.5.2 Invalid greeting\r\n").await?;
                    continue;
                }
                helo = arg.into();
                from = None;
                recipients.clear();
                extended = verb.eq_ignore_ascii_case("EHLO");
                if extended {
                    let starttls = if tls.is_some() && !encrypted {
                        "250-STARTTLS\r\n"
                    } else {
                        ""
                    };
                    reply(
                        &mut io,
                        &format!(
                            "250-{}\r\n250-SIZE {}\r\n250-8BITMIME\r\n{}250 PIPELINING\r\n",
                            cfg.hostname, cfg.smtp.max_message_bytes, starttls
                        ),
                    )
                    .await?;
                } else {
                    reply(&mut io, &format!("250 {}\r\n", cfg.hostname)).await?;
                }
            }
            "STARTTLS" => {
                if !arg.is_empty() {
                    reply(&mut io, "501 5.5.2 STARTTLS takes no parameters\r\n").await?;
                    continue;
                }
                let Some(acceptor) = tls.as_ref().filter(|_| !encrypted && extended) else {
                    reply(&mut io, "503 5.5.1 STARTTLS unavailable\r\n").await?;
                    continue;
                };
                ensure!(
                    io.buffer().is_empty(),
                    "plaintext pipelined across STARTTLS boundary"
                );
                reply(&mut io, "220 2.0.0 Ready to start TLS\r\n").await?;
                let stream =
                    tokio::time::timeout(Duration::from_secs(30), acceptor.accept(io.into_inner()))
                        .await??;
                io = BufReader::new(Box::new(stream));
                encrypted = true;
                helo.clear();
                extended = false;
                from = None;
                recipients.clear();
            }
            "MAIL" => {
                if helo.is_empty() || from.is_some() {
                    reply(&mut io, "503 5.5.1 Send greeting or RSET first\r\n").await?;
                    continue;
                }
                let (address, options) = match parse_path(arg, "FROM:", true) {
                    Ok(v) => v,
                    Err(_) => {
                        reply(&mut io, "501 5.5.2 Invalid reverse path\r\n").await?;
                        continue;
                    }
                };
                let mut bad = None;
                let mut seen = std::collections::HashSet::new();
                for option in options.split_whitespace() {
                    let upper = option.to_ascii_uppercase();
                    let key = upper.split('=').next().unwrap();
                    if !seen.insert(key.to_string()) {
                        bad = Some("501 5.5.4 Duplicate parameter\r\n");
                    } else if !extended {
                        bad = Some("555 5.5.4 ESMTP required\r\n");
                    } else if let Some(size) = upper.strip_prefix("SIZE=") {
                        match size.parse::<usize>() {
                            Ok(n) if n <= cfg.smtp.max_message_bytes => {}
                            Ok(_) => bad = Some("552 5.3.4 Message too large\r\n"),
                            Err(_) => bad = Some("501 5.5.4 Invalid SIZE\r\n"),
                        }
                    } else if upper != "BODY=8BITMIME" && upper != "BODY=7BIT" {
                        bad = Some("555 5.5.4 Unsupported MAIL parameter\r\n");
                    }
                }
                if let Some(error) = bad {
                    reply(&mut io, error).await?;
                    continue;
                }
                if available_bytes(&state.store.root)?
                    < cfg.smtp.minimum_free_bytes + cfg.smtp.max_message_bytes as u64
                {
                    reply(&mut io, "452 4.3.1 Insufficient storage\r\n").await?;
                    continue;
                }
                from = Some(address.into());
                recipients.clear();
                reply(&mut io, "250 2.1.0 Sender accepted\r\n").await?;
            }
            "RCPT" => {
                if from.is_none() {
                    reply(&mut io, "503 5.5.1 MAIL required\r\n").await?;
                    continue;
                }
                let (address, options) = match parse_path(arg, "TO:", false) {
                    Ok(v) => v,
                    Err(_) => {
                        reply(&mut io, "501 5.5.2 Invalid recipient\r\n").await?;
                        continue;
                    }
                };
                if !options.is_empty() {
                    reply(&mut io, "555 5.5.4 Unsupported RCPT parameter\r\n").await?;
                    continue;
                }
                if recipients.len() >= cfg.smtp.max_recipients {
                    reply(&mut io, "452 4.5.3 Too many recipients\r\n").await?;
                    continue;
                }
                let lookup = if address.eq_ignore_ascii_case("postmaster") {
                    &cfg.relay.postmaster
                } else {
                    address
                };
                if let Some(recipient) = cfg.recipient(lookup) {
                    if !recipients.iter().any(|r| r.address == recipient.address) {
                        recipients.push(recipient);
                    }
                    reply(&mut io, "250 2.1.5 Recipient accepted\r\n").await?;
                } else {
                    reply(&mut io, "550 5.1.1 Recipient not accepted\r\n").await?;
                }
            }
            "DATA" => {
                if !arg.is_empty() {
                    reply(&mut io, "501 5.5.2 DATA takes no parameters\r\n").await?;
                    continue;
                }
                if from.is_none() || recipients.is_empty() {
                    reply(&mut io, "503 5.5.1 MAIL and RCPT required\r\n").await?;
                    continue;
                }
                let permit = match state.processing.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        reply(&mut io, "451 4.3.2 Analysis capacity busy; retry later\r\n").await?;
                        from = None;
                        recipients.clear();
                        continue;
                    }
                };
                let id = uuid::Uuid::new_v4().to_string();
                let path = state.store.root.join("incoming").join(&id);
                let _cleanup = Incoming(path.clone());
                let file = match tokio::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .await
                {
                    Ok(f) => f,
                    Err(_) => {
                        reply(&mut io, "452 4.3.1 Cannot allocate storage\r\n").await?;
                        continue;
                    }
                };
                // Batch small SMTP lines without changing the durable enqueue/250 boundary.
                let mut file = tokio::io::BufWriter::with_capacity(64 * 1024, file);
                reply(&mut io, "354 End data with <CRLF>.<CRLF>\r\n").await?;
                let mut total = 0usize;
                let started = std::time::Instant::now();
                loop {
                    ensure!(
                        started.elapsed() < Duration::from_secs(1800),
                        "DATA total timeout"
                    );
                    let Some(mut chunk) = line(&mut io, 1001, 300).await? else {
                        return Ok(());
                    };
                    if chunk == b".\r\n" {
                        break;
                    }
                    if chunk.starts_with(b".") {
                        chunk.remove(0);
                    }
                    ensure!(chunk.len() <= 1000, "DATA line too long");
                    total += chunk.len();
                    if total > cfg.smtp.max_message_bytes {
                        reply(&mut io, "552 5.3.4 Message too large\r\n").await?;
                        return Ok(());
                    }
                    if file.write_all(&chunk).await.is_err() {
                        reply(&mut io, "452 4.3.1 Storage failure\r\n").await?;
                        return Ok(());
                    }
                }
                file.flush().await?;
                drop(file);
                let raw = tokio::fs::read(&path).await?;
                if let Err(error) = message::validate(&raw) {
                    tracing::debug!(%error,"message framing rejected");
                    reply(&mut io, "554 5.6.0 Invalid message structure\r\n").await?;
                    from = None;
                    recipients.clear();
                    continue;
                }
                let sender = from.take().unwrap();
                let recipients = std::mem::take(&mut recipients);
                let result = state
                    .engine
                    .process_smtp(&raw, peer.ip(), &helo, &sender, &id)
                    .await;
                let result = match result {
                    Ok((scan, raw)) => {
                        tracing::info!(id=%id,score=scan.score,complete=scan.complete,tagged=scan.tagged,analysis_ms=scan.elapsed_ms,"message analyzed");
                        state
                            .store
                            .enqueue(id.clone(), sender, recipients, scan, raw)
                            .await
                    }
                    Err(e) => Err(e),
                };
                drop(permit);
                match result {
                    Ok(()) => reply(&mut io, &format!("250 2.0.0 Queued as {id}\r\n")).await?,
                    Err(error) => {
                        tracing::error!(%error,"message not accepted");
                        reply(&mut io, "451 4.3.0 Unable to persist message; retry\r\n").await?;
                    }
                }
            }
            "RSET" if arg.is_empty() => {
                from = None;
                recipients.clear();
                reply(&mut io, "250 2.0.0 Reset\r\n").await?;
            }
            "NOOP" => reply(&mut io, "250 2.0.0 OK\r\n").await?,
            "QUIT" if arg.is_empty() => {
                reply(&mut io, "221 2.0.0 Bye\r\n").await?;
                break;
            }
            "VRFY" => reply(&mut io, "252 2.5.2 Cannot verify user\r\n").await?,
            "BDAT" => {
                reply(&mut io, "502 5.5.1 CHUNKING not supported\r\n").await?;
                break;
            }
            _ => {
                reply(&mut io, "500 5.5.2 Command unrecognized\r\n").await?;
                errors += 1;
                if errors >= 10 {
                    break;
                }
            }
        }
    }
    Ok(())
}
