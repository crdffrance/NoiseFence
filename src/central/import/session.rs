//! One bounded, owner-only local control session for an offline MX source.
use super::frozen::{FrozenSource, with_seeded_source, with_selected_source, with_source};
use crate::{central::selection::Selection, cluster::activation::Journal, config::Config};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const PROTOCOL: &str = "noisefence-source-session-1";
const MAX_FRAME: usize = 5 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    session: String,
    sequence: u32,
    command: Command,
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Check,
    Select {
        authority: Box<Journal>,
        selection: Box<Selection>,
        export_sha256: String,
        source_sequence: i64,
    },
    Abort,
    Release,
}

/// No TCP listener, service lifecycle change, PostgreSQL activation or automatic
/// restart. Supervisor must keep stopped services fenced after any local commit,
/// and impose an outer process deadline for filesystem stalls/process failure.
pub fn serve(
    config: &Config,
    parent: &Path,
    socket: &Path,
    lease: Duration,
    selected: Option<&Selection>,
    preserve_generations: bool,
) -> Result<()> {
    ensure!(
        (1..=1800).contains(&lease.as_secs()),
        "Source session lease must be 1..1800 seconds"
    );
    let deadline = Instant::now() + lease;
    let listener = Listener::bind(socket)?;
    loop {
        ensure!(
            Instant::now() < deadline,
            "Source session lease expired before connection"
        );
        match listener.socket.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                let mut channel = Channel { stream, deadline };
                return match selected {
                    Some(selected) => with_selected_source(config, parent, selected, |source| {
                        exchange(source, &mut channel)
                    }),
                    None if preserve_generations => {
                        with_seeded_source(config, parent, |source| exchange(source, &mut channel))
                    }
                    None => with_source(config, parent, |source| exchange(source, &mut channel)),
                };
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}

fn exchange(source: &mut FrozenSource<'_>, channel: &mut Channel) -> Result<()> {
    let session = uuid::Uuid::new_v4().to_string();
    channel.send(
        &serde_json::json!({"protocol":PROTOCOL,"session":session,"state":"frozen",
        "receipt":source.receipt,"export_path":source.export_path(),"existing_selection":source.existing_selection()}),
    )?;
    let mut selected = None;
    for sequence in 1..=64 {
        let request: Request = serde_json::from_slice(&channel.receive()?)
            .map_err(|_| anyhow::anyhow!("Invalid source session request"))?;
        ensure!(
            request.protocol == PROTOCOL
                && request.session == session
                && request.sequence == sequence,
            "Source session identity or sequence mismatch"
        );
        source.verify()?;
        let state = match request.command {
            Command::Check => "held",
            Command::Select {
                authority,
                selection,
                export_sha256,
                source_sequence,
            } => {
                ensure!(
                    selected.is_none(),
                    "Source was already selected in this session"
                );
                ensure!(
                    export_sha256 == source.receipt.sha256
                        && source_sequence == source.receipt.journal.sequence,
                    "Selection does not acknowledge this frozen export"
                );
                authority.validate()?;
                selected = Some(source.select(&authority, &selection)?);
                "selected"
            }
            Command::Abort => {
                ensure!(
                    selected.is_none() && source.existing_selection().is_none(),
                    "Cannot abort a committed source selection; recover the same authority"
                );
                "aborted"
            }
            Command::Release => {
                ensure!(selected.is_some(), "Release requires a committed selection");
                "released"
            }
        };
        channel.send(
            &serde_json::json!({"protocol":PROTOCOL,"session":session,"sequence":sequence,
            "state":state,"selection":selected}),
        )?;
        if matches!(state, "aborted" | "released") {
            return Ok(());
        }
    }
    anyhow::bail!("Source session command limit reached")
}

/// Four-byte network-order length followed by UTF-8 JSON. Updating timeouts on
/// every underlying read/write prevents fragmented frames from extending the
/// absolute lease. No unbounded read_line or stdin worker can hold locks forever.
struct Channel {
    stream: UnixStream,
    deadline: Instant,
}
impl Channel {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Source session lease expired"))
    }
    fn receive(&mut self) -> Result<Vec<u8>> {
        let mut header = [0; 4];
        self.read_exact(&mut header)
            .context("Source session frame unavailable")?;
        let length = u32::from_be_bytes(header) as usize;
        ensure!(
            (1..=MAX_FRAME).contains(&length),
            "Source session frame exceeds bounds"
        );
        let mut body = vec![0; length];
        self.read_exact(&mut body)
            .context("Source session frame incomplete")?;
        Ok(body)
    }
    fn send(&mut self, value: &impl Serialize) -> Result<()> {
        let body = serde_json::to_vec(value)?;
        ensure!(
            !body.is_empty() && body.len() <= MAX_FRAME,
            "Source session response exceeds bounds"
        );
        self.write_all(&(body.len() as u32).to_be_bytes())?;
        self.write_all(&body)?;
        Ok(())
    }
}
impl Read for Channel {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for Channel {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Listener {
    socket: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
}
impl Listener {
    fn bind(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .context("Source socket needs a parent directory")?;
        let metadata = fs::symlink_metadata(parent)?;
        // SAFETY: geteuid only reads process identity.
        ensure!(
            path.is_absolute()
                && parent.canonicalize()? == parent
                && metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0,
            "Source socket requires an owner-only physical parent directory"
        );
        // bind refuses any existing path, including an existing or stale socket.
        let socket = UnixListener::bind(path)?;
        let metadata = fs::symlink_metadata(path)?;
        let held = Self {
            socket,
            path: path.into(),
            identity: (metadata.dev(), metadata.ino()),
        };
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        held.socket.set_nonblocking(true)?;
        Ok(held)
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.file_type().is_socket() && (m.dev(), m.ino()) == self.identity)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// A local recovery receipt is bounded and must name the exact prior selection.
pub fn read_selection(path: &Path) -> Result<Selection> {
    use std::os::unix::fs::OpenOptionsExt;
    ensure!(
        path.is_absolute(),
        "Recovery selection path must be absolute"
    );
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let info = file.metadata()?;
    ensure!(
        info.is_file() && info.len() <= 8192,
        "Recovery selection must be a regular file of at most 8 KiB"
    );
    let mut raw = Vec::new();
    (&mut file).take(8193).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 8192, "Recovery selection exceeds bounds");
    let selected: Selection =
        serde_json::from_slice(&raw).map_err(|_| anyhow::anyhow!("Invalid recovery selection"))?;
    selected.validate()?;
    Ok(selected)
}

pub const COMMIT_PROTOCOL: &str = "noisefence-import-commit-1";

/// Local supervisor bridge. A connection is established with a bounded async
/// connect before taking PostgreSQL activation locks. Only the supervisor that
/// holds the original source sessions may serve this private endpoint.
pub(super) struct CommitChannel(Channel);
impl CommitChannel {
    pub async fn connect(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .context("Commit socket needs a parent directory")?;
        let dir = fs::symlink_metadata(parent)?;
        let file = fs::symlink_metadata(path)?;
        // SAFETY: geteuid only reads process identity.
        let uid = unsafe { libc::geteuid() };
        ensure!(
            path.is_absolute()
                && parent.canonicalize()? == parent
                && dir.is_dir()
                && dir.uid() == uid
                && dir.mode() & 0o077 == 0
                && file.file_type().is_socket()
                && file.uid() == uid
                && file.mode() & 0o077 == 0,
            "Commit socket must belong to the installation owner in a private physical directory"
        );
        let socket = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::UnixStream::connect(path),
        )
        .await
        .context("Commit supervisor connection deadline exceeded")??;
        let stream = socket.into_std()?;
        stream.set_nonblocking(false)?;
        Ok(Self(Channel {
            stream,
            deadline: Instant::now() + Duration::from_secs(90),
        }))
    }
    pub fn commit(
        &mut self,
        binding: &crate::central::binding::Binding,
        authority: &Journal,
        selections: &[Selection],
    ) -> Result<Vec<Selection>> {
        let request = uuid::Uuid::new_v4().to_string();
        self.0.send(
            &serde_json::json!({"protocol":COMMIT_PROTOCOL,"request":request,"database":binding,
            "authority":authority,"selections":selections}),
        )?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Reply {
            protocol: String,
            request: String,
            database: crate::central::binding::Binding,
            selections: Vec<Selection>,
        }
        let reply: Reply = serde_json::from_slice(&self.0.receive()?)
            .map_err(|_| anyhow::anyhow!("Invalid commit supervisor response"))?;
        ensure!(
            reply.protocol == COMMIT_PROTOCOL
                && reply.request == request
                && &reply.database == binding,
            "Commit supervisor authority or request mismatch"
        );
        ensure!(
            reply.selections.len() == selections.len(),
            "Commit supervisor source count mismatch"
        );
        // Central::activate_import additionally requires exact, unique durable
        // selections before the destination transaction can commit.
        Ok(reply.selections)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frames_are_bounded_and_a_partial_frame_cannot_outlive_its_lease() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let mut channel = Channel {
            stream: server,
            deadline: Instant::now() + Duration::from_millis(100),
        };
        client
            .write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
            .unwrap();
        assert!(
            channel
                .receive()
                .unwrap_err()
                .to_string()
                .contains("bounds")
        );
        client.write_all(&4u32.to_be_bytes()).unwrap();
        client.write_all(b"{").unwrap();
        assert!(channel.receive().is_err());
        assert!(channel.remaining().is_err());
        assert!(
            channel
                .send(&serde_json::json!({"state":"expired"}))
                .is_err()
        );
    }
}
