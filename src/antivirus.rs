//! Bounded ClamD INSTREAM client. The daemon only receives bytes over a local socket.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AntivirusConfig {
    pub socket: PathBuf,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_size")]
    pub max_bytes: usize,
    /// Unofficial detections remain advisory unless explicitly trusted by prefix.
    #[serde(default)]
    pub trusted_unofficial_prefixes: Vec<String>,
}
fn default_timeout() -> u64 {
    3000
}
fn default_size() -> usize {
    25 * 1024 * 1024
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AntivirusStatus {
    #[default]
    Disabled,
    Clean,
    Malware,
    Suspicious,
    Unscannable,
    Unavailable,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AntivirusResult {
    pub status: AntivirusStatus,
    pub signature: Option<String>,
    pub elapsed_ms: u64,
}

impl AntivirusConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.socket.is_absolute(),
            "ClamAV requires an absolute Unix socket path"
        );
        ensure!(
            (100..=5000).contains(&self.timeout_ms),
            "invalid ClamAV timeout"
        );
        ensure!(
            (1024..=100 * 1024 * 1024).contains(&self.max_bytes),
            "invalid ClamAV size limit"
        );
        ensure!(
            self.trusted_unofficial_prefixes.len() <= 32,
            "too many trusted signature prefixes"
        );
        for prefix in &self.trusted_unofficial_prefixes {
            ensure!(
                !prefix.is_empty()
                    && prefix.len() <= 128
                    && prefix
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "invalid trusted signature prefix"
            );
        }
        Ok(())
    }
}

fn response(raw: &[u8], config: &AntivirusConfig) -> Result<AntivirusResult> {
    let text = std::str::from_utf8(raw).context("non-UTF-8 ClamAV response")?;
    let status = if text == "stream: OK" {
        return Ok(AntivirusResult {
            status: AntivirusStatus::Clean,
            ..Default::default()
        });
    } else if let Some(signature) = text
        .strip_prefix("stream: ")
        .and_then(|s| s.strip_suffix(" FOUND"))
    {
        ensure!(
            !signature.is_empty()
                && signature.len() <= 256
                && signature.bytes().all(|b| (32..=126).contains(&b)),
            "invalid ClamAV signature"
        );
        if signature.starts_with("Heuristics.Limits.Exceeded")
            || signature.starts_with("Heuristics.Encrypted")
        {
            AntivirusStatus::Unscannable
        } else if signature.starts_with("PUA.")
            || signature.starts_with("Heuristics.")
            || (signature.ends_with(".UNOFFICIAL")
                && !config
                    .trusted_unofficial_prefixes
                    .iter()
                    .any(|p| signature.starts_with(p)))
        {
            AntivirusStatus::Suspicious
        } else {
            AntivirusStatus::Malware
        }
    } else {
        anyhow::bail!("ClamAV did not complete the scan");
    };
    Ok(AntivirusResult {
        status,
        signature: text
            .strip_prefix("stream: ")
            .and_then(|s| s.strip_suffix(" FOUND"))
            .map(str::to_string),
        elapsed_ms: 0,
    })
}

pub async fn scan(config: &AntivirusConfig, raw: &[u8]) -> AntivirusResult {
    let started = std::time::Instant::now();
    if raw.len() > config.max_bytes {
        return AntivirusResult {
            status: AntivirusStatus::Unscannable,
            ..Default::default()
        };
    }
    let work = async {
        let mut socket = UnixStream::connect(&config.socket).await?;
        socket.write_all(b"zINSTREAM\0").await?;
        for chunk in raw.chunks(64 * 1024) {
            socket
                .write_all(&(chunk.len() as u32).to_be_bytes())
                .await?;
            socket.write_all(chunk).await?;
        }
        socket.write_all(&0u32.to_be_bytes()).await?;
        let mut reply = Vec::with_capacity(512);
        loop {
            let byte = socket.read_u8().await?;
            if byte == 0 {
                break;
            }
            ensure!(reply.len() < 1024, "ClamAV reply exceeds limit");
            reply.push(byte);
        }
        response(&reply, config)
    };
    let mut result =
        match tokio::time::timeout(Duration::from_millis(config.timeout_ms), work).await {
            Ok(Ok(value)) => value,
            _ => AntivirusResult {
                status: AntivirusStatus::Unavailable,
                ..Default::default()
            },
        };
    result.elapsed_ms = started.elapsed().as_millis() as u64;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(socket: PathBuf) -> AntivirusConfig {
        AntivirusConfig {
            socket,
            timeout_ms: 100,
            max_bytes: 1024 * 1024,
            trusted_unofficial_prefixes: vec![],
        }
    }

    #[test]
    fn distinguishes_malware_advisory_and_unscannable() {
        let cfg = config("/tmp/clamd.sock".into());
        assert_eq!(
            response(b"stream: Win.Test.Malware FOUND", &cfg)
                .unwrap()
                .status,
            AntivirusStatus::Malware
        );
        assert_eq!(
            response(b"stream: Sanesecurity.Spam.Test.UNOFFICIAL FOUND", &cfg)
                .unwrap()
                .status,
            AntivirusStatus::Suspicious
        );
        assert_eq!(
            response(
                b"stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND",
                &cfg
            )
            .unwrap()
            .status,
            AntivirusStatus::Unscannable
        );
        assert!(response(b"stream: read error ERROR", &cfg).is_err());
        assert!(response(b"stream: injected\r\nHeader: value FOUND", &cfg).is_err());
    }

    #[tokio::test]
    async fn streams_exact_bytes_and_obeys_deadline() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("clamd.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let bytes = vec![42; 150_000];
        let expected = bytes.clone();
        let daemon = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut command = [0; 10];
            stream.read_exact(&mut command).await.unwrap();
            assert_eq!(&command, b"zINSTREAM\0");
            let mut received = Vec::new();
            loop {
                let size = stream.read_u32().await.unwrap() as usize;
                if size == 0 {
                    break;
                }
                assert!(size <= 64 * 1024);
                let mut chunk = vec![0; size];
                stream.read_exact(&mut chunk).await.unwrap();
                received.extend(chunk);
            }
            assert_eq!(received, expected);
            stream.write_all(b"stream: OK\0").await.unwrap();
            let (_stalled, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let cfg = config(path);
        assert_eq!(scan(&cfg, &bytes).await.status, AntivirusStatus::Clean);
        assert_eq!(
            scan(&cfg, b"test").await.status,
            AntivirusStatus::Unavailable
        );
        daemon.abort();
    }
}
