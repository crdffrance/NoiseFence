//! Immutable wire chunks. Recipient variants share one body allocation and keep
//! only their own headers; disk and replication consumers stream these chunks.
use anyhow::{Context, Result, ensure};
use axum::body::Bytes;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Write};

pub const MAX_VARIANTS: usize = 1000;
pub const MAX_RECIPIENTS_PER_VARIANT: usize = 100;
pub const MAX_BATCH_HEADERS: usize = 16 * 1024 * 1024;
pub const MAX_BATCH_METADATA: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct WireBody {
    prefix: Bytes,
    payload: Bytes,
}
impl From<Vec<u8>> for WireBody {
    fn from(raw: Vec<u8>) -> Self {
        Self {
            prefix: Bytes::new(),
            payload: Bytes::from(raw),
        }
    }
}
impl WireBody {
    pub fn shared_payload(raw: &[u8]) -> Result<Bytes> {
        Ok(Bytes::copy_from_slice(crate::message::fields(raw)?.1))
    }
    pub fn with_shared_payload(wire: Vec<u8>, payload: &Bytes) -> Result<Self> {
        // The incoming header limit does not include our Received/authentication/
        // diagnostic/ARC fields. Allow bounded headroom in the trusted renderer's
        // output while locating its FIRST separator, not just a matching suffix.
        let end = wire
            .windows(4)
            .take(crate::message::MAX_HEADER_BYTES * 2 + 1)
            .position(|w| w == b"\r\n\r\n")
            .context("rendered headers exceed capacity or lack a separator")?;
        let body = &wire[end + 4..];
        ensure!(
            body == payload.as_ref(),
            "recipient renderer changed the message body"
        );
        // Copy just the prefix. Slicing Bytes::from(wire) would keep an entire
        // body allocation alive for every recipient variant.
        let prefix = Bytes::copy_from_slice(&wire[..wire.len() - body.len()]);
        Ok(Self {
            prefix,
            payload: payload.clone(),
        })
    }
    pub fn len(&self) -> usize {
        self.prefix.len() + self.payload.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn header_bytes(&self) -> usize {
        self.prefix.len()
    }
    pub fn digest(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(&self.prefix);
        hash.update(&self.payload);
        hex::encode(hash.finalize())
    }
    pub fn write_to(&self, writer: &mut impl Write) -> std::io::Result<()> {
        writer.write_all(&self.prefix)?;
        writer.write_all(&self.payload)
    }
    /// Only single-message CLI/export callers need a contiguous representation.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.len());
        bytes.extend_from_slice(&self.prefix);
        bytes.extend_from_slice(&self.payload);
        bytes
    }
    pub fn http_body(&self) -> reqwest::Body {
        use tokio::io::AsyncReadExt;
        let reader = Cursor::new(self.prefix.clone()).chain(Cursor::new(self.payload.clone()));
        reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::with_capacity(
            reader,
            64 * 1024,
        ))
    }
    #[cfg(test)]
    pub(crate) fn payload_identity(&self) -> *const u8 {
        self.payload.as_ptr()
    }
}

/// Count serialization without allocating another copy of the metadata. These
/// bounds apply before retaining each additional variant/recipient.
#[derive(Default)]
pub struct Budget {
    metadata: usize,
    headers: usize,
}
impl Budget {
    pub fn metadata(&mut self, value: &impl Serialize) -> Result<()> {
        struct Counter<'a>(&'a mut usize);
        impl Write for Counter<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if bytes.len() > MAX_BATCH_METADATA.saturating_sub(*self.0) {
                    return Err(std::io::Error::other("queue metadata capacity exceeded"));
                }
                *self.0 += bytes.len();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(Counter(&mut self.metadata), value)?;
        Ok(())
    }
    pub fn headers(&mut self, body: &WireBody) -> Result<()> {
        self.headers = self.headers.saturating_add(body.header_bytes());
        ensure!(
            self.headers <= MAX_BATCH_HEADERS,
            "queue header capacity exceeded"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_thousand_variants_share_one_payload_and_preserve_each_wire_digest() {
        let raw = [
            b"Subject: test\r\n\r\n".as_slice(),
            &vec![b'x'; 1024 * 1024],
        ]
        .concat();
        let payload = WireBody::shared_payload(&raw).unwrap();
        let mut copies = Vec::new();
        for i in 0..MAX_VARIANTS {
            let wire =
                crate::message::rewrite(&raw, false, &format!("X-Variant: {i}\r\n")).unwrap();
            let hash = (i == 0 || i == MAX_VARIANTS - 1).then(|| crate::message::digest(&wire));
            let copy = WireBody::with_shared_payload(wire, &payload).unwrap();
            if let Some(hash) = hash {
                assert_eq!(copy.digest(), hash);
            }
            assert_eq!(copy.payload_identity(), payload.as_ptr());
            copies.push(copy);
        }
        assert!(copies.iter().map(WireBody::header_bytes).sum::<usize>() < 100_000);
        let mut written = Vec::new();
        copies[999].write_to(&mut written).unwrap();
        assert_eq!(written, copies[999].to_vec());
        assert_eq!(
            crate::message::fields(&written).unwrap().1,
            payload.as_ref()
        );
        assert!(
            WireBody::with_shared_payload(b"Subject: x\r\n\r\nchanged".to_vec(), &payload).is_err()
        );
    }
    #[test]
    fn metadata_and_headers_have_independent_hard_bounds() {
        let value = "x".repeat(1024 * 1024);
        let mut budget = Budget::default();
        let mut accepted = 0;
        while budget.metadata(&value).is_ok() {
            accepted += 1;
        }
        assert_eq!(accepted, 31); // JSON quotes count too.
        let payload = Bytes::new();
        let body = WireBody {
            prefix: Bytes::from(vec![b'x'; 1024 * 1024]),
            payload,
        };
        let mut budget = Budget::default();
        for _ in 0..16 {
            budget.headers(&body).unwrap();
        }
        assert!(budget.headers(&body).is_err());
    }
    #[test]
    fn a_body_write_failure_is_propagated_after_the_header_write() {
        struct Full {
            written: usize,
        }
        impl Write for Full {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                if self.written > 0 {
                    return Err(std::io::Error::from_raw_os_error(libc::ENOSPC));
                }
                self.written += data.len();
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let raw = b"Subject: test\r\n\r\nbody\r\n";
        let body =
            WireBody::with_shared_payload(raw.to_vec(), &WireBody::shared_payload(raw).unwrap())
                .unwrap();
        let mut disk = Full { written: 0 };
        assert_eq!(
            body.write_to(&mut disk).unwrap_err().raw_os_error(),
            Some(libc::ENOSPC)
        );
        assert_eq!(disk.written, body.header_bytes());
    }
    #[test]
    fn diagnostic_header_headroom_does_not_reject_valid_large_original_headers() {
        let raw = format!(
            "Subject: test\r\nX-Padding: x\r\n{}\r\nbody\r\n",
            format!(" {}\r\n", "a".repeat(980)).repeat(266)
        );
        crate::message::validate(raw.as_bytes()).unwrap();
        assert!(raw.split('\n').all(|line| line.len() <= 999));
        let payload = WireBody::shared_payload(raw.as_bytes()).unwrap();
        let extra = (0..16)
            .map(|i| format!("X-NoiseFence-Test-{i}: {}\r\n", "b".repeat(64)))
            .collect::<String>();
        let wire = crate::message::rewrite(raw.as_bytes(), false, &extra).unwrap();
        assert!(
            crate::message::fields(&wire).is_err(),
            "output includes our headers beyond the incoming limit"
        );
        let copy = WireBody::with_shared_payload(wire.clone(), &payload).unwrap();
        assert_eq!(copy.to_vec(), wire);
        assert!(
            WireBody::with_shared_payload(
                b"Subject: test\r\n\r\ninjected\r\n\r\nbody\r\n".to_vec(),
                &payload
            )
            .is_err()
        );
    }
}
