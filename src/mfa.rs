//! RFC 6238 TOTP, encrypted enrollment secrets and atomic single-use recovery.
use anyhow::{Result, bail, ensure};
use rand::RngCore;
use ring::{aead, hmac};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS mfa_credentials(username TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,secret BLOB NOT NULL,enabled INTEGER NOT NULL DEFAULT 0,pending_until INTEGER NOT NULL,last_step INTEGER NOT NULL DEFAULT -1);
CREATE TABLE IF NOT EXISTS mfa_recovery(username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,digest TEXT NOT NULL,PRIMARY KEY(username,digest));
CREATE TABLE IF NOT EXISTS mfa_sessions(token_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS mfa_attempts(username TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,until INTEGER NOT NULL,attempts INTEGER NOT NULL);
";

pub struct Key([u8; 32]);
impl Key {
    pub fn open(root: &Path) -> Result<Self> {
        let path = root.join("mfa.key");
        let mut bytes = [0u8; 32];
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(mut f) => {
                rand::rngs::OsRng.fill_bytes(&mut bytes);
                f.write_all(&bytes)?;
                f.sync_all()?;
                std::fs::File::open(root)?.sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut f = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(&path)?;
                ensure!(
                    f.metadata()?.is_file()
                        && f.metadata()?.len() == 32
                        && f.metadata()?.permissions().mode() & 0o077 == 0,
                    "MFA key requires a private regular 32-byte file"
                );
                f.read_exact(&mut bytes)?;
            }
            Err(e) => return Err(e.into()),
        }
        Ok(Self(bytes))
    }
    fn cipher(&self) -> Result<aead::LessSafeKey> {
        Ok(aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &self.0)
                .map_err(|_| anyhow::anyhow!("MFA encryption unavailable"))?,
        ))
    }
    pub fn seal(&self, user: &str, secret: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut data = secret.to_vec();
        self.cipher()?
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(user.as_bytes()),
                &mut data,
            )
            .map_err(|_| anyhow::anyhow!("MFA encryption failed"))?;
        let mut out = nonce.to_vec();
        out.extend(data);
        Ok(out)
    }
    pub fn open_secret(&self, user: &str, sealed: &[u8]) -> Result<Vec<u8>> {
        ensure!(sealed.len() == 12 + 20 + 16, "Invalid MFA record");
        let nonce: [u8; 12] = sealed[..12].try_into()?;
        let mut data = sealed[12..].to_vec();
        Ok(self
            .cipher()?
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(user.as_bytes()),
                &mut data,
            )
            .map_err(|_| anyhow::anyhow!("MFA decryption failed"))?
            .to_vec())
    }
}

pub fn secret() -> Vec<u8> {
    let mut bytes = vec![0; 20];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}
pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for byte in bytes {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}
fn hotp(secret: &[u8], step: u64, digits: u32) -> String {
    let mac = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret),
        &step.to_be_bytes(),
    );
    let bytes = mac.as_ref();
    let offset = (bytes[19] & 15) as usize;
    let number = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
    format!(
        "{:0width$}",
        number % 10u32.pow(digits),
        width = digits as usize
    )
}
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0, |x, (a, b)| x | (a ^ b)) == 0
}
pub fn matched_step(secret: &[u8], code: &str, time: i64, last: i64) -> Option<i64> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) || time < 30 {
        return None;
    }
    let current = time / 30;
    [current, current - 1, current + 1]
        .into_iter()
        .find(|step| *step > last && same(&hotp(secret, *step as u64, 6), code))
}
/// Must be called in the same transaction that creates the verified session.
/// Returns None for an incorrect factor, Some(false) when MFA is not enabled.
pub fn consume(
    db: &Connection,
    key: &Key,
    user: &str,
    code: &str,
    time: i64,
) -> Result<Option<bool>> {
    let record = db
        .query_row(
            "SELECT secret,last_step FROM mfa_credentials WHERE username=?1 AND enabled=1",
            [user],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((encrypted, last)) = record else {
        return Ok(Some(false));
    };
    if code.len() > 80 {
        return Ok(None);
    }
    let secret = key.open_secret(user, &encrypted)?;
    if let Some(step) = matched_step(&secret, code, time, last)
        && db.execute(
            "UPDATE mfa_credentials SET last_step=?2 WHERE username=?1 AND last_step<?2",
            params![user, step],
        )? == 1
    {
        return Ok(Some(true));
    }
    // Recovery tokens contain 128 random bits; SHA-256 is appropriate for this entropy.
    if code.len() == 32
        && code.bytes().all(|b| b.is_ascii_hexdigit())
        && db.execute(
            "DELETE FROM mfa_recovery WHERE username=?1 AND digest=?2",
            params![user, crate::message::digest(code.as_bytes())],
        )? == 1
    {
        return Ok(Some(true));
    }
    Ok(None)
}
pub fn recovery() -> Vec<String> {
    (0..10)
        .map(|_| {
            let mut b = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut b);
            hex::encode(b)
        })
        .collect()
}
/// Persistent, bounded challenge attempts, including enrollment and removal.
/// Call outside a transaction that may roll back after an invalid code.
pub fn attempt(db: &Connection, user: &str, time: i64) -> Result<bool> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username=?1)",
        [user],
        |r| r.get(0),
    )?;
    if !exists {
        return Ok(false);
    }
    db.execute("INSERT INTO mfa_attempts VALUES(?1,?2,1) ON CONFLICT(username) DO UPDATE SET until=CASE WHEN until<=?3 THEN ?2 ELSE until END,attempts=CASE WHEN until<=?3 THEN 1 ELSE attempts+1 END",params![user,time+600,time])?;
    Ok(db.query_row(
        "SELECT attempts<=10 FROM mfa_attempts WHERE username=?1",
        [user],
        |r| r.get(0),
    )?)
}
pub fn require_no_missing_key(root: &Path, db: &Connection) -> Result<()> {
    let any: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM mfa_credentials)", [], |r| {
        r.get(0)
    })?;
    if any && !root.join("mfa.key").exists() {
        bail!("MFA key missing: restore it, do not generate a replacement")
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc6238_sha1_vectors_and_replay() {
        let key = b"12345678901234567890";
        for (time, expected) in [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ] {
            assert_eq!(hotp(key, time / 30, 8), expected);
        }
        let code = hotp(key, 100, 6);
        assert_eq!(matched_step(key, &code, 3000, -1), Some(100));
        assert_eq!(matched_step(key, &code, 3000, 100), None);
        assert_eq!(matched_step(key, &code, 3090, -1), None);
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }
    #[test]
    fn encryption_binds_username_and_detects_changes() {
        let dir = tempfile::tempdir().unwrap();
        let key = Key::open(dir.path()).unwrap();
        let raw = secret();
        let sealed = key.seal("alice", &raw).unwrap();
        assert_ne!(sealed, raw);
        assert_eq!(key.open_secret("alice", &sealed).unwrap(), raw);
        assert!(key.open_secret("bob", &sealed).is_err());
        let mut bad = sealed;
        bad[15] ^= 1;
        assert!(key.open_secret("alice", &bad).is_err());
    }
}
