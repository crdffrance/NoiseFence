//! Local displayed-code challenge. Deliberate interaction, not proof of humanity.
//! Only hashes and bounded attempt counters persist; SVG contains paths, not text.
use crate::{message, now, store::Store};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

pub const PATH: &str = "/challenge/puzzle";
pub const TTL_SECONDS: i64 = 600;
pub const MAX_ISSUES: i64 = 8;
pub const MAX_ATTEMPTS: i64 = 8;
const ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub token: String,
}
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VisualRequest { token: [REDACTED] }")
    }
}
#[derive(Serialize)]
pub struct Puzzle {
    pub nonce: String,
    /// Base64 of a bounded SVG generated exclusively from local numeric geometry.
    pub image: String,
}

pub(super) fn valid_token(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn answer_hash(token_hash: &str, nonce: &str, code: &str) -> String {
    message::digest(format!("noisefence-visual-code-1\n{token_hash}\n{nonce}\n{code}").as_bytes())
}

// Original 5x7 bitmap glyphs. Ambiguous I/O/0/1 are intentionally absent.
fn glyph(letter: u8) -> [u8; 7] {
    match letter {
        b'2' => [14, 17, 1, 2, 4, 8, 31],
        b'3' => [30, 1, 1, 14, 1, 1, 30],
        b'4' => [2, 6, 10, 18, 31, 2, 2],
        b'5' => [31, 16, 16, 30, 1, 1, 30],
        b'6' => [14, 16, 16, 30, 17, 17, 14],
        b'7' => [31, 1, 2, 4, 8, 8, 8],
        b'8' => [14, 17, 17, 14, 17, 17, 14],
        b'9' => [14, 17, 17, 15, 1, 1, 14],
        b'A' => [14, 17, 17, 31, 17, 17, 17],
        b'B' => [30, 17, 17, 30, 17, 17, 30],
        b'C' => [14, 17, 16, 16, 16, 17, 14],
        b'D' => [30, 17, 17, 17, 17, 17, 30],
        b'E' => [31, 16, 16, 30, 16, 16, 31],
        b'F' => [31, 16, 16, 30, 16, 16, 16],
        b'G' => [14, 17, 16, 23, 17, 17, 15],
        b'H' => [17, 17, 17, 31, 17, 17, 17],
        b'J' => [7, 2, 2, 2, 2, 18, 12],
        b'K' => [17, 18, 20, 24, 20, 18, 17],
        b'L' => [16, 16, 16, 16, 16, 16, 31],
        b'M' => [17, 27, 21, 21, 17, 17, 17],
        b'N' => [17, 25, 21, 19, 17, 17, 17],
        b'P' => [30, 17, 17, 30, 16, 16, 16],
        b'Q' => [14, 17, 17, 17, 21, 18, 13],
        b'R' => [30, 17, 17, 30, 20, 18, 17],
        b'S' => [15, 16, 16, 14, 1, 1, 30],
        b'T' => [31, 4, 4, 4, 4, 4, 4],
        b'U' => [17, 17, 17, 17, 17, 17, 14],
        b'V' => [17, 17, 17, 17, 17, 10, 4],
        b'W' => [17, 17, 17, 21, 21, 21, 10],
        b'X' => [17, 17, 10, 4, 10, 17, 17],
        b'Y' => [17, 17, 10, 4, 4, 4, 4],
        b'Z' => [31, 1, 2, 4, 8, 16, 31],
        _ => [0; 7],
    }
}
fn svg(code: &[u8], random: &[u8; 64]) -> String {
    let mut out = String::from(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"330\" height=\"88\" viewBox=\"0 0 330 88\"><rect width=\"330\" height=\"88\" rx=\"8\" fill=\"#f0f4fa\"/>",
    );
    for i in 0..6 {
        let y = 8 + u32::from(random[40 + i]) % 72;
        let end = 8 + u32::from(random[48 + i]) % 72;
        out.push_str(&format!(
            "<path d=\"M8 {y}L322 {end}\" stroke=\"#9aaac1\" stroke-width=\"1\" opacity=\"0.3\"/>"
        ));
    }
    for (i, c) in code.iter().enumerate() {
        let x = 24 + 48 * i;
        let y = 25 + usize::from(random[54 + i] % 7);
        let angle = i32::from(random[40 + i] % 11) - 5;
        let mut path = String::new();
        for (row, pixels) in glyph(*c).iter().enumerate() {
            for col in 0..5 {
                if pixels & (1 << (4 - col)) != 0 {
                    path.push_str(&format!("M{} {}h4v4h-4z", col * 5, row * 5));
                }
            }
        }
        out.push_str(&format!("<path transform=\"translate({x} {y}) rotate({angle} 12 17)\" fill=\"#172d49\" d=\"{path}\"/>"));
    }
    out.push_str("</svg>");
    out
}
fn create() -> Result<(Puzzle, String)> {
    let mut random = [0u8; 64];
    rand::rngs::OsRng
        .try_fill_bytes(&mut random)
        .context("visual challenge entropy unavailable")?;
    let code: Vec<u8> = random[..6]
        .iter()
        .map(|b| ALPHABET[usize::from(b % 32)])
        .collect();
    let image = STANDARD.encode(svg(&code, &random));
    Ok((
        Puzzle {
            nonce: hex::encode(&random[6..38]),
            image,
        },
        String::from_utf8(code).expect("ASCII alphabet"),
    ))
}

/// Generate only after the visitor explicitly requests a picture. Invalid,
/// exhausted or expired bearer tokens receive an indistinguishable decoy without
/// creating database rows. No SMTP notification or delivery can be triggered here.
pub async fn issue(store: &Store, policy: &super::Policy, body: Request) -> Result<Puzzle> {
    let (puzzle, answer) = create()?;
    if !policy.enabled || !valid_token(&body.token) || policy.validate().is_err() {
        return Ok(puzzle);
    }
    let token_hash = message::digest(body.token.as_bytes());
    let nonce = puzzle.nonce.clone();
    let hash = answer_hash(&token_hash, &nonce, &answer);
    store.run(move |db| {
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let time = now();
        let request = tx.query_row("SELECT id,expires FROM challenge_requests WHERE token_hash=?1 AND state='pending' AND expires>?2", params![token_hash,time], |r| Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?))).optional()?;
        if let Some((id, expires)) = request {
            tx.execute("INSERT INTO challenge_visual_codes(challenge_id,nonce,answer_hash,expires,issues,attempts) VALUES(?1,?2,?3,?4,1,0)
             ON CONFLICT(challenge_id) DO UPDATE SET nonce=excluded.nonce,answer_hash=excluded.answer_hash,expires=excluded.expires,issues=issues+1
             WHERE issues<?5 AND attempts<?6", params![id,nonce,hash,expires.min(time.saturating_add(TTL_SECONDS)),MAX_ISSUES,MAX_ATTEMPTS])?;
        }
        tx.commit()?; Ok(())
    }).await?;
    Ok(puzzle)
}

/// Caller commits the surrounding transaction even on a wrong answer, so an
/// SMTP-process restart, another worker or a new picture cannot reset attempts.
pub(super) fn verify(
    db: &Connection,
    id: &str,
    token_hash: &str,
    nonce: &str,
    code: &str,
    time: i64,
) -> Result<bool> {
    let row = db.query_row("SELECT nonce,answer_hash,expires,attempts FROM challenge_visual_codes WHERE challenge_id=?1", [id], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?))).optional()?;
    let Some((expected_nonce, expected_hash, expires, attempts)) = row else {
        return Ok(false);
    };
    if attempts >= MAX_ATTEMPTS || expires <= time || expected_nonce.is_empty() {
        return Ok(false);
    }
    db.execute(
        "UPDATE challenge_visual_codes SET attempts=attempts+1 WHERE challenge_id=?1",
        [id],
    )?;
    let normalized = code
        .trim_matches(|c: char| c.is_ascii_whitespace())
        .to_ascii_uppercase();
    let valid = code.len() <= 32
        && valid_token(nonce)
        && nonce == expected_nonce
        && normalized.len() == 6
        && normalized.bytes().all(|b| ALPHABET.contains(&b))
        && answer_hash(token_hash, nonce, &normalized) == expected_hash;
    if valid || attempts + 1 >= MAX_ATTEMPTS {
        db.execute("UPDATE challenge_visual_codes SET nonce='',answer_hash='',expires=0 WHERE challenge_id=?1",[id])?;
    }
    Ok(valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn alphabet_glyphs_are_distinct_and_generated_images_contain_no_answer_text() {
        let mut seen = std::collections::BTreeSet::new();
        for c in ALPHABET {
            assert!(seen.insert(glyph(*c)));
            assert!(glyph(*c).iter().any(|x| *x != 0));
        }
        for _ in 0..32 {
            let (p, code) = create().unwrap();
            let image = String::from_utf8(STANDARD.decode(p.image).unwrap()).unwrap();
            assert!(valid_token(&p.nonce) && code.len() == 6);
            assert!(
                !image.contains(&code)
                    && !image.contains("<text")
                    && !image.contains("<script")
                    && !image.contains("href=")
            );
            assert!(image.len() < 16_000);
        }
    }
    #[test]
    fn answers_bind_token_nonce_and_case_normalized_code() {
        assert_ne!(
            answer_hash("a", "nonce", "ABC234"),
            answer_hash("b", "nonce", "ABC234")
        );
        assert_ne!(
            answer_hash("a", "nonce", "ABC234"),
            answer_hash("a", "other", "ABC234")
        );
    }

    #[test]
    fn generated_picture_answer_verifies_once_and_can_render_a_local_preview() {
        let (puzzle, code) = create().unwrap();
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE challenge_visual_codes(challenge_id TEXT PRIMARY KEY,nonce TEXT,answer_hash TEXT,expires INTEGER,issues INTEGER,attempts INTEGER);").unwrap();
        let token = message::digest(b"synthetic preview token");
        db.execute(
            "INSERT INTO challenge_visual_codes VALUES('fixture',?1,?2,?3,1,0)",
            params![
                puzzle.nonce,
                answer_hash(&token, &puzzle.nonce, &code),
                now() + TTL_SECONDS
            ],
        )
        .unwrap();
        assert!(verify(&db, "fixture", &token, &puzzle.nonce, &code, now()).unwrap());
        assert!(!verify(&db, "fixture", &token, &puzzle.nonce, &code, now()).unwrap());
        // Optional visual QA artifact, containing only an already-consumed
        // synthetic fixture. Never read/write a running service's data directory.
        if let Some(dir) = std::env::var_os("NOISEFENCE_VISUAL_PREVIEW") {
            let dir = std::path::PathBuf::from(dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("page.html"), super::super::PAGE).unwrap();
            std::fs::write(
                dir.join("puzzle.json"),
                serde_json::to_vec(&puzzle).unwrap(),
            )
            .unwrap();
            std::fs::write(
                dir.join("picture.svg"),
                STANDARD.decode(&puzzle.image).unwrap(),
            )
            .unwrap();
        }
    }
}
