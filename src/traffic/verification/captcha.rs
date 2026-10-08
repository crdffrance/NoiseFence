//! First-party visual challenges. The image has no answer metadata; only a
//! context-bound HMAC is stored. A submitted challenge is consumed on any answer.
use super::*;
use base64::Engine;
use rand::Rng;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sender_captcha_v1 (
 ticket TEXT PRIMARY KEY, id TEXT NOT NULL UNIQUE, answer_mac BLOB NOT NULL,
 expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS sender_captcha_expiry_v1 ON sender_captcha_v1(expires);";
const WIDTH: u32 = 280;
const HEIGHT: u32 = 96;
const LIFETIME: i64 = 300;
const GLYPHS: &[(u8, [u8; 7])] = &[
    (b'2', [14, 17, 1, 2, 4, 8, 31]),
    (b'3', [30, 1, 1, 14, 1, 1, 30]),
    (b'4', [2, 6, 10, 18, 31, 2, 2]),
    (b'5', [31, 16, 16, 30, 1, 1, 30]),
    (b'6', [14, 16, 16, 30, 17, 17, 14]),
    (b'7', [31, 1, 2, 4, 8, 8, 8]),
    (b'8', [14, 17, 17, 14, 17, 17, 14]),
    (b'9', [14, 17, 17, 15, 1, 1, 14]),
    (b'A', [14, 17, 17, 31, 17, 17, 17]),
    (b'C', [14, 17, 16, 16, 16, 17, 14]),
    (b'D', [30, 17, 17, 17, 17, 17, 30]),
    (b'E', [31, 16, 16, 30, 16, 16, 31]),
    (b'F', [31, 16, 16, 30, 16, 16, 16]),
    (b'H', [17, 17, 17, 31, 17, 17, 17]),
    (b'J', [7, 2, 2, 2, 2, 18, 12]),
    (b'K', [17, 18, 20, 24, 20, 18, 17]),
    (b'M', [17, 27, 21, 21, 17, 17, 17]),
    (b'N', [17, 25, 25, 21, 19, 19, 17]),
    (b'P', [30, 17, 17, 30, 16, 16, 16]),
    (b'R', [30, 17, 17, 30, 20, 18, 17]),
    (b'T', [31, 4, 4, 4, 4, 4, 4]),
    (b'U', [17, 17, 17, 17, 17, 17, 14]),
    (b'V', [17, 17, 17, 17, 17, 10, 4]),
    (b'W', [17, 17, 17, 21, 21, 21, 10]),
    (b'X', [17, 17, 10, 4, 10, 17, 17]),
    (b'Y', [17, 17, 10, 4, 4, 4, 4]),
];

#[derive(Serialize)]
pub struct Challenge {
    pub id: String,
    pub image: String,
    pub expires: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Answer {
    pub id: String,
    pub answer: String,
}
fn mac_input(ticket: &str, id: &str, answer: &str) -> String {
    format!("noisefence/local-captcha/v1\0{ticket}\0{id}\0{answer}")
}

pub struct Prepared {
    answer: String,
    image: Vec<u8>,
}
/// CPU work runs without holding the SMTP queue's writer lock.
pub fn prepare() -> Result<Prepared> {
    let mut rng = rand::thread_rng();
    let answer: String = (0..6)
        .map(|_| GLYPHS[rng.gen_range(0..GLYPHS.len())].0 as char)
        .collect();
    let image = render(&answer)?;
    Ok(Prepared { answer, image })
}
pub fn save(
    db: &mut rusqlite::Connection,
    token: &str,
    now: i64,
    prepared: Prepared,
) -> Result<Challenge> {
    let Prepared { answer, image } = prepared;
    let ticket = authorize(db, token, now)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    // Recheck after rendering: another request might have completed the ticket.
    authorize(&tx, token, now)?;
    tx.execute("DELETE FROM sender_captcha_v1 WHERE expires<=?1", [now])?;
    ensure!(
        tx.query_row(
            "SELECT COUNT(*) FROM sender_captcha_v1 WHERE ticket!=?1",
            [&ticket],
            |r| r.get::<_, i64>(0)
        )? < 10_000,
        "CAPTCHA capacity exhausted"
    );
    let expires: i64 = tx.query_row(
        "SELECT min(expires,?2) FROM sender_verification_v1 WHERE id=?1",
        params![ticket, now + LIFETIME],
        |r| r.get(0),
    )?;
    let id = uuid::Uuid::new_v4().to_string();
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &signing_secret(&tx)?);
    let mac = ring::hmac::sign(&key, mac_input(&ticket, &id, &answer).as_bytes());
    tx.execute("INSERT INTO sender_captcha_v1 VALUES(?1,?2,?3,?4) ON CONFLICT(ticket) DO UPDATE SET id=excluded.id,answer_mac=excluded.answer_mac,expires=excluded.expires",params![ticket,id,mac.as_ref(),expires])?;
    tx.commit()?;
    Ok(Challenge {
        id,
        image: format!(
            "data:image/png;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(image)
        ),
        expires,
    })
}

/// Caller commits even a wrong answer, so guessing cannot reuse the challenge.
pub(super) fn consume(
    db: &rusqlite::Connection,
    ticket: &str,
    proof: &Answer,
    now: i64,
) -> Result<bool> {
    ensure!(
        proof.id.len() <= 36 && proof.answer.len() <= 32,
        "Invalid CAPTCHA answer"
    );
    let row: Option<(Vec<u8>, i64)> = db
        .query_row(
            "DELETE FROM sender_captcha_v1 WHERE ticket=?1 AND id=?2 RETURNING answer_mac,expires",
            params![ticket, proof.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((mac, expires)) = row else {
        return Ok(false);
    };
    let answer = proof.answer.trim().to_ascii_uppercase();
    if expires <= now
        || answer.len() != 6
        || !answer.bytes().all(|b| GLYPHS.iter().any(|g| g.0 == b))
    {
        return Ok(false);
    }
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &signing_secret(db)?);
    Ok(ring::hmac::verify(&key, mac_input(ticket, &proof.id, &answer).as_bytes(), &mac).is_ok())
}

fn pixel(image: &mut [u8], x: i32, y: i32, color: [u8; 3]) {
    if x >= 0 && y >= 0 && x < WIDTH as i32 && y < HEIGHT as i32 {
        let i = (y as usize * WIDTH as usize + x as usize) * 3;
        image[i..i + 3].copy_from_slice(&color);
    }
}
fn render(answer: &str) -> Result<Vec<u8>> {
    ensure!(answer.len() == 6, "Invalid CAPTCHA length");
    let mut rng = rand::thread_rng();
    let mut image = vec![248u8; WIDTH as usize * HEIGHT as usize * 3];
    // Low contrast noise and curves preserve legibility; glyph geometry varies.
    for _ in 0..700 {
        let x = rng.gen_range(0..WIDTH) as i32;
        let y = rng.gen_range(0..HEIGHT) as i32;
        let c = rng.gen_range(175..235);
        pixel(&mut image, x, y, [c, c, c]);
    }
    for _ in 0..4 {
        let phase = rng.gen_range(0.0..6.0f64);
        let offset = rng.gen_range(15.0..80.0f64);
        for x in 0..WIDTH {
            let y = offset + 9.0 * (f64::from(x) / 30.0 + phase).sin();
            pixel(&mut image, x as i32, y as i32, [170, 180, 195]);
        }
    }
    for (index, letter) in answer.bytes().enumerate() {
        let glyph = GLYPHS
            .iter()
            .find(|g| g.0 == letter)
            .context("Invalid CAPTCHA glyph")?
            .1;
        let angle = rng.gen_range(-0.19..0.19f64);
        let scale = rng.gen_range(4.2..5.2f64);
        let left = 25.0 + index as f64 * 40.0 + rng.gen_range(-3.0..3.0);
        let top = 33.0 + rng.gen_range(-7.0..7.0);
        let phase = rng.gen_range(0.0..6.0f64);
        // Inverse mapping fills the raster without gaps from rotations.
        for y in 8..88 {
            for x in (index as i32 * 40 + 10)..(index as i32 * 40 + 56) {
                let dx = f64::from(x) - left;
                let dy = f64::from(y) - top - 2.0 * (f64::from(x) / 13.0 + phase).sin();
                let gx = ((dx * angle.cos() + dy * angle.sin()) / scale).floor() as i32;
                let gy = ((-dx * angle.sin() + dy * angle.cos()) / scale).floor() as i32;
                if (0..5).contains(&gx)
                    && (0..7).contains(&gy)
                    && glyph[gy as usize] & (1 << (4 - gx)) != 0
                {
                    pixel(&mut image, x, y, [35, 48, 68]);
                }
            }
        }
    }
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, WIDTH, HEIGHT);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&image)?;
        writer.finish()?;
    }
    ensure!(bytes.len() < 128 * 1024, "CAPTCHA image too large");
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn issue(db: &mut rusqlite::Connection, token: &str, now: i64) -> Result<Challenge> {
        save(db, token, now, prepare()?)
    }
    fn fixture() -> (rusqlite::Connection, String, String) {
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(super::super::SCHEMA).unwrap();
        db.execute_batch(SCHEMA).unwrap();
        let tx = db.transaction().unwrap();
        let ticket = super::super::ticket(
            &tx,
            &Settings::default(),
            "sender@example.org",
            "a@example.org",
            100,
        )
        .unwrap()
        .unwrap();
        tx.commit().unwrap();
        db.execute("UPDATE sender_verification_v1 SET armed=1", [])
            .unwrap();
        let token = capability(&db, &ticket).unwrap();
        (db, ticket, token)
    }
    fn known(db: &rusqlite::Connection, ticket: &str, id: &str) -> Answer {
        let answer = "AC234Y";
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &signing_secret(db).unwrap());
        let mac = ring::hmac::sign(&key, mac_input(ticket, id, answer).as_bytes());
        db.execute(
            "UPDATE sender_captcha_v1 SET answer_mac=?2 WHERE id=?1",
            params![id, mac.as_ref()],
        )
        .unwrap();
        Answer {
            id: id.into(),
            answer: answer.into(),
        }
    }
    #[test]
    fn challenge_is_png_bounded_and_contains_no_text_chunks() {
        let bytes = render("AC234Y").unwrap();
        assert!(bytes.len() < 128 * 1024);
        let mut reader = png::Decoder::new(std::io::Cursor::new(&bytes))
            .read_info()
            .unwrap();
        assert_eq!((reader.info().width, reader.info().height), (WIDTH, HEIGHT));
        assert!(
            reader.info().utf8_text.is_empty() && reader.info().uncompressed_latin1_text.is_empty()
        );
        let mut image = vec![0; reader.output_buffer_size().unwrap()];
        reader.next_frame(&mut image).unwrap();
        assert!(image.iter().any(|v| *v < 100));
        assert_ne!(bytes, render("AC234Y").unwrap());
    }
    #[test]
    fn refresh_binding_expiry_wrong_answer_and_replay() {
        let (mut db, ticket, token) = fixture();
        let a = issue(&mut db, &token, 100).unwrap();
        let b = issue(&mut db, &token, 101).unwrap();
        assert_ne!(a.id, b.id);
        assert!(!consume(&db, &ticket, &known(&db, &ticket, &a.id), 102).unwrap());
        let mut proof = known(&db, &ticket, &b.id);
        proof.answer = "wrong".into();
        assert!(!consume(&db, &ticket, &proof, 102).unwrap());
        proof.answer = "AC234Y".into();
        assert!(!consume(&db, &ticket, &proof, 102).unwrap());
        let a = issue(&mut db, &token, 110).unwrap();
        let mut proof = known(&db, &ticket, &a.id);
        assert!(!consume(&db, "another-ticket", &proof, 110).unwrap());
        proof.answer = " ac234y ".into();
        assert!(consume(&db, &ticket, &proof, 111).unwrap());
        assert!(!consume(&db, &ticket, &proof, 111).unwrap());
        let a = issue(&mut db, &token, 120).unwrap();
        let proof = known(&db, &ticket, &a.id);
        assert!(!consume(&db, &ticket, &proof, a.expires).unwrap());
        assert!(issue(&mut db, "invalid", 120).is_err());
        db.execute("UPDATE sender_verification_v1 SET verified=121", [])
            .unwrap();
        assert!(issue(&mut db, &token, 122).is_err());
    }
}
