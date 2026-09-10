//! Offline overlap keys robust to CSV punctuation spacing. Never model features.
use anyhow::{Result, ensure};
use regex::Regex;
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::Path,
};

fn canonical(words: &Regex, text: &str) -> String {
    words
        .find_iter(&text.to_lowercase())
        .take(20_000)
        .map(|m| {
            let word = m.as_str();
            if word.chars().all(char::is_numeric) {
                "#".to_owned()
            } else {
                word.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(args.len() == 3, "usage: corpus_keys MANIFEST ROOT OUTPUT");
    let root = Path::new(&args[1]).canonicalize()?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut out = BufWriter::new(options.open(&args[2])?);
    let words = Regex::new(r"[\p{L}\p{N}]+")?;
    let (mut exported, mut skipped) = (0, 0);
    for line in BufReader::new(File::open(&args[0])?).lines() {
        let row: serde_json::Value = serde_json::from_str(&line?)?;
        let path = root
            .join(
                row["path"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing path"))?,
            )
            .canonicalize()?;
        ensure!(
            path.starts_with(&root) && path.is_file(),
            "invalid corpus path"
        );
        let mut raw = Vec::new();
        File::open(path)?
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut raw)?;
        if raw.len() > 2 * 1024 * 1024 {
            skipped += 1;
            continue;
        }
        let Some((subject, body)) = noisefence::features::text(&raw) else {
            skipped += 1;
            continue;
        };
        let text = canonical(&words, &format!("{subject} {body}"));
        writeln!(
            out,
            "{}",
            serde_json::json!({
                "raw_sha256":noisefence::message::digest(&raw),
                "token_campaign":noisefence::message::digest(text.as_bytes()),
                "token_simhash":noisefence::features::simhash(&text)
            })
        )?;
        exported += 1;
    }
    out.flush()?;
    out.get_ref().sync_all()?;
    println!(
        "{}",
        serde_json::json!({"exported":exported,"skipped":skipped})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punctuation_spacing_and_numbers_do_not_hide_csv_overlap() {
        let words = Regex::new(r"[\p{L}\p{N}]+").unwrap();
        assert_eq!(
            canonical(&words, "RE: réunion 123 — L'équipe, test@example.org"),
            canonical(
                &words,
                "re : réunion 789 - l ' équipe , test @ example . org"
            )
        );
    }
}
