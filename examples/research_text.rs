//! Export bounded Rust text for local encoder experiments; no network or labels.
use anyhow::{Result, ensure};
use std::io::{BufRead, Write};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(args.len() == 3, "usage: research_text MANIFEST ROOT OUTPUT");
    let root = std::fs::canonicalize(&args[1])?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut writer = std::io::BufWriter::new(options.open(&args[2])?);
    let manifest = std::io::BufReader::new(std::fs::File::open(&args[0])?);
    let mut count = 0;
    for line in manifest.lines() {
        let row: serde_json::Value = serde_json::from_str(&line?)?;
        let path = root
            .join(
                row["path"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing path"))?,
            )
            .canonicalize()?;
        ensure!(path.starts_with(&root), "path outside corpus root");
        ensure!(
            std::fs::metadata(&path)?.len() <= 2 * 1024 * 1024,
            "oversized message"
        );
        let raw = std::fs::read(path)?;
        let (subject, body) =
            noisefence::features::text(&raw).ok_or_else(|| anyhow::anyhow!("text unavailable"))?;
        writeln!(
            writer,
            "{}",
            serde_json::json!({
                "raw_sha256": noisefence::message::digest(&raw),
                "subject": subject, "body": body,
                "text_schema": noisefence::features::VERSION
            })
        )?;
        count += 1;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    eprintln!("exported {count} texts");
    Ok(())
}
