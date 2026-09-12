//! Conservative detector compatibility: all Rust code and runtime data remain bound.
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub fn normalize_manifest(input: &str, lockfile: bool) -> String {
    let mut package = false;
    let mut own = false;
    let mut out = String::new();
    // Cargo.lock puts name before version. Cargo.toml identifies [package] explicitly.
    for line in input.lines() {
        let s = line.trim();
        if s.starts_with('[') {
            package = if lockfile {
                s == "[[package]]"
            } else {
                s == "[package]"
            };
            own = !lockfile && package;
        }
        if lockfile && package && s.starts_with("name = ") {
            own = s == "name = \"noisefence\"";
        }
        if package && own && s.starts_with("version = ") {
            out.push_str("version = \"APPLICATION_RELEASE\"\n");
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

pub fn inputs(root: &Path) -> io::Result<Vec<PathBuf>> {
    fn walk(dir: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            if ty.is_dir() {
                walk(&entry.path(), files)?;
            } else if ty.is_symlink() {
                return Err(io::Error::other("symlink in detector sources"));
            } else if entry
                .path()
                .extension()
                .is_some_and(|s| s == "rs" || s == "sql")
            {
                files.push(entry.path());
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files)?;
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "build_support.rs",
        "research/fusion-protocol.json",
        "research/quality-protocol.json",
        "research/semantic-protocol.json",
        "research/encoder-runtime.lock.json",
        "deploy/vision-worker.py",
        "deploy/update-url-feed.py",
    ] {
        files.push(root.join(path));
    }
    files.sort();
    Ok(files)
}

pub fn fingerprint(root: &Path, files: &[PathBuf], build_context: &str) -> io::Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"noisefence-detector-build-1\0");
    hash.update(build_context.as_bytes());
    for path in files {
        let relative = path.strip_prefix(root).map_err(io::Error::other)?;
        let raw = fs::read(path)?;
        let normalized;
        let bytes = if relative == Path::new("Cargo.toml") || relative == Path::new("Cargo.lock") {
            normalized = normalize_manifest(
                std::str::from_utf8(&raw).map_err(io::Error::other)?,
                relative == Path::new("Cargo.lock"),
            );
            normalized.as_bytes()
        } else {
            &raw
        };
        hash.update(relative.to_string_lossy().replace('\\', "/").as_bytes());
        hash.update([0]);
        hash.update(Sha256::digest(bytes));
    }
    Ok(format!("{:x}", hash.finalize()))
}
