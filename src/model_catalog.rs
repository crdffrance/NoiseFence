//! Explicit, model-only retention. Catalog files are separate from rollout caches
//! and never carry provider credentials, recipient policies or message contents.
use crate::{cluster::artifacts, config::Config, control::Settings};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub const MAX_SETS: usize = 16;
pub const MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const SCHEMA: &str = "noisefence-model-catalog-1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub schema: String,
    pub id: String,
    pub label: String,
    pub created: i64,
    pub source_build: String,
    pub source_revision: i64,
    pub files: BTreeMap<String, artifacts::Artifact>,
    pub quality_candidate: Option<crate::quality::workflow::Selection>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub id: String,
    pub sha256: String,
}
impl Selection {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            valid_id(&self.id) && valid_id(&self.sha256),
            "Invalid retained model selection"
        );
        Ok(())
    }
}
fn valid_id(id: &str) -> bool {
    crate::compatibility::valid_hash(id)
}
fn parent(root: &Path) -> PathBuf {
    root.join("cluster/model-catalog")
}
fn regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "Catalog input is not a regular file"
    );
    Ok(file)
}
fn directory(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_dir(),
        "Catalog directory is not a real directory"
    );
    Ok(())
}
fn create_directory(path: &Path) -> Result<()> {
    if !path.try_exists()? {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    directory(path)
}
fn slot_valid(slot: &str) -> bool {
    matches!(
        slot,
        "/filter/model"
            | "/filter/semantic/combination"
            | "/fusion/model"
            | "/fusion/validation_report"
            | "/quality/candidate"
            | "/native_filter/bayes_model"
    ) || slot
        .strip_prefix("/filter/semantic/encoder/")
        .is_some_and(|s| matches!(s, "config.json" | "tokenizer.json" | "model.safetensors"))
        || slot
            .strip_prefix("/native_filter/adaptive/domains/")
            .and_then(|s| s.strip_suffix("/model"))
            .is_some_and(crate::config::valid_domain)
}
impl Entry {
    fn identity(&self) -> Result<String> {
        Ok(crate::message::digest(&serde_json::to_vec(&(
            SCHEMA,
            &self.source_build,
            &self.files,
            &self.quality_candidate,
        ))?))
    }
    pub fn bytes(&self) -> u64 {
        self.files.values().map(|f| f.size).sum()
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA && valid_id(&self.id) && self.id == self.identity()?,
            "Invalid catalog identity"
        );
        ensure!(
            !self.label.trim().is_empty()
                && self.label.len() <= 80
                && !self.label.chars().any(char::is_control),
            "Invalid catalog label"
        );
        ensure!(
            self.created > 0
                && self.source_revision >= 0
                && !self.source_build.is_empty()
                && self.source_build.len() <= 64,
            "Invalid catalog provenance"
        );
        ensure!(
            !self.files.is_empty()
                && self.files.len() <= 32
                && self.files.iter().all(|(slot, f)| slot_valid(slot)
                    && valid_id(&f.sha256)
                    && f.size <= 512 * 1024 * 1024),
            "Invalid catalog files"
        );
        ensure!(
            self.bytes() <= 768 * 1024 * 1024,
            "Catalog set exceeds 768 MiB"
        );
        let encoder = self
            .files
            .keys()
            .filter(|s| s.starts_with("/filter/semantic/encoder/"))
            .count();
        ensure!(encoder == 0 || encoder == 3, "Incomplete retained encoder");
        if let Some(selection) = &self.quality_candidate {
            selection.path(Path::new("/unused"))?;
            ensure!(
                selection.sha256.as_ref()
                    == self.files.get("/quality/candidate").map(|f| &f.sha256),
                "Retained shadow selection mismatch"
            );
        }
        Ok(())
    }
    fn file_path(&self, dir: &Path, slot: &str) -> Result<PathBuf> {
        let file = self
            .files
            .get(slot)
            .context("Model slot absent from retained set")?;
        Ok(
            if let Some(name) = slot.strip_prefix("/filter/semantic/encoder/") {
                dir.join("encoder").join(name)
            } else {
                dir.join(&file.sha256)
            },
        )
    }
    pub fn verify(&self, root: &Path) -> Result<()> {
        self.validate()?;
        let dir = parent(root).join(&self.id);
        directory(&root.join("cluster"))?;
        directory(&parent(root))?;
        directory(&dir)?;
        for (slot, expected) in &self.files {
            let path = self.file_path(&dir, slot)?;
            directory(path.parent().unwrap())?;
            let mut file = regular(&path)?;
            ensure!(
                file.metadata()?.len() == expected.size,
                "Retained model size mismatch"
            );
            let mut hash = Sha256::new();
            let mut bytes = 0u64;
            let mut buffer = [0; 65536];
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                bytes += n as u64;
                ensure!(bytes <= expected.size, "Retained model changed");
                hash.update(&buffer[..n]);
            }
            ensure!(
                bytes == expected.size && hex::encode(hash.finalize()) == expected.sha256,
                "Retained model checksum mismatch"
            );
        }
        Ok(())
    }
    pub fn qualification(&self, root: &Path) -> serde_json::Value {
        let dir = parent(root).join(&self.id);
        let fusion = if !self.files.contains_key("/fusion/model") {
            "not_applicable"
        } else if !self.files.contains_key("/fusion/validation_report") {
            "missing"
        } else {
            let result = (|| -> Result<()> {
                self.verify(root)?;
                let (model, hash) =
                    crate::fusion::Model::load_bound(&self.file_path(&dir, "/fusion/model")?)?;
                crate::fusion::runtime::Validation::load(
                    &self.file_path(&dir, "/fusion/validation_report")?,
                )?
                .validate(&model, &hash, crate::now())
            })();
            if result.is_ok() {
                "report_contract_valid"
            } else {
                "invalid_or_stale"
            }
        };
        json!({"whole_pipeline":"not_evaluated","fusion_validation":fusion})
    }
    /// Bind only requested model slots. Policies, credentials and installation
    /// capabilities come from the current draft and current runtime.
    pub fn effective(&self, base: &Config, settings: &Settings) -> Result<Config> {
        self.verify(&base.data_dir)?;
        ensure!(
            settings.quality_candidate == self.quality_candidate,
            "Preview the retained shadow selection before saving"
        );
        let dir = parent(&base.data_dir).join(&self.id);
        let mut base = base.clone();
        base.quality = Some(crate::quality::Settings {
            candidate: self
                .files
                .get("/quality/candidate")
                .map(|_| self.file_path(&dir, "/quality/candidate"))
                .transpose()?,
        });
        let config = settings.effective_catalog(&base)?;
        let mut value = serde_json::to_value(&config)?;
        for slot in artifacts::file_slots(&value) {
            *value.pointer_mut(&slot).unwrap() = json!(self.file_path(&dir, &slot)?);
        }
        if let Some(target) = value.pointer_mut("/filter/semantic/encoder_dir") {
            ensure!(
                self.files
                    .keys()
                    .filter(|s| s.starts_with("/filter/semantic/encoder/"))
                    .count()
                    == 3,
                "Selected set has no complete encoder"
            );
            *target = json!(dir.join("encoder"));
        }
        let mut result: Config = serde_json::from_value(value)?;
        result.credential_generation = config.credential_generation;
        result.provider_credentials = config.provider_credentials;
        result.preferences = config.preferences;
        result.console_only = config.console_only;
        result.validate()?;
        Ok(result)
    }
}
pub fn load(root: &Path, id: &str) -> Result<Entry> {
    ensure!(valid_id(id), "Invalid catalog identifier");
    let dir = parent(root).join(id);
    directory(&root.join("cluster"))?;
    directory(&parent(root))?;
    directory(&dir)?;
    let mut bytes = Vec::new();
    regular(&dir.join("manifest.json"))?
        .take(32 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 32 * 1024, "Catalog manifest too large");
    let entry: Entry = serde_json::from_slice(&bytes)?;
    entry.validate()?;
    ensure!(entry.id == id, "Catalog directory identity mismatch");
    Ok(entry)
}
pub fn list(root: &Path) -> Result<Vec<Entry>> {
    let dir = parent(root);
    if !dir.try_exists()? {
        return Ok(Vec::new());
    }
    directory(&root.join("cluster"))?;
    directory(&dir)?;
    let mut entries = Vec::new();
    for file in fs::read_dir(dir)? {
        let file = file?;
        let id = file.file_name().to_string_lossy().into_owned();
        if valid_id(&id) {
            ensure!(entries.len() < MAX_SETS, "Catalog entry limit exceeded");
            entries.push(load(root, &id)?);
        }
    }
    entries.sort_by(|a, b| b.created.cmp(&a.created).then(a.id.cmp(&b.id)));
    Ok(entries)
}
/// Caller serializes catalog mutations with rollout preparation. Staging copies
/// exact model bytes into ordinary rollout storage before journal publication.
pub fn retain(
    root: &Path,
    publication: &artifacts::Publication,
    label: String,
    reserve: u64,
) -> Result<Entry> {
    let mut entry = Entry {
        schema: SCHEMA.into(),
        id: String::new(),
        label,
        created: crate::now(),
        source_build: publication.bundle.build.clone(),
        source_revision: publication.bundle.revision,
        files: artifacts::model_manifest(&publication.bundle)?,
        quality_candidate: publication.bundle.settings.quality_candidate.clone(),
    };
    entry.id = entry.identity()?;
    entry.validate()?;
    create_directory(&root.join("cluster"))?;
    create_directory(&parent(root))?;
    let existing = list(root)?;
    if let Some(saved) = existing.iter().find(|e| e.id == entry.id) {
        saved.verify(root)?;
        return Ok(saved.clone());
    }
    ensure!(
        existing.len() < MAX_SETS
            && existing
                .iter()
                .map(Entry::bytes)
                .sum::<u64>()
                .saturating_add(entry.bytes())
                <= MAX_BYTES,
        "Model catalog capacity reached; remove an unused retained set"
    );
    ensure!(
        crate::store::available_bytes(root)? >= reserve.saturating_add(entry.bytes()),
        "Insufficient space for retained models"
    );
    let temp = parent(root).join(format!(".stage-{}", uuid::Uuid::new_v4()));
    create_directory(&temp)?;
    let result = (|| -> Result<()> {
        for (slot, expected) in &entry.files {
            let dest = entry.file_path(&temp, slot)?;
            if dest.try_exists()? {
                continue;
            }
            if dest.parent().unwrap() != temp {
                create_directory(dest.parent().unwrap())?;
            }
            let name = publication
                .bundle
                .files
                .iter()
                .find(|(_, f)| f.sha256 == expected.sha256 && f.size == expected.size)
                .map(|(n, _)| n)
                .context("Missing captured model")?;
            let mut source = regular(
                publication
                    .paths
                    .get(name)
                    .context("Missing captured model path")?,
            )?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&dest)?;
            let mut hash = Sha256::new();
            let mut copied = 0u64;
            let mut buffer = [0; 65536];
            loop {
                let n = source.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                copied += n as u64;
                ensure!(copied <= expected.size, "Model changed during retention");
                hash.update(&buffer[..n]);
                output.write_all(&buffer[..n])?;
            }
            ensure!(
                copied == expected.size && hex::encode(hash.finalize()) == expected.sha256,
                "Model changed during retention"
            );
            output.sync_all()?;
            File::open(dest.parent().unwrap())?.sync_all()?;
        }
        let mut manifest = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temp.join("manifest.json"))?;
        manifest.write_all(&serde_json::to_vec(&entry)?)?;
        manifest.sync_all()?;
        File::open(&temp)?.sync_all()?;
        fs::rename(&temp, parent(root).join(&entry.id))?;
        File::open(parent(root))?.sync_all()?;
        File::open(root.join("cluster"))?.sync_all()?;
        File::open(root)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temp);
    }
    result?;
    Ok(entry)
}
pub fn remove(root: &Path, id: &str) -> Result<()> {
    ensure!(valid_id(id), "Invalid catalog identifier");
    directory(&root.join("cluster"))?;
    directory(&parent(root))?;
    let dir = parent(root).join(id);
    directory(&dir)?;
    fs::remove_dir_all(dir)?;
    File::open(parent(root))?.sync_all()?;
    Ok(())
}
