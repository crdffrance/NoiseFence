//! Immutable directory artifacts. Loading/validation happens during policy
//! preparation, never during SMTP or while rendering a message in the console.
use super::directory::{Catalog, Snapshot};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

pub const SCHEMA: &str = "identity-catalog-1";
pub const MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub catalog: PathBuf,
    pub sha256: String,
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            crate::compatibility::valid_hash(&self.sha256),
            "Invalid directory digest"
        );
        ensure!(
            !self.catalog.as_os_str().is_empty(),
            "Directory artifact path is required"
        );
        Ok(())
    }
}

/// The Web settings reference only a digest, never an administrator-supplied
/// filesystem path. An explicit empty selection disables the observation.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub sha256: Option<String>,
    /// Explicit review of the installed directory when replacing or disabling it.
    /// The candidate digest above and ordinary config revision bind both sides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_from: Option<String>,
}
impl Selection {
    /// Resolve a previously committed selection at startup. Review is checked
    /// only at the mutation boundary, not replayed against installation defaults.
    pub(crate) fn resolve(
        &self,
        root: &Path,
        installed: Option<&Settings>,
    ) -> Result<Option<Settings>> {
        ensure!(
            self.reviewed_from
                .as_ref()
                .is_none_or(|h| crate::compatibility::valid_hash(h)),
            "Invalid directory review identity"
        );
        let Some(hash) = &self.sha256 else {
            return Ok(None);
        };
        ensure!(
            crate::compatibility::valid_hash(hash),
            "Invalid directory selection"
        );
        if let Some(current) = installed.filter(|s| &s.sha256 == hash) {
            current.validate()?;
            return Ok(Some(current.clone()));
        }
        let settings = Settings {
            catalog: staged_path(root, hash),
            sha256: hash.clone(),
        };
        Loaded::load(&settings, crate::now())?;
        Ok(Some(settings))
    }
    /// Validate an administrator's change against the current resident policy.
    pub fn apply(&self, root: &Path, installed: Option<&Settings>) -> Result<Option<Settings>> {
        let candidate = self.resolve(root, installed)?;
        if self.sha256.as_deref() == installed.map(|s| s.sha256.as_str()) {
            return Ok(candidate);
        }
        ensure!(
            self.reviewed_from.as_deref() == installed.map(|s| s.sha256.as_str()),
            "Directory review no longer matches the installed snapshot"
        );
        if let (Some(previous), Some(next)) = (installed, candidate.as_ref()) {
            validate_transition(
                &read_document(previous, crate::now())?,
                &read_document(next, crate::now())?,
            )?;
        }
        Ok(candidate)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub schema: String,
    pub sources: Vec<Snapshot>,
}
impl Document {
    pub fn decode(bytes: &[u8], now: i64) -> Result<(Self, Catalog)> {
        ensure!(bytes.len() <= MAX_BYTES, "Directory catalog exceeds 64 MiB");
        let document: Self = serde_json::from_slice(bytes).context("Invalid directory catalog")?;
        let catalog = document.validate(now)?;
        Ok((document, catalog))
    }
    pub fn validate(&self, now: i64) -> Result<Catalog> {
        ensure!(
            self.schema == SCHEMA && self.sources.len() <= 16,
            "Unsupported directory catalog"
        );
        for source in &self.sources {
            ensure!(
                serde_json::to_vec(source)?.len() <= super::directory::MAX_BYTES,
                "Directory source exceeds 16 MiB"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_BYTES,
            "Directory catalog exceeds 64 MiB"
        );
        Catalog::new(self.sources.clone(), now)
    }
}

pub(crate) fn read_document(settings: &Settings, now: i64) -> Result<Document> {
    settings.validate()?;
    let bytes = crate::native_filter::read_bounded(&settings.catalog, MAX_BYTES)?;
    ensure!(
        crate::message::digest(&bytes) == settings.sha256,
        "Directory artifact digest mismatch"
    );
    Ok(Document::decode(&bytes, now)?.0)
}

/// Removing sources requires the exact catalog review in Selection::apply.
/// Reusing a source ID for a different authority is never a permitted refresh.
pub(crate) fn validate_transition(previous: &Document, candidate: &Document) -> Result<()> {
    let next: std::collections::BTreeMap<_, _> = candidate
        .sources
        .iter()
        .map(|s| (&s.source.id, s))
        .collect();
    for old in &previous.sources {
        if let Some(new) = next.get(&old.source.id) {
            ensure!(
                old.source.provider == new.source.provider
                    && old.source.authority == new.source.authority,
                "Changed directory authority requires a new source ID"
            );
            if old != *new {
                ensure!(
                    new.generation > old.generation && new.completed_at >= old.completed_at,
                    "Directory generation rollback"
                );
            }
        }
    }
    Ok(())
}

pub struct Loaded {
    pub sha256: String,
    pub catalog: Catalog,
}
impl Loaded {
    pub fn load(settings: &Settings, now: i64) -> Result<Self> {
        settings.validate()?;
        let bytes = crate::native_filter::read_bounded(&settings.catalog, MAX_BYTES)?;
        ensure!(
            crate::message::digest(&bytes) == settings.sha256,
            "Directory artifact digest mismatch"
        );
        let (_, catalog) = Document::decode(&bytes, now)?;
        Ok(Self {
            sha256: settings.sha256.clone(),
            catalog,
        })
    }
    pub fn inspect(
        &self,
        raw: &[u8],
        recipient: &str,
        evidence: Option<&crate::evidence::Evidence>,
        now: i64,
    ) -> Report {
        Report {
            catalog_sha256: self.sha256.clone(),
            // Conversation history and sensitive-request extraction are not
            // wired yet. Do not manufacture their absence as completed checks.
            relationships_available: false,
            sensitive_requests_available: false,
            observation: super::detection::inspect(
                &self.catalog,
                raw,
                &[recipient.to_owned()],
                evidence,
                &Default::default(),
                None,
                now,
            ),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub catalog_sha256: String,
    pub relationships_available: bool,
    pub sensitive_requests_available: bool,
    pub observation: super::detection::Report,
}

fn staged_path(root: &Path, hash: &str) -> PathBuf {
    root.join("identity/prepared").join(format!("{hash}.json"))
}

/// Persist an already-authorized draft without selecting or activating it.
/// Callers must authenticate and audit the request in the selected management
/// backend. The returned digest is bound to the exact validated bytes.
pub fn prepare(root: &Path, bytes: &[u8], now: i64, reserve: u64) -> Result<Selection> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    Document::decode(bytes, now)?;
    let hash = crate::message::digest(bytes);
    let target = staged_path(root, &hash);
    let parent = target.parent().unwrap();
    for dir in [root.join("identity"), parent.to_path_buf()] {
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&dir) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => ensure!(
                std::fs::symlink_metadata(&dir)?.file_type().is_dir(),
                "Invalid directory artifact folder"
            ),
            Err(e) => return Err(e.into()),
        }
    }
    if target.exists() {
        Loaded::load(
            &Settings {
                catalog: target,
                sha256: hash.clone(),
            },
            now,
        )?;
        return Ok(Selection {
            sha256: Some(hash),
            reviewed_from: None,
        });
    }
    let mut retained_bytes = 0u64;
    let mut retained_count = 0usize;
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        ensure!(
            entry.file_type()?.is_file(),
            "Invalid prepared directory entry"
        );
        retained_count += 1;
        retained_bytes = retained_bytes.saturating_add(metadata.len());
    }
    ensure!(
        retained_count < 32
            && retained_bytes.saturating_add(bytes.len() as u64) <= 128 * 1024 * 1024,
        "Prepared directory capacity reached; remove unused drafts before importing"
    );
    ensure!(
        crate::store::available_bytes(root)? >= reserve.saturating_add(bytes.len() as u64),
        "Insufficient space to prepare directory"
    );
    let temp = parent.join(format!(".prepare-{}", uuid::Uuid::new_v4()));
    let outcome = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        // No replace: concurrent preparations of the same content are harmless;
        // an unexpected existing/corrupt target must not be silently repaired.
        match std::fs::hard_link(&temp, &target) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Loaded::load(
                    &Settings {
                        catalog: target.clone(),
                        sha256: hash.clone(),
                    },
                    now,
                )?;
            }
            Err(e) => return Err(e.into()),
        }
        std::fs::remove_file(&temp)?;
        for directory in [
            parent.to_path_buf(),
            root.join("identity"),
            root.to_path_buf(),
        ] {
            std::fs::File::open(directory)?.sync_all()?;
        }
        Ok(())
    })();
    if outcome.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    outcome?;
    Ok(Selection {
        sha256: Some(hash),
        reviewed_from: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: i64 = 1_800_000_010;
    fn document() -> Document {
        Document {
            schema: SCHEMA.into(),
            sources: vec![
                serde_json::from_str(include_str!("../../tests/fixtures/identity/directory.json"))
                    .unwrap(),
            ],
        }
    }
    #[test]
    fn prepared_bytes_are_durable_private_and_cannot_be_silently_replaced() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let bytes = serde_json::to_vec(&document()).unwrap();
        let selection = prepare(root.path(), &bytes, NOW, 0).unwrap();
        assert_eq!(prepare(root.path(), &bytes, NOW, 0).unwrap(), selection);
        let path = staged_path(root.path(), selection.sha256.as_ref().unwrap());
        let settings = Settings {
            catalog: path.clone(),
            sha256: selection.sha256.clone().unwrap(),
        };
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(Loaded::load(&settings, NOW).is_ok());
        std::fs::write(path, b"corrupted").unwrap();
        assert!(Loaded::load(&settings, NOW).is_err());
        assert!(prepare(root.path(), &bytes, NOW, 0).is_err());
    }
    #[test]
    fn invalid_catalog_never_becomes_a_prepared_candidate() {
        let root = tempfile::tempdir().unwrap();
        let mut doc = document();
        doc.sources.push(doc.sources[0].clone());
        assert!(prepare(root.path(), &serde_json::to_vec(&doc).unwrap(), NOW, 0).is_err());
        assert!(!root.path().join("identity").exists());
        assert!(Document::decode(&vec![b' '; MAX_BYTES + 1], NOW).is_err());
    }
    #[test]
    fn unchanged_selection_pins_immutable_file_and_explicit_empty_disables() {
        let settings = Settings {
            catalog: "/installed/immutable/directory.json".into(),
            sha256: "a".repeat(64),
        };
        let root = Path::new("/unused");
        let selection = Selection {
            sha256: Some(settings.sha256.clone()),
            reviewed_from: None,
        };
        assert_eq!(
            selection.apply(root, Some(&settings)).unwrap(),
            Some(settings.clone())
        );
        assert_eq!(
            Selection {
                sha256: None,
                reviewed_from: Some(settings.sha256.clone())
            }
            .apply(root, Some(&settings))
            .unwrap(),
            None
        );
        assert!(Selection::default().apply(root, Some(&settings)).is_err());
        assert!(
            Selection {
                sha256: Some("../secret".into()),
                reviewed_from: None
            }
            .apply(root, None)
            .is_err()
        );
    }
    #[test]
    fn directory_never_claims_unwired_history_or_requests_are_complete() {
        let (_, catalog) =
            Document::decode(&serde_json::to_vec(&document()).unwrap(), NOW).unwrap();
        let loaded = Loaded {
            sha256: "a".repeat(64),
            catalog,
        };
        let report = loaded.inspect(
            b"From: Alice Finance <unknown@elsewhere.test>\r\n\r\nHello",
            "recipient@example.test",
            None,
            NOW,
        );
        assert!(
            report
                .observation
                .signals
                .contains(&super::super::detection::Signal::ProtectedNameMismatch)
        );
        assert!(!report.relationships_available && !report.sensitive_requests_available);
        assert!(report.observation.observation_only);
        let serialized = serde_json::to_string(&report).unwrap();
        for private in ["Alice", "recipient@", "example-directory", "person-alice"] {
            assert!(!serialized.contains(private));
        }
        assert_eq!(
            loaded
                .inspect(
                    b"From: Alice Finance <unknown@elsewhere.test>\r\n\r\nHello",
                    "other@elsewhere.test",
                    None,
                    NOW
                )
                .observation
                .status,
            "not_configured"
        );
        assert_eq!(
            loaded
                .inspect(
                    b"From: Alice Finance <unknown@elsewhere.test>\r\n\r\nHello",
                    "recipient@example.test",
                    None,
                    NOW + 86400
                )
                .observation
                .status,
            "stale"
        );
    }
}
