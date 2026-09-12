//! Transfer only typed policies and allowlisted data models. No executable or system paths.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub sha256: String,
    pub size: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub protocol: String,
    pub build: String,
    pub revision: i64,
    pub settings: crate::control::Settings,
    pub shared: Value,
    pub files: BTreeMap<String, Artifact>,
    pub digest: String,
}
pub struct Publication {
    pub bundle: Bundle,
    pub paths: BTreeMap<String, PathBuf>,
    pub config: crate::config::Config,
}
const SHARED: &[&str] = &[
    "filter",
    "actions",
    "custom_filtering",
    "fusion",
    "smtp_policy",
    "rbl",
    "antivirus",
    "signatures",
    "llm",
    "vision",
    "protection",
    "mailing",
    "quality",
    "native_filter",
    "domains",
];
pub fn file_digest(path: &Path) -> Result<(u64, String)> {
    let mut file = std::fs::File::open(path)?;
    let size = file.metadata()?.len();
    ensure!(size <= 512 * 1024 * 1024, "Model exceeds 512 MiB");
    let mut digest = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        ensure!(count <= size, "Model changed while hashing");
        digest.update(&buffer[..n]);
    }
    ensure!(count == size, "Model changed while hashing");
    Ok((size, hex::encode(digest.finalize())))
}
fn file_slots(value: &Value) -> Vec<String> {
    let mut paths = vec![
        "/filter/model",
        "/filter/semantic/combination",
        "/fusion/model",
        "/fusion/validation_report",
        "/quality/candidate",
        "/native_filter/bayes_model",
    ]
    .into_iter()
    .map(String::from)
    .collect::<Vec<_>>();
    if let Some(domains) = value
        .pointer("/native_filter/adaptive/domains")
        .and_then(Value::as_object)
    {
        for domain in domains.keys() {
            paths.push(format!("/native_filter/adaptive/domains/{domain}/model"));
        }
    }
    paths.retain(|p| value.pointer(p).is_some_and(Value::is_string));
    paths
}
/// Model files whose bytes must match the resident engine before publication.
pub fn bindings(
    config: &crate::config::Config,
    previous: Option<&BTreeMap<PathBuf, String>>,
) -> Result<BTreeMap<PathBuf, String>> {
    let value = serde_json::to_value(config)?;
    let mut paths = file_slots(&value)
        .into_iter()
        .map(|p| {
            let reuse = p.starts_with("/filter/") || p.starts_with("/native_filter/");
            (
                PathBuf::from(value.pointer(&p).unwrap().as_str().unwrap()),
                reuse,
            )
        })
        .collect::<Vec<_>>();
    if let Some(semantic) = &config.filter.semantic {
        for name in ["config.json", "tokenizer.json", "model.safetensors"] {
            paths.push((semantic.encoder_dir.join(name), true));
        }
    }
    paths
        .into_iter()
        .map(|(path, reuse)| {
            let hash = if reuse {
                previous.and_then(|p| p.get(&path)).cloned()
            } else {
                None
            };
            let hash = match hash {
                Some(h) => h,
                None => file_digest(&path)?.1,
            };
            Ok((path, hash))
        })
        .collect()
}
pub fn capture(
    config: &crate::config::Config,
    settings: crate::control::Settings,
    revision: i64,
) -> Result<Publication> {
    let mut shared = serde_json::to_value(config)?;
    shared
        .as_object_mut()
        .context("Invalid configuration")?
        .retain(|key, _| SHARED.contains(&key.as_str()));
    // Machine-specific credentials, signing identity and compatibility proof stay local.
    for p in [
        "/filter/arc_key",
        "/filter/arc_domain",
        "/filter/arc_selector",
        "/filter/proton_report",
        "/mailing/proton_report",
        "/filter/spamhaus_key_env",
        "/llm/api_key_env",
        "/antivirus/socket",
        "/signatures/socket",
        "/vision/socket",
    ] {
        if let Some(v) = shared.pointer_mut(p) {
            *v = Value::Null;
        }
    }
    let mut files = BTreeMap::new();
    let mut paths = BTreeMap::new();
    for (index, pointer) in file_slots(&shared).into_iter().enumerate() {
        let value = shared.pointer_mut(&pointer).unwrap();
        let path = PathBuf::from(value.as_str().unwrap());
        let name = format!("model-{index}.json");
        let (size, sha256) = file_digest(&path)?;
        files.insert(name.clone(), Artifact { sha256, size });
        paths.insert(name.clone(), path);
        *value = json!(name);
    }
    if let Some(value) = shared.pointer_mut("/filter/semantic/encoder_dir") {
        let root = PathBuf::from(value.as_str().context("Invalid encoder directory")?);
        for name in ["config.json", "tokenizer.json", "model.safetensors"] {
            let path = root.join(name);
            let (size, sha256) = file_digest(&path)?;
            let name = format!("encoder/{name}");
            files.insert(name.clone(), Artifact { sha256, size });
            paths.insert(name, path);
        }
        *value = json!("encoder");
    }
    let mut bundle = Bundle {
        protocol: "noisefence-cluster-1".into(),
        build: env!("CARGO_PKG_VERSION").into(),
        revision,
        settings,
        shared,
        files,
        digest: String::new(),
    };
    bundle.digest = bundle.hash()?;
    Ok(Publication {
        bundle,
        paths,
        config: config.clone(),
    })
}
impl Bundle {
    pub fn hash(&self) -> Result<String> {
        Ok(crate::message::digest(&serde_json::to_vec(
            &json!({"protocol":self.protocol,"build":self.build,"revision":self.revision,"settings":self.settings,"shared":self.shared,"files":self.files}),
        )?))
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol == "noisefence-cluster-1"
                && self.build == env!("CARGO_PKG_VERSION")
                && self.revision >= 0
                && self.digest == self.hash()?,
            "Configuration incompatible ou empreinte invalide."
        );
        ensure!(
            self.shared
                .as_object()
                .is_some_and(|v| v.keys().all(|k| SHARED.contains(&k.as_str())))
                && self.files.len() <= 32,
            "Invalid shared policy"
        );
        let mut total = 0u64;
        for (name, file) in &self.files {
            ensure!(
                valid_name(name)
                    && file.sha256.len() == 64
                    && file
                        .sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && file.size <= 512 * 1024 * 1024,
                "Invalid model manifest"
            );
            total = total.saturating_add(file.size);
        }
        ensure!(total <= 768 * 1024 * 1024, "Model manifest too large");
        Ok(())
    }
}
fn valid_name(name: &str) -> bool {
    [
        "encoder/config.json",
        "encoder/tokenizer.json",
        "encoder/model.safetensors",
    ]
    .contains(&name)
        || name
            .strip_prefix("model-")
            .and_then(|s| s.strip_suffix(".json"))
            .is_some_and(|n| !n.is_empty() && n.len() <= 2 && n.bytes().all(|b| b.is_ascii_digit()))
}
pub fn directory(root: &Path, bundle: &Bundle) -> PathBuf {
    root.join("cluster/models").join(crate::message::digest(
        &serde_json::to_vec(&bundle.files).expect("model manifest"),
    ))
}
pub fn materialize(
    base: &crate::config::Config,
    bundle: &Bundle,
    verify_files: bool,
) -> Result<crate::config::Config> {
    bundle.validate()?;
    let dir = directory(&base.data_dir, bundle);
    let mut shared = bundle.shared.clone();
    for pointer in file_slots(&shared) {
        let value = shared.pointer_mut(&pointer).unwrap();
        let name = value.as_str().unwrap();
        ensure!(bundle.files.contains_key(name), "Unlisted model");
        *value = json!(dir.join(name));
    }
    if let Some(v) = shared.pointer_mut("/filter/semantic/encoder_dir") {
        ensure!(
            v == "encoder"
                && ["config.json", "tokenizer.json", "model.safetensors"]
                    .iter()
                    .all(|n| bundle.files.contains_key(&format!("encoder/{n}"))),
            "Incomplete encoder"
        );
        *v = json!(dir.join("encoder"));
    }
    if verify_files {
        for (name, file) in &bundle.files {
            let (size, hash) = file_digest(&dir.join(name))?;
            ensure!(
                size == file.size && hash == file.sha256,
                "Installed model checksum mismatch"
            );
        }
    }
    let local = serde_json::to_value(base)?;
    let mut full = local.clone();
    for (key, value) in shared.as_object().unwrap() {
        full[key] = value.clone();
    }
    for pointer in [
        "/filter/arc_key",
        "/filter/arc_domain",
        "/filter/arc_selector",
        "/filter/proton_report",
        "/mailing/proton_report",
        "/filter/spamhaus_key_env",
        "/llm/api_key_env",
        "/antivirus/socket",
        "/signatures/socket",
        "/vision/socket",
    ] {
        if let Some(value) = full.pointer_mut(pointer) {
            *value = local.pointer(pointer).cloned().unwrap_or(Value::Null);
        }
    }
    // Optional decoders must be installed locally, never nominated by the coordinator.
    for module in ["vision", "antivirus", "signatures"] {
        ensure!(
            full[module].is_null() || !local[module].is_null(),
            "Service local manquant : {module}"
        );
    }
    if !full["llm"].is_null() && full["llm"]["api_key_env"].is_null() {
        full["llm"]["api_key_env"] = json!("NOISEFENCE_CLUSTER_LLM");
    }
    if bundle.settings.filters.reputation
        && crate::management::key_present(&base.data_dir, "spamhaus")
    {
        full["filter"]["spamhaus_key_env"] = json!("NOISEFENCE_WEB_DQS");
    }
    let mut config: crate::config::Config = serde_json::from_value(full)?;
    config.preferences = bundle.settings.preferences.clone();
    if let Some(rbl) = &config.rbl {
        crate::management::validate_rbl(rbl, base)?;
    }
    config.validate()?;
    Ok(config)
}

/// Retain the active manifest and one preceding generation, never arbitrary paths.
pub fn prune_models(root: &Path, active: &Bundle, previous: Option<&Bundle>) -> Result<()> {
    let parent = root.join("cluster/models");
    if !parent.is_dir() {
        return Ok(());
    }
    let active = directory(root, active);
    let previous = previous.map(|b| directory(root, b));
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry.file_type()?.is_dir()
            && name.len() == 64
            && name.bytes().all(|b| b.is_ascii_hexdigit())
            && entry.path() != active
            && previous.as_ref() != Some(&entry.path())
        {
            std::fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}
