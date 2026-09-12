//! Web-editable detector parameters. Deployment paths and secret references never enter patches.
use crate::config::Config;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Detection {
    pub modules: BTreeMap<String, Value>,
}
const LLM: &[&str] = &[
    "model",
    "project_id",
    "monthly_budget_micro_eur",
    "input_micro_eur_per_million",
    "output_micro_eur_per_million",
    "pricing_checked_at",
    "timeout_ms",
    "max_text_bytes",
    "max_output_tokens",
    "score_low",
    "score_high",
    "review_unconfirmed_high",
    "max_parallel",
];
const VISION: &[&str] = &[
    "timeout_ms",
    "max_parallel",
    "max_parts",
    "max_part_bytes",
    "max_total_bytes",
    "max_pixels",
    "max_pages",
    "max_text_chars",
    "max_codes",
];
const SMTP: &[&str] = &[
    "timeout_ms",
    "max_parallel",
    "cache_entries",
    "cache_ttl_seconds",
];
const PROTECTION: &[&str] = &["timeout_ms", "max_parallel", "url_resolution"];
const NATIVE: &[&str] = &[
    "max_bytes",
    "max_parallel",
    "timeout_ms",
    "fuzzy_memory",
    "content_rules",
    "patterns",
    "composites",
    "caps",
];
fn select<T: Serialize>(value: &T, keys: &[&str]) -> Value {
    let mut value = serde_json::to_value(value).expect("serializable configuration");
    value
        .as_object_mut()
        .unwrap()
        .retain(|k, _| keys.contains(&k.as_str()));
    value
}
fn patch<T: Serialize + DeserializeOwned>(
    base: &mut T,
    value: &Value,
    keys: &[&str],
) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Paramètres de moteur invalides."))?;
    ensure!(
        object.keys().all(|k| keys.contains(&k.as_str())),
        "Paramètre non modifiable depuis cette interface."
    );
    let mut full = serde_json::to_value(&*base)?;
    for (key, value) in object {
        full[key] = value.clone();
    }
    *base = serde_json::from_value(full)?;
    Ok(())
}
impl Detection {
    pub fn from_config(c: &Config) -> Self {
        let mut modules = BTreeMap::from([(
            "analysis".into(),
            json!({"max_bytes":c.filter.max_analysis_bytes}),
        )]);
        if let Some(s) = &c.protection {
            modules.insert("protection".into(), select(s, PROTECTION));
        }
        if let Some(s) = &c.llm {
            modules.insert("llm".into(), select(s, LLM));
        }
        if let Some(s) = &c.vision {
            modules.insert("vision".into(), select(s, VISION));
        }
        if let Some(s) = &c.smtp_policy {
            modules.insert("smtp_policy".into(), select(s, SMTP));
        }
        if let Some(s) = &c.native_filter {
            let mut value = select(s, NATIVE);
            value["enabled"] = json!(true);
            modules.insert("native".into(), value);
        }
        Self { modules }
    }
    pub fn apply(&self, c: &mut Config) -> Result<()> {
        for (name, value) in &self.modules {
            ensure!(
                Self::from_config(c).modules.contains_key(name),
                "Moteur non installé : {name}"
            );
            match name.as_str() {
                "analysis" => {
                    ensure!(
                        value
                            .as_object()
                            .is_some_and(|o| o.len() == 1 && o.contains_key("max_bytes")),
                        "Limite d’analyse invalide."
                    );
                    let n = value["max_bytes"]
                        .as_u64()
                        .ok_or_else(|| anyhow::anyhow!("Limite d’analyse invalide."))?;
                    ensure!(
                        (1024..=8 * 1024 * 1024).contains(&n),
                        "Analyse : 1 Kio à 8 Mio."
                    );
                    c.filter.max_analysis_bytes = n as usize;
                }
                "protection" => {
                    if let Some(s) = &mut c.protection {
                        patch(s, value, PROTECTION)?;
                        s.validate()?;
                    }
                }
                "llm" => {
                    if let Some(s) = &mut c.llm {
                        patch(s, value, LLM)?;
                        s.validate()?;
                    }
                }
                "vision" => {
                    if let Some(s) = &mut c.vision {
                        patch(s, value, VISION)?;
                        s.validate()?;
                    }
                }
                "smtp_policy" => {
                    if let Some(s) = &mut c.smtp_policy {
                        patch(s, value, SMTP)?;
                        s.validate()?;
                    }
                }
                "native" => {
                    if let Some(s) = &mut c.native_filter {
                        let mut values = value.clone();
                        let enabled = values
                            .as_object_mut()
                            .and_then(|v| v.remove("enabled"))
                            .unwrap_or(json!(true));
                        ensure!(enabled.is_boolean(), "Activation du moteur natif invalide.");
                        patch(s, &values, NATIVE)?;
                        s.validate()?;
                        if enabled == json!(false) {
                            c.native_filter = None;
                        }
                    }
                }
                _ => anyhow::bail!("Moteur inconnu : {name}"),
            }
        }
        Ok(())
    }
}
/// A Web patch may reuse a declared credential only with its original destination.
pub fn validate_rbl(settings: &crate::rbl::Settings, base: &Config) -> Result<()> {
    settings.validate()?;
    for list in &settings.lists {
        if list.key_env.is_some() {
            ensure!(
                base.rbl.as_ref().is_some_and(|b| b
                    .lists
                    .iter()
                    .any(|l| l.key_env == list.key_env
                        && l.zone == list.zone
                        && l.provider == list.provider)),
                "Une clé RBL ne peut être utilisée que pour son fournisseur configuré."
            );
        }
    }
    Ok(())
}

pub const WEB_DQS: &str = "NOISEFENCE_WEB_DQS";
fn key_path(root: &std::path::Path, provider: &str) -> Result<std::path::PathBuf> {
    ensure!(
        matches!(provider, "spamhaus" | "scaleway"),
        "Fournisseur inconnu."
    );
    Ok(root.join("credentials").join(format!("{provider}.key")))
}
pub fn read_key(root: &std::path::Path, provider: &str) -> Result<Option<String>> {
    match std::fs::read_to_string(key_path(root, provider)?) {
        Ok(key) => Ok(Some(key)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
pub fn key_present(root: &std::path::Path, provider: &str) -> bool {
    key_path(root, provider).is_ok_and(|p| p.is_file())
}
pub fn save_key(root: &std::path::Path, provider: &str, key: &str) -> Result<()> {
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    let destination = key_path(root, provider)?;
    ensure!(
        (16..=256).contains(&key.len())
            && key.bytes().all(|b| if provider == "spamhaus" {
                b.is_ascii_alphanumeric()
            } else {
                b.is_ascii_graphic()
            }),
        "Format de clé fournisseur invalide."
    );
    let folder = destination.parent().unwrap();
    std::fs::create_dir_all(folder)?;
    std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700))?;
    let temp = folder.join(format!(".key-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        f.write_all(key.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&temp, &destination)?;
        std::fs::File::open(folder)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}
pub fn dqs_key(config: &Config) -> Result<Option<String>> {
    let Some(env) = &config.filter.spamhaus_key_env else {
        return Ok(None);
    };
    let key = match read_key(&config.data_dir, "spamhaus")? {
        Some(key) => key,
        None => {
            std::env::var(env).map_err(|_| anyhow::anyhow!("Clé Spamhaus DQS indisponible."))?
        }
    };
    ensure!(
        !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric()),
        "Clé DQS invalide."
    );
    Ok(Some(key))
}
