//! Native offline preparation entry point. Fencing evidence is an operator
//! attestation; this command cannot verify a provider power state remotely.
use crate::{
    central::{Central, binding::Binding, bootstrap::Management, outbox::Identity},
    config::Config,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub protocol: String,
    pub operation: String,
    pub database: Binding,
    pub source_configs: Vec<PathBuf>,
    pub credentials_file: PathBuf,
    pub fences: Vec<Fence>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fence {
    pub source: Identity,
    pub method: Method,
    pub reference: String,
    pub created: i64,
    pub fenced: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Method {
    ProviderPoweroff,
    SystemdPersistentCondition,
}

impl Plan {
    pub fn read(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        // SAFETY: geteuid only reads the effective process identity.
        ensure!(
            meta.is_file()
                && meta.len() <= 65536
                && meta.permissions().mode() & 0o077 == 0
                && meta.uid() == unsafe { libc::geteuid() },
            "Recovery plan must be an owner-private regular file of at most 64 KiB"
        );
        let mut bytes = Vec::new();
        (&mut file).take(65537).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 65536, "Recovery plan exceeds limit");
        let plan: Self = serde_json::from_slice(&bytes)?;
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<()> {
        self.database.validate()?;
        ensure!(
            self.protocol == "noisefence-management-recovery-plan-1"
                && uuid::Uuid::parse_str(&self.operation)
                    .is_ok_and(|id| id.to_string() == self.operation),
            "Invalid recovery plan authority"
        );
        ensure!(
            (1..=64).contains(&self.source_configs.len())
                && self.source_configs.len() == self.fences.len()
                && self.source_configs.iter().all(|p| p.is_absolute())
                && self.source_configs.iter().collect::<BTreeSet<_>>().len()
                    == self.source_configs.len()
                && self.credentials_file.is_absolute(),
            "Invalid recovery source paths or count"
        );
        self.fenced_sources()?;
        Ok(())
    }

    fn fenced_sources(&self) -> Result<BTreeMap<String, String>> {
        let mut sources = BTreeMap::new();
        for fence in &self.fences {
            ensure!(
                crate::cluster::valid_id(&fence.source.node)
                    && uuid::Uuid::parse_str(&fence.source.epoch)
                        .is_ok_and(|id| id.to_string() == fence.source.epoch)
                    && fence.fenced
                    && (0..=3600).contains(&crate::now().saturating_sub(fence.created))
                    && !fence.reference.trim().is_empty()
                    && fence.reference.len() <= 500
                    && !fence.reference.chars().any(char::is_control),
                "Missing, invalid or expired source fencing attestation"
            );
            ensure!(
                sources
                    .insert(fence.source.node.clone(), fence.source.epoch.clone())
                    .is_none(),
                "Duplicate source fencing attestation"
            );
        }
        Ok(sources)
    }

    pub(super) fn check_sources(
        &self,
        binding: &Binding,
        operation: &str,
        sources: &BTreeMap<String, String>,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            &self.database == binding
                && self.operation == operation
                && &self.fenced_sources()? == sources,
            "Fencing attestation differs from locked recovery sources"
        );
        Ok(())
    }
}

/// The supervisor must independently establish the attested persistent fences
/// and configure the coordinator source to use the RESTORED PostgreSQL endpoint.
/// No ping, source heartbeat, or successfully acquired local lock proves this.
pub async fn prepare(
    path: &Path,
    verify_worker_installation: bool,
    activate_console: bool,
) -> Result<Value> {
    let plan = Plan::read(path)?;
    let configs = plan
        .source_configs
        .iter()
        .map(|p| Config::load(p))
        .collect::<Result<Vec<_>>>()?;
    let connections = configs
        .iter()
        .filter_map(|c| match &c.management {
            Some(Management::PostgreSql { connection }) => Some(connection),
            _ => None,
        })
        .collect::<Vec<_>>();
    ensure!(
        connections.len() == 1,
        "Recovery requires one explicitly configured PostgreSQL coordinator"
    );
    let central = Central::new_bound(connections[0], &plan.database)?;
    let mut report = tokio::time::timeout(
        std::time::Duration::from_secs(1800),
        central.prepare_recovered_management_inner(
            &configs,
            &plan.operation,
            &plan.credentials_file,
            Some(&plan),
            verify_worker_installation || activate_console,
            activate_console,
        ),
    )
    .await
    .context("Management recovery preparation exceeded 30 minutes; resume the same operation")??;
    report["fencing_attestation_sha256"] =
        Value::String(crate::message::digest(&serde_json::to_vec(&plan)?));
    report["status"] = Value::String(
        if activate_console {
            "console_authorized_not_started"
        } else {
            "prepared_not_activated"
        }
        .into(),
    );
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Value {
        json!({"protocol":"noisefence-management-recovery-plan-1",
            "operation":uuid::Uuid::new_v4().to_string(),
            "database":{"instance":uuid::Uuid::new_v4().to_string(),"source_digest":"a".repeat(64)},
            "source_configs":["/staged/mx1.toml"],"credentials_file":"/private/recovery.json",
            "fences":[{"source":{"node":"mx1","epoch":uuid::Uuid::new_v4().to_string()},
                "method":"provider-poweroff","reference":"provider operation 123",
                "created":crate::now(),"fenced":true}]})
    }

    #[test]
    fn recovery_plan_requires_fresh_exact_fencing_and_private_bounded_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("plan.json");
        let original = fixture();
        let write = |value: &Value| {
            crate::cluster::protocol::private_write(&path, &serde_json::to_vec(value).unwrap())
                .unwrap();
        };
        write(&original);
        let plan = Plan::read(&path).unwrap();
        let sources = plan.fenced_sources().unwrap();
        plan.check_sources(&plan.database, &plan.operation, &sources)
            .unwrap();
        assert!(
            plan.check_sources(&plan.database, &plan.operation, &BTreeMap::new())
                .is_err()
        );
        for (pointer, value) in [
            ("/fences/0/created", json!(crate::now() - 3601)),
            ("/fences/0/created", json!(crate::now() + 60)),
            ("/fences/0/fenced", json!(false)),
            ("/fences/0/method", json!("unreachable")),
            ("/fences/0/reference", json!("")),
            ("/fences/0/reference", json!("bad\nreference")),
            ("/fences/0/source/epoch", json!("bad")),
            ("/source_configs/0", json!("relative.toml")),
            ("/credentials_file", json!("relative.json")),
            ("/operation", json!("bad")),
            ("/protocol", json!("unknown")),
            ("/fences", json!([])),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            write(&changed);
            assert!(
                Plan::read(&path).is_err(),
                "accepted invalid field {pointer}"
            );
        }
        let mut duplicate = original.clone();
        duplicate["source_configs"]
            .as_array_mut()
            .unwrap()
            .push(json!("/staged/mx2.toml"));
        duplicate["fences"]
            .as_array_mut()
            .unwrap()
            .push(original["fences"][0].clone());
        write(&duplicate);
        assert!(Plan::read(&path).is_err());
        write(&original);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Plan::read(&path).is_err());
        write(&original);
        let link = root.path().join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(Plan::read(&link).is_err());
        crate::cluster::protocol::private_write(&path, &vec![b' '; 65537]).unwrap();
        assert!(Plan::read(&path).is_err());
    }
}
