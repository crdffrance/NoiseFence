//! Read-only release discovery. This module cannot install or restart anything.
use super::*;
use std::time::Instant;

const RELEASES: &str = "https://github.com/crdffrance/NoiseFence/releases";
const LATEST: &str = "https://api.github.com/repos/crdffrance/NoiseFence/releases/latest";
const CACHE_SECONDS: u64 = 6 * 3600;
const MAX_RESPONSE: usize = 128 * 1024;
pub(super) type Cache = tokio::sync::Mutex<Option<(Instant, Value)>>;

pub(super) fn routes() -> Router<App> {
    Router::new()
        .route("/system/version", get(version))
        .route("/admin/updates/check", post(check))
}
async fn version(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    authenticated(&app, &h).await?;
    let snapshot = app.control.as_ref().map(|control| control.snapshot());
    let static_dir = app.config.web.static_dir.clone();
    let installation = tokio::task::spawn_blocking(move || installed_identity(&static_dir))
        .await
        .unwrap_or_else(|_| json!({"console":null,"deployment":null}));
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "engine_build": env!("NOISEFENCE_DETECTOR_BUILD_SHA256"),
        "node": app.config.hostname,
        "runtime": snapshot.as_ref().map(|s| s.engine.software_identity()),
        "configuration_revision": snapshot.as_ref().map(|s| s.revision),
        "console": installation["console"],
        "deployment": installation["deployment"],
        "releases_url": RELEASES,
        "automatic_installation": false
    })))
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ConsoleIdentity {
    schema: String,
    version: String,
    source_sha256: String,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct DeploymentIdentity {
    schema: String,
    deployed_at: i64,
    engine_version: String,
    engine_build: String,
    console_source_sha256: String,
}
fn bounded_json<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Option<T> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(8193).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= 8192)
        .then(|| serde_json::from_slice(&bytes).ok())
        .flatten()
}
fn installed_identity(web: &std::path::Path) -> Value {
    let console = bounded_json::<ConsoleIdentity>(&web.join("version.json")).filter(|c| {
        c.schema == "noisefence-console-1"
            && artifact_version(&c.version)
            && crate::compatibility::valid_hash(&c.source_sha256)
    });
    // The sidecar is operator-written after a successful activation, outside the
    // immutable release directory. Missing/stale receipts never imply a deployment time.
    let deployment = web
        .parent()
        .and_then(|parent| bounded_json::<DeploymentIdentity>(&parent.join("deployment.json")))
        .filter(|d| {
            d.schema == "noisefence-deployment-1"
                && d.deployed_at > 0
                && d.deployed_at <= now()
                && d.engine_version == env!("CARGO_PKG_VERSION")
                && d.engine_build == env!("NOISEFENCE_DETECTOR_BUILD_SHA256")
                && console
                    .as_ref()
                    .is_some_and(|c| c.source_sha256 == d.console_source_sha256)
        });
    json!({"console":console,"deployment":deployment})
}
async fn check(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    admin::administrator(&app, &h, true).await?;
    // Single-flight and failure caching prevent refresh storms and quota exhaustion.
    let mut cache = app.updates.lock().await;
    if let Some((time, value)) = &*cache
        && time.elapsed() < Duration::from_secs(CACHE_SECONDS)
    {
        return Ok(Json(value.clone()));
    }
    let result = tokio::time::timeout(Duration::from_secs(5), fetch_latest()).await;
    let mut value = match result {
        Ok(Ok(value)) => value,
        _ => json!({"status":"unavailable"}),
    };
    value["checked_at"] = json!(now());
    value["next_check_at"] = json!(now() + CACHE_SECONDS as i64);
    value["releases_url"] = json!(RELEASES);
    *cache = Some((Instant::now(), value.clone()));
    Ok(Json(value))
}
#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}
// Installed identities also include reviewed release candidates. Keep the
// bounded artifact grammar aligned with deploy/postgresql/release_version.py;
// stable release discovery below intentionally uses its narrower contract.
fn artifact_version(raw: &str) -> bool {
    if raw.is_empty() || raw.len() > 64 || !raw.is_ascii() {
        return false;
    }
    let (core, prerelease) = raw
        .split_once('-')
        .map_or((raw, None), |(core, pre)| (core, Some(pre)));
    let numeric = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|c| c.is_ascii_digit())
            && (part.len() == 1 || !part.starts_with('0'))
    };
    core.split('.').count() == 3
        && core.split('.').all(numeric)
        && prerelease.is_none_or(|pre| {
            pre.split('.').all(|part| {
                !part.is_empty()
                    && part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                    && (!part.bytes().all(|c| c.is_ascii_digit()) || numeric(part))
            })
        })
}

// Only compare canonical stable release triplets. Development versions are not
// silently treated as the corresponding published release or as "up to date".
fn stable_version(raw: &str) -> Option<[u64; 3]> {
    let parts = raw.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }
    let mut result = [0; 3];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty()
            || !part.bytes().all(|c| c.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return None;
        }
        result[index] = part.parse().ok()?;
    }
    Some(result)
}
fn compare_release(current: &str, release: Release) -> Result<Value> {
    ensure!(
        !release.draft && !release.prerelease,
        "not a stable release"
    );
    let tag = &release.tag_name;
    let latest = tag.strip_prefix('v').and_then(stable_version);
    let latest = latest.ok_or_else(|| anyhow::anyhow!("invalid stable tag"))?;
    let status = match stable_version(current) {
        Some(installed) if installed < latest => "available",
        Some(installed) if installed > latest => "ahead",
        Some(_) => "same_version",
        None => "development",
    };
    Ok(json!({"status":status,"latest_version":tag,"release_url":format!("{RELEASES}/tag/{tag}")}))
}
async fn fetch_latest() -> Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("NoiseFence-release-check")
        .build()?;
    // Fixed public endpoint, no credentials, configuration, message or user data.
    let mut response = client
        .get(LATEST)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2026-03-10")
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(json!({"status":"no_public_release"}));
    }
    ensure!(response.status().is_success(), "release check failed");
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= MAX_RESPONSE,
            "release metadata too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    compare_release(env!("CARGO_PKG_VERSION"), serde_json::from_slice(&bytes)?)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deployed_version_examples_match_the_packaging_contract() {
        let examples: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/release_versions.json"))
                .unwrap();
        for (group, expected) in [("valid", true), ("invalid", false)] {
            for example in examples[group].as_array().unwrap() {
                let raw = example.as_str().unwrap();
                assert_eq!(artifact_version(raw), expected, "{raw:?}");
            }
        }
        assert!(!artifact_version(&format!("1.0.0-{}", "a".repeat(64))));
    }

    #[test]
    fn deployment_receipts_are_bound_to_both_running_engine_and_installed_console() {
        let dir = tempfile::tempdir().unwrap();
        let web = dir.path().join("web");
        std::fs::create_dir(&web).unwrap();
        let console = json!({"schema":"noisefence-console-1","version":env!("CARGO_PKG_VERSION"),"source_sha256":"a".repeat(64)});
        let mut receipt = json!({"schema":"noisefence-deployment-1","engine_version":env!("CARGO_PKG_VERSION"),"engine_build":env!("NOISEFENCE_DETECTOR_BUILD_SHA256"),"console_source_sha256":"a".repeat(64),"deployed_at":now()-10});
        std::fs::write(web.join("version.json"), console.to_string()).unwrap();
        assert!(installed_identity(&web)["deployment"].is_null());
        let save =
            |v: &Value| std::fs::write(dir.path().join("deployment.json"), v.to_string()).unwrap();
        save(&receipt);
        assert!(installed_identity(&web)["deployment"].is_object());
        receipt["console_source_sha256"] = json!("b".repeat(64));
        save(&receipt);
        assert!(installed_identity(&web)["deployment"].is_null());
        receipt["console_source_sha256"] = console["source_sha256"].clone();
        receipt["engine_build"] = json!("c".repeat(64));
        save(&receipt);
        assert!(installed_identity(&web)["deployment"].is_null());
        std::fs::write(web.join("version.json"), " ".repeat(9000)).unwrap();
        assert!(installed_identity(&web)["console"].is_null());
    }
    fn release(tag: &str) -> Release {
        Release {
            tag_name: tag.into(),
            draft: false,
            prerelease: false,
        }
    }
    #[test]
    fn comparisons_never_confuse_equal_versions_with_verified_build_identity() {
        for (current, latest, expected) in [
            ("0.9.0", "v0.10.0", "available"),
            ("0.29.0", "v0.29.0", "same_version"),
            ("0.30.0", "v0.29.0", "ahead"),
            ("0.30.0-rc.1", "v0.30.0", "development"),
        ] {
            assert_eq!(
                compare_release(current, release(latest)).unwrap()["status"],
                expected
            );
        }
        for tag in [
            "v0.30.0-rc.1",
            "v01.0.0",
            "1.2.3",
            "v1.2.3/../evil",
            "v999999999999999999999.0.0",
        ] {
            assert!(compare_release("0.29.0", release(tag)).is_err());
        }
        let mut draft = release("v1.0.0");
        draft.draft = true;
        assert!(compare_release("0.29.0", draft).is_err());
        let mut prerelease = release("v1.0.0");
        prerelease.prerelease = true;
        assert!(compare_release("0.29.0", prerelease).is_err());
    }
}
