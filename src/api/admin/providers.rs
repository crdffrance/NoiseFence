//! Read-only provider status. No upstream probes or credential material.
use super::*;

pub(super) async fn status(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    administrator(&app, &h, false).await?;
    let control = controller(&app)?;
    let snapshot = control.snapshot();
    let settings = snapshot.config.protection.as_ref();
    let base = control.base.protection.as_ref();
    let root = app.store.root.clone();
    let resident_keys = snapshot.config.provider_credentials.clone();
    let bound = snapshot.config.credential_generation.is_some();
    let staged_generation = control.activation_journal().await?.and_then(|j| {
        j.rollout()
            .filter(|r| {
                matches!(
                    r.phase(),
                    crate::cluster::activation::Phase::Preparing
                        | crate::cluster::activation::Phase::Committed
                )
            })
            .and_then(|r| r.candidate().credential_generation.clone())
    });
    let (keys, loaded_keys, pending_keys, usage) =
        tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            use crate::protection::providers::{Provider, quota_usage_with_key, read_key};
            let staged = staged_generation
                .as_deref()
                .map(|h| crate::credentials::generations::load(&root, h))
                .transpose()?;
            let mut saved = json!({});
            let mut loaded = json!({});
            let mut pending = json!({});
            let mut usage = json!({});
            for provider in [Provider::Crdf, Provider::Virustotal] {
                let name = provider.name();
                let current = resident_keys.as_ref().and_then(|keys| keys.get(name));
                let source = if bound || staged.is_some() {
                    staged
                        .as_ref()
                        .map_or(current, |s| s.get(name))
                        .map(str::to_owned)
                } else {
                    read_key(&root, provider).ok()
                };
                saved[name] = json!(source.is_some());
                loaded[name] = json!(current.is_some());
                pending[name] = json!(source.as_deref() != current);
                usage[name] = json!(quota_usage_with_key(&root, provider, current).ok());
            }
            Ok((saved, loaded, pending, usage))
        })
        .await
        .map_err(|_| {
            Error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Provider status is unavailable.".into(),
            )
        })??;
    let cfg = &snapshot.config;
    let budget_path = app.store.root.join("llm-budget.sqlite3");
    let budget_maximum = cfg.llm.as_ref().map_or(0, |c| c.monthly_budget_micro_eur);
    let llm_budget = tokio::task::spawn_blocking(move || {
        crate::llm::budget_status::read(&budget_path, budget_maximum).ok()
    })
    .await
    .map_err(anyhow::Error::from)?;
    use crate::protection::Provider;
    Ok(Json(json!({
        "checked_at":now(), "hostname":cfg.hostname,
        "node_id":cfg.cluster.as_ref().map(|c| &c.node_id),
        "cluster_role":cfg.cluster.as_ref().map(|c| c.role),
        "policy":settings.map(|s|json!({"crdf":s.policy.crdf,"virustotal":s.policy.virustotal,"follow_urls":s.policy.follow_urls})),
        "services":{
            "llm":{
                "installed":control.base.llm.is_some(), "enabled":cfg.llm.is_some(),
                "configuration":cfg.llm.as_ref().map(|s|json!({"model":s.model,"monthly_budget_micro_eur":s.monthly_budget_micro_eur,"pricing_checked_at":s.pricing_checked_at,"max_text_bytes":s.max_text_bytes,"timeout_ms":s.timeout_ms,"max_parallel":s.max_parallel,"score_low":s.score_low,"score_high":s.score_high,"review_unconfirmed_high":s.review_unconfirmed_high})),
                "budget":llm_budget
            },
            "rspamd":cfg.rspamd.as_ref().map(|s|json!({"enabled":s.enabled,"sample_percent":s.sample_percent,"timeout_ms":s.timeout_ms,"max_parallel":s.max_parallel})),
            "rbl":cfg.rbl.as_ref().map(|s|json!({"enabled_lists":s.lists.iter().filter(|l|l.enabled).count(),"action":s.action,"timeout_ms":s.timeout_ms,"max_parallel":s.max_parallel}))
        },
        "available":base.is_some(), "enabled":settings.is_some(), "revision":snapshot.revision,
        "keys":keys, "loaded_keys":loaded_keys, "pending_keys":pending_keys, "observation_only":true, "usage":usage,
        "quotas":settings.map(|s|json!({"crdf":s.quota(Provider::Crdf,&s.policy),"virustotal":s.quota(Provider::Virustotal,&s.policy)})),
        "bootstrap_quotas":base.map(|s|json!({"crdf":s.bootstrap_quota(Provider::Crdf),"virustotal":s.bootstrap_quota(Provider::Virustotal)})),
        "capacity":settings.map(|s|json!({"timeout_ms":s.timeout_ms,"max_parallel":s.max_parallel,"max_indicators":12}))
    })))
}
