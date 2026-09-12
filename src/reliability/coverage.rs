//! Bounded aggregates of recorded transport metadata; no message identities.
use crate::{
    engine::Scan,
    protection::{ProviderReport, Status, redirects::Detail},
};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Default, Serialize)]
pub struct Provider {
    messages: usize,
    checked: usize,
    cached: usize,
    omitted: usize,
    requests: usize,
    http_status: BTreeMap<u16, usize>,
    failures: BTreeMap<String, usize>,
    retry_after_max_seconds: u64,
}
impl Provider {
    fn add(&mut self, p: &ProviderReport) {
        self.messages += 1;
        self.checked += p.checked.min(12);
        self.cached += p.cache_hits.min(12);
        self.omitted += p.omitted.min(128);
        self.requests += p.request_count.min(24);
        self.retry_after_max_seconds = self
            .retry_after_max_seconds
            .max(p.retry_after_seconds.unwrap_or(0).min(7 * 86400));
        for (&code, &count) in p
            .http_status_counts
            .iter()
            .filter(|(code, _)| (100..=599).contains(*code))
        {
            *self.http_status.entry(code).or_default() += count.min(24);
        }
        if p.failure_counts.is_empty() {
            if let Some(failure) = p.failure {
                *self
                    .failures
                    .entry(super::fixed_token(failure))
                    .or_default() += 1;
            }
        } else {
            // Fixed vocabulary prevents private or attacker-controlled strings
            // on historical rows from leaking into an aggregate response.
            for (name, count) in &p.failure_counts {
                if serde_json::from_value::<crate::protection::ProviderFailure>(
                    serde_json::Value::String(name.clone()),
                )
                .is_ok()
                {
                    *self.failures.entry(name.clone()).or_default() += (*count).min(24);
                }
            }
        }
    }
}
#[derive(Default, Serialize)]
pub struct Coverage {
    providers: BTreeMap<String, Provider>,
    redirect_details: BTreeMap<String, usize>,
    redirect_categories: BTreeMap<String, usize>,
    redirect_http_status: BTreeMap<u16, usize>,
    redirects_complete: usize,
    redirects_omitted: usize,
}
impl Coverage {
    pub fn add(&mut self, scan: &Scan) {
        let Some(p) = &scan.protection else {
            return;
        };
        for (name, provider) in [("crdf", &p.crdf), ("virustotal", &p.virustotal)] {
            if provider.status != Status::Disabled {
                self.providers.entry(name.into()).or_default().add(provider);
            }
        }
        if let Some(r) = &p.url_resolution {
            self.redirects_omitted += r.omitted.min(128);
            for c in r.chains.iter().take(8) {
                self.redirects_complete += usize::from(c.complete);
                if let Some(d) = &c.detail {
                    *self
                        .redirect_details
                        .entry(super::fixed_token(d))
                        .or_default() += 1;
                    let category = match d {
                        Detail::UnsafeUrl | Detail::ForbiddenAddress => "policy_boundary",
                        Detail::Dns | Detail::Network | Detail::Deadline | Detail::Busy => {
                            "transport"
                        }
                        Detail::BodyLimit
                        | Detail::HopLimit
                        | Detail::ClientScript
                        | Detail::Encoding => "inspection_limit",
                        _ => "remote_response",
                    };
                    *self.redirect_categories.entry(category.into()).or_default() += 1;
                }
                for hop in c
                    .hops
                    .iter()
                    .take(9)
                    .filter(|h| (100..=599).contains(&h.code))
                {
                    *self.redirect_http_status.entry(hop.code).or_default() += 1;
                }
            }
        }
    }
}
#[derive(Default, Serialize)]
pub struct Misses {
    messages: usize,
    classified_legitimate: usize,
    review: usize,
    context: BTreeMap<String, usize>,
}
impl Misses {
    pub fn add(&mut self, scan: &Scan) {
        use crate::fusion::runtime::Outcome;
        let outcome = super::outcome(scan);
        if outcome == Outcome::Unwanted {
            return;
        }
        self.messages += 1;
        self.classified_legitimate += usize::from(outcome == Outcome::Legitimate);
        self.review += usize::from(outcome == Outcome::Undetermined);
        let incomplete = |s: &Status| {
            matches!(
                s,
                Status::Unavailable
                    | Status::Busy
                    | Status::Quota
                    | Status::Limited
                    | Status::Stale
                    | Status::NotConfigured
            )
        };
        for (name, present) in [
            ("analysis_incomplete", !scan.complete),
            (
                "extraction_incomplete",
                scan.features_complete == Some(false),
            ),
            (
                "authentication_unavailable",
                scan.evidence
                    .as_ref()
                    .is_none_or(|e| e.authentication.state != crate::evidence::State::Complete),
            ),
            (
                "provider_incomplete",
                scan.protection.as_ref().is_some_and(|p| {
                    incomplete(&p.crdf.status) || incomplete(&p.virustotal.status)
                }),
            ),
            (
                "redirect_incomplete",
                scan.protection
                    .as_ref()
                    .and_then(|p| p.url_resolution.as_ref())
                    .is_some_and(|r| r.omitted > 0 || r.chains.iter().any(|c| !c.complete)),
            ),
            (
                "decision_disagreement",
                scan.arbitration
                    .as_ref()
                    .is_some_and(|a| a.resolution == crate::decision::Resolution::Disagreement),
            ),
            (
                "corroboration_absent",
                !crate::confirmation::corroborated(scan),
            ),
        ] {
            if present {
                *self.context.entry(name.into()).or_default() += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn recovered_transport_is_counted_without_exposing_provider_text_or_claiming_a_miss() {
        let mut scan = Scan {
            protection: Some(crate::protection::Report {
                crdf: ProviderReport {
                    status: Status::Complete,
                    checked: 2,
                    request_count: 2,
                    http_status_counts: [(503, 1), (200, 1)].into(),
                    failure_counts: [("http".into(), 1), ("PRIVATE_RESPONSE".into(), 42)].into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut coverage = Coverage::default();
        coverage.add(&scan);
        let serialized = serde_json::to_value(coverage).unwrap();
        assert_eq!(serialized["providers"]["crdf"]["requests"], 2);
        assert_eq!(
            serialized["providers"]["crdf"]["failures"],
            json!({"http":1})
        );
        assert!(!serialized.to_string().contains("PRIVATE"));
        // The caller only supplies human-labelled spam to Misses; a captured
        // message cannot be counted as a miss even if its checks were partial.
        scan.decision = Some(crate::fusion::runtime::Decision::legacy(&scan, 95.));
        scan.decision.as_mut().unwrap().outcome = crate::fusion::runtime::Outcome::Unwanted;
        let mut misses = Misses::default();
        misses.add(&scan);
        assert_eq!(misses.messages, 0);
    }
}
