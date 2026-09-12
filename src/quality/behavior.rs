//! Private, bounded sender context. Only authenticated, human-labelled history
//! is eligible. Novelty is an observation, never a score or a trust exemption.
use crate::{config::Recipient, engine::Scan, message::digest, protection::Targets};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub status: String,
    pub sample: Option<Sample>,
    pub campaigns: usize,
    pub days: usize,
    pub new_recipient: bool,
    pub new_link_domain: bool,
    pub new_request: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub protocol: String,
    pub policy: String,
    pub recipient: String,
    pub links: BTreeSet<String>,
    pub requests: BTreeSet<String>,
}
const REQUESTS: [&str; 6] = [
    "NF_URGENCY",
    "NF_CREDENTIALS",
    "NF_FINANCIAL",
    "NF_WALLET_SECRET",
    "NF_FORM",
    "NF_UNSUBSCRIBE",
];
impl Sample {
    fn valid(&self) -> bool {
        self.protocol == "sender-behavior-1"
            && crate::compatibility::valid_hash(&self.policy)
            && crate::compatibility::valid_hash(&self.recipient)
            && self.links.len() <= 8
            && self
                .links
                .iter()
                .all(|s| crate::compatibility::valid_hash(s))
            && self.requests.iter().all(|s| REQUESTS.contains(&s.as_str()))
    }
}
pub fn capture(key: &str, scan: &Scan, recipients: &[Recipient], targets: &Targets) -> Report {
    let unavailable = || Report {
        status: "unavailable".into(),
        ..Default::default()
    };
    // Do not retain or publish another envelope recipient's identity on a
    // shared message. Multi-recipient SMTP transactions explicitly abstain.
    if recipients.len() != 1
        || targets.urls_truncated
        || targets.urls.len() > 8
        || !scan.features_complete.unwrap_or(false)
        || !scan
            .protection
            .as_ref()
            .is_some_and(|p| p.local_status == crate::protection::Status::Complete)
    {
        return unavailable();
    }
    let Some(native) = scan
        .native_filter
        .as_ref()
        .filter(|n| n.report.status == crate::native_filter::Status::Complete)
    else {
        return unavailable();
    };
    let recipient = &recipients[0].address;
    if recipient.len() > 320 || recipient.chars().any(char::is_control) {
        return unavailable();
    }
    let mut links = BTreeSet::new();
    for value in &targets.urls {
        let Ok(url) = reqwest::Url::parse(value) else {
            return unavailable();
        };
        let Some(host) = url.host_str().filter(|h| {
            h.contains('.') && !h.ends_with('.') && h.parse::<std::net::IpAddr>().is_err()
        }) else {
            return unavailable();
        };
        links.insert(digest(
            format!("behavior-link-1\0{key}\0{}", host.to_ascii_lowercase()).as_bytes(),
        ));
    }
    let sample = Sample {
        protocol: "sender-behavior-1".into(),
        policy: native.report.policy_sha256.clone(),
        recipient: digest(format!("behavior-recipient-1\0{key}\0{recipient}").as_bytes()),
        links,
        requests: native
            .local_symbols
            .iter()
            .filter(|s| REQUESTS.contains(&s.id.as_str()))
            .map(|s| s.id.clone())
            .collect(),
    };
    if !sample.valid() {
        return unavailable();
    }
    Report {
        status: "insufficient_history".into(),
        sample: Some(sample),
        ..Default::default()
    }
}

#[derive(Default)]
pub(super) struct History {
    // One campaign gets one vote even after multiple deliveries or corrections.
    rows: BTreeMap<String, Campaign>,
}
#[derive(Default)]
struct Campaign {
    legitimate: bool,
    unwanted: bool,
    limited: bool,
    samples: Vec<(i64, Sample)>,
}
impl History {
    pub fn add(
        &mut self,
        fingerprint: String,
        created: i64,
        legit: bool,
        spam: bool,
        serialized: Option<String>,
    ) {
        let entry = self.rows.entry(fingerprint).or_default();
        entry.legitimate |= legit;
        entry.unwanted |= spam;
        if let Some(serialized) = serialized.filter(|s| s.len() <= 4096)
            && let Ok(sample) = serde_json::from_str::<Sample>(&serialized)
            && sample.valid()
        {
            if entry.samples.len() < 16 {
                entry.samples.push((created / 86400, sample));
            } else {
                entry.limited = true;
            }
        }
    }
    pub fn finish(self, report: &mut Report) {
        let Some(current) = &report.sample else {
            return;
        };
        let mut recipients = BTreeSet::new();
        let mut links = BTreeSet::new();
        let mut requests = BTreeSet::new();
        let mut days = BTreeSet::new();
        for Campaign {
            legitimate,
            unwanted,
            limited,
            samples,
        } in self.rows.into_values()
        {
            if !legitimate || unwanted || limited {
                continue;
            }
            let mut accepted = false;
            for (date, sample) in samples
                .into_iter()
                .filter(|(_, s)| s.policy == current.policy && s.protocol == current.protocol)
            {
                accepted = true;
                days.insert(date);
                recipients.insert(sample.recipient);
                links.extend(sample.links);
                requests.extend(sample.requests);
            }
            if accepted {
                report.campaigns += 1;
            }
        }
        report.days = days.len();
        if report.campaigns >= 5 && report.days >= 3 {
            report.status = "complete".into();
            report.new_recipient = !recipients.contains(&current.recipient);
            report.new_link_domain = current.links.iter().any(|l| !links.contains(l));
            report.new_request = current.requests.iter().any(|r| !requests.contains(r));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Sample {
        Sample {
            protocol: "sender-behavior-1".into(),
            policy: digest(b"policy"),
            recipient: digest(b"alice"),
            links: [digest(b"known-link")].into(),
            requests: ["NF_FINANCIAL".into()].into(),
        }
    }
    fn history(samples: Vec<(String, bool, bool, Sample)>) -> History {
        let mut h = History::default();
        for (i, (campaign, legit, spam, s)) in samples.into_iter().enumerate() {
            h.add(
                campaign,
                i as i64 * 86400,
                legit,
                spam,
                Some(serde_json::to_string(&s).unwrap()),
            );
        }
        h
    }
    #[test]
    fn novelty_needs_five_confirmed_distinct_campaigns_three_days_and_matching_policy() {
        let mut current = sample();
        current.recipient = digest(b"bob");
        current.links.insert(digest(b"new-link"));
        current.requests.insert("NF_CREDENTIALS".into());
        let initial = Report {
            status: "insufficient_history".into(),
            sample: Some(current),
            ..Default::default()
        };
        let rows = (0..5)
            .map(|i| (format!("c{i}"), true, false, sample()))
            .collect::<Vec<_>>();
        let mut report = initial.clone();
        history(rows.clone()).finish(&mut report);
        assert_eq!(report.status, "complete");
        assert!(report.new_recipient && report.new_link_domain && report.new_request);
        for mode in ["conflict", "duplicate", "policy", "unlabelled"] {
            let mut changed = rows.clone();
            for row in &mut changed {
                match mode {
                    "conflict" => row.2 = true,
                    "duplicate" => row.0 = "one".into(),
                    "policy" => row.3.policy = digest(b"another policy"),
                    "unlabelled" => row.1 = false,
                    _ => unreachable!(),
                }
            }
            let mut report = initial.clone();
            history(changed).finish(&mut report);
            assert_eq!(report.status, "insufficient_history");
            assert!(!report.new_recipient && !report.new_link_domain && !report.new_request);
        }
    }
    #[test]
    fn partial_context_and_shared_envelopes_do_not_retain_recipient_features() {
        let recipient = Recipient {
            address: "private@example.test".into(),
            destination: "different@example.test".into(),
            hosts: vec![],
        };
        let r = capture(
            &digest(b"sender"),
            &Scan::default(),
            &[recipient.clone(), recipient],
            &Targets::default(),
        );
        assert_eq!(r.status, "unavailable");
        assert!(r.sample.is_none());
        assert!(!serde_json::to_string(&r).unwrap().contains("private"));
    }
}
