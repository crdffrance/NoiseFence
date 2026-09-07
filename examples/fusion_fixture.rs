//! Synthetic offline observations for software parity tests, never SMTP traffic.
use anyhow::{Result, ensure};
use noisefence::{
    antivirus::{AntivirusResult, AntivirusStatus},
    config::Config,
    engine::Signal,
    evidence::{Artifacts, AuthResult, DomainQuery, DomainRole, Evidence, Query, Source, State},
    llm::{Category, LlmStatus},
    message::digest,
    smtp_policy::{PolicyResult, PolicyStatus},
};
use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() == 2, "usage: fusion_fixture output.jsonl");
    let mut config: Config = toml::from_str(include_str!("../config/development.toml"))?;
    config.filter.authentication = true;
    config.filter.spamhaus_key_env = Some("SYNTHETIC_NO_DNS_QUERY".into());
    config.smtp_policy = Some(toml::from_str("")?);
    config.antivirus = Some(toml::from_str("socket = '/synthetic/not-opened'")?);
    config.signatures = config.antivirus.clone();
    config.llm = Some(toml::from_str(
        r#"
        project_id = "00000000-0000-0000-0000-000000000001"
        model = "synthetic-no-request"
        api_key_env = "UNUSED_SYNTHETIC_KEY"
        monthly_budget_micro_eur = 20000000
        input_micro_eur_per_million = 1
        output_micro_eur_per_million = 1
        pricing_checked_at = 1788739200
    "#,
    )?);
    let artifacts = Artifacts::new(
        &config,
        Some(digest(b"synthetic lexical fixture")),
        Some(digest(b"synthetic semantic fixture")),
        true,
    );
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args[1])?;
    for i in 0..400 {
        let id = digest(format!("fusion software fixture {i}").as_bytes());
        let h = hex::decode(&id)?;
        let spam = i % 2 == 1;
        let mut e = Evidence::new(&config, artifacts.clone(), true);
        e.source = Source::SmtpSession; // Fixture only: assert the trusted path's contract.
        e.analysis_complete = true;
        e.lexical_state = State::Complete;
        e.lexical_logit =
            Some((if spam { 2.0 } else { -2.0 }) + (f64::from(h[0]) / 255.0 - 0.5) * 5.0);
        e.semantic_state = State::Complete;
        e.semantic_logit =
            Some((if spam { 1.0 } else { -1.0 }) + (f64::from(h[1]) / 255.0 - 0.5) * 3.0);
        e.legacy_score = Some(100.0 / (1.0 + (-e.lexical_logit.unwrap()).exp()));
        e.authentication.arc_state = State::Complete;
        e.authentication.arc = Some(AuthResult::None);
        e.authentication.arc_can_seal = Some(true);
        // All detector families vary. These are fabricated measurements and
        // labels for exercising software, never an efficacy or latency sample.
        let suspicious = |index: usize| h[index] < if spam { 180 } else { 70 };
        e.authentication.state = State::Complete;
        e.authentication.spf_state = State::Complete;
        e.authentication.spf = Some(if suspicious(2) {
            AuthResult::Fail
        } else {
            AuthResult::Pass
        });
        e.authentication.dkim_state = State::Complete;
        e.authentication.dkim = Some(vec![if suspicious(3) {
            AuthResult::Fail
        } else {
            AuthResult::Pass
        }]);
        e.authentication.dmarc_state = State::Complete;
        e.authentication.dmarc_spf = e.authentication.spf;
        e.authentication.dmarc_dkim = Some(e.authentication.dkim.as_ref().unwrap()[0]);
        e.reputation.state = State::Complete;
        e.reputation.ip = Query {
            state: State::Complete,
            codes: if suspicious(4) {
                vec!["127.0.0.2".parse()?]
            } else {
                vec![]
            },
        };
        e.reputation.domains = vec![DomainQuery {
            roles: vec![DomainRole::Body],
            result: Query {
                state: State::Complete,
                codes: if suspicious(5) {
                    vec!["127.0.1.4".parse()?]
                } else {
                    vec![]
                },
            },
        }];
        e.smtp_policy_state = State::Complete;
        e.smtp_policy = Some(PolicyResult {
            status: PolicyStatus::Complete,
            version: noisefence::smtp_policy::VERSION.into(),
            checks: [
                if suspicious(6) {
                    "helo_address_mismatch"
                } else {
                    "helo_verified"
                },
                if suspicious(7) {
                    "ptr_missing"
                } else {
                    "ptr_verified"
                },
                if suspicious(8) {
                    "sender_null_mx"
                } else {
                    "sender_mx_present"
                },
            ]
            .into_iter()
            .map(|id| Signal {
                id: id.into(),
                detail: String::new(),
                weight: 0.0,
            })
            .collect(),
            ..Default::default()
        });
        e.antivirus_state = State::Complete;
        e.antivirus = Some(AntivirusResult {
            status: if suspicious(9) {
                AntivirusStatus::Suspicious
            } else {
                AntivirusStatus::Clean
            },
            ..Default::default()
        });
        e.signatures_state = State::Complete;
        e.signatures = Some(AntivirusResult {
            status: if suspicious(10) {
                AntivirusStatus::Suspicious
            } else {
                AntivirusStatus::Clean
            },
            ..Default::default()
        });
        e.llm.state = State::Complete;
        e.llm.outcome = Some(LlmStatus::Complete);
        e.llm.requested_at_score = Some(85.0);
        e.llm.category = Some(if suspicious(11) {
            Category::Phishing
        } else {
            Category::Legitimate
        });
        e.llm.reported_probability = Some(f64::from(h[12]) / 255.0);
        e.llm.reported_confidence = Some(f64::from(h[13]) / 255.0);
        if i % 17 == 0 {
            e.lexical_state = State::Unavailable;
            e.lexical_logit = None;
            e.analysis_complete = false;
        }
        if i % 19 == 0 {
            e.reputation.state = State::Unavailable;
            e.reputation.ip.state = State::Unavailable;
            e.reputation.ip.codes.clear();
            e.analysis_complete = false;
        }
        if i % 23 == 0 {
            e.llm.state = State::Busy;
            e.llm.outcome = Some(LlmStatus::Busy);
            e.llm.category = None;
            e.llm.reported_probability = None;
            e.llm.reported_confidence = None;
            e.analysis_complete = false;
        }
        let row = serde_json::json!({"schema":"noisefence-learning-1","source":"local_human_feedback",
            "id":id,"fingerprint":digest(format!("canonical fixture {i}").as_bytes()),"simhash":&id[..16],
            "observed_at":1788739200+i,"labelled_at":1788740200+i,"feature_version":3,"spam":spam,"evidence":e});
        writeln!(output, "{row}")?;
    }
    output.sync_all()?;
    Ok(())
}
