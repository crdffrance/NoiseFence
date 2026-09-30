//! Deterministic completed observation for persistence/ACL tests.
//! Exercise the real extractor and adaptive vector, without making export
//! eligibility depend on a loaded CI runner meeting an SMTP wall-clock budget.
use noisefence::{adaptive, native_filter};

pub fn completed(raw: &[u8], domain: &str) -> native_filter::Observation {
    let input = native_filter::input::extract(raw, 1024 * 1024).unwrap();
    let patterns = native_filter::rules::default_patterns();
    let runtime = adaptive::Runtime::new(
        adaptive::Settings {
            domains: [(domain.into(), adaptive::Tenant::default())].into(),
        },
        &patterns,
    )
    .unwrap();
    let (adaptive, vector) = runtime.predict(&input, &[], &[domain.into()]);
    input.features.validate().unwrap();
    assert_eq!(vector.as_ref().unwrap().len(), adaptive::WIDTH);
    native_filter::Observation {
        report: native_filter::Report {
            version: native_filter::VERSION.into(),
            policy_sha256: noisefence::message::digest(b"synthetic-export-fixture"),
            mode: native_filter::Mode::Observe,
            status: native_filter::Status::Complete,
            elapsed_ms: 0,
            score: None,
            bayes: Default::default(),
            bayes_sha256: None,
            fuzzy: Default::default(),
            calibrated: false,
            affects_delivery: false,
            adaptive: Some(adaptive),
        },
        features: Some(input.features),
        local_symbols: vec![],
        adaptive_vector: vector,
    }
}
