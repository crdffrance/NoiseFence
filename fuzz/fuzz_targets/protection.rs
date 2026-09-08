#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
fuzz_target!(|data: &[u8]| {
    static CONFIG: OnceLock<noisefence::config::Config> = OnceLock::new();
    let config = CONFIG
        .get_or_init(|| toml::from_str(include_str!("../../config/development.toml")).unwrap());
    let (report, _) = noisefence::protection::local_checks(
        data,
        "",
        config,
        &Default::default(),
        &Default::default(),
    );
    assert!(report.findings.len() <= 48 && report.observation_only);
});
