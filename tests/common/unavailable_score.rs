use noisefence::{
    config::Config,
    engine::{Scan, Signal},
};

pub fn scan(config: &Config) -> Scan {
    let mut scan = Scan {
        features_complete: Some(true),
        model: "unavailable-score-fixture".into(),
        reasons: [1., 2.]
            .into_iter()
            .map(|weight| Signal {
                id: "spf_fail".into(),
                detail: "Conflicting fixture contributions".into(),
                weight,
            })
            .collect(),
        ..Default::default()
    };
    let report = noisefence::scoring::combine(&scan, Some(-2.), false);
    assert!(report.score.is_none());
    scan.score = noisefence::scoring::UNAVAILABLE_SCORE;
    scan.scoring = Some(report);
    scan.reasons.push(Signal {
        id: "score_combination_invalid".into(),
        detail: "Fixture unavailable index".into(),
        weight: 0.,
    });
    scan.analysis_policy = Some(noisefence::diagnostics::AnalysisPolicy::capture(config));
    scan.decision = Some(noisefence::fusion::runtime::Decision::legacy(
        &scan,
        config.filter.threshold,
    ));
    scan.action = Some(noisefence::actions::evaluate(&scan, config));
    noisefence::decision_record::record_recipient(&mut scan, config, None, noisefence::now());
    scan
}
