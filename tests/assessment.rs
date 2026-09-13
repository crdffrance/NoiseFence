use noisefence::{assessment, engine::Scan};
use serde_json::{Value, json};

#[test]
fn shared_assessment_cases_preserve_evidence_and_policy() {
    let cases: Vec<Value> = serde_json::from_str(include_str!("fixtures/assessment.json")).unwrap();
    for case in cases {
        let mut data = serde_json::to_value(Scan::default()).unwrap();
        for (k, v) in case["scan"].as_object().unwrap() {
            data[k] = v.clone();
        }
        let scan: Scan = serde_json::from_value(data.clone()).unwrap();
        let snapshot = serde_json::to_value(&scan).unwrap();
        let actual = serde_json::to_value(assessment::assess(&scan, 80.)).unwrap();
        let expected = &case["expected"];
        assert_eq!(actual["version"], 1);
        assert_eq!(actual["score"]["scale"], 100);
        assert_eq!(
            actual["score"]["value"].as_f64(),
            expected["value"].as_f64()
        );
        for key in ["kind", "source"] {
            assert_eq!(
                actual["score"][key], expected[key],
                "{} / {key}",
                case["name"]
            );
        }
        for key in ["category", "classification_source"] {
            assert_eq!(actual[key], expected[key], "{} / {key}", case["name"]);
        }
        assert_eq!(
            serde_json::to_value(&scan).unwrap(),
            snapshot,
            "assessment must not mutate retained evidence"
        );
    }
}

#[test]
fn absent_or_nonfinite_values_never_become_zero() {
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1., 101.] {
        let s = Scan {
            score: value,
            ..Default::default()
        };
        let a = serde_json::to_value(assessment::assess(&s, 95.)).unwrap();
        assert_eq!(a["score"]["value"], Value::Null);
        assert_eq!(a["incomplete_reasons"], json!(["unspecified"]));
    }
}
