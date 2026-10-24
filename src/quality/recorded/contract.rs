//! Strict, content-free receipt projection for offline evaluation interchange.
use crate::{
    actions::Action,
    assessment::{ClassificationSource, valid_score},
    decision_record::Classification,
    fusion::runtime::{DecisionSource, Outcome},
    mailing::Category,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize};

// Nullable fields must still be present. Missing data must not silently turn an
// incomplete contract into a valid one during a decode/encode round trip.
fn required_option<'de, D, T>(decoder: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(decoder)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    schema: String,
    provenance: Provenance,
    #[serde(deserialize_with = "required_option")]
    engine: Option<Engine>,
    #[serde(rename = "final", deserialize_with = "required_option")]
    final_result: Option<Final>,
    #[serde(deserialize_with = "required_option")]
    action: Option<Applied>,
}
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Provenance {
    RecipientReceipt,
    AnalysisReceipt,
    Legacy,
    Invalid,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Engine {
    source: DecisionSource,
    outcome: Outcome,
    complete: bool,
    #[serde(deserialize_with = "required_option")]
    raw_score: Option<f64>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Final {
    category: Category,
    #[serde(deserialize_with = "required_option")]
    classification: Option<Classification>,
    classification_source: ClassificationSource,
    complete: bool,
    #[serde(deserialize_with = "required_option")]
    score: Option<f64>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Applied {
    requested: Action,
    effective: Action,
}
impl Snapshot {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == super::SCHEMA,
            "Unsupported recorded decision contract"
        );
        if self.provenance == Provenance::Invalid {
            ensure!(
                self.engine.is_none() && self.final_result.is_none() && self.action.is_none(),
                "Invalid recorded decision cannot supply results"
            );
            return Ok(());
        }
        let result = self
            .final_result
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing recorded policy result"))?;
        let valid = |value: Option<f64>| value.is_none() || valid_score(value).is_some();
        ensure!(
            valid(result.score) && self.engine.as_ref().is_none_or(|e| valid(e.raw_score)),
            "Invalid recorded risk index"
        );
        ensure!(
            self.provenance != Provenance::RecipientReceipt || result.classification.is_some(),
            "Recipient receipt requires its recorded classification"
        );
        let category = match result.classification {
            Some(Classification::Legitimate) => Some(Category::Legitimate),
            Some(Classification::Publicity) => Some(Category::Publicity),
            Some(Classification::Spam | Classification::Phishing | Classification::Malware) => {
                Some(Category::Spam)
            }
            Some(Classification::Unassessed) | None => None,
        };
        ensure!(
            category.is_none_or(|value| value == result.category),
            "Contradictory recorded classification"
        );
        Ok(())
    }
}
