//! PostgreSQL renders integral float8 columns as JSON integers (50, not 50.0).
//! Compare exact numeric values, never use an epsilon or round integer IDs.
use serde_json::Value;

pub(crate) fn equal(a: &Value, b: &Value) -> bool {
    if a == b {
        return true;
    }
    match (a, b) {
        (Value::Number(a), Value::Number(b)) => {
            let (float, integer) = if a.is_f64() && !b.is_f64() {
                (a, b)
            } else if b.is_f64() && !a.is_f64() {
                (b, a)
            } else {
                return false;
            };
            let Some(integer) = integer
                .as_i64()
                .map(i128::from)
                .or_else(|| integer.as_u64().map(i128::from))
            else {
                return false;
            };
            let float = float.as_f64().unwrap();
            // i128 holds every i64/u64 exactly. Converting the float instead of
            // the integer avoids accepting adjacent IDs above 2^53. Saturation
            // outside i128 cannot equal any of these i64/u64 integers.
            float.fract() == 0.0 && float as i128 == integer
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equal(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, a)| b.get(key).is_some_and(|b| equal(a, b)))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sql_float_notation_does_not_weaken_numeric_or_structure_parity() {
        for (a, b) in [
            (json!(50.0), json!(50)),
            (json!(-0.0), json!(0)),
            (json!(-9223372036854775808.0), json!(i64::MIN)),
            (
                json!({"score":[null,50.0],"enabled":true}),
                json!({"score":[null,50],"enabled":true}),
            ),
        ] {
            assert!(equal(&a, &b));
            assert!(equal(&b, &a));
        }
        for (a, b) in [
            (json!(1.0000000000000002), json!(1)),
            (json!(9007199254740992.0), json!(9007199254740993u64)),
            (json!(i64::MAX as f64), json!(i64::MAX)),
            (json!(u64::MAX as f64), json!(u64::MAX)),
            (json!(1e100), json!(u64::MAX)),
            (json!(50), json!("50")),
            (json!(1), json!(true)),
            (json!([1, 2]), json!([2, 1])),
            (json!({"score":50}), json!({"score":50,"extra":null})),
            (json!({"score":null}), json!({})),
        ] {
            assert!(!equal(&a, &b));
            assert!(!equal(&b, &a));
        }
    }
}
