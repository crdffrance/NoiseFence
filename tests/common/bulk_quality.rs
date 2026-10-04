use noisefence::{
    quality::{
        Kind,
        evaluation::{self, BulkLabel, Risk},
    },
    store::Store,
};

pub async fn check(store: &Store, batch: &str, ids: &[String], foreign: &str) {
    let labels = |ids: Vec<String>, overwrite| BulkLabel {
        ids,
        risk: Risk::Spam,
        kind: None,
        overwrite,
    };
    assert!(
        evaluation::label_bulk(
            store,
            "alice".into(),
            batch.into(),
            labels(vec![ids[0].clone(), foreign.into()], false)
        )
        .await
        .is_err()
    );
    assert!(
        evaluation::members(store, "alice".into(), batch.into())
            .await
            .unwrap()
            .iter()
            .all(|m| m["risk"].is_null())
    );
    assert!(
        evaluation::label_bulk(
            store,
            "bob".into(),
            batch.into(),
            labels(ids.to_vec(), false)
        )
        .await
        .is_err()
    );
    for invalid in [vec![], vec![ids[0].clone(); 2], vec![ids[0].clone(); 201]] {
        assert!(
            evaluation::label_bulk(store, "alice".into(), batch.into(), labels(invalid, false))
                .await
                .is_err()
        );
    }
    evaluation::label(
        store,
        "alice".into(),
        ids[0].clone(),
        Risk::Legitimate,
        Some(Kind::Newsletter),
    )
    .await
    .unwrap();
    let result = evaluation::label_bulk(
        store,
        "alice".into(),
        batch.into(),
        labels(ids.to_vec(), false),
    )
    .await
    .unwrap();
    assert_eq!((result.applied, result.skipped), (ids.len() - 1, 1));
    let result = evaluation::label_bulk(
        store,
        "alice".into(),
        batch.into(),
        labels(ids.to_vec(), false),
    )
    .await
    .unwrap();
    assert_eq!((result.applied, result.skipped), (0, ids.len()));
    let rows = evaluation::members(store, "alice".into(), batch.into())
        .await
        .unwrap();
    let first = rows.iter().find(|r| r["id"] == ids[0]).unwrap();
    assert_eq!(first["risk"], "legitimate");
    assert_eq!(first["kind"], "newsletter");
    let result = evaluation::label_bulk(
        store,
        "alice".into(),
        batch.into(),
        labels(ids.to_vec(), true),
    )
    .await
    .unwrap();
    assert_eq!(result.applied, ids.len());
    let rows = evaluation::members(store, "alice".into(), batch.into())
        .await
        .unwrap();
    assert!(
        rows.iter()
            .filter(|r| ids.iter().any(|id| r["id"] == *id))
            .all(|r| r["risk"] == "spam")
    );
    assert_eq!(
        rows.iter().find(|r| r["id"] == ids[0]).unwrap()["kind"],
        "newsletter"
    );
    evaluation::label_bulk(
        store,
        "alice".into(),
        batch.into(),
        BulkLabel {
            ids: ids.to_vec(),
            risk: Risk::Uncertain,
            kind: Some(Kind::Promotion),
            overwrite: true,
        },
    )
    .await
    .unwrap();
    let rows = evaluation::members(store, "alice".into(), batch.into())
        .await
        .unwrap();
    assert!(
        rows.iter()
            .filter(|r| ids.iter().any(|id| r["id"] == *id))
            .all(|r| r["risk"] == "uncertain" && r["kind"] == "promotion")
    );
}
