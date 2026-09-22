mod common;
use noisefence::{
    config::Config,
    engine::Scan,
    queue_body::WireBody,
    store::{QueueVariant, Store},
};

fn batch(cfg: &Config, ids: &[String]) -> Vec<QueueVariant> {
    let payload = WireBody::shared_payload(common::MESSAGE).unwrap();
    ids.iter()
        .enumerate()
        .map(|(i, id)| {
            let mut recipient = cfg.recipient("alice@example.test").unwrap();
            recipient.address = format!("r{i}@example.test");
            let mut scan = Scan {
                score: i as f64,
                complete: true,
                features_complete: Some(true),
                ..Default::default()
            };
            scan.decision = Some(noisefence::fusion::runtime::Decision::legacy(
                &scan,
                cfg.filter.threshold,
            ));
            scan.action = Some(noisefence::actions::evaluate(&scan, cfg));
            noisefence::decision_record::record_recipient(&mut scan, cfg, None, 1234);
            let headers = format!("X-NoiseFence-Id: {id}\r\n");
            let wire = noisefence::message::rewrite(common::MESSAGE, false, &headers).unwrap();
            QueueVariant {
                id: id.clone(),
                raw: WireBody::with_shared_payload(wire, &payload).unwrap(),
                scan,
                recipients: vec![(recipient, None)],
            }
        })
        .collect()
}
#[tokio::test]
async fn all_eight_variants_persist_and_recover_with_matching_receipts_and_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    let ids: Vec<_> = (0..8).map(|_| uuid::Uuid::new_v4().to_string()).collect();
    let variants = batch(&cfg, &ids);
    let expected = variants
        .iter()
        .map(|v| {
            (
                v.id.clone(),
                v.raw.digest(),
                serde_json::to_string(&v.scan).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    store
        .enqueue_variants_with_reserve("s@example.org".into(), variants, 0)
        .await
        .unwrap();
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    store.recover().await.unwrap();
    for (id, digest, scan) in expected {
        let raw = std::fs::read(store.raw_path(&id)).unwrap();
        assert_eq!(noisefence::message::digest(&raw), digest);
        assert_eq!(
            noisefence::message::fields(&raw).unwrap().1,
            noisefence::message::fields(common::MESSAGE).unwrap().1
        );
        assert!(String::from_utf8_lossy(&raw).contains(&format!("X-NoiseFence-Id: {id}\r\n")));
        assert_eq!(
            store
                .read(move |db| Ok(db.query_row(
                    "SELECT scan FROM messages WHERE id=?1",
                    [id],
                    |r| r.get::<_, String>(0)
                )?))
                .await
                .unwrap(),
            scan
        );
    }
    assert_eq!(
        store
            .read(|db| Ok(db.query_row(
                "SELECT COUNT(*) FROM deliveries WHERE status='pending'",
                [],
                |r| r.get::<_, i64>(0)
            )?))
            .await
            .unwrap(),
        8
    );
}
#[tokio::test]
async fn late_file_failure_and_disk_reserve_leave_no_partial_acceptance() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    let ids: Vec<_> = (0..8).map(|_| uuid::Uuid::new_v4().to_string()).collect();
    let error = store
        .enqueue_variants_with_reserve("s@example.org".into(), batch(&cfg, &ids), u64::MAX / 2)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("insufficient space"));
    assert_eq!(
        std::fs::read_dir(dir.path().join("spool")).unwrap().count(),
        0
    );
    // Simulate a collision at the eighth file, after seven new files were synced.
    std::fs::write(store.raw_path(&ids[7]), b"pre-existing file").unwrap();
    assert!(
        store
            .enqueue_variants("s@example.org".into(), batch(&cfg, &ids))
            .await
            .is_err()
    );
    for id in &ids[..7] {
        assert!(!store.raw_path(id).exists());
    }
    assert_eq!(
        std::fs::read(store.raw_path(&ids[7])).unwrap(),
        b"pre-existing file"
    );
    assert_eq!(
        store
            .read(|db| Ok(
                db.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0))?
            ))
            .await
            .unwrap(),
        0
    );
    assert!(store.claim().await.unwrap().is_none());
}
