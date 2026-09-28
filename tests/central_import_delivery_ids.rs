#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{central::import::DeliveryIdentities, store::Store};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn public_delivery_ids_survive_swaps_new_worker_rows_retries_and_late_failure() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let root = tempfile::tempdir().unwrap();
    let local = Store::open(root.path()).unwrap();
    let ids: Vec<String> = (1..=4)
        .map(|i| uuid::Uuid::from_u128(i).to_string())
        .collect();
    let messages = ids.clone();
    local.run(move |db| {
        for (i,message) in messages[..3].iter().enumerate() {
            db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,100,'sender@example.test','{}')",[message])?;
            let id=[2,1,50][i];
            db.execute("INSERT INTO deliveries(id,message_id,address,destination,hosts,next_attempt) VALUES(?1,?2,'alice@example.test','alice@example.test','[]',0)",rusqlite::params![id,message])?;
        }
        Ok(())
    }).await.unwrap();
    let snapshot = local
        .run(|db| DeliveryIdentities::capture(&db.transaction()?))
        .await
        .unwrap();
    assert!(
        f.central
            .import_delivery_identities(&snapshot)
            .await
            .is_err()
    );
    let epoch = uuid::Uuid::new_v4().to_string();
    pg.execute(
        "INSERT INTO noisefence.sources(node,epoch,created) VALUES('mx1',$1,100)",
        &[&epoch],
    )
    .await
    .unwrap();
    for message in &ids {
        pg.execute(
            "INSERT INTO noisefence.message_versions VALUES($1,'mx1',$2,1,false)",
            &[message, &epoch],
        )
        .await
        .unwrap();
        pg.execute("INSERT INTO noisefence.messages(id,created,sender,scan,is_dsn,raw_present,category,rules) VALUES($1,100,'sender@example.test','{}',false,true,'legitimate','')",&[message]).await.unwrap();
        pg.execute("INSERT INTO noisefence.deliveries(message_id,address,destination,status,attempts,next_attempt) VALUES($1,'alice@example.test','alice@example.test','delivered',1,0)",&[message]).await.unwrap();
    }
    pg.batch_execute("CREATE FUNCTION noisefence.break_id_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.id>10 THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$; CREATE TRIGGER break_id_import BEFORE UPDATE OF id ON noisefence.deliveries FOR EACH ROW EXECUTE FUNCTION noisefence.break_id_import();").await.unwrap();
    assert!(
        f.central
            .import_delivery_identities(&snapshot)
            .await
            .is_err()
    );
    for (i, message) in ids.iter().enumerate() {
        assert_eq!(
            pg.query_one(
                "SELECT id FROM noisefence.deliveries WHERE message_id=$1",
                &[message]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            i as i64 + 1
        );
    }
    pg.batch_execute("DROP TRIGGER break_id_import ON noisefence.deliveries;")
        .await
        .unwrap();
    f.central
        .import_delivery_identities(&snapshot)
        .await
        .unwrap();
    let initial = pg
        .query(
            "SELECT id,message_id FROM noisefence.deliveries ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.get::<_, i64>(0), r.get::<_, String>(1)))
        .collect::<Vec<_>>();
    assert_eq!(initial[0], (1, ids[1].clone()));
    assert_eq!(initial[1], (2, ids[0].clone()));
    assert_eq!(initial[2], (50, ids[2].clone()));
    assert!(initial[3].0 > 50);
    assert_eq!(initial[3].1, ids[3]);
    f.central
        .import_delivery_identities(&snapshot)
        .await
        .unwrap();
    let repeated = pg
        .query(
            "SELECT id,message_id FROM noisefence.deliveries ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.get::<_, i64>(0), r.get::<_, String>(1)))
        .collect::<Vec<_>>();
    assert_eq!(initial, repeated);
    let next:i64=pg.query_one("INSERT INTO noisefence.deliveries(message_id,address,destination,status,attempts,next_attempt) VALUES($1,'other@example.test','other@example.test','pending',0,0) RETURNING id",&[&ids[3]]).await.unwrap().get(0);
    assert!(next > initial[3].0);
    pg.execute(
        "INSERT INTO noisefence.delivery_log_versions VALUES('mx1',$1,1,$2,1,1,false)",
        &[&epoch, &ids[1]],
    )
    .await
    .unwrap();
    assert!(
        f.central
            .import_delivery_identities(&snapshot)
            .await
            .unwrap_err()
            .to_string()
            .contains("transcript")
    );
    local
        .read(|db| {
            assert_eq!(
                db.query_row("SELECT max(id) FROM deliveries", [], |r| r.get::<_, i64>(0))?,
                50
            );
            Ok(())
        })
        .await
        .unwrap();
    f.finish().await;
}
