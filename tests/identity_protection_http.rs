#[allow(dead_code)]
mod common;
#[path = "common/scim_http.rs"]
mod http;
#[path = "common/identity_protection.rs"]
mod protection;
use noisefence::store::Store;
#[tokio::test]
async fn local_protection_edit_requires_review_and_preserves_provider_freshness() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    for (name, token, admin) in [
        ("admin", http::ADMIN, true),
        ("reader", http::READER, false),
    ] {
        let hash = noisefence::message::digest(token.as_bytes());
        store
            .run(move |db| {
                db.execute(
                    "INSERT INTO users VALUES(?1,'unused',?2,0)",
                    rusqlite::params![name, admin],
                )?;
                db.execute(
                    "INSERT INTO sessions VALUES(?1,?2,'csrf-http',?3)",
                    rusqlite::params![hash, name, noisefence::now() + 3600],
                )?;
                Ok(())
            })
            .await
            .unwrap();
    }
    let mut config = (*common::config(root.path())).clone();
    protection::install(&mut config);
    let (router, control) = http::router(std::sync::Arc::new(config), store).await;
    protection::exercise(&router, &control).await;
}
