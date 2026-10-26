use noisefence::{
    identity::{
        connections::{Credential, Record, vault::Key},
        directory::Provider,
    },
    store::Store,
};
pub async fn run(store: &Store, root: &std::path::Path, session: &str) {
    let (key, version) = store
        .identity_connection_prepare("admin".into(), session.into())
        .await
        .unwrap();
    let source =
        super::common::record(&key, &store.directory_connection_authority(), version, None);
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/identity/ad-signed-export.json")).unwrap();
    let public = fixture["public_key"].as_str().unwrap().to_owned();
    let mut metadata = source.metadata;
    metadata.source.provider = Provider::ActiveDirectory;
    metadata.source.authority = "corp.example:2905b910-836f-4466-bba4-ae2a00661c74".into();
    metadata.expires = metadata.created + 86400;
    let record = key
        .seal(
            metadata,
            &Credential::AdCollectorPublicKey {
                public_key: public.clone(),
            },
        )
        .unwrap();
    store
        .identity_connection_save(None, record.clone(), "admin".into(), session.into())
        .await
        .unwrap();
    let recovered = store
        .identity_connection_get(
            "synthetic".into(),
            record.metadata.generation.clone(),
            "admin".into(),
            session.into(),
        )
        .await
        .unwrap();
    assert!(
        matches!(Key::load(root).unwrap().open(&recovered,noisefence::now()).unwrap(),Credential::AdCollectorPublicKey{public_key} if public_key==public)
    );
    let mut new_metadata = record.metadata.clone();
    new_metadata.generation = uuid::Uuid::new_v4().to_string();
    new_metadata.supersedes = Some(record.metadata.generation.clone());
    let replacement = key
        .seal(
            new_metadata,
            &Credential::AdCollectorPublicKey { public_key: public },
        )
        .unwrap();
    store
        .identity_connection_save(
            Some(record.metadata.generation.clone()),
            replacement.clone(),
            "admin".into(),
            session.into(),
        )
        .await
        .unwrap();
    assert!(
        store
            .identity_connection_get(
                "synthetic".into(),
                record.metadata.generation.clone(),
                "admin".into(),
                session.into()
            )
            .await
            .is_err()
    );
    // Records loaded after process restart cannot transform a public pin into a pull grant.
    let encoded = replacement.encode().unwrap();
    let mut reloaded: Record = serde_json::from_str(&encoded).unwrap();
    reloaded.metadata.source.provider = Provider::Entra;
    assert!(key.open(&reloaded, noisefence::now()).is_err());
    store
        .identity_connection_revoke(
            "synthetic".into(),
            replacement.metadata.generation.clone(),
            "admin".into(),
            session.into(),
        )
        .await
        .unwrap();
    assert!(
        store
            .identity_connection_get(
                "synthetic".into(),
                replacement.metadata.generation,
                "admin".into(),
                session.into()
            )
            .await
            .is_err()
    );
}
