use noisefence::identity::{
    connections::{Credential, Metadata, PROTOCOL, Record, vault::Key},
    directory::{Provider, Source},
};
pub fn record(key: &Key, authority: &str, owner_version: i64, previous: Option<&Record>) -> Record {
    let now = noisefence::now();
    key.seal(
        Metadata {
            protocol: PROTOCOL.into(),
            source: Source {
                id: "synthetic".into(),
                label: "Synthetic directory".into(),
                provider: Provider::Entra,
                authority: "11111111-1111-4111-8111-111111111111".into(),
                scopes: ["example.test".into()].into_iter().collect(),
                stale_after_seconds: 86400,
            },
            generation: uuid::Uuid::new_v4().to_string(),
            supersedes: previous.map(|p| p.metadata.generation.clone()),
            authority: authority.into(),
            key_id: key.id(),
            owner: "admin".into(),
            owner_version,
            created: now,
            expires: now + 3600,
        },
        &Credential::EntraApplication {
            client_id: "22222222-2222-4222-8222-222222222222".into(),
            client_secret: "SYNTHETIC-NO-LIVE-PROVIDER-SECRET".into(),
        },
    )
    .unwrap()
}
