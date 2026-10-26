use base64::{Engine, engine::general_purpose::STANDARD};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::{Value, json};
pub fn signed(source_id: &str, now: i64) -> (String, Value) {
    let rng = SystemRandom::new();
    let pkcs = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs.as_ref(), &rng).unwrap();
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/identity/ad-signed-export.json")).unwrap();
    let bytes = STANDARD
        .decode(fixture["envelope"]["payload"].as_str().unwrap())
        .unwrap();
    let mut data: Value = serde_json::from_slice(&bytes).unwrap();
    data["source_id"] = json!(source_id);
    data["started_at"] = json!(now - 1);
    data["completed_at"] = json!(now);
    data["collection_id"] = json!(uuid::Uuid::new_v4().to_string());
    let bytes = serde_json::to_vec(&data).unwrap();
    let signed = [noisefence::identity::connectors::ad::SIGNING_PREFIX, &bytes].concat();
    let signature = key.sign(&rng, &signed).unwrap();
    (
        STANDARD.encode(key.public_key().as_ref()),
        json!({"protocol":"noisefence-ad-export-1","id":data["collection_id"],"key_id":noisefence::message::digest(key.public_key().as_ref()),"payload":STANDARD.encode(&bytes),"signature":STANDARD.encode(signature.as_ref())}),
    )
}
