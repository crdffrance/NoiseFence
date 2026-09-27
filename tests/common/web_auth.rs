use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

pub async fn call(
    app: &Router,
    origin: &str,
    path: &str,
    cookie: &str,
    csrf: &str,
    body: Option<Value>,
) -> (StatusCode, Value, String) {
    let mut req = Request::builder()
        .uri(format!("/api/v1{path}"))
        .header("origin", origin)
        .header("cookie", cookie)
        .header("x-csrf-token", csrf);
    let b = if let Some(value) = body {
        req = req
            .method("POST")
            .header("content-type", "application/json");
        Body::from(value.to_string())
    } else {
        Body::empty()
    };
    let r = app.clone().oneshot(req.body(b).unwrap()).await.unwrap();
    let status = r.status();
    let cookie = r
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .unwrap_or_default();
    let bytes = r.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v, cookie)
}
pub fn current_code(encoded: &str) -> String {
    // Test client decodes the provisioning key and independently produces its OTP.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut raw = Vec::new();
    let mut n = 0u32;
    let mut bits = 0;
    for b in encoded.bytes() {
        n = (n << 5) | alphabet.iter().position(|v| *v == b).unwrap() as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            raw.push((n >> bits) as u8);
        }
    }
    let mac = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &raw),
        &((noisefence::now() / 30) as u64).to_be_bytes(),
    );
    let b = mac.as_ref();
    let i = (b[19] & 15) as usize;
    let n = u32::from_be_bytes(b[i..i + 4].try_into().unwrap()) & 0x7fffffff;
    format!("{:06}", n % 1_000_000)
}
