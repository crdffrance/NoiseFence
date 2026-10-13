use axum::{http::StatusCode, response::IntoResponse};

#[tokio::test]
async fn sqlite_contention_is_retryable_without_exposing_storage_details() {
    for code in [
        rusqlite::ffi::SQLITE_BUSY,
        rusqlite::ffi::SQLITE_BUSY_SNAPSHOT,
        rusqlite::ffi::SQLITE_LOCKED,
    ] {
        let error = anyhow::Error::new(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(code),
            Some("private SQL details".into()),
        ))
        .context("private operation context");
        let response = noisefence::api::Error::from(error).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()["retry-after"], "1");
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("Storage temporarily busy"));
        assert!(!text.contains("private"));
    }
    let response =
        noisefence::api::Error::from(anyhow::anyhow!("unrelated failure")).into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!response.headers().contains_key("retry-after"));
}
